"""Score decompilers' pseudocode beyond "is it C": does it behave like the original, how close
are its control flow and data flow to the source's, and how many types does it get right.

    python tools/decomp_quality.py CONFIG.json OUTPUTS_DIR [--json OUT.json]

OUTPUTS_DIR is what `tools/compare_decompilers.py --save` keeps (OUTPUTS_DIR/NAME/TOOL.json:
address -> pseudocode). CONFIG.json describes each binary NAME:

    {"lua-O2": {"debug": "dbg/lua-O2",                 # the same build with -g: DWARF types
                "sources": [{"files": ["lapi.c", ...], "flags": ["-DLUA_USE_LINUX"]}],
                "equiv": "-O2"}}                         # tools/bench/equiv.c at this level

Metrics, per tool and binary (functions: the ground truth of tools/compare_tools.py):

- **Syntax validity**: the function alone passes `gcc -fsyntax-only` (as compare_decompilers.py).
- **Behavioural equivalence** (binaries built from tools/bench/equiv.c only): the function's
  pseudocode, compiled again and linked into a harness, returns the same values and leaves the
  same memory as the original on 40 inputs per function (EQUIV below).
- **Control-flow similarity**: gcc's CFG of the pseudocode against gcc's CFG of the original
  source function, both at -O0, as a Weisfeiler-Lehman graph-kernel similarity (0..1).
- **Data-flow similarity**: the same on gcc's SSA def-use graphs (nodes labelled by operation:
  add, load, call, phi ...), and the number of variables against the source's.
- **Type recovery**: the parameters' and return type against DWARF: same kind (integer,
  float, pointer, struct) and size ("kind"), and also signedness and what a pointer points to
  ("exact"); and the same number of parameters.

To compile pseudocode that uses globals, callees or types it doesn't declare, the scorer adds
`extern long NAME;` / `typedef long NAME;` until gcc accepts it (or gives up); helper
pseudo-functions (Ghidra's CONCAT44, ...) are defined for every tool alike (COMPAT).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from compare_decompilers import PRELUDE, TOOL_PRELUDE, valid_c  # noqa: E402
from compare_tools import truth  # noqa: E402

ENV = {**os.environ, "LC_ALL": "C"}


def _compat() -> str:
    """Helper pseudo-functions some decompilers print (Ghidra's CONCATxy, SUBxy, ZEXTxy, SEXTxy,
    CARRYn, SCARRYn, SBORROWn), as macros"""
    # (and libc's headers, as anyone compiling the pseudocode again would include them)
    out = [f"#include <{h}.h>" for h in ("string", "ctype", "math", "stdlib", "stdio")]
    u = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t", 16: "unsigned __int128"}
    s = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t", 16: "__int128"}
    for x in (1, 2, 4, 8):
        for y in (1, 2, 4, 8):
            if x + y in u:
                out.append(f"#define CONCAT{x}{y}(a,b) (({u[x + y]})({u[x]})(a) << {8 * y} | ({u[y]})(b))")
            if y < x:
                out.append(f"#define SUB{x}{y}(v,o) (({u[y]})((v) >> ((o) * 8)))")
            if y > x:
                out.append(f"#define ZEXT{x}{y}(v) (({u[y]})({u[x]})(v))")
                out.append(f"#define SEXT{x}{y}(v) (({s[y]})({s[x]})(v))")
    for n in (1, 2, 4, 8):
        out.append(f"#define CARRY{n}(a,b) (({u[n]})(({u[n]})(a) + ({u[n]})(b)) < ({u[n]})(a))")
        out.append(f"#define SCARRY{n}(a,b) __builtin_add_overflow_p(({s[n]})(a), ({s[n]})(b), ({s[n]})0)")
        out.append(f"#define SBORROW{n}(a,b) __builtin_sub_overflow_p(({s[n]})(a), ({s[n]})(b), ({s[n]})0)")
    return "\n".join(out) + "\n"


COMPAT = _compat()


# ------------------------------------------------------------------ compiling to GIMPLE
def _gcc(src: str, tmp: str, extra_args=()) -> subprocess.CompletedProcess:
    path = os.path.join(tmp, "f.c")
    with open(path, "w") as fp:
        fp.write(src)
    for f in glob.glob(os.path.join(tmp, "f.c.*")):
        os.unlink(f)
    return subprocess.run(["gcc", "-O0", "-c", "-w", "-std=gnu11", "-fdump-tree-cfg-blocks", "-fdump-tree-ssa",
                           *extra_args, "f.c", "-o", "f.o"], cwd=tmp, capture_output=True, text=True, env=ENV)


def compile_pseudocode(text: str, tool: str, tmp: str) -> tuple[str, dict] | None:
    """(the C source gcc accepted, {function: (cfg dump, ssa dump)}) for one tool's pseudocode,
    declaring what it uses without declaring it; None when gcc still refuses it."""
    extra: list[str] = []
    for _ in range(8):
        src = PRELUDE + TOOL_PRELUDE.get(tool, "") + COMPAT + "\n".join(extra) + "\n" + text + "\n"
        r = _gcc(src, tmp)
        if r.returncode == 0:
            return src, dumps(tmp)
        new = [f"extern long {m};" for m in re.findall(r"'([A-Za-z_]\w*)' undeclared", r.stderr)]
        new += [f"typedef long {m};" for m in re.findall(r"unknown type name '([A-Za-z_]\w*)'", r.stderr)]
        new = list(dict.fromkeys(n for n in new if n not in extra))
        if not new:
            return None
        extra += new
    return None


def dumps(directory: str) -> dict[str, tuple[str, str]]:
    cfg = "".join(open(f).read() for f in glob.glob(os.path.join(directory, "*.cfg")))
    ssa = "".join(open(f).read() for f in glob.glob(os.path.join(directory, "*.ssa")))
    a, b = split_functions(cfg), split_functions(ssa)
    return {n: (a[n], b.get(n, "")) for n in a}


def split_functions(dump: str) -> dict[str, str]:
    out = {}
    for part in re.split(r"^;; Function ", dump, flags=re.M)[1:]:
        name = part.split(None, 1)[0]
        out.setdefault(name, part)
    return out


def source_dumps(sources: list[dict], cache: str) -> dict[str, tuple[str, str]]:
    """{function: (cfg, ssa)} of the original source, compiled at -O0 (cached by file list)."""
    key = hashlib.sha1(json.dumps(sources, sort_keys=True).encode()).hexdigest()[:16]
    path = os.path.join(cache, f"src-{key}.json")
    if os.path.exists(path):
        return {k: tuple(v) for k, v in json.load(open(path)).items()}
    out: dict[str, tuple[str, str]] = {}
    for group in sources:
        for f in group["files"]:
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run(["gcc", "-O0", "-c", "-w", "-fdump-tree-cfg-blocks", "-fdump-tree-ssa",
                                *group.get("flags", []), os.path.abspath(f), "-o", os.path.join(tmp, "x.o"),
                                "-dumpdir", tmp + "/"], capture_output=True, text=True, env=ENV)
                for n, v in dumps(tmp).items():
                    out.setdefault(n, v)
    os.makedirs(cache, exist_ok=True)
    with open(path, "w") as fp:
        json.dump(out, fp)
    return out


# ------------------------------------------------------------------ graphs
Graph = tuple[dict[str, str], list[tuple[str, str]]]


def cfg_graph(dump: str) -> Graph:
    """Basic blocks and edges from gcc's `;; N succs { ... }` lines; a block is labelled by its
    number of successors and predecessors."""
    edges = [(a, b) for a, succ in re.findall(r"^;; (\d+) succs \{([^}]*)\}", dump, re.M) for b in succ.split()]
    nodes = {n for e in edges for n in e}
    outd, ind = Counter(a for a, _ in edges), Counter(b for _, b in edges)
    return {n: f"{outd[n]}/{ind[n]}" for n in nodes}, edges


_SSA = re.compile(r"\b(?:[A-Za-z_][\w.]*_\d+|_\d+)(?:\(D\))?")
_OPS = [(" <= ", "cmp"), (" >= ", "cmp"), (" == ", "cmp"), (" != ", "cmp"), (" < ", "cmp"), (" > ", "cmp"),
        (" << ", "shl"), (" >> ", "shr"), (" r<< ", "rot"), (" r>> ", "rot"), (" * ", "mul"), (" / ", "div"),
        (" % ", "mod"), (" & ", "and"), (" | ", "or"), (" ^ ", "xor"), (" + ", "add"), (" - ", "sub")]


def _op(rhs: str) -> str:
    rhs = rhs.strip()
    if rhs.startswith("PHI"):
        return "phi"
    if re.match(r"[A-Za-z_][\w.]*\s\(", rhs) and not rhs.startswith(("MIN_EXPR", "MAX_EXPR", "ABS_EXPR")):
        return "call"
    for tok, name in _OPS:
        if tok in rhs:
            return name
    if rhs.startswith(("MIN_EXPR", "MAX_EXPR", "ABS_EXPR")):
        return rhs.split()[0].lower()
    if rhs.startswith("-"):
        return "neg"
    if rhs.startswith("~"):
        return "not"
    if rhs.startswith("("):
        return "cast"
    if rhs.startswith(("*", "MEM")) or "[" in rhs or "." in rhs.split()[0] or "->" in rhs:
        return "load"
    if rhs.startswith("&"):
        return "addr"
    if re.match(r"[-\d.]", rhs) or rhs.startswith('"'):
        return "const"
    return "copy"


def ssa_graph(dump: str) -> tuple[Graph, int]:
    """gcc's SSA def-use graph: a node per statement (labelled by its operation), an edge from
    the statement defining a value to each one using it; values kept in memory (a variable whose
    address is taken) link their stores to later loads. Also the number of declared variables."""
    body = dump.split("{", 1)[1] if "{" in dump else ""
    decls, stmts = [], []
    started = False
    for line in body.splitlines():
        t = line.strip()
        if t.startswith("<bb") or t.startswith("# "):
            started = True
        if not started:
            m = re.match(r".*?\b([A-Za-z_]\w*)(?:\[[^]]*\])?;$", t)
            if m and not t.startswith("//"):
                decls.append(m.group(1))
            continue
        if not t or t.startswith(("<bb", "goto", "else", "<L", "}", "//")) or t.endswith(":"):
            continue
        stmts.append(t.lstrip("# ").rstrip(";"))
    user_vars = [d for d in decls if not d.startswith(("_", "D.")) and not re.fullmatch(r"\w+\.\d+", d)]
    mem = set(decls)
    labels: dict[str, str] = {}
    edges: list[tuple[str, str]] = []
    defs: dict[str, str] = {}
    last_store: dict[str, str] = {}

    def use(name: str, node: str):
        if name.endswith("(D)"):
            name = name[:-3]
            if name not in defs:
                defs[name] = f"p{len(labels)}"
                labels[defs[name]] = "param"
        if name in defs:
            edges.append((defs[name], node))

    for i, st in enumerate(stmts):
        node = f"s{i}"
        if st.startswith(("if (", "switch (", "return")):
            labels[node] = "cond" if st.startswith("if") else st.split()[0].split("(")[0]
            rhs, lhs = st, None
        elif " = " in st:
            lhs, rhs = st.split(" = ", 1)
            lhs_ssa = _SSA.fullmatch(lhs.strip())
            labels[node] = _op(rhs) if lhs_ssa else "store"
            if lhs_ssa:
                defs[lhs.strip()] = node
            else:
                base = re.match(r"\*?([A-Za-z_]\w*)", lhs.strip())
                if base and base.group(1) in mem:
                    last_store[base.group(1)] = node
                for n in _SSA.findall(lhs):
                    use(n, node)
        else:
            labels[node] = "call" if "(" in st else "other"
            rhs, lhs = st, None
        for n in _SSA.findall(rhs):
            use(n, node)
        for v in re.findall(r"\b([A-Za-z_]\w*)\b", rhs):
            if v in last_store and not _SSA.fullmatch(v):
                edges.append((last_store[v], node))
    return (labels, edges), len(user_vars)


def wl_similarity(a: Graph, b: Graph, rounds: int = 3) -> float:
    """Weisfeiler-Lehman subtree kernel, normalised: 1.0 for graphs alike to `rounds` hops."""
    table: dict = {}
    feats = []
    for labels, edges in (a, b):
        succ: dict[str, list[str]] = {n: [] for n in labels}
        pred: dict[str, list[str]] = {n: [] for n in labels}
        for x, y in edges:
            if x in labels and y in labels:
                succ[x].append(y)
                pred[y].append(x)
        cur = {n: table.setdefault(("0", lab), len(table)) for n, lab in labels.items()}
        f = Counter(cur.values())
        for _ in range(rounds):
            cur = {n: table.setdefault((cur[n], tuple(sorted(cur[m] for m in succ[n])),
                                        tuple(sorted(cur[m] for m in pred[n]))), len(table)) for n in cur}
            f.update(cur.values())
        feats.append(f)
    fa, fb = feats
    dot = sum(v * fb[k] for k, v in fa.items())
    na, nb = math.sqrt(sum(v * v for v in fa.values())), math.sqrt(sum(v * v for v in fb.values()))
    return dot / (na * nb) if na and nb else 0.0


# ------------------------------------------------------------------ signatures and types
def header(text: str) -> tuple[str, str, list[str]] | None:
    """(name, return type, parameter declarations) of the function the pseudocode defines."""
    lines = [ln for ln in text.splitlines()]
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s or s.startswith(("//", "/*", "*", "#", "struct ", "typedef ", "union ", "enum ")) and "(" not in s:
            continue
        nxt = next((x.strip() for x in lines[i + 1:] if x.strip()), "")
        if "(" in s and (s.endswith("{") or nxt == "{") and not s.endswith(";"):
            sig = s[:-1].strip() if s.endswith("{") else s
            m = re.match(r"(.*?)\b([A-Za-z_]\w*)\s*\((.*)\)\s*$", sig)
            if not m:
                return None
            ret, name, params = m.group(1).strip(), m.group(2), m.group(3).strip()
            parts, depth, cur = [], 0, ""
            for ch in params:
                if ch == "," and depth == 0:
                    parts.append(cur.strip())
                    cur = ""
                    continue
                depth += ch in "([" and 1 or (-1 if ch in ")]" else 0)
                cur += ch
            if cur.strip():
                parts.append(cur.strip())
            parts = [p for p in parts if p not in ("void", "...")]
            return name, ret, parts
    return None


_INTS = {"char": (1, None), "signed char": (1, True), "unsigned char": (1, False), "short": (2, True),
         "unsigned short": (2, False), "int": (4, True), "unsigned int": (4, False), "unsigned": (4, False),
         "long": (8, True), "unsigned long": (8, False), "long long": (8, True), "unsigned long long": (8, False),
         "__int128": (16, True), "unsigned __int128": (16, False), "size_t": (8, False), "ssize_t": (8, True),
         "uchar": (1, False), "ushort": (2, False), "uint": (4, False), "ulong": (8, False), "longlong": (8, True),
         "ulonglong": (8, False), "byte": (1, False), "sbyte": (1, True), "word": (2, False), "sword": (2, True),
         "dword": (4, False), "sdword": (4, True), "qword": (8, False), "sqword": (8, True),
         "uintptr_t": (8, False), "intptr_t": (8, True), "int128_t": (16, True), "uint128_t": (16, False)}
for _n in (8, 16, 32, 64):
    _INTS[f"int{_n}_t"] = (_n // 8, True)
    _INTS[f"uint{_n}_t"] = (_n // 8, False)
for _n in range(1, 17):
    _INTS[f"undefined{_n}"] = (_n, None)
_INTS["undefined"] = (1, None)


def c_type(t: str) -> tuple:
    """A C type as (kind, size, signed, pointee) -- kind: int float bool ptr struct void unknown."""
    t = re.sub(r"\b(const|volatile|restrict|__restrict|register|static|inline|signed(?= \w))\b", "", t)
    t = " ".join(t.split())
    if "(*" in t or t.endswith("]"):
        return ("ptr", 8, None, ("unknown", None, None, None))
    stars = t.count("*")
    base = t.replace("*", "").strip()
    if stars:
        return ("ptr", 8, None, c_type(base) if stars == 1 else ("ptr", 8, None, None))
    if base in ("void", ""):
        return ("void", 0, None, None)
    if base in ("bool", "_Bool"):
        return ("bool", 1, None, None)
    if base in ("float", "double", "long double", "float10"):
        return ("float", {"float": 4, "double": 8}.get(base, 16), None, None)
    if base.startswith(("struct ", "union ")):
        return ("struct", None, None, None)
    if base == "code":
        return ("func", None, None, None)
    if base in _INTS:
        size, sign = _INTS[base]
        return ("int", size, sign, None)
    return ("unknown", None, None, None)


def param_type(decl: str) -> tuple:
    decl = re.sub(r"\s*\[[^]]*\]$", "*", decl.strip())
    if "(*" in decl:
        return c_type("void (*)()")
    m = re.match(r"(.*?[\s*])([A-Za-z_]\w*)$", decl)
    return c_type(m.group(1) if m and m.group(1).strip() else decl)


def dwarf_signatures(path: str) -> dict[int, tuple[tuple, list[tuple]]]:
    """{address: (return type, [parameter types])} from DWARF, as c_type() tuples."""
    from elftools.dwarf.enums import ENUM_DW_ATE
    from elftools.elf.elffile import ELFFile
    ate = {v: k for k, v in ENUM_DW_ATE.items()}

    def typ(die, depth=0) -> tuple:
        if die is None or depth > 8:
            return ("void", 0, None, None)
        tag = die.tag
        nxt = die.get_DIE_from_attribute("DW_AT_type") if "DW_AT_type" in die.attributes else None
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type",
                   "DW_TAG_atomic_type"):
            return typ(nxt, depth + 1)
        if tag == "DW_TAG_base_type":
            enc = ate.get(die.attributes["DW_AT_encoding"].value, "")
            size = die.attributes["DW_AT_byte_size"].value
            if enc == "DW_ATE_float":
                return ("float", size, None, None)
            if enc == "DW_ATE_boolean":
                return ("bool", 1, None, None)
            sign = None if enc in ("DW_ATE_signed_char", "DW_ATE_unsigned_char") and size == 1 and \
                die.attributes.get("DW_AT_name") and die.attributes["DW_AT_name"].value == b"char" else \
                enc in ("DW_ATE_signed", "DW_ATE_signed_char")
            return ("int", size, sign, None)
        if tag in ("DW_TAG_pointer_type", "DW_TAG_array_type", "DW_TAG_reference_type"):
            inner = typ(nxt, depth + 1) if tag != "DW_TAG_array_type" else typ(nxt, depth + 1)
            return ("ptr", 8, None, inner if depth < 2 else None)
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
            return ("struct", None, None, None)
        if tag == "DW_TAG_enumeration_type":
            return ("int", die.attributes["DW_AT_byte_size"].value, None, None)
        if tag == "DW_TAG_subroutine_type":
            return ("func", None, None, None)
        return ("unknown", None, None, None)

    out = {}
    with open(path, "rb") as fp:
        elf = ELFFile(fp)
        if not elf.has_dwarf_info():
            return out
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or "DW_AT_low_pc" not in die.attributes:
                    continue
                spec = die
                for attr in ("DW_AT_abstract_origin", "DW_AT_specification"):
                    if attr in spec.attributes:
                        spec = spec.get_DIE_from_attribute(attr)
                ret = typ(spec.get_DIE_from_attribute("DW_AT_type")) if "DW_AT_type" in spec.attributes else \
                    ("void", 0, None, None)
                params = [typ(c.get_DIE_from_attribute("DW_AT_type")) for c in spec.iter_children()
                          if c.tag == "DW_TAG_formal_parameter" and "DW_AT_type" in c.attributes]
                out[die.attributes["DW_AT_low_pc"].value] = (ret, params)
    return out


def same_kind(src: tuple, dec: tuple) -> bool:
    if src[0] in ("int", "bool") and dec[0] in ("int", "bool"):
        return src[1] == dec[1]
    if src[0] == "float" and dec[0] == "float":
        return src[1] == dec[1]
    return src[0] == dec[0] and src[0] in ("ptr", "struct", "void")


def same_exact(src: tuple, dec: tuple) -> bool:
    if not same_kind(src, dec):
        return False
    if src[0] == "int" and src[2] is not None and dec[0] == "int":
        return src[2] == dec[2]
    if src[0] == "ptr" and src[3] is not None and src[3][0] != "void":
        return dec[3] is not None and same_kind(src[3], dec[3]) and \
            (src[3][0] != "int" or src[3][2] is None or src[3][2] == dec[3][2])
    return True


# ------------------------------------------------------------------ behavioural equivalence
STRUCTS = """struct pt { int x, y; };
struct rect { int x0, y0, x1, y1; };
struct node { int v; struct node *next; };
struct acc { long sum; int count; int max; };
"""

# name: (return type, [argument kinds]) -- the generators below turn each kind into C
EQUIV = {
    "gcd": ("long", ["l", "l"]), "popcount": ("int", ["u64"]), "isqrt": ("uint32_t", ["u32"]),
    "collatz": ("int", ["u20"]), "powmod": ("uint64_t", ["u64", "u64", "m"]), "clamp": ("int", ["clamp"]),
    "fib": ("long", ["n90"]), "bitrev": ("uint32_t", ["u32"]), "sat_add": ("int32_t", ["i32", "i32"]),
    "digit_sum": ("int", ["l"]), "is_prime": ("int", ["u20"]), "div_round": ("long", ["l", "nz"]),
    "rotl": ("uint64_t", ["u64", "u32"]), "day_kind": ("int", ["day"]), "char_class": ("int", ["chr"]),
    "calc": ("long", ["op", "l", "l"]), "sum_array": ("long", ["arr"]), "max_index": ("int", ["arr"]),
    "reverse": ("void", ["arr"]), "bubble_sort": ("void", ["arr"]), "count_gt": ("int", ["arr", "l"]),
    "prefix_sum": ("void", ["arr"]), "dot": ("long", ["arr2"]), "bsearch_int": ("int", ["sarr", "l"]),
    "my_strlen": ("size_t", ["str"]), "count_char": ("int", ["str", "chr"]), "to_upper": ("void", ["str"]),
    "djb2": ("uint32_t", ["str"]), "atoi_simple": ("long", ["num"]), "is_palindrome": ("int", ["pal"]),
    "word_count": ("int", ["str"]), "manhattan": ("int", ["pt*", "pt*"]), "rect_area": ("long", ["rect*"]),
    "list_sum": ("long", ["list"]), "acc_add": ("void", ["acc*", "l"]), "pt_cross": ("int", ["pt", "pt"]),
    "poly": ("double", ["d"]), "mean": ("double", ["darr"]), "lerp": ("double", ["d", "d", "d"]),
    "sign_d": ("int", ["d"]), "fib_rec": ("long", ["n20"]), "ackermann": ("long", ["ack"]),
}
CASES = 40


def _case(kinds: list[str], rng: random.Random, k: int) -> tuple[list[str], list[str], list[str], list[str]]:
    """(setup lines, original's arguments, pseudocode's arguments, checks after both calls)."""
    setup, a, b, check = [], [], [], []
    for j, kind in enumerate(kinds):
        v = f"v{k}_{j}"
        if kind in ("l", "nz"):
            x = rng.randint(-10**6, 10**6) or 7
            a.append(f"{x}L")
        elif kind == "u64":
            a.append(f"{rng.getrandbits(64)}ULL")
        elif kind == "u32":
            a.append(f"{rng.getrandbits(32)}U")
        elif kind == "u20":
            a.append(str(rng.randint(0, 10**5)))
        elif kind == "m":
            a.append(f"{rng.randint(1, 2**40)}ULL")
        elif kind == "i32":
            a.append(f"(int32_t){rng.randint(-2**31, 2**31 - 1)}")
        elif kind == "n90":
            a.append(str(rng.randint(0, 90)))
        elif kind == "n20":
            a.append(str(rng.randint(0, 20)))
        elif kind == "clamp":
            lo, hi = sorted(rng.randint(-1000, 1000) for _ in range(2))
            a += [str(rng.randint(-2000, 2000)), str(lo), str(hi)]
        elif kind == "day":
            a.append(str(rng.randint(-2, 9)))
        elif kind == "chr":
            a.append(str(rng.choice([rng.randint(0, 127), *map(ord, " \t\n()+-*/0xa")])))
        elif kind == "op":
            a.append(str(rng.choice([*map(ord, "+-*/%&|^"), rng.randint(0, 127)])))
        elif kind == "ack":
            m = rng.randint(0, 3)
            a += [str(m), str(rng.randint(0, 4 if m == 3 else 8))]
        elif kind == "d":
            a.append(repr(rng.uniform(-100, 100)))
        elif kind in ("arr", "sarr", "arr2", "darr"):
            n = rng.randint(0, 20)
            ctype = "double" if kind == "darr" else "int"
            vals = [rng.uniform(-1000, 1000) if kind == "darr" else rng.randint(-10**6, 10**6) for _ in range(n)]
            if kind == "sarr":
                vals.sort()
            lit = "{" + ", ".join(map(repr, vals)) + "}" if n else "{0}"
            arrays = [v + "x"] if kind != "arr2" else [v + "x", v + "y"]
            for arr in arrays:
                if kind == "arr2":
                    lit = "{" + ", ".join(str(rng.randint(-10**4, 10**4)) for _ in range(n)) + "}" if n else "{0}"
                setup.append(f"{ctype} {arr}a[] = {lit}, {arr}b[] = {lit};")
                check.append(f"if (memcmp({arr}a, {arr}b, sizeof {arr}a)) bad++;")
            a.extend(f"{arr}a" for arr in arrays)
            b.extend(f"{arr}b" for arr in arrays)
            a.append(str(n))
            b.append(str(n))
            continue
        elif kind in ("str", "num", "pal"):
            n = rng.randint(0, 20)
            if kind == "num":
                s = " " * rng.randint(0, 2) + rng.choice(["", "-", "+"]) + "".join(rng.choice("0123456789")
                                                                                    for _ in range(rng.randint(0, 12)))
            elif kind == "pal":
                h = "".join(rng.choice("abc") for _ in range(rng.randint(0, 6)))
                s = h + rng.choice(["", "x"]) + h[::-1] if rng.random() < 0.6 else h + "ab"
            else:
                s = "".join(rng.choice("ab xyzAB01-+\t") for _ in range(n))
            lit = json.dumps(s)
            setup.append(f"char {v}a[] = {lit}, {v}b[] = {lit};")
            check.append(f"if (strcmp({v}a, {v}b)) bad++;")
            a.append(f"{v}a")
            b.append(f"{v}b")
            continue
        elif kind in ("pt*", "pt", "rect*", "acc*"):
            st = kind.rstrip("*")
            n = {"pt": 2, "rect": 4, "acc": 3}[st]
            vals = ", ".join(str(rng.randint(-1000, 1000)) for _ in range(n))
            setup.append(f"struct {st} {v}a = {{{vals}}}, {v}b = {{{vals}}};")
            check.append(f"if (memcmp(&{v}a, &{v}b, sizeof {v}a)) bad++;")
            ref = "&" if kind.endswith("*") else ""
            a.append(f"{ref}{v}a")
            b.append(f"{ref}{v}b")
            continue
        elif kind == "list":
            n = rng.randint(0, 8)
            setup.append(f"struct node {v}[9];")
            for i in range(n):
                nxt = f"&{v}[{i + 1}]" if i + 1 < n else "0"
                setup.append(f"{v}[{i}].v = {rng.randint(-1000, 1000)}; {v}[{i}].next = {nxt};")
            a.append(f"{v}" if n else "0")
        else:
            raise ValueError(kind)
        if len(b) < len(a):
            b.extend(a[len(b):])
    return setup, a, b, check


def harness(name: str, seed: int) -> str:
    ret, kinds = EQUIV[name]
    rng = random.Random(f"{name}-{seed}")
    out = ["#include <stdint.h>", "#include <stddef.h>", "#include <string.h>", "#include <stdio.h>",
           "#include <math.h>", STRUCTS]
    sig = {"l": "long", "nz": "long", "u64": "uint64_t", "u32": "uint32_t", "u20": "uint32_t", "m": "uint64_t",
           "i32": "int32_t", "n90": "int", "n20": "int", "clamp": "int, int, int", "day": "int", "chr": "int",
           "op": "int", "ack": "long, long", "d": "double", "arr": "int *, int", "sarr": "int *, int",
           "arr2": "int *, int *, int", "darr": "double *, int", "str": "char *", "num": "char *", "pal": "char *",
           "pt*": "struct pt *", "pt": "struct pt", "rect*": "struct rect *", "acc*": "struct acc *",
           "list": "struct node *"}
    params = ", ".join(sig[k] for k in kinds)
    out.append(f"{ret} {name}({params});")
    out.append("extern char dec_f[];")
    out.append(f"typedef {ret} (*fp_t)({params});")
    out.append("int main(void)\n{\n    fp_t dec = (fp_t)(void *)dec_f;\n    int bad = 0;")
    for k in range(CASES):
        setup, a, b, check = _case(kinds, rng, k)
        out.append("    {")
        out += ["        " + s for s in setup]
        if ret == "void":
            out.append(f"        {name}({', '.join(a)}); dec({', '.join(b)});")
        else:
            out.append(f"        {ret} r1 = {name}({', '.join(a)}), r2 = dec({', '.join(b)});")
            out.append("        if (fabs(r1 - r2) > 1e-9 * fabs(r1) + 1e-12) bad++;" if ret == "double" else
                       "        if (r1 != r2) bad++;")
        out += ["        " + c for c in check]
        out.append("    }")
    out.append('    printf("%d\\n", bad);\n    return 0;\n}')
    return "\n".join(out) + "\n"


def equivalent(text: str, tool: str, name: str, original_o: str, tmp: str) -> tuple[bool, str]:
    """(passed, why not) for one function's pseudocode against the original object."""
    h = header(text)
    if h is None:
        return False, "no function"
    renamed = re.sub(rf"\b{re.escape(h[0])}\b", "dec_f", text)
    got = compile_pseudocode(renamed, tool, tmp)
    if got is None:
        return False, "does not compile"
    with open(os.path.join(tmp, "h.c"), "w") as fp:
        fp.write(harness(name, 1))
    r = subprocess.run(["gcc", "-O0", "-w", "-o", "h", "f.o", "h.c", original_o, "-lm"], cwd=tmp,
                       capture_output=True, text=True, env=ENV)
    if r.returncode != 0:
        missing = re.findall(r"undefined reference to `([^']+)'", r.stderr)
        return False, "link: " + (", ".join(sorted(set(missing))[:4]) if missing else r.stderr.strip()[-120:])
    try:
        r = subprocess.run([os.path.join(tmp, "h")], capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    if r.returncode != 0:
        return False, f"crash ({r.returncode})"
    return r.stdout.strip() == "0", f"{r.stdout.strip()} of {CASES} cases differ"


def build_original(opt: str, cache: str) -> str:
    out = os.path.join(cache, f"equiv{opt}.o")
    subprocess.run(["gcc", opt, "-c", "-w", "-Dmain=equiv_main", os.path.join(HERE, "bench", "equiv.c"), "-o", out],
                   check=True)
    return out


# ------------------------------------------------------------------ scoring
def score(name: str, conf: dict, outputs: dict[str, dict], corpus: str, cache: str) -> dict:
    full = os.path.join(corpus, name)
    names = symbol_names(full)
    src = source_dumps(conf["sources"], cache) if conf.get("sources") else {}
    sigs = dwarf_signatures(conf["debug"]) if conf.get("debug") else {}
    orig_o = build_original(conf["equiv"], cache) if conf.get("equiv") else None
    given = {int(a) for got in outputs.values() for a in got}      # (what the tools were asked for)
    funcs = sorted(a for a in truth(full) if a in given)
    rows: dict[str, dict] = {}
    for tool, got in outputs.items():
        per = {}
        for a in funcs:
            d = got.get(str(a))
            text = d.get("text") if d else None
            fname = names.get(a, "")
            r: dict = {"name": fname, "decompiled": bool(text)}
            if text:
                r["valid_c"] = valid_c(text, tool)
                with tempfile.TemporaryDirectory() as tmp:
                    comp = compile_pseudocode(text, tool, tmp)
                    h = header(text)
                    if comp is not None and h is not None and h[0] in comp[1] and fname in src and "." not in fname:
                        mine, theirs = comp[1][h[0]], src[fname]
                        r["cfg"] = wl_similarity(cfg_graph(theirs[0]), cfg_graph(mine[0]))
                        (g1, n1), (g2, n2) = ssa_graph(theirs[1]), ssa_graph(mine[1])
                        r["dfg"] = wl_similarity(g1, g2)
                        r["vars"] = (n1, n2)
                    if h is not None and a in sigs and "." not in fname:
                        sret, sparams = sigs[a]
                        dparams = [param_type(p) for p in h[2]]
                        dret = c_type(h[1])
                        slots = max(len(sparams), len(dparams))
                        r["types"] = {
                            "slots": slots + 1,
                            "kind": same_kind(sret, dret) + sum(same_kind(s, d) for s, d in zip(sparams, dparams)),
                            "exact": same_exact(sret, dret) + sum(same_exact(s, d) for s, d in zip(sparams, dparams)),
                            "arity": len(sparams) == len(dparams), "ret": same_kind(sret, dret)}
                    if orig_o and fname in EQUIV:
                        ok, why = equivalent(text, tool, fname, orig_o, tmp)
                        r["equiv"], r["equiv_why"] = ok, why
            per[a] = r
        rows[tool] = per
    return rows


def symbol_names(path: str) -> dict[int, str]:
    out = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True).stdout
    names = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 8 and p[3] == "FUNC" and p[6] != "UND":
            names.setdefault(int(p[1], 16), p[7])
    return names


def summarise(rows: dict[str, dict]) -> dict:
    """Per tool: each metric over the functions it applies to; cfg/dfg also over the functions
    every C-producing tool compiled (`common`), so no tool is averaged over easier ones."""
    tools = list(rows)
    c_tools = [t for t in tools if any("cfg" in r for r in rows[t].values())]
    funcs = set.intersection(*(set(rows[t]) for t in tools)) if tools else set()
    common = [a for a in funcs if all("cfg" in rows[t][a] for t in c_tools)]
    out = {}
    for t in tools:
        rs = rows[t]
        eq = [r["equiv"] for r in rs.values() if "equiv" in r]
        eq_all = [r for r in rs.values() if r["name"] in EQUIV]
        cfg = [r["cfg"] for r in rs.values() if "cfg" in r]
        ty = [r["types"] for r in rs.values() if "types" in r]
        var = [r["vars"] for r in rs.values() if "vars" in r]
        out[t] = {
            "functions": len(rs), "decompiled": sum(r["decompiled"] for r in rs.values()),
            "valid_c": sum(bool(r.get("valid_c")) for r in rs.values()),
            "equiv_passed": sum(eq), "equiv_tested": len(eq_all),
            "compiled": len(cfg), "common": len(common),
            "cfg_mean": _mean(cfg), "dfg_mean": _mean([r["dfg"] for r in rs.values() if "dfg" in r]),
            "cfg_common": _mean([rs[a]["cfg"] for a in common if "cfg" in rs[a]]),
            "dfg_common": _mean([rs[a]["dfg"] for a in common if "dfg" in rs[a]]),
            "vars_ratio_median": _median([d / s for s, d in var if s]),
            "type_slots": sum(x["slots"] for x in ty), "type_kind": sum(x["kind"] for x in ty),
            "type_exact": sum(x["exact"] for x in ty), "type_functions": len(ty),
            "arity": sum(x["arity"] for x in ty), "ret": sum(x["ret"] for x in ty)}
    return out


def _mean(xs):
    return round(sum(xs) / len(xs), 4) if xs else None


def _median(xs):
    xs = sorted(xs)
    return round(xs[len(xs) // 2], 3) if xs else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config")
    ap.add_argument("outputs")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--tools", default="relic,angr,ghidra,retdec,r2")
    ap.add_argument("--cache", default=os.path.join(tempfile.gettempdir(), "decomp_quality"))
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    config = json.load(open(args.config))
    result = {}
    for name, conf in config.items():
        outputs = {}
        for tool in args.tools.split(","):
            path = os.path.join(args.outputs, name, f"{tool}.json")
            if os.path.exists(path):
                outputs[tool] = json.load(open(path))
        rows = score(name, conf, outputs, args.corpus, args.cache)
        summary = summarise(rows)
        for tool, s in summary.items():
            print(f"{name:14} {tool:7} {json.dumps(s)}", flush=True)
        result[name] = {"summary": summary, "functions": {t: {str(a): r for a, r in rs.items()}
                                                          for t, rs in rows.items()}}
    if args.json:
        with open(args.json, "w") as fp:
            json.dump(result, fp, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

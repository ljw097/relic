"""Stage 5: render the structured IR as C-like pseudocode.

`decompile(an, func)` runs `pipeline.prepare` and prints the result:

    int checksum(char *a1)
    {
        int var_c;      // ret-0xc
        ...
    }

Every output line carries the address of the instruction it came from, so
the CLI and the GUI can map between pseudocode and disassembly.
"""
from __future__ import annotations

import re

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import ir
from .ir import (Assign, BinOp, CallStmt, Cast, Const, Effect, Expr, Extract, Intrinsic, Ite, Load, Reg, Return,
                 StackAddr, StackVar, Store, UnOp, Unknown, Var)
from .fp import FARITH, FCMP, FP_INTRINSICS
from .fpconst import float_operands, is_float_expr
from .sigs import base_name
from .structure import Block, If, Jump1, Loop, Ret, Seq, Switch, _last, _negate, case_labels
from .vartypes import CType, infer_types, int_type, library_types, parse_ctype

if TYPE_CHECKING:
    from ..analysis import Analysis, Function
    from .pipeline import Prepared


def objc_method(name: str):
    """(`-` / `+`, class, selector) of an Objective-C method's name (`-[Animal speak:times:]`,
    `+[NSString(Extra) foo]`), else None."""
    import re
    m = re.fullmatch(r"([-+])\[([A-Za-z_$][\w$]*)(?:\([^)]*\))? ([^\]\s]+)\]", name)
    return (m.group(1), m.group(2), m.group(3)) if m else None


# SSE / AVX instructions the lifter keeps as intrinsics: the names of Intel's C intrinsics
_SSE = {"padd": "add_epi", "psub": "sub_epi", "padds": "adds_epi", "paddus": "adds_epu", "psubs": "subs_epi",
        "psubus": "subs_epu", "pcmpeq": "cmpeq_epi", "pcmpgt": "cmpgt_epi", "pmaxs": "max_epi", "pmins": "min_epi",
        "pmaxu": "max_epu", "pminu": "min_epu", "pavg": "avg_epu", "pabs": "abs_epi", "psrl": "srli_epi",
        "psll": "slli_epi", "psra": "srai_epi", "punpckl": "unpacklo_epi", "punpckh": "unpackhi_epi"}
_SSE_WIDTH = {"b": "8", "w": "16", "d": "32", "q": "64", "bw": "8", "wd": "16", "dq": "32", "qdq": "64"}
_SSE_FIXED = {"pand": "and_si", "por": "or_si", "pxor": "xor_si", "pandn": "andnot_si", "pmovmskb": "movemask_epi8",
              "psrldq": "srli_si", "pslldq": "slli_si", "pmullw": "mullo_epi16", "pmulld": "mullo_epi32",
              "pmulhw": "mulhi_epi16", "pmulhuw": "mulhi_epu16", "pmuludq": "mul_epu32", "pmaddwd": "madd_epi16",
              "psadbw": "sad_epu8", "pshufd": "shuffle_epi32", "pshufb": "shuffle_epi8", "ptest": "testz_si",
              "packsswb": "packs_epi16", "packssdw": "packs_epi32", "packuswb": "packus_epi16",
              "pshuflw": "shufflelo_epi16", "pshufhw": "shufflehi_epi16", "palignr": "alignr_epi8",
              "movmskps": "movemask_ps", "movmskpd": "movemask_pd", "shufps": "shuffle_ps", "shufpd": "shuffle_pd",
              "unpcklps": "unpacklo_ps", "unpckhps": "unpackhi_ps", "unpcklpd": "unpacklo_pd",
              "unpckhpd": "unpackhi_pd", "andps": "and_ps", "andpd": "and_pd", "orps": "or_ps", "orpd": "or_pd",
              "xorps": "xor_ps", "xorpd": "xor_pd", "andnps": "andnot_ps", "andnpd": "andnot_pd"}
for _op in ("add", "sub", "mul", "div", "min", "max", "sqrt"):
    _SSE_FIXED[_op + "ps"], _SSE_FIXED[_op + "pd"] = f"{_op}_ps", f"{_op}_pd"


def _sse_name(m: str, bits: int) -> str | None:
    """`paddd` -> `_mm_add_epi32`, `vpaddd` on 256 bits -> `_mm256_add_epi32`; None if not one."""
    core = m[1:] if m.startswith("v") and len(m) > 3 else m
    name = _SSE_FIXED.get(core)
    if name is None:
        for stem in sorted(_SSE, key=len, reverse=True):
            if core.startswith(stem) and core[len(stem):] in _SSE_WIDTH:
                name = _SSE[stem] + _SSE_WIDTH[core[len(stem):]]
                break
    if name is None:
        return None
    prefix = "_mm256_" if bits == 256 else "_mm_"
    if name.endswith("_si"):
        name += "256" if bits == 256 else "128"
    return prefix + name


_NUMBER_TYPES = ("size_t", "ssize_t", "int", "unsigned int", "long", "unsigned long", "off_t", "socklen_t",
                 "mode_t", "pid_t", "uid_t", "gid_t", "useconds_t", "time_t")
_OPEN_MODE = {"open": 2, "open64": 2, "openat": 3, "__open_2": 2}     # their (variadic) mode argument
_COPY = re.compile(r"([A-Za-z_]\w*) = ([A-Za-z_]\w*);")


@dataclass
class Line:
    text: str
    addr: int | None = None
    depth: int = 0


@dataclass
class Decompiled:
    name: str
    addr: int
    lines: list[Line] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)   # shown name -> generated name
    structs: dict[str, str] = field(default_factory=dict)     # shown struct name -> generated name
    fields: dict[str, list] = field(default_factory=dict)     # shown field -> [(struct, field), ...]
    types: dict[str, str] = field(default_factory=dict)       # generated variable name -> C type shown

    @property
    def text(self) -> str:
        return "\n".join(("    " * ln.depth + ln.text) if ln.text else "" for ln in self.lines)

    def __str__(self) -> str:
        return self.text

    def lines_at(self, addr: int) -> list[int]:
        """Line numbers produced from the instruction at `addr`."""
        return [k for k, ln in enumerate(self.lines) if ln.addr == addr]


# ----------------------------------------------------------------- constants
def number(v: int) -> str:
    """Decimal when it reads better (small, or rounder in decimal), else hex."""
    if v < 10:
        return str(v)
    dec, hx = str(v), f"{v:x}"
    zeros = lambda s: len(s) - len(s.rstrip("0"))
    return dec if v < 256 or zeros(dec) > zeros(hx) else f"{v:#x}"


def _bare(e: Expr) -> Expr:
    """Strip extensions C performs implicitly (argument passing, return)."""
    while isinstance(e, Cast) and e.kind in ("zext", "sext"):
        e = e.a
    return e


_NUMERIC_OPS = {"*", "/u", "/s", "%u", "%s", "<<", ">>u", ">>s", "&", "|", "^"}

# C precedence, larger binds tighter
PREC_TERNARY, PREC_UNARY, PREC_POSTFIX = 3, 14, 15
BIN = {"||": ("||", 4), "&&": ("&&", 5), "|": ("|", 6), "^": ("^", 7), "&": ("&", 8),
       "==": ("==", 9), "!=": ("!=", 9), "<s": ("<", 10), "<=s": ("<=", 10), "<u": ("<", 10), "<=u": ("<=", 10),
       "<<": ("<<", 11), ">>u": (">>", 11), ">>s": (">>", 11), "+": ("+", 12), "-": ("-", 12),
       "*": ("*", 13), "/u": ("/", 13), "/s": ("/", 13), "%u": ("%", 13), "%s": ("%", 13)}
FLIP = {"<": ">", "<=": ">="}


class CWriter:
    _bf_vars: set[str] = frozenset()     # reads only a bit-field store used: see _bitfield_stores

    def __init__(self, an: "Analysis", prep: "Prepared"):
        self.an = an
        self.p = prep
        self.ptr_bits = prep.arch.bits
        self.types: dict[str, CType] = infer_types(prep.fn, self.ptr_bits, self.is_addr)
        # library calls name what plain integers really are (`strlen(a1)`: a1 is a `char *`); a
        # pointer type recovered from how memory is accessed says more and is kept
        lib_structs: dict[str, str] = {}
        for name, t in library_types(prep.fn, self.ptr_bits, prep.arch.ret, self._callee_name,
                                     lambda a: an.bin.read_cstring(a, 512), an).items():
            cur = self.types.get(name)
            if cur is not None and cur.ptr == 0:
                self.types[name] = t
            elif t.ptr == 1 and t.base.startswith("struct ") and t.base[7:] in an.struct_names and \
                    (cur is None or cur.ptr <= 1 and not cur.base.startswith("struct ")):
                # a prototype's `struct tm *` (with the struct in the project, from a header or
                # a type library) says more than `int *` guessed from the accesses
                self.types[name] = t
                lib_structs[name] = f"{t.base} *"
        # floats and doubles: what floating-point operations read and produce, float parameters
        # and results (fpconst.float_types)
        from .fpabi import callee_ret, fp_params
        from .fpconst import float_types
        from .fpabi import fp_ret_reg
        fparams = dict(fp_params(an, prep.arch, prep.fn.addr))
        self.ftypes = float_types(prep.fn, fparams, prep.ret_float, lambda st: callee_ret(an, st),
                                  fp_ret_reg(prep.arch))
        for name, w in list(self.ftypes.items()):
            cur = self.types.get(name)
            if cur is not None and cur.ptr and name not in fparams:
                del self.ftypes[name]                # dereferenced: a pointer, whatever is copied to it
                continue
            self.types[name] = CType("double" if w == 64 else "float")
        from .fpconst import float_pointees
        for name, w in float_pointees(prep.fn, self.ftypes, self.is_addr).items():
            cur = self.types.get(name)
            if cur is not None and cur.ptr == 1 and cur.base in (int_type(w), int_type(w, True)):
                self.types[name] = CType("double" if w == 64 else "float", 1)
        self.shown_structs: dict[str, str] = {}
        self.shown_fields: dict[str, list] = {}
        self.names: dict[str, str] = {}
        # user names for variables (Analysis.var_names), keyed by the generated name
        self.user: dict[str, str] = dict(an.var_names.get(prep.fn.addr, {}))
        self.shown: dict[str, str] = {}
        self.commented: set[int] = set()
        self.out: list[Line] = []
        self._bf_vars = set()
        self._name_vars()
        if self._is_main():
            self._spread_types([r for r in self.p.params[1:3]])
        # user types (Analysis.var_types, keyed by generated name) -> by the IR's variable names
        wanted = an.var_types.get(prep.fn.addr, {})
        user_types: dict[str, str] = {}
        for name in set(self.types) | set(self.p.params):
            gen = self.names.get(name, name)
            if gen in wanted:
                user_types[name] = wanted[gen]
        for name, t in lib_structs.items():              # (the user's own type still wins)
            user_types.setdefault(name, t)
        # plain copies of a variable the user typed `struct X *` (`var_18 = a1` at -O0) point to X too
        todo = [n for n, t in user_types.items() if t.startswith("struct ") and t.count("*") == 1]
        while todo:
            n = todo.pop()
            for st in prep.fn.stmts():
                if isinstance(st, Assign) and isinstance(st.src, (Var, StackVar)) and st.src.name == n and \
                        isinstance(st.dst, (Var, StackVar)) and st.dst.bits == self.ptr_bits and \
                        st.dst.name not in user_types:
                    user_types[st.dst.name] = user_types[n]
                    todo.append(st.dst.name)
        from .structs import StructView
        self.structs = StructView(an, prep.fn, self.ptr_bits, user_types)
        for name in list(self.types):
            st = self.structs.var_struct(name)
            if st is not None and self.types[name].ptr <= 1:
                self.types[name] = CType(f"struct {self.sname(st)}", 1)
            else:
                ft = self.structs.var_field_type(name)
                if ft is not None and self.types[name].ptr <= 1:
                    self.types[name] = parse_ctype(ft)
        self.notes: list[str] = []
        for name, t in user_types.items():
            try:
                ct = parse_ctype(t)
            except ValueError:
                continue
            st = self.structs.forced.get(name)
            if st is not None:
                self.types[name] = CType(f"struct {self.sname(st)}", 1)
            elif ct.base.startswith("struct "):
                # no struct by that name (yet): keep what was recovered rather than declare one
                self.notes.append(f"// {self.names.get(name, name)}: no struct {ct.base[7:]} to apply "
                                  "(rename a recovered struct to it first)")
            else:
                self.types[name] = ct
        self.ret_type = an.var_types.get(prep.fn.addr, {}).get("@return")
        self._spread_user_types([n for n, t in self.types.items() if t.base.startswith("enum ") and not t.ptr])
        if self.ret_type and self.ret_type.endswith("*"):
            # what is returned is a pointer of that type (`v1 = "idle"; ... return v1;`)
            rt = parse_ctype(self.ret_type)
            for s in prep.fn.stmts():
                if isinstance(s, Return) and s.value is not None and isinstance(_bare(s.value), (Var, StackVar)):
                    v = _bare(s.value)
                    cur = self.types.get(v.name)
                    if v.bits == self.ptr_bits and (cur is None or not cur.ptr):
                        self.types[v.name] = rt
                        self._spread_user_types([v.name])
        # readable names for what the code shows the variables are (varnames.py); the user's win
        self.auto: dict[str, str] = {}
        if getattr(an, "auto_names", True):
            from .varnames import suggest
            self.auto = suggest(self)

    def _spread_user_types(self, names: list[str]):
        """Plain copies of these variables (`var_c = a1` at -O0) and variables they are copied
        from get their type when theirs is a plain integer of the same width."""
        todo = list(names)
        while todo:
            n = todo.pop()
            t = self.types.get(n)
            for st in self.p.fn.stmts():
                if not (isinstance(st, Assign) and isinstance(st.src, (Var, StackVar)) and
                        isinstance(st.dst, (Var, StackVar)) and st.dst.bits == st.src.bits):
                    continue
                other = st.dst.name if st.src.name == n else st.src.name if st.dst.name == n else None
                if other is None or other == n or str(self.types.get(other)) == str(t):
                    continue
                cur = self.types.get(other)
                if cur is None or not cur.ptr and not cur.base.startswith(("struct ", "enum ")) and \
                        cur.base not in ("float", "double"):
                    self.types[other] = t
                    todo.append(other)

    # --------------------------------------------------------------- enums
    def enum_of(self, e: Expr) -> dict[str, int] | None:
        """The enumerators of `e`'s type when it is an imported enum: a variable typed `enum X`
        or a struct field of that type."""
        while isinstance(e, Cast):
            e = e.a
        t = None
        if "types" not in self.__dict__:           # (a bare writer: structure tests)
            return None
        if isinstance(e, (Var, StackVar)):
            ct = self.types.get(e.name)
            if ct is not None and ct.ptr == 0:
                t = ct.base
        elif isinstance(e, Load):
            fa = self.structs.field(e.addr, e.bits)
            if fa is not None:
                t = self.ftype(fa[1], fa[2])
        if t and t.startswith("enum ") and "*" not in t:
            return self.an.enum(t[5:].strip())
        return None

    def enum_value(self, values: dict[str, int] | None, v: int, bits: int = 32) -> str | None:
        """An enumerator for `v` (`RED`), or an OR of flag enumerators (`MODE_A | MODE_C`)."""
        if not values:
            return None
        v &= (1 << bits) - 1
        if v >> (bits - 1):
            v -= 1 << bits
        for name, x in values.items():
            if x == v:
                return name
        flags = [(n, x) for n, x in values.items() if x > 0 and x & (x - 1) == 0]
        if v > 0 and flags and len(flags) == sum(1 for x in values.values() if x):
            parts = [n for n, x in sorted(flags, key=lambda nx: nx[1]) if v & x]
            if sum(values[n] for n in parts) == v:
                return " | ".join(parts)
        return None

    def _enum_text(self, other: Expr, c: Expr) -> str | None:
        if isinstance(c, Const):
            return self.enum_value(self.enum_of(other), c.value, c.bits)
        return None

    # ----------------------------------------------------------- bit-fields
    def _unit_bitfield(self, load: Expr, bit: int, width: int | None) -> str | None:
        """`p->flags` when `load` reads (part of) an imported struct's bit-field storage unit and
        the bits from `bit` (of the load) on, `width` of them (None: up to the load's top), are
        exactly one bit-field."""
        while isinstance(load, Cast):
            load = load.a
        if "structs" not in self.__dict__:
            return None
        if isinstance(load, (Var, StackVar)):            # `v1 = p->unit` read once, used twice
            load = self.structs.defs.get(load.name)
            while isinstance(load, Cast):
                load = load.a
        if not isinstance(load, Load):
            return None
        from .structs import split_addr
        sp = split_addr(load.addr)
        if sp is None:
            return None
        st = self.structs.struct_of(sp[0])
        if st is None:
            return None
        fields = self.an.struct_names.get(st.name, {}).get("bitfields")
        if not fields:
            return None
        width = load.bits - bit if width is None else width
        for f in st.fields.values():
            bfs = fields.get(f.name)
            if bfs and f.offset <= sp[1] < f.end:
                pos = (sp[1] - f.offset) * 8 + bit
                for name, b, w in bfs:
                    if b == pos and w == width and pos + width <= (sp[1] - f.offset) * 8 + load.bits:
                        return f"{self.expr(sp[0], PREC_POSTFIX)}->{name}"
        return None

    def _unit_of(self, e: Expr) -> Load | None:
        """The memory read `e` is (through casts, or a variable set once from it)."""
        while isinstance(e, Cast):
            e = e.a
        if isinstance(e, (Var, StackVar)):
            e = self.structs.defs.get(e.name)
            while isinstance(e, Cast):
                e = e.a
        return e if isinstance(e, Load) else None

    def bitfield_writes(self, s: Store) -> list[str] | None:
        """A store to an imported struct's bit-field storage unit, as one assignment per bit-field
        it changes: `unit = unit & keep | (x & m) << k | c` -> `p->f = x; p->g = c;` (the
        read-modify-write a compiler makes of `p->f = x`). None when it is not exactly that."""
        if "structs" not in self.__dict__:
            return None
        from .structs import split_addr
        sp = split_addr(s.dst)
        st = self.structs.struct_of(sp[0]) if sp is not None else None
        fields = self.an.struct_names.get(st.name, {}).get("bitfields") if st is not None else None
        if not fields:
            return None
        size = s.bits
        # (a container can overlap the next unit: `unsigned int a : 4` then a `short` unit at +2)
        inside, partly = [], []
        for unit in st.fields.values():
            if inside or not fields.get(unit.name) or not unit.offset <= sp[1] < sp[1] + size // 8 <= unit.end:
                continue
            base = (sp[1] - unit.offset) * 8
            near = [(n, b - base, w) for n, b, w in fields[unit.name] if b < base + size and b + w > base]
            partly = [(p, w) for _, p, w in near if p < 0 or p + w > size]   # its bits there must be kept
            inside = [x for x in near if 0 <= x[1] and x[1] + x[2] <= size]
        if not inside:
            return None
        terms: list[Expr] = []

        def flat(e):
            while isinstance(e, Cast) and e.kind in ("low", "zext"):
                e = e.a
            if isinstance(e, BinOp) and e.op == "|":
                flat(e.a)
                flat(e.b)
            else:
                terms.append(e)
        flat(s.src)
        keep, const, values, kept_var = 0, 0, [], None
        full = (1 << size) - 1
        for t in terms:
            if isinstance(t, Const):
                const |= t.value & full
                continue
            if isinstance(t, BinOp) and t.op == "&" and isinstance(t.b, Const):
                old = self._unit_of(t.a)
                if old is not None and old.addr == s.dst and old.bits >= size:
                    if keep:
                        return None
                    keep = t.b.value & full
                    a = t.a
                    while isinstance(a, Cast):
                        a = a.a
                    kept_var = a if isinstance(a, Var) else None
                    continue
            k = 0
            if isinstance(t, BinOp) and t.op == "<<" and isinstance(t.b, Const):
                t, k = t.a, t.b.value
                while isinstance(t, Cast) and t.kind in ("low", "zext"):
                    t = t.a
            if not 0 <= k < size:
                return None
            m = t.b.value if isinstance(t, BinOp) and t.op == "&" and isinstance(t.b, Const) else 0
            if m and m & (m + 1) == 0 and k + m.bit_length() <= size:
                values.append([k, m.bit_length(), t.a, False])
            else:
                values.append([k, size - k, t, False])
        for p, w in partly:
            lo, hi = max(p, 0), min(p + w, size)
            fm = ((1 << (hi - lo)) - 1) << lo
            if keep & fm != fm or const & fm or any(v[0] < hi and v[0] + v[1] > lo for v in values):
                return None
        ptr = self.expr(sp[0], PREC_POSTFIX)
        out = []
        for name, p, w in sorted(inside, key=lambda x: x[1]):
            fm = ((1 << w) - 1) << p
            hits = [v for v in values if v[0] < p + w and v[0] + v[1] > p]
            if keep & fm == fm:
                if hits or const & fm:
                    return None
                continue
            if keep & fm:
                return None                      # part of the field kept, part written
            if not hits:
                out.append(f"{ptr}->{name} = {number((const >> p) & ((1 << w) - 1))};")
                continue
            if len(hits) != 1 or hits[0][0] != p or hits[0][1] != w or const & fm:
                return None
            hits[0][3] = True
            x = hits[0][2]
            while isinstance(x, Cast) and x.kind in ("low", "zext") and x.bits >= w:
                x = x.a
            out.append(f"{ptr}->{name} = {self.expr(_bare(x))};")
        if not out or not all(v[3] for v in values):
            return None
        if kept_var is not None and not self._unit_unchanged(kept_var.name, s, sp):
            return None
        self._bf_kept = kept_var
        return out

    def _unit_unchanged(self, name: str, s: Store, sp) -> bool:
        """No store can change the bytes `s` writes between `name = <them>` and `s`: both in one
        block with no such store between, else no such store anywhere in the function."""
        from .structs import split_addr
        lo, hi = sp[1], sp[1] + s.bits // 8

        def clobbers(o) -> bool:
            if not isinstance(o, Store):
                return False
            op = split_addr(o.dst)
            return op is None or op[0] == sp[0] and op[1] < hi and op[1] + o.bits // 8 > lo
        for b in self.p.fn.blocks.values():
            d = next((k for k, o in enumerate(b.stmts) if isinstance(o, Assign) and isinstance(o.dst, Var)
                      and o.dst.name == name), None)
            w = next((k for k, o in enumerate(b.stmts) if isinstance(o, Store) and o.addr == s.addr
                      and o.dst == s.dst), None)
            if d is not None and w is not None and d < w:
                return not any(clobbers(o) for o in b.stmts[d + 1:w])
        return not any(clobbers(o) for o in self.p.fn.stmts() if not (o.addr == s.addr and o.dst == s.dst))

    def _drop_unit_reads(self):
        """`v1 = *(char *)a1;` read once for bit-fields that are all shown as `a1->version`,
        `a1->ihl`: the variable is left only in its declaration and that assignment -- drop both."""
        if not any(d.get("bitfields") for d in self.an.struct_names.values()):
            return
        from .structs import split_addr
        for st in self.p.fn.stmts():
            if not (isinstance(st, Assign) and isinstance(st.dst, Var) and st.dst.name in self.names):
                continue
            ld = st.src
            while isinstance(ld, Cast):
                ld = ld.a
            sp = split_addr(ld.addr) if isinstance(ld, Load) else None
            u = self.structs.struct_of(sp[0]) if sp is not None else None
            if u is None or not self.an.struct_names.get(u.name, {}).get("bitfields"):
                continue
            name = self.vname(st.dst.name)
            word = re.compile(rf"\b{re.escape(name)}\b")
            hits = [k for k, ln in enumerate(self.out) if word.search(ln.text)]
            if len(hits) != 2:
                continue
            decl, asg = (self.out[k].text for k in hits)
            if decl.endswith((f" {name};", f"*{name};")) and asg.startswith(f"{name} = "):
                for k in reversed(hits):
                    del self.out[k]
        # declarations all gone: no blank line under the brace
        if len(self.out) > 2 and self.out[1].text == "{" and self.out[2].text == "" and self.out[2].depth == 1:
            del self.out[2]

    def _bitfield_stores(self):
        """Find the stores `bitfield_writes` shows as field assignments (before the body is
        written), and hide the read of the old unit when that store was its only use (`v1 =
        *(char *)(p + 3)` at -O2)."""
        if not any(d.get("bitfields") for d in self.an.struct_names.values()):
            return
        stmts = list(self.p.fn.stmts())
        uses: dict[str, int] = {}
        for s in stmts:
            for top in ir.stmt_exprs(s):
                for x in ir.walk(top):
                    if isinstance(x, Var):
                        uses[x.name] = uses.get(x.name, 0) + 1
        for s in stmts:
            if isinstance(s, Store):
                self._bf_kept = None
                if self.bitfield_writes(s) is not None:
                    if self._bf_kept is not None and uses.get(self._bf_kept.name) == 1:
                        self._bf_vars.add(self._bf_kept.name)

    def _bit_unit(self, st, f) -> bool:
        """`f` is the storage of bit-fields (C has no name for it, nor its address): memory there
        that is not one bit-field is shown as plain memory."""
        return f is not None and bool(self.an.struct_names.get(st.name, {}).get("bitfields", {}).get(f.name))

    def bitfield(self, e: Expr) -> str | None:
        """A read of one bit-field: `(unit >> k) & (2^w - 1)`, `unit & (2^w - 1)`, `unit >> k`
        (the top bits)."""
        while isinstance(e, Cast) and e.kind in ("low", "zext"):
            e = e.a
        if isinstance(e, BinOp) and e.op == "&" and isinstance(e.b, Const):
            m = e.b.value & ((1 << e.b.bits) - 1)
            if m and m & (m + 1) == 0:
                x = e.a
                while isinstance(x, Cast) and x.kind in ("low", "zext"):
                    x = x.a
                if isinstance(x, BinOp) and x.op in (">>u", ">>s") and isinstance(x.b, Const):
                    return self._unit_bitfield(x.a, x.b.value, m.bit_length())
                return self._unit_bitfield(x, 0, m.bit_length())
        if isinstance(e, BinOp) and e.op == ">>u" and isinstance(e.b, Const):
            return self._unit_bitfield(e.a, e.b.value, e.bits - e.b.value)
        return None

    # ------------------------------------------------------------- structs
    def sname(self, st) -> str:
        shown = self.an.struct_names.get(st.name, {}).get("name") or st.name
        self.shown_structs[shown] = st.name
        return shown

    def ftype(self, st, f) -> str | None:
        """The user's type of a field; a struct it names is shown by its current name."""
        t = self.structs.field_type(st, f)
        if t and t.startswith("struct "):
            target = self.structs.find(t[7:].rstrip(" *"))
            if target is not None:
                return f"struct {self.sname(target)} " + "*" * t.count("*")
        return t

    def fname(self, st, f) -> str:
        shown = self.an.struct_names.get(st.name, {}).get("fields", {}).get(f.name) or f.name
        pairs = self.shown_fields.setdefault(shown, [])
        if (st.name, f.name) not in pairs:
            pairs.append((st.name, f.name))
        return shown

    # ------------------------------------------------------------- naming
    MAIN_PARAMS = (("argc", "int"), ("argv", "char **"), ("envp", "char **"))

    def _is_main(self) -> bool:
        return base_name(self.an.name(self.p.fn.addr) or self.p.fn.name) == "main"

    def _spread_types(self, names: list[str]):
        """Copies of these variables (`var_28 = argv`) get their type."""
        todo = list(names)
        while todo:
            n = todo.pop()
            t = self.types.get(n)
            for st in self.p.fn.stmts():
                if isinstance(st, Assign) and isinstance(st.src, (Var, StackVar)) and st.src.name == n and \
                        isinstance(st.dst, (Var, StackVar)) and st.dst.bits == st.src.bits and \
                        str(self.types.get(st.dst.name)) != str(t):
                    cur = self.types.get(st.dst.name)
                    if cur is None or cur.base in (int_type(self.ptr_bits), "char", "int") and cur.ptr <= 1:
                        self.types[st.dst.name] = t
                        todo.append(st.dst.name)

    def _name_vars(self):
        main = self._is_main() and len(self.p.params) <= 3
        for k, r in enumerate(self.p.params):
            self.names[r] = self.MAIN_PARAMS[k][0] if main else f"a{k + 1}"
            if main:
                self.types[r] = parse_ctype(self.MAIN_PARAMS[k][1])
        m = objc_method(self.an.name(self.p.fn.addr) or "")
        if m is not None and len(self.p.params) >= 2:
            # an Objective-C method: the receiver and the selector come first
            kind, cls, _sel = m
            self.names[self.p.params[0]], self.names[self.p.params[1]] = "self", "_cmd"
            self.types[self.p.params[0]] = CType(cls, 1) if kind == "-" else CType("Class")
            self.types[self.p.params[1]] = CType("SEL")
        n = 0
        for s in self.p.fn.stmts():
            if id(s) in self.p.hidden:
                continue
            for d in ir.stmt_defs(s):
                if isinstance(d, Var) and d.name.startswith("_v") and d.name not in self.names:
                    n += 1
                    self.names[d.name] = f"v{n}"

    def _find_stack_structs(self):
        """Stack slots whose address a call takes as a `struct S *` (a prototype, or a function
        the user typed) with S in the project: `struct stat buf_a8;`, and the stack variables
        inside it read as its fields (`buf_a8.st_size`)."""
        self.stack_structs: dict[int, tuple[str, int]] = {}     # slot offset -> (struct, size)
        self.stack_fields: dict[str, str] = {}                  # inner slot name -> `base.field`
        self._inner_slots: set[str] = set()
        if not self.an.struct_names:
            return
        from .sigs import lookup
        for st in self.p.fn.stmts():
            for top in ir.stmt_exprs(st):
                for c in ir.walk(top):
                    if not isinstance(c, ir.Call):
                        continue
                    sig = lookup(self._callee_name(c), self.an)
                    types = list(sig.types) if sig is not None else []
                    if isinstance(c.target, Const) and c.target.value in self.an.functions:
                        wanted = self.an.var_types.get(c.target.value) or {}
                        types = types or [wanted.get(f"a{k + 1}", "") for k in range(len(c.args))]
                    for k, a in enumerate(c.args):
                        t = types[k] if k < len(types) else ""
                        if isinstance(a, StackAddr) and t.startswith("struct ") and t.count("*") == 1:
                            name = t[7:].replace("*", "").strip()
                            entry = self.an.struct_names.get(name)
                            m = re.search(r"(\d+) bytes", (entry or {}).get("decl", [""])[0]) if entry else None
                            if m:
                                self.stack_structs[a.offset] = (name, int(m.group(1)))
        for base, (name, size) in self.stack_structs.items():
            entry = self.an.struct_names[name]
            base_slot = self.p.frame.slots.get(base)
            if base_slot is None:
                continue
            for off, sl in self.p.frame.slots.items():
                rel = off - base
                if off == base or not 0 < rel < size or sl.kind not in ("local", "buffer"):
                    continue
                self._inner_slots.add(sl.name())
                lay = entry.get("layout", {}).get(f"{rel:#x}")
                if lay and lay[0] == sl.width * 8:
                    field = entry["fields"].get(f"f_{rel:x}", f"f_{rel:x}")
                    self.stack_fields[sl.name()] = f"{base_slot.name()}.{field}"

    def vname(self, name: str) -> str:
        """Display name of a variable: the user's name, else the generated one (`v3`, `a1`, `var_c`)."""
        field = self.__dict__.get("stack_fields", {}).get(name)
        if field is not None:                        # a field of a stack struct: `buf_a8.st_size`
            base, _, rest = field.partition(".")
            return f"{self.vname(base)}.{rest}"
        gen = self.names.get(name, name)
        shown = self.user.get(gen) or self.__dict__.get("auto", {}).get(gen, gen)
        self.shown[shown] = gen
        return shown

    # -------------------------------------------------------- expressions
    def symbol(self, v: int) -> str | None:
        if not v:
            return None
        n = self.an.name(v)
        if n and "(" in n:                      # demangled C++: `Cls::method(int)` -> `Cls::method`
            from ..demangle import short_name
            n = short_name(n)
        return base_name(n) if n else None

    def _user_format(self, c: Const) -> str | None:
        """The number as the user chose to show it (H / R / B on the number), keyed by the value as shown."""
        if not self.an.num_formats:
            return None
        v = c.value
        nums = self.an.num_formats.get(self.p.fn.addr, {})
        shown = c.signed if c.bits >= 8 and v >> (c.bits - 1) and c.signed > -0x10000 else v
        fmt = nums.get(str(shown)) or nums.get(str(v))
        if fmt is None:
            return None
        from ..numfmt import format_number
        return format_number(v, fmt, c.bits)

    def const(self, c: Const) -> str:
        v = c.value
        text = self._user_format(c)
        if text is not None:
            return text
        if c.bits == self.ptr_bits and v and self.an.bin.is_mapped(v):
            lit = self.string(v)
            if lit is not None:
                return lit
            sym = self.symbol(v)
            if sym:
                return sym if v in self.an.functions else f"&{sym}"
        if c.bits == self.ptr_bits and v:
            inside = self._inside_object(v)
            if inside is not None:                # in or just past a data object (an end pointer)
                return f"(char *)&{inside[0]} + {number(inside[1])}"
        if c.bits >= 8 and v >> (c.bits - 1) and c.signed > -0x10000:
            return "-" + number(-c.signed)
        return number(v)

    def _inside_object(self, v: int) -> tuple[str, int] | None:
        """(object symbol, offset) for an address inside a sized data object or one past its
        end (`&pool[4]`, a loop's end pointer)."""
        objs = self.__dict__.get("_objs")
        if objs is None:
            import bisect
            objs = sorted((s.addr, s.size, s.name) for s in self.an.bin.symbols.values()
                          if s.kind == "object" and s.size)
            self._objs = objs
            self._obj_starts = [o[0] for o in objs]
            self._bisect = bisect
        k = self._bisect.bisect_left(self._obj_starts, v) - 1
        if k < 0:
            return None
        a, size, name = self._objs[k]
        if a < v <= a + size:
            return base_name(self.an.name(a) or name), v - a
        return None

    def string(self, v: int) -> str | None:
        from ..analysis.strings import escape
        from .refs import _kind
        s = self.an.string_at(v)
        if s is not None:
            return f'"{escape(s.value)}"'
        # other literals (short ones the string scan skips: "> ", "%d") must start a string:
        # a NUL before them -- not the middle of one, which a small integer in a PIE often hits
        prev = self.an.bin.read(v - 1, 1)
        if prev != b"\0":
            return None
        if _kind(self.an, v) == "string":
            return f'"{escape(self.an.bin.read_cstring(v, 256))}"'
        sec = self.an.bin.section_at(v)
        if sec is not None and sec.loaded and not sec.x and not getattr(sec, "w", False):
            text = self.an.bin.read_cstring(v, 256)
            if text and text.isprintable():
                return f'"{escape(text)}"'
        return None

    def _declared_string(self, v: int) -> str | None:
        from ..analysis.strings import escape
        sec = self.an.bin.section_at(v)
        if sec is None or not sec.loaded or sec.x:
            return None
        text = self.an.bin.read_cstring(v, 256)
        return f'"{escape(text)}"' if text and all(ch.isprintable() or ch in "\n\t\r" for ch in text) else None

    def _num(self, c: Const) -> str:
        if c.bits >= 8 and c.value >> (c.bits - 1) and c.signed > -0x10000:
            return "-" + number(-c.signed)
        return number(c.value)

    def is_addr(self, v: int) -> bool:
        return bool(v) and self.an.bin.is_mapped(v) and v >= 0x100

    def mem(self, addr: Expr, bits: int) -> str:
        """An lvalue/rvalue for the `bits`-wide memory at `addr`."""
        size = bits // 8
        if isinstance(addr, Const):
            sym = self.symbol(addr.value)
            if sym:
                # the first element of an array object (`pool[0]`): the bare name is the array
                s = self.an.bin.symbols.get(addr.value)
                if s is not None and s.kind == "object" and s.size > size and s.size % size == 0:
                    return f"{sym}[0]"
                return sym
            # a GOT slot read on its own (kept in a register): the address of the import
            imp = self.an.bin.imports_by_got.get(addr.value)
            if imp is not None and imp.name and bits == self.an.bin.bits:
                return f"&{base_name(imp.name)}"
            if self.string(addr.value) is not None and not self.an.string_at(addr.value):
                # data read whole that happens to look like text (a stripped `stdout`'s
                # pointer bytes): an address, not a string literal
                return f"*({int_type(bits)} *){number(addr.value)}"
        if isinstance(addr, Load) and isinstance(addr.addr, Const):
            # through a GOT slot: `*(*(stdout@got))` is the imported object itself
            imp = self.an.bin.imports_by_got.get(addr.addr.value)
            if imp is not None and imp.name:
                return base_name(imp.name)
        if isinstance(addr, StackAddr) and addr.offset in self.__dict__.get("stack_structs", {}):
            entry = self.an.struct_names[self.stack_structs[addr.offset][0]]   # its first field
            lay = entry.get("layout", {}).get("0x0")
            if lay and lay[0] == bits:
                return f"{self.vname(addr.name)}.{entry['fields'].get('f_0', 'f_0')}"
        ivar = self._objc_ivar(addr)
        if ivar is not None:
            return ivar
        fa = self.structs.field(addr, bits)
        if fa is not None and not self._bit_unit(*fa[1:]):
            return f"{self.expr(fa[0], PREC_POSTFIX)}->{self.fname(*fa[1:])}"
        ar = self.structs.array_ref(addr, bits)
        if ar is not None:
            base, st, f, idx = ar
            return f"{self.expr(base, PREC_POSTFIX)}->{self.fname(st, f)}[{self.expr(_bare(idx))}]"
        if self.an.bin.endian == "little":
            pa = self.structs.part_of_field(addr, bits)
            if pa is not None and not self._bit_unit(*pa[1:]):     # the low bytes of a wider field
                return f"*({int_type(bits)} *)&{self.expr(pa[0], PREC_POSTFIX)}->{self.fname(*pa[1:])}"
        idx = self._indexed(addr, size)
        if idx is not None:
            base, i = idx
            return f"{base}[{self.expr(i)}]"
        if isinstance(addr, BinOp) and addr.op == "+" and isinstance(addr.a, StackAddr) and \
                isinstance(addr.b, Const) and addr.b.value % size == 0:
            slot = self.p.frame.slots.get(addr.a.offset)
            if slot is not None and slot.kind != "buffer" and \
                    addr.a.offset not in self.__dict__.get("stack_structs", {}):
                # a word of a wider local (`((int *)&var_20)[1]`: the high half of a double)
                return f"(({int_type(bits)} *)&{self.vname(addr.a.name)})[{addr.b.value // size}]"
        base = addr if isinstance(addr, (Var, StackVar)) else None
        if base is not None:
            t = self.types.get(base.name)
            if t is not None and t.ptr == 1 and (t.base == int_type(bits) or self._float_of(t.base, bits)) \
                    or t is not None and t.ptr >= 2 and bits == self.ptr_bits:
                return f"*{self.expr(base, PREC_UNARY)}"
        return f"*({int_type(bits)} *){self.expr(addr, PREC_UNARY)}"

    @staticmethod
    def _float_of(base: str, bits: int) -> bool:
        return base == "double" and bits == 64 or base == "float" and bits == 32

    def _indexed(self, addr: Expr, size: int):
        """(base text, index) for `base + i*size` where base is a symbol or a matching pointer."""
        if not (isinstance(addr, BinOp) and addr.op == "+"):
            return None
        for base, off in ((addr.a, addr.b), (addr.b, addr.a)):
            i = None
            if isinstance(off, BinOp) and off.op == "*" and isinstance(off.b, Const) and off.b.value == size:
                i = off.a
            elif isinstance(off, BinOp) and off.op == "<<" and isinstance(off.b, Const) and 1 << off.b.value == size:
                i = off.a
            elif size == 1 and not isinstance(off, Const):
                i = off
            elif isinstance(off, Const) and off.value % size == 0 and self._ptr_size(base) == size:
                i = Const(off.value // size, off.bits)
            if i is None:
                continue
            if isinstance(base, Const):
                sym = self.symbol(base.value)
                if sym:
                    return sym, _bare(i)
            if isinstance(base, (Var, StackVar)):
                t = self.types.get(base.name)
                if t is not None and t.ptr == 1 and (t.base == int_type(size * 8) or self._float_of(t.base, size * 8)) \
                        or t is not None and t.ptr >= 2 and size * 8 == self.ptr_bits:
                    return self.vname(base.name), _bare(i)
            if isinstance(base, StackAddr):
                return self.vname(base.name), _bare(i)
        return None

    def expr(self, e: Expr, prec: int = 0) -> str:
        text, p = self._expr(e)
        return f"({text})" if p < prec else text

    # ------------------------------------------------------------ floating point
    def _float_var(self, e: Expr) -> bool:
        return isinstance(e, (Var, StackVar)) and e.name in self.ftypes

    def _unwrap_float(self, e: Expr, loose: bool = False) -> Expr:
        """`low64(x)` / `zext128(x)` around a float: C sees just the float. `loose`: where a float
        is expected anyway, also around constants and memory."""
        while isinstance(e, Cast) and e.kind in ("low", "zext") and (
                self._float_var(e.a) or is_float_expr(e.a) or
                loose and isinstance(e.a, (Cast, Const, Load))):
            e = e.a
        return e

    def fexpr(self, e: Expr, prec: int = 0, bits: int | None = None) -> str:
        """`e` where a float of `bits` (default: its width) is expected: constants are literals,
        memory is read as `double` / `float`."""
        w = bits or e.bits
        if self.p.arch.name == "arm-aapcs-vfp":
            sp = self._vfp_param(e)
            if sp is not None:
                return self.vname(sp)
        e = self._unwrap_float(e, True)
        if isinstance(e, Const):
            from .fp import literal
            v = literal(e.value & ((1 << min(w, 64)) - 1), 32 if w == 32 else 64)
            return f"({v})" if v.startswith("-") and prec > PREC_UNARY else v
        if isinstance(e, Load) and e.bits in (32, 64):
            from .fpconst import _ro_value
            c = _ro_value(self.an, e)
            if c is not None and self.symbol(e.addr.value) is None:      # a constant in .rodata
                return self.fexpr(c, prec, e.bits)
            text = self.mem(e.addr, e.bits)
            ft = "double" if e.bits == 64 else "float"
            raw = f"*({int_type(e.bits)} *)"
            if text.startswith(raw):
                text = f"*({ft} *)" + text[len(raw):]
            return f"({text})" if prec > PREC_UNARY and text.startswith("*") else text
        return self.expr(e, prec)

    _FCMP_C = {"f<": "<", "f<=": "<=", "f==": "==", "f!=": "!=", "f<u": "<", "f<=u": "<=", "f==u": "==",
               "f!=o": "!="}
    _FARITH_C = {"f+": ("+", 12), "f-": ("-", 12), "f*": ("*", 13), "f/": ("/", 13)}
    _FCASTS = {"sitofp", "uitofp", "fptosi", "fptoui", "fpconv"}

    def _fbinop(self, e: BinOp) -> tuple[str, int]:
        if e.op in self._FARITH_C:
            op, p = self._FARITH_C[e.op]
            return f"{self.fexpr(e.a, p)} {op} {self.fexpr(e.b, p + 1)}", p
        if e.op in ("funord", "ford"):
            text = f"isunordered({self.fexpr(e.a)}, {self.fexpr(e.b)})"
            return (text, PREC_POSTFIX) if e.op == "funord" else (f"!{text}", PREC_UNARY)
        if e.op in ("f<u", "f<=u"):
            # unordered or less (than or equal): exactly "not greater (than or equal)" in C, NaN included
            neg = ">=" if e.op == "f<u" else ">"
            return f"!({self.fexpr(e.a, 10)} {neg} {self.fexpr(e.b, 11)})", PREC_UNARY
        a, b, op = e.a, e.b, self._FCMP_C[e.op]
        if isinstance(self._unwrap_float(a), Const) and not isinstance(self._unwrap_float(b), Const):
            a, b, op = b, a, FLIP.get(op, op)
        elif op in ("<", "<="):                   # `b < a` reads better as `a > b` when a is a name
            if not isinstance(self._unwrap_float(a), (Var, StackVar)) and \
                    isinstance(self._unwrap_float(b), (Var, StackVar)):
                a, b, op = b, a, FLIP[op]
        return f"{self.fexpr(a, 10)} {op} {self.fexpr(b, 11)}", 10

    def _fintrinsic(self, e: Intrinsic) -> tuple[str, int]:
        x = e.args[0]
        if e.name in ("sitofp", "uitofp"):
            t = "double" if e.bits == 64 else "float"
            if e.name == "sitofp" and isinstance(x, Cast) and x.kind == "zext" and x.a.bits < x.bits:
                # a zero-extended narrower integer converted as a signed wider one: an unsigned one
                inner = self.expr(_bare(x.a), PREC_UNARY)
                if not self._unsigned(x.a):
                    inner = f"({int_type(x.a.bits, True)}){inner}"
                return f"({t}){inner}", PREC_UNARY
            inner = self.expr(_bare(x), PREC_UNARY)
            if e.name == "uitofp" and not self._unsigned(x):
                inner = f"({int_type(x.bits, True)}){inner}"
            return f"({t}){inner}", PREC_UNARY
        if e.name in ("fptosi", "fptoui"):
            return f"({int_type(e.bits, e.name == 'fptoui')}){self.fexpr(x, PREC_UNARY)}", PREC_UNARY
        if e.name == "fpconv":
            t = "double" if e.bits == 64 else "float"
            if isinstance(x, (Var, StackVar)) and self.ftypes.get(x.name) == e.bits:
                return self._expr(x)               # (PowerPC: a float variable held as a double)
            return f"({t}){self.fexpr(x, PREC_UNARY)}", PREC_UNARY
        return f"{e.name}({', '.join(self.fexpr(a) for a in e.args)})", PREC_POSTFIX

    def _vfp_param(self, e: Expr) -> str | None:
        """ARM hard-float: `low32(d1)` / the high half of `d1` read on entry is the float
        parameter passed in s2 / s3."""
        if isinstance(e, Var) and e.bits == 32:                 # narrowed to the float it holds
            v, odd = e, 0
        elif isinstance(e, Cast) and e.kind == "low" and e.bits == 32:
            v, odd = e.a, 0
        elif isinstance(e, Extract) and e.lo == 32 and e.bits == 32:
            v, odd = e.a, 1
        else:
            return None
        if isinstance(v, Var) and v.name[:1] == "d" and v.name[1:].isdigit():
            s = f"s{2 * int(v.name[1:]) + odd}"
            if s in self.p.params:
                return s
        return None

    def _double_word(self, e: Expr) -> str | None:
        """A word of a double variable's bits (RV32 copies doubles through core registers a word at
        a time): `((unsigned int *)&x)[0]`, the low word on a little-endian target."""
        if e.bits != 32 or self.p.arch.bits != 32:
            return None
        if isinstance(e, Cast) and e.kind == "low":
            x, hi = e.a, False
            if isinstance(x, BinOp) and x.op == ">>u" and isinstance(x.b, Const) and x.b.value == 32:
                x, hi = x.a, True
        elif isinstance(e, Extract) and e.lo == 32:
            x, hi = e.a, True
        else:
            return None
        if not (isinstance(x, (Var, StackVar)) and x.bits == 64 and self.ftypes.get(x.name) == 64):
            return None
        k = int(hi) ^ (getattr(self.an.bin, "endian", "little") == "big")
        return f"((unsigned int *)&{self.vname(x.name)})[{k}]"

    def _expr(self, e: Expr) -> tuple[str, int]:
        if isinstance(e, (Cast, Extract, Var)) and self.p.arch.name == "arm-aapcs-vfp":
            s = self._vfp_param(e)
            if s is not None:
                return self.vname(s), PREC_POSTFIX
        half = self._double_word(e)
        if half is not None:
            return half, PREC_POSTFIX
        if isinstance(e, Cast) and e.kind in ("low", "zext") and self._unwrap_float(e) is not e:
            return self._expr(self._unwrap_float(e))
        if isinstance(e, Const):
            return self.const(e), PREC_POSTFIX
        if isinstance(e, Var):
            return self.vname(e.name), PREC_POSTFIX
        if isinstance(e, Reg):
            return e.name, PREC_POSTFIX
        if isinstance(e, StackVar):
            return self.vname(e.name), PREC_POSTFIX
        if isinstance(e, StackAddr):
            slot = self.p.frame.slots.get(e.offset)
            if e.offset in self.__dict__.get("stack_structs", {}):
                return f"&{self.vname(e.name)}", PREC_UNARY
            if slot is not None and slot.kind == "buffer":
                return self.vname(e.name), PREC_POSTFIX
            return f"&{self.vname(e.name)}", PREC_UNARY
        if isinstance(e, Load):
            text = self.mem(e.addr, e.bits)
            return text, PREC_UNARY if text.startswith("*") else PREC_POSTFIX
        if isinstance(e, BinOp):
            return self._binop(e)
        if isinstance(e, UnOp):
            if e.op == "!":
                neg = _negate(e.a)
                if not (isinstance(neg, UnOp) and neg.op == "!"):
                    return self._expr(neg)
            if e.op == "fneg":
                return f"-{self.fexpr(e.a, PREC_UNARY)}", PREC_UNARY
            return f"{e.op}{self.expr(e.a, PREC_UNARY)}", PREC_UNARY
        if isinstance(e, Cast):
            if e.a.bits == 1:                     # bool widened to an int: C does this already
                return self._expr(e.a)
            t = int_type(e.bits, e.kind == "zext")
            if e.kind == "zext" and e.a.bits in (8, 16, 32) and e.a.bits < e.bits and not self._unsigned(e.a) \
                    and not isinstance(e.a, Const):
                # C widens a signed value with its sign: zero-extend through the unsigned type
                inner = e.a.a if isinstance(e.a, Cast) and e.a.kind == "low" else e.a
                return f"({t})({int_type(e.a.bits, True)}){self.expr(inner, PREC_UNARY)}", PREC_UNARY
            return f"({t}){self.expr(e.a, PREC_UNARY)}", PREC_UNARY
        if isinstance(e, Extract):
            inner = self.expr(e.a, 11)
            return f"({int_type(e.bits, True)})({inner} >> {e.lo})", PREC_UNARY
        if isinstance(e, Ite) and e.bits == 1 and (isinstance(e.a, Const) or isinstance(e.b, Const)):
            from .passes import bool_ite
            return self._expr(bool_ite(e))            # `c ? x : 0` reads `c && x`
        if isinstance(e, Ite):
            fl = float_operands(e)
            sub = self.fexpr if fl else self.expr
            return (f"{self.expr(e.cond, PREC_TERNARY + 1)} ? {sub(e.a, PREC_TERNARY + 1)} : "
                    f"{sub(e.b, PREC_TERNARY)}"), PREC_TERNARY
        if isinstance(e, Intrinsic) and (e.name in self._FCASTS or e.name in FP_INTRINSICS):
            return self._fintrinsic(e)
        if isinstance(e, Intrinsic):
            name = _sse_name(e.name, e.bits) or f"__{e.name}"
            return f"{name}({', '.join(self.expr(a) for a in e.args)})", PREC_POSTFIX
        if isinstance(e, ir.Call):
            return self.call(e), PREC_POSTFIX
        return str(e), PREC_POSTFIX

    def _binop(self, e: BinOp) -> tuple[str, int]:
        bf = self.bitfield(e) if e.op in ("&", ">>u") else None
        if bf is not None:                        # `p->ihl`
            return bf, PREC_POSTFIX
        if e.op in ("==", "!=") and isinstance(e.b, Const) and isinstance(e.a, BinOp) and e.a.op == "&" and \
                isinstance(e.a.b, Const):
            # `(unit & 0xe0) == 0x40`: the bit-field there compared with 2
            m = e.a.b.value & ((1 << e.a.b.bits) - 1)
            low = (m & -m).bit_length() - 1 if m else 0
            run = m >> low
            if m and run & (run + 1) == 0 and e.b.value & ~m & ((1 << e.b.bits) - 1) == 0:
                bf = self._unit_bitfield(e.a.a, low, run.bit_length())
                if bf is not None:
                    op = BIN[e.op][0]
                    return f"{bf} {op} {number(e.b.value >> low)}", BIN[e.op][1]
        if e.op == "+" and e.bits == self.ptr_bits:
            fa = self.structs.field_addr(e)
            if fa is not None and not self._bit_unit(*fa[1:]):     # the address of a field: `&p->f_8`
                return f"&{self.expr(fa[0], PREC_POSTFIX)}->{self.fname(*fa[1:])}", PREC_UNARY
        if e.op[0] == "f" and (e.op in FARITH or e.op in FCMP):
            return self._fbinop(e)
        if e.op not in BIN:                       # carry / sborrow ... : flag helpers
            return f"__{e.op}({self.expr(e.a)}, {self.expr(e.b)})", PREC_POSTFIX
        if e.op in _NUMERIC_OPS:
            # operands of *, /, %, shifts and bit operations are numbers, never addresses
            a = Const(e.a.value, e.a.bits) if isinstance(e.a, Const) else e.a
            b = e.b
            if isinstance(a, Const) or isinstance(b, Const):
                op, p = BIN[e.op]
                flag = self._enum_text(b, a) or None if e.op in ("&", "|", "^") else None
                ta = flag if flag else self._num(a) if isinstance(a, Const) else self.expr(a, p)
                if e.op in ("/u", "%u", ">>u") and not isinstance(a, Const) and a.bits in (8, 16, 32, 64) and \
                        not self._unsigned(a) and isinstance(a, Cast):
                    # an unsigned operation on a narrowed signed value: C needs the unsigned type
                    ta = f"(unsigned {int_type(a.bits)}){self.expr(a.a if a.kind == 'low' else a, PREC_UNARY)}" \
                        if a.bits in (8, 16, 32) else f"({int_type(a.bits, True)}){self.expr(a, PREC_UNARY)}"
                flag = self._enum_text(a, b) if e.op in ("&", "|", "^") else None
                tb = flag if flag else self._num(b) if isinstance(b, Const) else self.expr(b, p + 1)
                return f"{ta} {op} {tb}", p
        op, p = BIN[e.op]
        a, b = e.a, e.b
        if e.op in ("==", "!=") and isinstance(b, Const) and b.value == 0 and isinstance(a, BinOp) and \
                a.op == "&" and isinstance(a.b, Const) and a.b.value == 1 and isinstance(a.a, BinOp) and \
                a.a.op in (">>u", ">>s") and isinstance(a.a.b, Const):
            # a bit test (`tbz`) of a flag: `((o >> 2) & 1) != 0` is `(o & OPT_DRY) != 0`
            x, k = a.a.a, a.a.b.value
            name = self.enum_value(self.enum_of(x), 1 << k) if k < 31 else None
            if name is not None and " " not in name:
                return f"({self.expr(x, 8)} & {name}) {op} 0", p
        if p in (9, 10):                                            # `state == RUNNING`
            x, y = (b, a) if isinstance(a, Const) and not isinstance(b, Const) else (a, b)
            name = self._enum_text(x, y)
            if name is not None:
                op2 = FLIP.get(op, op) if x is not a else op
                return f"{self.expr(x, p)} {op2} {name if ' ' not in name else f'({name})'}", p
        if p == 10:
            if isinstance(a, Const) and not isinstance(b, Const):   # `5 < x` reads as `x > 5`
                a, b, op = b, a, FLIP[op]
            if e.op.endswith("u") and not self._unsigned(a):
                left = f"(unsigned {int_type(a.bits)}){self.expr(a, PREC_UNARY)}" if a.bits in (8, 16, 32) \
                    else f"({int_type(a.bits, True)}){self.expr(a, PREC_UNARY)}"
                return f"{left} {op} {self.expr(b, p + 1)}", p
        if e.op in ("+", "-") and (self._struct_ptr(a) or e.op == "+" and self._struct_ptr(b)):
            # a byte offset from a struct pointer (not a field: a loop's end pointer, say)
            if self._struct_ptr(b) and not self._struct_ptr(a):
                a, b = b, a
            return f"(char *){self.expr(a, PREC_UNARY)} {op} {self.expr(b, p + 1)}", p
        if e.op in ("+", "-"):
            ptr = self._scaled(a, b)
            if ptr is not None:
                b = ptr
            elif e.op == "+" and self._ptr_size(b) and not self._ptr_size(a):
                ptr = self._scaled(b, a)
                if ptr is not None:
                    a, b = b, ptr
                elif self._ptr_size(b) > 1:     # (a byte offset that is not a whole element)
                    return f"(char *){self.expr(b, PREC_UNARY)} + {self.expr(a, p + 1)}", p
            elif self._ptr_size(a) > 1:   # byte offset that is not a whole element
                return f"(char *){self.expr(a, PREC_UNARY)} {op} {self.expr(b, p + 1)}", p
        if e.op == "+" and isinstance(b, Const) and b.signed < 0 and b.bits >= 8:
            return f"{self.expr(a, p)} - {number(-b.signed)}", p
        if e.op == "-" and isinstance(b, Const) and b.signed < 0 and b.bits >= 8 and -b.signed < 0x10000:
            return f"{self.expr(a, p)} + {number(-b.signed)}", p
        if e.op == "+" and isinstance(a, Const) and not isinstance(b, Const):
            a, b = b, a
        return f"{self.expr(a, p)} {op} {self.expr(b, p + 1)}", p

    _SIZES = {"char": 1, "unsigned char": 1, "short": 2, "unsigned short": 2, "int": 4, "unsigned int": 4,
              "int64_t": 8, "uint64_t": 8, "float": 4, "double": 8, "bool": 1, "__int128": 16,
              "unsigned __int128": 16}

    def _struct_ptr(self, e: Expr) -> bool:
        if isinstance(e, (Var, StackVar)):
            t = self.types.get(e.name)
            # (a `FILE *` too: C would scale arithmetic on it by an unknown size)
            return t is not None and t.ptr >= 1 and (t.base.startswith("struct ") or t.base == "FILE")
        return False

    def _ptr_size(self, e: Expr) -> int:
        """Element size if `e` is a typed pointer variable (C scales arithmetic on it), else 0."""
        if isinstance(e, (Var, StackVar)):
            t = self.types.get(e.name)
            if t is not None and t.ptr == 1:
                return self._SIZES.get(t.base, 0)
            if t is not None and t.ptr >= 2:           # a pointer to pointers
                return self.ptr_bits // 8
        return 0

    def _scaled(self, ptr: Expr, off: Expr) -> Expr | None:
        """`off` in elements for `ptr + off` (byte offsets in the IR), when it divides evenly."""
        size = self._ptr_size(ptr)
        if size <= 1:
            return off if size == 1 else None
        if isinstance(off, Const) and off.value % size == 0:
            return Const(off.value // size, off.bits)
        if isinstance(off, BinOp) and off.op == "*" and isinstance(off.b, Const) and off.b.value % size == 0:
            k = off.b.value // size
            return off.a if k == 1 else BinOp("*", off.a, Const(k, off.b.bits), off.bits)
        if isinstance(off, BinOp) and off.op == "<<" and isinstance(off.b, Const) and \
                (1 << off.b.value) % size == 0:
            k = off.b.value - (size.bit_length() - 1)
            return off.a if k == 0 else BinOp("<<", off.a, Const(k, off.b.bits), off.bits)
        return None

    def _unsigned(self, e: Expr) -> bool:
        if isinstance(e, (Var, StackVar)):
            t = self.types.get(e.name)
            return t is not None and t.ptr == 0 and (t.base.startswith(("unsigned", "uint")) or t.base == "size_t")
        return isinstance(e, Cast) and e.kind == "zext"

    def _callee_name(self, c: ir.Call) -> str | None:
        t = c.target
        if isinstance(t, Load) and isinstance(t.addr, Const):
            imp = self.an.bin.imports_by_got.get(t.addr.value)
            if imp is not None:                 # through the import's GOT slot (MIPS `jalr $t9`)
                return base_name(imp.name)
            got = getattr(self.an.bin, "got_names", {}).get(t.addr.value)
            if got and any(i.name == got for i in self.an.bin.imports):      # (a second GOT slot)
                return base_name(got)
        if isinstance(t, Const):
            return self.symbol(t.value) or f"sub_{t.value:x}"
        names = self.__dict__.get("_call_names")
        if names is None:                       # (the callee the lifter traced a register call to)
            names = self._call_names = {id(st.call): st.name for st in self.p.fn.stmts()
                                        if isinstance(st, CallStmt) and st.name}
        name = names.get(id(c))
        return base_name(name) if name else None

    def _ivar_vars(self) -> dict:
        """Variables whose only definition loads an ivar offset: name -> that load."""
        got = self.__dict__.get("_ivar_var_map")
        if got is None:
            objc = self.an.bin.objc
            defs: dict = {}
            for st in self.p.fn.stmts():
                if isinstance(st, Assign) and isinstance(st.dst, Var):
                    src = st.src
                    while isinstance(src, Cast):        # (arm64 `ldrsw`: sign-extended)
                        src = src.a
                    defs.setdefault(st.dst.name, []).append(src)
            got = self._ivar_var_map = {
                n: srcs[0] for n, srcs in defs.items() if len(srcs) == 1 and isinstance(srcs[0], Load)
                and isinstance(srcs[0].addr, Const) and srcs[0].addr.value in objc.ivar_slots}
        return got

    def _objc_ivar(self, addr) -> str | None:
        """`obj->ivar`: an object plus the ivar offset its metadata says the code reads."""
        objc = getattr(self.an.bin, "objc", None)
        if objc is None or not objc.ivar_slots or not (isinstance(addr, BinOp) and addr.op == "+"):
            return None
        for obj, off in ((addr.a, addr.b), (addr.b, addr.a)):
            o = off
            while isinstance(o, Cast):
                o = o.a
            if isinstance(o, Var):              # the offset loaded once, ahead of a loop
                o = self._ivar_vars().get(o.name, o)
            if isinstance(o, Load) and isinstance(o.addr, Const) and o.addr.value in objc.ivar_slots:
                return f"{self.expr(obj, PREC_POSTFIX)}->{objc.ivar_slots[o.addr.value][1]}"
        return None

    def _objc_ref(self, e, table: str) -> str | None:
        """What an Objective-C selector / class reference load names, else None."""
        objc = getattr(self.an.bin, "objc", None)
        e = _bare(e)
        if objc is None or not (isinstance(e, Load) and isinstance(e.addr, Const)):
            return None
        return getattr(objc, table).get(e.addr.value)

    def _objc_send(self, name: str, c: ir.Call) -> str | None:
        """`[receiver part1:arg1 part2:arg2]` for a message send (and clang's alloc / init / new
        shortcuts), else None."""
        from .sigs import OBJC_SENDS
        args = c.args
        if name in ("objc_alloc_init", "objc_alloc", "objc_opt_new") and len(args) == 1:
            cls = self._objc_ref(args[0], "classrefs") or self.expr(args[0])
            return {"objc_alloc_init": f"[[{cls} alloc] init]", "objc_alloc": f"[{cls} alloc]",
                    "objc_opt_new": f"[{cls} new]"}[name]
        if name not in OBJC_SENDS or len(args) < 2:
            return None
        sel = self._objc_ref(args[1], "selrefs")
        if sel is None:
            return None
        if name.startswith("objc_msgSendSuper"):
            recv = "super"
        else:
            recv = self._objc_ref(args[0], "classrefs") or self.expr(args[0], PREC_POSTFIX)
        parts = sel.split(":")
        if len(parts) == 1:
            return f"[{recv} {sel}]"
        rest = [self.expr(_bare(a)) for a in args[2:]]
        words = [f"{p}:{rest[k] if k < len(rest) else '?'}" for k, p in enumerate(parts[:-1])]
        return f"[{recv} {' '.join(words)}]"

    def call(self, c: ir.Call) -> str:
        target = c.target
        if getattr(self.an.bin, "func_descriptors", None) and isinstance(target, Load) and \
                isinstance(target.addr, (Load, Var, StackVar)):
            target = target.addr                # (PowerPC64 ELFv1: through the function's descriptor)
        name = self._callee_name(c) or f"(*{self.expr(target, PREC_UNARY)})"
        send = self._objc_send(name, c)
        if send is not None:
            return send
        fl = dict(c.fargs)
        from .sigs import arg_type, lookup
        sig = lookup(name, self.an)
        args = []
        for k, a in enumerate(c.args):
            if k in fl:
                args.append(self.fexpr(a, 0, fl[k]))
                continue
            if sig is not None and arg_type(sig, k) == "char *" and isinstance(a, Const) and \
                    self.string(a.value) is None:
                lit = self._declared_string(a.value)     # a string by the signature, wherever it sits
                if lit is not None:
                    args.append(lit)
                    continue
            if isinstance(_bare(a), Const) and self._user_format(_bare(a)) is not None:
                args.append(self._user_format(_bare(a)))        # (the user's choice wins)
                continue
            ptype = self._param_type(c, k)
            if ptype is not None and ptype.startswith("enum ") and isinstance(_bare(a), Const):
                text = self.enum_value(self.an.enum(ptype[5:]), _bare(a).value, _bare(a).bits)
                if text is not None:                    # `set_mode(MODE_A | MODE_C)`
                    args.append(text)
                    continue
            if isinstance(_bare(a), Const) and ptype is None:
                from .consts import constant_name
                text = constant_name(name, k, _bare(a).value, _bare(a).bits, self.an.bin.arch)
                if text is not None:                    # `mmap(0, n, PROT_READ | PROT_WRITE, ...)`
                    args.append(text)
                    continue
            ty = arg_type(sig, k) if sig is not None else None
            if isinstance(_bare(a), Const) and (ty == "mode_t" or k == _OPEN_MODE.get(base_name(name or ""))):
                args.append(f"0{_bare(a).value & 0o7777:o}")      # (file permissions: `0644`)
                continue
            if isinstance(_bare(a), Const) and ty in _NUMBER_TYPES:
                cv = _bare(a)                       # (a size or a count, never an address)
                args.append(number(cv.signed if ty not in ("size_t", "unsigned int", "unsigned long") else cv.value))
                continue
            args.append(self.expr(_bare(a)))
        return f"{name}({', '.join(args)})"

    def _param_type(self, c: ir.Call, k: int) -> str | None:
        """The type the user gave (or a header declared for) parameter `k` of the function called."""
        if not isinstance(c.target, Const) or c.target.value not in self.an.functions:
            return None
        t = self.an.var_types.get(c.target.value, {}).get(f"a{k + 1}")
        if t is None:                   # (a library function a header declared: its prototype)
            proto = self.an.user_types.get("prototypes", {}).get(base_name(self._callee_name(c) or ""))
            params = proto.get("params", []) if proto else []
            t = params[k] if k < len(params) and params[k].startswith("enum ") else None
        return t

    # --------------------------------------------------------- statements
    def stmt(self, s) -> str | None:
        if isinstance(s, Assign):
            if isinstance(s.src, ir.Phi):
                return None
            if isinstance(s.dst, Var) and getattr(self.an.bin, "objc", None) is not None and \
                    s.dst.name in self._ivar_vars():
                return None                     # (an ivar offset: its uses read `obj->ivar`)
            lhs = self.expr(s.dst)
            src = s.src
            if isinstance(src, BinOp) and src.a == s.dst and src.op in ("+", "-", "*", "&", "|", "^", "<<"):
                b = src.b
                if src.op in ("+", "-") and self._ptr_size(s.dst):
                    b = self._scaled(s.dst, b)
                    if b is None:
                        return f"{lhs} = {self.expr(src)};"
                if src.op in ("+", "-") and isinstance(b, Const) and b.value == 1:
                    return f"{lhs}{src.op}{src.op};"
                name = self._enum_text(s.dst, b) if src.op in ("&", "|", "^") else None
                return f"{lhs} {BIN[src.op][0]}= {name or self.expr(b)};"
            if self._float_var(s.dst):
                return f"{lhs} = {self.fexpr(src, 0, s.dst.bits if s.dst.bits in (32, 64) else None)};"
            name = self._enum_text(s.dst, _bare(src))
            if name is not None:
                return f"{lhs} = {name};"
            return f"{lhs} = {self.expr(_bare(src) if self._implicit(s.dst, src) else src)};"
        if isinstance(s, Store):
            bf = self.bitfield_writes(s)
            if bf is not None:
                return ", ".join(t.rstrip(";") for t in bf) + ";"
            name = self._enum_text(ir.Load(s.dst, s.bits), _bare(s.src))
            return f"{self.mem(s.dst, s.bits)} = {name or self.expr(s.src)};"
        if isinstance(s, CallStmt):
            text = self.call(s.call)
            from .fpabi import callee_ret
            from .fpabi import fp_ret_reg, is_fp_arch
            reg = fp_ret_reg(self.p.arch) if is_fp_arch(self.p.arch) and callee_ret(self.an, s) else self.p.arch.ret
            ret = next((v for r, v in s.defs if r == reg), None)
            if ret is not None:
                text = f"{self.expr(ret)} = {text}"
            return text + ";"
        if isinstance(s, ir.IndirectJump):
            return f"goto *{self.expr(s.expr, PREC_UNARY)};  // unresolved jump"
        if isinstance(s, Effect):
            return f"__{s.name}({', '.join(self.expr(a) for a in s.args)});"
        if isinstance(s, Unknown):
            return f'__asm("{s.text}");'
        return f"/* {s} */"

    def _implicit(self, dst: Expr, src: Expr) -> bool:
        """Assignment converts integers implicitly: `int64_t x = (int64_t)i` -> `x = i`."""
        return isinstance(src, Cast) and src.kind in ("zext", "sext") and dst.bits == src.bits

    # ------------------------------------------------------------- blocks
    def emit(self, text: str, addr: int | None, depth: int):
        # a user comment on the instruction shows once, on the first line it produced
        note = self.an.comments.get(addr) if addr is not None and depth > 0 else None
        if note and addr not in self.commented:
            self.commented.add(addr)
            text = f"{text}  // {note}"
        m = _COPY.fullmatch(text)
        if m and self.out and self.out[-1].depth == depth and \
                self.out[-1].text == f"{m.group(2)} = {m.group(1)};":
            return                              # `a = b; b = a`: b holds that value already
        self.out.append(Line(text, addr, depth))

    def node(self, n, depth: int):
        if isinstance(n, Seq):
            items = _tidy(_flatten(n))
            k = 0
            while k < len(items):
                it = items[k]
                nxt = items[k + 1] if k + 1 < len(items) else None
                parts = _for_parts(it, nxt, self.p.gotos) if isinstance(nxt, Loop) else None
                if parts is not None:
                    prev, init, step, body = parts
                    self.node(prev, depth)
                    self._for(nxt, init, step, body, depth)
                    k += 2
                    continue
                self.node(it, depth)
                k += 1
        elif isinstance(n, Block):
            if n.addr in self.p.gotos and not n.copy:
                self.emit(f"loc_{n.addr:x}:", n.addr, max(depth - 1, 0))
            for s in n.stmts:
                if id(s) in getattr(self.p, "hidden", ()) or \
                        isinstance(s, Assign) and isinstance(s.dst, Var) and s.dst.name in self._bf_vars:
                    continue
                bf = self.bitfield_writes(s) if isinstance(s, Store) else None
                if bf is not None:
                    for text in bf:
                        self.emit(text, s.addr, depth)
                    continue
                text = self.stmt(s)
                if text is not None:
                    self.emit(text, s.addr, depth)
        elif isinstance(n, Ret):
            v = n.stmt.value
            if v is not None and self.p.ret_float:
                text = f"return {self.fexpr(v, 0, self.p.ret_bits)};"
            else:
                text = "return;" if v is None else f"return {self.expr(_bare(v))};"
            self.emit(text, n.stmt.addr, depth)
        elif isinstance(n, Jump1):
            self.emit(f"goto loc_{n.addr:x};" if n.kind == "goto" else f"{n.kind};", None, depth)
        elif isinstance(n, If):
            addr = self._term_addr(n.addr)
            cond, then, els = n.cond, n.then, n.els
            # if (a) { if (b) { X } }  ->  if (a && b) { X }
            inner = _only_if(then, self.p.gotos) if els is None else None
            while inner is not None and inner.els is None:
                cond, then = BinOp("&&", cond, inner.cond, 1), inner.then
                inner = _only_if(then, self.p.gotos)
            # if (c) { ...; return; } else { Y }  ->  if (c) { ...; return; } Y
            if els is not None and _exits(then):
                self.node(If(n.addr, cond, then), depth)
                self.node(els, depth)
                return
            if els is not None and then is not None and _exits(els) and not _exits(then):
                self.node(If(n.addr, _negate(cond), els), depth)
                self.node(then, depth)
                return
            self.emit(f"if ({self.expr(cond)}) {{", addr, depth)
            self.node(then or Seq(), depth + 1)
            while els is not None:
                inner = _only_if(els, self.p.gotos)
                if inner is None:
                    self.emit("} else {", None, depth)
                    self.node(els, depth + 1)
                    break
                self.emit(f"}} else if ({self.expr(inner.cond)}) {{", self._term_addr(inner.addr), depth)
                self.node(inner.then or Seq(), depth + 1)
                els = inner.els
            self.emit("}", None, depth)
        elif isinstance(n, Loop):
            body = n.body
            if n.kind == "while" and n.header in self.p.gotos:
                # the header is only the test: a jump to it re-enters the loop before the test
                self.emit(f"loc_{n.header:x}:", n.header, max(depth - 1, 0))
            if n.kind == "while":
                self.emit(f"while ({self.expr(n.cond)}) {{", None, depth)
            elif n.kind == "dowhile":
                self.emit("do {", None, depth)
            else:
                self.emit("while (1) {", None, depth)
            self.node(_loop_body(body), depth + 1)
            out = getattr(self, "out", None)
            if out and out[-1].text == "continue;" and out[-1].depth == depth + 1:
                out.pop()                       # (the end of the body continues anyway)
            self.emit(f"}} while ({self.expr(n.cond)});" if n.kind == "dowhile" else "}", None, depth)
        elif isinstance(n, Switch):
            self.emit(f"switch ({self.expr(_bare(n.expr))}) {{", self._term_addr(n.addr), depth)
            values = self.enum_of(_bare(n.expr))

            def label_of(v: int) -> str:
                name = self.enum_value(values, v, 64) if values else None
                return name if name is not None and " " not in name else number(v)
            for case in n.cases:
                for label in case_labels(case, label_of):
                    self.emit(f"{label}:", case.addr, depth)
                self.node(case.body, depth + 1)
            self.emit("}", None, depth)

    def _for(self, loop: Loop, init, step, body, depth: int):
        text = lambda st: self.stmt(st).rstrip(";")
        self.emit(f"for ({text(init)}; {self.expr(loop.cond)}; {text(step)}) {{", init.addr, depth)
        self.node(body, depth + 1)
        self.emit("}", None, depth)

    def _term_addr(self, block_addr: int) -> int | None:
        b = self.p.fn.blocks.get(block_addr)
        return b.stmts[-1].addr if b is not None and b.stmts else block_addr

    # ------------------------------------------------------------ function
    def signature(self) -> str:
        fn = self.p.fn
        name = base_name(self.an.name(fn.addr) or fn.name)
        if "(" in name:
            from ..demangle import short_name
            name = short_name(name)
        params = []
        for r in self.p.params:
            t = self.types.get(r) or CType(int_type(self.ptr_bits))
            params.append(t.decl(self.vname(r)))
        ret = "void"
        if self.ret_type:
            ret = self.ret_type
        elif self.p.returns:
            vals = [s.value for s in fn.stmts() if isinstance(s, Return) and s.value is not None]
            if self.p.ret_float:
                ret = "double" if self.p.ret_bits == 64 else "float"
            elif self.p.ret_bits is not None:
                ret = int_type(self.p.ret_bits)
            else:
                ret = self._ret_type(vals[0]) if vals else "int"
        return f"{ret}{'' if ret.endswith('*') else ' '}{name}({', '.join(params) or 'void'})"

    def _ret_type(self, v: Expr) -> str:
        v = _bare(v)
        if isinstance(v, (Var, StackVar)) and v.name in self.types:
            return str(self.types[v.name])
        if isinstance(v, ir.Call):               # `return strdup(s)`: the library's result type
            from .sigs import lookup
            sig = lookup(self._callee_name(v), self.an)
            if sig is not None and sig.ret.endswith("*") and v.bits == self.ptr_bits:
                return sig.ret
        return int_type(v.bits) if v.bits != 1 else "bool"

    @property
    def _base(self) -> str:
        """What stack offsets are relative to: the return address on x86 (it is on the stack
        at entry), the entry stack pointer elsewhere (the return address is in a register)."""
        return "ret" if self.p.arch.name.startswith(("x64", "x86")) else "sp0"

    def declarations(self, depth: int):
        for note in self.notes:
            self.emit(note, None, depth)
        frame = self.p.frame
        used = {x.name for s in self.p.fn.stmts() for top in ir.stmt_exprs(s) for x in ir.walk(top)
                if isinstance(x, (StackVar, StackAddr))}
        used |= {d.name for s in self.p.fn.stmts() for d in ir.stmt_defs(s) if isinstance(d, StackVar)}
        if frame.realigned:
            self.emit("// stack realigned on entry: ret-relative offsets are approximate", None, depth)
        for slot in frame.locals():
            if slot.name() in self.p.params:
                continue                       # a stack parameter: declared in the signature
            if slot.kind == "canary":
                self.emit(f"// stack canary at {self._base}-{-slot.offset:#x} (check hidden)", None, depth)
                continue
            gen = slot.name()
            if gen in self._inner_slots and gen in self.stack_fields:
                continue                         # declared as a field of the stack struct around it
            if gen not in used and slot.offset not in self.stack_structs:
                continue
            name = self.vname(gen)
            where = f"// {self._base}-{-slot.offset:#x}" if slot.offset < 0 else f"// {self._base}+{slot.offset:#x}"
            if slot.offset in self.stack_structs:
                sname = self.stack_structs[slot.offset][0]
                shown = self.an.struct_names.get(sname, {}).get("name") or sname
                self.emit(f"struct {shown} {name};  {where}", None, depth)
            elif slot.kind == "buffer":
                self.emit(f"char {name}[{number(slot.size)}];  {where}", None, depth)
            else:
                t = self.types.get(gen) or CType(int_type(slot.width * 8))
                self.emit(f"{t.decl(name)};  {where}", None, depth)
        regs = sorted({v for v in self.names if v.startswith("_v") and v not in self.p.params},
                      key=lambda n: int(self.names[n][1:]))
        for v in regs:
            t = self.types.get(v)
            if t is not None and v not in self._bf_vars:
                self.emit(f"{t.decl(self.vname(v))};", None, depth)
        if self.out and self.out[-1].depth == depth:
            self.emit("", None, depth)

    def render(self) -> list[Line]:
        self.emit(self.signature(), self.p.fn.addr, 0)
        self.emit("{", None, 0)
        self._bitfield_stores()
        self._find_stack_structs()
        self.declarations(1)
        body = _flatten(self.p.tree)
        if body and isinstance(body[-1], Ret) and body[-1].stmt.value is None:
            body.pop()            # `return;` at the end of a void function says nothing
        self.node(Seq(body), 1)
        self._drop_unit_reads()
        # a `return;` that ends a void function says nothing
        if len(self.out) >= 2 and self.out[-1].text == "return;" and self.out[-1].depth == 1:
            self.out.pop()
        self.emit("}", None, 0)
        bare = self.an.user_types.get("bare")
        if bare:
            # `enum options_t` / `struct point` of a typedef'd anonymous enum / struct: C names it bare
            pat = re.compile(r"\b(?:enum|struct|union) (" + "|".join(map(re.escape, bare)) + r")\b")
            for ln in self.out:
                ln.text = pat.sub(r"\1", ln.text)
        if self.structs.used:                     # the structs the body refers to, above it
            from .structs import struct_declaration
            done: set = set()
            head = []
            for st in self.structs.used:
                lines = struct_declaration(self.an, st, self.sname, lambda f, st=st: self.fname(st, f),
                                           lambda f, st=st: self.ftype(st, f), done)
                head += [Line(t, None, 0) for t in lines + ([""] if lines else [])]
            self.out[:0] = head
        return self.out


# ------------------------------------------------------------- tree tidying
def _only_if(n, gotos=()):
    """`n` if it is (a Seq of) exactly one If node -- an `else if` / `&&` candidate.

    Empty blocks are ignored unless they carry a label some `goto` jumps to:
    folding the If into `else if` / `&&` would lose that label.
    """
    items = [x for x in _flatten(n)
             if not (isinstance(x, Block) and not x.stmts and (x.copy or x.addr not in gotos))] \
        if n is not None else []
    return items[0] if len(items) == 1 and isinstance(items[0], If) else None


def _exits(n) -> bool:
    """Control never falls out of the end of `n` (return / break / continue / goto)."""
    items = _flatten(n) if n is not None else []
    return bool(items) and isinstance(items[-1], (Ret, Jump1))


def _ends_with(n, kind: str) -> bool:
    while isinstance(n, Seq) and n.items:
        n = n.items[-1]
    return isinstance(n, Jump1) and n.kind == kind


def _is_jump(n, kind: str) -> bool:
    while isinstance(n, Seq) and len(n.items) == 1:
        n = n.items[0]
    return isinstance(n, Jump1) and n.kind == kind


def _drop_last(n):
    if isinstance(n, Jump1):
        return Seq()
    if isinstance(n, Seq) and n.items:
        if isinstance(n.items[-1], Jump1):
            return Seq(n.items[:-1])
        return Seq(n.items[:-1] + [_drop_last(n.items[-1])])
    return n


def _loop_body(body):
    """Tidy a loop body: drop the trailing `continue`, and turn a final
    `if (c) { X; continue; } else { break; }` into `if (!c) break; X`."""
    items = _flatten(body)
    while items and isinstance(items[-1], Jump1) and items[-1].kind == "continue":
        items.pop()
    if items and isinstance(items[-1], If):
        last = items[-1]
        for keep, leave, cond in ((last.then, last.els, _negate(last.cond)), (last.els, last.then, last.cond)):
            # (only when `leave` does leave: falling out of it must not run X)
            if keep is not None and leave is not None and _ends_with(keep, "continue") and \
                    not _ends_with(leave, "continue") and _exits(leave):
                items[-1] = If(last.addr, cond, leave)
                items.append(_drop_last(keep))
                break
            if keep is not None and _is_jump(keep, "continue") and leave is not None:
                items[-1] = If(last.addr, cond, leave)
                break
    return Seq(items)


def _flatten(n) -> list:
    if isinstance(n, Seq):
        return [x for it in n.items for x in _flatten(it)]
    return [n]


def _for_parts(prev, loop, gotos):
    """Split `X = init; while (c(X)) { ...; X += k; }` into for-loop parts.

    Returns (block without the init, init statement, step statement, body
    without the step) or None. A `continue` of this loop in the body rules it
    out: in a `while` it skips the step, in a `for` it would run it.
    """
    if loop.kind != "while" or loop.header in gotos or not isinstance(prev, Block) or not prev.stmts:
        return None
    init = prev.stmts[-1]
    if not isinstance(init, Assign) or not isinstance(init.dst, (Var, StackVar)):
        return None
    x = init.dst
    if not any(v == x for v in ir.walk(loop.cond)):
        return None
    items = _flatten(_loop_body(loop.body))
    last = items[-1] if items else None
    if not isinstance(last, Block) or not last.stmts or (last.addr in gotos and not last.copy):
        return None
    step = last.stmts[-1]
    if not (isinstance(step, Assign) and step.dst == x and isinstance(step.src, BinOp)
            and step.src.op in ("+", "-") and step.src.a == x and isinstance(step.src.b, Const)):
        return None
    if _has_continue(Seq(items)):
        return None
    body = Seq(items[:-1] + ([Block(last.addr, last.stmts[:-1], last.copy)] if last.stmts[:-1] else []))
    return Block(prev.addr, prev.stmts[:-1], prev.copy), init, step, body


def _has_continue(n) -> bool:
    """A `continue` that belongs to the enclosing loop (not to a nested one)."""
    if isinstance(n, Jump1):
        return n.kind == "continue"
    if isinstance(n, Loop):
        return False
    if isinstance(n, Seq):
        return any(_has_continue(x) for x in n.items)
    if isinstance(n, If):
        return _has_continue(n.then) or _has_continue(n.els)
    if isinstance(n, Switch):
        return any(_has_continue(c.body) for c in n.cases)
    return False


def _tidy(items):
    """Drop an empty `else`, and an unreachable `break` right after a `return`."""
    out = []
    for it in items:
        if out and isinstance(it, Jump1) and isinstance(_last(out[-1]), (Ret, Jump1)):
            continue
        out.append(it)
    return out


# ----------------------------------------------------------------- entry
def decompile(an: "Analysis", func: "Function") -> Decompiled:
    from .pipeline import prepare
    prep = prepare(an, func)
    w = CWriter(an, prep)
    lines = w.render()
    from ..extend import DECOMPILE_HOOKS
    for hook in DECOMPILE_HOOKS:             # plugins may rewrite the pseudocode (relic.extend)
        try:
            new = hook(an, func, lines)
        except Exception as e:  # noqa: BLE001 - a plugin bug must not lose the pseudocode
            import sys
            print(f"relic: decompile hook {getattr(hook, '__name__', hook)}: {e}", file=sys.stderr)
            continue
        if new is not None:
            lines = list(new)
    types = {w.names.get(n, n): str(t) for n, t in w.types.items()}
    return Decompiled(an.name(func.addr) or func.name, func.addr, lines, dict(w.shown), dict(w.shown_structs),
                      {k: list(v) for k, v in w.shown_fields.items()}, types)


__all__ = ["Decompiled", "Line", "decompile", "number"]

"""Names for functions a stripped binary leaves as `sub_XXXX`, from what their code shows.

Strongest first:

- `assert()`: glibc's `__assert_fail(expr, file, line, function)` (and its kin) is handed the
  enclosing function's own name -- the name the source gave it;
- a log or error message naming its function: `"parse_header: bad magic"`, `"[load_config] ..."`,
  `"init_table(): ..."` (an identifier with an underscore or camelCase, one per function, not a
  libc name, not the prefix every message of the program has);
- a thunk: nothing but a jump to (or a call of and a return from) a named function -> `j_name`;
- an allocation wrapper: calls `malloc` (calloc, realloc, strdup, fopen) and, failing, a function
  that does not return -> `xmalloc`;
- `usage`: prints a "Usage:" message and exits;
- `fatal`: prints a message and does not return.

The user's names, symbols and library signatures always win; these only fill `sub_` names
(Analysis.name). Each name says why it was given (Analysis.auto_func_reasons).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..disasm import CALL, JMP, RET

if TYPE_CHECKING:
    from . import Analysis
    from .functions import Function

# function -> index of the argument that names the asserting function
ASSERTS = {"__assert_fail": 3, "__assert_perror_fail": 3, "__assert2": 2, "__assert_rtn": 0, "__assert": 0,
           "_assert_func": 2}
ALLOCATORS = ("malloc", "calloc", "realloc", "reallocarray", "strdup", "strndup", "fopen", "fdopen", "opendir")
PRINTS = ("printf", "fprintf", "vfprintf", "vprintf", "puts", "fputs", "perror", "__fprintf_chk", "__printf_chk",
          "__vfprintf_chk", "dprintf", "write", "warn", "warnx", "fwrite")
EXITS = ("exit", "_exit", "_Exit", "abort", "err", "errx", "verr", "verrx", "error")
_FRAME = re.compile(r"^(?:nop|endbr64|endbr32|leave|bti|paciasp|autiasp|(?:push|pop) [re]bp|mov [re]bp, [re]sp|"
                    r"(?:sub|add) [re]sp, \w+|stp x29, x30, .*|ldp x29, x30, .*|mov x29, sp)\b")
_IDENT = r"[A-Za-z_][A-Za-z0-9_]{2,40}"
# `parse_header: ...`, `[parse_header] ...`, `parse_header(): ...`, `in parse_header: ...`
_LOG = re.compile(rf"^(?:\[({_IDENT})\]|({_IDENT})\(\)\s*:?|({_IDENT}):)\s")
_WORDS = frozenset("error warning warn fatal info debug note usage failed fail invalid cannot unable".split())


def auto_names(an: "Analysis") -> tuple[dict[int, str], dict[int, str]]:
    """({function address: name}, {function address: why}) for functions without a name."""
    from ..decompiler.sigs import base_name, lookup
    names: dict[int, str] = {}
    why: dict[int, str] = {}
    used = {f.name for f in an.functions.values()} | set(an.renames.values()) | set(an.bin.name_to_addr)
    unnamed = [f for f in an.functions.values() if not f.is_import and _unnamed(an, f)]

    def give(f: "Function", name: str, reason: str, exact: bool = False):
        if f.addr in names or not name:
            return
        if name in used:
            if exact:
                return                      # (the name is somebody else's already)
            k = 2
            while f"{name}_{k}" in used:
                k += 1
            name = f"{name}_{k}"
        used.add(name)
        names[f.addr] = name
        why[f.addr] = reason

    calls = {f.addr: [base_name(an.call_name(i) or "") for b in f.blocks.values() for i in b.insns
                      if i.kind == CALL] for f in unnamed}
    # calls of functions that do not return, by the callee itself (an unnamed `xalloc_die` too)
    dies = {f.addr: any(i.kind == CALL and i.target in an.functions and an.functions[i.target].noreturn
                        for b in f.blocks.values() for i in b.insns) for f in unnamed}
    strings = {f.addr: [s for b in f.blocks.values() for i in b.insns for r in i.refs
                        if (s := an.bin.read_cstring(r, 200))] for f in unnamed}

    # assert(): the function's own name, as the compiler passed it
    for f in unnamed:
        hits = [c for c in calls[f.addr] if c in ASSERTS]
        if hits:
            n = _assert_name(an, f, hits)
            if n:
                give(f, n, "assert() names it", exact=True)
    # a message naming its function
    prefixes: dict[str, set[int]] = {}
    for f in unnamed:
        for s in strings[f.addr]:
            m = _LOG.match(s)
            ident = next((g for g in m.groups() if g), None) if m else None
            if ident and _looks_like_function(ident) and lookup(ident, an) is None:
                prefixes.setdefault(ident, set()).add(f.addr)
    for f in unnamed:
        mine = {p for p, fs in prefixes.items() if f.addr in fs and len(fs) == 1}
        if len(mine) == 1:
            give(f, mine.pop(), "its messages name it", exact=True)
    # thunks, wrappers, usage, fatal
    for f in unnamed:
        t = _thunk_target(an, f)
        if t:
            give(f, f"j_{t}", f"a jump to {t}")
            continue
        cs = calls[f.addr]
        insns = sum(len(b.insns) for b in f.blocks.values())
        noret = [c for c in cs if c in EXITS or _noreturn(an, c)] or (["?"] if dies[f.addr] else [])
        alloc = next((c for c in cs if c in ALLOCATORS), None)
        # (a wrapper: little code, one allocation, at most a message and the call that dies)
        if alloc and noret and insns <= 30 and len(cs) <= 3 and cs.count(alloc) == 1:
            give(f, f"x{alloc}", f"{alloc}() that dies on failure")
            continue
        texts = strings[f.addr]
        if any(re.match(r"\s*usage\s*:", s, re.I) for s in texts) and (noret or f.noreturn):
            give(f, "usage", 'prints "Usage:" and exits')
            continue
        if f.noreturn and insns <= 80 and any(c in PRINTS for c in cs) and noret:
            give(f, "fatal", "prints a message and does not return")
    return names, why


def _unnamed(an: "Analysis", f: "Function") -> bool:
    return f.addr not in an.renames and f.name.startswith("sub_") and f.addr not in an.lib_names


def _noreturn(an: "Analysis", name: str) -> bool:
    a = an.bin.name_to_addr.get(name)
    f = an.functions.get(a) if a is not None else None
    return bool(f is not None and f.noreturn)


def _looks_like_function(ident: str) -> bool:
    """An identifier a programmer would name a function: with an underscore or camelCase, not an
    English word (`Error:`)."""
    if ident.lower() in _WORDS or ident.isupper():
        return False
    return "_" in ident.strip("_") or bool(re.search(r"[a-z][A-Z]", ident))


def _assert_name(an: "Analysis", f: "Function", hits: list[str]) -> str | None:
    """The function-name argument of the assert call in `f` (from the decompiler's recovered
    call arguments: any architecture, any calling convention)."""
    try:
        from ..decompiler.cleanup import cached_ir
        from ..decompiler.ir import CallStmt, Const
        from ..decompiler.sigs import base_name
        fn = cached_ir(an, f)
    except Exception:  # noqa: BLE001 - no name from a function the decompiler cannot read
        return None
    found = set()
    for s in fn.stmts():
        if not isinstance(s, CallStmt):
            continue
        name = base_name(s.name or (an.name(s.call.target.value) if isinstance(s.call.target, Const) else "") or "")
        k = ASSERTS.get(name)
        if k is None or k >= len(s.call.args) or not isinstance(s.call.args[k], Const):
            continue
        text = an.bin.read_cstring(s.call.args[k].value, 300)
        n = _function_of(text) if text else None
        if n:
            found.add(n)
    return found.pop() if len(found) == 1 else None


def _function_of(text: str) -> str | None:
    """`parse_header` from `__func__` (C), `int Table::insert(int)` from `__PRETTY_FUNCTION__`
    (C++: `Table::insert`)."""
    head = text.split("(", 1)[0].strip()
    head = head.split()[-1] if head.split() else ""
    head = head.lstrip("*&")
    if re.fullmatch(r"(?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*", head) and len(head) <= 80:
        return head
    return None


def _thunk_target(an: "Analysis", f: "Function") -> str | None:
    """The named function `f` does nothing but pass control to."""
    insns = [i for b in sorted(f.blocks.values(), key=lambda b: b.addr) for i in b.insns]
    if len(insns) > 8:
        return None
    # (anything but setting up and tearing down a frame -- `mov edi, 5` sets an argument: a wrapper)
    flow = [i for i in insns if i.kind in (CALL, JMP, RET) or not _FRAME.match(f"{i.mnemonic} {i.op_str}".strip())]
    target = None
    if len(flow) == 1 and flow[0].kind == JMP:
        target = flow[0].target
    elif len(flow) == 2 and flow[0].kind == CALL and flow[1].kind == RET:
        target = flow[0].target
    if target is None or target == f.addr:
        return None
    name = an.name(target)
    if not name or name.startswith(("sub_", "j_")):
        return None
    from ..decompiler.sigs import base_name
    return base_name(name)


__all__ = ["auto_names"]

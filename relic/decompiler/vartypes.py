"""Stage 5: variable widths and simple C types.

Two steps on the out-of-SSA IR:

- `narrow`: a 64-bit variable whose every use reads only its low n bits
  (`low32(v)`), or hands it on unchanged (a call argument, `return`), is
  really an n-bit value that the machine kept in a wide register. It is
  rewritten as an n-bit variable, so the output says `int v1` and drops
  the `low32(...)` / `zext64(...)` noise around it.
- `infer_types`: one C type per variable, from width and use: a value
  used as a load/store address is a pointer to what is loaded; a value
  compared unsigned is unsigned; stack buffers are `char name[size]`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .ir import (Assign, BinOp, Call, CallStmt, Cast, Const, Expr, IRFunction, Ite, Load, Return, StackVar,
                 Store, UnOp, Var, children, map_stmt, stmt_defs, stmt_exprs, transform, walk)

if TYPE_CHECKING:
    from .sigs import Sig

_INT = {1: "bool", 8: "char", 16: "short", 32: "int", 64: "int64_t", 128: "__int128"}
_UINT = {1: "bool", 8: "unsigned char", 16: "unsigned short", 32: "unsigned int", 64: "uint64_t",
         128: "unsigned __int128"}


def int_type(bits: int, unsigned: bool = False) -> str:
    return (_UINT if unsigned else _INT).get(bits, f"int{bits}_t")


# ------------------------------------------------------------------- narrowing
def simplify_low(e: Expr) -> Expr:
    """Push `low_n(...)` through modular arithmetic and fold it into extensions."""
    def node(x: Expr) -> Expr:
        if not (isinstance(x, Cast) and x.kind == "low"):
            if isinstance(x, Cast) and x.a.bits == x.bits:
                return x.a
            return x
        n, a = x.bits, x.a
        if isinstance(a, Const):
            return Const(a.value, n)
        if isinstance(a, Cast) and a.kind in ("zext", "sext", "low"):
            if a.a.bits == n:
                return a.a
            if a.a.bits > n:
                return node(Cast("low", a.a, n))
            return Cast(a.kind, a.a, n)       # low32(zext64(x8)) == zext32(x8)
        if isinstance(a, BinOp) and a.op in ("+", "-", "*", "&", "|", "^"):
            return BinOp(a.op, node(Cast("low", a.a, n)), node(Cast("low", a.b, n)), n)
        if isinstance(a, BinOp) and a.op == "<<" and isinstance(a.b, Const):
            return BinOp("<<", node(Cast("low", a.a, n)), Const(a.b.value, n), n)
        if isinstance(a, UnOp) and a.op in ("-", "~"):
            return UnOp(a.op, node(Cast("low", a.a, n)), n)
        if isinstance(a, Ite):
            return Ite(a.cond, node(Cast("low", a.a, n)), node(Cast("low", a.b, n)), n)
        return x
    return transform(e, node)


_CMPS = ("==", "!=", "<s", "<=s", "<u", "<=u")


def _narrow_widths(fn: IRFunction, cands: dict[str, Var], sx: dict[str, int] | None = None) -> dict[str, int]:
    """For every candidate variable, the width all its uses agree on, when every use only reads
    its low bits (`low_n(v)`) or hands it on whole (a call argument, `return`). One walk.

    `sx`: variables known to hold a sign-extended n-bit value (name -> n); comparing one whole
    is a use of that value too, and low reads of it may be narrower."""
    width: dict[str, int] = {}
    bad: set[str] = set()
    sx = sx or {}

    def visit(e: Expr, top: bool):
        if isinstance(e, Cast) and e.kind == "low" and isinstance(e.a, Var):
            v = cands.get(e.a.name)
            if v is not None and e.a == v:
                if v.name in sx:
                    if e.bits <= sx[v.name]:
                        width[v.name] = sx[v.name]
                        return
                    bad.add(v.name)
                elif width.setdefault(v.name, e.bits) != e.bits:
                    bad.add(v.name)
                return
        elif isinstance(e, Var):
            if not top and cands.get(e.name) == e:
                bad.add(e.name)
            return
        elif isinstance(e, BinOp) and (e.op in _CMPS and e.bits == 1 or e.op in ("&", "|", "^")):
            # (a bitwise operation on `sext(v)` narrows back with it: `low32(sext(v) ^ k)` is `v ^ k`)
            for k in (e.a, e.b):
                if isinstance(k, Var) and k.name in sx and cands.get(k.name) == k:
                    continue
                visit(k, False)
            return
        for k in children(e):
            visit(k, False)

    for s in fn.stmts():
        if isinstance(s, CallStmt):
            for a in s.call.args:
                visit(a, True)
            visit(s.call.target, False)
        elif isinstance(s, Return):
            if s.value is not None:
                visit(s.value, True)
        else:
            for x in stmt_exprs(s):
                visit(x, False)
    for n, w in sx.items():                      # compared and handed on only
        width.setdefault(n, w)
    return {n: w for n, w in width.items() if n not in bad}


def _collect_vars(fn: IRFunction) -> dict[str, Var]:
    seen: dict[str, Var] = {}
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Var):
                    seen.setdefault(x.name, x)
        for d in stmt_defs(s):
            if isinstance(d, Var):
                seen.setdefault(d.name, d)
    return seen


def _sext_vars(fn: IRFunction, cands: dict[str, Var], params: set[str]) -> dict[str, int]:
    """Variables every definition of which is a sign-extended n-bit value (`v = sext64(x32)`,
    RISC-V `addw` / `lw` / `sext.w`; a bitwise operation on such values, a small zero-extension, a
    constant that fits, a copy of another such variable): name -> n. `params` (entry values the
    calling convention passes sign-extended) count as 32-bit."""
    defs: dict[str, list] = {}
    for s in fn.stmts():
        for d in stmt_defs(s):
            if isinstance(d, Var) and cands.get(d.name) == d:
                defs.setdefault(d.name, []).append(s.src if isinstance(s, Assign) and s.dst == d else None)
    pars = {n for n, v in cands.items() if v.version == 0 and v.name in params}
    # optimistic: every variable with a sign extension among its definitions, then drop the ones a
    # definition contradicts until none does (`h = sext(...)` and `h ^= 0x1337` keep each other)
    live = pars | {n for n, srcs in defs.items()
                   if any(isinstance(x, Cast) and x.kind in ("sext", "zext") for x in srcs)}

    def width(e: Expr | None) -> int | None:
        """n when `e` is a sign-extended n-bit value (32 for one built from such values)."""
        if isinstance(e, Cast) and e.kind == "sext" and 8 <= e.a.bits < e.bits:
            return e.a.bits
        if isinstance(e, Cast) and e.kind == "zext" and e.a.bits < 32 and e.a.bits < e.bits:
            return 32                            # `lbu`: 0..255
        if isinstance(e, Const):
            return next((k for k in (8, 16, 32) if k < e.bits and _fits_signed(e.value, k, e.bits)), None)
        if isinstance(e, Var):
            return 32 if e.name in live else None
        if isinstance(e, BinOp) and e.op in ("&", "|", "^"):
            wa, wb = width(e.a), width(e.b)
            return max(wa, wb, 32) if wa and wb else None
        return None

    while True:
        drop = {n for n in live if n not in pars and not all(width(x) for x in defs.get(n, ()))}
        if not drop:
            break
        live -= drop
    out = {}
    for n in live:
        ws = [width(x) for x in defs.get(n, ())]
        out[n] = max([32 if n in pars else 0, *(w for w in ws if w)]) or 32
    return out


def _fits_signed(v: int, n: int, bits: int) -> bool:
    lo = v & ((1 << n) - 1)
    if lo >> (n - 1):
        lo |= ((1 << bits) - 1) & ~((1 << n) - 1)
    return lo == v


def narrow(fn: IRFunction, keep: set[str] = frozenset(), sext_params: set[str] = frozenset()) -> dict[str, int]:
    """Narrow wide variables that are only read as their low bits (in place); name -> new width.

    Narrowing one variable can expose another (`v1 = v2 + 1` becomes `v1 = low32(v2) + 1`), so
    rounds repeat until nothing more narrows. A variable holding a sign-extended value (see
    `_sext_vars`) may also be compared whole: it becomes `sext(v)` there. `sext_params`: entry
    registers the calling convention fills sign-extended (RISC-V `int` arguments); they narrow
    only with a low read to show they are `int`s."""
    done: dict[str, int] = {}
    while True:
        cands = {n: v for n, v in _collect_vars(fn).items() if n not in keep and n not in done and v.bits > 8}
        sx = _sext_vars(fn, cands, sext_params)
        widths = _narrow_widths(fn, cands, sx)
        params = {n for n, v in cands.items() if v.version == 0 and v.name in sext_params}
        if params:
            low_read = {n for n in params if _int_evidence(fn, cands[n], sx, params)}
            widths = {n: w for n, w in widths.items() if n not in params or n in low_read}
            # an int parameter also used whole (`p + n` indexes with the sign-extended value):
            # every such use is `(long)n`, exactly
            widths.update({n: sx[n] for n in low_read if n in sx})
        found = {n: w for n, w in widths.items() if w < cands[n].bits}
        if not found:
            break
        olds = {cands[n]: Var(n, cands[n].version, w) for n, w in found.items()}
        news = {nv: v for v, nv in olds.items()}

        def low_first(x: Expr) -> Expr:
            if isinstance(x, Cast) and x.kind == "low" and x.a in olds:
                nv = olds[x.a]
                if x.bits == nv.bits:
                    return nv
            return x

        def node(x: Expr) -> Expr:
            if isinstance(x, Cast) and x.kind == "low" and x.a in news:
                return x.a if x.bits == x.a.bits else Cast("low", x.a, x.bits)
            if isinstance(x, Var) and x in olds:
                return Cast("sext" if x.name in sx else "zext", olds[x], x.bits)
            return x

        def sub(e: Expr) -> Expr:
            # replace `low_w(v)` first so the zext placeholder does not swallow it
            return transform(transform(e, low_first), node)

        for b in fn.blocks.values():
            for s in b.stmts:
                map_stmt(s, sub)
                if isinstance(s, Assign) and isinstance(s.dst, Var) and s.dst in olds:
                    nv = olds[s.dst]
                    s.dst = nv
                    s.src = simplify_low(Cast("low", s.src, nv.bits))
                elif hasattr(s, "defs") and not isinstance(s, Assign):
                    s.defs = [(r, olds.get(d, d) if isinstance(d, Var) else d) for r, d in s.defs]
        done.update(found)
    if done:
        for b in fn.blocks.values():
            for s in b.stmts:
                map_stmt(s, simplify_low)
    return done


def _int_evidence(fn: IRFunction, v: Var, sx: dict[str, int], params: set[str]) -> bool:
    """`v` is read as its low half, or compared with a sign-extended int (`v == (long)i`)."""
    def ext(e: Expr) -> bool:
        return isinstance(e, Cast) and e.kind == "sext" and e.a.bits <= 32 or \
            isinstance(e, Var) and e.name in sx and e.name not in params
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Cast) and x.kind == "low" and x.a == v:
                    return True
                if isinstance(x, BinOp) and x.op in _CMPS and (x.a == v and ext(x.b) or x.b == v and ext(x.a)):
                    return True
    return False


# ----------------------------------------------------------------------- types
@dataclass
class CType:
    base: str            # scalar type, or the pointee for pointers
    ptr: int = 0         # pointer depth
    array: int | None = None

    def decl(self, name: str) -> str:
        arr = f"[{self.array}]" if self.array is not None else ""
        return f"{self.base} {'*' * self.ptr}{name}{arr}"

    def __str__(self) -> str:
        return self.base + (" " + "*" * self.ptr if self.ptr else "")


_BASES = {"void", "char", "short", "int", "long", "bool", "float", "double", "size_t", "ssize_t", "FILE",
          "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
          "unsigned char", "unsigned short", "unsigned int", "unsigned long", "unsigned", "signed char",
          "long long", "unsigned long long", "__int128", "unsigned __int128", "long double", "wchar_t",
          "intptr_t", "uintptr_t", "ptrdiff_t"}


def parse_ctype(text: str) -> CType:
    """`int`, `unsigned int`, `char *`, `struct note *`, `void **` -> CType; ValueError otherwise."""
    import re
    t = " ".join(text.replace("*", " * ").split())
    m = re.fullmatch(r"(?:const )?((?:struct |enum )?[A-Za-z_][A-Za-z0-9_]*(?: [A-Za-z_][A-Za-z0-9_]*)*)((?: \*)*)",
                     t)
    if m is None:
        raise ValueError(f"not a C type: {text!r}")
    base, ptr = m.group(1), m.group(2).count("*")
    if not base.startswith(("struct ", "enum ")) and base not in _BASES:
        raise ValueError(f"unknown type {base!r} (an integer type, void, char, or struct NAME)")
    if base == "void" and not ptr:
        raise ValueError("void is only a pointer target")
    return CType(base, ptr)


def _addr_base(a: Expr, is_addr=lambda v: False):
    """The variable a memory address is based on (`v`, `v + 8`, `v + i*4`).

    In `v + K` where K is itself an address (a global array), `v` is the
    index, not the pointer.
    """
    if isinstance(a, (Var, StackVar)):
        return a
    if isinstance(a, BinOp) and a.op == "-" and isinstance(a.b, Const) and isinstance(a.a, (Var, StackVar)):
        return a.a
    if isinstance(a, BinOp) and a.op == "+":
        if any(isinstance(x, Const) and is_addr(x.value) for x in (a.a, a.b)):
            return None
        for x in (a.a, a.b):
            if isinstance(x, (Var, StackVar)):
                return x
    return None


def infer_types(fn: IRFunction, ptr_bits: int, is_addr=lambda v: False,
                hints: dict[str, CType] | None = None) -> dict[str, CType]:
    """C type per variable name (registers' Vars and stack locals).

    `is_addr(value)` says whether a constant is a data address; `hints` are
    known types (e.g. from library signatures) that win over inference.
    """
    widths: dict[str, int] = {}
    pointee: dict[str, int] = {}
    unsigned: set[str] = set()
    signed: set[str] = set()
    copies: list[tuple[str, str]] = []

    def note(e: Expr):
        for x in walk(e):
            if isinstance(x, (Var, StackVar)):
                widths.setdefault(x.name, x.bits)
            if isinstance(x, Load):
                b = _addr_base(x.addr, is_addr)
                if b is not None and b.bits == ptr_bits:
                    pointee.setdefault(b.name, x.bits)
            if isinstance(x, BinOp) and x.op in ("<u", "<=u", "<s", "<=s", "/u", "/s", ">>u", ">>s", "%u", "%s"):
                for side in (x.a, x.b):
                    if isinstance(side, (Var, StackVar)):
                        (unsigned if x.op.endswith("u") else signed).add(side.name)

    for s in fn.stmts():
        for top in stmt_exprs(s):
            note(top)
        if isinstance(s, Store):
            b = _addr_base(s.dst, is_addr)
            if b is not None and b.bits == ptr_bits:
                pointee.setdefault(b.name, s.src.bits)
        if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)) and isinstance(s.src, (Var, StackVar)) \
                and s.dst.bits == s.src.bits:
            copies.append((s.dst.name, s.src.name))
        for d in stmt_defs(s):
            if isinstance(d, (Var, StackVar)):
                widths.setdefault(d.name, d.bits)

    # a copy carries the pointer type both ways (`var_20 = a1` makes a1 a char * too)
    changed = True
    while changed:
        changed = False
        for x, y in copies:
            for p, q in ((x, y), (y, x)):
                if p in pointee and q not in pointee:
                    pointee[q] = pointee[p]
                    changed = True

    out: dict[str, CType] = {}
    for name, bits in widths.items():
        if hints and name in hints:
            out[name] = hints[name]
        elif name in pointee and bits == ptr_bits:
            out[name] = CType(int_type(pointee[name]), 1)
        else:
            out[name] = CType(int_type(bits, name in unsigned and name not in signed))
    return out


# the more a type says, the more it wins when several calls disagree
_HINT_RANK = {"void *": 1, "size_t": 1, "ssize_t": 1}


# C integer types by width (LP64 / ILP32 `long` is taken as the pointer width where it matters)
_INT_WIDTHS = {"char": 8, "short": 16, "int": 32, "long long": 64, "int8_t": 8, "uint8_t": 8, "int16_t": 16,
               "uint16_t": 16, "int32_t": 32, "uint32_t": 32, "int64_t": 64, "uint64_t": 64, "bool": 8,
               "_Bool": 8}


def library_types(fn: IRFunction, ptr_bits: int, ret_reg: str, callee=lambda call: None,
                  cstring=lambda addr: None, an=None) -> dict[str, CType]:
    """Types variables get from the library calls they meet: an argument of `strlen` is a
    `char *`, of `malloc` a `size_t`, the result of `fopen` a `FILE *` (sigs.SIGS), what a
    constant format string's `%s` consumes a `char *`. Only plain variables of the type's width
    count; copies carry a type both ways. A variable two calls give different equally specific
    types gets none. `callee(call)` names a call's target, `cstring(addr)` reads a string."""
    from .sigs import Sig, arg_type, format_types, lookup
    widths = {"char *": ptr_bits, "void *": ptr_bits, "FILE *": ptr_bits, "size_t": ptr_bits,
              "ssize_t": ptr_bits}
    found: dict[str, str | None] = {}

    def give(v: Expr, t: str | None):
        if t is not None and t not in widths and t.endswith("*"):
            try:                                 # an exact pointer type from a prototype
                parse_ctype(t)
                widths[t] = ptr_bits
            except ValueError:
                return
        if t not in widths or not isinstance(v, (Var, StackVar)) or v.bits != widths[t]:
            return
        old = found.get(v.name, "")
        if old is None or old == t:
            return
        if old == "" or _HINT_RANK.get(old, 2) < _HINT_RANK.get(t, 2):
            found[v.name] = t
        elif _HINT_RANK.get(old, 2) == _HINT_RANK.get(t, 2):
            found[v.name] = None              # disagreement: no hint

    def user_sig(c: Call) -> Sig | None:
        """A function of the program the user gave parameter / return types (`Y` on it, or a
        prototype imported for it): those types reach its callers' arguments and results."""
        if an is None or not isinstance(c.target, Const) or c.target.value not in an.functions:
            return None
        wanted = an.var_types.get(c.target.value) or {}
        params = [wanted.get(f"a{k + 1}") for k in range(len(c.args))]
        if not any(params) and "@return" not in wanted:
            return None
        for t in [*params, wanted.get("@return")]:
            if t and t not in widths:
                try:
                    ct = parse_ctype(t)
                except ValueError:
                    continue
                w = ptr_bits if ct.ptr else _INT_WIDTHS.get(ct.base.replace("unsigned ", "").replace("signed ", ""))
                if w:
                    widths[t] = w
        return Sig(len(c.args), ret=wanted.get("@return") or "", types=tuple(t or "" for t in params))

    def call(c: Call, name: str | None) -> Sig | None:
        sig = lookup(name, an)
        if sig is None:
            sig = user_sig(c)
            if sig is not None:
                for k, a in enumerate(c.args):
                    give(a, sig.types[k] or None)
            return sig
        for k, a in enumerate(c.args):
            give(a, arg_type(sig, k))
        if sig.fmt is not None and sig.fmt < len(c.args) and isinstance(c.args[sig.fmt], Const):
            fmt = cstring(c.args[sig.fmt].value)
            if fmt:
                rest = c.args[sig.fmt + 1:]
                for a, t in zip(rest, format_types(fmt, "scanf" in (name or ""))):
                    give(a, t)
        return sig

    copies: list[tuple[Expr, Expr]] = []
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Call) and not (isinstance(s, CallStmt) and x is s.call):
                    sig = call(x, callee(x))    # a call inside an expression: `return strlen(p) + 1`
                    src = s.src if isinstance(s, Assign) else None
                    while isinstance(src, Cast):
                        src = src.a
                    if sig is not None and src is x:           # `v = localtime(&t)`: v gets its result type
                        give(s.dst, sig.ret)
        if isinstance(s, CallStmt):
            sig = call(s.call, s.name or callee(s.call))
            if sig is None:
                continue
            for r, d in s.defs:
                if r == ret_reg:
                    give(d, sig.ret)
        elif isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)) and \
                isinstance(s.src, (Var, StackVar)) and s.dst.bits == s.src.bits:
            copies.append((s.dst, s.src))
    changed = True
    while changed:
        changed = False
        for x, y in copies:
            for p, q in ((x, y), (y, x)):
                t = found.get(p.name)
                if t and found.get(q.name, "") == "":
                    found[q.name] = t
                    changed = True
    return {n: parse_ctype(t) for n, t in found.items() if t}


__all__ = ["library_types", "narrow", "simplify_low", "infer_types", "int_type", "parse_ctype", "CType"]

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

from .ir import (Assign, BinOp, CallStmt, Cast, Const, Expr, IRFunction, Ite, Load, Return, StackVar,
                 Store, UnOp, Var, children, map_stmt, stmt_exprs, transform, walk)

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


def _narrow_widths(fn: IRFunction, cands: dict[str, Var]) -> dict[str, int]:
    """For every candidate variable, the width all its uses agree on, when every use only reads
    its low bits (`low_n(v)`) or hands it on whole (a call argument, `return`). One walk."""
    width: dict[str, int] = {}
    bad: set[str] = set()

    def visit(e: Expr, top: bool):
        if isinstance(e, Cast) and e.kind == "low" and isinstance(e.a, Var):
            v = cands.get(e.a.name)
            if v is not None and e.a == v:
                if width.setdefault(v.name, e.bits) != e.bits:
                    bad.add(v.name)
                return
        elif isinstance(e, Var):
            if not top and cands.get(e.name) == e:
                bad.add(e.name)
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
    return {n: w for n, w in width.items() if n not in bad}


def _collect_vars(fn: IRFunction) -> dict[str, Var]:
    seen: dict[str, Var] = {}
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Var):
                    seen.setdefault(x.name, x)
        for d in _defs(s):
            if isinstance(d, Var):
                seen.setdefault(d.name, d)
    return seen


def narrow(fn: IRFunction, keep: set[str] = frozenset()) -> dict[str, int]:
    """Narrow wide variables that are only read as their low bits (in place); name -> new width.

    Narrowing one variable can expose another (`v1 = v2 + 1` becomes `v1 = low32(v2) + 1`), so
    rounds repeat until nothing more narrows."""
    done: dict[str, int] = {}
    while True:
        cands = {n: v for n, v in _collect_vars(fn).items() if n not in keep and n not in done and v.bits > 8}
        found = {n: w for n, w in _narrow_widths(fn, cands).items() if w < cands[n].bits}
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
                return Cast("zext", olds[x], x.bits)
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


def _defs(s):
    from .ir import stmt_defs
    return stmt_defs(s)


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
          "long long", "unsigned long long", "__int128", "unsigned __int128"}


def parse_ctype(text: str) -> CType:
    """`int`, `unsigned int`, `char *`, `struct note *`, `void **` -> CType; ValueError otherwise."""
    import re
    t = " ".join(text.replace("*", " * ").split())
    m = re.fullmatch(r"(?:const )?((?:struct )?[A-Za-z_][A-Za-z0-9_]*(?: [A-Za-z_][A-Za-z0-9_]*)*)((?: \*)*)", t)
    if m is None:
        raise ValueError(f"not a C type: {text!r}")
    base, ptr = m.group(1), m.group(2).count("*")
    if not base.startswith("struct ") and base not in _BASES:
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
        for d in _defs(s):
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


__all__ = ["narrow", "simplify_low", "infer_types", "int_type", "parse_ctype", "CType"]

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

from .ir import (Assign, BinOp, CallStmt, Cast, Const, Expr, IRFunction, Ite, Load, Return, StackAddr, StackVar,
                 Store, UnOp, Var, map_stmt, stmt_exprs, transform, walk)

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


def _narrow_width(fn: IRFunction, v: Var) -> int | None:
    """The width every use of `v` agrees on, if all uses only read its low bits."""
    width = None
    passthrough = False

    def visit(e: Expr, top: bool) -> bool:
        nonlocal width, passthrough
        if isinstance(e, Cast) and e.kind == "low" and e.a == v:
            if width is not None and width != e.bits:
                return False
            width = e.bits
            return True
        if e == v:
            if top:
                passthrough = True      # handed on whole: call argument / return value / copy
                return True
            return False
        return all(visit(k, False) for k in _kids(e))

    for s in fn.stmts():
        if isinstance(s, CallStmt):
            tops = [(a, True) for a in s.call.args] + [(s.call.target, False)]
        elif isinstance(s, Return):
            tops = [(s.value, True)] if s.value is not None else []
        else:
            tops = [(x, False) for x in stmt_exprs(s)]
        for e, top in tops:
            if not visit(e, top):
                return None
    return width


def _kids(e):
    from .ir import children
    return children(e)


def narrow(fn: IRFunction, keep: set[str] = frozenset()) -> dict[str, int]:
    """Narrow wide variables that are only read as their low bits (in place); name -> new width."""
    done: dict[str, int] = {}
    seen: dict[str, Var] = {}
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Var):
                    seen.setdefault(x.name, x)
        for d in _defs(s):
            if isinstance(d, Var):
                seen.setdefault(d.name, d)
    for name, v in seen.items():
        if name in keep or v.bits <= 8:
            continue
        w = _narrow_width(fn, v)
        if w is None or w >= v.bits:
            continue
        nv = Var(v.name, v.version, w)

        def sub(e: Expr, v=v, nv=nv, w=w) -> Expr:
            def node(x: Expr) -> Expr:
                if isinstance(x, Cast) and x.kind == "low" and x.a == nv:
                    return nv if x.bits == w else Cast("low", nv, x.bits)
                if x == v:
                    return Cast("zext", nv, v.bits)
                return x
            # replace `low_w(v)` first so the zext placeholder does not swallow it
            e = transform(e, lambda x: nv if isinstance(x, Cast) and x.kind == "low" and x.a == v
                          and x.bits == w else x)
            return transform(e, node)

        for b in fn.blocks.values():
            for s in b.stmts:
                map_stmt(s, sub)
                if isinstance(s, Assign) and s.dst == v:
                    s.dst = nv
                    s.src = simplify_low(Cast("low", s.src, w))
                elif hasattr(s, "defs") and not isinstance(s, Assign):
                    s.defs = [(r, nv if d == v else d) for r, d in s.defs]
        done[name] = w
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


__all__ = ["narrow", "simplify_low", "infer_types", "int_type", "CType"]

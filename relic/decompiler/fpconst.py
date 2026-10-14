"""Floating-point constants: compilers load them from read-only data (`movsd xmm0, [rip+X]`).
Where such a load feeds a floating-point operation it is replaced by the constant, which the
C writer prints as a literal (`3.0 * x`)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from .fp import FARITH, FCMP, FP_INTRINSICS
from .ir import BinOp, Call, Const, Expr, Intrinsic, IRFunction, Ite, Load, UnOp, children, map_stmt, rebuild

if TYPE_CHECKING:
    from ..analysis import Analysis


def _ro_value(an: "Analysis", e: Expr) -> Const | None:
    if not (isinstance(e, Load) and isinstance(e.addr, Const) and e.bits in (32, 64)):
        return None
    sec = an.bin.section_at(e.addr.value)
    if sec is None or sec.w or sec.x or not sec.loaded:
        return None
    v = an.bin.read_int(e.addr.value, e.bits // 8)
    return Const(v, e.bits) if v is not None else None


def is_float_expr(e: Expr) -> bool:
    """`e` computes a floating-point value (its bits are a float / double)."""
    if isinstance(e, BinOp):
        return e.op in FARITH
    if isinstance(e, UnOp):
        return e.op == "fneg"
    if isinstance(e, Intrinsic):
        return e.name in FP_INTRINSICS or e.name in ("sitofp", "fpconv")
    return False


def float_operands(e: Expr) -> tuple[Expr, ...]:
    """The operands of `e` that are floats."""
    if isinstance(e, BinOp) and (e.op in FARITH or e.op in FCMP):
        return (e.a, e.b)
    if isinstance(e, UnOp) and e.op == "fneg":
        return (e.a,)
    if isinstance(e, Intrinsic) and (e.name in FP_INTRINSICS or e.name in ("fptosi", "fpconv")):
        return e.args
    if isinstance(e, Ite) and (is_float_expr(e.a) or is_float_expr(e.b)):
        return (e.a, e.b)
    return ()


def fold_float_constants(an: "Analysis", fn: IRFunction, extra=()) -> int:
    """Replace read-only loads used as floats by constants; also those returned or passed where
    a float is expected (`extra`: expressions known to be floats, e.g. return values)."""
    n = 0

    def visit(e: Expr) -> Expr:
        nonlocal n
        kids = children(e)
        if not kids:
            return e
        floats = {id(k) for k in float_operands(e)}
        new = []
        for k in kids:
            c = _ro_value(an, k) if id(k) in floats else None
            if c is not None:
                n += 1
                new.append(c)
            else:
                new.append(visit(k))
        return rebuild(e, tuple(new)) if any(a is not b for a, b in zip(new, kids)) else e

    for s in fn.stmts():
        map_stmt(s, visit)
    return n


def float_types(fn: IRFunction, params_fp: dict[str, int], ret_float: bool,
                callee_ret=lambda stmt: None) -> dict[str, int]:
    """Variables (register Vars and stack locals) that hold floats -> width (64 double, 32 float).

    A variable is a float when a floating-point operation reads or produces it, when it is a
    float parameter or the float result of a call, is returned as the float result, or is a copy
    of (or copied to) one."""
    from .ir import Assign, Call, Cast, CallStmt, Return, StackVar, Store, Var, stmt_exprs, walk
    out: dict[str, int] = dict(params_fp)

    def name_of(e: Expr):
        while isinstance(e, Cast) and e.kind in ("low", "zext"):
            e = e.a
        return e if isinstance(e, (Var, StackVar)) else None

    def mark(e: Expr, w: int):
        v = name_of(e)
        if v is not None and w in (32, 64):
            out.setdefault(v.name, w)

    copies = []
    ints: set[str] = set()       # used as integers or addresses: copies do not make these floats

    def int_use(e: Expr):
        v = name_of(e)
        if v is not None:
            ints.add(v.name)

    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                for k in float_operands(x):
                    mark(k, k.bits)
                if isinstance(x, BinOp) and x.op[0] != "f":
                    int_use(x.a)
                    int_use(x.b)
                elif isinstance(x, Load):
                    int_use(x.addr)
                elif isinstance(x, Intrinsic) and x.name == "sitofp":
                    int_use(x.args[0])
        if isinstance(s, Store):
            int_use(s.dst)
        if isinstance(s, Assign):
            src = s.src
            inner = src.a if isinstance(src, Cast) and src.kind == "zext" else src
            if is_float_expr(inner):
                mark(s.dst, inner.bits)
            elif name_of(src) is not None and name_of(s.dst) is not None:
                copies.append((name_of(s.dst), name_of(src)))
            elif isinstance(inner, Ite) and (is_float_expr(inner.a) or is_float_expr(inner.b)):
                mark(s.dst, inner.bits)
        if isinstance(s, CallStmt):
            w = callee_ret(s)
            if w is not None:
                for r, d in s.defs:
                    if r == "xmm0":
                        mark(d, w)
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Call):
                    for k, w in x.fargs:
                        if k < len(x.args):
                            mark(x.args[k], w)
        if isinstance(s, Return) and ret_float and s.value is not None:
            mark(s.value, s.value.bits)
    changed = True
    while changed:
        changed = False
        for d, src in copies:
            if d.name in out and src.name not in out and src.name not in ints:
                out[src.name] = out[d.name]
                changed = True
            elif src.name in out and d.name not in out and d.name not in ints:
                out[d.name] = out[src.name]
                changed = True
    return out


def float_pointees(fn: IRFunction, ftypes: dict[str, int], is_addr=lambda v: False) -> dict[str, int]:
    """Pointer variables whose memory is read or written as floats -> the float width
    (`*v2` compared as a double makes v2 a `double *`)."""
    from .ir import Assign, Cast, StackVar, Store, Var, stmt_exprs, walk
    from .vartypes import _addr_base
    out: dict[str, int] = {}
    copies = []

    def mem(load: Expr):
        if isinstance(load, Cast) and load.kind in ("low", "zext"):
            load = load.a
        if isinstance(load, Load) and load.bits in (32, 64):
            b = _addr_base(load.addr, is_addr)
            if b is not None:
                out.setdefault(b.name, load.bits)

    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                for k in float_operands(x):
                    mem(k)
                if isinstance(x, Call):
                    for k, _w in x.fargs:
                        if k < len(x.args):
                            mem(x.args[k])
        if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)) and s.dst.name in ftypes:
            mem(s.src)
        if isinstance(s, Store) and s.src.bits in (32, 64):
            v = s.src.a if isinstance(s.src, Cast) and s.src.kind == "low" else s.src
            if is_float_expr(v) or isinstance(v, (Var, StackVar)) and v.name in ftypes:
                b = _addr_base(s.dst, is_addr)
                if b is not None:
                    out.setdefault(b.name, s.src.bits)
        if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)) and isinstance(s.src, (Var, StackVar)) \
                and s.dst.bits == s.src.bits:
            copies.append((s.dst.name, s.src.name))
    changed = True
    while changed:            # a copy of a float pointer points at floats too
        changed = False
        for x, y in copies:
            for p, q in ((x, y), (y, x)):
                if p in out and q not in out and q not in ftypes:
                    out[q] = out[p]
                    changed = True
    return out

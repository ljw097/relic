"""Stage-2 optimisation passes over SSA IR.

The passes run to a fixpoint and keep the function's meaning: constant
folding, algebraic simplification, constant/copy propagation, single-use
load forwarding, condition recovery (turning the flag soup left by `cmp`
into real comparisons) and dead-code elimination.

Because the IR is in SSA form, every register value has a single
definition that dominates its uses, so a pure, load-free definition can be
substituted into its uses without worrying about ordering. Loads are moved
only by the dedicated, conservative forwarding pass.

`optimize(fn, arch)` expects the output of `ssa.to_ssa` and mutates it in
place (it also returns it). Correctness is checked dynamically: the test
suite runs a function through the IR interpreter before and after
optimisation and compares the results (see tests/test_passes.py).
"""
from __future__ import annotations

from collections import Counter

from .arch import ArchInfo
from .interp import InterpError, apply_binop, apply_cast, apply_unop
from .ir import (BARRIERS, Assign, BinOp, Call, CallStmt, Cast, Const, Effect, Expr, Extract, IRFunction,
                 Ite, Load, Phi, UnOp, Unknown, Var, mask, stmt_exprs, transform, walk)

MAX_ITERS = 64


# ----------------------------------------------------------------- predicates
def _has(e: Expr, *types) -> bool:
    return any(isinstance(x, types) for x in walk(e))


def _trivial(e: Expr) -> bool:
    return isinstance(e, (Const, Var))


def _movable(e: Expr) -> bool:
    """Pure and load-free: can be substituted anywhere in SSA."""
    return not _has(e, Load, Call)


def _droppable(e: Expr) -> bool:
    """Evaluating it has no observable effect, so it may be dropped or duplicated."""
    return not _has(e, Load, Call)


def _count_uses(fn: IRFunction) -> Counter:
    c: Counter = Counter()
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Var):
                    c[x] += 1
    return c


def _uses_var(s, v: Var) -> bool:
    return any(x == v for top in stmt_exprs(s) for x in walk(top))


# --------------------------------------------------------------- rewrite driver
def _rewrite(fn: IRFunction, f) -> bool:
    """Apply `f` to every expression a statement reads; report whether anything changed."""
    from .ir import map_stmt
    changed = False
    for b in fn.blocks.values():
        for s in b.stmts:
            before = list(stmt_exprs(s))
            map_stmt(s, f)
            if stmt_exprs(s) != before:
                changed = True
    return changed


def _subst(e: Expr, sub: dict[Var, Expr]) -> Expr:
    if not sub:
        return e
    return transform(e, lambda x: sub.get(x, x) if isinstance(x, Var) else x)


# ------------------------------------------------------- constant folding / simplify
def _fold_node(e: Expr) -> Expr:
    if isinstance(e, BinOp) and isinstance(e.a, Const) and isinstance(e.b, Const):
        try:
            return Const(apply_binop(e.op, e.a.value, e.b.value, e.a.bits, e.b.bits), e.bits)
        except InterpError:
            return e
    if isinstance(e, UnOp) and isinstance(e.a, Const):
        try:
            return Const(apply_unop(e.op, e.a.value, e.bits), e.bits)
        except InterpError:
            return e
    if isinstance(e, Cast) and isinstance(e.a, Const):
        return Const(apply_cast(e.kind, e.a.value, e.a.bits, e.bits), e.bits)
    if isinstance(e, Extract) and isinstance(e.a, Const):
        return Const((e.a.value >> e.lo) & mask(e.bits), e.bits)
    if isinstance(e, Ite) and isinstance(e.cond, Const):
        return e.a if e.cond.value else e.b
    return e


def _simp_node(e: Expr) -> Expr:
    if isinstance(e, BinOp):
        a, b, op, w = e.a, e.b, e.op, e.bits
        z = lambda x: isinstance(x, Const) and x.value == 0
        one = lambda x: isinstance(x, Const) and x.value == 1
        ones = lambda x: isinstance(x, Const) and x.value == mask(x.bits)
        if op == "+":
            if z(b): return a
            if z(a): return b
        elif op == "-":
            if z(b): return a
            if a == b and _droppable(a): return Const(0, w)
        elif op == "*":
            if (z(a) and _droppable(b)) or (z(b) and _droppable(a)): return Const(0, w)
            if one(b): return a
            if one(a): return b
        elif op == "|":
            if z(b): return a
            if z(a): return b
            if a == b and _droppable(a): return a
            if (ones(a) and _droppable(b)) or (ones(b) and _droppable(a)): return Const(mask(w), w)
        elif op == "&":
            if (z(a) and _droppable(b)) or (z(b) and _droppable(a)): return Const(0, w)
            if ones(b): return a
            if ones(a): return b
            if a == b and _droppable(a): return a
        elif op == "^":
            if z(b): return a
            if z(a): return b
            if a == b and _droppable(a): return Const(0, w)
        elif op in ("<<", ">>u", ">>s"):
            if z(b): return a
        elif op in ("&&", "||"):
            if a == b and _droppable(a): return a
    elif isinstance(e, UnOp) and isinstance(e.a, UnOp) and e.op == e.a.op and e.op in ("-", "~"):
        return e.a.a
    elif isinstance(e, UnOp) and e.op == "!" and isinstance(e.a, UnOp) and e.a.op == "!" and e.a.a.bits == 1:
        return e.a.a
    elif isinstance(e, Ite) and e.a == e.b:
        return e.a
    elif isinstance(e, Cast) and e.a.bits == e.bits:
        return e.a
    elif isinstance(e, Cast) and e.kind == "low" and isinstance(e.a, Cast) and e.bits <= e.a.a.bits:
        # low_n(cast_m(x)) == low_n(x) when x is at least n bits wide
        return Cast("low", e.a.a, e.bits)
    return e


def _fold_pass(fn: IRFunction) -> bool:
    return _rewrite(fn, lambda e: transform(e, lambda x: _simp_node(_fold_node(x))))


# ----------------------------------------------------- constant / copy propagation
def _propagate(fn: IRFunction) -> bool:
    defs: dict[Var, Expr] = {}
    for s in fn.stmts():
        if isinstance(s, Assign) and isinstance(s.dst, Var):
            defs[s.dst] = s.src
    uses = _count_uses(fn)
    sub: dict[Var, Expr] = {}
    for v, src in defs.items():
        if isinstance(src, Phi):
            continue
        if _trivial(src):
            sub[v] = src
        elif _movable(src) and uses.get(v, 0) == 1:
            sub[v] = src
    if not sub:
        return False
    return _rewrite(fn, lambda e: _subst(e, sub))


# ----------------------------------------------------------------- load forwarding
def _forward_loads(fn: IRFunction) -> bool:
    from .ir import map_stmt
    changed = False
    while True:
        uses = _count_uses(fn)
        progressed = False
        for b in fn.blocks.values():
            for di, ds in enumerate(b.stmts):
                if not (isinstance(ds, Assign) and isinstance(ds.dst, Var)):
                    continue
                src = ds.src
                if isinstance(src, Phi) or not _has(src, Load) or _has(src, Call):
                    continue
                if uses.get(ds.dst, 0) != 1:
                    continue
                use_idx = None
                for j in range(di + 1, len(b.stmts)):
                    st = b.stmts[j]
                    if _uses_var(st, ds.dst):
                        use_idx = j
                        break
                    if isinstance(st, BARRIERS):
                        break  # a memory write sits between the load and its use
                if use_idx is None:
                    continue
                map_stmt(b.stmts[use_idx], lambda e: _subst(e, {ds.dst: src}))
                del b.stmts[di]
                progressed = changed = True
                break
            if progressed:
                break
        if not progressed:
            return changed


# ------------------------------------------------------------- condition recovery
def _sub_ops(x: Expr):
    return (x.a, x.b) if isinstance(x, BinOp) and x.op == "-" else None


def _match_signed(p: Expr, q: Expr):
    """`(a-b) <s 0` paired with `sborrow(a, b)` -> (a, b)  (the `SF`/`OF` of a cmp)."""
    if isinstance(p, BinOp) and p.op == "<s" and isinstance(p.b, Const) and p.b.value == 0:
        s = _sub_ops(p.a)
        if s and isinstance(q, BinOp) and q.op == "sborrow" and q.a == s[0] and q.b == s[1]:
            return s
    return None


def _or_le(a: Expr, b: Expr):
    """`(a < b) | (a == b)` -> `a <= b` (same signedness)."""
    if isinstance(a, BinOp) and a.op in ("<u", "<s") and isinstance(b, BinOp) and b.op == "==" \
            and a.a == b.a and a.b == b.b:
        return BinOp("<=u" if a.op == "<u" else "<=s", a.a, a.b, 1)
    return None


def _and_gt(a: Expr, b: Expr):
    """`!(a < b) & !(a == b)` -> `b < a`  (strictly greater)."""
    na = a.a if isinstance(a, UnOp) and a.op == "!" else None
    nb = b.a if isinstance(b, UnOp) and b.op == "!" else None
    if na is None or nb is None:
        return None
    for cmp, eq in ((na, nb), (nb, na)):
        if isinstance(cmp, BinOp) and cmp.op in ("<u", "<s") and isinstance(eq, BinOp) and eq.op == "==" \
                and cmp.a == eq.a and cmp.b == eq.b:
            return BinOp(cmp.op, cmp.b, cmp.a, 1)
    return None


def _combine_node(e: Expr) -> Expr:
    if not isinstance(e, BinOp):
        return e
    op, a, b = e.op, e.a, e.b
    if op in ("==", "!="):
        for x, y in ((a, b), (b, a)):
            if isinstance(y, Const) and y.value == 0:
                s = _sub_ops(x)
                if s:
                    return BinOp(op, s[0], s[1], 1)
        m = _match_signed(a, b) or _match_signed(b, a)
        if m:
            lt = BinOp("<s", m[0], m[1], 1)
            return lt if op == "!=" else UnOp("!", lt, 1)
    elif op == "|":
        return _or_le(a, b) or _or_le(b, a) or e
    elif op == "&":
        return _and_gt(a, b) or _and_gt(b, a) or e
    return e


_INVERT = {"==": "!=", "!=": "=="}
_SWAP = {"<u": "<=u", "<=u": "<u", "<s": "<=s", "<=s": "<s"}


def _tidy_node(e: Expr) -> Expr:
    """Push `!` into a comparison so conditions read naturally (`!(a < b)` -> `b <= a`)."""
    if isinstance(e, UnOp) and e.op == "!":
        x = e.a
        if isinstance(x, UnOp) and x.op == "!" and x.a.bits == 1:
            return x.a
        if isinstance(x, BinOp):
            if x.op in _INVERT:
                return BinOp(_INVERT[x.op], x.a, x.b, 1)
            if x.op in _SWAP:
                return BinOp(_SWAP[x.op], x.b, x.a, 1)
    return e


def _conditions(fn: IRFunction) -> bool:
    return _rewrite(fn, lambda e: transform(transform(e, _combine_node), _tidy_node))


# -------------------------------------------------------------- dead-code elimination
def _dce(fn: IRFunction) -> bool:
    changed = False
    while True:
        uses = _count_uses(fn)
        removed = False
        for b in fn.blocks.values():
            kept = []
            for s in b.stmts:
                if isinstance(s, Assign) and isinstance(s.dst, Var) \
                        and uses.get(s.dst, 0) == 0 and _droppable(s.src):
                    removed = True
                    continue
                if isinstance(s, (CallStmt, Effect, Unknown)):
                    live = [(r, v) for r, v in s.defs if not (isinstance(v, Var) and uses.get(v, 0) == 0)]
                    if len(live) != len(s.defs):
                        s.defs = live
                        removed = True
                kept.append(s)
            b.stmts = kept
        changed |= removed
        if not removed:
            return changed


# ---------------------------------------------------------------------- driver
def optimize(fn: IRFunction, arch: ArchInfo | None = None) -> IRFunction:
    """Run every pass to a fixpoint. Mutates and returns `fn` (expects SSA input)."""
    for _ in range(MAX_ITERS):
        changed = False
        changed |= _fold_pass(fn)
        changed |= _propagate(fn)
        changed |= _forward_loads(fn)
        changed |= _conditions(fn)
        changed |= _dce(fn)
        if not changed:
            break
    return fn


__all__ = ["optimize"]

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

from ..progress import checkpoint
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
    """Safe to drop *or duplicate*: no loads (which could fault) and no calls."""
    return not _has(e, Load, Call)


def _dead_removable(e: Expr) -> bool:
    """Safe to drop when its result is unused: loads are side-effect-free, calls are not."""
    return not _has(e, Call)


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


_NEG_CMP = {"==": "!=", "!=": "==", "<s": ">=s", ">=s": "<s", "<=s": ">s", ">s": "<=s",
            "<u": ">=u", ">=u": "<u", "<=u": ">u", ">u": "<=u"}


def _not(c: Expr) -> Expr:
    """Logical negation, pushed through comparisons and (De Morgan) 1-bit `&` / `|`."""
    if isinstance(c, UnOp) and c.op == "!":
        return c.a
    if isinstance(c, BinOp) and c.op in ("<s", "<=s", "<u", "<=u"):     # IR spelling: swap operands
        return BinOp({"<s": "<=s", "<=s": "<s", "<u": "<=u", "<=u": "<u"}[c.op], c.b, c.a, 1)
    if isinstance(c, BinOp) and c.op in _NEG_CMP:
        return BinOp(_NEG_CMP[c.op], c.a, c.b, 1)
    if isinstance(c, BinOp) and c.op in ("&", "|") and c.bits == 1:
        return BinOp("|" if c.op == "&" else "&", _not(c.a), _not(c.b), 1)
    return UnOp("!", c, 1)


_FLIP = {">s": "<s", ">=s": "<=s", ">u": "<u", ">=u": "<=u"}


def _canon_cmp(e: Expr) -> Expr:
    """`b > a` as `a < b`: one spelling per comparison."""
    if isinstance(e, BinOp) and e.op in _FLIP:
        return BinOp(_FLIP[e.op], e.b, e.a, 1)
    return e


def _same_cond(x: Expr, y: Expr) -> bool:
    x, y = _canon_cmp(x), _canon_cmp(y)
    if x == y:
        return True
    return isinstance(x, BinOp) and isinstance(y, BinOp) and x.op == y.op and x.op in ("&", "|", "==", "!=") \
        and _same_cond(x.a, y.b) and _same_cond(x.b, y.a)


def _negation(x: Expr, y: Expr) -> bool:
    """`x` is the logical negation of `y` (1-bit conditions; ARM `gt` / `le` flag tests included)."""
    return _same_cond(x, _not(y)) or _same_cond(_not(x), y)


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
        elif op in ("==", "!=") and z(b) and isinstance(a, BinOp) and a.op == "|" and \
                isinstance(a.b, Const) and a.b.value and _droppable(a.a):
            return Const(int(op == "!="), 1)          # `(x | 1) == 0` never holds
        elif op in ("==", "!=") and z(b) and isinstance(a, Cast) and a.kind == "zext" and a.a.bits == 1:
            return a.a if op == "!=" else _not(a.a)   # `(int)c == 0` -> `!c`
    elif isinstance(e, UnOp) and isinstance(e.a, UnOp) and e.op == e.a.op and e.op in ("-", "~"):
        return e.a.a
    elif isinstance(e, UnOp) and e.op == "!" and isinstance(e.a, UnOp) and e.a.op == "!" and e.a.a.bits == 1:
        return e.a.a
    elif isinstance(e, Ite) and e.a == e.b:
        return e.a
    elif isinstance(e, Ite) and isinstance(e.a, Const) and isinstance(e.b, Const) and \
            {e.a.value, e.b.value} == {0, 1} and e.cond.bits == 1:
        # `c ? 1 : 0` is `c`, `c ? 0 : 1` is `!c`
        c = e.cond if e.a.value == 1 else _not(e.cond)
        return c if e.bits == 1 else Cast("zext", c, e.bits)
    elif isinstance(e, Ite) and e.bits == 1 and not isinstance(e.b, Const) and _same_cond(e.b, e.cond):
        return Ite(e.cond, e.a, Const(0, 1), 1)       # `c ? x : c` -> `c ? x : 0`
    elif isinstance(e, Ite) and e.bits == 1 and not isinstance(e.a, Const) and _same_cond(e.a, e.cond):
        return Ite(e.cond, Const(1, 1), e.b, 1)
    elif isinstance(e, Ite) and isinstance(e.b, Ite) and (e.b.cond == e.cond or _negation(e.b.cond, e.cond)):
        # predicated moves (`moveq r3, #1; movne r3, #0`): the inner test is decided by the outer one
        return Ite(e.cond, e.a, e.b.b if e.b.cond == e.cond else e.b.a, e.bits)
    elif isinstance(e, Cast) and e.a.bits == e.bits:
        return e.a
    elif isinstance(e, Cast) and e.kind == "low" and isinstance(e.a, BinOp) and e.a.op in ("|", "^", "+"):
        # low_n((x & C) | y) == low_n(y) when C keeps none of the low n bits (a partial register
        # write such as `setle bl` merging into ebx)
        def high_only(t):
            return isinstance(t, BinOp) and t.op == "&" and _droppable(t) and \
                any(isinstance(k, Const) and k.value & mask(e.bits) == 0 for k in (t.a, t.b))
        a, b = e.a.a, e.a.b
        if high_only(a):
            return Cast("low", b, e.bits) if b.bits > e.bits else b
        if high_only(b):
            return Cast("low", a, e.bits) if a.bits > e.bits else a
    elif isinstance(e, Cast) and e.kind == "low" and isinstance(e.a, Cast) and e.bits <= e.a.a.bits:
        # low_n(cast_m(x)) == low_n(x) when x is at least n bits wide
        return Cast("low", e.a.a, e.bits)
    return e


def _fold_pass(fn: IRFunction) -> bool:
    return _rewrite(fn, lambda e: transform(e, lambda x: _simp_node(_fold_node(x))))


# ----------------------------------------------------- constant / copy propagation
_FLAG_NAMES = frozenset(("zf", "cf", "sf", "of", "pf"))


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
        elif v.name in _FLAG_NAMES and not isinstance(src, Ite) and _droppable(src) and sum(1 for _ in walk(src)) <= 8:
            # a flag read by several conditions (ARM predicated code): duplicate the compare so
            # every condition can be recombined into a plain comparison
            sub[v] = src
    if not sub:
        return False
    return _rewrite(fn, lambda e: _subst(e, sub))


# ----------------------------------------------------------------- load forwarding
def _forward_loads(fn: IRFunction) -> bool:
    from .ir import map_stmt
    changed = False
    # forwarding moves an expression from one statement into another: every other
    # variable keeps its use count, so one count serves the whole pass
    uses = _count_uses(fn)
    for b in fn.blocks.values():
        di = 0
        while di < len(b.stmts):
            ds = b.stmts[di]
            src = ds.src if isinstance(ds, Assign) else None
            if not (isinstance(ds, Assign) and isinstance(ds.dst, Var)) or isinstance(src, Phi) \
                    or not _has(src, Load) or _has(src, Call) or uses.get(ds.dst, 0) != 1:
                di += 1
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
                di += 1
                continue
            map_stmt(b.stmts[use_idx], lambda e, v=ds.dst, src=src: _subst(e, {v: src}))
            del b.stmts[di]
            uses.pop(ds.dst, None)
            changed = True
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
        # `cmp x, 0`: folding has already turned `x - 0` into `x`
        if isinstance(q, BinOp) and q.op == "sborrow" and q.a == p.a and isinstance(q.b, Const) and q.b.value == 0:
            return p.a, q.b
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


def _le_and_ne(a: Expr, b: Expr):
    """`(x <= y) & (x != y)` -> `x < y` (ARM's `hi` / `gt`: carry or N==V together with !Z)."""
    if isinstance(a, BinOp) and a.op in ("<=u", "<=s") and isinstance(b, BinOp) and b.op == "!=" \
            and {b.a, b.b} == {a.a, a.b}:
        return BinOp("<u" if a.op == "<=u" else "<s", a.a, a.b, 1)
    return None


def _combine_node(e: Expr) -> Expr:
    if not isinstance(e, BinOp):
        return e
    op, a, b = e.op, e.a, e.b
    if op in ("==", "!=") and isinstance(b, Const) and b.value == 0 and a.bits == 1:
        # a flag compared with 0 (`SF != OF` once `test` made OF zero): the flag itself, or its negation
        return a if op == "!=" else UnOp("!", a, 1)
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
        return _and_gt(a, b) or _and_gt(b, a) or _le_and_ne(a, b) or _le_and_ne(b, a) or e
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


def _hoist_ite(e: Expr) -> Expr:
    """`op(c ? x1 : y1, c ? x2 : y2)` -> `c ? op(x1, x2) : op(y1, y2)` for boolean results.

    AArch64 `ccmp` leaves every flag as `c ? <compare> : <constant>`; with the
    selects hoisted out of a condition, each side is a plain flag pattern the
    other rules recover (`a2 > 1`) or a constant that folds away.
    """
    if e.bits != 1 or not isinstance(e, (BinOp, UnOp)):
        return e
    kids = (e.a, e.b) if isinstance(e, BinOp) else (e.a,)
    ites = [k for k in kids if isinstance(k, Ite)]
    if not ites or any(k.cond != ites[0].cond for k in ites):
        return e
    c = ites[0].cond
    if any(not isinstance(k, Ite) and not _droppable(k) for k in kids):
        return e

    def side(pick):
        ks = tuple(pick(k) if isinstance(k, Ite) else k for k in kids)
        return BinOp(e.op, ks[0], ks[1], 1) if isinstance(e, BinOp) else UnOp(e.op, ks[0], 1)
    return Ite(c, side(lambda k: k.a), side(lambda k: k.b), 1)


def bool_ite(e: Expr) -> Expr:
    """A boolean select with a constant side is a short-circuit condition (used for display:
    the IR keeps the select so `_hoist_ite` can still see it)."""
    if not (isinstance(e, Ite) and e.bits == 1):
        return e
    c, a, b = e.cond, e.a, e.b
    if isinstance(b, Const):
        return BinOp("&&", c, a, 1) if b.value == 0 else BinOp("||", UnOp("!", c, 1), a, 1)
    if isinstance(a, Const):
        return BinOp("||", c, b, 1) if a.value else BinOp("&&", UnOp("!", c, 1), b, 1)
    return e


def _conditions(fn: IRFunction) -> bool:
    def one(e):
        e = transform(e, _hoist_ite)
        e = transform(e, lambda x: _simp_node(_fold_node(x)))
        return transform(transform(e, _combine_node), _tidy_node)
    return _rewrite(fn, one)


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
                        and uses.get(s.dst, 0) == 0 and _dead_removable(s.src):
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
        checkpoint()                 # a cancelled decompilation stops between rounds
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

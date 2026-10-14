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
from .fp import fold_fcmp, is_fcmp, negate_fcmp
from .interp import InterpError, apply_binop, apply_cast, apply_unop
from .ir import (BARRIERS, Assign, BinOp, Branch, Call, CallStmt, Cast, Const, Effect, Expr, Extract, IRFunction,
                 Ite, Jump, Load, Phi, Return, UnOp, Unknown, Var, children, mask, stmt_exprs, transform, walk)

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


def _add_uses(c: Counter, s, k: int = 1) -> None:
    """Add `k` to the count of every variable statement `s` reads (an explicit stack: this
    runs over every statement of every pass round, generator recursion costs too much)."""
    stack = list(stmt_exprs(s))
    pop, push = stack.pop, stack.extend
    while stack:
        x = pop()
        if isinstance(x, Var):
            c[x] += k
        else:
            push(children(x))


def _count_uses(fn: IRFunction) -> Counter:
    c: Counter = Counter()
    for s in fn.stmts():
        _add_uses(c, s)
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


def _fixed(f, memo: dict | None):
    """`f` (a pure rewrite of one expression) skipping expressions it already left unchanged:
    `memo` maps id -> expression for those (the expression is kept alive, so its id is not
    reused). An unchanged result returns the original object, so it stays known next round."""
    if memo is None:
        return f

    def g(e: Expr) -> Expr:
        if memo.get(id(e)) is e:
            return e
        r = f(e)
        if r == e:
            memo[id(e)] = e
            return e
        return r
    return g


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
    if is_fcmp(c):
        return negate_fcmp(c)
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


def _simp_extract(e: Extract) -> Expr:
    """Bits [lo, lo+w) of a value built from parts (ARM `s15`, the high half of a `d7` that a
    write of `s14` / `s15` merged): the part that supplies those bits."""
    a, lo, w = e.a, e.lo, e.bits
    span = mask(w) << lo
    if isinstance(a, BinOp) and a.op == "|" and _droppable(a):
        for x, y in ((a.a, a.b), (a.b, a.a)):
            if isinstance(x, BinOp) and x.op == "&" and any(isinstance(k, Const) and not k.value & span
                                                             for k in (x.a, x.b)):
                return _simp_extract(Extract(y, lo, w))
            if isinstance(x, Const) and not x.value & span:          # a constant in the other half
                return _simp_extract(Extract(y, lo, w))
    if isinstance(a, BinOp) and a.op == "&" and isinstance(a.b, Const) and a.b.value & span == span:
        return _simp_extract(Extract(a.a, lo, w))                     # a mask that keeps these bits
    if isinstance(a, BinOp) and a.op == "<<" and isinstance(a.b, Const) and a.b.value == lo:
        v = a.a
        if isinstance(v, Cast) and v.kind == "zext" and v.a.bits == w:
            return v.a
        if lo == 0:
            return Cast("low", v, w) if v.bits > w else v
    if isinstance(a, Cast) and a.kind == "zext" and lo >= a.a.bits:
        return Const(0, w)
    if isinstance(a, Const):
        return Const((a.value >> lo) & mask(w), w)
    return e


def _has_fcmp(e: Expr) -> bool:
    return any(is_fcmp(x) for x in walk(e))


def _simp_node(e: Expr) -> Expr:
    if e.bits == 1 and isinstance(e, (BinOp, UnOp, Ite)) and (not isinstance(e, BinOp) or e.op[0] != "f"):
        f = fold_fcmp(e)
        if f is not e:
            return f
    if isinstance(e, Ite) and e.bits > 1:
        # `c ? 0 : zext(x)` (x 1-bit) -> `zext(c ? 0 : x)`: a condition that can fold further
        k, x = (e.a, e.b) if isinstance(e.a, Const) else (e.b, e.a)
        if isinstance(k, Const) and k.value in (0, 1) and isinstance(x, Cast) and x.kind == "zext" and \
                x.a.bits == 1 and (_has_fcmp(e.cond) or _has_fcmp(x.a)):
            kb = Const(k.value, 1)
            inner = Ite(e.cond, kb, x.a, 1) if k is e.a else Ite(e.cond, x.a, kb, 1)
            return Cast("zext", _simp_node(inner), e.bits)
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
            if isinstance(a, Cast) and a.kind == "zext" and a.a.bits == 1 and isinstance(b, Const) and b.value & 1:
                return a                                  # `(int)c & 0xff`: c is 0 or 1 already
        elif op == "<u" and one(b):
            return BinOp("==", a, Const(0, a.bits), 1)    # `x <u 1` (MIPS `sltiu x, 1`): x == 0
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
    elif isinstance(e, Extract):
        r = _simp_extract(e)
        if r is not e:
            return r
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


def _fold_pass(fn: IRFunction, memo: dict | None = None) -> bool:
    return _rewrite(fn, _fixed(lambda e: transform(e, lambda x: _simp_node(_fold_node(x))), memo))


# ----------------------------------------------------- constant / copy propagation
_FLAG_NAMES = frozenset(("zf", "cf", "sf", "of", "pf", "fpscr_n", "fpscr_z", "fpscr_c", "fpscr_v"))


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


def _conditions(fn: IRFunction, memo: dict | None = None) -> bool:
    def one(e):
        e = transform(e, _hoist_ite)
        e = transform(e, lambda x: _simp_node(_fold_node(x)))
        return transform(transform(e, _combine_node), _tidy_node)
    return _rewrite(fn, _fixed(one, memo))


# -------------------------------------------------------------- dead-code elimination
def _dce(fn: IRFunction) -> bool:
    changed = False
    # counted once: a removed statement takes its reads off the count, which can make the
    # definitions it read dead in the next round
    uses = _count_uses(fn)
    while True:
        removed = False
        for b in fn.blocks.values():
            kept = []
            for s in b.stmts:
                if isinstance(s, Assign) and isinstance(s.dst, Var) \
                        and uses.get(s.dst, 0) == 0 and _dead_removable(s.src):
                    _add_uses(uses, s, -1)
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


def _sign_test(c: Expr) -> bool:
    """`x < 0` / `0 <= x` style: the sign of one value."""
    return isinstance(c, BinOp) and c.op in ("<s", "<=s") and any(isinstance(k, Const) and k.value == 0
                                                                 for k in (c.a, c.b))


def _sign_fixups(fn: IRFunction) -> bool:
    """`if (x < 0) x += 15;` and `return x < 0 ? f(x) : x` written as branches (MIPS has no
    select instruction): turn them into selects, so the division recovery sees gcc's
    rounding of signed power-of-two quotients and remainders. Only sign tests of pure values,
    with nothing else in the branch, are converted."""
    from .cleanup import _relink
    changed = False
    for h in list(fn.blocks.values()):
        last = h.stmts[-1] if h.stmts else None
        if not isinstance(last, Branch) or not _sign_test(last.cond) or last.true == last.false:
            continue
        t, f = fn.blocks.get(last.true), fn.blocks.get(last.false)
        if t is None or f is None:
            continue
        # two returns: `return c ? a : b`
        rets = [b.stmts[0] if len(b.stmts) == 1 and isinstance(b.stmts[0], Return) else None for b in (t, f)]
        if all(r is not None and r.value is not None and _droppable(r.value) for r in rets) and \
                t.preds == [h.addr] and f.preds == [h.addr]:
            r = rets[0]
            h.stmts[-1] = Return(r.addr, Ite(last.cond, rets[0].value, rets[1].value, r.value.bits))
            h.succs = []
            changed = True
            continue
        # a triangle: an empty side block, the values chosen by a phi at the join
        for side, join, c in ((t, f, last.cond), (f, t, _not(last.cond))):
            if side.preds != [h.addr] or side.succs != [join.addr] or \
                    any(not isinstance(s, Jump) for s in side.stmts) or \
                    sorted(join.preds) != sorted([h.addr, side.addr]):
                continue
            phis = [s for s in join.stmts if isinstance(s, Assign) and isinstance(s.src, Phi)]
            srcs = [dict(s.src.sources) for s in phis]
            if not phis or not all(side.addr in d and h.addr in d and _droppable(d[side.addr]) for d in srcs):
                continue
            for s, d in zip(phis, srcs):
                s.src = Ite(c, d[side.addr], d[h.addr], s.src.bits)
            h.stmts[-1] = Jump(last.addr, join.addr)
            h.succs = [join.addr]
            changed = True
            break
    if changed:
        _relink(fn)
    return changed


# ---------------------------------------------------------------------- driver
# ------------------------------------------------------- halves of a register
_LO_KEEP, _HI_KEEP = 0xFFFFFFFF00000000, 0xFFFFFFFF


def _merge(e: Expr):
    """A 32-bit half written into a 64-bit register (ARM `s14` into `d7`, see the lifter's
    `write_reg`): ("lo" | "hi", the rest of the register, the value), else None."""
    if not (isinstance(e, BinOp) and e.op == "|" and e.bits == 64):
        return None
    for keep, v in ((e.a, e.b), (e.b, e.a)):
        if isinstance(keep, BinOp) and keep.op == "&" and isinstance(keep.b, Const):
            if keep.b.value == _LO_KEEP and isinstance(v, Cast) and v.kind == "zext" and v.a.bits == 32:
                return "lo", keep.a, v.a
            if keep.b.value == _LO_KEEP and isinstance(v, Const) and v.value >> 32 == 0:
                return "lo", keep.a, Const(v.value, 32)
            if keep.b.value == _HI_KEEP and isinstance(v, Const) and v.value & 0xFFFFFFFF == 0:
                return "hi", keep.a, Const(v.value >> 32, 32)
            if keep.b.value == _HI_KEEP and isinstance(v, BinOp) and v.op == "<<" and isinstance(v.b, Const) \
                    and v.b.value == 32 and isinstance(v.a, Cast) and v.a.kind == "zext" and v.a.a.bits == 32:
                return "hi", keep.a, v.a.a
    return None


def _read_halves(fn: IRFunction) -> bool:
    """Reads of one half of a register assembled from halves read the value written there: the
    written value goes into a temporary of its own (moving it could cross a store), and
    `low32(d7)` / `d7[32:64]` become that temporary or, for the other half, the same read of the
    register before the write. The 64-bit merges are then usually dead."""
    changed = False
    n = getattr(fn, "_half_temps", 0)
    for b in fn.blocks.values():
        out = []
        for s in b.stmts:
            if isinstance(s, Assign) and isinstance(s.dst, Var):
                m = _merge(s.src)
                if m is not None and not isinstance(m[2], (Var, Const)):
                    n += 1
                    t = Var("_h", n, 32)
                    out.append(Assign(s.addr, t, m[2]))
                    side, rest, _ = m
                    s.src = BinOp("|", BinOp("&", rest, Const(_LO_KEEP if side == "lo" else _HI_KEEP, 64), 64),
                                  Cast("zext", t, 64) if side == "lo" else
                                  BinOp("<<", Cast("zext", t, 64), Const(32, 8), 64), 64)
                    changed = True
            out.append(s)
        b.stmts = out
    fn._half_temps = n
    defs = {s.dst: s.src for s in fn.stmts() if isinstance(s, Assign) and isinstance(s.dst, Var)}

    def half(v: Expr, want: str, depth: int = 12):
        while depth:
            if isinstance(v, Var) and v in defs:
                v = defs[v]
            m = _merge(v)
            if m is None:
                break
            side, rest, val = m
            if side == want:
                return val if not _has(val, Load, Call) else None      # (hoisted into a temporary first)
            v, depth = rest, depth - 1
        return None

    def node(e: Expr) -> Expr:
        if isinstance(e, Cast) and e.kind == "low" and e.bits == 32 and e.a.bits == 64:
            r = half(e.a, "lo")
            return r if r is not None else e
        if isinstance(e, Extract) and e.lo == 32 and e.bits == 32 and e.a.bits == 64:
            r = half(e.a, "hi")
            return r if r is not None else e
        return e
    return _rewrite(fn, lambda e: transform(e, node)) or changed


def _pair_of_loads(lo: Expr, hi: Expr):
    """`[a]:32` and `[a + 4]:32`: the address of the 64-bit value they are the halves of."""
    if isinstance(lo, Load) and isinstance(hi, Load) and lo.bits == hi.bits == 32:
        a = hi.addr
        if isinstance(a, BinOp) and a.op == "+" and a.a == lo.addr and isinstance(a.b, Const) and a.b.value == 4:
            return lo.addr
    return None


def _pair(e: Expr):
    """`zext64(lo) | zext64(hi) << 32` -> (lo, hi), else None."""
    if not (isinstance(e, BinOp) and e.op == "|" and e.bits == 64):
        return None
    for x, y in ((e.a, e.b), (e.b, e.a)):
        if isinstance(x, Cast) and x.kind == "zext" and x.a.bits == 32 and isinstance(y, BinOp) and \
                y.op == "<<" and isinstance(y.b, Const) and y.b.value == 32 and isinstance(y.a, Cast) and \
                y.a.kind == "zext" and y.a.a.bits == 32:
            return x.a, y.a.a
    return None


def _join_halves(fn: IRFunction) -> bool:
    """A double moved through two core registers (ARM `ldrd r2, r3, [x]; vmov d7, r2, r3`) is the
    64-bit value again: `zext(lo) | zext(hi) << 32` of the two halves of one value, of two adjacent
    loads, or -- at a join -- of two phis whose sources are such load pairs (a 64-bit load is put
    after each pair, where no store can come between)."""
    defs = {s.dst: s.src for s in fn.stmts() if isinstance(s, Assign) and isinstance(s.dst, Var)}
    where: dict[Var, tuple] = {}
    for b in fn.blocks.values():
        for k, s in enumerate(b.stmts):
            if isinstance(s, Assign) and isinstance(s.dst, Var):
                where[s.dst] = (b, k)
    changed = False
    n = getattr(fn, "_join_temps", 0)

    def joined(e: Expr) -> Expr:
        nonlocal changed, n
        p = _pair(e)
        if p is None:
            return e
        lo, hi = p
        if isinstance(lo, Cast) and lo.kind == "low" and isinstance(hi, Extract) and hi.lo == 32 and \
                lo.a == hi.a and lo.a.bits == 64:
            changed = True
            return lo.a
        a = _pair_of_loads(lo, hi)
        if a is not None:
            changed = True
            return Load(a, 64)
        pl, ph = defs.get(lo), defs.get(hi)
        if isinstance(pl, Phi) and isinstance(ph, Phi) and where.get(lo, (None,))[0] is where.get(hi, (None,))[0]:
            sl, sh = dict(pl.sources), dict(ph.sources)
            if set(sl) != set(sh):
                return e
            plan = []
            for pred in sl:
                x, y = sl[pred], sh[pred]
                if not (isinstance(x, Var) and isinstance(y, Var) and x in where and y in where):
                    return e
                bx, kx = where[x]
                by, ky = where[y]
                addr = _pair_of_loads(defs[x], defs[y])
                if addr is None or bx is not by or bx.addr != pred:
                    return e
                last = max(kx, ky)
                # the 64-bit load goes after both halves: nothing may write memory in between
                if any(isinstance(t, BARRIERS) for t in bx.stmts[min(kx, ky):last]):
                    return e
                plan.append((pred, bx, last, addr))
            srcs = []
            for pred, bx, last, addr in plan:
                n += 1
                t = Var("_j", n, 64)
                bx.stmts.insert(last + 1, Assign(bx.stmts[last].addr, t, Load(addr, 64)))
                srcs.append((pred, t))
            n += 1
            joined_var = Var("_j", n, 64)
            blk = where[lo][0]
            blk.stmts.insert(0, Assign(blk.addr, joined_var, Phi(tuple(srcs), 64)))
            changed = True
            return joined_var
        return e

    def simple(x: Expr) -> Expr:          # the halves of one value, adjacent loads: anywhere
        nonlocal changed
        p = _pair(x)
        if p is None:
            return x
        lo, hi = p
        if isinstance(lo, Cast) and lo.kind == "low" and isinstance(hi, Extract) and hi.lo == 32 and \
                lo.a == hi.a and lo.a.bits == 64:
            changed = True
            return lo.a
        a = _pair_of_loads(lo, hi)
        if a is not None:
            changed = True
            return Load(a, 64)
        return x
    _rewrite(fn, lambda x: transform(x, simple))
    for b in list(fn.blocks.values()):
        for s in list(b.stmts):
            if not isinstance(s, Assign) or not isinstance(s.src, BinOp):
                continue
            new = joined(s.src)
            if new is not s.src:
                s.src = new
                fn._join_temps = n
                return True                  # positions moved: one at a time, the loop comes back
    fn._join_temps = n
    return changed


def optimize(fn: IRFunction, arch: ArchInfo | None = None) -> IRFunction:
    """Run every pass to a fixpoint. Mutates and returns `fn` (expects SSA input)."""
    folded: dict = {}
    conds: dict = {}
    halves = arch is not None and arch.name.startswith("arm-aapcs")
    for _ in range(MAX_ITERS):
        checkpoint()                 # a cancelled decompilation stops between rounds
        changed = False
        if halves:
            changed |= _read_halves(fn)
            changed |= _join_halves(fn)
        changed |= _fold_pass(fn, folded)
        changed |= _propagate(fn)
        changed |= _forward_loads(fn)
        changed |= _conditions(fn, conds)
        changed |= _sign_fixups(fn)
        changed |= _dce(fn)
        if not changed:
            break
    return fn


__all__ = ["optimize"]

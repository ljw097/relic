"""Chains of `x == C` tests on one value -> `switch` (on the structured tree).

gcc compiles small or sparse switches to compare chains, often split into a
binary search on the value (`if (x > 4) { ...6, 8, 5... } else { ...2, 3, 0, 1... }`).
Three shapes become a switch here:

1. a run of `if (x == C) { ...; return / continue / goto }` in a sequence: every
   case leaves, so a value no case matches falls out of the switch into the code
   that followed the chain -- that code stays after the switch;
2. a range split `if (x <s K) A else B` whose branches are both such case sets
   (every value of A satisfies the test and no value of B does): their union;
3. an else-if chain `if (x == C1) T1 else if (x == C2) T2 ... else E` whose bodies
   need not leave: each case ends in `break`, `E` is the `default`.

A `break` in a moved body that is not inside a nested loop or switch would
then leave the new switch instead of the enclosing loop, so such chains stay
as they are. Fewer than three cases stay an `if` chain.
"""
from __future__ import annotations

from .interp import _s
from .ir import BinOp, Const, Expr, Reg, StackVar, Var, mask
from .structure import Block, Case, If, Jump1, Loop, Ret, Seq, Switch

MIN_CASES = 3
_RANGE = ("<s", "<=s", "<u", "<=u")


def _flatten(n) -> list:
    if isinstance(n, Seq):
        out = []
        for x in n.items:
            out += _flatten(x)
        return out
    return [] if n is None else [n]


def _exits(n) -> bool:
    items = _flatten(n)
    return bool(items) and (isinstance(items[-1], Ret) or
                            isinstance(items[-1], Jump1) and items[-1].kind in ("continue", "goto"))


def _stray_break(n) -> bool:
    """A `break` that would bind to a switch placed around `n`."""
    if isinstance(n, Jump1):
        return n.kind == "break"
    if isinstance(n, Seq):
        return any(_stray_break(x) for x in n.items)
    if isinstance(n, If):
        return _stray_break(n.then) or _stray_break(n.els)
    return False            # Loop / Switch bodies bind their own breaks; blocks hold none


def _empty(n, gotos) -> bool:
    """Nothing to run and no label: can sit between two tests of a chain."""
    return all(isinstance(x, Block) and not x.stmts and (x.copy or x.addr not in gotos) for x in _flatten(n))


def _eq_test(cond) -> tuple[Expr, int] | None:
    """`x == C` (either order) -> (x, C)."""
    if isinstance(cond, BinOp) and cond.op == "==":
        if isinstance(cond.b, Const) and not isinstance(cond.a, Const):
            return cond.a, cond.b.value
        if isinstance(cond.a, Const) and not isinstance(cond.b, Const):
            return cond.b, cond.a.value
    return None


def _range_test(cond, x):
    """A comparison of `x` with a constant -> a predicate on the value, else None."""
    if not (isinstance(cond, BinOp) and cond.op in _RANGE):
        return None
    signed = cond.op.endswith("s")
    strict = not cond.op.startswith("<=")
    bits = x.bits

    def val(v):
        v &= mask(bits)
        return _s(v, bits) if signed else v
    if cond.a == x and isinstance(cond.b, Const):
        k = val(cond.b.value)
        return (lambda v: val(v) < k) if strict else (lambda v: val(v) <= k)
    if cond.b == x and isinstance(cond.a, Const):
        k = val(cond.a.value)
        return (lambda v: k < val(v)) if strict else (lambda v: k <= val(v))
    return None


def _subject(cond):
    """The value a test compares with a constant (`x == C`, or a range test `x <s K`)."""
    t = _eq_test(cond)
    if t is not None and isinstance(t[0], (Var, StackVar, Reg)):
        return t[0]
    if isinstance(cond, BinOp) and cond.op in _RANGE:
        for a, b in ((cond.a, cond.b), (cond.b, cond.a)):
            if isinstance(b, Const) and isinstance(a, (Var, StackVar, Reg)):
                return a
    return None


def _linear(n, x) -> list:
    """`n` as a flat item list, with `if (x == C) { leave } else E` unfolded into
    `if (x == C) { leave }; E` (the same thing, since the `then` side never falls out)."""
    out = []
    for item in _flatten(n):
        if isinstance(item, If) and item.els is not None and _exits(item.then):
            t = _eq_test(item.cond)
            if t is not None and t[0] == x:
                out.append(If(item.addr, item.cond, item.then, None))
                out += _linear(item.els, x)
                continue
        out.append(item)
    return out


def _leaving_cases(items: list, x, gotos, tail_ok: bool):
    """(cases `[(value, body, addr)]`, number of items they span) for a leading run of `items`
    made only of tests of `x` whose matches all leave (shapes 1 and 2). With `tail_ok` the run
    may stop before the end (the rest runs for values no case matches); otherwise it must
    cover every item (a branch of a range split falls out as a whole)."""
    out: list = []
    used = 0
    for k, item in enumerate(items):
        if _empty(item, gotos):
            used = k + 1
            continue
        if isinstance(item, If) and item.els is None:
            t = _eq_test(item.cond)
            if t is not None and t[0] == x and _exits(item.then) and not _stray_break(item.then):
                out.append((t[1] & mask(x.bits), item.then, item.addr))
                used = k + 1
                continue
        if isinstance(item, If):
            pred = _range_test(item.cond, x)
            if pred is not None:
                a = _leaving_cases(_linear(item.then, x), x, gotos, False)
                b = _leaving_cases(_linear(item.els, x), x, gotos, False) if item.els is not None else ([], 0)
                if a is not None and b is not None and all(pred(v) for v, _, _ in a[0]) and \
                        not any(pred(v) for v, _, _ in b[0]):
                    out += a[0] + b[0]
                    used = k + 1
                    continue
        if not tail_ok:
            return None
        break
    return out, used


def _shape(n):
    """Structure for comparing two bodies (duplicated blocks compare equal to their original)."""
    return [(x.addr, tuple(map(id, x.stmts))) if isinstance(x, Block) else repr(x) for x in _flatten(n)]


def _else_if_cases(n, x, gotos=frozenset()):
    """Shape 3: `if (x == C1) T1 else if (x == C2) T2 ... else E` -> (cases, default).

    Range tests may sit in the chain (`else if (x > 8) E`, an unoptimised compare tree) when
    their body is the final `else` -- the default -- and no later case value satisfies them."""
    cases, ranges = [], []
    while isinstance(n, If):
        t = _eq_test(n.cond)
        if t is not None and t[0] == x and not _stray_break(n.then):
            v = t[1] & mask(x.bits)
            if any(pred(v) for pred, _ in ranges):
                return None                     # a dead test under an earlier range: keep it
            cases.append((v, n.then, n.addr))
        else:
            pred = _range_test(n.cond, x)
            if pred is None:
                break
            ranges.append((pred, n.then))
        items = _flatten(n.els)
        while len(items) > 1 and _empty(items[0], gotos):     # a label-less empty block between tests
            items = items[1:]
        n = items[0] if len(items) == 1 else (Seq(items) if items else None)
    if n is not None and _stray_break(n):
        return None
    if ranges and any(_shape(body) != _shape(n) for _, body in ranges):
        return None                             # a range goes somewhere else than the default
    return cases, n


def _switch(addr, x, cases, default=None, add_break=False):
    if len({v for v, _, _ in cases}) != len(cases):
        return None                                   # a repeated value: a dead test, keep it
    out = []
    for v, body, a in sorted(cases, key=lambda c: _s(c[0], x.bits)):
        if add_break and not _exits(body):
            body = Seq(_flatten(body) + [Jump1("break")])
        out.append(Case(a, [_s(v, x.bits)], False, body))
    if default is not None and _flatten(default):
        if add_break and not _exits(default):
            default = Seq(_flatten(default) + [Jump1("break")])
        out.append(Case(addr, [], True, default))
    return Switch(addr, x, out)


def _inner(sw: Switch, gotos) -> Switch:
    return Switch(sw.addr, sw.expr, [Case(c.addr, c.values, c.default, switchify(c.body, gotos))
                                     for c in sw.cases])


def switchify(n, gotos=frozenset()):
    """Rewrite compare chains in the tree `n` (returns the new tree). Chains are matched on the
    original tree first, outermost first, so a range split joins the chains under it."""
    if isinstance(n, Seq):
        items = n.items
        out, k = [], 0
        while k < len(items):
            it = items[k]
            x = _subject(it.cond) if isinstance(it, If) else None
            if x is not None:
                # shapes 1 / 2: the run of leaving tests from here; what follows stays after it
                lin = _linear(Seq(items[k:]), x)
                r = _leaving_cases(lin, x, gotos, True)
                if r is not None and len(r[0]) >= MIN_CASES:
                    sw = _switch(it.addr, x, r[0])
                    if sw is not None:
                        out.append(_inner(sw, gotos))
                        out += [switchify(t, gotos) for t in lin[r[1]:]]
                        return Seq(out)
            out.append(switchify(it, gotos))
            k += 1
        return Seq(out)
    if isinstance(n, If):
        x = _subject(n.cond)
        if x is not None:
            lin = _linear(n, x)
            r = _leaving_cases(lin, x, gotos, True)
            if r is not None and len(r[0]) >= MIN_CASES:
                sw = _switch(n.addr, x, r[0])
                if sw is not None:
                    return Seq([_inner(sw, gotos)] + [switchify(t, gotos) for t in lin[r[1]:]])
            r = _else_if_cases(n, x, gotos)
            if r is not None and len(r[0]) >= MIN_CASES:
                sw = _switch(n.addr, x, r[0], r[1], add_break=True)
                if sw is not None:
                    return _inner(sw, gotos)
        return If(n.addr, n.cond, switchify(n.then, gotos), switchify(n.els, gotos) if n.els is not None else None)
    if isinstance(n, Loop):
        return Loop(n.kind, n.cond, switchify(n.body, gotos), n.header)
    if isinstance(n, Switch):
        return _inner(n, gotos)
    return n


__all__ = ["switchify"]

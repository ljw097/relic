"""Recover division and remainder by constants.

Compilers replace `x / c` by a multiply with a "magic" constant and shifts,
`x % c` by `x - (x / c) * c`, and the test `x % c == r` by a multiply with
the modular inverse of `c` and an unsigned compare. Matching every idiom
by shape is brittle, so this pass checks candidates by evaluation instead:

1. For an arithmetic subexpression of a single variable `x` (after
   following the block-local definitions it uses), guess the divisor --
   from `E(x)` at a large `x` for a quotient, from an already recovered
   division for a remainder, from the inverse of the multiplier for a
   divisibility test.
2. Evaluate the subexpression on edge values (0, ±1, ±c, the extremes)
   and random inputs with the interpreter's own arithmetic, and compare
   with `x / c`, `x % c` or `x % c == r`, signed and unsigned.
3. Only a candidate that matches on every input replaces the expression.

The replacement is exact on all inputs tried; the test set covers the
corner cases where the magic sequences differ from naive ones (negative
dividends, the most negative value), but it is a check, not a proof.
"""
from __future__ import annotations

import random

from .interp import InterpError, _s, apply_binop, apply_cast, apply_unop
from .ir import (Assign, BinOp, Call, CallStmt, Cast, Const, Effect, Expr, Extract, IRFunction, Ite, Load, Reg,
                 StackVar, Store, UnOp, Unknown, Var, children, map_stmt, mask, stmt_defs, transform, walk)

_RNG = random.Random(0x5EED)


def _samples(bits: int) -> list[int]:
    top = 1 << (bits - 1)
    base = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 16, 17, 25, 99, 100, 101, 1000, 12345, 65535, 65536,
            top - 1, top - 2, top >> 1, top, top + 1, (1 << bits) - 1, (1 << bits) - 2, (1 << bits) - 7,
            (1 << bits) - 100, (1 << bits) - 12345]
    return [v & mask(bits) for v in base] + [_RNG.getrandbits(bits) for _ in range(48)] + \
        [_RNG.getrandbits(bits) >> _RNG.randrange(bits) for _ in range(16)]


_SAMPLES = {b: _samples(b) for b in (8, 16, 32, 64)}


def _eval(e: Expr, x: Expr, v: int) -> int:
    if e == x:
        return v & mask(e.bits)
    if isinstance(e, Const):
        return e.value
    if isinstance(e, BinOp):
        return apply_binop(e.op, _eval(e.a, x, v), _eval(e.b, x, v), e.a.bits, e.b.bits) & mask(e.bits)
    if isinstance(e, Cast):
        return apply_cast(e.kind, _eval(e.a, x, v), e.a.bits, e.bits)
    if isinstance(e, UnOp):
        return apply_unop(e.op, _eval(e.a, x, v), e.bits)
    if isinstance(e, Extract):
        return (_eval(e.a, x, v) >> e.lo) & mask(e.bits)
    if isinstance(e, Ite):
        return _eval(e.a, x, v) if _eval(e.cond, x, v) else _eval(e.b, x, v)
    raise InterpError(f"cannot evaluate {e}")


def _leaves(e: Expr) -> set:
    return {n for n in walk(e) if isinstance(n, (Var, StackVar, Reg))}


def _pure(e: Expr) -> bool:
    return not any(isinstance(n, (Load, Call)) for n in walk(e))


def _interesting(e: Expr) -> bool:
    """Contains a magic multiply, a modular-inverse multiply or a recovered division."""
    for n in walk(e):
        if isinstance(n, BinOp):
            if n.op == "*" and any(isinstance(k, Const) and k.value >= 0x10000 for k in (n.a, n.b)):
                return True
            if n.op in ("/s", "/u"):
                return True
            # signed division by 2^k rounds towards zero with the sign bit: `x >>s (w-1)`
            if n.op in (">>s", ">>u") and isinstance(n.b, Const) and n.b.value == n.a.bits - 1:
                return True
            # a magic multiply spelled as shifts and adds (MIPS64: `dsll` / `daddu` chains),
            # then the high bits taken
            if n.op in (">>s", ">>u") and isinstance(n.b, Const) and n.b.value >= 16 and \
                    sum(isinstance(k, BinOp) and k.op == "<<" for k in walk(n.a)) >= 3:
                return True
        # ... or by adding the sign test (`(x >> 4) + (x < 0 && (x & 15))`: PowerPC `srawi; addze`)
        if isinstance(n, BinOp) and n.op == "<s" and isinstance(n.b, Const) and n.b.value == 0:
            return True
        # ... or with a conditional add on negative inputs (`x < 0 ? x + 15 : x`)
        if isinstance(n, Ite) and isinstance(n.cond, BinOp) and n.cond.op in ("<s", "<=s") and \
                any(isinstance(k, Const) and k.value == 0 for k in (n.cond.a, n.cond.b)):
            return True
    return False


def _sdiv(a, c, w):
    """C division (truncating towards zero) of signed `a` by `c` (which may be negative)."""
    sa = _s(a, w)
    q = abs(sa) // abs(c)
    return (q if (sa >= 0) == (c > 0) else -q) & mask(w)


def _smod(a, c, w):
    sa = _s(a, w)
    return (sa - _s(_sdiv(a, c, w), w) * c) & mask(w)


def _matches(full: Expr, x: Expr, ref) -> bool:
    w = x.bits
    try:
        for v in _SAMPLES.get(w, _SAMPLES[64]):
            if _eval(full, x, v) != ref(v) & mask(full.bits):
                return False
    except InterpError:
        return False
    return True


def _extend(expr: Expr, bits: int, kind: str) -> Expr:
    return expr if expr.bits == bits else Cast(kind, expr, bits)


def _recognise(full: Expr, x: Expr) -> Expr | None:
    """`x / c`, `x % c` or `x % c == r` equal to `full` on every sample, or None."""
    w, rb = x.bits, full.bits
    if w not in _SAMPLES:
        return None
    if rb == 1:
        return _divisibility(full, x)
    # quotient: guess c from a large positive dividend
    probe = (1 << (w - 2)) + 12345
    try:
        q = _s(_eval(full, x, probe), rb)
    except InterpError:
        q = 0
    cands = []
    if q != 0:
        c0 = round(probe / q)
        cands += [c for c in (c0, c0 - 1, c0 + 1) if 2 <= abs(c) < (1 << (w - 1))]
        # a large divisor leaves a small quotient: every divisor giving that quotient (`x / 100000`
        # of a 32-bit x: probe / q is ~100005)
        aq = abs(q)
        lo, hi = probe // (aq + 1) + 1, probe // aq
        if 0 < hi - lo < 64:
            sign = 1 if q > 0 else -1
            cands += [sign * c for c in range(lo, hi + 1) if sign * c not in cands and 2 <= c < (1 << (w - 1))]
    for c in cands:
        for signed in (True, False):
            if c < 0 and not signed:
                continue
            f = (lambda v, c=c: _sdiv(v, c, w)) if signed else (lambda v, c=c: (v & mask(w)) // c)
            for ext in ("sext", "zext"):
                ref = (lambda v, f=f, ext=ext: apply_cast(ext, f(v), w, rb)) if rb > w else f
                if rb >= w and _matches(full, x, ref):
                    op = "/s" if signed else "/u"
                    return _extend(BinOp(op, x, Const(c, w), w), rb, ext)
    # remainder: the divisor comes from a division already recovered inside
    divisors = {n.b.value for n in walk(full) if isinstance(n, BinOp) and n.op in ("/s", "/u")
                and isinstance(n.b, Const)}
    # ... or a remainder already, of the dividend widened (x86 `cdq; idiv`: edx:eax % c)
    divisors |= {n.b.value for n in walk(full) if isinstance(n, BinOp) and n.op in ("%s", "%u")
                 and isinstance(n.b, Const) and 2 <= n.b.value < (1 << (w - 1))}
    # a power of two: the remainder keeps the low bits (`& 7` for `% 8`)
    divisors |= {n.b.value + 1 for n in walk(full) if isinstance(n, BinOp) and n.op == "&"
                 and isinstance(n.b, Const) and n.b.value and (n.b.value + 1) & n.b.value == 0}
    # ... keeping the sign bit too (`& 0x80000007`, then `| -8` for negative inputs: MIPS)
    for n in walk(full):
        if isinstance(n, BinOp) and n.op in ("&", "|") and isinstance(n.b, Const):
            low = n.b.value & (mask(n.b.bits) >> 1) if n.op == "&" else -n.b.value & mask(n.b.bits)
            if n.op == "&" and n.b.value >> (n.b.bits - 1) and low and (low + 1) & low == 0:
                divisors.add(low + 1)
            elif n.op == "|" and low > 1 and low & (low - 1) == 0:
                divisors.add(low)
    for c in sorted(divisors):
        for signed in (True, False):
            f = (lambda v, c=c: _smod(v, c, w)) if signed else (lambda v, c=c: (v & mask(w)) % c)
            for ext in ("sext", "zext"):
                ref = (lambda v, f=f, ext=ext: apply_cast(ext, f(v), w, rb)) if rb > w else f
                if rb >= w and _matches(full, x, ref):
                    return _extend(BinOp("%s" if signed else "%u", x, Const(c, w), w), rb, ext)
    return None


_R_SAMPLES = 1024


def _divisibility(full: Expr, x: Expr) -> Expr | None:
    """`(x * inv - k) <=u lim` and friends: the test `x % c == r`."""
    w = x.bits
    cands = set()
    for n in walk(full):
        if isinstance(n, BinOp) and n.op in ("/s", "/u") and isinstance(n.b, Const):
            cands.add(n.b.value)                 # `x == (x / c) * c`
        if not (isinstance(n, BinOp) and n.op == "*"):
            continue
        for k in (n.a, n.b):
            if not (isinstance(k, Const) and k.value & 1 and k.bits == w):
                continue
            try:
                c = pow(k.value, -1, 1 << w)
            except ValueError:
                continue
            for shift in range(0, 6):
                if c << shift < 1 << 16:
                    cands.add(c << shift)
    for c in sorted(cands):
        if c < 2:
            continue
        for signed in (True, False):
            mod = (lambda v, c=c: _s(_smod(v, c, w), w)) if signed else (lambda v, c=c: (v & mask(w)) % c)
            # r: read it off the samples where the test holds (a bounded set: every candidate is
            # checked on the full samples below; the multiples of c find the usual `% c == 0`)
            vals = range(0, min(4 * c, _R_SAMPLES))
            if 4 * c > _R_SAMPLES:
                vals = [*vals, *(k * c for k in range(1, 9))]
            try:
                hits = {mod(v) for v in vals if _eval(full, x, v)}
            except InterpError:
                return None
            if len(hits) != 1:
                continue
            r = hits.pop()
            if _matches(full, x, lambda v, mod=mod, r=r: int(mod(v) == r)):
                op = "%s" if signed else "%u"
                return BinOp("==", BinOp(op, x, Const(c, w), w), Const(r & mask(w), w), 1)
    return None


def _ext32(e: Expr) -> str | None:
    """"zext" / "sext" if `e` is a 32-bit value widened to 64 bits (`x & 0xffffffff`, a cast)."""
    if e.bits != 64:
        return None
    if isinstance(e, Cast) and e.kind in ("zext", "sext") and e.a.bits <= 32:
        return e.kind
    if isinstance(e, BinOp) and e.op == "&" and any(isinstance(k, Const) and k.value == 0xFFFFFFFF
                                                    for k in (e.a, e.b)):
        return "zext"
    return None


def _recognise_narrow(full: Expr, x: Expr, kind: str) -> Expr | None:
    """`full` of a 64-bit `x` known to hold a 32-bit value (`kind`-extended): recognised on that
    value, in terms of `low32(x)`."""
    x32 = Var("__x32", 0, 32)
    proxy = transform(full, lambda n: Cast(kind, x32, 64) if n == x else n)
    rep = _recognise(proxy, x32)
    if rep is None:
        return None
    return transform(rep, lambda n: Cast("low", x, 32) if n == x32 else n)


def recover_division(fn: IRFunction, sext_params: frozenset = frozenset()) -> int:
    """Rewrite division / remainder sequences by constants (non-SSA input, in place).
    `sext_params`: argument registers that hold `int`s sign-extended to 64 bits (RISC-V, MIPS64)."""
    from .ssa import reachable_order
    count = 0
    out_avail: dict[int, dict] = {}
    order = [fn.blocks[a] for a in reachable_order(fn) if a in fn.blocks]
    order += [b for b in fn.blocks.values() if b not in order]
    for b in order:
        # single-def variable -> its definition (one level); a straight-line predecessor's
        # definitions still hold here (an epilogue block after the computation, -O0)
        pred = fn.blocks.get(b.preds[0]) if len(b.preds) == 1 else None
        avail: dict[Expr, Expr] = dict(out_avail.get(pred.addr, {})) if pred is not None and \
            pred.succs == [b.addr] else {}
        out_avail[b.addr] = avail

        def expand(e: Expr, keep=None) -> Expr:
            """Substitute block-local definitions (except `keep`, the dividend), following chains."""
            for _ in range(6):
                new = transform(e, lambda n: avail.get(n, n) if isinstance(n, (Var, StackVar)) and n != keep else n)
                if new == e:
                    break
                e = new
            return e

        def candidates(e: Expr) -> list:
            """Variables that could be the dividend: those of `e`, then of what they are defined as."""
            seen, order, frontier = set(), [], list(_leaves(e))
            while frontier and len(order) < 8:
                y = frontier.pop(0)
                if y in seen:
                    continue
                seen.add(y)
                order.append(y)
                if y in avail:
                    frontier += sorted(_leaves(avail[y]), key=str)
            return order

        for st in b.stmts:
            def rewrite(e: Expr) -> Expr:
                nonlocal count

                def node(n: Expr) -> Expr:
                    nonlocal count
                    if not isinstance(n, (BinOp, Cast, Ite, UnOp)) or not children(n):
                        return n
                    for x in candidates(n):
                        full = expand(n, keep=x)
                        if _leaves(full) == {x} and _pure(full) and _interesting(full):
                            # the first dividend that explains it (`v1 = a1 & 0x80000007` is not one)
                            rep = _recognise(full, x)
                            if rep is None and x.bits == 64:
                                # an argument register holds an int sign-extended, an unsigned int
                                # zero-extended: the one that explains the code is its type
                                kinds = (_ext32(avail[x]),) if x in avail else \
                                    ("sext", "zext") if isinstance(x, Var) and x.version == 0 and \
                                    x.name in sext_params else ()
                                for kind in kinds:
                                    if kind is not None and rep is None:
                                        rep = _recognise_narrow(full, x, kind)
                            if rep is not None:
                                count += 1
                                return rep
                    return n
                return transform(e, node)

            map_stmt(st, rewrite)
            # keep `avail` sound: a definition kills every expansion that reads what it writes
            written = {d for d in stmt_defs(st) if isinstance(d, (Var, StackVar))}
            clobbers_memory = isinstance(st, (Store, CallStmt, Effect, Unknown))
            for k in list(avail):
                lv = _leaves(avail[k])
                if k in written or lv & written or (clobbers_memory and any(isinstance(n, StackVar) for n in lv)):
                    del avail[k]
            # a definition stays usable until something it reads (or its target) is written again;
            # one that reads its own target (`x = x / 10`) cannot be substituted for it
            if isinstance(st, Assign) and isinstance(st.dst, Var) and _pure(st.src) \
                    and st.dst not in _leaves(st.src):
                avail[st.dst] = st.src
    return count


__all__ = ["recover_division"]

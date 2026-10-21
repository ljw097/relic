"""Floating point in the IR: operators, their concrete semantics, and comparison folding.

Values stay bit patterns (an IEEE single in 32 bits, a double in 64) so the
rest of the IR needs no new value kind; the operators say how to read them:

- `f+ f- f* f/` (BinOp, operands and result of one width) and `fneg` (UnOp);
- comparisons, 1-bit results. A comparison of two floats has four outcomes --
  less, equal, greater, unordered (a NaN) -- and each operator is the set of
  outcomes it is true for:

      f<  {lt}      f<=  {lt, eq}      f==  {eq}      f!=  {lt, gt, un}  (C's !=)
      f<u {lt, un}  f<=u {lt, eq, un}  f==u {eq, un}  f!=o {lt, gt}
      funord {un}   ford {lt, eq, gt}

  `comisd a, b` sets ZF = `a f==u b`, PF = `funord`, CF = `a f<u b`; any
  condition built from those flags is a set of outcomes too, and
  `fold_fcmp` turns it back into one comparison (`ja` -> `b f< a`);
- conversions, as intrinsics (integer passes leave them alone): `sitofp`
  (signed integer -> float of the result's width), `fptosi` (truncating float
  -> integer), `fpconv` (float <-> double); `sqrt`, `fabs`, `floor`, ... (and
  their `f`-suffixed single forms).
"""
from __future__ import annotations

import math
import struct

from .ir import BinOp, Const, Expr, UnOp

FARITH = ("f+", "f-", "f*", "f/")
LT, EQ, GT, UN = 1, 2, 4, 8
FCMP = {"f<": LT, "f<=": LT | EQ, "f==": EQ, "f!=": LT | GT | UN, "f<u": LT | UN, "f<=u": LT | EQ | UN,
        "f==u": EQ | UN, "f!=o": LT | GT, "funord": UN, "ford": LT | EQ | GT}
FP_CASTS = ("sitofp", "uitofp", "fptosi", "fptoui", "fpconv")
_BY_SET = {v: k for k, v in FCMP.items()}


def is_fcmp(e: Expr) -> bool:
    return isinstance(e, BinOp) and e.op in FCMP


def is_fp_op(op: str) -> bool:
    return op in FARITH or op in FCMP


# ------------------------------------------------------------------ bit patterns
def to_float(v: int, bits: int) -> float:
    if bits == 32:
        return struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]
    return struct.unpack("<d", struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))[0]


def from_float(x: float, bits: int) -> int:
    if bits == 32:
        try:
            return struct.unpack("<I", struct.pack("<f", x))[0]
        except OverflowError:
            return struct.unpack("<I", struct.pack("<f", math.copysign(math.inf, x)))[0]
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def outcome(a: float, b: float) -> int:
    if math.isnan(a) or math.isnan(b):
        return UN
    return LT if a < b else EQ if a == b else GT


def apply_fbinop(op: str, a: int, b: int, bits: int) -> int:
    x, y = to_float(a, bits), to_float(b, bits)
    if op in FCMP:
        return int(bool(FCMP[op] & outcome(x, y)))
    try:
        if op == "f+":
            r = x + y
        elif op == "f-":
            r = x - y
        elif op == "f*":
            r = x * y
        else:
            r = x / y if y != 0 else (math.nan if x == 0 or math.isnan(x) else math.copysign(math.inf, x) *
                                      math.copysign(1, y))
    except OverflowError:
        r = math.inf
    return from_float(r, bits)


def apply_fcast(kind: str, a: int, src_bits: int, bits: int) -> int:
    if kind == "uitofp":
        return from_float(float(a & ((1 << src_bits) - 1)), bits)
    if kind == "fptoui":
        x = to_float(a, src_bits)
        if math.isnan(x) or x <= -1 or math.isinf(x):
            return 0 if (math.isnan(x) or x < 0) else (1 << bits) - 1
        return min(int(x), (1 << bits) - 1)
    if kind == "sitofp":
        s = a & ((1 << src_bits) - 1)
        if s >> (src_bits - 1):
            s -= 1 << src_bits
        return from_float(float(s), bits)
    if kind == "fpconv":
        return from_float(to_float(a, src_bits), bits)
    # fptosi: truncation; out of range / NaN gives the "integer indefinite" value like cvttsd2si
    x = to_float(a, src_bits)
    if math.isnan(x) or math.isinf(x) or not -(2 ** (bits - 1)) <= int(x) < 2 ** (bits - 1):
        return 1 << (bits - 1)
    return int(x) & ((1 << bits) - 1)


def _fma(x: float, y: float, z: float) -> float:
    """x * y + z rounded once (exact rational arithmetic; inf / nan the plain way)."""
    if not all(map(math.isfinite, (x, y, z))):
        return x * y + z
    from fractions import Fraction
    r = Fraction(x) * Fraction(y) + Fraction(z)
    if r == 0:
        return x * y + z               # the sign of an exact zero
    try:
        return float(r)
    except OverflowError:
        return math.copysign(math.inf, r)


def apply_fintrinsic(name: str, args: list[int], bits: int) -> int:
    x = to_float(args[0], bits)
    base = name[:-1] if bits == 32 and name.endswith("f") and name not in ("fabsf",) else name
    if base in ("fma",):
        return from_float(_fma(x, to_float(args[1], bits), to_float(args[2], bits)), bits)
    if base in ("fmax", "fmin"):           # C fmax / fmin: a NaN operand gives the other one
        y = to_float(args[1], bits)
        if math.isnan(x):
            return args[1]
        if math.isnan(y):
            return args[0]
        if x == y == 0:                    # +0 is larger than -0
            neg = math.copysign(1, x) < 0 and math.copysign(1, y) < 0 if base == "fmax" else \
                math.copysign(1, x) < 0 or math.copysign(1, y) < 0
            return from_float(-0.0 if neg else 0.0, bits)
        return args[0] if (x > y) == (base == "fmax") else args[1]
    if base == "round":                    # halfway cases away from zero
        if not math.isfinite(x):
            return args[0]
        t = float(math.trunc(x))
        if abs(x - t) >= 0.5:              # (x - trunc(x) is exact)
            t += math.copysign(1.0, x)
        return from_float(math.copysign(t, x), bits)
    if name in ("sqrt", "sqrtf"):
        r = math.sqrt(x) if x >= 0 else (x if math.isnan(x) else math.nan)
    elif name in ("fabs", "fabsf"):
        return args[0] & ((1 << (bits - 1)) - 1)
    elif name in ("floor", "floorf"):
        r = float(math.floor(x)) if math.isfinite(x) else x
    elif name in ("ceil", "ceilf"):
        r = float(math.ceil(x)) if math.isfinite(x) else x
    elif name in ("trunc", "truncf"):
        r = float(math.trunc(x)) if math.isfinite(x) else x
    elif name in ("rint", "rintf", "nearbyint", "nearbyintf"):
        r = float(round(x)) if math.isfinite(x) else x
    else:
        raise ValueError(name)
    return from_float(r, bits)


def as_float(e: Expr) -> Expr | None:
    """`e`, a double computed from floats only (floats widened, constants a float holds exactly),
    as the float expression it evaluates: x87 code computes float arithmetic at its own precision
    and rounds when the result is stored -- as C does where FLT_EVAL_METHOD is 2. None when some
    operand is a genuine double (or `e` has no float value in it at all)."""
    from .ir import Intrinsic, Ite
    found = [False]

    def go(x: Expr) -> Expr | None:
        if x.bits != 64:
            return None
        if isinstance(x, Intrinsic) and x.name == "fpconv" and x.args[0].bits == 32:
            found[0] = True
            return x.args[0]
        if isinstance(x, Const):
            v = to_float(x.value, 64)
            return Const(from_float(v, 32), 32) if math.isnan(v) or to_float(from_float(v, 32), 32) == v else None
        if isinstance(x, BinOp) and x.op in FARITH:
            a, b = go(x.a), go(x.b)
            return BinOp(x.op, a, b, 32) if a is not None and b is not None else None
        if isinstance(x, UnOp) and x.op == "fneg":
            a = go(x.a)
            return UnOp("fneg", a, 32) if a is not None else None
        if isinstance(x, Intrinsic) and x.name in ("sqrt", "fabs") and len(x.args) == 1:
            a = go(x.args[0])
            return Intrinsic(x.name + "f", (a,), 32) if a is not None else None
        if isinstance(x, Ite):
            a, b = go(x.a), go(x.b)
            return Ite(x.cond, a, b, 32) if a is not None and b is not None else None
        return None
    r = go(e)
    return r if found[0] else None


FP_INTRINSICS = ("sqrt", "sqrtf", "fabs", "fabsf", "floor", "floorf", "ceil", "ceilf", "trunc", "truncf",
                 "rint", "rintf", "round", "roundf", "fma", "fmaf", "fmax", "fmaxf", "fmin", "fminf")


def literal(v: int, bits: int) -> str:
    """C literal for a float bit pattern: `1.5`, `0.1f`, `-2.0`, `1e+300`."""
    x = to_float(v, bits)
    if math.isnan(x):
        return "NAN" if bits == 64 else "NAN"
    if math.isinf(x):
        return ("-" if x < 0 else "") + "INFINITY"
    if bits == 32:
        # the shortest decimal that reads back as the same single
        for p in range(1, 10):
            s = f"{x:.{p}g}"
            try:
                if struct.unpack("<f", struct.pack("<f", float(s)))[0] == x:
                    break
            except OverflowError:       # (rounded past FLT_MAX: more digits)
                continue
    else:
        s = repr(x)
    if "e" not in s and "." not in s and "n" not in s:
        s += ".0"
    return s + ("f" if bits == 32 else "")


# ------------------------------------------------------------- comparison folding
def _swap(mask_: int) -> int:
    """Outcome set of `b op a` from that of `a op b` (lt <-> gt)."""
    return (mask_ & (EQ | UN)) | (LT if mask_ & GT else 0) | (GT if mask_ & LT else 0)


def _set_of(e: Expr, pair) -> int | None:
    """Outcome set of a 1-bit condition over comparisons of one operand pair, else None."""
    if is_fcmp(e):
        if (e.a, e.b) == pair:
            return FCMP[e.op]
        if (e.b, e.a) == pair:
            return _swap(FCMP[e.op])
        return None
    if isinstance(e, UnOp) and e.op == "!" and e.bits == 1:
        s = _set_of(e.a, pair)
        return None if s is None else (LT | EQ | GT | UN) & ~s
    if isinstance(e, BinOp) and e.bits == 1 and e.op in ("&", "|", "^", "==", "!=", "&&", "||"):
        x, y = _set_of(e.a, pair), _set_of(e.b, pair)
        if x is None or y is None:
            return None
        full = LT | EQ | GT | UN
        return {"&": x & y, "&&": x & y, "|": x | y, "||": x | y, "^": x ^ y, "!=": x ^ y,
                "==": full & ~(x ^ y)}[e.op]
    if isinstance(e, Const) and e.bits == 1:
        return (LT | EQ | GT | UN) if e.value else 0
    from .ir import Ite
    if isinstance(e, Ite) and e.bits == 1:
        c, x, y = _set_of(e.cond, pair), _set_of(e.a, pair), _set_of(e.b, pair)
        if c is None or x is None or y is None:
            return None
        return (c & x) | ((LT | EQ | GT | UN) & ~c & y)
    return None


def _pair(e: Expr):
    if is_fcmp(e):
        return (e.a, e.b)
    for k in ("cond", "a", "b"):
        x = getattr(e, k, None)
        if isinstance(x, Expr):
            p = _pair(x)
            if p is not None:
                return p
    return None


def fold_fcmp(e: Expr) -> Expr:
    """A 1-bit combination of comparisons of the same two floats -> one comparison."""
    from .ir import Ite
    if not (e.bits == 1 and isinstance(e, (BinOp, UnOp, Ite))) or is_fcmp(e) and e.op in ("f<", "f<=", "f==", "f!="):
        return e
    pair = _pair(e)
    if pair is None:
        return e
    s = _set_of(e, pair)
    if s is None:
        return e
    if s == 0:
        return Const(0, 1)
    if s == LT | EQ | GT | UN:
        return Const(1, 1)
    a, b = pair
    # prefer the spellings C has (ordered <, <=, ==, and unordered-or-unequal !=), operands
    # either way round
    for op in ("f<", "f<=", "f==", "f!="):
        if FCMP[op] == s:
            return BinOp(op, a, b, 1)
        if FCMP[op] == _swap(s):
            return BinOp(op, b, a, 1)
    if s in _BY_SET:
        return BinOp(_BY_SET[s], a, b, 1)
    if _swap(s) in _BY_SET:
        return BinOp(_BY_SET[_swap(s)], b, a, 1)
    # {lt, gt, eq} minus something with unordered: express as the negation of a known set
    neg = (LT | EQ | GT | UN) & ~s
    for cand in (neg, _swap(neg)):
        if cand in _BY_SET:
            x, y = (a, b) if cand == neg else (b, a)
            return UnOp("!", BinOp(_BY_SET[cand], x, y, 1), 1)
    return e


def negate_fcmp(e: BinOp) -> Expr:
    """`!(a op b)` as one comparison."""
    return fold_fcmp(UnOp("!", e, 1))

"""Floating-point arguments and results in the x86-64 calling conventions.

SysV passes `double` / `float` arguments in xmm0-xmm7 (separately from the
integer registers) and returns them in xmm0; Win64 gives every argument a
position, in rcx/rdx/r8/r9 or xmm0-xmm3 by its type. Which registers carry
floats is worked out the same way as for integers: from libc signatures and
format strings, from what an internal callee reads on entry, and -- for
results -- from what callers read after the call.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .arch import ArchInfo
from .ir import Assign, CallStmt, Cast, Expr, IRFunction, Reg, Return, Var, children, stmt_defs, stmt_exprs

if TYPE_CHECKING:
    from ..analysis import Analysis, Function

FP_ARGS = {"x64-sysv": tuple(f"xmm{k}" for k in range(8)), "x64-win": tuple(f"xmm{k}" for k in range(4))}
FP_RET = "xmm0"
FLOAT_CONVS = "eEfFgGaA"
# libc functions taking / returning floating point: argument codes `d` double, `f` float
FP_SIGS = {
    "sqrt": ("d", "double"), "sqrtf": ("f", "float"), "pow": ("dd", "double"), "powf": ("ff", "float"),
    "sin": ("d", "double"), "cos": ("d", "double"), "tan": ("d", "double"), "atan": ("d", "double"),
    "atan2": ("dd", "double"), "exp": ("d", "double"), "log": ("d", "double"), "log10": ("d", "double"),
    "log2": ("d", "double"), "floor": ("d", "double"), "ceil": ("d", "double"), "round": ("d", "double"),
    "trunc": ("d", "double"), "fabs": ("d", "double"), "fmod": ("dd", "double"), "hypot": ("dd", "double"),
    "sinf": ("f", "float"), "cosf": ("f", "float"), "expf": ("f", "float"), "logf": ("f", "float"),
    "floorf": ("f", "float"), "ceilf": ("f", "float"), "fabsf": ("f", "float"), "roundf": ("f", "float"),
    "fmin": ("dd", "double"), "fmax": ("dd", "double"), "ldexp": ("di", "double"), "frexp": ("dp", "double"),
    "lround": ("d", "long"), "lrint": ("d", "long"),
    "atof": ("s", "double"), "strtod": ("sp", "double"), "strtof": ("sp", "float"), "drand48": ("", "double"),
    "difftime": ("ii", "double"),
}


def is_fp_arch(arch: ArchInfo) -> bool:
    return arch.name in FP_ARGS


def fp_sig(name: str | None):
    from .sigs import base_name
    return FP_SIGS.get(base_name(name))


def ret_bits_of(name: str | None) -> int | None:
    s = fp_sig(name)
    if s is None:
        return None
    return {"double": 64, "float": 32}.get(s[1])


def _width(e: Expr) -> int | None:
    """Width of the float a written xmm value holds: `zext128(<w-bit value>)` -> w; 0 for a
    zeroed register (`pxor xmm0, xmm0`: 0.0 of either width); None: no float."""
    from .fpconst import is_float_expr
    from .ir import Const, Load
    if isinstance(e, Const):
        return 0 if e.value == 0 else None
    if isinstance(e, Cast) and e.kind == "zext" and e.a.bits in (32, 64):
        e = e.a
    from .fp import is_fcmp
    from .ir import Ite
    if is_float_expr(e) or isinstance(e, Load) and e.bits in (32, 64) or \
            isinstance(e, Ite) and is_fcmp(e.cond) and e.bits in (32, 64):
        return e.bits
    return None


def _xmm_source(e: Expr) -> str | None:
    """The xmm register a copy reads: `xmm2`, `zext128(low64(xmm2))` (movsd between registers)."""
    if isinstance(e, Cast) and e.kind == "zext":
        e = e.a
    if isinstance(e, Cast) and e.kind == "low":
        e = e.a
    return e.name if isinstance(e, Reg) and e.name.startswith("xmm") else None


def _cache(an: "Analysis", key: str) -> dict:
    return an.__dict__.setdefault("_fpabi_" + key, {})


def fp_return(an: "Analysis", func: "Function") -> int | None:
    """Width (64 double, 32 float) of a floating-point result `func` returns in xmm0, else None."""
    from .arch import arch_for
    try:
        arch = arch_for(an.bin)
    except NotImplementedError:
        return None
    if not is_fp_arch(arch) or func.is_import or (an.name(func.addr) or "") == "main":
        return None
    c = _cache(an, "ret")
    if func.addr in c:
        return c[func.addr]
    c[func.addr] = None                         # recursion guard
    c[func.addr] = r = _fp_return(an, func, arch)
    return r


def set_fp_returns(an: "Analysis", func: "Function", fn: IRFunction) -> int | None:
    """Make the `return`s of a lifted function that returns a float read it from xmm0 (SSA
    construction would otherwise return rax); the float's width, or None."""
    w = fp_return(an, func)
    if w is not None:
        for s in fn.stmts():
            if isinstance(s, Return) and s.value is None:
                s.value = Cast("low", Reg(FP_RET, 128), w)
    return w


def _fp_return(an, func, arch) -> int | None:
    from .cleanup import _lifted, result_reads
    xr = result_reads(an, func, FP_RET)
    ir_ = result_reads(an, func, arch.ret)
    xmm_w = [r for r in xr if isinstance(r, int)]
    int_r = [r for r in ir_ if r != "none"]
    if int_r:
        return None                             # callers use the integer result
    try:
        fn = _lifted(an, func)
    except Exception:
        return None
    # the function must leave a float in xmm0 on every return path, written after any write of
    # the integer result register (callers handing xmm0 straight to another call show no read:
    # their calls' arguments are not known yet)
    last = _last_writes(an, fn, arch)
    if last is None:
        return None
    if xmm_w:
        return 32 if all(w == 32 for w in xmm_w) else 64
    return last


def _last_writes(an, fn: IRFunction, arch: ArchInfo) -> int | None:
    """Width of the float in xmm0 at every `return`, when each path's last write of xmm0 / rax
    is xmm0 with a float; None otherwise."""
    widths = set()
    for b in fn.blocks.values():
        if not b.stmts or not isinstance(b.stmts[-1], Return):
            continue
        w = _scan_back(an, fn, b, len(b.stmts) - 1, arch, set(), 0)
        if w is None:
            return None
        widths.add(w)
    widths.discard(0)
    if not widths:                  # nothing but zeroing: not evidence of a float result
        return None
    return 32 if widths == {32} else 64


def _scan_back(an, fn, b, k, arch, seen, depth, reg: str = FP_RET) -> int | None:
    """Width of the float `reg` holds before statement `k` of block `b`, following copies between
    xmm registers back (`movapd xmm0, xmm2` after `minsd xmm2, ...`); 0 for a zeroed register or an
    untouched float parameter (either width); None when it is not a float (or rax is the result)."""
    for s in reversed(b.stmts[:k]):
        if isinstance(s, CallStmt):
            return callee_ret(an, s) if reg == FP_RET else None
        for d in stmt_defs(s):
            if reg == FP_RET and isinstance(d, Reg) and d.name == arch.ret:
                return None
            if isinstance(d, Reg) and d.name == reg and isinstance(s, Assign):
                src = _xmm_source(s.src)
                if src is not None:
                    reg = src                           # a copy: what the source held
                    break
                return _width(s.src)
            if isinstance(d, Reg) and d.name == reg:
                return None
    if not b.preds:                                     # the function's entry
        return 0 if reg in dict(fp_params(an, arch, fn.addr)) else None
    if depth > 6 or b.addr in seen:
        return None
    seen = seen | {b.addr}
    ws = [_scan_back(an, fn, fn.blocks[p], len(fn.blocks[p].stmts) - (1 if _ends_jump(fn.blocks[p]) else 0),
                     arch, seen, depth + 1, reg) for p in b.preds if p in fn.blocks]
    if not ws or any(w is None for w in ws):
        return None
    ws = [w for w in ws if w]
    return 0 if not ws else 32 if all(w == 32 for w in ws) else 64


def _ends_jump(b) -> bool:
    from .ir import TERMINATORS
    return bool(b.stmts) and isinstance(b.stmts[-1], TERMINATORS)


def callee_ret(an: "Analysis", s: CallStmt) -> int | None:
    """Width of the float result of the call (libc signature or internal callee), else None."""
    w = ret_bits_of(s.name)
    if w is not None:
        return w
    t = s.call.target
    f = an.functions.get(t.value) if hasattr(t, "value") else None
    if f is not None and not f.is_import:
        return fp_return(an, f)
    if f is not None:
        return ret_bits_of(an.name(f.addr) or f.name)
    return None


def fp_params(an: "Analysis", arch: ArchInfo, target: int) -> list[tuple[str, int]]:
    """xmm parameters of an internal callee: the contiguous prefix of xmm argument registers it
    reads on entry, with the width it reads them at (64 double, 32 float)."""
    if not is_fp_arch(arch):
        return []
    c = _cache(an, "params")
    if target in c:
        return c[target]
    from .calls import _entry_ssa
    ssa = _entry_ssa(an, arch, target)
    out: list[tuple[str, int]] = []
    if ssa is not None:
        regs = set(FP_ARGS[arch.name])
        widths: dict[str, int] = {}

        def visit(e: Expr, under: int | None):
            if isinstance(e, Var) and e.version == 0 and e.name in regs:
                w = under if under in (32, 64) else 64
                widths[e.name] = max(widths.get(e.name, 0), w) if e.name in widths else w
                return
            if isinstance(e, Cast) and e.kind == "low":
                visit(e.a, e.bits)
                return
            for k in children(e):
                visit(k, None)
        for s in ssa.stmts():
            if isinstance(s, CallStmt):
                fs = fp_sig(s.name)
                if fs is not None:                       # a wrapper handing its float on
                    for r, v in s.uses:
                        if r in FP_ARGS[arch.name][:sum(1 for ch in fs[0] if ch in "df")]:
                            visit(v, 32 if "f" in fs[0] else 64)
                for k in children(s.call):
                    visit(k, None)
                continue
            if isinstance(s, Assign) and type(s.src).__name__ == "Phi":
                continue
            for top in stmt_exprs(s):
                visit(top, None)
        for r in FP_ARGS[arch.name]:
            if r not in widths:
                break
            out.append((r, widths[r]))
    c[target] = out
    return out


def arg_classes(sig, fmt: str | None, fsig=None, scan: bool = False) -> list[str] | None:
    """`i` / `d` / `f` per argument of a libc call, in order: the signature's fixed arguments and,
    for printf-style formats, one per conversion (`%f` and friends take a double)."""
    if fsig is not None:
        return ["d" if ch == "d" else "f" if ch == "f" else "i" for ch in fsig[0]]
    if sig is None:
        return None
    from .sigs import _CONV
    out = ["i"] * sig.argc
    if sig.fmt is None or fmt is None:
        return out
    out = ["i"] * (sig.fmt + 1)
    for m in _CONV.finditer(fmt):
        conv = m.group(6)
        if conv == "%":
            continue
        out += ["i"] * ((m.group(2) == "*") + (m.group(4) == "*"))
        out.append("d" if conv in FLOAT_CONVS and not scan else "i")
    return out


def assign_regs(arch: ArchInfo, classes: list[str], int_regs: tuple[str, ...]) -> list[str] | None:
    """Registers carrying arguments of these classes, in argument order (None past the registers)."""
    fpr = FP_ARGS.get(arch.name, ())
    out = []
    if arch.name == "x64-win":
        for k, c in enumerate(classes):
            regs = fpr if c in "df" else int_regs
            if k >= len(regs):
                break
            out.append(regs[k])
        return out
    ni = nf = 0
    for c in classes:
        if c in "df":
            if nf >= len(fpr):
                break
            out.append(fpr[nf])
            nf += 1
        else:
            if ni >= len(int_regs):
                break
            out.append(int_regs[ni])
            ni += 1
    return out

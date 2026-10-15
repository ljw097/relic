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
from .ir import (Assign, BinOp, CallStmt, Cast, Const, Expr, Extract, IRFunction, Reg, Return, Var, children, stmt_defs,
                 stmt_exprs)

if TYPE_CHECKING:
    from ..analysis import Analysis, Function

FP_ARGS = {"x64-sysv": tuple(f"xmm{k}" for k in range(8)), "x64-win": tuple(f"xmm{k}" for k in range(4)),
           "arm64-aapcs": tuple(f"v{k}" for k in range(8)),
           "arm-aapcs-vfp": tuple(f"d{k}" for k in range(8)),
           "riscv64-lp64d": tuple(f"fa{k}" for k in range(8))}
FP_RET = "xmm0"                  # x86-64; AArch64 returns floats in v0 (see fp_ret_reg)


def fp_ret_reg(arch: ArchInfo) -> str:
    if arch.name.startswith("arm64"):
        return "v0"
    if arch.name == "arm-aapcs-vfp":
        return "d0"                      # a float result is s0, its low half
    if arch.name.startswith("riscv"):
        return "fa0"
    return FP_RET


def fp_part(name: str) -> tuple[str, int, int | None]:
    """(register holding it, low bit, width or None for the whole) of an FP argument location:
    ARM `s5` is the high half of `d2`; `d2`, `xmm3`, `v3` are themselves; RISC-V `=a1` (a float
    a variadic call passes in a core register) is `a1`."""
    if name[:1] == "=":
        return name[1:], 0, None
    if name[:1] == "s" and name[1:].isdigit():
        k = int(name[1:])
        return f"d{k // 2}", 32 * (k & 1), 32
    return name, 0, None


def reg_bits(name: str) -> int:
    """Width of a full FP register: ARM `d` and RISC-V `fa` 64, SSE / AArch64 128."""
    return 64 if name[:1] in ("d", "f") else 128


def is_fp_reg(name: str) -> bool:
    """An SSE / SIMD-and-FP register (`xmm3`, AArch64 `v3`, ARM VFP `d3` / `s5`, RISC-V `fa3`)."""
    return name.startswith("xmm") or name[:1] in ("v", "d", "s") and name[1:].isdigit() or \
        name[:2] in ("fa", "ft", "fs") and name[2:].isdigit()
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
    if isinstance(e, BinOp) and e.op == "|" and e.bits == 64 and any(
            isinstance(x, BinOp) and x.op == "<<" and isinstance(x.a, Cast) and x.a.kind == "zext"
            and x.a.a.bits == 32 for x in (e.a, e.b)) and not any(
            isinstance(x, BinOp) and x.op == "&" for x in (e.a, e.b)):
        return 64                       # ARM `vmov d7, r2, r3`: a double put together from core registers
    e = _unmerge(e)                                     # ARM `s0 = v` merged into d0
    if isinstance(e, Cast) and e.kind == "zext" and e.a.bits in (32, 64):
        e = e.a
    from .fp import is_fcmp
    from .ir import Ite
    if is_float_expr(e) or isinstance(e, Load) and e.bits in (32, 64) or \
            isinstance(e, Ite) and e.bits in (32, 64) and (is_fcmp(e.cond) or _xmm_source(e.a) or _xmm_source(e.b)):
        return e.bits
    return None


def _unmerge(e: Expr) -> Expr:
    """The value written into part of a register: ARM `(d0 & ~0xffffffff) | zext(v)` -> zext(v)."""
    if isinstance(e, BinOp) and e.op == "|":
        for a, b in ((e.a, e.b), (e.b, e.a)):
            if isinstance(a, BinOp) and a.op == "&" and isinstance(b, (Cast, BinOp)):
                return b.a if isinstance(b, BinOp) and b.op == "<<" else b
    return e


def _xmm_source(e: Expr) -> str | None:
    """The FP register a copy reads: `xmm2`, `zext128(low64(xmm2))` (movsd between registers), ARM
    `s15` (the high half of d7)."""
    e = _unmerge(e)
    if isinstance(e, Cast) and e.kind == "zext":
        e = e.a
    if isinstance(e, (Cast, Extract)) and (not isinstance(e, Cast) or e.kind == "low"):
        e = e.a
    return e.name if isinstance(e, Reg) and is_fp_reg(e.name) else None


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
    busy = _cache(an, "busy")
    c[func.addr] = None                         # recursion guard
    busy[func.addr] = True
    try:
        c[func.addr] = r = _fp_return(an, func, arch)
    finally:
        busy.pop(func.addr, None)
    return r


def fp_return_pending(an: "Analysis", addr: int) -> bool:
    """`fp_return` of this function is being worked out further up the stack (its answer so far,
    None, is only the recursion guard: nothing derived from it should be kept)."""
    return addr in _cache(an, "busy")


def set_fp_returns(an: "Analysis", func: "Function", fn: IRFunction) -> int | None:
    """Make the `return`s of a lifted function that returns a float read it from xmm0 (SSA
    construction would otherwise return rax); the float's width, or None."""
    w = fp_return(an, func)
    if w is not None:
        from .arch import arch_for
        reg = fp_ret_reg(arch_for(an.bin))
        for s in fn.stmts():
            if isinstance(s, Return) and s.value is None:
                s.value = Cast("low", Reg(reg, reg_bits(reg)), w) if w < reg_bits(reg) else Reg(reg, w)
    return w


def _fp_return(an, func, arch) -> int | None:
    from .cleanup import _lifted, result_reads
    xr = result_reads(an, func, fp_ret_reg(arch))
    ir_ = result_reads(an, func, arch.ret)
    xmm_w = [r for r in xr if isinstance(r, int)]
    if fp_ret_reg(arch)[:1] in ("d", "f"):              # ARM d0 / RISC-V fa0 read whole: a double
        xmm_w += [64 for r in xr if r == "whole"]
    int_r = [r for r in ir_ if r != "none"]
    if int_r and not xmm_w:
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
    return last or None


def _last_writes(an, fn: IRFunction, arch: ArchInfo) -> int | None:
    """Width of the float in xmm0 at every `return`, when each path's last write of xmm0 / rax
    is xmm0 with a float (0: only zeroed, or an untouched float parameter); None otherwise."""
    widths = set()
    for b in fn.blocks.values():
        if not b.stmts or not isinstance(b.stmts[-1], Return):
            continue
        w = _scan_back(an, fn, b, len(b.stmts) - 1, arch, set(), 0)
        if w is None:
            return None
        widths.add(w)
    widths.discard(0)
    if not widths:                  # nothing but zeroing / float parameters: no evidence either way
        return 0
    return 32 if widths == {32} else 64


def _scan_back(an, fn, b, k, arch, seen, depth, reg: str | None = None) -> int | None:
    """Width of the float `reg` holds before statement `k` of block `b`, following copies between
    xmm registers back (`movapd xmm0, xmm2` after `minsd xmm2, ...`); 0 for a zeroed register or an
    untouched float parameter (either width); None when it is not a float (or rax is the result)."""
    ret = fp_ret_reg(arch)
    reg = reg or ret
    for s in reversed(b.stmts[:k]):
        if isinstance(s, CallStmt):
            return callee_ret(an, s) if reg == ret else None
        for d in stmt_defs(s):
            if reg == ret and isinstance(d, Reg) and d.name == arch.ret:
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

        halves: dict[str, set] = {}                      # ARM: d register -> {"lo", "hi", "whole"}

        def visit(e: Expr, under: int | None):
            if isinstance(e, Var) and e.version == 0 and e.name in regs:
                w = under if under in (32, 64) else 64
                widths[e.name] = max(widths.get(e.name, 0), w) if e.name in widths else w
                halves.setdefault(e.name, set()).add("lo" if under == 32 else "whole")
                return
            if isinstance(e, Extract) and isinstance(e.a, Var) and e.a.version == 0 and e.a.name in regs \
                    and e.lo == 32 and e.bits == 32:
                halves.setdefault(e.a.name, set()).add("hi")
                widths.setdefault(e.a.name, 32)
                return
            if isinstance(e, Cast) and e.kind == "low":
                visit(e.a, e.bits)
                return
            if isinstance(e, BinOp) and e.op == "&" and isinstance(e.a, Var) and isinstance(e.b, Const) and \
                    e.b.value in (0xFFFFFFFF, 0xFFFFFFFF00000000):
                return              # ARM: the half a write of the other half keeps -- not a read
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
        for k, r in enumerate(FP_ARGS[arch.name]):
            if r not in widths:
                break
            h = halves.get(r, set())
            if arch.name == "arm-aapcs-vfp" and "whole" not in h:
                out += [(f"s{2 * k}", 32)] + ([(f"s{2 * k + 1}", 32)] if "hi" in h else [])
            else:
                out.append((r, widths[r]))
    c[target] = out
    return out


def float_int_params(an: "Analysis", arch: ArchInfo, target: int) -> list[tuple[str, int]]:
    """RISC-V: once fa0-fa7 are taken, further float arguments travel in the integer argument
    registers. The ones an internal callee moves straight into an FP register (`fmv.d.x fa5, a0`)
    with the width moved (64 double, 32 float); empty unless every fa register is a parameter."""
    if not arch.name.startswith("riscv") or len(fp_params(an, arch, target)) < len(FP_ARGS[arch.name]):
        return []
    c = _cache(an, "fint")
    if target in c:
        return c[target]
    from .calls import _entry_ssa, int_arg_regs
    ssa = _entry_ssa(an, arch, target)
    found: dict[str, int] = {}
    if ssa is not None:
        from .ir import Load, Store
        regs = set(int_arg_regs(arch))
        # -O0 spills the register and reloads the slot into an FP register (`sd a0, -80(s0)`,
        # `fld fa5, -80(s0)`)
        spilled = {s.dst: s.src for s in ssa.stmts() if isinstance(s, Store) and isinstance(s.src, Var)
                   and s.src.version == 0 and s.src.name in regs}
        for s in ssa.stmts():
            if not (isinstance(s, Assign) and isinstance(s.dst, Var) and is_fp_reg(s.dst.name)):
                continue
            src = s.src
            if isinstance(src, Load) and src.addr in spilled:
                src = spilled[src.addr] if src.bits == 64 else Cast("low", spilled[src.addr], src.bits)
                if src.bits < 64:
                    src = Cast("zext", src, 64)
            w = 64
            if isinstance(src, Cast) and src.kind in ("zext", "sext") and isinstance(src.a, Cast) and \
                    src.a.kind == "low":
                src, w = src.a.a, src.a.bits
            if isinstance(src, Var) and src.version == 0 and src.name in regs:
                found[src.name] = w
    c[target] = out = [(r, found[r]) for r in int_arg_regs(arch) if r in found]
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


def place_args(arch: ArchInfo, classes: list[str], int_regs: tuple[str, ...],
               variadic: bool = False) -> list[str | None]:
    """Where each argument goes, in argument order: its register, or None for the stack. SysV /
    AAPCS64 fill integer and float registers separately (a float after the seventh integer still
    gets an xmm register); Win64 gives argument k the k-th register of its kind."""
    fpr = FP_ARGS.get(arch.name, ())
    out: list[str | None] = []
    if arch.name == "arm-aapcs-vfp" and variadic:
        # a variadic call uses the base standard even on armhf: a double in an even-odd pair of
        # core registers (`r2:r3`), else on the stack -- and once one is there, all that follow
        ncrn = 0
        for c in classes:
            if c in "df":
                ncrn += ncrn & 1
                if ncrn + 1 < len(int_regs):
                    out.append(f"{int_regs[ncrn]}:{int_regs[ncrn + 1]}")
                    ncrn += 2
                else:
                    ncrn = len(int_regs)
                    out.append(None)
            else:
                out.append(int_regs[ncrn] if ncrn < len(int_regs) else None)
                ncrn += 1
        return out
    if arch.name == "arm-aapcs-vfp":
        # AAPCS-VFP: a double takes the first free aligned pair of single slots (d0-d7), a float
        # the first free slot (s0-s15) -- back-filling a hole a double left -- until one goes to
        # the stack, after which every float argument does
        free = [True] * 16
        ni, stacked = 0, False
        for c in classes:
            if c not in "df":
                out.append(int_regs[ni] if ni < len(int_regs) else None)
                ni += 1
                continue
            slot = None
            if not stacked:
                if c == "d":
                    slot = next((k for k in range(0, 16, 2) if free[k] and free[k + 1]), None)
                else:
                    slot = next((k for k in range(16) if free[k]), None)
            if slot is None:
                stacked = True
                out.append(None)
                continue
            if c == "d":
                free[slot] = free[slot + 1] = False
                out.append(f"d{slot // 2}")
            else:
                free[slot] = False
                out.append(f"s{slot}")
        return out
    if arch.name.startswith("riscv") and variadic:
        # the variadic arguments of a RISC-V call travel in core registers, floats too (and the
        # fixed ones of printf-like functions are pointers and integers)
        out = [None if k >= len(int_regs) else ("=" if c in "df" else "") + int_regs[k]
               for k, c in enumerate(classes)]
        return out
    if arch.name == "x64-win":
        for k, c in enumerate(classes):
            regs = fpr if c in "df" else int_regs
            out.append(regs[k] if k < len(regs) else None)
        return out
    ni = nf = 0
    for c in classes:
        if c in "df":
            out.append(fpr[nf] if nf < len(fpr) else None)
            nf += 1
        else:
            out.append(int_regs[ni] if ni < len(int_regs) else None)
            ni += 1
    return out


def stack_arg_base(arch: ArchInfo) -> int:
    """Offset of the first stack argument from the stack pointer at the call (Win64 leaves the
    callee 32 bytes of home space for the register arguments)."""
    return 32 if arch.name == "x64-win" else 0

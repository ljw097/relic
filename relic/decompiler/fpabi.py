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
           "arm64-aapcs-apple": tuple(f"v{k}" for k in range(8)),
           "arm-aapcs-vfp": tuple(f"d{k}" for k in range(8)),
           "riscv64-lp64d": tuple(f"fa{k}" for k in range(8)),
           "riscv32-ilp32d": tuple(f"fa{k}" for k in range(8)),
           "ppc32-sysv": tuple(f"f{k}" for k in range(1, 9)),
           "ppc64-elfv2": tuple(f"f{k}" for k in range(1, 14)),
           "x86-cdecl": ()}             # (on the stack; a result in x87_0)
FP_RET = "xmm0"                  # x86-64; AArch64 returns floats in v0 (see fp_ret_reg)


def fp_ret_reg(arch: ArchInfo) -> str:
    if arch.name.startswith("arm64"):
        return "v0"
    if arch.name == "arm-aapcs-vfp":
        return "d0"                      # a float result is s0, its low half
    if arch.name.startswith("riscv"):
        return "fa0"
    if arch.name.startswith("ppc"):
        return "f1"
    if arch.name == "x86-cdecl":
        return "x87_0"                   # the bottom of the x87 stack (lift/x87.py)
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
    """Width of a full FP register: ARM `d`, RISC-V `fa` and x87 64, SSE / AArch64 128."""
    return 64 if name[:1] in ("d", "f") or name.startswith("x87_") else 128


def is_fp_reg(name: str) -> bool:
    """An SSE / SIMD-and-FP register (`xmm3`, AArch64 `v3`, ARM VFP `d3` / `s5`, RISC-V `fa3`)."""
    return name.startswith(("xmm", "x87_")) or name[:1] in ("v", "d", "s", "f") and name[1:].isdigit() or \
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
        ppc = an.bin.arch.startswith("ppc")
        for s in fn.stmts():
            if isinstance(s, Return) and s.value is None:
                if (ppc or reg.startswith("x87_")) and w == 32:     # a float result is the double form's value
                    from .ir import Intrinsic
                    s.value = Intrinsic("fpconv", (Reg(reg, 64),), 32)
                else:
                    s.value = Cast("low", Reg(reg, reg_bits(reg)), w) if w < reg_bits(reg) else Reg(reg, w)
    return w


def _fp_return(an, func, arch) -> int | None:
    from .cleanup import _lifted, result_reads
    if arch.name == "x86-cdecl":
        return _x87_return(an, func, arch)
    xr = result_reads(an, func, fp_ret_reg(arch))
    ir_ = result_reads(an, func, arch.ret)
    xmm_w = [r for r in xr if isinstance(r, int)]
    if fp_ret_reg(arch)[:1] in ("d", "f") and not arch.name.startswith("ppc"):
        # ARM d0 / RISC-V fa0 read whole: a double (a PowerPC FPR always holds a double form)
        xmm_w += [64 for r in xr if r == "whole"]
    int_r = [r for r in ir_ if r != "none"]
    ppc_whole = arch.name.startswith("ppc") and any(r == "whole" for r in xr)
    try:
        fn = _lifted(an, func)
    except Exception:
        return None
    if int_r and not xmm_w and not ppc_whole:
        # callers use the integer result -- unless the function never writes it: a caller that
        # knows so (gcc's -fipa-ra) keeps its own value there across the call
        if not ("whole" in xr and not any(isinstance(d, Reg) and d.name == arch.ret
                                          for s in fn.stmts() for d in stmt_defs(s))):
            return None
    # the function must leave a float in xmm0 on every return path, written after any write of
    # the integer result register (callers handing xmm0 straight to another call show no read:
    # their calls' arguments are not known yet)
    last = _last_writes(an, fn, arch)
    if last is None:
        return None
    if xmm_w:
        return 32 if all(w == 32 for w in xmm_w) else 64
    if ppc_whole and not last:
        return 64          # PowerPC: callers read f1 (its double form), the callee only passes one on
    return last or None


def _x87_return(an, func, arch) -> int | None:
    """x87: a function returns a float exactly when it leaves one value on the stack at every
    `ret` (the ABI hands back an empty stack otherwise) -- or tail-calls one that does. A float
    when callers store it as one (`fstp dword`) or its values are float arithmetic, else a double."""
    from ..disasm import RET
    from .cleanup import result_reads
    from .lift.x87 import depths
    try:
        d = depths(an, func)
    except Exception:  # noqa: BLE001 - no x87 summary for a function that does not decode
        return None
    exits = [d.get(i.addr) for b in func.blocks.values() for i in b.insns if i.kind == RET]
    tails = [an.functions.get(t) for t in getattr(func, "tail_calls", ())]
    if not exits and not tails:
        return None
    if any(x != 1 for x in exits):
        return None
    if any(t is None or t.is_import and ret_bits_of(an.name(t.addr)) is None or
           not t.is_import and fp_return(an, t) is None for t in tails):
        return None
    reads = [r for r in result_reads(an, func, fp_ret_reg(arch)) if isinstance(r, int)]
    if reads and all(r == 32 for r in reads) or not reads and _x87_float_result(an, func, arch):
        return 32
    return 64


def _x87_float_result(an, func, arch) -> bool:
    """x87: every value the function returns is float arithmetic (fp.as_float) -- a `float`
    function, whose result the stack holds at its own precision as for any other."""
    import copy

    from .cleanup import _lifted
    from .fp import as_float
    from .ir import Phi, Var, rebuild
    from .passes import optimize
    from .ssa import to_ssa
    fn = copy.deepcopy(_lifted(an, func))
    for s in fn.stmts():
        if isinstance(s, Return):
            s.value = Reg(fp_ret_reg(arch), 64)
    try:
        fn = optimize(to_ssa(fn, arch), arch)
    except Exception:  # noqa: BLE001 - no evidence from a function that does not optimise
        return False
    defs = {s.dst: s.src for s in fn.stmts() if isinstance(s, Assign) and isinstance(s.dst, Var)}

    def expand(e, depth):
        if isinstance(e, Var) and e in defs and not isinstance(defs[e], Phi) and depth < 8:
            return expand(defs[e], depth + 1)
        kids = children(e)
        if not kids:
            return e
        return rebuild(e, tuple(expand(k, depth) for k in kids))

    def values(e, seen):
        if isinstance(e, Var) and isinstance(defs.get(e), Phi):
            if e in seen:
                return []
            seen.add(e)
            return [x for _, v in defs[e].sources for x in values(v, seen)]
        return [expand(e, 0)]
    outs = [x for s in fn.stmts() if isinstance(s, Return) and s.value is not None for x in values(s.value, set())]
    return bool(outs) and all(as_float(x) is not None for x in outs)


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
                w = _width(s.src)
                if w == 64 and arch.name.startswith("ppc") and _widened_float(s.src):
                    return 32                           # PowerPC: a float result, held as a double
                return w
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


def _widened_float(e: Expr) -> bool:
    """A float widened to double (`fpconv64(<32-bit>)`): how a PowerPC FPR holds a single."""
    from .ir import Intrinsic
    return isinstance(e, Intrinsic) and e.name == "fpconv" and e.bits == 64 and e.args[0].bits == 32


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
        ppc = arch.name.startswith("ppc")

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
            if ppc and type(e).__name__ == "Intrinsic" and e.name == "fpsingle":
                visit(e.args[0], 32)                    # PowerPC: a float read from its double form
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
    with the width moved (64 double, 32 float); empty unless every fa register is a parameter.
    RV32 has no 64-bit move: a double comes in a pair of registers (`a0:a1`) the callee stores
    side by side and reloads with `fld`."""
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
        from .calls import _split_addr
        words: dict = {}                  # the word stored at each stack slot so far (in order)
        order = list(int_arg_regs(arch))
        for s in ssa.stmts():
            if isinstance(s, Store):
                words[_split_addr(s.dst)] = s.src
                continue
            if not (isinstance(s, Assign) and isinstance(s.dst, Var) and is_fp_reg(s.dst.name)):
                continue
            src = s.src
            if arch.bits == 32 and isinstance(src, Load) and src.bits == 64:
                base, k = _split_addr(src.addr)
                lo, hi = words.get((base, k)), words.get((base, k + 4))
                if isinstance(lo, Var) and isinstance(hi, Var) and lo.version == hi.version == 0 and \
                        lo.name in order and hi.name in order and \
                        order.index(hi.name) == order.index(lo.name) + 1:
                    found[f"{lo.name}:{hi.name}"] = 64
                continue
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
    regs = list(int_arg_regs(arch))
    c[target] = out = sorted(found.items(), key=lambda rw: regs.index(rw[0].split(":")[0]))
    return out


def join_pair_params(fn, pairs: list[str]):
    """RV32: each double that came in a pair of core registers (`a0:a1`) becomes one 64-bit entry
    value named after the low register, and the two word stores spilling its halves next to each
    other one store of it (so the `fld` that reloads them reads the double)."""
    from .calls import _split_addr
    from .ir import Load, Store, map_stmt, stmt_exprs, transform, walk
    halves = {}
    for p in pairs:
        lo, hi = p.split(":")
        whole = Var(lo, 0, 64)
        halves[(lo, 32)] = Cast("low", whole, 32)
        halves[(hi, 32)] = Extract(whole, 32, 32)

    def sub(e):
        if isinstance(e, Var) and e.version == 0:
            return halves.get((e.name, e.bits), e)
        return e
    for s in fn.stmts():
        map_stmt(s, lambda e: transform(e, sub))
    for b in fn.blocks.values():
        stmts = b.stmts
        for j, s in enumerate(stmts):
            if not (isinstance(s, Store) and isinstance(s.src, Cast) and s.src.kind == "low" and
                    isinstance(s.src.a, Var) and s.src.a.bits == 64 and s.src.a.version == 0):
                continue
            base, k = _split_addr(s.dst)
            for j2 in range(j + 1, len(stmts)):
                t = stmts[j2]
                if isinstance(t, Store) and isinstance(t.src, Extract) and t.src.a == s.src.a and \
                        t.src.lo == 32 and _split_addr(t.dst) == (base, k + 4):
                    s.src = s.src.a
                    stmts[j2] = None
                    break
                if not isinstance(t, (Assign, Store)) or isinstance(t, Store) and \
                        _split_addr(t.dst)[0] == base or any(isinstance(x, Load) and _split_addr(x.addr)[0] == base
                                                              for e in stmt_exprs(t) for x in walk(e)):
                    break                               # (something between may read the slot)
        b.stmts = [s for s in stmts if s is not None]


def arg_classes(sig, fmt: str | None, fsig=None, scan: bool = False, wide: bool = False) -> list[str] | None:
    """`i` / `d` / `f` per argument of a libc call, in order: the signature's fixed arguments and,
    for printf-style formats, one per conversion (`%f` and friends take a double). With `wide`,
    `q` for a 64-bit integer conversion (`%lld`, `%jd`: two words on a 32-bit stack)."""
    if fsig is not None:
        return ["d" if ch == "d" else "f" if ch == "f" else "i" for ch in fsig[0]]
    if sig is None:
        return None
    from .sigs import _CONV
    fixed = [{"double": "d", "float": "f"}.get(t, "i") for t in sig.types] if sig.types else []
    out = (fixed + ["i"] * sig.argc)[:sig.argc]
    if sig.fmt is None or fmt is None:
        return out
    out = out[:sig.fmt + 1]
    for m in _CONV.finditer(fmt):
        conv = m.group(6)
        if conv == "%":
            continue
        out += ["i"] * ((m.group(2) == "*") + (m.group(4) == "*"))
        wide_int = wide and not scan and m.group(5) in ("ll", "j") and conv in "diouxX"
        out.append("d" if conv in FLOAT_CONVS and not scan else "q" if wide_int else "i")
    return out


def place_args(arch: ArchInfo, classes: list[str], int_regs: tuple[str, ...],
               variadic: bool = False, fixed: int | None = None) -> list[str | None]:
    """Where each argument goes, in argument order: its register, or None for the stack. SysV /
    AAPCS64 fill integer and float registers separately (a float after the seventh integer still
    gets an xmm register); Win64 gives argument k the k-th register of its kind."""
    fpr = FP_ARGS.get(arch.name, ())
    out: list[str | None] = []
    if arch.name == "arm64-aapcs-apple" and variadic and fixed is not None:
        # Apple arm64: the fixed arguments in registers, every variadic one in an 8-byte stack slot
        return place_args(arch, classes[:fixed], int_regs) + [None] * (len(classes) - fixed)
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
    if arch.name.startswith("riscv") and variadic and arch.bits == 32:
        # RV32: a variadic double in an even-aligned pair of core registers (`a2:a3`), else on the
        # stack
        n = 0
        for c in classes:
            if c in "df":
                n += n & 1
                if n + 1 < len(int_regs):
                    out.append(f"{int_regs[n]}:{int_regs[n + 1]}")
                    n += 2
                else:
                    n = len(int_regs)
                    out.append(None)
            else:
                out.append(int_regs[n] if n < len(int_regs) else None)
                n += 1
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
    if arch.name.startswith("ppc32"):
        return 8                    # past the back chain and the LR save word
    if arch.name.startswith("ppc64"):
        return 96                   # the parameter save area past the 8 register doublewords
    return 32 if arch.name == "x64-win" else 0

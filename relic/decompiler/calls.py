"""Stage 3: recover call arguments and return values.

After optimisation each `CallStmt` still carries the full register traffic
the calling convention allows (`uses`). This pass works out how many of
those registers are real arguments -- from a libc signature for imports, or
from the callee's live-in registers for internal functions -- and records
them as `Call.args`, so the IR reads `printf("%s", buf)` instead of a wall
of register assignments.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .arch import ArchInfo
from .ir import Assign, Call, CallStmt, Const, IRFunction, Phi, Var, stmt_exprs, walk
from .sigs import arg_count, lookup

if TYPE_CHECKING:
    from ..analysis import Analysis

# integer argument registers, in order, per calling convention
_INT_ARGS = {
    "x64-sysv": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "x64-win": ("rcx", "rdx", "r8", "r9"),
    "x86-cdecl": (),  # arguments are passed on the stack (recovered with the frame, stage 3b)
}


def int_arg_regs(arch: ArchInfo) -> tuple[str, ...]:
    return _INT_ARGS.get(arch.name, ())


def _read_format(an: "Analysis", value) -> str | None:
    if not isinstance(value, Const):
        return None
    s = an.bin.read_cstring(value.value, 256)
    return s if s else None


def _livein_arg_regs(an: "Analysis", arch: ArchInfo, target: int) -> list[str]:
    """Argument registers an internal callee reads on entry (its parameters, heuristically)."""
    f = an.functions.get(target)
    if f is None or f.is_import:
        return []
    from .lift import lift_function
    from .ssa import to_ssa
    try:
        ssa = to_ssa(lift_function(an, f), arch)
    except Exception:
        return []
    # a call's implicit `uses` list every argument register the convention allows, which
    # would make every register look like a parameter; only count what the callee really
    # reads, plus the registers a known libc callee consumes (wrappers passing args along).
    # Phis are followed only from such real uses (clobbered registers merge at joins).
    phis: dict[Var, Phi] = {}
    used: set[Var] = set()
    for s in ssa.stmts():
        if isinstance(s, Assign) and isinstance(s.src, Phi):
            phis[s.dst] = s.src
            continue
        tops = stmt_exprs(s)
        if isinstance(s, CallStmt):
            tops = [s.call]
            sig = lookup(s.name or (an.name(s.call.target.value) if isinstance(s.call.target, Const) else None))
            if sig is not None:
                keep = set(int_arg_regs(arch)[:sig.argc])
                tops += [v for r, v in s.uses if r in keep]
        used |= {x for top in tops for x in walk(top) if isinstance(x, Var)}
    work = [v for v in used if v in phis]
    while work:
        for x in walk(phis[work.pop()]):
            if isinstance(x, Var) and x not in used:
                used.add(x)
                if x in phis:
                    work.append(x)
    livein = {v.name for v in used if v.version == 0}
    # take the contiguous prefix of argument registers: a gap means the later
    # ones are scratch (e.g. a partial write like `mov dl, al` reads rdx), not parameters
    params: list[str] = []
    for r in int_arg_regs(arch):
        if r not in livein:
            break
        params.append(r)
    return params


def recover_calls(fn: IRFunction, an: "Analysis", arch: ArchInfo) -> IRFunction:
    """Fill in `Call.args` for every resolved call (mutates and returns `fn`)."""
    argregs = int_arg_regs(arch)
    cache: dict[int, list[str]] = {}
    for b in fn.blocks.values():
        for s in b.stmts:
            if not isinstance(s, CallStmt) or not isinstance(s.call.target, Const):
                continue
            uses = dict(s.uses)
            name = s.name or an.name(s.call.target.value)
            sig = lookup(name)
            if sig is not None:
                fmt = _read_format(an, uses.get(argregs[sig.fmt])) if sig.fmt is not None and \
                    sig.fmt < len(argregs) else None
                selected = list(argregs[:arg_count(sig, fmt)])
            else:
                tgt = s.call.target.value
                if tgt not in cache:
                    cache[tgt] = _livein_arg_regs(an, arch, tgt)
                selected = cache[tgt]
            args = [uses[r] for r in selected if r in uses]
            s.call = Call(s.call.target, tuple(args), s.call.bits)
            s.uses = [(r, uses[r]) for r in selected if r in uses]
    return fn


__all__ = ["recover_calls", "int_arg_regs"]

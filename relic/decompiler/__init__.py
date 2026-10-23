"""Decompiler (work in progress). See docs/decompiler-plan.md.

Stage 1: `lift(an, func)` turns a function's CFG into IR (`relic.decompiler.ir`).
Stage 2: `to_ssa` + `optimize` put it in SSA form and clean it up; `ir_xrefs`
and `format_ir` keep strings and cross references visible on the result.
"""
from __future__ import annotations

from .ir import IRFunction
from .lift import lift_function as lift


def decompile_ir(an, func, optimize: bool = True):
    """Lift a function, and (by default) raise it to optimised SSA IR with calls recovered."""
    import copy

    from .arch import arch_for
    from .calls import optimized_ssa, recover_calls
    from .fpabi import set_fp_returns
    from .passes import _dce
    from .passes import optimize as run_passes
    from .ssa import to_ssa
    if func.addr not in func.blocks:
        # (a symbol on data among code: MinGW's `__CTOR_LIST__` in .text)
        raise ValueError(f"no instructions at {func.addr:#x} (its bytes do not decode)")
    if not optimize:
        return lift(an, func)
    try:
        arch = arch_for(an.bin)
    except NotImplementedError:
        return lift(an, func)
    # the optimised SSA before call recovery is what callers read this function's parameters
    # from too: computed once for both (recover_calls changes it: a copy)
    opt = optimized_ssa(an, arch, func.addr)
    if opt is not None:
        fn = copy.deepcopy(opt)
    else:
        fn = lift(an, func)
        set_fp_returns(an, func, fn)
        fn = run_passes(to_ssa(fn, arch), arch)
    fn = recover_calls(fn, an, arch)
    _dce(fn)  # call uses not selected as arguments (stack pointer, scratch registers) are gone
    return fn


__all__ = ["IRFunction", "lift", "decompile_ir"]

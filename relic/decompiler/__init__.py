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
    fn = lift(an, func)
    if not optimize:
        return fn
    from .arch import arch_for
    from .calls import recover_calls
    from .passes import optimize as run_passes
    from .ssa import to_ssa
    try:
        arch = arch_for(an.bin)
    except NotImplementedError:
        return fn
    from .passes import _dce
    from .fpabi import set_fp_returns
    set_fp_returns(an, func, fn)
    fn = recover_calls(run_passes(to_ssa(fn, arch), arch), an, arch)
    _dce(fn)  # call uses not selected as arguments (stack pointer, scratch registers) are gone
    return fn


__all__ = ["IRFunction", "lift", "decompile_ir"]

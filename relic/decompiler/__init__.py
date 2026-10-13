"""Decompiler (work in progress). See docs/decompiler-plan.md.

Stage 1: `lift(an, func)` turns a function's CFG into IR (`relic.decompiler.ir`).
Stage 2: `to_ssa` + `optimize` put it in SSA form and clean it up; `ir_xrefs`
and `format_ir` keep strings and cross references visible on the result.
"""
from __future__ import annotations

from .ir import IRFunction
from .lift import lift_function as lift


def decompile_ir(an, func, optimize: bool = True):
    """Lift a function, and (by default) raise it to optimised SSA IR."""
    fn = lift(an, func)
    if not optimize:
        return fn
    from .arch import arch_for
    from .passes import optimize as run_passes
    from .ssa import to_ssa
    try:
        arch = arch_for(an.bin)
    except NotImplementedError:
        return fn
    return run_passes(to_ssa(fn, arch), arch)


__all__ = ["IRFunction", "lift", "decompile_ir"]

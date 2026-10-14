"""The decompiler pipeline from a function to structured, non-SSA IR.

    lift -> SSA -> optimise -> calls     (decompile_ir)
    frame -> canary / return value -> stack locals -> DCE
    out-of-SSA -> forward empty blocks -> result widths -> narrow -> inline temporaries
    -> structure

`prepare` returns everything the C emitter needs.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .arch import ArchInfo, arch_for
from .arith import recover_division
from .cleanup import (cached_ir, drop_return_values, drop_stack_pointer_chains, fold_short_circuits, forward_empty_blocks, hide_canary,
                      inline_single_use,
                      narrow_library_results, narrow_returns, return_width, returns_value, rewrite_locals)
from .ir import IRFunction
from .outssa import out_of_ssa
from .passes import _dce, _fold_pass
from .stack import Frame, analyze_frame
from .structure import Structurer
from .vartypes import narrow

if TYPE_CHECKING:
    from ..analysis import Analysis, Function


@dataclass
class Prepared:
    fn: IRFunction          # structured-ready, non-SSA IR
    arch: ArchInfo
    frame: Frame
    params: list[str]       # parameter registers, in order
    returns: bool
    tree: object            # structure.Seq
    gotos: set
    ret_bits: int | None = None   # width of the result, when known


def prepare(an: "Analysis", func: "Function") -> Prepared:
    from .calls import _livein_arg_regs
    arch = arch_for(an.bin)
    fn = copy.deepcopy(cached_ir(an, func))
    from .cleanup import stack_guards
    frame = analyze_frame(fn, arch, stack_guards(an))
    hide_canary(fn, frame)
    rets = returns_value(an, func, fn, arch.ret)
    if not rets:
        drop_return_values(fn)
    rewrite_locals(fn, frame)
    drop_stack_pointer_chains(fn, frame)
    _dce(fn)
    fn = out_of_ssa(fn)
    forward_empty_blocks(fn)
    if arch.name == "x86-cdecl":
        # stack parameters: [esp_0 + 4], [esp_0 + 8], ... are a1, a2, ...
        from .calls import stack_param_count
        word = arch.bits // 8
        n = stack_param_count(an, arch, func.addr)
        params = [frame.slots[o].name() if o in frame.slots else f"arg_{o:x}"
                  for o in range(word, word * (n + 1), word)]
    else:
        params = _livein_arg_regs(an, arch, func.addr)
    narrow_library_results(fn)
    from .calls import narrow_call_args
    narrow_call_args(an, arch, fn)
    w = None
    if rets:
        w = return_width(an, func, arch.ret)
        if w is not None:
            narrow_returns(fn, w)
    narrow(fn)
    inline_single_use(fn)
    _fold_pass(fn)          # constants exposed by narrowing and inlining
    recover_division(fn)    # magic-number multiplies -> x / c, x % c
    _dce(fn)
    fold_short_circuits(fn)
    st = Structurer(fn)
    tree = st.run()
    return Prepared(fn, arch, frame, params, rets, tree, st.gotos, w)


__all__ = ["Prepared", "prepare"]

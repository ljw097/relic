"""Machine code -> IR. `lift_function` picks the lifter for the binary's architecture."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...disasm import JMP
from ..ir import TERMINATORS, CallStmt, IRBlock, IRFunction, Jump, Unknown

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function


def lifter_for(an: Analysis):
    if an.bin.arch in ("x86", "x64"):
        from .x86 import X86Lifter
        return X86Lifter(an)
    raise NotImplementedError(f"no lifter for {an.bin.arch} yet")


def lift_function(an: Analysis, f: Function) -> IRFunction:
    lifter = lifter_for(an)
    out = IRFunction(f.addr, an.name(f.addr) or f.name)
    for a in sorted(f.blocks):
        blk = f.blocks[a]
        ib = IRBlock(a, succs=list(blk.succs), preds=list(blk.preds))
        for i in blk.insns:
            if i.kind == JMP and i is blk.last:
                ib.stmts += lifter.lift_jmp(i, f)
            else:
                ib.stmts += lifter.lift_insn(i, f)
        last = ib.stmts[-1] if ib.stmts else None
        ends = isinstance(last, TERMINATORS) or isinstance(last, Unknown) and blk.last.is_terminator or \
            isinstance(last, CallStmt) and last.noreturn
        if not ends and len(blk.succs) == 1:
            ib.stmts.append(Jump(blk.last.addr, blk.succs[0]))
        out.blocks[a] = ib
    return out


__all__ = ["lift_function", "lifter_for"]

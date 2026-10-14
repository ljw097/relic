"""Machine code -> IR. `lift_function` picks the lifter for the binary's architecture."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...disasm import JMP
from ..ir import TERMINATORS, Branch, Call, CallStmt, Const, IRBlock, IRFunction, Jump, Return, Unknown

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function


def lifter_for(an: Analysis):
    if an.bin.arch in ("x86", "x64"):
        from .x86 import X86Lifter
        return X86Lifter(an)
    if an.bin.arch == "arm64":
        from .arm64 import Arm64Lifter
        return Arm64Lifter(an)
    if an.bin.arch == "arm":
        from .arm import ArmLifter
        return ArmLifter(an)
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
    # blocks the lifter split off an instruction (`blne f`, `addls pc, pc, ...`): the block
    # ending in that instruction now branches to the synthetic block or falls through
    extra = getattr(lifter, "extra_blocks", {})
    for a, (stmts, succs) in sorted(extra.items()):
        out.blocks[a] = IRBlock(a, list(stmts), succs=[s for s in succs if s in out.blocks])
    if extra:
        for ib in list(out.blocks.values()):
            last = ib.stmts[-1] if ib.stmts else None
            if not isinstance(last, Branch) or not ({last.true, last.false} & set(extra)):
                continue
            new = [t for t in dict.fromkeys((last.true, last.false)) if t in out.blocks]
            for s in ib.succs:
                if s not in new and s in out.blocks and ib.addr in out.blocks[s].preds:
                    out.blocks[s].preds.remove(ib.addr)
            ib.succs = new
        for ib in out.blocks.values():
            for s in ib.succs:
                if s in out.blocks and ib.addr not in out.blocks[s].preds:
                    out.blocks[s].preds.append(ib.addr)
    # calls to functions of this binary change only the registers the callee writes (gcc keeps
    # values in caller-saved registers across such calls at -O2: -fipa-ra)
    from ..clobbers import callee_clobbers
    for ib in out.blocks.values():
        for s in ib.stmts:
            if isinstance(s, CallStmt) and not s.tail and isinstance(s.call.target, Const):
                s.clobbers = callee_clobbers(an, s.call.target.value)
    # a conditional jump into another function is a conditional tail call: give it a
    # block of its own (call + return) so every branch target is a block of this function
    bits = an.bin.bits
    for ib in list(out.blocks.values()):
        last = ib.stmts[-1] if ib.stmts else None
        if not isinstance(last, Branch):
            continue
        for t in (last.true, last.false):
            if t in f.blocks:
                continue
            if t not in out.blocks:
                out.blocks[t] = IRBlock(t, [CallStmt(last.addr, Call(Const(t, bits), (), bits), tail=True,
                                                     name=an.name(t)), Return(last.addr)])
            if t not in ib.succs:
                ib.succs.append(t)
            if ib.addr not in out.blocks[t].preds:
                out.blocks[t].preds.append(ib.addr)
    return out


__all__ = ["lift_function", "lifter_for"]

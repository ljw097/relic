"""Register constant propagation for data references (AArch64, ARM / Thumb, x86-32 PIC, MIPS).

x86-64 code names its data directly (`lea rax, [rip + x]`), so every string
or global it touches already is an instruction reference. Elsewhere the
address is built over several instructions:

    AArch64     adrp x0, page ; add x0, x0, #lo12        (or ldr x0, [x0, #lo12])
    ARM PIC     ldr r3, [pc, #k] ; add r3, pc            (a literal-pool offset from pc)
    ARM         ldr r0, =addr / movw + movt              (absolute, non-PIE)
    x86-32 PIC  call __x86.get_pc_thunk.bx ; add ebx, off ; lea eax, [ebx - k]
    MIPS        lui v0, hi ; addiu a0, v0, lo             (absolute, non-PIC)
                lw t9, -0x7fc0(gp) ; jalr t9              (a call through the GOT)

This pass follows constant register values through each function (a forward
dataflow over its CFG: a value survives a join only when every predecessor
agrees, a call ends the caller-saved ones) and records the address an
instruction computes or accesses as that instruction's data reference --
which gives strings, globals and GOT slots their xrefs, and the listing its
comments, on these targets too.

Values carry an "address" flag: only a value derived from the pc (adrp, adr,
`add rX, pc`, a pc thunk) or an absolute literal of a non-PIE binary is an
address. A PIE's literal-pool word or a `movw` is just a number until pc is
added to it.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..disasm import CALL, JMP, Insn
from ..progress import checkpoint

if TYPE_CHECKING:
    from . import Analysis
    from .functions import Function

OP_REG, OP_IMM, OP_MEM = 1, 2, 3
Val = tuple[int, bool]          # (value, is an address)
MAX_ROUNDS = 8


class _Target:
    """Register naming and the per-instruction transfer for one architecture."""

    def __init__(self, an: "Analysis"):
        self.an = an
        self.bin = an.bin
        self.mask = (1 << an.bin.bits) - 1
        self.pie = getattr(an.bin, "elf_type", "") == "ET_DYN" or an.bin.format == "PE"

    def canon(self, name: str) -> str:
        return name

    clobbered_by_call: frozenset = frozenset()
    delay_slots = False             # a call takes effect after the next instruction (MIPS)

    def entry_state(self) -> dict:
        return {}

    def clobber(self, st: dict):
        for k in self.clobbered_by_call:
            st.pop(k, None)

    def transfer(self, i: Insn, st: dict, refs: list) -> None:
        raise NotImplementedError

    # helpers
    def kill_written(self, i: Insn, st: dict):
        for r in i.regs_write:
            st.pop(self.canon(r), None)

    def readonly(self, addr: int) -> bool:
        sec = self.bin.section_at(addr)
        return sec is not None and sec.loaded and not getattr(sec, "w", False)


class _Arm64(_Target):
    clobbered_by_call = frozenset([f"x{k}" for k in range(19)] + ["x30"])

    def canon(self, name: str) -> str:
        if name[:1] in ("w", "x") and name[1:].isdigit():
            return "x" + name[1:]
        return {"fp": "x29", "lr": "x30"}.get(name, name)

    def transfer(self, i, st, refs):
        c = i.cs
        ops = c.operands
        m = i.mnemonic
        name = c.reg_name
        dst = self.canon(name(ops[0].reg)) if ops and ops[0].type == OP_REG else None
        if m == "adrp" and len(ops) == 2:
            st[dst] = (ops[1].imm & self.mask, True)
            return
        if m == "adr" and len(ops) == 2:
            st[dst] = (ops[1].imm & self.mask, True)
            refs.append(ops[1].imm & self.mask)
            return
        if m in ("add", "sub") and len(ops) == 3 and ops[1].type == OP_REG and ops[2].type == OP_IMM:
            src = st.get(self.canon(name(ops[1].reg)))
            imm = ops[2].imm << (ops[2].shift.value if ops[2].shift.type else 0)
            if src is not None:
                v = (src[0] + imm if m == "add" else src[0] - imm) & self.mask
                st[dst] = (v, src[1])
                if src[1]:
                    refs.append(v)
                return
        if m == "mov" and len(ops) == 2 and ops[1].type == OP_REG:
            src = st.get(self.canon(name(ops[1].reg)))
            if src is not None:
                st[dst] = src
                return
        if m.startswith(("ldr", "str", "ldp", "stp", "ldur", "stur")):
            for o in ops:
                if o.type == OP_MEM and not o.mem.index:
                    base = st.get(self.canon(name(o.mem.base)))
                    if base is not None and base[1]:
                        addr = (base[0] + o.mem.disp) & self.mask
                        refs.append(addr)
                        writeback = getattr(c, "writeback", False)
                        self.kill_written(i, st)
                        if writeback:
                            st.pop(self.canon(name(o.mem.base)), None)
                        if m == "ldr" and dst is not None and self.readonly(addr):
                            v = self.bin.read_int(addr, 8 if name(ops[0].reg).startswith("x") else 4)
                            if v is not None:
                                st[dst] = (v, self.bin.is_mapped(v))
                        return
        self.kill_written(i, st)


class _Arm(_Target):
    clobbered_by_call = frozenset(["r0", "r1", "r2", "r3", "r12", "lr"])

    def canon(self, name: str) -> str:
        from ..decompiler.lift.arm import ArmLifter
        return ArmLifter.canon(name)

    def pc(self, i: Insn, aligned: bool) -> int:
        v = i.addr + (4 if i.thumb else 8)
        return v & ~3 if aligned and i.thumb else v

    def get(self, i: Insn, st: dict, op) -> Val | None:
        if op.type == OP_IMM:
            return (op.imm & self.mask, False)
        if op.type != OP_REG or op.shift.type:
            return None
        r = self.canon(i.cs.reg_name(op.reg))
        if r == "pc":
            return (self.pc(i, False), True)
        return st.get(r)

    def transfer(self, i, st, refs):
        c = i.cs
        ops = c.operands
        m = i.mnemonic.split(".")[0]
        if i.cond:
            self.kill_written(i, st)        # a predicated write may or may not happen
            return
        name = c.reg_name
        dst = self.canon(name(ops[0].reg)) if ops and ops[0].type == OP_REG else None
        if m in ("ldr",) and len(ops) == 2 and ops[1].type == OP_MEM and \
                self.canon(name(ops[1].mem.base)) == "pc" and not ops[1].mem.index:
            lit = self.bin.read_int((self.pc(i, True) + ops[1].mem.disp) & self.mask, 4)
            if lit is not None and dst not in (None, "pc"):
                addr = not self.pie and self.bin.is_mapped(lit)
                st[dst] = (lit, addr)
                if addr:
                    refs.append(lit)
                return
        if m == "adr" and len(ops) == 2:
            v = (self.pc(i, True) + ops[1].imm) & self.mask
            st[dst] = (v, True)
            refs.append(v)
            return
        if m in ("add", "addw", "sub", "subw") and dst and dst != "pc" and len(ops) in (2, 3):
            a, b = (st.get(dst), self.get(i, st, ops[1])) if len(ops) == 2 else \
                (self.get(i, st, ops[1]), self.get(i, st, ops[2]))
            if len(ops) == 3 and ops[1].type == OP_REG and self.canon(name(ops[1].reg)) == "pc" and \
                    ops[2].type == OP_IMM:
                a = (self.pc(i, True), True)        # `add rd, pc, #k` (adr) reads the aligned pc
            if a is not None and b is not None:
                v = (a[0] + b[0] if m.startswith("add") else a[0] - b[0]) & self.mask
                st[dst] = (v, a[1] or b[1])
                if a[1] or b[1]:
                    refs.append(v)
                return
        if m == "mov" and dst and len(ops) == 2:
            src = self.get(i, st, ops[1])
            if src is not None and dst != "pc":
                st[dst] = src
                return
        if m == "movw" and dst:
            st[dst] = (ops[1].imm & 0xFFFF, False)
            return
        if m == "movt" and dst and dst in st:
            v = (st[dst][0] & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
            addr = not self.pie and self.bin.is_mapped(v)
            st[dst] = (v, addr)
            if addr:
                refs.append(v)
            return
        if m.startswith(("ldr", "str")):
            for o in ops:
                if o.type == OP_MEM:
                    base = st.get(self.canon(name(o.mem.base)))
                    idx = st.get(self.canon(name(o.mem.index))) if o.mem.index else (0, False)
                    if base is not None and idx is not None and (base[1] or idx[1]):
                        sign = -1 if getattr(o, "subtracted", False) else 1
                        addr = (base[0] + sign * idx[0] + o.mem.disp) & self.mask
                        refs.append(addr)
                        self.kill_written(i, st)
                        if m == "ldr" and dst and dst != "pc" and self.readonly(addr):
                            v = self.bin.read_int(addr, 4)
                            if v is not None:
                                st[dst] = (v, not self.pie and self.bin.is_mapped(v))
                        return
        self.kill_written(i, st)


class _X86PIC(_Target):
    clobbered_by_call = frozenset(["eax", "ecx", "edx"])

    def __init__(self, an):
        super().__init__(an)
        from ..decompiler.lift.x86 import _reg_table
        self.table = _reg_table(32)

    def canon(self, name: str) -> str:
        return self.table.get(name, (name,))[0]

    def thunk(self, i: Insn) -> str | None:
        if i.target is None:
            return None
        name = self.an.name(i.target) or ""
        if name.startswith(("__x86.get_pc_thunk.", "__i686.get_pc_thunk.")):
            return "e" + name.rsplit(".", 1)[1]
        first = self.an.dis.decode(i.target)
        if first is None or first.mnemonic != "mov" or len(first.cs.operands) != 2:
            return None
        d, s = first.cs.operands
        if d.type != OP_REG or s.type != OP_MEM or first.cs.reg_name(s.mem.base) != "esp" or s.mem.disp:
            return None
        nxt = self.an.dis.decode(first.end)
        return self.canon(first.cs.reg_name(d.reg)) if nxt is not None and nxt.mnemonic == "ret" else None

    def transfer(self, i, st, refs):
        c = i.cs
        ops = c.operands
        m = i.mnemonic
        name = c.reg_name
        if i.kind == CALL:
            r = self.thunk(i)
            if r is not None:
                for k in self.clobbered_by_call:
                    st.pop(k, None)
                st[r] = (i.end, True)
                return
        dst = self.canon(name(ops[0].reg)) if ops and ops[0].type == OP_REG else None
        if m in ("add", "sub") and len(ops) == 2 and dst in st and ops[1].type == OP_IMM and \
                name(ops[0].reg) == dst:
            v, a = st[dst]
            st[dst] = ((v + ops[1].imm if m == "add" else v - ops[1].imm) & self.mask, a)
            return
        found = None
        for o in ops:
            if o.type == OP_MEM and o.mem.base and not o.mem.index:
                base = st.get(self.canon(name(o.mem.base)))
                if base is not None and base[1]:
                    found = (base[0] + o.mem.disp) & self.mask
        if found is not None:
            refs.append(found)
            if m == "lea" and dst:
                self.kill_written(i, st)
                st[dst] = (found, True)
                return
        if m == "mov" and len(ops) == 2 and ops[1].type == OP_REG and dst and name(ops[0].reg) == dst:
            src = st.get(self.canon(name(ops[1].reg)))
            if src is not None:
                st[dst] = src
                return
        self.kill_written(i, st)


class _Mips(_Target):
    """`$gp` is the same everywhere in a module (`_gp`, GOT + 0x7ff0): it is pinned to that,
    whatever the code does to it (PIC prologues rebuild it from `$t9`, calls reload it from the
    stack). A word loaded from the GOT keeps the slot it came from (`@reg`), so `jalr $t9`
    can be named after the import that slot belongs to."""
    clobbered_by_call = frozenset(["at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
                                   "t6", "t7", "t8", "t9", "ra"])
    delay_slots = True
    _LOADS = {"lw": 4, "ld": 8}
    _MEM = ("lw", "sw", "lb", "lbu", "lh", "lhu", "sb", "sh", "ld", "sd", "lwu", "lwl", "lwr", "swl", "swr",
            "lwc1", "swc1", "ldc1", "sdc1", "ll", "sc")

    def __init__(self, an):
        super().__init__(an)
        self.gp = an.bin.mips_gp
        self.calls: dict[int, tuple[int | None, Val | None]] = {}     # jalr / jr address -> (slot, value)
        got = next((s for s in an.bin.sections if s.name == ".got"), None)
        self.got = (got.addr, got.end) if got is not None else (0, 0)

    def canon(self, name: str) -> str:
        name = name.lstrip("$")
        return {"s8": "fp", "30": "fp", "29": "sp", "28": "gp", "25": "t9", "31": "ra"}.get(name, name)

    def entry_state(self) -> dict:
        return {"gp": (self.gp, True)} if self.gp is not None else {}

    def kill_written(self, i: Insn, st: dict):
        for r in i.regs_write:
            r = self.canon(r)
            if r != "gp":
                st.pop(r, None)
                st.pop("@" + r, None)

    def clobber(self, st: dict):
        for k in self.clobbered_by_call:
            st.pop(k, None)
            st.pop("@" + k, None)

    def transfer(self, i, st, refs):
        c = i.cs
        ops = c.operands
        m = i.mnemonic
        name = c.reg_name
        regs = [self.canon(name(o.reg)) for o in ops if o.type == OP_REG]
        dst = regs[0] if ops and ops[0].type == OP_REG else None
        if dst == "gp" and m not in ("jalr", "jr"):
            return
        if m in ("jalr", "jr", "jalr.hb", "jr.hb") and regs:
            r = regs[-1]
            self.calls[i.addr] = (st.get("@" + r), st.get(r))
            self.kill_written(i, st)
            return
        if m == "lui" and len(ops) == 2 and ops[1].type == OP_IMM:
            st[dst] = ((ops[1].imm << 16) & self.mask, not self.pie)
            st.pop("@" + dst, None)
            return
        if m in ("addiu", "daddiu", "addi", "ori") and len(ops) == 3 and ops[2].type == OP_IMM:
            src = st.get(regs[1])
            if src is not None:
                v = (src[0] | ops[2].imm if m == "ori" else src[0] + ops[2].imm) & self.mask
                self.kill_written(i, st)
                st[dst] = (v, src[1])
                if src[1] and v != src[0]:
                    refs.append(v)
                return
        if m == "move" and len(regs) == 2:
            src = st.get(regs[1])
            self.kill_written(i, st)
            if src is not None:
                st[dst] = src
                if "@" + regs[1] in st:
                    st["@" + dst] = st["@" + regs[1]]
            return
        if m in self._MEM:
            for o in ops:
                if o.type != OP_MEM:
                    continue
                base = st.get(self.canon(name(o.mem.base)))
                if base is None or not base[1]:
                    break
                addr = (base[0] + o.mem.disp) & self.mask
                refs.append(addr)
                self.kill_written(i, st)
                size = self._LOADS.get(m)
                if size and dst and dst != "gp" and \
                        (self.got[0] <= addr < self.got[1] or self.readonly(addr)):
                    v = self.bin.read_int(addr, size)
                    if v is not None:
                        st[dst] = (v, bool(v) and self.bin.is_mapped(v))
                        if self.got[0] <= addr < self.got[1]:
                            st["@" + dst] = addr
                return
        self.kill_written(i, st)


def _target_for(an: "Analysis") -> _Target | None:
    arch = an.bin.arch
    if arch == "arm64":
        return _Arm64(an)
    if arch == "arm":
        return _Arm(an)
    if arch == "x86":
        return _X86PIC(an)
    if arch in ("mips", "mips64"):
        return _Mips(an)
    return None


def _meet(states: list[dict]) -> dict:
    if not states:
        return {}
    out = dict(states[0])
    for s in states[1:]:
        for k in list(out):
            if s.get(k) != out[k]:
                del out[k]
    return out


def _function_refs(t: _Target, f: "Function") -> dict[int, list[int]]:
    """Instruction address -> data addresses it computes or accesses."""
    order = sorted(f.blocks)
    out_state: dict[int, dict] = {}
    found: dict[int, list[int]] = {}
    for _ in range(MAX_ROUNDS):
        changed = False
        for a in order:
            blk = f.blocks[a]
            st = _meet([out_state[p] for p in blk.preds if p in out_state]) if a != f.addr else t.entry_state()
            pending = False             # a MIPS call clobbers registers after its delay slot
            for i in blk.insns:
                refs: list[int] = []
                try:
                    t.transfer(i, st, refs)
                except (AttributeError, IndexError, TypeError, ValueError):
                    t.kill_written(i, st)
                if pending:
                    t.clobber(st)
                    pending = False
                if i.kind == CALL and not (isinstance(t, _X86PIC) and t.thunk(i)):
                    if t.delay_slots:
                        pending = True
                    else:
                        t.clobber(st)
                if refs:
                    found[i.addr] = refs
            if out_state.get(a) != st:
                out_state[a] = st
                changed = True
        if not changed:
            break
    return found


def propagate_refs(an: "Analysis") -> int:
    """Add the data references constant propagation finds to the instructions (in place)."""
    t = _target_for(an)
    if t is None:
        return 0
    n = 0
    for f in an.functions.values():
        if f.is_import or not f.blocks:
            continue
        checkpoint()
        found = _function_refs(t, f)
        for blk in f.blocks.values():
            for i in blk.insns:
                for r in found.get(i.addr, ()):
                    if t.bin.is_mapped(r) and r not in i.refs:
                        if isinstance(t, _Arm64) and i.mnemonic == "add":
                            i.refs[:] = [x for x in i.refs if x != i.cs.operands[2].imm]   # the lo12 offset
                        i.refs.append(r)
                        n += 1
    if isinstance(t, _Mips):
        n += _name_mips_calls(an, t)
    return n


def _name_mips_calls(an: "Analysis", t: _Mips) -> int:
    """`jalr $t9` after `lw $t9, slot($gp)`: a call of the import that owns the slot (named
    through `mem_target`, like an x86 `call [slot]`), or of the function the slot holds."""
    n = 0
    for f in an.functions.values():
        for blk in f.blocks.values():
            for i in blk.insns:
                slot, val = t.calls.get(i.addr, (None, None))
                if i.kind not in (CALL, JMP) or i.target is not None:
                    continue
                if slot is not None and slot in an.bin.imports_by_got:
                    i.mem_target = slot
                    n += 1
                elif val is not None and val[1] and val[0] in an.functions:
                    i.target = val[0]
                    if i.kind == CALL:
                        f.calls.add(val[0])
                    n += 1
    return n


__all__ = ["propagate_refs"]

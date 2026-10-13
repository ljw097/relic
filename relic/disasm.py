"""Capstone wrapper that turns raw bytes into classified instructions."""
from __future__ import annotations

from dataclasses import dataclass, field

import capstone as cs

from .loader.base import Binary

OP_REG = getattr(cs, "CS_OP_REG", 1)
OP_IMM = getattr(cs, "CS_OP_IMM", 2)
OP_MEM = getattr(cs, "CS_OP_MEM", 3)
_ARM64 = cs.CS_ARCH_ARM64 if hasattr(cs, "CS_ARCH_ARM64") else cs.CS_ARCH_AARCH64

# kinds
NORMAL, CALL, JMP, CJMP, RET, HALT = "normal", "call", "jmp", "cjmp", "ret", "halt"


@dataclass(slots=True)
class Insn:
    addr: int
    size: int
    mnemonic: str
    op_str: str
    raw: bytes
    kind: str = NORMAL
    target: int | None = None  # direct branch / call target
    refs: list[int] = field(default_factory=list)  # data addresses referenced
    mem_target: int | None = None  # `call/jmp [mem]`: address of the pointer slot
    regs_write: tuple[str, ...] = ()
    regs_read: tuple[str, ...] = ()
    cs: object = field(default=None, repr=False, compare=False)  # underlying capstone insn (detail available)

    @property
    def end(self) -> int:
        return self.addr + self.size

    @property
    def is_branch(self) -> bool:
        return self.kind in (JMP, CJMP)

    @property
    def is_terminator(self) -> bool:
        return self.kind in (JMP, CJMP, RET, HALT)

    def __str__(self) -> str:
        return f"{self.addr:#x}: {self.mnemonic} {self.op_str}".rstrip()


def capstone_for(arch: str, endian: str = "little") -> cs.Cs:
    be = cs.CS_MODE_BIG_ENDIAN if endian == "big" else cs.CS_MODE_LITTLE_ENDIAN
    table = {
        "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
        "x64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
        "arm": (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | be),
        "thumb": (cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | be),
        "arm64": (_ARM64, cs.CS_MODE_ARM | be),
        "mips": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | be),
        "mips64": (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64 | be),
        "riscv32": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV32 | cs.CS_MODE_RISCVC),
        "riscv64": (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64 | cs.CS_MODE_RISCVC),
        "ppc": (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN),
        "ppc64": (cs.CS_ARCH_PPC, cs.CS_MODE_64 | be),
    }
    if arch not in table:
        raise ValueError(f"unsupported architecture: {arch}")
    a, m = table[arch]
    md = cs.Cs(a, m)
    md.detail = True
    if a == cs.CS_ARCH_X86:
        md.syntax = cs.CS_OPT_SYNTAX_INTEL
    return md


_X86_CJMP = {"jo", "jno", "js", "jns", "je", "jne", "jb", "jae", "jbe", "ja", "jl", "jge", "jle", "jg",
             "jp", "jnp", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}
_HALT = {"hlt", "ud2", "int3", "brk", "udf", "ebreak"}


class Disassembler:
    """Decodes instructions out of a `Binary` with a per-address cache."""

    def __init__(self, binary: Binary):
        self.bin = binary
        self.arch = binary.arch
        self.md = capstone_for(binary.arch, binary.endian)
        self.delay_slots = binary.arch in ("mips", "mips64")
        self._cache: dict[int, Insn | None] = {}

    # ------------------------------------------------------------------ decode
    def decode(self, addr: int) -> Insn | None:
        if addr in self._cache:
            return self._cache[addr]
        insn = None
        if self.bin.is_exec(addr) or self.bin.format == "RAW":
            code = self.bin.read(addr, 16)
            for c in self.md.disasm(code, addr, 1):
                insn = self._convert(c)
        self._cache[addr] = insn
        return insn

    def decode_block(self, addr: int, end: int) -> list[Insn]:
        """Linear sweep from addr to end (stops at undecodable bytes)."""
        out = []
        code = self.bin.read(addr, end - addr)
        for c in self.md.disasm(code, addr):
            i = self._cache.get(c.address)
            if i is None:
                i = self._convert(c)
                self._cache[c.address] = i
            out.append(i)
        return out

    def linear(self, addr: int, count: int) -> list[Insn]:
        out = []
        while len(out) < count:
            i = self.decode(addr)
            if i is None:
                break
            out.append(i)
            addr = i.end
        return out

    # ------------------------------------------------------------- classify
    def _convert(self, c) -> Insn:
        i = Insn(c.address, c.size, c.mnemonic, c.op_str, bytes(c.bytes), cs=c)
        try:
            r, w = c.regs_access()
            i.regs_read = tuple(c.reg_name(x) for x in r)
            i.regs_write = tuple(c.reg_name(x) for x in w)
        except cs.CsError:
            pass
        if self.arch in ("x86", "x64"):
            self._classify_x86(c, i)
        else:
            self._classify_generic(c, i)
        return i

    def _classify_x86(self, c, i: Insn):
        m = c.mnemonic
        for p in ("notrack ", "bnd ", "rep ", "repne "):
            if m.startswith(p) and m[len(p):] in ("jmp", "call", "ret"):
                m = m[len(p):]
        if m == "call":
            i.kind = CALL
        elif m == "jmp" or m == "ljmp":
            i.kind = JMP
        elif m in _X86_CJMP:
            i.kind = CJMP
        elif m in ("ret", "retf", "iret", "iretd", "iretq", "sysret"):
            i.kind = RET
        elif m in _HALT:
            i.kind = HALT
        nxt = c.address + c.size
        for op in c.operands:
            if op.type == OP_IMM:
                if i.kind in (CALL, JMP, CJMP):
                    i.target = op.imm & self._mask
                elif self.bin.is_mapped(op.imm & self._mask) and op.imm > 0xFF:
                    i.refs.append(op.imm & self._mask)
            elif op.type == OP_MEM:
                mm = op.mem
                addr = None
                if mm.base == cs.x86.X86_REG_RIP:
                    addr = (nxt + mm.disp) & self._mask
                elif mm.base == 0 and mm.index == 0:
                    addr = mm.disp & self._mask
                elif mm.disp > 0xFFFF and self.bin.is_mapped(mm.disp & self._mask):
                    addr = mm.disp & self._mask  # table[reg*8]
                if addr is not None:
                    i.refs.append(addr)
                    if i.kind in (CALL, JMP) and mm.index == 0:
                        i.mem_target = addr

    def _classify_generic(self, c, i: Insn):
        m = c.mnemonic
        groups = set(c.groups)
        arch = self.arch
        if cs.CS_GRP_RET in groups or m in ("ret", "c.ret") or \
                (arch.startswith("ppc") and m == "blr") or \
                (arch.startswith("mips") and m == "jr" and c.op_str.strip() == "$ra") or \
                (arch == "arm" and (m == "bx" and c.op_str == "lr" or (m.startswith("pop") and "pc" in c.op_str))):
            i.kind = RET
        elif cs.CS_GRP_CALL in groups or m in ("bl", "blx", "blr", "jal", "jalr", "bctrl"):
            i.kind = CALL
        elif cs.CS_GRP_JUMP in groups or cs.CS_GRP_BRANCH_RELATIVE in groups:
            cond = False
            if arch == "arm64":
                cond = m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz")
            elif arch in ("arm", "thumb"):
                cond = getattr(c, "cc", cs.arm.ARM_CC_AL) not in (cs.arm.ARM_CC_AL, 0) or m in ("cbz", "cbnz")
            elif arch.startswith("mips"):
                cond = m not in ("j", "jr", "b")
            elif arch.startswith("riscv"):
                cond = m.startswith("b") or m in ("c.beqz", "c.bnez")
            elif arch.startswith("ppc"):
                cond = m not in ("b", "ba", "bctr")
            i.kind = CJMP if cond else JMP
        elif m in _HALT:
            i.kind = HALT
        imms = [op.imm for op in c.operands if op.type == OP_IMM]
        if i.kind in (CALL, JMP, CJMP) and imms:
            i.target = imms[-1] & self._mask
        else:
            for v in imms:
                v &= self._mask
                if v > 0xFF and self.bin.is_mapped(v):
                    i.refs.append(v)

    @property
    def _mask(self) -> int:
        return (1 << self.bin.bits) - 1

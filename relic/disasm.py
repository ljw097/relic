"""Capstone wrapper that turns raw bytes into classified instructions."""
from __future__ import annotations

import bisect
import re
import threading
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
    _regs: tuple | None = field(default=None, repr=False, compare=False)    # (read, write), on first use
    _cs: object = field(default=None, repr=False, compare=False)  # underlying capstone insn (detail available)
    cond: bool = False  # ARM: executes only when its condition holds
    thumb: bool = False  # ARM: decoded as Thumb
    delay: bool = False  # MIPS: in the delay slot of the branch before it (runs before the branch takes effect)
    _dis: object = field(default=None, repr=False, compare=False)  # decodes `cs` on first use

    @property
    def cs(self):
        """The capstone instruction (operand detail): decoded again on first use for instructions
        found by a lightweight decode."""
        if self._cs is None and self._dis is not None:
            self._cs = self._dis._full(self)
        return self._cs

    @property
    def end(self) -> int:
        return self.addr + self.size

    def _access(self) -> tuple:
        """Registers read and written (capstone's `regs_access`, worked out on first use: most
        instructions never need it)."""
        if self._regs is None:
            r = w = ()
            if self.cs is not None:
                try:
                    a, b = self.cs.regs_access()
                    r = tuple(self.cs.reg_name(x) for x in a)
                    w = tuple(self.cs.reg_name(x) for x in b)
                except cs.CsError:
                    pass
            self._regs = (r, w)
        return self._regs

    @property
    def regs_read(self) -> tuple[str, ...]:
        return self._access()[0]

    @property
    def regs_write(self) -> tuple[str, ...]:
        return self._access()[1]

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
        # disassembly only
        "sparc": (cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN),
        "sparc64": (cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN | cs.CS_MODE_V9),
        "s390x": (cs.CS_ARCH_SYSZ, cs.CS_MODE_BIG_ENDIAN),
        "m68k": (cs.CS_ARCH_M68K, cs.CS_MODE_BIG_ENDIAN | cs.CS_MODE_M68K_040),
        "sh": (cs.CS_ARCH_SH, cs.CS_MODE_SH4 | be),
        "tricore": (cs.CS_ARCH_TRICORE, cs.CS_MODE_TRICORE_162),
        "bpf": (cs.CS_ARCH_BPF, cs.CS_MODE_BPF_EXTENDED | be),
        "wasm": (cs.CS_ARCH_WASM, 0),
    }
    if arch not in table:
        raise ValueError(f"unsupported architecture: {arch}")
    a, m = table[arch]
    md = cs.Cs(a, m)
    md.detail = True
    if a == cs.CS_ARCH_X86:
        md.syntax = cs.CS_OPT_SYNTAX_INTEL
    return md


DISASM_ONLY = ("sparc", "sparc64", "s390x", "m68k", "sh", "tricore", "bpf", "wasm")
_X86_CJMP = {"jo", "jno", "js", "jns", "je", "jne", "jb", "jae", "jbe", "ja", "jl", "jge", "jle", "jg",
             "jp", "jnp", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}
_HALT = {"hlt", "ud2", "int3", "brk", "udf", "ebreak"}


def _x86_operands(op_str: str) -> list[tuple] | None:
    """The immediates and memory operands of capstone's Intel-syntax text, as ("imm", value) and
    ("mem", base, index, disp) -- what classification needs, without capstone's (costly) operand
    detail. None for text it does not take."""
    out = []
    for op in op_str.split(", "):
        k = op.find("[")
        if k < 0:
            if op[:1] in "0123456789-":
                try:
                    out.append(("imm", int(op, 0)))
                except ValueError:
                    return None
            continue
        if not op.endswith("]"):
            return None
        base = index = ""
        disp, sign = 0, 1
        for t in op[k + 1:-1].split(" "):
            if t == "+":
                sign = 1
            elif t == "-":
                sign = -1
            elif "*" in t:
                index = t
            elif t[:1].isdigit():
                try:
                    disp += sign * int(t, 0)
                except ValueError:
                    return None
            elif t.isalnum():
                if base:
                    index = t           # (`[rdx + rdi]`: scale 1)
                else:
                    base = t
            else:
                return None
        out.append(("mem", base, index, disp))
    return out


def _x86_cs_operands(c) -> list[tuple]:
    out = []
    for op in c.operands:
        if op.type == OP_IMM:
            out.append(("imm", op.imm))
        elif op.type == OP_MEM:
            mm = op.mem
            base = "rip" if mm.base == cs.x86.X86_REG_RIP else c.reg_name(mm.base) if mm.base else ""
            out.append(("mem", base, c.reg_name(mm.index) if mm.index else "", mm.disp))
    return out


class Disassembler:
    """Decodes instructions out of a `Binary` with a per-address cache."""

    def __init__(self, binary: Binary):
        self.bin = binary
        self.arch = binary.arch
        from .extend import PROCESSORS
        self.custom = PROCESSORS.get(binary.arch)       # a plugin's processor module (relic.extend)
        self.md = capstone_for(binary.arch, binary.endian) if self.custom is None else None
        self.delay_slots = binary.arch in ("mips", "mips64", "sparc", "sparc64", "sh")
        self._cache: dict[int, Insn | None] = {}
        # capstone handles are not thread-safe: the GUI decodes while a background job (the
        # decompiler, the vulnerability scan) does
        self._lock = threading.RLock()
        # ARM / Thumb interworking: the instruction set is a property of the address
        self.md_thumb = capstone_for("thumb", binary.endian) if binary.arch == "arm" else None
        self.modes: dict[int, bool] = {a: True for a in getattr(binary, "thumb_code", ())}  # addr -> thumb
        mapping = getattr(binary, "arm_mapping", {})
        self._map_addrs = sorted(mapping)
        self._map_kinds = [mapping[a] for a in self._map_addrs]

    # ------------------------------------------------------------------ modes
    def is_thumb(self, addr: int) -> bool:
        """Instruction set at `addr`: control-flow hints first, then the `$a`/`$t` mapping symbols."""
        if self.md_thumb is None:
            return False
        if addr in self.modes:
            return self.modes[addr]
        k = bisect.bisect_right(self._map_addrs, addr) - 1
        return k >= 0 and self._map_kinds[k] == "t"

    def hint(self, addr: int, thumb: bool):
        """Record the instruction set control flow reaches `addr` in (an odd address is Thumb)."""
        if self.md_thumb is None:
            return
        if addr & 1:
            addr, thumb = addr & ~1, True
        if addr not in self.modes and addr not in self._cache:
            self.modes[addr] = thumb

    # ------------------------------------------------------------------ decode
    def decode(self, addr: int) -> Insn | None:
        if self.md_thumb is not None and addr & 1:
            self.hint(addr, True)
            addr &= ~1
        if addr in self._cache:
            return self._cache[addr]
        if self.custom is not None:
            insn = None
            if self.bin.is_exec(addr) or self.bin.format == "RAW":
                code = self.bin.read(addr, 16)
                insn = self.custom.decode(code, addr) if code else None
            self._cache[addr] = insn
            return insn
        with self._lock:
            insn = None
            if self.bin.is_exec(addr) or self.bin.format == "RAW":
                thumb = self.is_thumb(addr)
                if not thumb and self.md_thumb is None:
                    return self._decode_run(addr)
                md = self.md_thumb if thumb else self.md
                code = self.bin.read(addr, 16)
                for c in md.disasm(code, addr, 1):
                    insn = self._convert(c, thumb)
                if thumb and insn is not None and insn.mnemonic.startswith("it"):
                    return self._it_block(insn)
            self._cache[addr] = insn
            return insn

    RUN = 8      # instructions decoded per capstone call on a miss

    def _decode_run(self, addr: int) -> Insn | None:
        """Decode the instruction at `addr` and the few after it in one capstone call (an
        instruction decodes the same however it is reached, so they are cached for later)."""
        first = None
        code = self.bin.read(addr, 16 * self.RUN)
        lite = self.arch in ("x86", "x64")
        run = self.md.disasm_lite(code, addr, self.RUN) if lite else \
            ((c.address, c.size, c.mnemonic, c.op_str, c) for c in self.md.disasm(code, addr, self.RUN))
        for c in run:
            a, size, mnem, ops = c[:4]
            if first is not None and not (self.bin.is_exec(a) or self.bin.format == "RAW"):
                break                              # (decode() answers None outside code)
            i = self._cache.get(a)
            if i is None and a not in self._cache:
                if lite:        # (capstone's operand detail only when it is needed)
                    i = Insn(a, size, mnem, ops, code[a - addr:a - addr + size], _dis=self)
                    self._classify_x86(i)
                else:
                    i = self._convert(c[4])
                self._cache[a] = i
            if first is None:
                first = i
            if i is not None and i.kind in (JMP, RET):
                break                              # what follows may be data or padding
        if first is None:
            self._cache[addr] = None
        return first

    def _it_block(self, it: Insn) -> Insn:
        """Thumb `it`: capstone only applies its conditions within one decode run, so decode the
        block in one go and cache the conditional instructions with their condition."""
        n = len(it.mnemonic.split()[0]) - 1          # `it` 1, `itt`/`ite` 2, ...
        code = self.bin.read(it.addr, 2 + 4 * n)
        for k, c in enumerate(self.md_thumb.disasm(code, it.addr, n + 1)):
            i = it if k == 0 else self._convert(c, True)
            self._cache[c.address] = i
            self.modes.setdefault(c.address, True)
        return it

    def linear(self, addr: int, count: int) -> list[Insn]:
        out = []
        while len(out) < count:
            i = self.decode(addr)
            if i is None:
                break
            out.append(i)
            addr = i.end
            if self.md_thumb is not None and addr not in self._map_addrs:
                self.hint(addr, i.thumb)       # a linear sweep stays in the same instruction set
        return out

    # ------------------------------------------------------------- classify
    def _convert(self, c, thumb: bool = False) -> Insn:
        i = Insn(c.address, c.size, c.mnemonic, c.op_str, bytes(c.bytes), _cs=c, thumb=thumb)
        if self.arch in ("x86", "x64"):
            self._classify_x86(i)
        else:
            self._classify_generic(c, i)
        return i

    def _full(self, i: Insn):
        with self._lock:
            md = self.md_thumb if i.thumb else self.md
            return next(md.disasm(i.raw, i.addr, 1), None)

    def _classify_x86(self, i: Insn):
        m = i.mnemonic
        if " " in m:                    # (a prefix: every one ends in a space)
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
        if "[" not in i.op_str and "0x" not in i.op_str:
            return                      # (no address in it)
        ops = _x86_operands(i.op_str)
        if ops is None:                 # (an operand the text parse does not take: capstone's detail)
            ops = _x86_cs_operands(i.cs)
        nxt = i.end
        for op in ops:
            if op[0] == "imm":
                imm = op[1]
                if i.kind in (CALL, JMP, CJMP):
                    i.target = imm & self._mask
                elif imm > 0xFF and self.bin.is_mapped(imm & self._mask):
                    i.refs.append(imm & self._mask)
            else:
                _, base, index, disp = op
                addr = None
                if base == "rip":
                    addr = (nxt + disp) & self._mask
                elif not base and not index:
                    addr = disp & self._mask
                elif disp > 0xFFFF and self.bin.is_mapped(disp & self._mask):
                    addr = disp & self._mask  # table[reg*8]
                if addr is not None:
                    i.refs.append(addr)
                    if i.kind in (CALL, JMP) and not index:
                        i.mem_target = addr

    def _classify_generic(self, c, i: Insn):
        m = c.mnemonic
        groups = set(c.groups)
        arch = self.arch
        if arch in ("arm", "thumb"):
            cc = getattr(c, "cc", cs.arm.ARM_CC_AL)
            i.cond = cc not in (cs.arm.ARM_CC_AL, 0)
            base = m.split(".")[0]
            if i.cond and len(base) > 2:
                base = base[:-2]                  # `bxeq` -> `bx`, `popne` -> `pop`
            ops = c.op_str.replace(" ", "")
            if (base == "bx" and ops == "lr") or (base in ("pop", "ldm", "ldmia", "ldmfd") and "pc" in ops) or \
                    (base == "mov" and ops == "pc,lr") or (base == "ldr" and ops.startswith("pc,[sp]")):
                # a conditional return falls through when its condition fails
                i.kind = CJMP if i.cond else RET
                return
            if (base == "add" and ops.startswith("pc,pc,")) or base in ("tbb", "tbh") or \
                    (base == "ldr" and ops.startswith("pc,[pc,")) or (base == "mov" and ops.startswith("pc,")):
                i.kind = JMP                      # switch dispatch / computed jump
                return
        if arch.startswith("riscv"):
            self._classify_riscv(c, i)
            return
        if arch.startswith("ppc"):
            self._classify_ppc(c, i)
            return
        if arch in DISASM_ONLY:
            self._classify_other(c, i)
            return
        if cs.CS_GRP_RET in groups or m in ("ret", "c.ret") or \
                (arch.startswith("ppc") and m == "blr") or \
                (arch.startswith("mips") and m == "jr" and c.op_str.strip() == "$ra") or \
                (arch == "arm" and (m == "bx" and c.op_str == "lr" or (m.startswith("pop") and "pc" in c.op_str))):
            i.kind = RET
        elif cs.CS_GRP_CALL in groups or m in ("bl", "blx", "blr", "jal", "jalr", "bctrl") or \
                (arch.startswith("mips") and m in ("bal", "bgezal", "bltzal", "jalx", "jalr.hb")):
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
        if arch.startswith("mips") and m == "bal" and imms and imms[-1] & self._mask == i.addr + 8:
            i.kind = NORMAL                       # `bal .+8`: reads pc into $ra (PIC startup), not a call
            return
        if i.kind in (CALL, JMP, CJMP) and imms:
            i.target = imms[-1] & self._mask
        elif m == "adrp" or (arch in ("arm", "thumb", "arm64") and m != "adr"):
            # ARM / AArch64 immediates are offsets, masks and pages (`mov w0, #0xffff` is not an
            # address, even where a PIE maps it); the analysis' constant propagation finds the
            # addresses built from them (adrp + add, literal pools, pc-relative adds)
            pass
        else:
            for v in imms:
                v &= self._mask
                if v > 0xFF and self.bin.is_mapped(v):
                    i.refs.append(v)

    def _classify_other(self, c, i: Insn):
        """Processors only disassembled (no lifter): returns, calls and jumps from the mnemonics,
        branch targets from the immediate operands."""
        arch = self.arch
        m = c.mnemonic.split(",")[0]            # (SPARC `bne,a`: annulled delay slot)
        ops = c.op_str.replace(" ", "")
        groups = set(c.groups)
        kind = None
        if arch.startswith("sparc"):
            if m in ("ret", "retl") or (m == "jmpl" and ops.startswith(("%i7+8", "%o7+8"))):
                kind = RET
            elif m == "call" or (m == "jmpl" and ops.endswith("%o7")):
                kind = CALL
            elif m in ("ba", "b", "jmp", "jmpl"):
                kind = JMP
            elif m.startswith(("b", "fb", "cb")) and m not in ("bn", "bset", "bclr", "btst", "btog"):
                kind = CJMP
        elif arch == "s390x":
            if m in ("br", "bcr") and ops.endswith("%r14") and (m == "br" or ops.startswith("15,")):
                kind = RET
            elif m.startswith(("bras", "basr", "bas")):
                kind = CALL
            elif m in ("j", "jg", "br", "b") or (m in ("bc", "bcr", "brc", "brcl") and ops.startswith("15,")):
                kind = JMP
            elif m in ("bc", "bcr", "brc", "brcl") and ops.startswith("0,"):
                kind = NORMAL                   # (never taken: a nop)
            elif cs.CS_GRP_JUMP in groups or m.startswith("j") or m in ("bc", "bcr", "brc", "brcl", "brct",
                                                                        "brctg", "bct", "bctg"):
                kind = CJMP                     # (`jne`, `cijle` compare-and-branch, ...)
        elif arch == "m68k":
            if m in ("rts", "rte", "rtr", "rtd"):
                kind = RET
            elif m in ("jsr", "bsr", "bsr.w", "bsr.b", "bsr.l"):
                kind = CALL
            elif m.split(".")[0] in ("bra", "jmp"):
                kind = JMP
            elif m.startswith(("b", "db")) and m.split(".")[0] not in ("bchg", "bclr", "bset", "btst", "bfchg",
                                                                        "bfclr", "bfset", "bftst", "bfextu",
                                                                        "bfexts", "bfffo", "bfins", "bkpt"):
                kind = CJMP
        elif arch == "sh":
            if m in ("rts", "rte"):
                kind = RET
            elif m in ("jsr", "bsr", "bsrf"):
                kind = CALL
            elif m in ("bra", "braf", "jmp"):
                kind = JMP
            elif m in ("bt", "bf", "bt/s", "bf/s"):
                kind = CJMP
        elif arch == "bpf":
            if m == "exit":
                kind = RET
            elif m == "call":
                kind = CALL
            elif m == "ja":
                kind = JMP
            elif m.startswith("j"):
                kind = CJMP
        elif arch == "tricore":
            if m in ("ret", "rfe"):
                kind = RET
            elif m.startswith(("call", "fcall", "jl")):
                kind = CALL
            elif m in ("j", "ja", "ji", "jli"):
                kind = JMP
            elif m.startswith("j") or m.startswith("loop"):
                kind = CJMP
        elif arch == "wasm":
            if m == "return":
                kind = RET
            elif m == "call":
                kind = CALL
            elif m == "unreachable":
                kind = HALT
        if kind is None and arch not in ("bpf", "wasm"):     # (their group numbers mean other things)
            if cs.CS_GRP_RET in groups:
                kind = RET
            elif cs.CS_GRP_CALL in groups:
                kind = CALL
            elif cs.CS_GRP_JUMP in groups:
                kind = JMP
        i.kind = kind or NORMAL
        if arch == "wasm":
            if m == "call":                     # (a function index, not an address)
                try:
                    idx = int(ops, 0)
                except ValueError:
                    idx = None
                funcs = getattr(self.bin, "wasm_funcs", [])
                i.target = funcs[idx] if idx is not None and 0 <= idx < len(funcs) and funcs[idx] else None
            return
        if arch == "bpf":
            if i.kind in (JMP, CJMP):           # `goto +off`: in 8-byte instructions after this one
                off = ops.rsplit(",", 1)[-1]
                try:
                    k = int(off, 0)
                except ValueError:
                    k = None
                if k is not None and k >= 0x8000:
                    k -= 0x10000                # (a 16-bit signed offset, printed unsigned)
                i.target = (i.addr + 8 + 8 * k) & self._mask if k is not None else None
            return
        if i.kind in (CALL, JMP, CJMP):
            imms = []
            try:
                imms = [op.imm for op in c.operands if op.type == OP_IMM]
            except (cs.CsError, AttributeError):
                imms = []
            if arch == "m68k":                  # (`bne.b $100022`: the displacement is not an imm operand)
                hexes = re.findall(r"\$([0-9a-fA-F]+)", c.op_str)
                imms = [int(hexes[-1], 16)] if hexes and not c.op_str.startswith("#") else []
            if imms:
                i.target = imms[-1] & self._mask

    def _classify_ppc(self, c, i: Insn):
        """PowerPC control flow from the instruction word (capstone's simplified mnemonics hide
        the BO field: `bcl 20,31,.+4` decodes as `bdnzl`). Branch targets are absolute in
        capstone's operands. `b<cond>lr` / `b<cond>ctr`: conditional return / jump."""
        raw = int.from_bytes(c.bytes, "big" if self.bin.endian == "big" else "little")
        op = raw >> 26
        lk = raw & 1
        imm = next((o.imm for o in c.operands if o.type == OP_IMM), None)
        if op == 18:                                          # b / ba / bl / bla
            i.kind = CALL if lk else JMP
            i.target = imm & self._mask if imm is not None else None
            if i.target is not None:                          # (ELFv2: a local entry is its function)
                i.target = self.bin.ppc_local_entry.get(i.target, i.target)
            return
        if op == 16:                                          # bc
            bo = (raw >> 21) & 0x1F
            always = bo & 0x14 == 0x14
            target = imm & self._mask if imm is not None else None
            if lk:
                if always and target == i.addr + 4:
                    return                                    # `bcl 20,31,.+4`: reads pc into lr (PIC)
                i.kind, i.target = CALL, target
                return
            i.kind, i.target = (JMP if always else CJMP), target
            return
        if op == 19:
            xo = (raw >> 1) & 0x3FF
            bo = (raw >> 21) & 0x1F
            always = bo & 0x14 == 0x14
            if xo == 16:                                      # bclr: return (or call through lr)
                if lk:
                    i.kind = CALL
                else:
                    i.kind = RET if always else CJMP
                return
            if xo == 528:                                     # bcctr: indirect call / jump
                i.kind = CALL if lk else (JMP if always else CJMP)
                return
            return
        if c.mnemonic in ("trap",) or (op == 31 and ((raw >> 1) & 0x3FF) == 4 and (raw >> 21) & 0x1F == 31):
            i.kind = HALT                                     # `trap` (tw 31, 0, 0)
            return
        for v in (o.imm for o in c.operands if o.type == OP_IMM):
            v &= self._mask
            if v > 0xFF and self.bin.is_mapped(v):
                i.refs.append(v)

    def _classify_riscv(self, c, i: Insn):
        """RISC-V control flow by its operands (capstone's groups call `jr t3` and the PLT's
        `jalr t1, t3` calls). Branch and jump immediates are offsets from the instruction."""
        m = c.mnemonic
        ops = c.operands
        regs = [c.reg_name(o.reg) for o in ops if o.type == OP_REG]
        imm = next((o.imm for o in ops if o.type == OP_IMM), None)
        rel = (i.addr + imm) & self._mask if imm is not None else None
        if m in ("ret", "c.ret"):
            i.kind = RET
        elif m in ("jal", "c.jal"):
            rd = regs[0] if regs else "ra"               # `jal off` links ra
            i.kind = JMP if rd == "zero" else CALL
            i.target = rel
        elif m in ("j", "c.j"):
            i.kind, i.target = JMP, rel
        elif m in ("jr", "c.jr"):
            i.kind = RET if regs[:1] == ["ra"] and not imm else JMP
        elif m == "c.jalr":
            i.kind = CALL
        elif m == "jalr":
            rd = regs[0] if len(regs) == 2 else "ra"     # `jalr rs` links ra
            rs = regs[-1] if regs else ""
            if rd == "zero":
                i.kind = RET if rs == "ra" and not imm else JMP
            else:
                i.kind = CALL if rd == "ra" else JMP     # `jalr t1, t3`: a PLT stub's jump
        elif cs.CS_GRP_JUMP in set(c.groups) or cs.CS_GRP_BRANCH_RELATIVE in set(c.groups):
            i.kind, i.cond, i.target = CJMP, False, rel
        elif m in _HALT or m in ("ebreak", "c.ebreak", "unimp", "c.unimp"):
            i.kind = HALT

    @property
    def _mask(self) -> int:
        return (1 << self.bin.bits) - 1

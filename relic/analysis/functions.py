"""Function discovery and control-flow graphs (recursive descent)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..disasm import CALL, CJMP, HALT, JMP, RET, Disassembler, Insn
from ..loader.base import Binary, Symbol
from ..progress import checkpoint, report

NORETURN = {
    "exit", "_exit", "_Exit", "abort", "__stack_chk_fail", "__assert_fail", "__fortify_fail",
    "__chk_fail", "err", "errx", "verr", "verrx", "pthread_exit", "longjmp", "siglongjmp",
    "__libc_start_main", "__cxa_throw", "__cxa_rethrow", "_Unwind_Resume", "quick_exit",
    "ExitProcess", "ExitThread", "TerminateProcess", "__report_gsfailure", "_invalid_parameter_noinfo_noreturn",
}


@dataclass
class Block:
    addr: int
    insns: list[Insn] = field(default_factory=list, repr=False)
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        return self.insns[-1].end if self.insns else self.addr

    @property
    def last(self) -> Insn:
        return self.insns[-1]


@dataclass
class Function:
    addr: int
    name: str
    blocks: dict[int, Block] = field(default_factory=dict, repr=False)
    calls: set[int] = field(default_factory=set)  # direct call targets
    callers: set[int] = field(default_factory=set)  # call-site addresses
    tail_calls: set[int] = field(default_factory=set)
    jump_tables: dict[int, list[int]] = field(default_factory=dict)  # jmp addr -> targets
    is_import: bool = False
    noreturn: bool = False

    @property
    def end(self) -> int:
        return max((b.end for b in self.blocks.values()), default=self.addr)

    @property
    def size(self) -> int:
        return self.end - self.addr

    def insns(self) -> list[Insn]:
        out = []
        for a in sorted(self.blocks):
            out.extend(self.blocks[a].insns)
        return out

    def block_at(self, addr: int) -> Block | None:
        for b in self.blocks.values():
            if b.addr <= addr < b.end:
                return b
        return None


class FunctionAnalyzer:
    MAX_INSNS = 200_000

    def __init__(self, binary: Binary, dis: Disassembler):
        self.bin = binary
        self.dis = dis
        self.funcs: dict[int, Function] = {}
        self.prev: dict[int, int] = {}  # insn addr -> previous insn addr on fallthrough
        self._queue: list[int] = []

    # ------------------------------------------------------------- driver
    def run(self) -> dict[int, Function]:
        b = self.bin
        for imp in b.imports:
            if imp.addr and b.is_exec(imp.addr):
                f = Function(imp.addr, imp.name, is_import=True, noreturn=imp.name in NORETURN)
                self.funcs[imp.addr] = f
        seeds = [b.entry] if b.entry and b.is_exec(b.entry) else []
        seeds += sorted(a for a, s in b.symbols.items() if s.kind == "func" and b.is_exec(a))
        seeds += self._elf_ctor_seeds()
        seeds += [a for a in getattr(b, "function_starts", []) if b.is_exec(a)]   # PE .pdata
        self._queue.extend(seeds)
        self._drain()
        main = self._find_main()
        if main is not None:
            self._queue.append(main)
            self._drain()
        self._scan_gaps()
        self._link()
        return self.funcs

    def _drain(self):
        while self._queue:
            report("functions", len(self.funcs))
            a = self._queue.pop()
            if self.dis.md_thumb is not None and a & 1:      # ARM: a Thumb function pointer
                self.dis.hint(a, True)
                a &= ~1
            if a in self.funcs or not self.bin.is_exec(a):
                continue
            self._analyze(a)

    def _name(self, addr: int) -> str:
        n = self.bin.name_of(addr)
        if n:
            return n
        if addr == self.bin.entry:
            return "_start" if self.bin.format == "ELF" else "entry"
        return f"sub_{addr:x}"

    def _elf_ctor_seeds(self) -> list[int]:
        b = self.bin
        if b.format != "ELF":
            return []
        out = []
        dyn = getattr(b, "dynamic", {})
        for tag, name in (("DT_INIT", "_init"), ("DT_FINI", "_fini")):
            a = dyn.get(tag)
            if a and b.is_exec(a):
                out.append(a)
                b.add_symbol(Symbol(name, a, 0, "func", "synthetic"))
        for sec_name in (".init_array", ".fini_array"):
            sec = b.section(sec_name)
            if sec is None:
                continue
            for off in range(0, sec.size, b.bits // 8):
                a = b.read_ptr(sec.addr + off)
                if a and b.is_exec(a):
                    out.append(a)
        return out

    # ---------------------------------------------------------- one function
    def _analyze(self, start: int):
        f = Function(start, self._name(start))
        self.funcs[start] = f
        insns: dict[int, Insn] = {}
        leaders = {start}
        edges: dict[int, list[int]] = {}  # terminator addr -> successors
        work = [start]
        while work and len(insns) < self.MAX_INSNS:
            a = work.pop()
            while a not in insns:
                if a != start and a in self.funcs and not self.funcs[a].is_import:
                    break
                i = self.dis.decode(a)
                if i is None:
                    break
                insns[a] = i
                nxt = i.end
                if self.dis.md_thumb is not None:
                    self._hint_modes(i)
                if i.kind == CALL:
                    tgt = i.target
                    if tgt is not None and self.bin.is_exec(tgt):
                        f.calls.add(tgt)
                        if tgt not in self.funcs:
                            self._queue.append(tgt)
                    if self._is_noreturn_call(i):
                        edges[a] = []
                        break
                    if i.cond:
                        # ARM conditional call: the block ends so the lifter can branch around it
                        edges[a] = [nxt]
                        leaders.add(nxt)
                        work.append(nxt)
                        break
                elif i.kind == RET or i.kind == HALT:
                    edges[a] = []
                    break
                elif i.kind == JMP:
                    tgt = i.target
                    succ = []
                    if tgt is not None:
                        if self._is_tail_call(f, tgt):
                            f.tail_calls.add(tgt)
                            if tgt not in self.funcs:
                                self._queue.append(tgt)
                        elif self.bin.is_exec(tgt):
                            succ = [tgt]
                    else:
                        table = self._jump_table(i)
                        if table:
                            f.jump_tables[a] = table
                            succ = list(dict.fromkeys(table))
                        if i.cond:                      # ARM `addls pc, pc, ...`: default falls through
                            succ.append(nxt)
                        for t in succ:
                            self.dis.hint(t, i.thumb)
                    edges[a] = succ
                    for t in succ:
                        leaders.add(t)
                        work.append(t)
                    break
                elif i.kind == CJMP:
                    succ = []
                    if i.target is not None and self.bin.is_exec(i.target):
                        succ.append(i.target)
                    succ.append(nxt)
                    edges[a] = succ
                    for t in succ:
                        leaders.add(t)
                        work.append(t)
                    self.prev[nxt] = a
                    if i.target is not None:
                        # a branch target's first predecessor: lets jump-table matching look past
                        # `b.ls table_block` back to the bounds check (`cmp w0, #11`)
                        self.prev.setdefault(i.target, a)
                    a = nxt
                    continue
                # function pointers taken by address -- not on ARM (its immediates are offsets and
                # masks, addresses come from literal pools) nor from AArch64 `adr` (local labels
                # such as a jump table's base; function pointers come from `adrp` + `add`)
                for r in (i.refs if self.dis.md_thumb is None and i.mnemonic != "adr" else ()):
                    if r not in self.funcs and self.bin.is_exec(r) and r != start and self._looks_like_code(r):
                        self._queue.append(r)
                self.prev[nxt] = a
                a = nxt
        self._build_blocks(f, insns, leaders, edges)

    def _build_blocks(self, f: Function, insns: dict[int, Insn], leaders: set[int], edges: dict[int, list[int]]):
        cur: Block | None = None
        for a in sorted(insns):
            i = insns[a]
            if cur is None or a in leaders or cur.end != a:
                if cur is not None and cur.last.addr not in edges and cur.end == a:
                    cur.succs.append(a)  # fallthrough into a leader
                cur = Block(a)
                f.blocks[a] = cur
            cur.insns.append(i)
            if a in edges:
                cur.succs.extend(edges[a])
                cur = None
        if cur is not None and cur.last.addr not in edges and cur.end in insns:
            cur.succs.append(cur.end)
        for b in f.blocks.values():
            b.succs = [s for s in dict.fromkeys(b.succs) if s in f.blocks]
            for s in b.succs:
                f.blocks[s].preds.append(b.addr)

    # ------------------------------------------------------------- helpers
    def _hint_modes(self, i: Insn):
        """ARM interworking: successors run in the instruction set of `i`, except a `blx label`."""
        self.dis.hint(i.end, i.thumb)
        if i.target is not None:
            flip = i.kind == CALL and i.mnemonic.startswith("blx") and not i.op_str.startswith(("r", "l", "s", "i"))
            self.dis.hint(i.target, i.thumb != flip)

    def _is_noreturn_call(self, i: Insn) -> bool:
        tgt = i.target
        name = None
        if tgt is not None:
            fn = self.funcs.get(tgt)
            if fn is not None and fn.noreturn:
                return True
            name = self.bin.name_of(tgt)
        elif i.mem_target is not None:
            imp = self.bin.imports_by_got.get(i.mem_target)
            name = imp.name if imp else None
        return name in NORETURN

    def _is_tail_call(self, f: Function, tgt: int) -> bool:
        if tgt == f.addr:
            return False
        if tgt in self.funcs:
            return True
        s = self.bin.symbols.get(tgt)
        return bool(s and s.kind == "func")

    def _looks_like_code(self, addr: int) -> bool:
        i = self.dis.decode(addr)
        return i is not None and i.mnemonic not in ("add", "(bad)") and self.bin.section_at(addr) is not None

    def _back(self, addr: int, n: int) -> list[Insn]:
        out = []
        a = self.prev.get(addr)
        while a is not None and len(out) < n:
            i = self.dis.decode(a)
            if i is None:
                break
            out.append(i)
            a = self.prev.get(a)
        return out

    def _arm64_jump_table(self, jmp: Insn) -> list[int]:
        """gcc's AArch64 switch dispatch, bounded by a `cmp wI, #n` before it:

            adrp xT, table ; add xT, xT, :lo12:table
            ldrb wE, [xT, wI, uxtw]          (ldrh ... lsl #1 / ldr ... lsl #2: wider entries)
            adr  xB, base
            add  xD, xB, wE, sxtb #2         (entries are signed offsets from `base`, in words)
            br   xD
        """
        import capstone.arm64 as A64
        c = jmp.cs
        if jmp.mnemonic != "br" or not c.operands or c.operands[0].type != 1:
            return []

        def reg(name: str) -> str:              # w5 and x5 are the same register
            return name[1:] if name[:1] in ("w", "x") and name[1:].isdigit() else name

        def ops(i):
            return i.cs.operands

        hist = self._back(jmp.addr, 16)
        want = reg(c.reg_name(c.operands[0].reg))
        k = 0

        def find(pred):
            nonlocal k
            while k < len(hist):
                i = hist[k]
                k += 1
                if pred(i):
                    return i
            return None

        add = find(lambda i: i.mnemonic == "add" and len(ops(i)) == 3 and ops(i)[2].type == 1
                   and reg(i.cs.reg_name(ops(i)[0].reg)) == want)
        if add is None:
            return []
        o = ops(add)
        base_reg, off_reg = reg(add.cs.reg_name(o[1].reg)), reg(add.cs.reg_name(o[2].reg))
        ext, shift = o[2].ext, o[2].shift.value
        signed = ext in (A64.ARM64_EXT_SXTB, A64.ARM64_EXT_SXTH, A64.ARM64_EXT_SXTW)
        save = k
        adr = find(lambda i: i.mnemonic == "adr" and reg(i.cs.reg_name(ops(i)[0].reg)) == base_reg)
        if adr is None:
            return []
        base = ops(adr)[1].imm
        k = save
        load = find(lambda i: i.mnemonic in ("ldrb", "ldrh", "ldr", "ldrsb", "ldrsh", "ldrsw")
                    and reg(i.cs.reg_name(ops(i)[0].reg)) == off_reg and len(ops(i)) == 2
                    and ops(i)[1].type == 3 and ops(i)[1].mem.index)
        if load is None:
            return []
        m = ops(load)[1].mem
        tab_reg, idx = reg(load.cs.reg_name(m.base)), reg(load.cs.reg_name(m.index))
        size = {"ldrb": 1, "ldrsb": 1, "ldrh": 2, "ldrsh": 2, "ldrsw": 4}.get(
            load.mnemonic, 4 if load.cs.reg_name(ops(load)[0].reg).startswith("w") else 8)
        lo = find(lambda i: i.mnemonic == "add" and len(ops(i)) == 3 and ops(i)[2].type == 2
                  and reg(i.cs.reg_name(ops(i)[0].reg)) == tab_reg)
        page = find(lambda i: i.mnemonic == "adrp" and reg(i.cs.reg_name(ops(i)[0].reg)) == tab_reg)
        if lo is None or page is None:
            return []
        table = ops(page)[1].imm + ops(lo)[2].imm
        # the bound: `cmp` on the index or on the register it was copied from (`mov w5, w0`)
        aliases = {idx}
        for _ in range(3):
            for i in hist:
                o = ops(i)
                if i.mnemonic == "mov" and len(o) == 2 and o[1].type == 1:
                    a, b = reg(i.cs.reg_name(o[0].reg)), reg(i.cs.reg_name(o[1].reg))
                    if a in aliases or b in aliases:
                        aliases |= {a, b}
        n = None
        for i in hist:
            o = ops(i)
            if i.mnemonic == "cmp" and len(o) == 2 and o[0].type == 1 and o[1].type == 2 and \
                    reg(i.cs.reg_name(o[0].reg)) in aliases:
                n = o[1].imm
                break
        if n is None or not 0 <= n < 4096:
            return []
        out = []
        for e in range(n + 1):
            v = self.bin.read_int(table + size * e, size, signed=signed)
            if v is None:
                return []
            t = base + (v << shift)
            if not self.bin.is_exec(t):
                return []
            out.append(t)
        return out

    def _arm_jump_table(self, jmp: Insn) -> list[int]:
        """ARM / Thumb switch dispatch, bounded by the `cmp rI, #n` before it:

        - `addls pc, pc, rI, lsl #2`: a branch per case right after the dispatch;
        - `tbb [pc, rI]` / `tbh [pc, rI, lsl #1]`: byte / halfword offsets (in halfwords);
        - `ldr pc, [pc, rI, lsl #2]`: absolute addresses after the dispatch;
        - `adr rB, T; ldr rT, [rB, rI, lsl #2]; add rB, rT; bx rB`: offsets from the table T.
        """
        ops = jmp.cs.operands
        m = jmp.mnemonic.split(".")[0]
        if jmp.cond:
            m = m[:-2]
        hist = self._back(jmp.addr, 8)
        name = jmp.cs.reg_name

        def pc_of(i: Insn) -> int:
            return ((i.addr + 4) & ~3) if i.thumb else i.addr + 8

        def bound(idx) -> int | None:
            for i in hist:
                o = i.cs.operands
                if i.mnemonic.split(".")[0] == "cmp" and len(o) == 2 and o[0].type == 1 and o[0].reg == idx \
                        and o[1].type == 2:
                    return o[1].imm if 0 <= o[1].imm < 1024 else None
            return None

        def words(base, n, relative):
            out = []
            for k in range(n + 1):
                v = self.bin.read_int(base + 4 * k, 4, signed=relative)
                if v is None:
                    return []
                out.append(((base + v) if relative else v) & ~1 & 0xFFFFFFFF)
            return out

        if m == "add" and len(ops) == 3 and ops[2].type == 1:             # addls pc, pc, rI, lsl #2
            n = bound(ops[2].reg)
            return [jmp.addr + 8 + 4 * k for k in range(n + 1)] if n is not None else []
        if m in ("tbb", "tbh") and ops and ops[0].type == 3:
            n = bound(ops[0].mem.index)
            if n is None:
                return []
            base, size = jmp.addr + 4, 1 if m == "tbb" else 2
            out = []
            for k in range(n + 1):
                v = self.bin.read_int(base + size * k, size)
                if v is None:
                    return []
                out.append(base + 2 * v)
            return out
        if m == "ldr" and len(ops) == 2 and ops[1].type == 3 and name(ops[1].mem.base) == "pc":
            n = bound(ops[1].mem.index)
            return words(pc_of(jmp), n, False) if n is not None else []
        if m not in ("bx", "mov") or not ops or ops[-1].type != 1:
            return []
        target = ops[-1].reg
        offset_reg = None
        k = 0
        if hist and hist[0].mnemonic.split(".")[0] == "add":                # add rB, rT
            o = hist[0].cs.operands
            regs = [x.reg for x in o if x.type == 1]
            if regs and regs[0] == target and len(regs) >= 2:
                offset_reg = regs[-1] if regs[-1] != target or len(regs) == 2 else regs[-2]
                k = 1
        load_dst = offset_reg if offset_reg is not None else target
        for j in range(k, len(hist)):
            i = hist[j]
            o = i.cs.operands
            if i.mnemonic.split(".")[0] == "ldr" and len(o) == 2 and o[0].type == 1 and o[0].reg == load_dst \
                    and o[1].type == 3 and o[1].mem.index:
                base_reg, idx = o[1].mem.base, o[1].mem.index
                n = bound(idx)
                if n is None:
                    return []
                for a in hist[j + 1:]:
                    ao = a.cs.operands
                    am = a.mnemonic.split(".")[0]
                    if not ao or ao[0].type != 1 or ao[0].reg != base_reg:
                        continue
                    if am == "adr" and ao[1].type == 2:
                        table = pc_of(a) + ao[1].imm
                    elif am in ("add", "addw") and len(ao) == 3 and ao[1].type == 1 and \
                            a.cs.reg_name(ao[1].reg) == "pc" and ao[2].type == 2:
                        table = pc_of(a) + ao[2].imm
                    else:
                        return []
                    return words(table, n, offset_reg is not None)
                return []
        return []

    def _jump_table(self, jmp: Insn) -> list[int]:
        """Resolve `jmp reg` / `jmp [table+reg*N]` switch dispatch on x86."""
        if self.dis.arch == "arm":
            return self._arm_jump_table(jmp)
        if self.dis.arch == "arm64":
            return self._arm64_jump_table(jmp)
        if self.dis.arch not in ("x86", "x64"):
            return []
        ptr = self.bin.bits // 8
        hist = self._back(jmp.addr, 16)
        base = None
        relative = True
        anchor = None          # relative tables: entries are offsets from here (default: the table)
        # jmp [table + reg*ptr]
        for op in jmp.cs.operands:
            if op.type == 3 and op.mem.index and op.mem.scale == ptr and op.mem.disp:
                base, relative = op.mem.disp & self.dis._mask, False
        if base is None:
            for i in hist:
                for op in i.cs.operands:
                    if op.type != 3:
                        continue
                    m = op.mem
                    if m.index and m.scale == ptr and m.base == 0 and m.disp and i.mnemonic == "mov":
                        base, relative = m.disp & self.dis._mask, False
                if base is not None:
                    break
                if i.mnemonic == "lea" and i.refs:
                    base = i.refs[0]
                    break
        if base is None and self.bin.bits == 32:
            # x86-32 PIC: `add/mov R, [G + idx*4 + d]` with G holding the GOT address, entries
            # are offsets from the GOT (`add R, G; jmp R`)
            got = self._got_base()
            for i in [jmp, *hist]:
                for op in i.cs.operands:
                    # scale 4, or 1 when the index was scaled beforehand (`shl edx, 2` at -O0)
                    if op.type == 3 and op.mem.base and op.mem.index and op.mem.scale in (1, 4) and \
                            i.mnemonic in ("add", "mov") and got is not None:
                        base, anchor = (got + op.mem.disp) & self.dis._mask, got
                        break
                if base is not None:
                    break
        if base is None:
            return []
        count = None
        for k, i in enumerate(hist):
            if i.mnemonic in ("ja", "jae", "jb", "jbe") and k + 1 < len(hist):
                cmp = hist[k + 1]
                if cmp.mnemonic == "cmp" and cmp.cs.operands[-1].type == 2:
                    v = cmp.cs.operands[-1].imm
                    count = v + 1 if i.mnemonic in ("ja", "jbe") else v
                break
        limit = count if count is not None and 0 < count <= 4096 else 512
        sec = self.bin.section_at(jmp.addr)
        out = []
        for n in range(limit):
            if relative:
                v = self.bin.read_int(base + 4 * n, 4, signed=True)
                if v is None:
                    break
                t = ((anchor if anchor is not None else base) + v) & self.dis._mask
            else:
                t = self.bin.read_ptr(base + ptr * n)
                if t is None:
                    break
            if not (sec and sec.contains(t)):
                if count is None:
                    break
                continue
            out.append(t)
        return out

    def _got_base(self) -> int | None:
        """The x86-32 PIC GOT pointer: `_GLOBAL_OFFSET_TABLE_`, else the start of .got.plt."""
        b = self.bin
        a = b.name_to_addr.get("_GLOBAL_OFFSET_TABLE_")
        if a:
            return a
        sec = b.section(".got.plt") or b.section(".got")
        return sec.addr if sec is not None else None

    def _find_main(self) -> int | None:
        """Recover `main` from the `__libc_start_main(main, ...)` call in `_start`."""
        b = self.bin
        if b.format != "ELF" or "main" in b.name_to_addr:
            return None
        start = self.funcs.get(b.entry)
        if start is None:
            return None
        reg = "rdi" if b.arch == "x64" else None
        hist = start.insns()
        for k, i in enumerate(hist):
            if i.kind != CALL:
                continue
            imp = b.imports_by_got.get(i.mem_target) if i.mem_target else None
            name = imp.name if imp else (b.name_of(i.target) if i.target else None)
            if name != "__libc_start_main":
                continue
            for j in reversed(hist[:k]):
                if reg and reg in j.regs_write and j.mnemonic in ("mov", "lea") and j.refs:
                    cand = j.refs[0]
                    if b.is_exec(cand):
                        return self._name_main(cand)
            if b.arch == "x86":  # main is the last push before the call
                pushes = [j for j in hist[:k] if j.mnemonic == "push"]
                if pushes and pushes[-1].refs and b.is_exec(pushes[-1].refs[0]):
                    return self._name_main(pushes[-1].refs[0])
        return None

    def add_function(self, addr: int, name: str | None = None) -> int:
        """Analyse one more function (and what it reaches) after `run`; returns its address."""
        if self.dis.md_thumb is not None and addr & 1:
            self.dis.hint(addr, True)
            addr &= ~1
        self._queue.append(addr)
        self._drain()
        if name == "main":
            self._name_main(addr)
        self._link()
        return addr

    def _name_main(self, cand: int) -> int:
        self.bin.add_symbol(Symbol("main", cand, 0, "func", "synthetic"), override=True)
        self.bin.name_to_addr["main"] = cand
        if cand in self.funcs:
            self.funcs[cand].name = "main"
        return cand

    def _scan_gaps(self):
        """Pick up functions only reachable indirectly (prologue scan: x86, ARM, AArch64)."""
        if self.dis.arch not in ("x86", "x64", "arm", "arm64"):
            return
        prologues = (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb", b"\x55\x48\x89\xe5", b"\x55\x89\xe5")
        tried: set[int] = set()
        for sec in self.bin.exec_sections:
            if sec.name in (".plt", ".plt.sec", ".plt.got", ".init", ".fini"):
                continue
            changed = True
            while changed:
                checkpoint()
                changed = False
                covered = sorted((f.addr, f.end) for f in self.funcs.values() if sec.contains(f.addr))
                gaps, cur = [], sec.addr
                for s, e in covered:
                    if s > cur:
                        gaps.append((cur, s))
                    cur = max(cur, e)
                if cur < sec.end:
                    gaps.append((cur, sec.end))
                for s, e in gaps:
                    if self.dis.arch in ("arm", "arm64"):
                        start = self._arm_gap_function(s, e)
                    else:
                        start = self._gap_function(s, e, prologues)
                    if start is not None and start not in tried:
                        tried.add(start)
                        self._queue.append(start)
                        self._drain()
                        changed = True
                        break

    def _arm_gap_function(self, s: int, e: int) -> int | None:
        """First prologue in [s, e) after padding (an odd result is a Thumb start).

        AArch64: `stp x29, x30, [sp, #-n]!`, `paciasp`, `bti c`. ARM: A32 `push {..., lr}`
        (`stmdb sp!` / `str lr, [sp, #-4]!`), Thumb `push {..., lr}` and Thumb-2 `push.w`.
        Gaps also hold literal pools and tables, so only a real prologue counts here.
        """
        a = (s + 3) & ~3 if self.dis.arch == "arm64" else (s + 1) & ~1
        while a + 4 <= e:
            w = self.bin.read_int(a, 4)
            if w is None:
                return None
            if self.dis.arch == "arm64":
                if w == 0 or w == 0xD503201F:                       # padding, nop
                    a += 4
                    continue
                if (w & 0xFFC07FFF) == 0xA9807BFD or w in (0xD503233F, 0xD503245F, 0xD503249F):
                    return a
                return None
            h = w & 0xFFFF
            if w == 0 or h == 0xBF00 or w == 0xE1A00000 or w == 0xE320F000:   # padding, nops
                a += 2 if h in (0, 0xBF00) and w != 0 else 4
                continue
            if a % 4 == 0 and ((w & 0xFFFF4000) == 0xE92D4000 or w == 0xE52DE004):
                return a                                            # A32 push {..., lr}
            if (h & 0xFF00) == 0xB500 or (h == 0xE92D and (w >> 16) & 0x4000):
                return a | 1                                        # Thumb push {..., lr}
            return None
        return None

    def _gap_function(self, s: int, e: int, prologues: tuple[bytes, ...]) -> int | None:
        """First plausible function start in [s, e) after alignment padding."""
        a = s
        while a < e:
            if self.bin.read(a, 1) in (b"\x90", b"\xcc", b"\x00"):
                a += 1
                continue
            i = self.dis.decode(a)
            if i is None:
                return None
            if not i.mnemonic.startswith("nop"):
                break
            a = i.end
        if a >= e:
            return None
        if self.bin.read(a, 4).startswith(prologues):
            return a
        if a % 16 == 0 and a != s:
            run = self.dis.linear(a, 3)
            if len(run) == 3 and not any(i.mnemonic in ("(bad)", "add") and i.raw[:2] == b"\0\0" for i in run):
                return a
        return None

    def _link(self):
        for f in self.funcs.values():
            for b in f.blocks.values():
                for i in b.insns:
                    if i.kind == CALL and i.target in self.funcs:
                        self.funcs[i.target].callers.add(i.addr)
        # propagate noreturn: a function whose every path ends in a noreturn call
        for f in self.funcs.values():
            if f.is_import or not f.blocks:
                continue
            exits = [b for b in f.blocks.values() if not b.succs]
            if exits and all(b.last.kind == CALL for b in exits):
                f.noreturn = True

"""Function discovery and control-flow graphs (recursive descent)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..disasm import CALL, CJMP, HALT, JMP, RET, Disassembler, Insn
from ..loader.base import Binary, Symbol

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
            a = self._queue.pop()
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
                if i.kind == CALL:
                    tgt = i.target
                    if tgt is not None and self.bin.is_exec(tgt):
                        f.calls.add(tgt)
                        if tgt not in self.funcs:
                            self._queue.append(tgt)
                    if self._is_noreturn_call(i):
                        edges[a] = []
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
                    a = nxt
                    continue
                for r in i.refs:  # function pointers taken by address
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

    def _jump_table(self, jmp: Insn) -> list[int]:
        """Resolve `jmp reg` / `jmp [table+reg*N]` switch dispatch on x86."""
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

    def _name_main(self, cand: int) -> int:
        self.bin.add_symbol(Symbol("main", cand, 0, "func", "synthetic"), override=True)
        self.bin.name_to_addr["main"] = cand
        if cand in self.funcs:
            self.funcs[cand].name = "main"
        return cand

    def _scan_gaps(self):
        """Pick up functions only reachable indirectly (prologue scan, x86)."""
        if self.dis.arch not in ("x86", "x64"):
            return
        prologues = (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb", b"\x55\x48\x89\xe5", b"\x55\x89\xe5")
        for sec in self.bin.exec_sections:
            if sec.name in (".plt", ".plt.sec", ".plt.got", ".init", ".fini"):
                continue
            changed = True
            while changed:
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
                    start = self._gap_function(s, e, prologues)
                    if start is not None:
                        self._queue.append(start)
                        self._drain()
                        changed = True
                        break

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

"""Function discovery and control-flow graphs (recursive descent)."""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from ..disasm import CALL, CJMP, HALT, JMP, RET, Disassembler, Insn
from ..loader.base import Binary, Symbol
from ..progress import checkpoint, report

NORETURN = {
    "exit", "_exit", "_Exit", "abort", "__stack_chk_fail", "__assert_fail", "__fortify_fail",
    "__chk_fail", "err", "errx", "verr", "verrx", "pthread_exit", "longjmp", "siglongjmp",
    "_longjmp", "__longjmp_chk",
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
        """The block's terminator: on MIPS the branch, not the delay-slot instruction after it."""
        if len(self.insns) > 1 and self.insns[-1].delay:
            return self.insns[-2]
        return self.insns[-1]


class _Cover:
    """Sorted, disjoint [start, end) ranges of code already claimed by functions."""

    def __init__(self):
        self.starts: list[int] = []
        self.ends: list[int] = []

    def add(self, s: int, e: int):
        if e <= s:
            return
        i = bisect.bisect_left(self.ends, s)          # first range that ends at or after s
        j = bisect.bisect_right(self.starts, e)       # ranges starting after e stay
        if i < j:
            s = min(s, self.starts[i])
            e = max(e, self.ends[j - 1])
        self.starts[i:j] = [s]
        self.ends[i:j] = [e]

    def add_blocks(self, f: "Function", sec):
        for b in f.blocks.values():
            if sec.contains(b.addr):
                self.add(b.addr, b.end)

    def next_gap(self, pos: int, end: int) -> tuple[int, int] | None:
        """The first uncovered range [s, e) at or after `pos`, before `end`."""
        i = bisect.bisect_right(self.starts, pos) - 1
        if i >= 0 and self.ends[i] > pos:
            pos = self.ends[i]
            i += 1
        else:
            i += 1
        if pos >= end:
            return None
        e = self.starts[i] if i < len(self.starts) else end
        return (pos, min(e, end)) if pos < min(e, end) else self.next_gap(min(e, end), end) if e < end else None


def _fragment(name: str) -> bool:
    """gcc's names for pieces split off a function (`f.cold`, `f.cold.3`): its code, not one of
    their own (`f.part.0` and `f.isra.0` are real functions)."""
    return ".cold" in name


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
    library: bool = False   # named by a library signature (libsigs), not by a symbol

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


_ENDBR = (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb")


class FunctionAnalyzer:
    MAX_INSNS = 200_000

    def __init__(self, binary: Binary, dis: Disassembler, noreturn: set[int] = frozenset()):
        self.bin = binary
        self.dis = dis
        self.noreturn = noreturn      # functions known not to return (named by library signatures)
        self.funcs: dict[int, Function] = {}
        self.prev: dict[int, int] = {}  # insn addr -> previous insn addr on fallthrough
        self._queue: list[int] = []
        self._fde: set[int] = set()     # ELF: function starts `.eh_frame` describes

    # ------------------------------------------------------------- driver
    def run(self) -> dict[int, Function]:
        b = self.bin
        for imp in b.imports:
            if imp.addr and b.is_exec(imp.addr):
                f = Function(imp.addr, imp.name, is_import=True, noreturn=imp.name in NORETURN)
                self.funcs[imp.addr] = f
        self._fde = self._eh_frame_starts()
        seeds = [b.entry] if b.entry and b.is_exec(b.entry) else []
        seeds += sorted(a for a, s in b.symbols.items() if s.kind == "func" and b.is_exec(a) and not _fragment(s.name))
        seeds += self._elf_ctor_seeds()
        seeds += [a for a in getattr(b, "function_starts", []) if b.is_exec(a)]   # PE .pdata
        self._queue.extend(seeds)
        self._drain()
        main = self._find_main()
        if main is not None:
            self._queue.append(main)
            self._drain()
        self._eh_frame_seeds()
        self._data_pointer_seeds()
        self._infer_noreturn()
        self._scan_gaps()
        self._infer_noreturn()
        self._link()
        return self.funcs

    # DWARF number of the stack pointer and the CFA offset from it at a function's first
    # instruction (only the return address pushed, on x86)
    _ENTRY_CFA = {"x64": (7, 8), "x86": (4, 4), "arm64": (31, 0), "arm": (13, 0), "mips": (29, 0),
                  "mips64": (29, 0), "riscv64": (2, 0), "riscv32": (2, 0), "ppc": (1, 0), "ppc64": (1, 0)}

    def _eh_frame_starts(self) -> set[int]:
        """ELF: the start of every function `.eh_frame` describes (stripped or not). An FDE whose
        first row is not the entry state (a `.cold` fragment, the PLT) does not start one."""
        b = self.bin
        if b.format != "ELF" or b.section(".eh_frame") is None:
            return set()
        entry = self._ENTRY_CFA.get(b.arch)
        out = set()
        try:
            import io

            from elftools.elf.elffile import ELFFile
            dwarf = ELFFile(io.BytesIO(b.data)).get_dwarf_info()
            for e in dwarf.EH_CFI_entries():
                if type(e).__name__ != "FDE":
                    continue
                if entry is not None:
                    rows = e.get_decoded().table
                    cfa = rows[0].get("cfa") if rows else None
                    if cfa is None or (cfa.reg, cfa.offset) != entry:
                        continue
                out.add(e.header["initial_location"])
        except Exception:                       # noqa: BLE001 - malformed or unusual CFI: none
            return set()
        return out

    def _infer_noreturn(self):
        """Functions that never return, from their code: no way out of them but calls of (or jumps
        to) functions that do not return -- `exit`, `abort`, others found here -- or no way out at
        all. Their callers, analyzed before this was known, ran on past such calls into whatever
        follows (often the next function); they are analyzed again, until nothing changes."""
        while True:
            new: set[int] = set()
            changed = True
            while changed:
                changed = False
                for f in self.funcs.values():
                    if not f.is_import and not f.noreturn and f.blocks and not self._returns(f):
                        f.noreturn = True
                        new.add(f.addr)
                        changed = True
            if not new:
                return
            redo = [f for f in self.funcs.values() if not f.is_import and (f.calls | f.tail_calls) & new]
            for f in redo:
                for blk in f.blocks.values():
                    for i in blk.insns:
                        self.prev.pop(i.end, None)
                del self.funcs[f.addr]
                if self.dis.md_thumb is not None and f.addr in f.blocks:
                    self.dis.hint(f.addr, f.blocks[f.addr].insns[0].thumb)
                self._analyze(f.addr)
                g = self.funcs[f.addr]
                g.name, g.noreturn, g.library = f.name, f.noreturn, f.library
            self._drain()

    def _calls_noreturn(self, i: Insn) -> bool:
        if i.kind == CALL:
            return self._is_noreturn_call(i)
        if i.kind == JMP and i.target is not None:      # (a tail call)
            fn = self.funcs.get(i.target)
            return fn is not None and fn.noreturn or i.target in self.noreturn
        return False

    def _returns(self, f: Function) -> bool:
        """Whether some path from `f`'s entry leaves it other than by a call that does not return.
        A way out that cannot be followed (an unresolved jump, undecodable bytes) counts as one."""
        seen, work = set(), [f.addr]
        while work:
            a = work.pop()
            if a in seen or a not in f.blocks:
                continue
            seen.add(a)
            blk = f.blocks[a]
            if any(self._calls_noreturn(i) for i in blk.insns if i.kind in (CALL, JMP)):
                continue
            if blk.succs:
                work.extend(blk.succs)
                continue
            last = blk.last
            if last.kind == HALT or last.kind == CALL:      # (a call cut short: does not return)
                continue
            if last.kind not in (RET, JMP, CJMP):
                nxt = self.funcs.get(blk.end)           # (runs into the next function)
                if nxt is not None and nxt.noreturn:
                    continue
            return True
        return False

    def _eh_frame_seeds(self):
        """The functions `.eh_frame` describes that nothing reached. After the others are found,
        so that the separate FDE of a `.cold` fragment -- code of a function already found --
        does not start one."""
        b = self.bin
        starts = sorted(self._fde)
        if not starts:
            return
        inside = self._covered()
        for a in starts:
            if a in self.funcs or not b.is_exec(a) or inside(a):    # (inside a function found already)
                continue
            self._queue.append(a)
        self._drain()

    def _covered(self):
        """Predicate: whether an address lies in a block of a function found so far."""
        covered = sorted((blk.addr, blk.end) for f in self.funcs.values() if not f.is_import
                         for blk in f.blocks.values())
        firsts = [c[0] for c in covered]

        def inside(a: int) -> bool:
            k = bisect.bisect_right(firsts, a) - 1
            return k >= 0 and covered[k][0] <= a < covered[k][1]
        return inside

    def _data_pointer_seeds(self):
        """Functions only called through pointers stored in data (callback tables, vtables,
        `struct` initializers): the code addresses that position-independent data relocates.
        x86 code built for CET starts every such function with `endbr64`."""
        b = self.bin
        x86 = self.dis.arch in ("x64", "x86")
        cet = x86 and b.entry is not None and b.read(b.entry, 4) in _ENDBR
        inside = self._covered()
        for r in getattr(b, "relocs", ()):
            if "RELATIVE" not in r.kind or b.is_exec(r.addr):
                continue
            a = r.addend or b.read_ptr(r.addr)
            if not a or a in self.funcs or not b.is_exec(a & ~1) or inside(a & ~1):
                continue
            if x86 and not (b.read(a, 4) in _ENDBR if cet else a % 16 == 0):
                continue
            if self.dis.md_thumb is not None:
                self.dis.hint(a & ~1, bool(a & 1))      # (before decoding it: the mode sticks)
            if self._looks_like_code(a & ~1):
                self._queue.append(a)
        self._drain()

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
        pic = self.dis.arch == "x64" and getattr(self.bin, "elf_type", None) == "ET_DYN"
        while work and len(insns) < self.MAX_INSNS:
            a = work.pop()
            while a not in insns:
                if a != start and a in self.funcs and not self.funcs[a].is_import:
                    break
                if a != start and a in self._fde and self.prev.get(a) is not None and a not in leaders:
                    break               # (falling into the next function: unwind info starts one here)
                i = self.dis.decode(a)
                if i is None:
                    break
                insns[a] = i
                nxt = i.end
                if self.dis.md_thumb is not None:
                    self._hint_modes(i)
                # MIPS: the instruction after a branch, call or return runs before control moves;
                # it belongs to the branch's block, which then ends after it (edges are keyed by it)
                if self.dis.delay_slots and i.kind in (CALL, RET, JMP, CJMP):
                    d = self.dis.decode(nxt)
                    if d is not None and nxt not in insns:
                        d.delay = True
                        insns[nxt] = d
                        self.prev[nxt] = a
                        a, nxt = nxt, d.end
                if i.kind == CALL:
                    tgt = i.target
                    if tgt is not None and self.bin.is_exec(tgt):
                        f.calls.add(tgt)
                        if tgt not in self.funcs:
                            self._queue.append(tgt)
                    if self._is_noreturn_call(i) or nxt in self._fde and nxt != start:
                        # (a call the next function's unwind info follows does not come back)
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
                        if self._is_tail_call(f, tgt) or tgt not in insns and self._x86_frame_gone(i, start):
                            f.tail_calls.add(tgt)
                            if tgt not in self.funcs:
                                self._queue.append(tgt)
                        elif self.bin.is_exec(tgt):
                            succ = [tgt]
                    else:
                        self._jt_func = f.addr
                        table = self._jump_table(i)
                        if table:
                            f.jump_tables[i.addr] = table
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
                # (x86-64 PIC takes addresses `rip`-relative: its immediates are numbers, not addresses)
                for r in (i.refs if self.dis.md_thumb is None and i.mnemonic != "adr" and
                          not (pic and not (i.mnemonic == "lea" and "rip" in i.op_str)) else ()):
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
                if cur is not None and cur.insns[-1].addr not in edges and cur.end == a:
                    cur.succs.append(a)  # fallthrough into a leader
                cur = Block(a)
                f.blocks[a] = cur
            cur.insns.append(i)
            if a in edges:
                cur.succs.extend(edges[a])
                cur = None
        if cur is not None and cur.insns[-1].addr not in edges and cur.end in insns:
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

    def _mips_call_slot(self, i: Insn) -> int | None:
        """The GOT slot a MIPS `jalr $t9` calls through: `lw $t9, off($gp)` shortly before it,
        directly or by way of a `move $t9, $v0`."""
        gp = self.bin.mips_gp
        if gp is None or not i.op_str.endswith("$t9"):
            return None
        want = "$t9"
        for p in self._back(i.addr, 8):
            ops = [o.strip() for o in p.op_str.split(",")]
            if not ops or ops[0] != want:
                continue
            if p.mnemonic == "move" and len(ops) == 2:
                want = ops[1]
                continue
            if p.mnemonic in ("lw", "ld") and len(ops) == 2 and ops[1].endswith("($gp)"):
                try:
                    return (gp + int(ops[1][:-5] or "0", 0)) & ((1 << self.bin.bits) - 1)
                except ValueError:
                    return None
            return None
        return None

    def _is_noreturn_call(self, i: Insn) -> bool:
        if i.target is None and i.mem_target is None and i.mnemonic == "jalr" and self.dis.delay_slots:
            i.mem_target = self._mips_call_slot(i)
        tgt = i.target
        name = None
        if tgt is not None:
            if tgt in self.noreturn:
                return True
            fn = self.funcs.get(tgt)
            if fn is not None and fn.noreturn:
                return True
            name = self.bin.name_of(tgt)
        elif i.mem_target is not None:
            imp = self.bin.imports_by_got.get(i.mem_target)
            name = imp.name if imp else None
        if name in ("error", "error_at_line"):          # (exits when its status is not 0)
            return self._nonzero_first_arg(i)
        return name in NORETURN

    def _nonzero_first_arg(self, i: Insn) -> bool:
        reg = {"x64": "edi", "arm64": "w0"}.get(self.dis.arch)
        for p in self._back(i.addr, 4) if reg else ():
            ops = [o.strip() for o in p.op_str.split(",")]
            if ops and ops[0] in (reg, "r" + reg[1:], "x0"):
                return p.mnemonic == "mov" and len(ops) == 2 and ops[1].lstrip("#").isdigit() and \
                    int(ops[1].lstrip("#")) != 0
        return False

    def _is_tail_call(self, f: Function, tgt: int) -> bool:
        if tgt == f.addr:
            return False
        if tgt in self.funcs:
            return True
        if tgt in self._fde:
            return True                         # a function's entry by its unwind info
        s = self.bin.symbols.get(tgt)
        if s is not None:
            return s.kind == "func" and not _fragment(s.name)
        # CET: indirect-branch targets start with `endbr64` -- functions, never a block of this one
        # (gcc reaches switch cases by `notrack jmp`)
        return self.dis.arch in ("x64", "x86") and self.bin.read(tgt, 4) in _ENDBR

    _EPILOGUE = ("pop", "leave")

    def _x86_frame_gone(self, jmp: Insn, start: int) -> bool:
        """x86: a `jmp` to a function's alignment (16) with the caller's frame gone -- right after
        an epilogue (`pop`s, `leave`, `add rsp`), or (backwards, before this function) from a
        wrapper that never set one up: a tail call of a function nothing else reaches."""
        if self.dis.arch not in ("x64", "x86") or jmp.target % 16:
            return False
        sp = "rsp" if self.dis.arch == "x64" else "esp"
        a = self.prev.get(jmp.addr)
        for k in range(64):
            if a is None:
                return False
            i = self.dis.decode(a)
            if i is None:
                return False
            if k < 8 and (i.mnemonic in self._EPILOGUE or i.mnemonic == "add" and i.op_str.startswith(sp + ",")):
                return True
            if i.mnemonic in ("push", "call", "enter") or sp in i.op_str:
                return False
            if a == start:
                return jmp.target < start
            a = self.prev.get(a)
        return False

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

    def _mips_jump_table(self, jmp: Insn) -> list[int]:
        """`jr $v0` after `lw $v0, 0(table + idx * 4)`: the table address built with `lui` + `addiu`
        or read from the GOT (`lw $v0, %got(table)($gp)` + `addiu`), entries absolute or -- PIC
        `.gpword` tables -- relative to `$gp` (`addu $v0, $v0, $gp`). The bound comes from the
        `sltiu $t, idx, N` that guards it."""
        b = self.bin
        msk = self.dis._mask
        hist = self._back(jmp.addr, 20)[::-1]                     # oldest first
        regs: dict[str, tuple] = {}                               # register -> ("c", v) / ("idx",) / ...
        gp = b.mips_gp
        bound = None
        word = b.bits // 8                                        # (MIPS64: `.gpdword` entries)
        shift = "3" if word == 8 else "2"

        def ops_of(i):
            return [o.strip().lstrip("$") for o in i.op_str.split(",")]

        t9_written = False

        def val(r):
            if r == "zero":
                return ("c", 0)
            if r == "gp" and gp is not None:
                return ("c", gp)
            if r == "t9" and r not in regs and not t9_written and getattr(self, "_jt_func", None) is not None:
                return ("c", self._jt_func)           # PIC: `$t9` holds the function's own address
            return regs.get(r)

        for i in hist:
            m, ops = i.mnemonic, ops_of(i)
            if not ops or not ops[0]:
                continue
            d = ops[0]
            new = None
            if m == "lui" and len(ops) == 2:
                new = ("c", (int(ops[1], 0) << 16) & msk)
            elif m in ("addiu", "daddiu", "ori") and len(ops) == 3 and (v := val(ops[1])) and v[0] == "c":
                k = int(ops[2], 0)
                new = ("c", (v[1] | k if m == "ori" else v[1] + k) & msk)
            elif m in ("sll", "dsll") and len(ops) == 3 and ops[2] in (shift, hex(int(shift))):
                new = ("scaled",)
            elif m == "sltiu" and len(ops) == 3:
                bound = int(ops[2], 0)
            elif m in ("addu", "daddu") and len(ops) == 3:
                a, c = val(ops[1]), val(ops[2])
                if a and c and a[0] == c[0] == "c":
                    new = ("c", (a[1] + c[1]) & msk)          # `daddu a1, a1, $t9`: building _gp
                elif a and c and {a[0], c[0]} == {"c", "scaled"}:
                    new = ("elem", a[1] if a[0] == "c" else c[1])
                elif a and c and a[0] == "entry" and c == ("c", gp):
                    new = ("gprel", a[1])
                elif a and c and c[0] == "entry" and a == ("c", gp):
                    new = ("gprel", c[1])
            elif m == ("ld" if word == 8 else "lw") and len(ops) == 2 and "(" in ops[1]:
                off, base = ops[1].rstrip(")").split("(")
                off = int(off or "0", 0)
                v = val(base.lstrip("$"))
                if v and v[0] == "elem" and off == 0:
                    new = ("entry", v[1])
                elif v and v[0] == "c":
                    w = b.read_int((v[1] + off) & msk, word)    # a GOT entry holding the table's page
                    new = ("c", w) if w is not None else None
            if d == "t9" and m not in ("sw", "sd"):
                t9_written = True
            if new is not None:
                regs[d] = new
            elif d in regs and m not in ("sw", "sh", "sb", "sd", "beqz", "bnez", "beq", "bne", "sltiu"):
                del regs[d]
        target = val(ops_of(jmp)[0]) if jmp.op_str else None
        if not target or target[0] not in ("entry", "gprel"):
            return []
        table, rel = target[1], target[0] == "gprel"
        out = []
        for k in range(bound if bound else 256):
            w = b.read_int((table + word * k) & msk, word)
            if w is None:
                break
            t = (w + gp) & msk if rel else w
            if not b.is_exec(t) or t & 3:
                break
            out.append(t)
        return out if bound is None or len(out) == bound else []

    def _ppc_jump_table(self, jmp: Insn) -> list[int]:
        """gcc's PowerPC switch dispatch, `bctr` after:

            cmplwi rI, N ; bgt default                       the bound
            lis rT, hi ; addi rT, rT, lo                     the table (or `lwz rT, off(r30)` / TOC)
            slwi rI, rI, 2 ; lwzx rE, rT, rI                 (or `add` + `lwz 0(...)`, `lwax`)
            add rE, rE, rT ; mtctr rE ; bctr                 entries are offsets from the table

        Followed with a few symbolic values per register, from the instruction words."""
        b, msk = self.bin, self.dis._mask
        big = b.endian == "big"
        hist = self._back(jmp.addr, 24)[::-1]
        regs: dict[int, tuple] = {}
        lr = None
        ctr = None
        bound = None
        toc = getattr(b, "ppc_toc", None) if b.bits == 64 else None

        def val(r):
            if r == 2 and toc is not None:
                return ("c", toc)
            return regs.get(r)

        def sx(v, n):
            v &= (1 << n) - 1
            return v - (1 << n) if v >> (n - 1) else v

        for i in hist:
            w = int.from_bytes(i.raw, "big" if big else "little")
            op = w >> 26
            rt, ra, rb = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
            simm = sx(w, 16)
            new, dst = None, None
            if op in (14, 15):                                   # addi / addis (li / lis)
                k = simm << 16 if op == 15 else simm
                base = ("c", 0) if ra == 0 else val(ra)
                dst = rt
                if base and base[0] == "c":
                    new = ("c", (base[1] + k) & msk)
            elif op == 24 and rt == ra and (w & 0xFFFF) == 0:
                continue                                         # nop
            elif op == 24:                                       # ori
                dst = ra
                v = val(rt)
                if v and v[0] == "c":
                    new = ("c", v[1] | (w & 0xFFFF))
            elif op == 16 and w & 1 and (w >> 21) & 0x14 == 0x14:
                lr = i.end                                       # bcl 20,31,.+4
                continue
            elif op == 31 and (w >> 1) & 0x3FF == 339 and (ra | rb << 5) == 8:     # mflr
                dst = rt
                new = ("c", lr) if lr is not None else None
            elif op == 31 and (w >> 1) & 0x3FF == 467 and (ra | rb << 5) == 9:     # mtctr
                ctr = val(rt)
                continue
            elif op == 10:                                       # cmplwi / cmpldi
                bound = (w & 0xFFFF) + 1
                continue
            elif op == 21:                                       # rlwinm: slwi 2
                dst = ra
                sh, mb, me = rb, (w >> 6) & 31, (w >> 1) & 31
                if sh == 2 and mb == 0 and me == 29:
                    new = ("scaled", 4)
            elif op == 30 and (w >> 2) & 7 == 1:                 # rldicr: sldi 2 / 3
                dst = ra
                sh = rb | (((w >> 1) & 1) << 5)
                if sh in (2, 3):
                    new = ("scaled", 1 << sh)
            elif op == 31 and (w >> 1) & 0x1FF == 266:           # add
                dst = rt
                x, y = val(ra), val(rb)
                if x and y:
                    kinds = {x[0], y[0]}
                    c = x if x[0] == "c" else y
                    o = y if c is x else x
                    if kinds == {"c", "scaled"}:
                        new = ("elem", c[1], o[1])
                    elif kinds == {"c", "entry"} and o[1] == c[1]:
                        new = ("rel", o[1], o[2])
                    elif kinds == {"c"}:
                        new = ("c", (x[1] + y[1]) & msk)
            elif op == 31 and (w >> 1) & 0x3FF in (23, 341, 21):  # lwzx / lwax / ldx
                dst = rt
                x, y = val(ra), val(rb)
                size = 8 if (w >> 1) & 0x3FF == 21 else 4
                if x and y and {x[0], y[0]} == {"c", "scaled"}:
                    c = x if x[0] == "c" else y
                    new = ("entry", c[1], size, (w >> 1) & 0x3FF == 341)
            elif op == 31 and (w >> 1) & 0x3FF == 986:          # extsw: a signed 32-bit entry
                dst = ra
                v = val(rt)
                new = ("entry", v[1], v[2], True) if v and v[0] == "entry" and v[2] == 4 else None
            elif op == 31 and (w >> 1) & 0x3FF == 444 and rt == rb:              # mr
                dst = ra
                new = val(rt)
            elif op in (32, 58):                                 # lwz / ld / lwa
                dst = rt
                d = simm if op == 32 else sx(w & 0xFFFC, 16)
                size = 4 if op == 32 or w & 3 == 2 else 8
                v = val(ra)
                if v and v[0] == "elem" and d == 0:
                    new = ("entry", v[1], size, op == 58 and w & 3 == 2)
                elif v and v[0] == "c":
                    m = b.read_int((v[1] + d) & msk, size)       # a GOT / TOC word: the table's address
                    new = ("c", m) if m is not None else None
            else:
                continue
            if dst is not None:
                if new is None:
                    regs.pop(dst, None)
                else:
                    regs[dst] = new
        if not ctr or ctr[0] not in ("rel", "entry") or not bound:
            return []
        table = ctr[1]
        size = ctr[2] if ctr[0] == "entry" else 4
        rel = ctr[0] == "rel"
        out = []
        for k in range(bound):
            e = b.read_int((table + size * k) & msk, size)
            if e is None:
                return []
            t = (table + sx(e, size * 8)) & msk if rel else e
            if not b.is_exec(t) or t & 3:
                return []
            out.append(t)
        return out

    def _riscv_jump_table(self, jmp: Insn) -> list[int]:
        """gcc's RISC-V switch dispatch, bounded by a `bltu K, idx` (K in a register) before it:

            auipc a4, hi ; addi a4, a4, lo      table T
            slli a0, a0, 2 ; add a0, a0, a4
            lw a5, 0(a0) ; add a5, a5, a4       entries are offsets from T (PIC)
            jr a5                               (non-PIC: `ld` / RV32 `lw` of absolute addresses)
        """
        b, msk = self.bin, self.dis._mask
        hist = list(reversed(self._back(jmp.addr, 24)))
        consts: dict[str, int] = {}
        table = entry = None
        bound = None
        pic = True
        for i in hist:
            c, m = i.cs, i.mnemonic
            ops = c.operands
            regs = [c.reg_name(o.reg) for o in ops if o.type == 1]
            imm = next((o.imm for o in ops if o.type == 2), None)
            d = regs[0] if regs else None
            new = None
            if m == "auipc" and imm is not None:
                hi = imm & 0xFFFFF
                new = (i.addr + ((hi - (1 << 20) if hi & 0x80000 else hi) << 12)) & msk
            elif m in ("lui", "c.lui") and imm is not None:                 # (non-PIC)
                hi = imm & 0xFFFFF
                new = ((hi - (1 << 20) if hi & 0x80000 else hi) << 12) & msk
            elif m in ("li", "c.li") and imm is not None:
                new = imm & msk
            elif m in ("addi", "c.addi") and imm is not None:
                src = regs[1] if len(regs) > 1 else d
                if src in consts:
                    new = (consts[src] + imm) & msk
            elif m in ("mv", "c.mv") and len(regs) == 2 and regs[1] in consts:
                new = consts[regs[1]]
            elif m in ("bltu", "bgeu") and len(regs) == 2:
                if m == "bltu" and regs[0] in consts:          # K <u idx: the default case
                    bound = consts[regs[0]] + 1
                elif m == "bgeu" and regs[1] in consts:        # idx >=u K
                    bound = consts[regs[1]]
                continue
            elif m in ("lw", "ld", "c.lw", "c.ld"):
                entry = 4 if m.endswith("lw") else 8
                pic = False
            elif m in ("add", "c.add") and entry:
                pic = True                                      # an offset from the table
            if new is not None and d is not None:
                consts[d] = new
                sec = b.section_at(new)
                if sec is not None and not sec.x and sec.name not in (".got", ".got.plt"):
                    table = new
            elif d is not None:
                consts.pop(d, None)
        if table is None or entry is None or not bound or bound > 4096:
            return []
        sec = b.section_at(jmp.addr)
        out = []
        for k in range(bound):
            if entry == 4 and (pic or b.bits == 64):
                v = b.read_int(table + 4 * k, 4, signed=True)
                t = (table + v) & msk if v is not None else None
            else:                                               # absolute addresses
                t = b.read_ptr(table + entry * k)
            if t is None or not (sec and sec.contains(t)):
                return []
            out.append(t)
        return out

    def _jump_table(self, jmp: Insn) -> list[int]:
        """Resolve `jmp reg` / `jmp [table+reg*N]` switch dispatch on x86."""
        if self.dis.arch.startswith("riscv"):
            return self._riscv_jump_table(jmp)
        if self.dis.arch == "arm":
            return self._arm_jump_table(jmp)
        if self.dis.arch == "arm64":
            return self._arm64_jump_table(jmp)
        if self.dis.arch in ("mips", "mips64"):
            return self._mips_jump_table(jmp)
        if self.dis.arch in ("ppc", "ppc64"):
            return self._ppc_jump_table(jmp)
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
        tbl_reg = self._table_reg(hist)
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
                if i.mnemonic == "lea" and i.refs and (tbl_reg is None or (
                        i.cs.operands[0].type == 1 and self._full_reg(i.cs.reg_name(i.cs.operands[0].reg)) == tbl_reg)):
                    base = i.refs[0]            # (the lea of the register the table is read through)
                    break
        if base is None:
            base = self._x86_hoisted_table(jmp, hist)
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
                    width = cmp.cs.operands[0].size * 8
                    v = cmp.cs.operands[-1].imm & ((1 << width) - 1)
                    if i.mnemonic == "jb" and v >> (width - 1):
                        # `cmp x, -5; jb default`: x in [-5, -1], the index `x + 5` (gcc's switch on
                        # negative cases): as many entries as values up to the top
                        count = (1 << width) - v
                    else:
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

    def _x86_hoisted_table(self, jmp: Insn, hist: list[Insn]) -> int | None:
        """A relative table read as `movsxd rax, [R + idx*4]` with R set by `lea R, [rip + table]`
        out of sight of the dispatch (hoisted out of a loop, or kept for several switches): back
        through earlier instructions to R's last write."""
        if self.bin.bits != 64:
            return None
        want = self._table_reg(hist)
        if want is None:
            return None
        back = self._back(jmp.addr, 400)
        found = self._last_lea(back, want)
        if found is None and getattr(self, "_jt_func", None) is not None and 0 < jmp.addr - self._jt_func < 0x8000:
            # the dispatch block is reached by a jump: the function's code in address order (gcc
            # keeps data out of .text), the latest write before the dispatch
            linear, a = [], self._jt_func
            while a < jmp.addr:
                i = self.dis.decode(a)
                if i is None:
                    break
                linear.append(i)
                a = i.end
            if a == jmp.addr:
                found = self._last_lea(list(reversed(linear)), want, calls_kill=False)
        return found or None

    def _table_reg(self, hist: list[Insn]) -> str | None:
        """The register a relative table is read through (`movsxd rax, [R + idx*4]`), as its
        64-bit name, or None."""
        if self.bin.bits != 64:
            return None
        for i in hist:
            if i.mnemonic in ("movsxd", "mov") and len(i.cs.operands) == 2 and i.cs.operands[1].type == 3:
                m = i.cs.operands[1].mem
                if m.base and m.index and m.scale == 4 and not m.disp:
                    reg = i.cs.reg_name(m.base)
                    return None if reg in ("rip", "rsp") else self._full_reg(reg)
        return None

    def _last_lea(self, insns: list[Insn], want: str, calls_kill: bool = True) -> int | None:
        """The table a `lea want, [rip + table]` gives, if that is the latest write to `want` in
        `insns` (newest first); 0 when something else writes it first, None when nothing does."""
        for i in insns:
            try:
                _r, w = i.cs.regs_access()
            except Exception:                   # noqa: BLE001 - capstone cannot always tell
                return 0
            if want in {self._full_reg(i.cs.reg_name(x)) for x in w}:
                if i.mnemonic == "lea" and i.refs:
                    return i.refs[0]
                return 0
            if calls_kill and i.kind == "call" and want in ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
                                                             "r11"):
                return 0                        # (a caller-saved register does not survive a call)
        return None

    @staticmethod
    def _full_reg(name: str) -> str:
        """The 64-bit register a sub-register belongs to (`ebx` -> `rbx`, `r12d` -> `r12`)."""
        if name.startswith("r") and name[1:].rstrip("dwb").isdigit():
            return name.rstrip("dwb") if name[-1] in "dwb" else name
        base = {"al": "ax", "bl": "bx", "cl": "cx", "dl": "dx", "sil": "si", "dil": "di", "bpl": "bp", "spl": "sp"}
        n = base.get(name, name)
        n = n[1:] if n[0] == "e" or n[0] == "r" and len(n) == 3 else n
        return "r" + n

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
            if name is None and i.target in self.funcs:       # (named by a library signature)
                name = self.funcs[i.target].name
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
        """Pick up functions only reachable indirectly (prologue scan: x86, ARM, AArch64, MIPS,
        RISC-V)."""
        if self.dis.arch not in ("x86", "x64", "arm", "arm64", "mips", "mips64", "riscv64", "riscv32", "ppc",
                                 "ppc64"):
            return
        prologues = (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb", b"\x55\x48\x89\xe5", b"\x55\x89\xe5")
        tried: set[int] = set()
        for sec in self.bin.exec_sections:
            if sec.name in (".plt", ".plt.sec", ".plt.got", ".init", ".fini"):
                continue
            # block ranges, not [first, last) of each function: a function's cold blocks
            # (assert paths, .text.unlikely) can lie far away, past other functions
            cover = _Cover()
            for f in self.funcs.values():
                if not f.is_import:
                    cover.add_blocks(f, sec)
            known = set(self.funcs)
            pos = sec.addr
            while True:
                checkpoint()
                gap = cover.next_gap(pos, sec.end)
                if gap is None:
                    break
                s, e = gap
                if self.dis.arch in ("arm", "arm64"):
                    start = self._arm_gap_function(s, e)
                elif self.dis.arch in ("mips", "mips64"):
                    start = self._mips_gap_function(s, e)
                elif self.dis.arch.startswith("riscv"):
                    start = self._riscv_gap_function(s, e)
                elif self.dis.arch in ("ppc", "ppc64"):
                    start = self._ppc_gap_function(s, e)
                else:
                    start = self._gap_function(s, e, prologues)
                if start is None or start in tried:
                    pos = e
                    continue
                tried.add(start)
                self._queue.append(start)
                self._drain()
                # only the functions just found change what is covered; gaps before this one can
                # shrink too (a new function's callees), so scanning resumes from the earliest
                new = [self.funcs[a] for a in set(self.funcs) - known]
                known.update(a for a in self.funcs)
                lo = min((b.addr for f in new if not f.is_import for b in f.blocks.values()
                          if sec.contains(b.addr)), default=s)
                for f in new:
                    if not f.is_import:
                        cover.add_blocks(f, sec)
                pos = max(sec.addr, min(s, lo))

    def _arm_gap_function(self, s: int, e: int) -> int | None:
        """First prologue in [s, e) (an odd result is a Thumb start).

        AArch64: `stp x29, x30, [sp, #-n]!`, `paciasp`, `bti c`. ARM: A32 `push {..., lr}`
        (`stmdb sp!` / `str lr, [sp, #-4]!`), Thumb `push {..., lr}` and Thumb-2 `push.w`.
        Gaps also hold literal pools, tables and unreached code, so a prologue counts only at the
        start of the gap (after padding) or right after an instruction that ends a function.
        """
        arm64 = self.dis.arch == "arm64"
        step = 4 if arm64 else 2
        a = (s + 3) & ~3 if arm64 else (s + 1) & ~1
        at_start = True
        prev_end = False            # the word before ends control flow (ret / b / bx lr / pop {pc})
        while a + 4 <= e:
            w = self.bin.read_int(a, 4)
            if w is None:
                return None
            h = w & 0xFFFF
            if arm64:
                if w == 0 or w == 0xD503201F:                        # padding, nop
                    a += 4
                    continue
                if ((w & 0xFFC07FFF) == 0xA9807BFD or w in (0xD503233F, 0xD503245F, 0xD503249F)) and \
                        (at_start or prev_end):
                    return a
                prev_end = w == 0xD65F03C0 or (w & 0xFC000000) == 0x14000000 or (w & 0xFFFFFC1F) == 0xD61F0000
            else:
                if w == 0 or h == 0xBF00 or w == 0xE1A00000 or w == 0xE320F000:   # padding, nops
                    a += 2 if h in (0, 0xBF00) and w != 0 else 4
                    continue
                if at_start or prev_end:
                    if a % 4 == 0 and ((w & 0xFFFF4000) == 0xE92D4000 or w == 0xE52DE004):
                        return a                                     # A32 push {..., lr}
                    if (h & 0xFF00) == 0xB500 or (h == 0xE92D and (w >> 16) & 0x4000):
                        return a | 1                                 # Thumb push {..., lr}
                # Thumb `bx lr`, `pop {..., pc}`, `b.n`; A32 `bx lr`, `pop {..., pc}`, `b`
                prev_end = h == 0x4770 or (h & 0xFF00) == 0xBD00 or (h & 0xF800) == 0xE000 or \
                    (a % 4 == 0 and (w == 0xE12FFF1E or (w & 0xFFFF8000) == 0xE8BD8000 or
                                     (w & 0x0F000000) == 0x0A000000 and w >> 28 == 0xE))
            at_start = False
            a += step
        return None

    def _riscv_gap_function(self, s: int, e: int) -> int | None:
        """First RISC-V prologue in [s, e): `addi sp, sp, -n` (`c.addi16sp sp, -n`), at the start
        of the gap after padding or right after an instruction that ends a function."""
        a = (s + 1) & ~1
        at_start, prev_end = True, False
        while a + 2 <= e:
            i = self.dis.decode(a)
            if i is None:
                a += 2
                at_start, prev_end = False, False
                continue
            if i.mnemonic in ("nop", "c.nop") or self.bin.read_int(a, 2) == 0:
                a += i.size if i.mnemonic in ("nop", "c.nop") else 2
                continue
            ops = i.cs.operands
            if (at_start or prev_end) and i.mnemonic in ("addi", "c.addi16sp", "c.addi") and ops and \
                    i.cs.reg_name(ops[0].reg) == "sp" and any(o.type == 2 and o.imm < 0 for o in ops):
                return a
            prev_end = i.kind in (RET, JMP)
            at_start = False
            a += i.size
        return None

    def _mips_gap_function(self, s: int, e: int) -> int | None:
        """First prologue in [s, e) past `nop` padding: `addiu $sp, $sp, -n` (a frame) or
        `lui $gp, hi` (PIC: `$gp` from `$t9`, the frame right after)."""
        a = s
        while a < e and self.bin.read_int(a, 4) == 0:
            a += 4
        for _ in range(4):
            if a >= e:
                return None
            i = self.dis.decode(a)
            if i is None:
                return None
            ops = [o.strip() for o in i.op_str.split(",")]
            if i.mnemonic in ("addiu", "daddiu") and ops[:2] == ["$sp", "$sp"] and ops[2].startswith("-"):
                return a
            if i.mnemonic == "lui" and ops[0] == "$gp":
                return a
            if i.kind != "normal" or i.mnemonic != "nop":
                return None
            a = i.end
        return None

    def _ppc_gap_function(self, s: int, e: int) -> int | None:
        """First PowerPC prologue in [s, e) past zero / `nop` padding: `addis r2, r12, hi` (an ELFv2
        global entry), `mflr r0`, `stwu r1, -n(r1)` / `stdu r1, -n(r1)`, or `std rX, -n(r1)`."""
        a = s
        big = self.bin.endian == "big"
        while a + 4 <= e:
            raw = self.bin.read(a, 4)
            if len(raw) < 4:
                return None
            w = int.from_bytes(raw, "big" if big else "little")
            if w in (0, 0x60000000):                         # padding / nop
                a += 4
                continue
            op = w >> 26
            rt, ra = (w >> 21) & 31, (w >> 16) & 31
            if op == 15 and rt == 2 and ra == 12:            # addis r2, r12, hi
                return a
            if w == 0x7C0802A6:                              # mflr r0
                return a
            if op == 37 and rt == 1 and ra == 1 and w & 0x8000:   # stwu r1, -n(r1)
                return a
            if op == 62 and ra == 1 and w & 0x8000 and (w & 3) in (0, 1):    # std / stdu rX, -n(r1)
                return a
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

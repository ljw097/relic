"""Targets of indirect calls through function-pointer variables. x86: `call [rip + slot]`,
`mov rax, [rip + slot]; call rax`, `lea rax, [rip + slot]; call [rax]`; other processors (after
constant propagation gave loads their addresses): a register call (`blr x1`, `blx r3`, `jalr`,
`bctrl`) of a register loaded from the slot (`adrp x20, ...; ldr x1, [x20, #0x10]`).

A slot's possible targets are its initial value and every value the code stores to it
(`lea rcx, [rip + f]; mov [rip + slot], rcx`). The set is complete when every way the code uses
the slot is seen: loads, calls and stores of known functions -- no store of an unknown value and
no address of it handed elsewhere.
"""
from __future__ import annotations

from ..disasm import CALL, Insn


def _ops(i: Insn) -> list[str]:
    return [o.strip() for o in i.op_str.split(",")] if i.op_str else []


def _mem(op: str, addr: dict[str, int]) -> int | None:
    """The address a memory operand (`0x10(s1)`, `[x20, #8]`, `[r3]`) names, from a register
    holding a known address."""
    op = op.strip()
    if op.endswith(")") and "(" in op:
        off, _, base = op[:-1].partition("(")
    elif op.startswith("[") and op.endswith("]"):
        base, _, off = op[1:-1].partition(",")
    else:
        return None
    base, off = base.strip(), off.strip().lstrip("#") or "0"
    if base not in addr:
        return None
    try:
        return addr[base] + int(off, 0)
    except ValueError:
        return None


def _reg(op: str) -> bool:
    return op.isalnum() and not op[:1].isdigit()


class SlotTargets:
    def __init__(self, binary, funcs):
        self.bin = binary
        self.funcs = funcs
        self.sites: dict[int, int] = {}            # call site -> slot
        self.stores: dict[int, set[int]] = {}      # slot -> function addresses stored to it
        self.escaped: set[int] = set()             # slots stored to unknown values / address taken
        self._memo: dict[int, bool] = {}

    def run(self, generic: bool = False) -> dict[int, tuple[frozenset[int], bool]]:
        """call site -> (possible targets, whether that is all of them). x86 during function
        discovery; the other processors (`generic`) once their loads carry addresses."""
        b = self.bin
        x86 = b.arch in ("x64", "x86")
        if x86 == generic:
            return {}
        got = set(getattr(b, "imports_by_got", {}))
        for f in self.funcs.values():
            if f.is_import:
                continue
            if not x86:
                # a block starts with what all its predecessors (seen before it) left in registers
                ends: dict[int, dict] = {}
                for a in sorted(f.blocks):
                    blk = f.blocks[a]
                    ins = [ends.get(p) for p in blk.preds]
                    start = None
                    if ins and all(x is not None for x in ins):   # (what every way in agrees on)
                        start = {k: v for k, v in ins[0].items() if all(x.get(k) == v for x in ins[1:])}
                    ends[a] = self._generic_block(blk.insns, got, start)
                continue
            for blk in f.blocks.values():
                if any(i.kind == CALL and i.target is None or "rip" in i.op_str for i in blk.insns):
                    self._block(blk.insns, got)
        out = {}
        for site, slot in self.sites.items():
            targets = set(self.stores.get(slot, ()))
            init = b.read_ptr(slot)
            if init and b.arch == "arm" and init not in self.funcs:
                init &= ~1                              # (a Thumb function's address)
            complete = slot not in self.escaped
            if init:
                if init in self.funcs:
                    targets.add(init)
                else:
                    complete = False
            if targets:
                out[site] = (frozenset(targets), complete)
        return out

    def _slot(self, a: int, got: set[int]) -> bool:
        v = self._memo.get(a)
        if v is None:
            v = self._memo[a] = self._is_slot(a, got)
        return v

    def _is_slot(self, a: int, got: set[int]) -> bool:
        b = self.bin
        sec = b.section_at(a)
        return a not in got and sec is not None and not b.is_exec(a) and not sec.name.startswith(".got") and \
            (b.is_writable(a) or sec.name.startswith(".data.rel.ro"))

    def _block(self, insns: list[Insn], got: set[int]):
        lea: dict[str, int] = {}         # register -> function address a `lea` put in it (this block)
        slots: dict[str, int] = {}       # register -> slot a `lea` of it put in it, not yet used
        loaded: dict[str, int] = {}      # register -> slot loaded into it

        def deref(op: str) -> str | None:        # `qword ptr [rax]` -> "rax"
            return op.split("[")[-1][:-1] if op.endswith("]") and "+" not in op and "-" not in op else None

        def drop(reg: str):
            for d in (lea, loaded):
                d.pop(reg, None)
            if reg in slots:
                self.escaped.add(slots.pop(reg))     # (its address kept for something unseen)

        for i in insns:
            ops = _ops(i)
            m = i.mnemonic
            rip = [r for r in i.refs if self._slot(r, got)] if "rip" in i.op_str else []
            if i.kind == CALL and i.target is None:
                if i.mem_target is not None and i.mem_target in rip:
                    self.sites[i.addr] = i.mem_target
                elif ops and ops[0] in loaded:
                    self.sites[i.addr] = loaded[ops[0]]
                elif ops and deref(ops[0]) in slots:
                    self.sites[i.addr] = slots.pop(deref(ops[0]))
            if i.kind == CALL:
                for reg in list(slots):
                    drop(reg)
                lea.clear(), loaded.clear()
                continue
            if m == "mov" and len(ops) == 2 and deref(ops[1]) in slots:     # `mov rdx, [rax]`
                r = slots.pop(deref(ops[1]))
                drop(ops[0])
                loaded[ops[0]] = r
                continue
            if m == "mov" and len(ops) == 2 and deref(ops[0]) in slots:     # `mov [rax], rcx`
                self._store(slots.pop(deref(ops[0])), ops[1], lea)
                continue
            for r in rip:
                if m == "lea":
                    drop(ops[0])
                    slots[ops[0]] = r
                elif m == "mov" and len(ops) == 2 and ops[0].endswith("]"):
                    self._store(r, ops[1], lea)
                elif m == "mov" and len(ops) == 2 and _reg(ops[0]):
                    drop(ops[0])
                    loaded[ops[0]] = r
                elif m not in ("cmp", "test"):
                    self.escaped.add(r)
            if rip:
                continue
            if m == "lea" and len(ops) == 2 and i.refs and "rip" in i.op_str and i.refs[0] in self.funcs:
                drop(ops[0])
                lea[ops[0]] = i.refs[0]
                continue
            for op in ops:
                if op in slots:                      # (a slot's address used any other way)
                    self.escaped.add(slots.pop(op))
            if ops and _reg(ops[0]) and m not in ("cmp", "test", "push"):
                drop(ops[0])
        for reg in list(slots):
            drop(reg)

    _LOADS = ("ldr", "ld", "lw", "lwz", "ldur")
    _STORES = ("str", "sd", "sw", "stw", "std", "stur")
    _COPIES = ("mov", "move", "mr", "mv")

    def _generic_block(self, insns: list[Insn], got: set[int], start: dict | None = None) -> dict:
        """ARM, AArch64, MIPS, RISC-V, PowerPC: the first operand is what a load writes and what a
        store stores; a register a function's address was put in (`adrp` + `add`) is known."""
        b = self.bin
        word = b.bits // 8
        mask = (1 << b.bits) - 1
        loaded: dict[str, int] = {}      # register -> slot loaded into it
        faddr: dict[str, int] = {}       # register -> function address in it
        addr: dict[str, int] = dict(start or {})      # register -> other address in it
        toc = getattr(b, "ppc_toc", None)
        if toc is not None:
            addr["r2"] = toc
        for i in insns:
            ops = _ops(i)
            m = i.mnemonic.removeprefix("c.").split(".")[0]
            if i.kind == CALL:
                if i.target is None:
                    reg = "ctr" if m.startswith("bctr") else (ops[-1] if ops else None)
                    if reg in loaded:
                        self.sites[i.addr] = loaded[reg]
                loaded.clear(), faddr.clear()
                continue
            dst = ops[0] if ops else None
            slots = [r for r in i.refs if self._slot(r, got)]
            if not slots and len(ops) >= 2 and (m in self._LOADS or m in self._STORES):
                a = _mem(", ".join(ops[1:]), addr)
                if a is not None and self._slot(a & mask, got):
                    slots = [a & mask]
            if slots and m in self._LOADS and (word == 4 or not dst.startswith("w")):
                loaded[dst] = slots[0]
                faddr.pop(dst, None)
                continue
            if slots and m in self._STORES:
                v = faddr.get(dst)
                if dst in ("xzr", "wzr", "$zero", "zero"):
                    continue                      # (cleared)
                if v is not None:
                    self.stores.setdefault(slots[0], set()).add(v)
                else:
                    self.escaped.add(slots[0])
                continue
            if m in self._COPIES and len(ops) == 2:
                for d in (loaded, faddr):
                    if ops[1] in d:
                        d[dst] = d[ops[1]]
                    else:
                        d.pop(dst, None)
                continue
            if m == "mtctr" and ops:
                for d in (loaded, faddr):
                    if ops[0] in d:
                        d["ctr"] = d[ops[0]]
                continue
            if not dst:
                continue
            fn = next((r & ~1 for r in i.refs if (r & ~1) in self.funcs), None)
            new = None                  # the address this instruction puts in `dst`, if known
            if fn is None and i.refs:
                new = i.refs[0]                          # (an address: of a slot, loaded from later)
            elif fn is None and m in ("lis", "lui") and len(ops) == 2:
                try:
                    new = (int(ops[1], 0) << (12 if b.arch.startswith("riscv") else 16)) & mask
                except ValueError:
                    pass
            elif fn is None and m in ("addis", "addi", "add", "addiu", "daddiu", "ori") and len(ops) == 3 \
                    and ops[1] in addr:
                try:
                    v = int(ops[2].lstrip("#"), 0)
                    new = addr[ops[1]] | v if m == "ori" else (addr[ops[1]] + (v << 16 if m == "addis" else v)) & mask
                except ValueError:
                    pass
            for d in (loaded, faddr, addr):
                d.pop(dst, None)
            if new is not None and (new & ~1) in self.funcs:     # (`lis` + `addi` of a function)
                fn, new = new & ~1, None
            if fn is not None:
                faddr[dst] = fn
            elif new is not None:
                addr[dst] = new
        return addr

    def _store(self, slot: int, value: str, lea: dict[str, int]):
        v = None
        if value in lea:
            v = lea[value]
        elif value[:1].isdigit():
            try:
                v = int(value, 0)
            except ValueError:
                v = None
            if v == 0:
                return                               # (cleared: no call goes through it then)
        if v is not None and v in self.funcs:
            self.stores.setdefault(slot, set()).add(v)
        else:
            self.escaped.add(slot)

"""Targets of indirect calls through function-pointer variables (x86): `call [rip + slot]`,
`mov rax, [rip + slot]; call rax`, `lea rax, [rip + slot]; call [rax]`.

A slot's possible targets are its initial value and every value the code stores to it
(`lea rcx, [rip + f]; mov [rip + slot], rcx`). The set is complete when every way the code uses
the slot is seen: loads, calls and stores of known functions -- no store of an unknown value and
no address of it handed elsewhere.
"""
from __future__ import annotations

from ..disasm import CALL, Insn


def _ops(i: Insn) -> list[str]:
    return [o.strip() for o in i.op_str.split(",")] if i.op_str else []


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

    def run(self) -> dict[int, tuple[frozenset[int], bool]]:
        """call site -> (possible targets, whether that is all of them)."""
        b = self.bin
        if b.arch not in ("x64", "x86"):
            return {}
        got = set(getattr(b, "imports_by_got", {}))
        for f in self.funcs.values():
            if f.is_import:
                continue
            for blk in f.blocks.values():
                if any(i.kind == CALL and i.target is None or "rip" in i.op_str for i in blk.insns):
                    self._block(blk.insns, got)
        out = {}
        for site, slot in self.sites.items():
            targets = set(self.stores.get(slot, ()))
            init = b.read_ptr(slot)
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
        return a not in got and sec is not None and not b.is_exec(a) and \
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

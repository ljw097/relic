"""Stage 3: stack frame reconstruction.

Works out each function's stack layout from its SSA IR: every stack address
is normalised to a signed offset from the frame base (the stack pointer on
entry, so the return address is at offset 0). Slots are classified as the
return address, saved registers, the stack canary, address-taken buffers or
plain locals, and buffers are sized by the distance to the next slot -- the
overflow-to-canary distance a pwnable needs.

This is analysis only; it does not rewrite the IR. `relic opt` prints the
frame summary alongside the listing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .arch import ArchInfo
from .ir import (Assign, BinOp, CallStmt, Const, Expr, IRFunction, Load, Phi, Reg, Return, Store, Var,
                 stmt_exprs, walk)

_CANARY_OFF = 0x28  # glibc thread-pointer offset of the stack guard


def _callee_saved(arch: ArchInfo) -> set[str]:
    if arch.bits == 64:
        return {"rbp", "rbx", "r12", "r13", "r14", "r15"}
    return {"ebp", "ebx", "esi", "edi"}


@dataclass
class Slot:
    offset: int           # signed offset from the entry stack pointer
    size: int = 0         # bytes until the next slot (span of this slot)
    width: int = 0        # widest access seen, in bytes
    taken: bool = False   # its address escaped (passed by pointer)
    kind: str = "local"   # retaddr | saved | canary | buffer | local
    saved_reg: str = ""

    def name(self) -> str:
        if self.kind == "retaddr":
            return "retaddr"
        if self.kind == "saved":
            return f"saved_{self.saved_reg}" if self.saved_reg else "saved"
        if self.kind == "canary":
            return "canary"
        # above the return address: the caller's argument area (stack parameters, Win64 home
        # slots). A distinct prefix keeps +8 and -8 from sharing the name `var_8`
        if self.offset > 0:
            return f"arg_{self.offset:x}"
        tag = "buf" if self.kind == "buffer" else "var"
        return f"{tag}_{abs(self.offset):x}"


@dataclass
class Frame:
    arch: ArchInfo
    spoff: dict[Var, int] = field(default_factory=dict)   # sp-derived var -> offset from entry sp
    slots: dict[int, Slot] = field(default_factory=dict)
    canary: int | None = None
    realigned: bool = False   # `and esp, -16` seen: offsets below it are approximate

    def offset_of(self, e: Expr) -> int | None:
        """Signed frame offset if `e` is a stack address, else None."""
        if isinstance(e, Var):
            return self.spoff.get(e)
        if isinstance(e, BinOp) and e.op == "&" and isinstance(e.b, Const) and e.b.signed < 0 \
                and (-e.b.signed) & (-e.b.signed - 1) == 0:
            # stack realignment (`and esp, -16`, 32-bit main): the padding it adds is unknown
            # (0..15 bytes); count it as none so the frame stays analysable
            base = self.offset_of(e.a)
            if base is not None:
                self.realigned = True
            return base
        if isinstance(e, BinOp) and e.op in ("+", "-"):
            if isinstance(e.b, Const):
                base = self.offset_of(e.a)
                if base is not None:
                    return base + (e.b.signed if e.op == "+" else -e.b.signed)
            if e.op == "+" and isinstance(e.a, Const):
                base = self.offset_of(e.b)
                if base is not None:
                    return base + e.a.signed
        return None

    def name_at(self, off: int) -> str | None:
        s = self.slots.get(off)
        return s.name() if s else None

    def locals(self) -> list[Slot]:
        """Slots below the saved registers, lowest address first (what a listing shows)."""
        return [s for _, s in sorted(self.slots.items()) if s.kind in ("local", "buffer", "canary")]

    def buffers(self) -> list[Slot]:
        return [s for s in self.locals() if s.kind == "buffer"]


def _is_canary(e: Expr) -> bool:
    # fs_base/gs_base starts as a Reg and becomes a Var once the IR is in SSA form
    return any(isinstance(n, (Reg, Var)) and n.name in ("fs_base", "gs_base") for n in walk(e))


def _build_spoff(fn: IRFunction, arch: ArchInfo) -> dict[Var, int]:
    return build_frame(fn, arch).spoff


def build_frame(fn: IRFunction, arch: ArchInfo) -> Frame:
    """A frame with every stack-pointer-derived variable's offset (no slots yet)."""
    spoff: dict[Var, int] = {}
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Var) and x.name == arch.sp and x.version == 0:
                    spoff[x] = 0
    frame = Frame(arch, spoff)
    changed = True
    while changed:
        changed = False
        for s in fn.stmts():
            if isinstance(s, Assign) and isinstance(s.dst, Var) and s.dst not in spoff:
                if isinstance(s.src, Phi):
                    # the stack pointer merged at a join (loop header): balanced paths agree.
                    # Optimistic -- a source still unknown (computed from this phi around the
                    # loop) is assumed to agree with the known ones
                    offs = {frame.offset_of(v) for _, v in s.src.sources} - {None}
                    off = offs.pop() if len(offs) == 1 else None
                else:
                    off = frame.offset_of(s.src)
                if off is not None:
                    spoff[s.dst] = off
                    changed = True
    return frame


def _frame_bookkeeping(frame: Frame, value: Expr) -> bool:
    """The return address, or a pointer into the caller's frame (the incoming stack pointer)."""
    if isinstance(value, Load) and frame.offset_of(value.addr) == 0:
        return True
    off = frame.offset_of(value)
    return off is not None and off > 0


def analyze_frame(fn: IRFunction, arch: ArchInfo) -> Frame:
    frame = build_frame(fn, arch)
    realign_entry = frame.realigned
    saved = _callee_saved(arch)

    def slot(off: int) -> Slot:
        return frame.slots.setdefault(off, Slot(off))

    frame.slots[0] = Slot(0, size=arch.bits // 8, width=arch.bits // 8, kind="retaddr")

    for s in fn.stmts():
        # dereferences: Load / Store addresses are real accesses (not address-taken)
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Load):
                    off = frame.offset_of(x.addr)
                    if off is not None:
                        slot(off).width = max(slot(off).width, x.bits // 8)
        if isinstance(s, Store):
            off = frame.offset_of(s.dst)
            if off is not None:
                sl = slot(off)
                sl.width = max(sl.width, s.bits // 8)
                if _is_canary(s.src):
                    sl.kind, frame.canary = "canary", off
                elif isinstance(s.src, Var) and s.src.version == 0 and s.src.name in saved and sl.kind == "local":
                    sl.kind, sl.saved_reg = "saved", s.src.name
                elif realign_entry and sl.kind == "local" and _frame_bookkeeping(frame, s.src):
                    # realigning prologue: keeps a copy of the return address and of the
                    # incoming stack pointer (`push [ecx-4]`, `push ecx`)
                    sl.kind, sl.saved_reg = "saved", "frame"
        # escaping addresses: call arguments, stored pointers, returned pointers
        escaped: list[Expr] = []
        if isinstance(s, CallStmt):
            escaped += list(s.call.args)
        elif isinstance(s, Store):
            escaped.append(s.src)
        elif isinstance(s, Return) and s.value is not None:
            escaped.append(s.value)
        elif isinstance(s, Assign) and s.dst not in frame.spoff:
            escaped.append(s.src)
        for e in escaped:
            off = frame.offset_of(e)
            if off is not None:
                slot(off).taken = True

    # size each slot by the distance to the next slot above it; classify leftovers
    offs = sorted(frame.slots)
    for i, off in enumerate(offs):
        sl = frame.slots[off]
        sl.size = (offs[i + 1] - off) if i + 1 < len(offs) else sl.width
        # an address-taken slot larger than a single scalar access (or accessed as bytes)
        # is a buffer; a taken 4/8-byte scalar (e.g. &choice for scanf("%d", ...)) is not
        if sl.kind == "local" and sl.taken and (sl.size > sl.width or sl.width <= 1):
            sl.kind = "buffer"
    return frame


__all__ = ["Frame", "Slot", "analyze_frame"]

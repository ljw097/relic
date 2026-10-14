"""Which registers a call can really change (interprocedural register allocation).

The calling convention says a call may overwrite every caller-saved
register, and the decompiler assumes so by default. gcc's `-fipa-ra`
(default at -O2) knows better for functions in the same unit: if `gcd`
never touches `w3`, the caller keeps a live value in `w3` across `bl gcd`.
Treating `w3` as clobbered there loses that value -- the pseudocode reads an
undefined variable.

So for a call to a function of this binary the clobber set is what the
callee (transitively) writes: its own instructions' written registers plus
those of the functions it calls or tail-calls, solved to a fixpoint for
recursion. Anything not provable keeps the full calling-convention set:
imports, indirect calls, unresolved indirect jumps, system calls, or an
instruction whose register access capstone cannot report.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..disasm import CALL, JMP

if TYPE_CHECKING:
    from ..analysis import Analysis

_FLAGS = frozenset(("zf", "cf", "sf", "of", "pf"))
_UNKNOWN = None


def _canon_x86(bits: int):
    from .lift.x86 import _reg_table
    table = _reg_table(bits)

    def canon(name: str) -> tuple[str, ...]:
        if name in table:
            return (table[name][0],)
        if name in ("rflags", "eflags", "flags"):
            return tuple(_FLAGS)
        if name.startswith(("ymm", "zmm")):
            return ("xmm" + name[3:],)
        return (name,)
    return canon


def _canon_arm64():
    from .lift.arm64 import _REGS

    def canon(name: str) -> tuple[str, ...]:
        if name in _REGS:
            return (_REGS[name][0],)
        if name == "nzcv":
            return ("zf", "cf", "sf", "of")
        return (name,)
    return canon


def _canon_arm():
    from .lift.arm import ArmLifter

    def canon(name: str) -> tuple[str, ...]:
        if name in ("cpsr", "apsr", "apsr_nzcv", "spsr"):
            return ("zf", "cf", "sf", "of")
        return (ArmLifter.canon(name),)
    return canon


def _canon_for(an: "Analysis"):
    arch = an.bin.arch
    if arch in ("x86", "x64"):
        return _canon_x86(an.bin.bits)
    if arch == "arm64":
        return _canon_arm64()
    if arch == "arm":
        return _canon_arm()
    return None


_SYSCALLS = {"syscall", "sysenter", "int", "svc", "swi", "hvc", "smc"}


def _own_writes(an: "Analysis", f, canon):
    """(registers f's instructions write, callees whose writes add to them) or None if unknown."""
    regs: set[str] = set()
    callees: set[int] = set(f.tail_calls)
    for blk in f.blocks.values():
        for i in blk.insns:
            if i.mnemonic in _SYSCALLS or i.cs is None:
                return None
            try:
                _, written = i.cs.regs_access()
            except Exception:                       # noqa: BLE001 - capstone cannot tell
                return None
            for r in written:
                regs.update(canon(i.cs.reg_name(r)))
            if i.kind == CALL:
                if i.target is None:
                    return None                     # indirect call: anything
                callees.add(i.target)
            elif i.kind == JMP and i.target is None and i.addr not in f.jump_tables:
                return None                         # unresolved indirect jump (tail call?)
    return regs, callees


def callee_clobbers(an: "Analysis", addr: int) -> frozenset[str] | None:
    """Registers a call to the function at `addr` may change, or None for "the whole ABI set"."""
    cache = an.__dict__.setdefault("_clobbers", {})
    if addr in cache:
        return cache[addr]
    canon = _canon_for(an)
    if canon is None:
        return None
    # collect the call graph reachable from `addr`
    own: dict[int, tuple[set, set] | None] = {}
    work = [addr]
    while work:
        a = work.pop()
        if a in own:
            continue
        f = an.functions.get(a)
        if a in cache:
            own[a] = None if cache[a] is None else (set(cache[a]), set())
            continue
        if f is None or f.is_import or not f.blocks:
            own[a] = None
            continue
        own[a] = _own_writes(an, f, canon)
        if own[a] is not None:
            work.extend(own[a][1])
    # unknown spreads to every caller; the rest is a union fixpoint over the call graph
    unknown = {a for a, v in own.items() if v is None}
    changed = True
    while changed:
        changed = False
        for a, v in own.items():
            if a not in unknown and v is not None and v[1] & unknown:
                unknown.add(a)
                changed = True
    regs = {a: set(v[0]) for a, v in own.items() if a not in unknown}
    changed = True
    while changed:
        changed = False
        for a in regs:
            for c in own[a][1]:
                if c in regs and not regs[c] <= regs[a]:
                    regs[a] |= regs[c]
                    changed = True
    for a in own:
        if a not in cache:
            cache[a] = None if a in unknown else frozenset(regs[a])
    return cache[addr]


__all__ = ["callee_clobbers"]

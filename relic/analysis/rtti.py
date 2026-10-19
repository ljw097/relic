"""C++ classes from Itanium RTTI (gcc, clang: ELF), stripped binaries included.

A class's `typeinfo` object starts with a pointer into one of libstdc++'s typeinfo vtables -- the
dynamic relocation naming `__class_type_info` (no bases), `__si_class_type_info` (one base) or
`__vmi_class_type_info` (several) -- followed by its mangled name and its bases. A vtable is the
offset to the top of the object, the typeinfo, then the virtual methods; classes with several
bases have one per base, one after the other.

Found: classes with their bases, vtables and virtual methods; names `typeinfo for X`,
`vtable for X` and `X::vfuncN` (methods without a name of their own).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..demangle import demangle
from ..loader.base import Symbol

_KINDS = {"_ZTVN10__cxxabiv117__class_type_infoE": "class", "_ZTVN10__cxxabiv120__si_class_type_infoE": "si",
          "_ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi"}
_PURE = ("__cxa_pure_virtual", "__cxa_deleted_virtual")


@dataclass
class VTable:
    addr: int                    # its address point: the first virtual method's slot
    offset: int                  # offset to the top of the object (0 for the primary one)
    slots: list[int] = field(default_factory=list)      # method addresses (0: pure virtual)


@dataclass
class CppClass:
    name: str
    typeinfo: int
    bases: list[str] = field(default_factory=list)
    vtables: list[VTable] = field(default_factory=list)


def recover_classes(an, finder=None) -> dict[str, CppClass]:
    b = an.bin
    if b.format != "ELF":
        return {}
    ptr = b.bits // 8
    kinds: dict[int, str] = {}
    pure: set[int] = set()
    for r in getattr(b, "relocs", ()):
        k = _KINDS.get(r.name)
        if k is not None:
            kinds[r.addr] = k
        elif r.name in _PURE:
            pure.add(r.addr)
    if not kinds:
        return {}
    by_ti: dict[int, CppClass] = {}
    inside: set[int] = set()                 # words of typeinfo objects (not vtable candidates)
    for ti, kind in kinds.items():
        mangled = b.read_cstring(b.read_ptr(ti + ptr) or 0)
        if not mangled:
            continue
        name = (demangle("_ZTS" + mangled) or "").removeprefix("typeinfo name for ") or mangled
        by_ti[ti] = CppClass(name, ti)
        size = 2 * ptr
        if kind == "si":
            size = 3 * ptr
        elif kind == "vmi":
            size = 2 * ptr + 8 + 2 * ptr * (b.read_int(ti + 2 * ptr + 4, 4) or 0)
        inside.update(range(ti, ti + size, 4))
    for ti, kind in kinds.items():
        c = by_ti.get(ti)
        if c is None:
            continue
        if kind == "si":
            bases = [b.read_ptr(ti + 2 * ptr)]
        elif kind == "vmi":
            n = b.read_int(ti + 2 * ptr + 4, 4) or 0
            bases = [b.read_ptr(ti + 2 * ptr + 8 + 2 * ptr * k) for k in range(min(n, 64))]
        else:
            bases = []
        c.bases = [by_ti[t].name if t in by_ti else _external(b, t) for t in bases if t]
    _vtables(an, by_ti, inside, pure, ptr)
    classes = {c.name: c for c in by_ti.values()}
    _name(an, classes, finder, ptr)
    return classes


def _external(b, ti: int) -> str:
    """A base class whose typeinfo lives in a library: the name of the symbol its pointer binds."""
    for r in getattr(b, "relocs", ()):
        if r.addr == ti and r.name.startswith("_ZTI"):
            return (demangle(r.name) or r.name).removeprefix("typeinfo for ")
    return f"class_{ti:x}"


def _vtables(an, by_ti: dict[int, CppClass], inside: set[int], pure: set[int], ptr: int):
    b = an.bin
    lim = 1 << (b.bits - 1)
    for sec in b.sections:
        if not sec.loaded or sec.x or sec.size == 0 or not (sec.name.startswith(".data") or sec.name == ".rodata"):
            continue
        a = sec.addr + ptr
        a += -a % ptr
        while a + ptr <= sec.end:
            ti = b.read_ptr(a)
            if ti not in by_ti or a in inside:
                a += ptr
                continue
            off = b.read_ptr(a - ptr) or 0
            off = off - (1 << b.bits) if off >= lim else off
            if off > 0 or off < -0x100000 or off % ptr:
                a += ptr
                continue
            vt = VTable(a + ptr, off)
            s = a + ptr
            while s + ptr <= sec.end:
                v = b.read_ptr(s) or 0
                if s in pure:
                    vt.slots.append(0)
                elif v and b.is_exec(v & ~1):
                    vt.slots.append(v)
                else:
                    break
                s += ptr
            by_ti[ti].vtables.append(vt)
            a = s


def _ancestors(name: str, classes: dict[str, CppClass], seen=None) -> set[str]:
    seen = set() if seen is None else seen
    if name in seen:
        return seen
    seen.add(name)
    for n in classes[name].bases if name in classes else ():
        _ancestors(n, classes, seen)
    return seen


def _depth(name: str, classes: dict[str, CppClass]) -> int:
    return len(_ancestors(name, classes))


def _name(an, classes: dict[str, CppClass], finder, ptr: int):
    b = an.bin

    def symbol(name: str, addr: int, size: int):
        if b.symbols.get(addr) is None:
            b.add_symbol(Symbol(name, addr, size, "object", "rtti"))
            b.name_to_addr.setdefault(name, addr)

    users: dict[int, list[tuple[str, int, int]]] = {}       # method -> (class, slot, vtable offset)
    for c in classes.values():
        symbol(f"typeinfo for {c.name}", c.typeinfo, 0)
        for vt in c.vtables:
            if vt.offset == 0:
                symbol(f"vtable for {c.name}", vt.addr - 2 * ptr, (len(vt.slots) + 2) * ptr)
            for k, m in enumerate(vt.slots):
                if m:
                    users.setdefault(m, []).append((c.name, k, vt.offset))
    for m, us in users.items():
        f = an.functions.get(m & ~1)
        if f is None and finder is not None:
            f = an.functions.get(finder.add_function(m))
        if f is None or not f.name.startswith("sub_"):
            continue
        # a method several classes share: named after the nearest class they all derive from
        common = set.intersection(*(_ancestors(n, classes) for n, _, _ in us))
        owner = max(common, key=lambda n: _depth(n, classes)) if common else us[0][0]
        _, k, off = next((u for u in us if u[0] == owner), us[0])
        f.name = f"{owner}::vfunc{k}" if off == 0 else f"{owner}::thunk{-off}_vfunc{k}"
        b.add_symbol(Symbol(f.name, f.addr, 0, "func", "rtti"), override=True)
        b.name_to_addr.setdefault(f.name, f.addr)


def virtual_calls(an, classes: dict[str, CppClass]) -> dict[int, tuple[frozenset[int], bool]]:
    """x86: calls of a virtual method through `this` in a virtual method (`mov rax, [rdi];
    call [rax + 0x10]`): the method in that slot of its class and of every class derived from it."""
    b = an.bin
    if b.arch not in ("x64", "x86") or not classes:
        return {}
    ptr = b.bits // 8
    this = "rdi" if b.arch == "x64" else None
    if this is None:
        return {}
    derived: dict[str, set[str]] = {n: set() for n in classes}
    for n in classes:
        for a in _ancestors(n, classes):
            if a in derived:
                derived[a].add(n)
    owners: dict[int, set[str]] = {}            # method -> classes with it in their primary vtable
    for c in classes.values():
        for vt in c.vtables:
            if vt.offset == 0:
                for m in vt.slots:
                    if m:
                        owners.setdefault(m, set()).add(c.name)
    out = {}
    for m, cls in owners.items():
        f = an.functions.get(m)
        if f is None:
            continue
        family = set().union(*(derived[n] for n in cls))
        for site, slot in _this_calls(f, this, ptr):
            targets = set()
            for n in family:
                vt = next((v for v in classes[n].vtables if v.offset == 0), None)
                if vt is not None and slot < len(vt.slots) and vt.slots[slot]:
                    targets.add(vt.slots[slot])
            if targets:
                out[site] = (frozenset(targets), False)
    return out


def _this_calls(f, this: str, ptr: int):
    """(call site, vtable slot) of the calls through `this`'s vtable: `this` (and registers only
    ever copied from it) never written in `f`."""
    insns = [i for blk in f.blocks.values() for i in blk.insns]
    writes: dict[str, list] = {}
    for i in insns:
        ops = [o.strip() for o in i.op_str.split(",")] if i.op_str else []
        if ops and ops[0].isalnum() and i.mnemonic not in ("cmp", "test", "push", "call", "pop"):
            writes.setdefault(ops[0], []).append((i.mnemonic, ops[1] if len(ops) > 1 else ""))
    if this in writes:
        return []
    regs = {this} | {r for r, w in writes.items() if all(m == "mov" and src == this for m, src in w)}
    out = []
    for blk in f.blocks.values():
        vptr: dict[str, bool] = {}
        slot_in: dict[str, int] = {}
        for i in blk.insns:
            ops = [o.strip() for o in i.op_str.split(",")] if i.op_str else []
            mem = ops[-1].split("[")[-1][:-1] if ops and ops[-1].endswith("]") else None
            if i.mnemonic == "call" and i.target is None and ops:
                if mem is not None:
                    base, _, disp = mem.partition(" + ")
                    if base in vptr and (disp == "" or disp[:1].isdigit()):
                        out.append((i.addr, (int(disp, 0) if disp else 0) // ptr))
                elif ops[0] in slot_in:
                    out.append((i.addr, slot_in[ops[0]]))
                vptr.clear(), slot_in.clear()
                continue
            if i.mnemonic == "mov" and len(ops) == 2 and ops[0].isalnum() and mem is not None:
                base, _, disp = mem.partition(" + ")
                if base in regs and disp == "":
                    vptr[ops[0]] = True
                    slot_in.pop(ops[0], None)
                    continue
                if base in vptr and (disp == "" or disp[:1].isdigit()):
                    slot_in[ops[0]] = (int(disp, 0) if disp else 0) // ptr
                    vptr.pop(ops[0], None)
                    continue
            if ops and ops[0].isalnum():
                vptr.pop(ops[0], None)
                slot_in.pop(ops[0], None)
    return out

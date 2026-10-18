"""Objective-C 2 runtime metadata in a Mach-O image (64-bit): classes, their methods, ivars and
properties, categories, and the selector / class references code loads.

Every method implementation is named the way the runtime prints it, `-[Animal speak:times:]` /
`+[Animal new]`; a selector reference (`__objc_selrefs` slot) is named `selRef_<selector>`, a class
reference `classRef_<Class>`. Method lists come in two layouts: three pointers per method, or
(`entsize` flag 0x80000000) three 32-bit offsets relative to each field, the name one pointing at
a selector reference.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .base import Binary, Symbol

FAST_DATA_MASK = 0x00007FFFFFFFFFF8
_PTR_MASK = 0x0000FFFFFFFFFFFF          # (tagged / authenticated pointer bits above)
RELATIVE_METHODS = 0x80000000


@dataclass
class ObjcMethod:
    name: str
    types: str
    imp: int
    meta: bool = False                  # a class method (`+`)


@dataclass
class ObjcClass:
    name: str
    addr: int
    superclass: str = ""
    methods: list[ObjcMethod] = field(default_factory=list)
    ivars: list[tuple[str, str, int]] = field(default_factory=list)       # (name, type, offset)
    properties: list[tuple[str, str]] = field(default_factory=list)       # (name, attributes)
    category: str = ""                  # for a category: its name (`addr` is the category_t)


@dataclass
class ObjcInfo:
    classes: list[ObjcClass] = field(default_factory=list)
    selrefs: dict[int, str] = field(default_factory=dict)        # selector reference -> selector
    classrefs: dict[int, str] = field(default_factory=dict)      # class reference -> class name
    ivar_slots: dict[int, tuple[str, str]] = field(default_factory=dict)   # ivar offset word -> (class, ivar)


def _ptr(b: Binary, addr: int) -> int:
    v = b.read_ptr(addr)
    return (v or 0) & _PTR_MASK


def _str(b: Binary, addr: int) -> str:
    return (b.read_cstring(addr) or "") if addr else ""


def _class_name(b: Binary, cls: int, names_by_addr: dict[int, str]) -> str:
    """A class_t's name, or the import it is bound to (`OBJC_CLASS_$_NSObject` -> NSObject)."""
    if not cls:
        return ""
    if cls in names_by_addr:
        return names_by_addr[cls]
    ro = _ptr(b, cls + 32) & FAST_DATA_MASK
    return _str(b, _ptr(b, ro + 24)) if ro else ""


def _bound_class(b: Binary, slot: int) -> str:
    """The class an imported reference names (`_OBJC_CLASS_$_NSObject` bound at `slot`)."""
    name = getattr(b, "got_names", {}).get(slot, "") or ""
    for prefix in ("OBJC_CLASS_$_", "_OBJC_CLASS_$_", "OBJC_METACLASS_$_", "_OBJC_METACLASS_$_"):
        if name.startswith(prefix):
            return name[len(prefix):]
    return ""


def _methods(b: Binary, lst: int, meta: bool) -> list[ObjcMethod]:
    if not lst:
        return []
    raw = b.read(lst, 8)
    if len(raw) < 8:
        return []
    flags, count = struct.unpack("<II", raw)
    out = []
    if flags & RELATIVE_METHODS:
        size = flags & 0xFFFC or 12
        for k in range(min(count, 10000)):
            e = lst + 8 + k * size
            rel = b.read(e, 12)
            if len(rel) < 12:
                break
            name_off, types_off, imp_off = struct.unpack("<iii", rel)
            # the name field points at a selector reference (unless the list is in the shared cache)
            name = _str(b, _ptr(b, e + name_off))
            out.append(ObjcMethod(name, _str(b, e + 4 + types_off), (e + 8 + imp_off) & _PTR_MASK, meta))
    else:
        size = flags & 0xFFFC or 24
        for k in range(min(count, 10000)):
            e = lst + 8 + k * size
            out.append(ObjcMethod(_str(b, _ptr(b, e)), _str(b, _ptr(b, e + 8)), _ptr(b, e + 16), meta))
    return out


def _ivar_slots(b: Binary, lst: int) -> list[int]:
    """Where each ivar's offset word is (code reads the offset from there: it can slide)."""
    if not lst:
        return []
    raw = b.read(lst, 8)
    if len(raw) < 8:
        return []
    size, count = struct.unpack("<II", raw)
    return [_ptr(b, lst + 8 + k * (size or 32)) for k in range(min(count, 10000))]


def _ivars(b: Binary, lst: int) -> list[tuple[str, str, int]]:
    if not lst:
        return []
    raw = b.read(lst, 8)
    if len(raw) < 8:
        return []
    size, count = struct.unpack("<II", raw)
    size = size or 32
    out = []
    for k in range(min(count, 10000)):
        e = lst + 8 + k * size
        off_ptr = _ptr(b, e)
        off = b.read_int(off_ptr, 4) if off_ptr else None
        out.append((_str(b, _ptr(b, e + 8)), _str(b, _ptr(b, e + 16)), off if off is not None else -1))
    return out


def _properties(b: Binary, lst: int) -> list[tuple[str, str]]:
    if not lst:
        return []
    raw = b.read(lst, 8)
    if len(raw) < 8:
        return []
    size, count = struct.unpack("<II", raw)
    size = size or 16
    return [(_str(b, _ptr(b, lst + 8 + k * size)), _str(b, _ptr(b, lst + 16 + k * size)))
            for k in range(min(count, 10000))]


def parse_objc(b: Binary) -> ObjcInfo | None:
    """The image's Objective-C metadata (64-bit Mach-O), or None when it has none."""
    if b.bits != 64 or b.format != "Mach-O":
        return None
    secs = {s.name: s for s in b.sections}
    if not any(n in secs for n in ("__objc_classlist", "__objc_catlist", "__objc_selrefs")):
        return None
    info = ObjcInfo()
    names_by_addr: dict[int, str] = {}
    classlist = secs.get("__objc_classlist")
    cls_addrs = [_ptr(b, classlist.addr + 8 * k) for k in range(classlist.size // 8)] if classlist else []
    for cls in cls_addrs:
        ro = _ptr(b, cls + 32) & FAST_DATA_MASK
        if ro:
            names_by_addr[cls] = _str(b, _ptr(b, ro + 24))
    for cls in cls_addrs:
        ro = _ptr(b, cls + 32) & FAST_DATA_MASK
        if not ro:
            continue
        c = ObjcClass(names_by_addr.get(cls, ""), cls)
        sup = _ptr(b, cls + 8)
        c.superclass = _class_name(b, sup, names_by_addr) if sup else _bound_class(b, cls + 8)
        c.methods = _methods(b, _ptr(b, ro + 32), False)
        c.ivars = _ivars(b, _ptr(b, ro + 48))
        for slot, (iname, _t, _o) in zip(_ivar_slots(b, _ptr(b, ro + 48)), c.ivars):
            if slot:
                info.ivar_slots[slot] = (c.name, iname)
        c.properties = _properties(b, _ptr(b, ro + 64))
        meta = _ptr(b, cls)
        mro = _ptr(b, meta + 32) & FAST_DATA_MASK if meta else 0
        if mro:
            c.methods += _methods(b, _ptr(b, mro + 32), True)
        info.classes.append(c)
    catlist = secs.get("__objc_catlist")
    for k in range(catlist.size // 8 if catlist else 0):
        cat = _ptr(b, catlist.addr + 8 * k)
        if not cat:
            continue
        cls = _ptr(b, cat + 8)
        owner = _class_name(b, cls, names_by_addr) if cls else _bound_class(b, cat + 8)
        c = ObjcClass(owner, cat, category=_str(b, _ptr(b, cat)))
        c.methods = _methods(b, _ptr(b, cat + 16), False) + _methods(b, _ptr(b, cat + 24), True)
        c.properties = _properties(b, _ptr(b, cat + 40))
        info.classes.append(c)
    sel = secs.get("__objc_selrefs")
    for k in range(sel.size // 8 if sel else 0):
        slot = sel.addr + 8 * k
        name = _str(b, _ptr(b, slot))
        if name:
            info.selrefs[slot] = name
    for sname in ("__objc_classrefs", "__objc_superrefs"):
        sec = secs.get(sname)
        for k in range(sec.size // 8 if sec else 0):
            slot = sec.addr + 8 * k
            target = _ptr(b, slot)
            name = _class_name(b, target, names_by_addr) if target else _bound_class(b, slot)
            if name:
                info.classrefs[slot] = name
    return info


def name_objc(b: Binary, info: ObjcInfo) -> None:
    """Symbols for the metadata: method implementations, selector and class references."""
    b.objc_types = {}                       # implementation -> type encoding (`v24@0:8*16i20`)
    for c in info.classes:
        owner = f"{c.name}({c.category})" if c.category else c.name
        for m in c.methods:
            if m.imp and b.is_exec(m.imp):
                b.objc_types[m.imp] = m.types
                b.add_symbol(Symbol(f"{'+' if m.meta else '-'}[{owner} {m.name}]", m.imp, 0, "func", "objc"),
                             override=True)
    for slot, s in info.selrefs.items():
        b.add_symbol(Symbol(f"selRef_{s}", slot, 8, "object", "objc"), override=True)
    for slot, s in info.classrefs.items():
        b.add_symbol(Symbol(f"classRef_{s}", slot, 8, "object", "objc"), override=True)


__all__ = ["ObjcClass", "ObjcInfo", "ObjcMethod", "name_objc", "parse_objc"]

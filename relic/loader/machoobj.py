"""Mach-O relocatable objects (`MH_OBJECT`, clang's `.o`): the sections, already laid out one after
another from 0, are placed from `BASE`; every undefined symbol gets a stub (a call's target, the
import's address) and a GOT slot, and the relocations are applied so that code reads as it would
once linked. x86-64 and arm64."""
from __future__ import annotations

import struct

from .base import Binary, Import, Relocation, Section, Segment, Symbol
from .elfobj import BASE, STUB, _align

N_STAB, N_TYPE, N_EXT, N_SECT, N_UNDF = 0xE0, 0x0E, 0x01, 0x0E, 0x0

# x86-64 relocation types
X86_UNSIGNED, X86_SIGNED, X86_BRANCH, X86_GOT_LOAD, X86_GOT = 0, 1, 2, 3, 4
X86_SIGNED_N = (6, 7, 8)
# arm64 relocation types
A64_UNSIGNED, A64_BRANCH26, A64_PAGE21, A64_PAGEOFF12 = 0, 2, 3, 4
A64_GOT_PAGE21, A64_GOT_PAGEOFF12, A64_ADDEND = 5, 6, 10

_STUB_CODE = {"x64": b"\xc3", "arm64": (0xD65F03C0).to_bytes(4, "little")}       # ret


def _temporary(name: str) -> bool:
    """Assembler-local labels (`ltmp0`, `l_.str`, `L_.str`): relocation targets, not names."""
    return name.startswith(("ltmp", "l_", "L"))


def load_macho_object(b: Binary, data: bytes, end: str, is64: bool, secs: list, symtab) -> None:
    # 1. layout: the object's own section addresses, moved to BASE
    for sec, *_ in secs:
        sec.addr += BASE
    top = max((s.addr + s.size for s, *_ in secs), default=BASE)
    # 2. symbols: defined ones at their (moved) address, undefined ones get a stub and a GOT slot
    entries = _nlist(data, end, is64, symtab)
    externs: dict[str, int] = {}
    commons: dict[str, int] = {}
    for raw, ntype, _nsect, _desc, value in entries:
        if ntype & N_STAB or (ntype & N_TYPE) != N_UNDF or not raw:
            continue
        if value:                                  # a common symbol: `value` is its size
            commons[raw] = value
        else:
            externs.setdefault(raw, 0)
    ext_start = _align(top, 16)
    for k, raw in enumerate(externs):
        externs[raw] = ext_start + k * STUB
    got_start = _align(ext_start + len(externs) * STUB, 16)
    word = 8 if is64 else 4
    got: dict[str, int] = {}
    cstart = _align(got_start + (len(externs) + len(entries)) * word, 16)
    pos = cstart
    for raw, size in commons.items():
        commons[raw] = pos
        pos = _align(pos + size, 16)
    image = bytearray(pos - BASE)
    for sec, *_ in secs:
        if sec.loaded and sec.size:
            image[sec.addr - BASE:sec.addr - BASE + sec.size] = data[sec.offset:sec.offset + sec.size]
    stub = _STUB_CODE.get(b.arch, b"")
    for a in externs.values():
        image[a - BASE:a - BASE + len(stub)] = stub

    def sym_addr(idx: int) -> int:
        raw, ntype, nsect, _desc, value = entries[idx]
        if (ntype & N_TYPE) == N_SECT and 0 < nsect <= len(secs):
            return value + BASE
        return externs.get(raw) or commons.get(raw, 0)

    def got_slot(idx: int) -> int:
        raw = entries[idx][0]
        if raw not in got:
            got[raw] = got_start + len(got) * word
            target = sym_addr(idx)
            image[got[raw] - BASE:got[raw] - BASE + word] = target.to_bytes(word, "little")
        return got[raw]

    def get(off: int, n: int) -> int:
        return int.from_bytes(image[off:off + n], "little")

    def put(off: int, n: int, v: int):
        image[off:off + n] = (v & ((1 << 8 * n) - 1)).to_bytes(n, "little")

    # 3. relocations
    for sec, *_ in secs:
        reloff, nrel = getattr(sec, "relocs", (0, 0))
        addend = 0
        for k in range(nrel):
            r_address, info = struct.unpack_from(end + "iI", data, reloff + 8 * k)
            if r_address & 0x80000000 or r_address < 0:     # scattered (32-bit targets)
                continue
            symnum, length, extern, rtype = info & 0xFFFFFF, (info >> 25) & 3, (info >> 27) & 1, info >> 28
            P = sec.addr + r_address
            off = P - BASE
            if off < 0 or off + 4 > len(image):
                continue
            name = ""
            if extern and symnum < len(entries):
                raw = entries[symnum][0]
                name = raw[1:] if raw.startswith("_") else raw
            if b.arch == "x64":
                _x64(rtype, length, extern, symnum, P, off, get, put, sym_addr, got_slot)
            elif b.arch == "arm64":
                if rtype == A64_ADDEND:
                    addend = symnum - (1 << 24) if symnum & 0x800000 else symnum
                    continue
                _arm64(rtype, length, extern, symnum, P, off, addend, get, put, sym_addr, got_slot)
                addend = 0
            b.relocs.append(Relocation(P, name, str(rtype), 0))
    # 4. the image
    b.data = bytes(image)
    b.segments = []
    for sec, *_ in secs:
        sec.offset = sec.addr - BASE
        b.segments.append(Segment(sec.addr, sec.size, sec.offset, sec.size if sec.loaded else 0, True, sec.w, sec.x))
    if externs:
        n = len(externs) * STUB
        b.sections.append(Section("__extern", ext_start, n, ext_start - BASE, True, False, True))
        b.segments.append(Segment(ext_start, n, ext_start - BASE, n, True, False, True))
    if got:
        n = len(got) * word
        b.sections.append(Section("__got", got_start, n, got_start - BASE, True, True, False))
        b.segments.append(Segment(got_start, n, got_start - BASE, n, True, True, False))
    if commons:
        n = pos - cstart
        b.sections.append(Section("__common", cstart, n, cstart - BASE, True, True, False))
        b.segments.append(Segment(cstart, n, cstart - BASE, n, True, True, False))
    # 5. names
    for raw, ntype, nsect, _desc, value in entries:
        if ntype & N_STAB or not raw or _temporary(raw):
            continue
        name = raw[1:] if raw.startswith("_") else raw
        if (ntype & N_TYPE) == N_SECT and 0 < nsect <= len(secs):
            sec = secs[nsect - 1][0]
            sym = Symbol(name, value + BASE, 0, "func" if sec.x else "object", "symtab")
            b.add_symbol(sym)
            if ntype & N_EXT:
                b.exports.append(sym)
        elif raw in commons:
            b.add_symbol(Symbol(name, commons[raw], 0, "object", "symtab"))
    b.got_names = {}
    for raw, a in externs.items():
        name = raw[1:] if raw.startswith("_") else raw
        b.imports.append(Import(name, a, got.get(raw, 0)))
        b.add_symbol(Symbol(name, a, 0, "func", "plt"))
    for raw, a in got.items():
        b.got_names[a] = raw[1:] if raw.startswith("_") else raw
    funcs = sorted(a for a, s in b.symbols.items() if s.kind == "func" and s.source == "symtab")
    for i, a in enumerate(funcs[:-1]):
        b.symbols[a].size = funcs[i + 1] - a
    main = b.name_to_addr.get("main") if hasattr(b, "name_to_addr") else None
    main = next((a for a, s in b.symbols.items() if s.name == "main"), None) if main is None else main
    b.entry = main if main is not None else next((s.addr for s, *_ in secs if s.x), BASE)
    b.base = BASE
    b.info["layout"] = f"relocatable object: sections from {BASE:#x}, {len(externs)} external symbols"
    b._finalize()


def _nlist(data: bytes, end: str, is64: bool, symtab) -> list[tuple[str, int, int, int, int]]:
    if symtab is None:
        return []
    symoff, nsyms, stroff, strsize = symtab
    size = 16 if is64 else 12
    fmt = end + ("IBBHQ" if is64 else "IBBHI")
    out = []
    for k in range(nsyms):
        o = symoff + k * size
        if o + size > len(data):
            break
        strx, ntype, nsect, desc, value = struct.unpack_from(fmt, data, o)
        e = data.find(b"\0", stroff + strx) if 0 < strx < strsize else -1
        raw = data[stroff + strx:e].decode(errors="replace") if e >= 0 else ""
        out.append((raw, ntype, nsect, desc, value))
    return out


def _x64(rtype, length, extern, symnum, P, off, get, put, sym_addr, got_slot):
    n = 8 if length == 3 else 4
    if rtype == X86_UNSIGNED:
        put(off, n, (sym_addr(symnum) if extern else BASE) + get(off, n))
    elif rtype in (X86_SIGNED, X86_BRANCH, *X86_SIGNED_N):
        if extern:          # (a section-relative one is already right: every section moved alike)
            field = get(off, 4)
            field -= (1 << 32) if field >> 31 else 0
            put(off, 4, sym_addr(symnum) + field - (P + 4))
    elif rtype in (X86_GOT_LOAD, X86_GOT) and extern:
        field = get(off, 4)
        field -= (1 << 32) if field >> 31 else 0
        put(off, 4, got_slot(symnum) + field - (P + 4))


def _arm64(rtype, length, extern, symnum, P, off, addend, get, put, sym_addr, got_slot):
    if not extern:
        if rtype == A64_UNSIGNED:
            n = 8 if length == 3 else 4
            put(off, n, BASE + get(off, n))
        return
    w = get(off, 4)
    if rtype == A64_UNSIGNED:
        n = 8 if length == 3 else 4
        put(off, n, sym_addr(symnum) + addend + get(off, n))
    elif rtype == A64_BRANCH26:
        put(off, 4, (w & 0xFC000000) | (((sym_addr(symnum) + addend - P) >> 2) & 0x3FFFFFF))
    elif rtype in (A64_PAGE21, A64_GOT_PAGE21):
        target = got_slot(symnum) if rtype == A64_GOT_PAGE21 else sym_addr(symnum) + addend
        delta = ((target & ~0xFFF) - (P & ~0xFFF)) >> 12
        put(off, 4, (w & 0x9F00001F) | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5))
    elif rtype in (A64_PAGEOFF12, A64_GOT_PAGEOFF12):
        target = got_slot(symnum) if rtype == A64_GOT_PAGEOFF12 else sym_addr(symnum) + addend
        lo = target & 0xFFF
        if (w & 0x1F000000) == 0x11000000:          # add / sub (immediate): unscaled
            imm = lo
        elif (w & 0x3B000000) == 0x39000000:        # load / store (unsigned offset): scaled
            scale = w >> 30
            if w & 0x04000000 and scale == 0 and w & 0x00800000:
                scale = 4                            # a 128-bit q register
            imm = lo >> scale
        else:
            return
        put(off, 4, (w & ~(0xFFF << 10)) | ((imm & 0xFFF) << 10))


__all__ = ["load_macho_object"]

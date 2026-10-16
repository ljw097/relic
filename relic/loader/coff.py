"""COFF objects (`.obj` from MSVC, `.o` from MinGW): laid out and linked alone, like ELF
objects (`elfobj`): sections one after another from BASE, external symbols as import stubs
(`__imp_` slots for dllimport calls), relocations applied (AMD64, i386)."""
from __future__ import annotations

import struct

from .base import Binary, Import, Relocation, Section, Segment, Symbol
from .elfobj import BASE, STUB, _align, _sx

MACHINES = {0x8664: ("x64", 64), 0x14C: ("x86", 32)}
_SCN_CODE, _SCN_INIT, _SCN_UNINIT, _SCN_EXEC, _SCN_WRITE = 0x20, 0x40, 0x80, 0x20000000, 0x80000000
_SCN_DISCARD, _SCN_INFO, _SCN_REMOVE = 0x02000000, 0x200, 0x800


def is_coff(data: bytes) -> bool:
    """A COFF object: a known machine, a plausible section table and symbol table inside the file."""
    if len(data) < 20:
        return False
    machine, nsec, _ts, symoff, nsyms, opt, _ch = struct.unpack_from("<HHIIIHH", data, 0)
    if machine not in MACHINES or not 0 < nsec < 1000 or opt not in (0,):
        return False
    if 20 + 40 * nsec > len(data) or (nsyms and symoff + 18 * nsyms > len(data)):
        return False
    return True


def load_coff(path: str, data: bytes) -> Binary:
    machine, nsec, _ts, symoff, nsyms, opt, _ch = struct.unpack_from("<HHIIIHH", data, 0)
    b = Binary(path, data)
    b.format = "COFF"
    b.arch, b.bits = MACHINES[machine]
    b.os = "windows"
    strtab = symoff + 18 * nsyms

    def name_of(raw: bytes) -> str:
        if raw[:4] == b"\0\0\0\0":
            off = strtab + struct.unpack_from("<I", raw, 4)[0]
            end = data.find(b"\0", off)
            return data[off:end if end >= 0 else None].decode("latin-1", "replace")
        return raw.rstrip(b"\0").decode("latin-1", "replace")

    def plain(name: str) -> str:
        if b.arch == "x86" and name.startswith("_") and not name.startswith("__imp_"):
            name = name[1:]
        if b.arch == "x86" and "@" in name and name.rsplit("@", 1)[1].isdigit():
            name = name.rsplit("@", 1)[0]
        return name
    secs = []                                     # (number, name, size, raw, reloc, nreloc, ch, align)
    for k in range(nsec):
        off = 20 + opt + 40 * k
        (raw_name, _vs, _va, size, raw, reloc, _ln, nreloc, _nl, ch) = struct.unpack_from("<8sIIIIIIHHI", data, off)
        name = raw_name.rstrip(b"\0").decode("latin-1", "replace")
        if name.startswith("/") and name[1:].isdigit():
            name = name_of(b"\0\0\0\0" + struct.pack("<I", int(name[1:])))
        align = 1 << (((ch >> 20) & 0xF) - 1) if (ch >> 20) & 0xF else 16
        secs.append((k + 1, name, size, raw, reloc, nreloc, ch, align))
    syms = []                                     # by index: (name, value, section, type, class)
    k = 0
    while k < nsyms:
        raw = data[symoff + 18 * k: symoff + 18 * k + 18]
        value, secnum, typ, storage, naux = struct.unpack_from("<IhHBB", raw, 8)
        syms.append((name_of(raw[:8]), value, secnum, typ, storage))
        syms.extend([None] * naux)
        k += 1 + naux
    # layout
    addr = BASE
    where = {}
    for num, _name, size, _raw, _r, _n, ch, align in secs:
        if ch & (_SCN_INFO | _SCN_REMOVE | _SCN_DISCARD) or not size:
            continue
        addr = _align(addr, align)
        where[num] = addr
        addr += size
    externs: dict[str, int] = {}
    for s in syms:
        if s is not None and s[2] == 0 and s[4] == 2 and s[0] and not s[1]:      # undefined external
            externs.setdefault(s[0], 0)
    ext_start = _align(addr, 16)
    for k, name in enumerate(sorted(externs)):
        externs[name] = ext_start + k * STUB
    end = ext_start + len(externs) * STUB
    img = bytearray(end - BASE)
    for num, _name, size, raw, _r, _n, ch, _a in secs:
        if num in where and not ch & _SCN_UNINIT and raw:
            img[where[num] - BASE:where[num] - BASE + size] = data[raw:raw + size]
    for name, a in externs.items():
        if b.arch in ("x64", "x86") and not name.startswith("__imp_"):
            img[a - BASE] = 0xC3

    def sym_addr(s) -> int:
        if s is None:
            return 0
        if s[2] > 0 and s[2] in where:
            return where[s[2]] + s[1]
        return externs.get(s[0], 0)
    word = b.bits // 8
    # `__imp_X` slots hold the address of X's stub (dllimport calls go through them)
    for name, a in externs.items():
        if name.startswith("__imp_"):
            target = name[6:]
            stub = externs.get(target) or externs.get("_" + target)
            if stub is None:
                stub = a                          # (points at itself: still an import)
            img[a - BASE:a - BASE + word] = stub.to_bytes(word, "little")
    # symbols
    for s in syms:
        if s is None or not s[0] or s[2] <= 0 or s[2] not in where or s[4] not in (2, 3):
            continue
        if s[4] == 3 and s[1] == 0 and s[0].startswith("."):
            continue                              # (a section symbol)
        sec = next(x for x in secs if x[0] == s[2])
        kind = "func" if (s[3] >> 4) == 2 or (s[4] == 2 and sec[6] & _SCN_EXEC) else "object"
        sym = Symbol(plain(s[0]), where[s[2]] + s[1], 0, kind, "symtab")
        b.add_symbol(sym)
        if s[4] == 2:
            b.exports.append(sym)
    for name, a in externs.items():
        if name.startswith("__imp_"):
            b.imports.append(Import(plain(name[6:]) if b.arch != "x86" else name[6:].lstrip("_").split("@")[0],
                                    externs.get(name[6:], a), a, ""))
        elif ("__imp_" + name) not in externs:
            b.imports.append(Import(plain(name), a, 0, ""))
    # relocations
    for num, _name, _size, _raw, reloc, nreloc, _ch, _a in secs:
        if num not in where:
            continue
        for r in range(nreloc):
            roff, rsym, rtype = struct.unpack_from("<IIH", data, reloc + 10 * r)
            s = syms[rsym] if rsym < len(syms) else None
            S, P = sym_addr(s), where[num] + roff
            off = P - BASE
            b.relocs.append(Relocation(P, plain(s[0]) if s else "", str(rtype), 0))
            if off + 4 > len(img):
                continue
            A = _sx(int.from_bytes(img[off:off + 4], "little"), 32)
            if b.arch == "x64":
                if rtype == 1:                    # ADDR64
                    A8 = int.from_bytes(img[off:off + 8], "little")
                    img[off:off + 8] = ((S + A8) & (2 ** 64 - 1)).to_bytes(8, "little")
                elif rtype in (2, 3):             # ADDR32, ADDR32NB (image-relative)
                    v = S + A - (BASE if rtype == 3 else 0)
                    img[off:off + 4] = (v & 0xFFFFFFFF).to_bytes(4, "little")
                elif 4 <= rtype <= 9:             # REL32, REL32_1..5
                    v = S + A - (P + 4 + (rtype - 4))
                    img[off:off + 4] = (v & 0xFFFFFFFF).to_bytes(4, "little")
            else:
                if rtype == 6:                    # DIR32
                    img[off:off + 4] = ((S + A) & 0xFFFFFFFF).to_bytes(4, "little")
                elif rtype == 7:                  # DIR32NB
                    img[off:off + 4] = ((S + A - BASE) & 0xFFFFFFFF).to_bytes(4, "little")
                elif rtype == 0x14:               # REL32
                    img[off:off + 4] = ((S + A - (P + 4)) & 0xFFFFFFFF).to_bytes(4, "little")
    b.data = bytes(img)
    for num, name, size, _raw, _r, _n, ch, _a in secs:
        if num not in where:
            continue
        a = where[num]
        x, w = bool(ch & (_SCN_EXEC | _SCN_CODE)), bool(ch & _SCN_WRITE)
        b.sections.append(Section(name, a, size, a - BASE, True, w, x, True))
        b.segments.append(Segment(a, size, a - BASE, size, True, w, x))
    if externs:
        n = len(externs) * STUB
        b.sections.append(Section(".extern", ext_start, n, ext_start - BASE, True, False, True))
        b.segments.append(Segment(ext_start, n, ext_start - BASE, n, True, False, True))
    b.sections.sort(key=lambda s: s.addr)
    b.segments.sort(key=lambda s: s.addr)
    main = next((s.addr for s in b.symbols.values() if s.name in ("main", "wmain", "WinMain")), None)
    b.entry = main if main is not None else next((s.addr for s in b.sections if s.x), BASE)
    b.base = BASE
    b.info["layout"] = f"COFF object: sections from {BASE:#x}, {len(externs)} external symbols"
    b._finalize()
    return b


__all__ = ["is_coff", "load_coff"]

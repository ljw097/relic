"""PE (Windows) loader built on pefile."""
from __future__ import annotations

import pefile

from .base import Binary, Import, Section, Segment, Symbol

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_UNINIT = 0x00000080


def load_pe(path: str, data: bytes) -> Binary:
    pe = pefile.PE(data=data, fast_load=False)
    b = Binary(path, data)
    b.format = "PE"
    b.os = "windows"
    m = pe.FILE_HEADER.Machine
    if m == 0x8664:
        b.arch, b.bits = "x64", 64
    elif m == 0x14C:
        b.arch, b.bits = "x86", 32
    elif m == 0xAA64:
        b.arch, b.bits = "arm64", 64
    elif m in (0x1C0, 0x1C4):
        b.arch, b.bits = "arm", 32
    else:
        b.arch, b.bits = "unknown", 32
    base = pe.OPTIONAL_HEADER.ImageBase
    b.base = base
    b.entry = base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    b.pe = pe

    # headers as a read-only segment
    hdr_size = pe.OPTIONAL_HEADER.SizeOfHeaders
    b.segments.append(Segment(base, hdr_size, 0, hdr_size, True, False, False))
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("latin-1")
        ch = s.Characteristics
        r, w, x = bool(ch & IMAGE_SCN_MEM_READ), bool(ch & IMAGE_SCN_MEM_WRITE), bool(ch & IMAGE_SCN_MEM_EXECUTE)
        va = base + s.VirtualAddress
        vsize = max(s.Misc_VirtualSize, s.SizeOfRawData) if s.Misc_VirtualSize == 0 else s.Misc_VirtualSize
        b.sections.append(Section(name, va, vsize, s.PointerToRawData, r, w, x, s.SizeOfRawData > 0))
        b.segments.append(Segment(va, vsize, s.PointerToRawData, min(s.SizeOfRawData, vsize), r, w, x))

    b.add_symbol(Symbol("entry", b.entry, 0, "func", "synthetic"))

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            lib = entry.dll.decode("latin-1")
            b.libraries.append(lib)
            for imp in entry.imports:
                name = imp.name.decode("latin-1") if imp.name else f"{lib.split('.')[0]}_ord{imp.ordinal}"
                # code calls through the IAT slot: `call [iat]`
                b.imports.append(Import(name, imp.address, imp.address, lib))
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.address is None:
                continue
            name = exp.name.decode("latin-1") if exp.name else f"ord_{exp.ordinal}"
            s = Symbol(name, base + exp.address, 0, "func", "export")
            b.exports.append(s)
            b.add_symbol(s)

    oh = pe.OPTIONAL_HEADER
    b.info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))
    b.info["dll_characteristics"] = oh.DllCharacteristics
    b.info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    b._finalize()
    # IAT slots are not code: don't make them callable symbols, but keep names
    b.imports_by_addr = {}
    return b

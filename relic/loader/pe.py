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

    _coff_symbols(pe, data, b)
    _function_starts(pe, b)

    oh = pe.OPTIONAL_HEADER
    b.info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))
    b.info["dll_characteristics"] = oh.DllCharacteristics
    b.info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    b._finalize()
    # IAT slots are not code: don't make them callable symbols, but keep names
    b.imports_by_addr = {}
    return b


def _coff_symbols(pe, data: bytes, b: Binary):
    """Names from the COFF symbol table (kept by MinGW unless stripped).

    Each entry is 18 bytes: name (inline, or an offset into the string table
    that follows the entries), value, section number, type, storage class and
    the number of auxiliary entries to skip. x86 C names carry a leading `_`
    (and `@N` for stdcall), which is dropped.
    """
    import struct
    fh = pe.FILE_HEADER
    off, count = fh.PointerToSymbolTable, fh.NumberOfSymbols
    if not off or not count or off + 18 * count > len(data):
        return
    strtab = off + 18 * count
    sections = pe.sections
    k = 0
    while k < count:
        raw = data[off + 18 * k: off + 18 * k + 18]
        if len(raw) < 18:
            break
        name_raw, value, secnum, typ, storage, naux = struct.unpack("<8sIhHBB", raw)
        k += 1 + naux
        if storage not in (2, 3) or secnum <= 0 or secnum > len(sections):   # EXTERNAL / STATIC
            continue
        if name_raw[:4] == b"\0\0\0\0":
            (soff,) = struct.unpack("<I", name_raw[4:])
            end = data.find(b"\0", strtab + soff)
            name = data[strtab + soff: end if end >= 0 else None].decode("latin-1", "replace")
        else:
            name = name_raw.rstrip(b"\0").decode("latin-1", "replace")
        if not name or name.startswith(".") or name.startswith("__imp_"):
            continue
        sec = sections[secnum - 1]
        addr = b.base + sec.VirtualAddress + value
        is_code = bool(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)
        is_func = (typ >> 4) == 2 or (is_code and storage == 2)
        if b.arch == "x86" and name.startswith("_"):
            name = name[1:].split("@", 1)[0]
        b.add_symbol(Symbol(name, addr, 0, "func" if is_func and is_code else "object", "symtab"))


def _function_starts(pe, b: Binary):
    """Function entries the PE declares itself: x64 exception data and TLS callbacks.

    `.pdata` holds a RUNTIME_FUNCTION per non-leaf function (chained entries,
    which describe a fragment of another function, are skipped). TLS callbacks
    run before the entry point -- a favourite hiding place for anti-debugging
    -- and are named `tls_callback_N`.
    """
    starts: list[int] = []
    for rf in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", []) or []:
        st = getattr(rf, "struct", None)
        if st is None:
            continue
        unwind = getattr(rf, "unwindinfo", None)
        if unwind is not None and getattr(unwind, "Flags", 0) & 0x4:      # UNW_FLAG_CHAININFO
            continue
        starts.append(b.base + st.BeginAddress)
    b.function_starts = sorted(set(starts))
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls is not None:
        ptr = tls.struct.AddressOfCallBacks
        for k in range(64):
            if not ptr:
                break
            cb = b.read_ptr(ptr + k * (b.bits // 8))
            if not cb:
                break
            b.add_symbol(Symbol(f"tls_callback_{k}", cb, 0, "func", "synthetic"))

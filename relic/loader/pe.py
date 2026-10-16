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
    _delay_imports(pe, b)
    _function_starts(pe, b)
    _tls_callbacks(pe, b)
    _resources(pe, b)
    _debug_info(pe, b)
    _dotnet(pe, b)

    oh = pe.OPTIONAL_HEADER
    b.info["subsystem"] = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, str(oh.Subsystem))
    b.info["dll_characteristics"] = oh.DllCharacteristics
    b.info["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    b._finalize()
    # IAT slots are not code: don't make them callable symbols, but keep names
    b.imports_by_addr = {}
    return b


def _delay_imports(pe, b: Binary):
    """Imports the program loads on first call (delay-load descriptors: data directory 13, or
    -- GNU ld leaves it empty -- the `__DELAY_IMPORT_DESCRIPTOR_*` symbols MinGW's import
    libraries define). Each IAT slot first holds a thunk calling the delay-load helper."""
    import struct
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    starts = []
    if len(dirs) > 13 and dirs[13].VirtualAddress:
        starts.append(dirs[13].VirtualAddress)
    starts += sorted(s.addr - b.base for s in b.symbols.values()
                     if s.name.startswith("__DELAY_IMPORT_DESCRIPTOR_"))
    word = b.bits // 8
    seen, libs = set(), []
    for rva in starts:
        for k in range(256):                     # (a null descriptor ends the array)
            try:
                attrs, name, _mod, iat, nt, *_ = struct.unpack("<8I", pe.get_data(rva + 32 * k, 32))
            except (pefile.PEFormatError, struct.error):
                break
            if not name or rva + 32 * k in seen:
                break
            seen.add(rva + 32 * k)
            rel = 0 if attrs & 1 else b.base          # (version 1 descriptors hold RVAs, version 0 VAs)
            try:
                lib = pe.get_string_at_rva(name - rel).decode("latin-1")
            except Exception:  # noqa: BLE001 - a bad name: not a descriptor
                break
            if not lib:
                break
            libs.append(lib)
            for j in range(4096):
                try:
                    ent = int.from_bytes(pe.get_data(nt - rel + j * word, word), "little")
                except pefile.PEFormatError:
                    break
                if not ent:
                    break
                if ent >> (b.bits - 1):
                    fname = f"{lib.split('.')[0]}_ord{ent & 0xFFFF}"
                else:
                    try:
                        fname = pe.get_string_at_rva((ent & 0x7FFFFFFF) - rel + 2).decode("latin-1")
                    except Exception:  # noqa: BLE001
                        break
                slot = b.base + iat - rel + j * word
                if not any(i.got == slot for i in b.imports):
                    b.imports.append(Import(fname, slot, slot, lib))
    if libs:
        b.delay_libraries = libs
        b.libraries += [lib for lib in libs if lib not in b.libraries]
        b.info["delay imports"] = ", ".join(libs)


def _tls_callbacks(pe, b: Binary):
    """Functions the loader calls before the entry point (the TLS directory's callback array)."""
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    va = getattr(getattr(tls, "struct", None), "AddressOfCallBacks", 0) if tls is not None else 0
    if not va:
        return
    word = b.bits // 8
    out = []
    for k in range(64):
        try:
            raw = pe.get_data(va - b.base + k * word, word)
        except pefile.PEFormatError:
            break
        p = int.from_bytes(raw, "little") if len(raw) == word else 0
        if not p:
            break
        out.append(p)
    for k, p in enumerate(out):
        if not any(s.addr == p for s in b.symbols.values()):
            b.add_symbol(Symbol(f"tls_callback_{k}", p, 0, "func", "synthetic"))
    if out:
        b.tls_callbacks = out
        b.info["tls_callbacks"] = ", ".join(f"{p:#x}" for p in out)


def _resources(pe, b: Binary):
    """The resource types it carries (`RT_ICON x3, RT_VERSION`) and its version strings."""
    res = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if res is None:
        return
    kinds = []
    for e in res.entries:
        name = pefile.RESOURCE_TYPE.get(e.id, str(e.name) if e.name else str(e.id)) if e.id is not None else str(e.name)
        n = sum(len(getattr(d, "directory", None).entries) if hasattr(d, "directory") else 1
                for d in getattr(getattr(e, "directory", None), "entries", []))
        kinds.append(f"{name} x{n}" if n > 1 else name)
    if kinds:
        b.info["resources"] = ", ".join(kinds)
    version = {}
    for fi in getattr(pe, "FileInfo", None) or []:
        for entry in fi:
            for table in getattr(entry, "StringTable", []):
                for k, v in table.entries.items():
                    version[k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")
    if version:
        b.version_info = version
        for key in ("CompanyName", "ProductName", "FileVersion", "OriginalFilename"):
            if version.get(key):
                b.info[key] = version[key]


def _debug_info(pe, b: Binary):
    """The PDB the build wrote its symbols to (a CodeView RSDS record): path, GUID and age."""
    import struct
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        if d.struct.Type != 2:                    # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        off, size = d.struct.PointerToRawData, d.struct.SizeOfData
        raw = pe.__data__[off:off + size]
        if raw[:4] != b"RSDS" or len(raw) < 24:
            continue
        d1, d2, d3 = struct.unpack_from("<IHH", raw, 4)
        d4 = raw[12:20]
        age = struct.unpack_from("<I", raw, 20)[0]
        path = raw[24:].split(b"\0")[0].decode("utf-8", "replace")
        guid = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}"
        b.pdb = {"path": path, "guid": guid, "age": age}
        b.info["pdb"] = f"{path} (GUID {guid}, age {age})"
        return


def _dotnet(pe, b: Binary):
    """A .NET assembly: the CLR header (data directory 14) and its metadata's runtime version."""
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(dirs) <= 14 or not dirs[14].VirtualAddress:
        return
    try:
        hdr = pe.get_data(dirs[14].VirtualAddress, 72)
        meta_rva, meta_size = int.from_bytes(hdr[8:12], "little"), int.from_bytes(hdr[12:16], "little")
        flags = int.from_bytes(hdr[16:20], "little")
        meta = pe.get_data(meta_rva, min(meta_size, 256)) if meta_rva else b""
    except pefile.PEFormatError:
        return
    version = ""
    if meta[:4] == b"BSJB":
        n = int.from_bytes(meta[12:16], "little")
        version = meta[16:16 + n].split(b"\0")[0].decode("latin-1", "replace")
    b.dotnet = {"runtime": version, "il_only": bool(flags & 1)}
    b.info["dotnet"] = f"CLR {version or '?'}" + (", IL only" if flags & 1 else ", mixed native code")


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

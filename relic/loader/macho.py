"""Mach-O (macOS / iOS): executables, dylibs and bundles, 32- and 64-bit, and universal (fat)
files, one slice of which is loaded.

Segments and their sections come from `LC_SEGMENT(_64)`; section names stay Apple's (`__text`,
`__stubs`, `__cstring`, ...). Symbols come from the `LC_SYMTAB` nlist table, names without the
leading underscore C symbols carry. Imports are what the indirect symbol table (`LC_DYSYMTAB`)
gives each slot of the stub and pointer sections: a call goes to the `__stubs` entry (the
import's address), which jumps through its `__la_symbol_ptr` / `__got` slot. The entry point is
`LC_MAIN` (the address of `main` itself) or the pc of `LC_UNIXTHREAD`; `LC_FUNCTION_STARTS`
seeds function discovery.
"""
from __future__ import annotations

import struct

from .base import Binary, Import, Section, Segment, Symbol

MH_MAGIC, MH_MAGIC_64 = 0xFEEDFACE, 0xFEEDFACF
FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF

CPU_X86, CPU_X86_64 = 7, 0x01000007
CPU_ARM, CPU_ARM64, CPU_ARM64_32 = 12, 0x0100000C, 0x0200000C
CPU_PPC, CPU_PPC64 = 18, 0x01000012
_ARCH = {CPU_X86: ("x86", 32), CPU_X86_64: ("x64", 64), CPU_ARM: ("arm", 32), CPU_ARM64: ("arm64", 64),
         CPU_PPC: ("ppc", 32), CPU_PPC64: ("ppc64", 64)}

_FILETYPE = {1: "object", 2: "executable", 6: "dylib", 7: "dylinker", 8: "bundle", 10: "dSYM",
             11: "kext"}

LC_SEGMENT, LC_SYMTAB, LC_UNIXTHREAD, LC_DYSYMTAB, LC_LOAD_DYLIB, LC_ID_DYLIB = 0x1, 0x2, 0x5, 0xB, 0xC, 0xD
LC_LOAD_DYLINKER, LC_SEGMENT_64, LC_UUID, LC_RPATH, LC_CODE_SIGNATURE = 0xE, 0x19, 0x1B, 0x8000001C, 0x1D
LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB = 0x80000018, 0x8000001F, 0x20
LC_FUNCTION_STARTS, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS = 0x26, 0x24, 0x25
LC_MAIN, LC_SOURCE_VERSION, LC_BUILD_VERSION, LC_ENCRYPTION_INFO_64 = 0x80000028, 0x2A, 0x32, 0x2C
LC_ENCRYPTION_INFO = 0x21
_DYLIBS = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB)

# section types (flags & 0xff) and attributes
S_ZEROFILL, S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS, S_SYMBOL_STUBS = 0x1, 0x6, 0x7, 0x8
S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL, S_LAZY_DYLIB_SYMBOL_POINTERS = 0xC, 0x12, 0x10
S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS = 0x80000000, 0x400
_ZEROFILL = {S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL}
_POINTERS = {S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS, S_LAZY_DYLIB_SYMBOL_POINTERS}

INDIRECT_SYMBOL_LOCAL, INDIRECT_SYMBOL_ABS = 0x80000000, 0x40000000
N_STAB, N_TYPE, N_EXT, N_SECT, N_UNDF = 0xE0, 0x0E, 0x01, 0x0E, 0x0
_PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS", 6: "Mac Catalyst",
              7: "iOS simulator", 8: "tvOS simulator", 9: "watchOS simulator", 11: "visionOS"}


def is_macho(data: bytes) -> bool:
    if len(data) < 8:
        return False
    le = struct.unpack_from("<I", data)[0]
    be = struct.unpack_from(">I", data)[0]
    if le in (MH_MAGIC, MH_MAGIC_64) or be in (MH_MAGIC, MH_MAGIC_64):
        return True
    # fat: big-endian magic and a small slice count (Java class files share CAFEBABE)
    return be in (FAT_MAGIC, FAT_MAGIC_64) and 0 < struct.unpack_from(">I", data, 4)[0] < 20


def slices(data: bytes) -> list[tuple[str, int, int]]:
    """A universal file's slices: (arch, offset, size); one slice covering a thin file."""
    magic = struct.unpack_from(">I", data)[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return [("", 0, len(data))]
    n = struct.unpack_from(">I", data, 4)[0]
    out = []
    pos = 8
    for _ in range(n):
        if magic == FAT_MAGIC:
            cpu, _sub, off, size, _align = struct.unpack_from(">iiIII", data, pos)
            pos += 20
        else:
            cpu, _sub, off, size, _align, _res = struct.unpack_from(">iiQQII", data, pos)
            pos += 32
        out.append((_ARCH.get(cpu & 0xFFFFFFFF, (f"cpu{cpu:#x}", 0))[0], off, size))
    return out


def load_macho(path: str, data: bytes, arch: str | None = None) -> Binary:
    sl = slices(data)
    fat = len(sl) > 1 or sl[0][0] != ""
    if fat:
        # the requested slice, else the host's (x86-64), else the first
        pick = next((s for s in sl if s[0] == arch), None) or next((s for s in sl if s[0] == "x64"), None) or sl[0]
        body = data[pick[1]:pick[1] + pick[2]]
    else:
        pick, body = None, data
    b = _load_thin(path, body)
    if fat:
        b.info["universal"] = ", ".join(s[0] for s in sl) + f" (loaded: {pick[0]})"
        b.info["slice offset"] = f"{pick[1]:#x}"
    return b


def _load_thin(path: str, data: bytes) -> Binary:
    magic_le = struct.unpack_from("<I", data)[0]
    end = "<" if magic_le in (MH_MAGIC, MH_MAGIC_64) else ">"
    magic = struct.unpack_from(end + "I", data)[0]
    is64 = magic == MH_MAGIC_64
    cpu, _sub, ftype, ncmds, sizeofcmds, flags = struct.unpack_from(end + "iiIIII", data, 4)
    b = Binary(path, data)
    b.format = "Mach-O"
    b.os = "macos"
    b.endian = "little" if end == "<" else "big"
    b.arch, b.bits = _ARCH.get(cpu & 0xFFFFFFFF, ("x64", 64))
    if (cpu & 0xFFFFFFFF) == CPU_ARM64_32:
        b.arch, b.bits = "arm64", 32
    b.macho_type = _FILETYPE.get(ftype, str(ftype))
    b.info["type"] = b.macho_type
    b.macho_flags = flags
    pos = 32 if is64 else 28
    ptr = 8 if is64 else 4

    secs_by_index: list[tuple[Section, int, int, int]] = []    # (section, flags, reserved1, reserved2)
    symtab = dysymtab = None
    entryoff = thread_pc = None
    starts_cmd = None
    text_vmaddr = None
    b.macho_segments = []
    for _ in range(ncmds):
        if pos + 8 > len(data):
            break
        cmd, size = struct.unpack_from(end + "II", data, pos)
        if size < 8:
            break
        body = pos + 8
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if cmd == LC_SEGMENT_64:
                segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _fl = \
                    struct.unpack_from(end + "16sQQQQiiII", data, body)
                spos = body + 64
            else:
                segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, _fl = \
                    struct.unpack_from(end + "16sIIIIiiII", data, body)
                spos = body + 48
            segname = segname.rstrip(b"\0").decode(errors="replace")
            b.macho_segments.append(segname)
            if segname == "__TEXT":
                text_vmaddr = vmaddr
            if initprot and vmsize:              # (not __PAGEZERO)
                b.segments.append(Segment(vmaddr, vmsize, fileoff, min(filesize, vmsize), bool(initprot & 1),
                                          bool(initprot & 2), bool(initprot & 4)))
            for _k in range(nsects):
                if cmd == LC_SEGMENT_64:
                    sectname, sseg, addr, ssize, off, _al, _reloff, _nrel, sflags, r1, r2, _r3 = \
                        struct.unpack_from(end + "16s16sQQIIIIIIII", data, spos)
                    spos += 80
                else:
                    sectname, sseg, addr, ssize, off, _al, _reloff, _nrel, sflags, r1, r2 = \
                        struct.unpack_from(end + "16s16sIIIIIIIII", data, spos)
                    spos += 68
                name = sectname.rstrip(b"\0").decode(errors="replace")
                stype = sflags & 0xFF
                code = bool(sflags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
                sec = Section(name, addr, ssize, off, bool(initprot & 1) or not initprot,
                              bool(initprot & 2), code or bool(initprot & 4) and segname == "__TEXT" and
                              name in ("__text", "__stubs", "__stub_helper", "__auth_stubs"),
                              stype not in _ZEROFILL)
                sec.segment = sseg.rstrip(b"\0").decode(errors="replace")
                b.sections.append(sec)
                secs_by_index.append((sec, sflags, r1, r2))
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack_from(end + "IIII", data, body)
        elif cmd == LC_DYSYMTAB:
            dysymtab = struct.unpack_from(end + "18I", data, body)
        elif cmd == LC_MAIN:
            entryoff, stack = struct.unpack_from(end + "QQ", data, body)
        elif cmd == LC_UNIXTHREAD:
            thread_pc = _thread_pc(data, body, end, b.arch)
        elif cmd in _DYLIBS:
            name_off = struct.unpack_from(end + "I", data, body)[0]
            b.libraries.append(_cstr(data, pos + name_off))
        elif cmd == LC_ID_DYLIB:
            name_off = struct.unpack_from(end + "I", data, body)[0]
            b.info["install name"] = _cstr(data, pos + name_off)
        elif cmd == LC_LOAD_DYLINKER:
            b.interp = _cstr(data, pos + struct.unpack_from(end + "I", data, body)[0])
        elif cmd == LC_RPATH:
            b.info.setdefault("rpath", "")
            b.info["rpath"] = ", ".join(filter(None, [b.info["rpath"],
                                                      _cstr(data, pos + struct.unpack_from(end + "I", data, body)[0])]))
        elif cmd == LC_UUID:
            u = data[body:body + 16].hex().upper()
            b.info["uuid"] = f"{u[:8]}-{u[8:12]}-{u[12:16]}-{u[16:20]}-{u[20:]}"
        elif cmd == LC_BUILD_VERSION:
            platform, minos, sdk = struct.unpack_from(end + "III", data, body)
            b.info["platform"] = f"{_PLATFORMS.get(platform, platform)} {_ver(minos)} (SDK {_ver(sdk)})"
        elif cmd in (LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS):
            ver, sdk = struct.unpack_from(end + "II", data, body)
            b.info["platform"] = f"{'macOS' if cmd == LC_VERSION_MIN_MACOSX else 'iOS'} {_ver(ver)} (SDK {_ver(sdk)})"
        elif cmd == LC_FUNCTION_STARTS:
            starts_cmd = struct.unpack_from(end + "II", data, body)
        elif cmd == LC_CODE_SIGNATURE:
            b.info["code signature"] = "yes"
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if struct.unpack_from(end + "III", data, body)[2]:
                b.info["encrypted"] = "yes (FairPlay): the encrypted range reads as ciphertext"
        pos += size

    b.base = text_vmaddr or 0
    if entryoff is not None:
        b.entry = (text_vmaddr or 0) + entryoff
    elif thread_pc is not None:
        b.entry = thread_pc

    names = _symbols(b, data, end, is64, symtab, secs_by_index)
    _imports(b, data, end, ptr, names, symtab, dysymtab, secs_by_index)
    if starts_cmd is not None and text_vmaddr is not None:
        b.function_starts = _function_starts(data, *starts_cmd, text_vmaddr)
    if b.entry and b.entry not in b.symbols:
        # LC_MAIN points at main itself; LC_UNIXTHREAD at the runtime's start
        b.add_symbol(Symbol("main" if entryoff is not None else "start", b.entry, 0, "func", "synthetic"))
    b._finalize()
    return b


def _ver(v: int) -> str:
    return f"{v >> 16}.{(v >> 8) & 0xFF}" + (f".{v & 0xFF}" if v & 0xFF else "")


def _cstr(data: bytes, off: int) -> str:
    e = data.find(b"\0", off)
    return data[off:e if e >= 0 else len(data)].decode(errors="replace")


def _thread_pc(data: bytes, body: int, end: str, arch: str) -> int | None:
    """The pc in an LC_UNIXTHREAD's register state (flavor, count, then the registers)."""
    flavor, count = struct.unpack_from(end + "II", data, body)
    regs = body + 8
    if arch == "x64" and flavor == 4:            # x86_THREAD_STATE64: rip is register 16
        return struct.unpack_from(end + "Q", data, regs + 16 * 8)[0]
    if arch == "x86" and flavor == 1:            # i386_THREAD_STATE: eip is register 10
        return struct.unpack_from(end + "I", data, regs + 10 * 4)[0]
    if arch == "arm64" and flavor == 6:          # ARM_THREAD_STATE64: x0-x28, fp, lr, sp, pc
        return struct.unpack_from(end + "Q", data, regs + 32 * 8)[0]
    if arch == "arm" and flavor == 1:            # ARM_THREAD_STATE: r0-r12, sp, lr, pc
        return struct.unpack_from(end + "I", data, regs + 15 * 4)[0]
    return None


def _symbols(b: Binary, data: bytes, end: str, is64: bool, symtab, secs) -> list[str]:
    """The nlist table: defined symbols into `b.symbols` (exports too when external); the name of
    every entry, in order (the indirect symbol table refers to them by index)."""
    if symtab is None:
        return []
    symoff, nsyms, stroff, strsize = symtab
    size = 16 if is64 else 12
    fmt = end + ("IBBHQ" if is64 else "IBBhI")
    names = []
    for k in range(nsyms):
        off = symoff + k * size
        if off + size > len(data):
            break
        strx, ntype, nsect, _desc, value = struct.unpack_from(fmt, data, off)
        raw = _cstr(data, stroff + strx) if 0 < strx < strsize else ""
        names.append(raw)
        if ntype & N_STAB or (ntype & N_TYPE) != N_SECT or not raw or not (0 < nsect <= len(secs)):
            continue
        sec = secs[nsect - 1][0]
        name = raw[1:] if raw.startswith("_") else raw
        # (`__mh_execute_header` names the header, before the section it claims)
        kind = "func" if sec.x and sec.contains(value) else "object"
        sym = Symbol(name, value, 0, kind, "symtab")
        b.add_symbol(sym)
        if ntype & N_EXT:
            b.exports.append(sym)
    # nlist has no sizes: a function runs up to the next symbol (data objects stay unsized, their
    # neighbour says nothing about how big they are)
    addrs = sorted(b.symbols)
    for i, a in enumerate(addrs[:-1]):
        if b.symbols[a].kind == "func":
            b.symbols[a].size = addrs[i + 1] - a
    return names


def _imports(b: Binary, data: bytes, end: str, ptr: int, names: list[str], symtab, dysymtab, secs):
    """Each slot of a stub / pointer section names its import through the indirect symbol table."""
    if dysymtab is None or not names:
        return
    indirectsymoff, nindirect = dysymtab[12], dysymtab[13]
    indirect = [struct.unpack_from(end + "I", data, indirectsymoff + 4 * k)[0] for k in range(nindirect)
                if indirectsymoff + 4 * k + 4 <= len(data)]
    lib_of = _library_ordinals(b, data, end, ptr == 8, symtab)
    got: dict[str, int] = {}
    stubs: dict[str, int] = {}
    for sec, flags, r1, r2 in secs:
        stype = flags & 0xFF
        if stype == S_SYMBOL_STUBS:
            step = r2 or 1
        elif stype in _POINTERS:
            step = ptr
        else:
            continue
        for k in range(sec.size // step):
            if r1 + k >= len(indirect):
                break
            idx = indirect[r1 + k]
            if idx & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) or idx >= len(names):
                continue
            raw = names[idx]
            name = raw[1:] if raw.startswith("_") else raw
            if not name:
                continue
            slot = sec.addr + k * step
            if stype == S_SYMBOL_STUBS:
                stubs.setdefault(name, slot)
            else:
                # the lazy pointer is what the stub jumps through; a non-lazy one (`__got`) is read
                # by the code directly
                if stype != S_NON_LAZY_SYMBOL_POINTERS or name not in got:
                    got[name] = slot
            b.got_names = getattr(b, "got_names", {})
            if stype != S_SYMBOL_STUBS:
                b.got_names[slot] = name
    for name in dict.fromkeys([*stubs, *got]):
        lib = lib_of.get(name, "")
        b.imports.append(Import(name, stubs.get(name, 0), got.get(name, 0), lib))
        if name in stubs:
            b.add_symbol(Symbol(name, stubs[name], 0, "func", "plt"))


def _library_ordinals(b: Binary, data: bytes, end: str, is64: bool, symtab) -> dict[str, str]:
    """Two-level namespace: an undefined symbol's library, from the ordinal in its n_desc."""
    out: dict[str, str] = {}
    if symtab is None:
        return out
    symoff, nsyms, stroff, strsize = symtab
    size = 16 if is64 else 12
    fmt = end + ("IBBHQ" if is64 else "IBBHI")
    for k in range(nsyms):
        off = symoff + k * size
        if off + size > len(data):
            break
        strx, ntype, _nsect, desc, _value = struct.unpack_from(fmt, data, off)
        if ntype & N_STAB or (ntype & N_TYPE) != N_UNDF or not 0 < strx < strsize:
            continue
        raw = _cstr(data, stroff + strx)
        name = raw[1:] if raw.startswith("_") else raw
        ordinal = (desc >> 8) & 0xFF
        if 0 < ordinal <= len(b.libraries):
            out[name] = b.libraries[ordinal - 1].rsplit("/", 1)[-1]
    return out


def _function_starts(data: bytes, off: int, size: int, base: int) -> list[int]:
    """LC_FUNCTION_STARTS: ULEB128 deltas from the start of __TEXT, ended by a 0."""
    out = []
    addr = base
    pos, stop = off, off + size
    while pos < stop:
        v = shift = 0
        while pos < stop:
            byte = data[pos]
            pos += 1
            v |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        if v == 0:
            break
        addr += v
        out.append(addr)
    return out


__all__ = ["is_macho", "load_macho", "slices"]

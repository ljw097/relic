"""Exploit-mitigation summary (checksec) for ELF, PE and Mach-O."""
from __future__ import annotations

from ..loader.base import Binary

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000
PF_X = 1


def checksec(b: Binary) -> dict[str, str]:
    if b.format == "ELF":
        return _elf(b)
    if b.format == "PE":
        return _pe(b)
    if b.format == "Mach-O":
        return _macho(b)
    return {"Arch": b.arch}


def _elf(b: Binary) -> dict[str, str]:
    phdrs = getattr(b, "program_headers", [])
    dyn = getattr(b, "dynamic", {})
    types = {p["type"] for p in phdrs}
    imported = {i.name for i in b.imports}

    bind_now = bool(dyn.get("DT_FLAGS", 0) & DF_BIND_NOW) or bool(dyn.get("DT_FLAGS_1", 0) & DF_1_NOW) \
        or "DT_BIND_NOW" in dyn
    if "PT_GNU_RELRO" in types:
        relro = "Full RELRO" if bind_now else "Partial RELRO"
    else:
        relro = "No RELRO"

    canary = "__stack_chk_fail" in imported or "__stack_chk_guard" in imported or \
        "__stack_chk_fail" in b.name_to_addr
    stack = next((p for p in phdrs if p["type"] == "PT_GNU_STACK"), None)
    nx = stack is not None and not (stack["flags"] & PF_X)

    etype = getattr(b, "elf_type", "")
    if etype == "ET_DYN":
        pie = "PIE enabled" if (b.interp or dyn.get("DT_FLAGS_1", 0) & DF_1_PIE) else "DSO"
    elif etype == "ET_REL":
        pie = "REL"
    else:
        pie = f"No PIE ({b.segments[0].addr:#x})" if b.segments else "No PIE"

    fortified = sorted(n for n in imported if n.startswith("__") and n.endswith("_chk") and n != "__stack_chk_fail")
    stripped = not any(s.source == "symtab" for s in b.symbols.values())
    res = {
        "Arch": f"{b.arch}-{b.bits}-{b.endian}",
        "RELRO": relro,
        "Stack": "Canary found" if canary else "No canary found",
        "NX": "NX enabled" if nx else "NX disabled",
        "PIE": pie,
    }
    if "RPATH" in dyn:
        res["RPATH"] = dyn["RPATH"]
    if "RUNPATH" in dyn:
        res["RUNPATH"] = dyn["RUNPATH"]
    res["FORTIFY"] = f"Enabled ({', '.join(fortified)})" if fortified else "No"
    res["Stripped"] = "Yes" if stripped else "No"
    if b.interp:
        res["Interp"] = b.interp
    return res


def _pe(b: Binary) -> dict[str, str]:
    dc = int(b.info.get("dll_characteristics", 0))
    pe = getattr(b, "pe", None)
    gs = any(i.name == "__security_check_cookie" for i in b.imports)
    if pe is not None and hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        gs = gs or bool(getattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, "SecurityCookie", 0))
    return {
        "Arch": f"{b.arch}-{b.bits}-{b.endian}",
        "ASLR": "Yes" if dc & 0x40 else "No",
        "HighEntropyVA": "Yes" if dc & 0x20 else "No",
        "DEP/NX": "Yes" if dc & 0x100 else "No",
        "CFG": "Yes" if dc & 0x4000 else "No",
        "SEH": "No (NO_SEH)" if dc & 0x400 else "Yes",
        "GS": "Yes" if gs else "No",
        "Subsystem": str(b.info.get("subsystem", "")),
    }


MH_ALLOW_STACK_EXECUTION, MH_PIE, MH_NO_HEAP_EXECUTION = 0x20000, 0x200000, 0x1000000


def _macho(b: Binary) -> dict[str, str]:
    flags = getattr(b, "macho_flags", 0)
    imported = {i.name for i in b.imports}
    fortified = sorted(n for n in imported if n.startswith("__") and n.endswith("_chk") and n != "__stack_chk_fail")
    return {
        "Arch": f"{b.arch}-{b.bits}-{b.endian}",
        "PIE": "Yes" if flags & MH_PIE else "No",
        "NX stack": "No (MH_ALLOW_STACK_EXECUTION)" if flags & MH_ALLOW_STACK_EXECUTION else "Yes",
        # (64-bit processes never get an executable heap; the flag matters for 32-bit ones)
        "NX heap": "Yes" if flags & MH_NO_HEAP_EXECUTION or b.bits == 64 else "No",
        "Canary": "Yes" if imported & {"__stack_chk_fail", "__stack_chk_guard"} else "No",
        "Fortify": ", ".join(fortified) if fortified else "No",
        "Code signature": "Yes" if "code signature" in b.info else "No",
        "Encrypted": "Yes" if "encrypted" in b.info else "No",
        "Restrict": "Yes" if "__RESTRICT" in getattr(b, "macho_segments", ()) else "No",
        "ARC": "Yes" if imported & {"objc_release", "objc_retain", "objc_storeStrong"} else "No",
    }

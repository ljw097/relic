"""ELF core dumps: the memory of a process when it died (or when gdb's `gcore` saved it).

The PT_LOAD segments are its memory; the notes say which process it was (NT_PRPSINFO), why
it stopped and its registers (NT_PRSTATUS: x86-64, x86, AArch64, ARM, RISC-V), and which file
each mapping came from (NT_FILE). The entry point is the program counter at the time of the
dump, and the symbols of the executable (when its file is still there) are added at the
address it was loaded at, so the code the process ran reads with its names."""
from __future__ import annotations

import os
import struct

from .base import Binary, Section, Segment, Symbol

# elf_prstatus: registers start after this prefix (64-bit / 32-bit layouts)
_PR_REG = {64: 112, 32: 72}
# register names in pr_reg order (user_regs_struct / pt_regs)
_REGS = {
    "x64": ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
            "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"],
    "x86": ["ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "xds", "xes", "xfs", "xgs", "orig_eax", "eip", "xcs",
            "eflags", "esp", "xss"],
    "arm64": [f"x{k}" for k in range(31)] + ["sp", "pc", "pstate"],
    "arm": [f"r{k}" for k in range(13)] + ["sp", "lr", "pc", "cpsr", "orig_r0"],
    "riscv64": ["pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
                "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"],
}
_PC = {"x64": "rip", "x86": "eip", "arm64": "pc", "arm": "pc", "riscv64": "pc"}
_SIGNALS = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS",
            8: "SIGFPE", 9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2", 13: "SIGPIPE", 14: "SIGALRM",
            15: "SIGTERM"}


def load_core(b: Binary, elf) -> None:
    """Fill `b` (arch, bits and endian set) from the core file `elf`."""
    word = b.bits // 8
    fmt = "<" if b.endian == "little" else ">"
    for seg in elf.iter_segments():
        h = seg.header
        if h.p_type == "PT_LOAD" and h.p_memsz:
            r, w, x = bool(h.p_flags & 4), bool(h.p_flags & 2), bool(h.p_flags & 1)
            b.segments.append(Segment(h.p_vaddr, h.p_memsz, h.p_offset, h.p_filesz, r, w, x))
    files: list[tuple[int, int, int, str]] = []
    threads = []
    for seg in elf.iter_segments():
        if seg.header.p_type != "PT_NOTE":
            continue
        for n in seg.iter_notes():
            t, desc = n["n_type"], n["n_desc"]
            if t == "NT_PRPSINFO":
                name = desc.get("pr_fname", b"")
                b.info["process"] = (name.split(b"\0")[0] if isinstance(name, bytes) else str(name)).decode(
                    "latin-1", "replace") if isinstance(name, bytes) else str(name)
                args = desc.get("pr_psargs", b"")
                if isinstance(args, bytes) and args.strip(b"\0"):
                    b.info["command"] = args.split(b"\0")[0].decode("latin-1", "replace").strip()
            elif t == "NT_PRSTATUS" and isinstance(desc, bytes):
                sig = struct.unpack_from(fmt + "H", desc, 12)[0]
                pid = struct.unpack_from(fmt + "i", desc, 32 if b.bits == 64 else 24)[0]
                names = _REGS.get(b.arch, [])
                off = _PR_REG[b.bits]
                regs = {}
                for k, nm in enumerate(names):
                    if off + (k + 1) * word <= len(desc):
                        regs[nm] = int.from_bytes(desc[off + k * word:off + (k + 1) * word], b.endian)
                threads.append({"pid": pid, "signal": sig, "regs": regs})
            elif t == "NT_FILE" and not isinstance(desc, bytes):
                page = desc.get("page_size", 1) or 1
                for e, path in zip(desc.get("Elf_Nt_File_Entry", []), desc.get("filename", [])):
                    p = path.decode("latin-1", "replace") if isinstance(path, bytes) else str(path)
                    files.append((e["vm_start"], e["vm_end"], e["page_offset"] * page, p))
    b.core_threads = threads
    b.core_files = files
    if threads:
        main = threads[0]
        b.core_regs = main["regs"]
        sig = main["signal"]
        b.info["signal"] = f"{_SIGNALS.get(sig, sig)} ({sig})" if sig else "none"
        b.info["pid"] = str(main["pid"])
        if len(threads) > 1:
            b.info["threads"] = str(len(threads))
        pc = main["regs"].get(_PC.get(b.arch, "pc"))
        if pc:
            b.entry = pc
            b.info["pc"] = f"{pc:#x}"
    # sections: one per mapping, named after its file
    for sg in b.segments:
        f = next((f for f in files if f[0] <= sg.addr < f[1]), None)
        sp = next((v for k, v in getattr(b, "core_regs", {}).items() if k in ("rsp", "esp", "sp")), None)
        name = os.path.basename(f[3]) if f else "[stack]" if sp is not None and sg.addr <= sp < sg.addr + sg.memsz \
            else "[anon]"
        b.sections.append(Section(name, sg.addr, sg.memsz, sg.offset, sg.r, sg.w, sg.x, sg.filesz > 0))
    if files:
        b.info["mapped files"] = str(len({f[3] for f in files}))
    _executable_symbols(b, files)


def _executable_symbols(b: Binary, files: list) -> None:
    """Symbols of the mapped files that are still on disk (the executable first), at the
    addresses they were loaded at."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    seen = set()
    for start, _end, off, path in files:
        if off != 0 or path in seen or not os.path.isfile(path):
            continue
        seen.add(path)
        try:
            with open(path, "rb") as fp:
                e = ELFFile(fp)
                pie = e["e_type"] == "ET_DYN"
                low = min((s["p_vaddr"] - s["p_offset"] for s in e.iter_segments() if s["p_type"] == "PT_LOAD"),
                          default=0)
                bias = start - low if pie else 0
                for sec in e.iter_sections():
                    if not isinstance(sec, SymbolTableSection):
                        continue
                    for sym in sec.iter_symbols():
                        if sym["st_info"]["type"] in ("STT_FUNC", "STT_OBJECT") and sym.name and sym["st_value"]:
                            kind = "func" if sym["st_info"]["type"] == "STT_FUNC" else "object"
                            b.add_symbol(Symbol(sym.name.split("@")[0], sym["st_value"] + bias, sym["st_size"],
                                                kind, "symtab"))
        except Exception:  # noqa: BLE001 - a file that is not ELF (or moved): no names from it
            continue
        if len(seen) >= 8:
            break


__all__ = ["load_core"]

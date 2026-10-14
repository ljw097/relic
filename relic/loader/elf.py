"""ELF loader built on pyelftools."""
from __future__ import annotations

import io

import capstone as cs
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_reloc_type
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from .base import Binary, Import, Relocation, Section, Segment, Symbol

MACHINES = {
    "EM_X86_64": ("x64", 64),
    "EM_386": ("x86", 32),
    "EM_ARM": ("arm", 32),
    "EM_AARCH64": ("arm64", 64),
    "EM_MIPS": ("mips", 32),
    "EM_RISCV": ("riscv64", 64),
    "EM_PPC": ("ppc", 32),
    "EM_PPC64": ("ppc64", 64),
}

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
PF_X, PF_W, PF_R = 1, 2, 4


def load_elf(path: str, data: bytes) -> Binary:
    b = Binary(path, data)
    b.format = "ELF"
    elf = ELFFile(io.BytesIO(data))
    arch, bits = MACHINES.get(elf["e_machine"], ("unknown", elf.elfclass))
    if arch == "mips" and elf.elfclass == 64:
        arch = "mips64"
    if arch == "riscv64" and elf.elfclass == 32:
        arch, bits = "riscv32", 32
    b.arch, b.bits = arch, elf.elfclass
    b.endian = "little" if elf.little_endian else "big"
    b.entry = elf["e_entry"]
    if arch == "arm" and b.entry & 1:         # Thumb entry point
        b.entry &= ~1
        b.thumb_code.add(b.entry)
    b.info["type"] = elf["e_type"]
    b.info["machine"] = elf["e_machine"]
    b.elf_type = elf["e_type"]

    b.program_headers = []
    for seg in elf.iter_segments():
        h = seg.header
        b.program_headers.append(dict(type=h.p_type, flags=h.p_flags, vaddr=h.p_vaddr,
                                      memsz=h.p_memsz, offset=h.p_offset, filesz=h.p_filesz))
        if h.p_type == "PT_LOAD" and h.p_memsz:
            b.segments.append(Segment(h.p_vaddr, h.p_memsz, h.p_offset, h.p_filesz,
                                      bool(h.p_flags & PF_R), bool(h.p_flags & PF_W), bool(h.p_flags & PF_X)))
        if h.p_type == "PT_INTERP":
            b.interp = seg.get_interp_name()

    for sec in elf.iter_sections():
        h = sec.header
        if not (h.sh_flags & SHF_ALLOC) or not sec.name:
            continue
        b.sections.append(Section(sec.name, h.sh_addr, h.sh_size, h.sh_offset, True,
                                  bool(h.sh_flags & SHF_WRITE), bool(h.sh_flags & SHF_EXECINSTR),
                                  h.sh_type != "SHT_NOBITS"))
    if not b.segments:  # relocatable object: lay sections out as-is
        for s in b.sections:
            s.addr = s.addr or 0

    # symbols
    for sec in elf.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        source = "dynsym" if sec.name == ".dynsym" else "symtab"
        for sym in sec.iter_symbols():
            t = sym["st_info"]["type"]
            if not sym.name or sym["st_shndx"] == "SHN_UNDEF" or sym["st_value"] == 0:
                continue
            if arch == "arm" and sym.name[:2] in ("$a", "$t", "$d") and sym.name[2:3] in ("", "."):
                b.arm_mapping[sym["st_value"]] = sym.name[1]
                continue
            kind = {"STT_FUNC": "func", "STT_OBJECT": "object", "STT_GNU_IFUNC": "func"}.get(t)
            if kind is None:
                continue
            addr = sym["st_value"]
            if arch == "arm" and kind == "func":
                if addr & 1:
                    b.thumb_code.add(addr & ~1)
                addr &= ~1
            name = sym.name.split("@")[0]
            s = Symbol(name, addr, sym["st_size"], kind, source)
            b.add_symbol(s)
            if source == "dynsym" and sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                b.exports.append(s)

    # dynamic info
    b.dynamic = {}
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    b.libraries.append(tag.needed)
                elif tag.entry.d_tag == "DT_RPATH":
                    b.dynamic["RPATH"] = tag.rpath
                elif tag.entry.d_tag == "DT_RUNPATH":
                    b.dynamic["RUNPATH"] = tag.runpath
                else:
                    b.dynamic[tag.entry.d_tag] = tag.entry.d_val

    # relocations -> GOT slot names
    got_names: dict[int, str] = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        try:
            symtab = elf.get_section(sec["sh_link"])
        except Exception:
            symtab = None
        for rel in sec.iter_relocations():
            name = ""
            if symtab is not None and isinstance(symtab, SymbolTableSection) and rel["r_info_sym"]:
                try:
                    name = symtab.get_symbol(rel["r_info_sym"]).name.split("@")[0]
                except Exception:
                    name = ""
            off = rel["r_offset"]
            b.relocs.append(Relocation(off, name, describe_reloc_type(rel["r_info_type"], elf)))
            if name:
                got_names[off] = name
    b.got_names = got_names

    _resolve_plt(b, got_names)
    b._finalize()
    return b


def _resolve_plt(b: Binary, got_names: dict[int, str]):
    """Map PLT stubs to imported function names by decoding the stubs."""
    plt_secs = [s for s in b.sections if s.name.startswith(".plt") or s.name == ".iplt"]
    gotplt = next((s for s in b.sections if s.name == ".got.plt"), None) or \
        next((s for s in b.sections if s.name == ".got"), None)
    found: dict[int, str] = {}
    if b.arch in ("x64", "x86"):
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if b.arch == "x64" else cs.CS_MODE_32)
        md.detail = True
        for sec in plt_secs:
            code = b.data[sec.offset:sec.offset + sec.size]
            for insn in md.disasm(code, sec.addr):
                if insn.mnemonic not in ("jmp", "bnd jmp") or len(insn.operands) != 1:
                    continue
                op = insn.operands[0]
                if op.type != cs.x86.X86_OP_MEM:
                    continue
                m = op.mem
                slot = None
                if m.base == cs.x86.X86_REG_RIP:
                    slot = insn.address + insn.size + m.disp
                elif m.base == 0 and m.index == 0:
                    slot = m.disp & 0xFFFFFFFF
                elif b.arch == "x86" and m.base == cs.x86.X86_REG_EBX and gotplt is not None:
                    slot = (gotplt.addr + m.disp) & 0xFFFFFFFF
                if slot is None or slot not in got_names:
                    continue
                stub = insn.address
                # stub start: entries are 16-byte aligned on x86
                stub -= (stub - sec.addr) % 16 if sec.size % 16 == 0 else 0
                found.setdefault(stub, got_names[slot])
                b.imports.append(Import(got_names[slot], stub, slot))
    elif b.arch == "arm64":
        md = cs.Cs(cs.CS_ARCH_ARM64 if hasattr(cs, "CS_ARCH_ARM64") else cs.CS_ARCH_AARCH64, cs.CS_MODE_ARM)
        for sec in plt_secs:
            code = b.data[sec.offset:sec.offset + sec.size]
            insns = list(md.disasm(code, sec.addr))
            for i in range(len(insns) - 1):
                a, l = insns[i], insns[i + 1]
                if a.mnemonic == "adrp" and l.mnemonic == "ldr":
                    try:
                        page = int(a.op_str.split("#")[-1], 16)
                        off = int(l.op_str.split("#")[-1].rstrip("]!"), 16) if "#" in l.op_str else 0
                    except ValueError:
                        continue
                    slot = page + off
                    if slot in got_names and a.address not in found:
                        b.imports.append(Import(got_names[slot], a.address, slot))
                        found[a.address] = got_names[slot]
    elif b.arch == "arm":
        # `add ip, pc, #a, r; add ip, ip, #b; ldr pc, [ip, #c]!` -- emulate ip to find the slot
        md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        md.detail = True
        md.skipdata = True             # the Thumb entry halfwords are not valid A32
        for sec in plt_secs:
            code = b.data[sec.offset:sec.offset + sec.size]
            ip, start = None, None
            for insn in md.disasm(code, sec.addr):
                if insn.id == 0:
                    ip = None
                    continue
                ops = insn.operands
                regs = [insn.reg_name(o.reg) for o in ops if o.type == cs.arm.ARM_OP_REG]
                imms = [o.imm for o in ops if o.type == cs.arm.ARM_OP_IMM]
                if insn.mnemonic == "add" and regs[:2] == ["ip", "pc"] and imms:
                    ip, start = insn.address + 8 + (imms[0] & 0xFFFFFFFF), insn.address
                elif insn.mnemonic == "add" and regs[:2] == ["ip", "ip"] and imms and ip is not None:
                    ip += imms[0]
                elif insn.mnemonic == "ldr" and regs[:1] == ["pc"] and ip is not None:
                    slot = (ip + ops[1].mem.disp) & 0xFFFFFFFF
                    if slot in got_names:
                        # a Thumb caller enters 4 bytes earlier, at `bx pc; b.n .-2`
                        thumb = start - 4 >= sec.addr and b.read(start - 4, 2) == b"\x78\x47"
                        for stub in ((start - 4, start) if thumb else (start,)):
                            b.imports.append(Import(got_names[slot], stub, slot))
                            found[stub] = got_names[slot]
                    ip = None
                else:
                    ip = None if insn.mnemonic != "add" else ip
    # fallback: order of .rela.plt entries -> sequential PLT stubs
    if not found and plt_secs and got_names:
        plt = plt_secs[0]
        ent = 16 if b.arch in ("x64", "x86", "arm64") else 12
        hdr = 32 if b.arch == "arm64" else (20 if b.arch == "arm" else ent)
        jmp_slots = [r for r in b.relocs if "JUMP_SLOT" in r.kind and r.name]
        for i, r in enumerate(jmp_slots):
            stub = plt.addr + hdr + i * ent
            if stub < plt.end:
                b.imports.append(Import(r.name, stub, r.addr))
    # data imports (GLOB_DAT): no stub, referenced through GOT
    have = {i.got for i in b.imports}
    for r in b.relocs:
        if r.name and r.addr not in have and ("GLOB_DAT" in r.kind or "JUMP_SLOT" in r.kind):
            b.imports.append(Import(r.name, 0, r.addr))
            have.add(r.addr)
    for imp in b.imports:
        if imp.addr:
            b.add_symbol(Symbol(imp.name, imp.addr, 0, "func", "plt"))

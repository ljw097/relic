"""ELF loader built on pyelftools."""
from __future__ import annotations

import bisect
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
    # disassembly (and function discovery) only: no decompiler for these
    "EM_SPARC": ("sparc", 32), "EM_SPARC32PLUS": ("sparc", 32), "EM_SPARCV9": ("sparc64", 64),
    "EM_S390": ("s390x", 64), "EM_68K": ("m68k", 32), "EM_SH": ("sh", 32), "EM_TRICORE": ("tricore", 32),
    "EM_BPF": ("bpf", 64),
}

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
PF_X, PF_W, PF_R = 1, 2, 4


def load_elf(path: str, data: bytes) -> Binary:
    b = Binary(path, data)
    b.format = "ELF"
    elf = ELFFile(io.BytesIO(data))
    arch = MACHINES.get(elf["e_machine"], ("unknown", elf.elfclass))[0]
    if arch == "mips" and elf.elfclass == 64:
        arch = "mips64"
    if arch == "riscv64" and elf.elfclass == 32:
        arch = "riscv32"
    b.arch, b.bits = arch, elf.elfclass
    b.endian = "little" if elf.little_endian else "big"
    b.entry = elf["e_entry"]
    if arch == "arm" and b.entry & 1:         # Thumb entry point
        b.entry &= ~1
        b.thumb_code.add(b.entry)
    b.info["type"] = elf["e_type"]
    b.info["machine"] = elf["e_machine"]
    if arch == "arm":
        # EF_ARM_ABI_FLOAT_HARD: floating-point arguments and results in VFP registers (armhf)
        b.arm_hard_float = bool(elf["e_flags"] & 0x400)
    b.elf_type = elf["e_type"]
    if b.elf_type == "ET_CORE":               # a core dump: the process's memory, registers and files
        from .core import load_core
        load_core(b, elf)
        b._finalize()
        return b
    if b.elf_type == "ET_REL":                # a relocatable object: lay it out and link it alone
        from .elfobj import load_elf_object
        load_elf_object(b, elf)
        b._finalize()
        return b

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
            if arch == "ppc64" and kind == "func":
                # ELFv2: callers sharing the TOC enter past the TOC setup (st_other bits 5-7)
                try:
                    v = int(sym["st_other"]["local"])
                except (KeyError, TypeError):
                    v = 0
                if 2 <= v <= 6:
                    b.ppc_local_entry[addr + (((1 << v) >> 2) << 2)] = addr
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
            kind = _RISCV_RELOCS.get(rel["r_info_type"], "") if b.arch == "riscv64" else ""
            b.relocs.append(Relocation(off, name, kind or describe_reloc_type(rel["r_info_type"], elf),
                                       rel["r_addend"] if rel.is_RELA() else 0))
            if name:
                got_names[off] = name
            elif rel.is_RELA() and rel["r_addend"] and "RELATIVE" in b.relocs[-1].kind and \
                    b.read_int(off, b.bits // 8) == 0:
                b.fill_relocation(off, rel["r_addend"], b.bits // 8)
    b.got_names = got_names

    if arch == "ppc64":
        got = next((s for s in b.sections if s.name == ".got"), None)
        if got is not None:
            b.ppc_toc = got.addr + 0x8000            # ELFv2's `.TOC.`
        _ppc64_descriptors(b)
    if arch.startswith("mips"):
        _resolve_mips_got(b, elf, got_names)
        if getattr(b, "mips_gp", None) is None:
            _mips_gp_from_reginfo(b, elf)
    _resolve_plt(b, got_names)
    b._finalize()
    return b


def _ppc64_descriptors(b: Binary):
    """PowerPC64 ELFv1: a function's symbol, the entry point and function pointers name its
    descriptor in `.opd` -- the code address, then the function's TOC (r2), then an environment
    pointer. The functions are at the code addresses (under the symbols' names: the descriptors
    become `name_desc`), and the TOC is the one the descriptors give."""
    opd = b.section(".opd")
    if opd is None or b.endian != "big":
        return
    descs: dict[int, int] = {}
    tocs: dict[int, int] = {}
    code_secs = [(sec.addr, sec.end) for sec in b.sections if sec.x and sec.loaded]   # (before _finalize)
    for a in range(opd.addr, opd.end - 15, 24):
        code = b.read_ptr(a)
        if code and any(lo <= code < hi for lo, hi in code_secs):
            descs[a] = code
            tocs[a] = b.read_ptr(a + 8) or 0
    if not descs:
        return
    b.func_descriptors = descs
    for sym in list(b.symbols.values()):
        code = descs.get(sym.addr)
        if code is None:
            continue
        b.symbols[sym.addr] = Symbol(f"{sym.name}_desc", sym.addr, 24, "object", sym.source)
        b.add_symbol(Symbol(sym.name, code, 0, "func", sym.source), override=True)
    b.function_starts = list(getattr(b, "function_starts", [])) + sorted(set(descs.values()))
    toc = tocs.get(b.entry) or next((t for t in tocs.values() if t), None)
    if b.entry in descs:
        b.entry = descs[b.entry]
    if toc:
        b.ppc_toc = toc


def _ppc_call_stubs(b: Binary, got_names: dict[int, str], found: dict[int, str]):
    """PowerPC calls go through stubs in `.text` that load a `.plt` slot into `ctr`:

        lis r11, hi ; lwz r11, lo(r11) ; mtctr r11 ; bctr          32-bit, absolute
        lwz r11, off(r30) ; mtctr r11 ; bctr                       32-bit PIC
        [std r2, 24(r1)] ; addis r12, r2, hi ; ld r12, lo(r12) ; mtctr r12 ; bctr   64-bit (r2 = TOC)

    A 32-bit PIC stub indexes from the `r30` of its callers: their object's `.got2` + 0x8000,
    which each builds with `bcl 20,31,.+4; mflr r30; addis r30,r30,hi; addi r30,r30,lo`."""
    bits = 64 if b.arch == "ppc64" else 32
    mode = (cs.CS_MODE_64 if bits == 64 else cs.CS_MODE_32) | \
        (cs.CS_MODE_BIG_ENDIAN if b.endian == "big" else cs.CS_MODE_LITTLE_ENDIAN)
    md = cs.Cs(cs.CS_ARCH_PPC, mode)
    md.detail = True
    md.skipdata = True                  # (words in .text that are not instructions: keep going)
    mask = (1 << bits) - 1
    toc = getattr(b, "ppc_toc", None)
    listings = [list(md.disasm(b.data[sec.offset:sec.offset + sec.size], sec.addr)) for sec in b.exec_sections]
    by_addr = {i.address: (insns, k) for insns in listings for k, i in enumerate(insns)}
    starts = sorted(s.addr for s in b.symbols.values() if s.kind == "func")

    def stub_at(addr):
        """(start, slot register, displacement, absolute slot or None) of the stub at `addr`."""
        pos = by_addr.get(addr)
        if pos is None:
            return None
        insns, k = pos
        seq = insns[k:k + 6]
        n = next((j for j, i in enumerate(seq) if i.mnemonic == "bctr"), None)
        if n is None or n < 2 or seq[n - 1].mnemonic != "mtctr":
            return None
        ld = seq[n - 2]
        if ld.mnemonic not in ("lwz", "ld") or len(ld.operands) != 2 or ld.operands[1].type != cs.ppc.PPC_OP_MEM:
            return None
        r = ld.reg_name(ld.operands[0].reg)
        base, disp = ld.reg_name(ld.operands[1].mem.base), ld.operands[1].mem.disp
        hi = seq[n - 3] if n >= 3 else None
        if base == "r2" and toc is not None:                  # `ld r12, off(r2)`: a TOC-relative slot
            start = addr
            return start, None, 0, (toc + disp) & mask
        if hi is not None and hi.mnemonic in ("lis", "addis") and base == r and hi.reg_name(hi.operands[0].reg) == r:
            imm = hi.operands[-1].imm << 16
            if hi.mnemonic == "lis":
                return addr, None, 0, (imm + disp) & mask
            src = hi.reg_name(hi.operands[1].reg)
            if src == "r2" and toc is not None:
                return addr, None, 0, (toc + imm + disp) & mask
            return None
        return addr, base, disp, None

    # absolute stubs: wherever they are
    for insns in listings:
        for i in insns:
            st = stub_at(i.address) if i.mnemonic in ("lis", "std", "addis") else None
            if st and st[3] in got_names and i.address not in found:
                b.imports.append(Import(got_names[st[3]], i.address, st[3]))
                found[i.address] = got_names[st[3]]
    # PIC stubs: through their callers' r30
    for insns in listings:
        r30 = None
        func = None
        for k, i in enumerate(insns):
            f = starts[bisect.bisect_right(starts, i.address) - 1] if starts and i.address >= starts[0] else None
            if f != func:
                func, r30 = f, None
            raw = int.from_bytes(i.bytes, "big" if b.endian == "big" else "little")
            if raw == 0x429F0005 and k + 3 < len(insns):         # bcl 20,31,.+4 (capstone: `bdnzl`)
                m, hi, lo = insns[k + 1:k + 4]
                if m.mnemonic == "mflr" and hi.mnemonic == "addis" and lo.mnemonic == "addi" and \
                        len(hi.operands) == 3 and len(lo.operands) == 3:
                    r30 = (m.address + (hi.operands[2].imm << 16) + lo.operands[2].imm) & mask
                continue
            if i.mnemonic != "bl" or r30 is None or not i.operands:
                continue
            t = i.operands[0].imm & mask
            if t in found:
                continue
            st = stub_at(t)
            if st and st[1] == "r30" and (r30 + st[2]) & mask in got_names:
                slot = (r30 + st[2]) & mask
                b.imports.append(Import(got_names[slot], t, slot))
                found[t] = got_names[slot]


# dynamic relocation types pyelftools does not name for RISC-V
_RISCV_RELOCS = {1: "R_RISCV_32", 2: "R_RISCV_64", 3: "R_RISCV_RELATIVE", 4: "R_RISCV_COPY",
                 5: "R_RISCV_JUMP_SLOT", 6: "R_RISCV_TLS_DTPMOD32", 7: "R_RISCV_TLS_DTPMOD64",
                 8: "R_RISCV_TLS_DTPREL32", 9: "R_RISCV_TLS_DTPREL64", 10: "R_RISCV_TLS_TPREL32",
                 11: "R_RISCV_TLS_TPREL64", 58: "R_RISCV_IRELATIVE"}


def _mips_gp_from_reginfo(b: Binary, elf: ELFFile):
    """`$gp` of a module without a dynamic GOT (a static binary): `ri_gp_value`, the word at
    offset 20 of `.reginfo` (after ri_gprmask and ri_cprmask[4]). It points 0x7ff0 past the
    small-data / GOT area, so that area must be mapped."""
    sec = elf.get_section_by_name(".reginfo")
    if sec is None:
        return
    raw = sec.data()
    if len(raw) < 24:
        return
    v = int.from_bytes(raw[20:24], b.endian)
    if v and b.is_mapped(v - 0x7FF0):
        b.mips_gp = v


def _resolve_mips_got(b: Binary, elf: ELFFile, got_names: dict[int, str]):
    """MIPS has no JUMP_SLOT relocations: the dynamic linker fills the global part of the GOT
    from the dynamic symbol table. GOT entry `local_gotno + (k - gotsym)` belongs to dynamic
    symbol k; an imported function's symbol value is its lazy-binding stub in `.MIPS.stubs`
    (0 when calls go straight through the GOT). Code reaches the GOT through `$gp`, which
    points 0x7ff0 bytes past its start (`_gp`, the same for every function of a module)."""
    d = b.dynamic
    got, local, gotsym, symtabno = (d.get(k) for k in ("DT_PLTGOT", "DT_MIPS_LOCAL_GOTNO", "DT_MIPS_GOTSYM",
                                                       "DT_MIPS_SYMTABNO"))
    if got is None:
        return
    b.mips_gp = got + 0x7FF0
    dynsym = elf.get_section_by_name(".dynsym")
    if local is None or gotsym is None or not isinstance(dynsym, SymbolTableSection):
        return
    word = b.bits // 8
    # the local part: page addresses and local symbols, only rebased by the dynamic linker
    b.mips_local_got = (got, got + local * word)
    count = symtabno if symtabno is not None else dynsym.num_symbols()
    for k in range(gotsym, count):
        sym = dynsym.get_symbol(k)
        name = sym.name.split("@")[0]
        if not name:
            continue
        slot = got + (local + k - gotsym) * word
        got_names.setdefault(slot, name)
        if sym["st_shndx"] != "SHN_UNDEF":
            continue                    # defined here: reached through the GOT, but not an import
        stub = sym["st_value"] if sym["st_info"]["type"] == "STT_FUNC" else 0
        b.imports.append(Import(name, stub, slot))


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
                a, ld = insns[i], insns[i + 1]
                if a.mnemonic == "adrp" and ld.mnemonic == "ldr":
                    try:
                        page = int(a.op_str.split("#")[-1], 16)
                        off = int(ld.op_str.split("#")[-1].rstrip("]!"), 16) if "#" in ld.op_str else 0
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
    elif b.arch.startswith("riscv"):
        # `auipc t3, %pcrel_hi(slot); l[dw] t3, %pcrel_lo(t3); jalr t1, t3; nop`
        bits = 64 if b.arch == "riscv64" else 32
        md = cs.Cs(cs.CS_ARCH_RISCV, (cs.CS_MODE_RISCV64 if bits == 64 else cs.CS_MODE_RISCV32) | cs.CS_MODE_RISCVC)
        md.detail = True
        mask = (1 << bits) - 1
        for sec in plt_secs:
            code = b.data[sec.offset:sec.offset + sec.size]
            insns = list(md.disasm(code, sec.addr))
            for k in range(len(insns) - 1):
                a, ld = insns[k], insns[k + 1]
                if a.mnemonic != "auipc" or ld.mnemonic not in ("ld", "lw"):
                    continue
                ao, lo = a.operands, ld.operands
                if len(ao) != 2 or len(lo) != 2 or lo[1].type != cs.riscv.RISCV_OP_MEM or \
                        lo[1].mem.base != ao[0].reg:
                    continue
                slot = (a.address + (ao[1].imm << 12) + lo[1].mem.disp) & mask
                if slot in got_names and a.address not in found:
                    b.imports.append(Import(got_names[slot], a.address, slot))
                    found[a.address] = got_names[slot]
    elif b.arch in ("ppc", "ppc64"):
        _ppc_call_stubs(b, got_names, found)
    # fallback: order of .rela.plt entries -> sequential PLT stubs
    if not found and plt_secs and got_names and not b.arch.startswith("ppc"):
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
        # (RISC-V has no GLOB_DAT: a symbol's GOT slot is an R_RISCV_64 in .got; PowerPC PIC code
        # reads `.got2` / `.toc` words relocated by R_PPC_ADDR32 / R_PPC64_ADDR64)
        got_slot = r.kind in ("R_RISCV_64", "R_PPC_ADDR32", "R_PPC64_ADDR64") and \
            any(s.name in (".got", ".got2", ".toc") and s.addr <= r.addr < s.addr + s.size for s in b.sections)
        if r.name and r.addr not in have and ("GLOB_DAT" in r.kind or "JUMP_SLOT" in r.kind or got_slot):
            b.imports.append(Import(r.name, 0, r.addr))
            have.add(r.addr)
    for imp in b.imports:
        if imp.addr:
            b.add_symbol(Symbol(imp.name, imp.addr, 0, "func", "plt"))

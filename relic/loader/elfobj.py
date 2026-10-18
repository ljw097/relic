"""Relocatable ELF objects (`.o`): laid out and linked as far as one file allows.

A relocatable object has no addresses: every section starts at 0 and the code refers to
symbols through relocations. To analyse it like a program, its allocatable sections are laid
out one after another (aligned) from BASE, its symbols get the addresses that follows, every
symbol it uses without defining (`printf`, another object's function) gets a stub in an
`.extern` section (an import, so calls read `printf(...)`), symbols reached through the GOT
get a slot in a `.got` section, and the relocations are applied to a copy of the code: calls,
branches, address computations and data pointers then hold real addresses.

Relocation kinds applied: x86-64, x86, AArch64, ARM / Thumb, MIPS (o32, including the GOT
forms -mabicalls code uses) and RISC-V. Others are left as the compiler wrote them.
"""
from __future__ import annotations

from .base import Binary, Import, Relocation, Section, Segment, Symbol

BASE = 0x100000
STUB = 16                     # bytes per extern stub


def _align(v: int, a: int) -> int:
    return (v + a - 1) // a * a if a > 1 else v


def _sx(v: int, bits: int) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


class _Image:
    def __init__(self, size: int, endian: str):
        self.buf = bytearray(size)
        self.endian = endian

    def get(self, off: int, n: int) -> int:
        return int.from_bytes(self.buf[off:off + n], self.endian)

    def put(self, off: int, n: int, v: int):
        self.buf[off:off + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, self.endian)

    def get16le(self, off: int) -> int:              # Thumb halfwords are little-endian here
        return int.from_bytes(self.buf[off:off + 2], "little")


def load_elf_object(b: Binary, elf) -> None:
    """Fill `b` (format, arch, bits and endian set) from the relocatable ELF `elf`."""
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    word = b.bits // 8
    # 1. layout
    secs = {}                                     # section index -> (address, section)
    addr = BASE
    for k, sec in enumerate(elf.iter_sections()):
        h = sec.header
        if not h.sh_flags & 2 or not h.sh_size:   # SHF_ALLOC
            continue
        addr = _align(addr, max(h.sh_addralign, 1))
        secs[k] = (addr, sec)
        addr += h.sh_size
    symtab = next((s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)), None)
    # 2. what is used without being defined, and what is reached through a GOT
    externs: dict[str, int] = {}
    got_syms: dict[tuple, int] = {}
    got_kinds = {"x64": {9, 41, 42}, "arm64": {311, 312}, "riscv64": {20}, "riscv32": {20},
                 "mips": {9, 11, 29, 30, 31}}.get(b.arch, set())
    relsecs = [rs for rs in elf.iter_sections() if isinstance(rs, RelocationSection) and rs["sh_info"] in secs]
    for rs in relsecs:
        st = elf.get_section(rs["sh_link"])
        for r in rs.iter_relocations():
            if not r["r_info_sym"] or not isinstance(st, SymbolTableSection):
                continue
            sym = st.get_symbol(r["r_info_sym"])
            if sym["st_shndx"] == "SHN_UNDEF" and sym.name:
                externs.setdefault(sym.name, 0)
            if r["r_info_type"] in got_kinds:
                got_syms.setdefault((sym.name, r["r_info_sym"]), 0)
    ext_start = _align(addr, 16)
    for k, name in enumerate(sorted(externs)):
        externs[name] = ext_start + k * STUB
    got_start = _align(ext_start + len(externs) * STUB, 16)
    for k, key in enumerate(sorted(got_syms, key=str)):
        got_syms[key] = got_start + k * word
    end = got_start + len(got_syms) * word
    img = _Image(end - BASE, b.endian)
    for a, sec in secs.values():
        if sec.header.sh_type != "SHT_NOBITS":
            img.buf[a - BASE:a - BASE + sec.header.sh_size] = sec.data()
    stub = {"x64": b"\xc3", "x86": b"\xc3"}.get(b.arch, b"")
    for a in externs.values():
        img.buf[a - BASE:a - BASE + len(stub)] = stub
    # 3. symbols
    def sym_addr(sym) -> int:
        shndx = sym["st_shndx"]
        if shndx == "SHN_UNDEF":
            return externs.get(sym.name, 0)
        if shndx == "SHN_ABS":
            return sym["st_value"]
        if shndx == "SHN_COMMON":
            return commons.get(sym.name, 0)
        if isinstance(shndx, int) and shndx in secs:
            return secs[shndx][0] + sym["st_value"]
        return 0
    commons: dict[str, int] = {}
    if symtab is not None:                         # tentative definitions (`int counter;` with -fcommon)
        for sym in symtab.iter_symbols():
            if sym["st_shndx"] == "SHN_COMMON" and sym.name:
                commons[sym.name] = 0
        if commons:
            cstart = _align(end, 16)
            for k, name in enumerate(sorted(commons)):
                commons[name] = cstart + k * 16
            img.buf += bytes(cstart - end + len(commons) * 16)
            end = cstart + len(commons) * 16
    if symtab is not None:
        for sym in symtab.iter_symbols():
            t = sym["st_info"]["type"]
            if not sym.name or sym["st_shndx"] == "SHN_UNDEF":
                continue
            a = sym_addr(sym)
            if b.arch == "arm" and sym.name[:2] in ("$a", "$t", "$d") and sym.name[2:3] in ("", "."):
                b.arm_mapping[a] = sym.name[1]
                continue
            kind = {"STT_FUNC": "func", "STT_OBJECT": "object", "STT_GNU_IFUNC": "func"}.get(t)
            if kind is None and not (t == "STT_NOTYPE" and sym["st_info"]["bind"] != "STB_LOCAL"):
                continue
            if b.arch == "arm" and kind == "func":
                if a & 1:
                    b.thumb_code.add(a & ~1)
                a &= ~1
            s = Symbol(sym.name, a, sym["st_size"], kind or "func", "symtab")
            b.add_symbol(s)
            if sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                b.exports.append(s)
    slot_of = {name: slot for (name, _i), slot in got_syms.items() if name}
    for name, a in externs.items():
        b.imports.append(Import(name, a, slot_of.get(name, 0), ""))     # (reached through a GOT slot too)
    # 4. GOT slots hold what they point to
    for (_name, idx), slot in got_syms.items():
        sym = elf.get_section(relsecs[0]["sh_link"]).get_symbol(idx) if relsecs else None
        if sym is not None:
            img.put(slot - BASE, word, sym_addr(sym))
    # 5. relocations
    applier = _APPLY.get(b.arch)
    for rs in relsecs:
        base_addr = secs[rs["sh_info"]][0]
        st = elf.get_section(rs["sh_link"])
        rels = list(rs.iter_relocations())
        hi_values: dict[int, int] = {}            # RISC-V: value a PCREL_HI20 at an offset computed
        for k, r in enumerate(rels):
            sym = st.get_symbol(r["r_info_sym"]) if r["r_info_sym"] and isinstance(st, SymbolTableSection) else None
            S = sym_addr(sym) if sym is not None else 0
            P = base_addr + r["r_offset"]
            G = got_syms.get((sym.name, r["r_info_sym"]), 0) if sym is not None else 0
            A = r["r_addend"] if r.is_RELA() else None
            name = sym.name if sym is not None and sym["st_info"]["type"] != "STT_SECTION" else ""
            b.relocs.append(Relocation(P, name, str(r["r_info_type"]), A or 0))
            if applier is not None:
                try:
                    applier(img, r["r_info_type"], P - BASE, S, A, P, G, ctx={
                        "rels": rels, "k": k, "symtab": st, "sym_addr": sym_addr, "base": base_addr,
                        "hi": hi_values, "got": got_start, "gp": got_start + 0x7FF0,
                        "local": sym is not None and (sym["st_info"]["bind"] == "STB_LOCAL" or
                                                      sym["st_info"]["type"] == "STT_SECTION")})
                except (IndexError, ValueError):
                    continue
    # 6. the image
    b.data = bytes(img.buf)
    for a, sec in secs.values():
        h = sec.header
        b.sections.append(Section(sec.name, a, h.sh_size, a - BASE, True, bool(h.sh_flags & 1),
                                  bool(h.sh_flags & 4), True))
        b.segments.append(Segment(a, h.sh_size, a - BASE, h.sh_size, True, bool(h.sh_flags & 1),
                                  bool(h.sh_flags & 4)))
    if externs:
        b.sections.append(Section(".extern", ext_start, len(externs) * STUB, ext_start - BASE, True, False, True))
        b.segments.append(Segment(ext_start, len(externs) * STUB, ext_start - BASE, len(externs) * STUB,
                                  True, False, True))
    if got_syms:
        n = len(got_syms) * word
        b.sections.append(Section(".got", got_start, n, got_start - BASE, True, True, False))
        b.segments.append(Segment(got_start, n, got_start - BASE, n, True, True, False))
        if b.arch == "mips":
            b.mips_gp = got_start + 0x7FF0
            b.mips_local_got = (got_start, got_start)
            b.got_names = {slot: name for (name, _i), slot in got_syms.items() if name}
    if commons:
        cstart = min(commons.values())
        n = len(commons) * 16
        b.sections.append(Section(".common", cstart, n, cstart - BASE, True, True, False))
        b.segments.append(Segment(cstart, n, cstart - BASE, n, True, True, False))
    b.sections.sort(key=lambda s: s.addr)
    b.segments.sort(key=lambda s: s.addr)
    main = next((s.addr for s in b.symbols.values() if s.name == "main"), None)
    b.entry = main if main is not None else next((s.addr for s in b.sections if s.x), BASE)
    b.base = BASE
    b.info["layout"] = f"relocatable object: sections from {BASE:#x}, {len(externs)} external symbols"


# ------------------------------------------------------------------ appliers
def _x64(img, t, off, S, A, P, G, ctx):
    if A is None:
        A = _sx(img.get(off, 4), 32)
    if t == 1:                                    # R_X86_64_64
        img.put(off, 8, S + A)
    elif t in (2, 4, 24):                         # PC32, PLT32, PC64 (4 bytes here)
        img.put(off, 4, S + A - P)
    elif t in (10, 11):                           # 32, 32S
        img.put(off, 4, S + A)
    elif t in (9, 41, 42) and G:                  # GOTPCREL(X): the slot holding S
        img.put(off, 4, G + A - P)


def _x86(img, t, off, S, A, P, G, ctx):
    if A is None:
        A = _sx(img.get(off, 4), 32)
    if t == 1:                                    # R_386_32
        img.put(off, 4, S + A)
    elif t in (2, 4):                             # PC32, PLT32
        img.put(off, 4, S + A - P)


def _arm64(img, t, off, S, A, P, G, ctx):
    A = A or 0
    w = img.get(off, 4)
    if t == 257:                                  # ABS64
        img.put(off, 8, S + A)
    elif t == 258:                                # ABS32
        img.put(off, 4, S + A)
    elif t == 261:                                # PREL32
        img.put(off, 4, S + A - P)
    elif t in (282, 283):                         # JUMP26, CALL26
        img.put(off, 4, (w & 0xFC000000) | (((S + A - P) >> 2) & 0x3FFFFFF))
    elif t in (275, 311):                         # ADR_PREL_PG_HI21, ADR_GOT_PAGE
        target = G if t == 311 else S + A
        v = ((target & ~0xFFF) - (P & ~0xFFF)) >> 12
        img.put(off, 4, (w & 0x9F00001F) | ((v & 3) << 29) | (((v >> 2) & 0x7FFFF) << 5))
    elif t == 274:                                # ADR_PREL_LO21
        v = S + A - P
        img.put(off, 4, (w & 0x9F00001F) | ((v & 3) << 29) | (((v >> 2) & 0x7FFFF) << 5))
    elif t in (277, 278, 284, 285, 286, 299, 312):  # ADD / LDST lo12, LD64_GOT_LO12_NC
        shift = {278: 0, 284: 1, 285: 2, 286: 3, 299: 4, 312: 3}.get(t, 0)
        v = ((G if t == 312 else S + A) & 0xFFF) >> shift
        img.put(off, 4, (w & ~(0xFFF << 10)) | ((v & 0xFFF) << 10))
    elif t in (280, 273):                         # CONDBR19, LD_PREL_LO19
        img.put(off, 4, (w & ~(0x7FFFF << 5)) | ((((S + A - P) >> 2) & 0x7FFFF) << 5))
    elif t == 279:                                # TSTBR14
        img.put(off, 4, (w & ~(0x3FFF << 5)) | ((((S + A - P) >> 2) & 0x3FFF) << 5))


def _arm(img, t, off, S, A, P, G, ctx):
    w = img.get(off, 4)
    if t == 2:                                    # ABS32
        img.put(off, 4, S + (_sx(w, 32) if A is None else A))
    elif t == 3:                                  # REL32
        img.put(off, 4, S + (_sx(w, 32) if A is None else A) - P)
    elif t in (28, 29, 1):                        # CALL, JUMP24, PC24: imm24, A in the instruction
        a = (_sx(w & 0xFFFFFF, 24) << 2) if A is None else A
        img.put(off, 4, (w & 0xFF000000) | (((S + a - P) >> 2) & 0xFFFFFF))
    elif t in (10, 30):                           # THM_CALL, THM_JUMP24: two halfwords
        h1, h2 = img.get16le(off), img.get16le(off + 2)
        if A is None:
            s_ = (h1 >> 10) & 1
            j1, j2 = (h2 >> 13) & 1, (h2 >> 11) & 1
            i1, i2 = 1 - (j1 ^ s_), 1 - (j2 ^ s_)
            a = _sx((s_ << 24) | (i1 << 23) | (i2 << 22) | ((h1 & 0x3FF) << 12) | ((h2 & 0x7FF) << 1), 25)
        else:
            a = A
        v = (S & ~1) + a - P
        if t == 10 and not S & 1 and not h2 & 0x1000:   # (blx to ARM code)
            v = (S & ~3) + a - (P & ~3)
        s_ = (v >> 24) & 1
        i1, i2 = (v >> 23) & 1, (v >> 22) & 1
        j1, j2 = 1 - (i1 ^ s_), 1 - (i2 ^ s_)
        h1 = (h1 & 0xF800) | (s_ << 10) | ((v >> 12) & 0x3FF)
        h2 = (h2 & 0xD000) | (j1 << 13) | (j2 << 11) | ((v >> 1) & 0x7FF)
        img.buf[off:off + 4] = h1.to_bytes(2, "little") + h2.to_bytes(2, "little")
    elif t in (43, 44):                           # MOVW_ABS_NC, MOVT_ABS
        a = (((w >> 4) & 0xF000) | (w & 0xFFF)) if A is None else A
        v = (S + _sx(a, 16)) & 0xFFFF if t == 43 else ((S + _sx(a, 16)) >> 16) & 0xFFFF
        img.put(off, 4, (w & 0xFFF0F000) | ((v & 0xF000) << 4) | (v & 0xFFF))
    elif t in (47, 48):                           # THM_MOVW_ABS_NC, THM_MOVT_ABS
        h1, h2 = img.get16le(off), img.get16le(off + 2)
        v = (S + (A or 0)) & 0xFFFF if t == 47 else ((S + (A or 0)) >> 16) & 0xFFFF
        h1 = (h1 & 0xFBF0) | (((v >> 11) & 1) << 10) | ((v >> 12) & 0xF)
        h2 = (h2 & 0x8F00) | (((v >> 8) & 7) << 12) | (v & 0xFF)
        img.buf[off:off + 4] = h1.to_bytes(2, "little") + h2.to_bytes(2, "little")


def _mips(img, t, off, S, A, P, G, ctx):
    w = img.get(off, 4)
    if t == 2:                                    # R_MIPS_32
        img.put(off, 4, S + (_sx(w, 32) if A is None else A))
    elif t == 4:                                  # R_MIPS_26
        a = ((w & 0x3FFFFFF) << 2) if A is None else A
        img.put(off, 4, (w & 0xFC000000) | ((((a | (P & 0xF0000000)) + S) >> 2) & 0x3FFFFFF))
    elif t in (5, 9):                             # HI16 / GOT16 (local): with the LO16 after it
        rels, k = ctx["rels"], ctx["k"]
        lo = next((r for r in rels[k + 1:] if r["r_info_type"] == 6), None)
        lo_a = _sx(img.get(lo["r_offset"] + ctx["base"] - BASE, 4) & 0xFFFF, 16) if lo is not None else 0
        ahl = ((w & 0xFFFF) << 16) + lo_a if A is None else A
        if t == 5:
            img.put(off, 4, (w & 0xFFFF0000) | (((S + ahl + 0x8000) >> 16) & 0xFFFF))
        elif G and not ctx.get("local"):          # a global symbol: its slot holds its address
            img.put(off, 4, (w & 0xFFFF0000) | ((G - ctx["gp"]) & 0xFFFF))
        elif G:                                   # the slot holds the 64K page; the LO16 adds the rest
            page = (S + ahl + 0x8000) & ~0xFFFF
            img.put(G - BASE, 4, page)
            img.put(off, 4, (w & 0xFFFF0000) | ((G - ctx["gp"]) & 0xFFFF))
    elif t == 6:                                  # LO16
        a = _sx(w & 0xFFFF, 16) if A is None else A
        img.put(off, 4, (w & 0xFFFF0000) | ((S + a) & 0xFFFF))
    elif t in (11, 29, 30, 31) and G:             # CALL16, GOT_DISP / PAGE / OFST: a GOT slot, gp-relative
        img.put(off, 4, (w & 0xFFFF0000) | ((G - ctx["gp"]) & 0xFFFF))


def _rv_hi(v: int) -> int:
    return ((v + 0x800) >> 12) & 0xFFFFF


def _riscv(img, t, off, S, A, P, G, ctx):
    A = A or 0
    w = img.get(off, 4)
    if t == 1:
        img.put(off, 4, S + A)
    elif t == 2:
        img.put(off, 8, S + A)
    elif t in (18, 19):                           # CALL / CALL_PLT: auipc + jalr
        v = S + A - P
        img.put(off, 4, (w & 0xFFF) | (_rv_hi(v) << 12))
        w2 = img.get(off + 4, 4)
        img.put(off + 4, 4, (w2 & 0xFFFFF) | ((v & 0xFFF) << 20))
    elif t in (23, 20):                           # PCREL_HI20 / GOT_HI20
        v = (G if t == 20 else S + A) - P
        ctx["hi"][P] = v
        img.put(off, 4, (w & 0xFFF) | (_rv_hi(v) << 12))
    elif t in (24, 25):                           # PCREL_LO12_I / _S: the value of the HI20 at S
        v = ctx["hi"].get(S, 0)
        if t == 24:
            img.put(off, 4, (w & 0xFFFFF) | ((v & 0xFFF) << 20))
        else:
            img.put(off, 4, (w & 0x1FFF07F) | (((v >> 5) & 0x7F) << 25) | ((v & 0x1F) << 7))
    elif t == 26:                                 # HI20
        img.put(off, 4, (w & 0xFFF) | (_rv_hi(S + A) << 12))
    elif t == 27:                                 # LO12_I
        img.put(off, 4, (w & 0xFFFFF) | (((S + A) & 0xFFF) << 20))
    elif t == 28:                                 # LO12_S
        v = S + A
        img.put(off, 4, (w & 0x1FFF07F) | (((v >> 5) & 0x7F) << 25) | ((v & 0x1F) << 7))
    elif t == 17:                                 # JAL
        v = S + A - P
        enc = (((v >> 20) & 1) << 31) | (((v >> 1) & 0x3FF) << 21) | (((v >> 11) & 1) << 20) | \
            (((v >> 12) & 0xFF) << 12)
        img.put(off, 4, (w & 0xFFF) | enc)
    elif t == 16:                                 # BRANCH
        v = S + A - P
        enc = (((v >> 12) & 1) << 31) | (((v >> 5) & 0x3F) << 25) | (((v >> 1) & 0xF) << 8) | \
            (((v >> 11) & 1) << 7)
        img.put(off, 4, (w & 0x1FFF07F) | enc)
    elif t == 44:                                 # RVC_BRANCH
        v = S + A - P
        h = img.get(off, 2)
        enc = (((v >> 8) & 1) << 12) | (((v >> 3) & 3) << 10) | (((v >> 6) & 3) << 5) | \
            (((v >> 1) & 3) << 3) | (((v >> 5) & 1) << 2)
        img.put(off, 2, (h & 0xE383) | enc)
    elif t == 45:                                 # RVC_JUMP
        v = S + A - P
        h = img.get(off, 2)
        enc = (((v >> 11) & 1) << 12) | (((v >> 4) & 1) << 11) | (((v >> 8) & 3) << 9) | \
            (((v >> 10) & 1) << 8) | (((v >> 6) & 1) << 7) | (((v >> 7) & 1) << 6) | \
            (((v >> 1) & 7) << 3) | (((v >> 5) & 1) << 2)
        img.put(off, 2, (h & 0xE003) | enc)


_APPLY = {"x64": _x64, "x86": _x86, "arm64": _arm64, "arm": _arm, "mips": _mips,
          "riscv64": _riscv, "riscv32": _riscv}

__all__ = ["BASE", "load_elf_object"]

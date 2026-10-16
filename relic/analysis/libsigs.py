"""Library signatures: name the library functions linked into a stripped static binary.

A signature is a library function's machine code with the bytes the linker fills in
(relocations) masked out. They are built from static libraries (`libc.a`: an `ar` archive
of relocatable ELF objects) once:

    relic sigs build /usr/lib/x86_64-linux-gnu/libc.a -o ~/.relic/sigs/glibc-x64.sig

and every analysis then names the functions whose code matches one (`sub_401a20` becomes
`strlen`), when they have no symbol of their own. Signature files are looked for in the
directories of `RELIC_SIGS` (separated like PATH) and `~/.relic/sigs`.

Matching: functions are indexed by their first bytes under each distinct mask of a
signature's first 16 bytes, then the whole masked pattern is compared. The longest pattern
that matches wins; a pattern several unrelated names share is skipped (aliases of one
symbol -- `__libc_malloc` and `malloc` -- are one name, the public one). Short patterns
(fewer than MIN_FIXED known bytes) are not used: they would name unrelated stubs.
"""
from __future__ import annotations

import bisect
import gzip
import io
import json
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from . import Analysis

MIN_FIXED = 12      # known (unmasked) bytes a pattern needs to be used
REF_WEIGHT = 4      # ... where each checked reference counts as this many bytes
MIN_SHORT = 16      # (a shorter pattern needs this much with its references counted)
LONG_FIXED = 64     # known bytes past which a match needs no check of where the function ends
PREFIX_FIXED = 32   # known bytes a prefix signature needs (function prologues look alike)
PREFIX = 16         # bytes indexed for lookup
MAX_LEN = 4096      # bytes of a function compared at most

_ARCH = {"EM_X86_64": "x64", "EM_386": "x86", "EM_ARM": "arm", "EM_AARCH64": "arm64", "EM_MIPS": "mips",
         "EM_RISCV": "riscv64"}

# relocation types patching 8 bytes (the rest patch 4: data words and instruction words alike)
_WIDE = {"x64": {1, 24, 25, 27, 28, 29, 31, 33}, "arm64": {257}, "riscv64": {2}}
# ARM / AArch64 relocations filling only some bits of an instruction: type -> (bits it may
# change, as a little-endian int over `size` bytes). The opcode and registers around them stay
# known. Others (data words, GOT and TLS sequences the linker may relax) mask whole fields.
_A64_PAGE, _A64_LO12, _A64_B26 = 0x60FFFFE0, 0x003FFC00, 0x03FFFFFF
_FIELDS = {
    "arm64": {275: (_A64_PAGE, 4), 276: (_A64_PAGE, 4), 274: (_A64_PAGE, 4),     # adrp / adr
              277: (_A64_LO12, 4), 278: (_A64_LO12, 4), 284: (_A64_LO12, 4),     # add / ldst lo12
              285: (_A64_LO12, 4), 286: (_A64_LO12, 4), 299: (_A64_LO12, 4),
              282: (_A64_B26, 4), 283: (_A64_B26, 4),                            # b / bl
              280: (0x00FFFFE0, 4), 273: (0x00FFFFE0, 4), 279: (0x0007FFE0, 4),  # b.cond, ldr lit, tbz
              263: (0x001FFFE0, 4), 264: (0x001FFFE0, 4), 265: (0x001FFFE0, 4),  # movz / movk
              266: (0x001FFFE0, 4), 267: (0x001FFFE0, 4), 268: (0x001FFFE0, 4), 269: (0x001FFFE0, 4)},
    # Thumb-2 halfwords (first in the low 16 bits); bl / b.w may become blx (bit 12 of the second)
    "arm": {10: (0x3FFF07FF, 4), 30: (0x3FFF07FF, 4),                            # THM_CALL / JUMP24
            51: (0x2FFF043F, 4),                                                 # THM_JUMP19
            47: (0x70FF040F, 4), 48: (0x70FF040F, 4),                            # THM_MOVW / MOVT
            102: (0x07FF, 2), 103: (0x00FF, 2),                                  # THM_JUMP11 / JUMP8
            # ARM: bl / b may become blx (the condition field and bit 24 change too)
            1: (0xF1FFFFFF, 4), 28: (0xF1FFFFFF, 4), 29: (0xF1FFFFFF, 4),
            43: (0x000F0FFF, 4), 44: (0x000F0FFF, 4)},                           # MOVW / MOVT
    # MIPS: the 26-bit jump field, 16-bit immediates (%hi / %lo / %got / %call16 / branches);
    # R_MIPS_JALR is a hint the linker may act on (jalr -> bal): whole word
    "mips": {4: (0x03FFFFFF, 4), 5: (0xFFFF, 4), 6: (0xFFFF, 4), 7: (0xFFFF, 4), 9: (0xFFFF, 4),
             10: (0xFFFF, 4), 11: (0xFFFF, 4), 19: (0xFFFF, 4), 20: (0xFFFF, 4), 21: (0xFFFF, 4),
             22: (0xFFFF, 4), 23: (0xFFFF, 4), 30: (0xFFFF, 4), 31: (0xFFFF, 4)},
    # RISC-V: U (auipc / lui), I, S and B immediates, jal, an unrelaxed call (auipc + jalr), the
    # compressed branches and jumps
    "riscv64": {23: (0xFFFFF000, 4), 26: (0xFFFFF000, 4), 20: (0xFFFFF000, 4),
                24: (0xFFF00000, 4), 27: (0xFFF00000, 4), 25: (0xFE000F80, 4), 28: (0xFE000F80, 4),
                16: (0xFE000F80, 4), 17: (0xFFFFF000, 4), 18: (0xFFF00000_FFFFF000, 8),
                19: (0xFFF00000_FFFFF000, 8), 44: (0x1C7C, 2), 45: (0x1FFC, 2)},
}
# relocations storing a whole pointer (in data: vtables, tables of function pointers)
_ABS_PTR = {"x64": 1, "x86": 1, "arm64": 257, "arm": 2, "mips": 2, "riscv64": 2}
_PTR_SIZE = {"x64": 8, "arm64": 8, "riscv64": 8, "x86": 4, "arm": 4, "mips": 4}
_RELA = {"x64", "arm64", "riscv64"}

# RISC-V R_RISCV_RELAX (the relocation at the same place may be relaxed: code after it moves)
# and R_RISCV_ALIGN (nops the linker deletes)
_RV_MOVES = {51, 43}

# x86-64 relocations the linker may rewrite the instruction around (GOT relaxation, TLS models)
_X64_RELAX = {41: 3, 42: 3, 9: 3}          # GOTPCREL(X): opcode / ModRM / REX before the field
_X64_TLS = {19, 20, 22, 23}                # TLSGD, TLSLD, GOTTPOFF, TPOFF32: whole sequences change


def _public(names: list[str]) -> str:
    """The public name of an alias set (global symbols first, then weak ones): the first
    without leading underscores (`strchr` before its weak alias `index`), else the shortest."""
    plain = [n for n in names if not n.startswith("_")]
    return plain[0] if plain else min(names, key=lambda n: (len(n), n))


_CTOR_VARIANT = re.compile(r"([CD])2(?=E)")


def _plain(name: str) -> str:
    """A name without decoration that tells aliases apart: leading underscores, glibc's `libc_`
    prefix, and C++'s base-object constructor / destructor (`C2` / `D2`), which is the
    complete-object one's code (`C1` / `D1`) when there are no virtual bases."""
    n = name.lstrip("_")
    n = n[5:] if n.startswith("libc_") else n
    return _CTOR_VARIANT.sub(r"\g<1>1", n) if n.startswith("Z") else n


@dataclass
class Signature:
    # one alias set (names of one symbol address in one object) per place this code was found:
    # several sets with unrelated names (`mq_close`, `__close_nocancel`) make the code ambiguous.
    # An IFUNC's resolver (the code behind an STT_GNU_IFUNC symbol) is named `<name>_ifunc`
    groups: list[list[str]]
    pattern: bytes
    mask: bytes                    # bits that must match (0: filled in by the linker)
    # what the masked bytes refer to: (offset of the relocated field, symbol name)
    refs: list[tuple[int, str]] = field(default_factory=list)
    # only the start of the function: past it the linker may move code (RISC-V relaxation
    # shortens calls), so it says nothing about where the function ends
    prefix: bool = False

    @property
    def fixed(self) -> int:
        """Known bytes (bits / 8)."""
        return sum(bin(m).count("1") for m in self.mask) // 8

    @property
    def names(self) -> list[str]:
        return sorted({n for g in self.groups for n in g})

    @property
    def name(self) -> str | None:
        """The function's name, or None when the same code has unrelated names."""
        publics = {_public(g) for g in self.groups}
        if len({_plain(n) for n in publics}) != 1:
            return None
        return _public(sorted(publics))


@dataclass
class SigDB:
    arch: str
    sigs: list[Signature] = field(default_factory=list)
    source: str = ""
    # data objects holding pointers (vtables, tables of function pointers): name -> [its size,
    # the pointers it holds: [offset, name pointed to, 1 when that is a function], ...]
    tables: dict[str, list] = field(default_factory=dict)

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        data = {"arch": self.arch, "source": self.source,
                "sigs": [_entry(s) for s in self.sigs]}
        if self.tables:
            data["tables"] = self.tables
        with gzip.open(path, "wt") as fp:
            json.dump(data, fp)

    @classmethod
    def load(cls, path: str) -> "SigDB":
        with gzip.open(path, "rt") as fp:
            data = json.load(fp)
        db = cls(data["arch"], source=data.get("source", path), tables=data.get("tables", {}))
        for groups, text, *rest in data["sigs"]:
            pattern, mask = _decode(text)
            if len(rest) > 1 and rest[1]:        # some bytes only partly known
                mask = bytes.fromhex(rest[1])
            db.sigs.append(Signature(groups, pattern, mask, [tuple(r) for r in rest[0]] if rest else [],
                                     len(rest) > 2 and bool(rest[2])))
        return db


def _entry(s: Signature) -> list:
    """[groups, pattern text, refs] (+ full mask when some bytes are only partly known, + 1 for a
    prefix signature)."""
    out = [s.groups, _encode(s.pattern, s.mask), s.refs]
    partial = any(m not in (0, 0xFF) for m in s.mask)
    if partial or s.prefix:
        out.append(s.mask.hex() if partial else "")
    if s.prefix:
        out.append(1)
    return out


def _encode(pattern: bytes, mask: bytes) -> str:
    return "".join(f"{b:02x}" if m else ".." for b, m in zip(pattern, mask))


_MASK_CHARS = str.maketrans("0123456789abcdef.", "ffffffffffffffff0")


def _decode(text: str) -> tuple[bytes, bytes]:
    return bytes.fromhex(text.replace("..", "00")), bytes.fromhex(text.translate(_MASK_CHARS))


# ---------------------------------------------------------------- building
def ar_members(data: bytes) -> Iterator[tuple[str, bytes]]:
    """(name, contents) of every member of an `ar` archive (GNU long names understood)."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    pos, longnames = 8, b""
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("latin-1").rstrip()
        size = int(hdr[48:58].decode().strip() or 0)
        body = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name == "//":
            longnames = body
            continue
        if name in ("/", "/SYM64/"):
            continue                    # symbol index
        if name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            name = longnames[off:longnames.index(b"\n", off)].decode("latin-1")
        yield name.rstrip("/"), body


def object_signatures(data: bytes, tables: dict | None = None) -> tuple[str, list[Signature]]:
    """The arch and the function signatures of one relocatable ELF object; with `tables`, the
    pointers its data objects hold are added to it too (see SigDB.tables)."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
    elf = ELFFile(io.BytesIO(data))
    arch = _ARCH.get(elf["e_machine"], "unknown")
    if elf["e_type"] != "ET_REL":
        return arch, []
    symtab = next((s for s in elf.iter_sections() if isinstance(s, SymbolTableSection)), None)
    if symtab is None:
        return arch, []
    # masked bytes per section: what relocations fill in
    masks: dict[int, bytearray] = {}
    moves: dict[int, list[int]] = {}         # section -> offsets past which code may move
    refs: dict[int, list[tuple[int, str]]] = {}
    for rs in elf.iter_sections():
        if not isinstance(rs, RelocationSection):
            continue
        target = rs["sh_info"]
        sec = elf.get_section(target)
        if sec["sh_type"] != "SHT_PROGBITS" or not sec["sh_flags"] & 4:      # SHF_EXECINSTR
            continue
        m = masks.setdefault(target, bytearray(b"\xff" * sec["sh_size"]))
        rsym = elf.get_section(rs["sh_link"])
        for r in rs.iter_relocations():
            off, t = r["r_offset"], r["r_info_type"]
            if arch == "riscv64" and t in _RV_MOVES:
                moves.setdefault(rs["sh_info"], []).append(off)
                continue
            weak_undef = False
            if r["r_info_sym"] and isinstance(rsym, SymbolTableSection):
                target = rsym.get_symbol(r["r_info_sym"])
                if target.name and target["st_info"]["type"] != "STT_SECTION":
                    refs.setdefault(rs["sh_info"], []).append((off, target.name))
                # a call to a weak symbol nothing defines becomes a nop: the whole word changes
                weak_undef = target["st_info"]["bind"] == "STB_WEAK" and target["st_shndx"] == "SHN_UNDEF"
            bits = None if weak_undef else _FIELDS.get(arch, {}).get(t)
            if bits is not None:
                change, size = bits
                for k in range(size):
                    if 0 <= off + k < len(m):
                        m[off + k] &= ~(change >> (8 * k)) & 0xFF
                continue
            lo, hi = off, off + (8 if t in _WIDE.get(arch, ()) else 4)
            if arch == "x64":
                lo -= _X64_RELAX.get(t, 0)
                if t in _X64_TLS:
                    lo, hi = off - 4, off + 12
            for k in range(max(lo, 0), min(hi, len(m))):
                m[k] = 0
    funcs: dict[tuple[int, int], list[str]] = {}
    sizes: dict[tuple[int, int], int] = {}
    for sym in symtab.iter_symbols():
        kind = sym["st_info"]["type"]
        if kind not in ("STT_FUNC", "STT_LOOS", "STT_GNU_IFUNC") or \
                sym["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK", "STB_LOCAL"):
            continue
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int) or not sym["st_size"]:
            continue
        key = (shndx, sym["st_value"])
        # an IFUNC symbol names its resolver; callers reach the chosen code through a stub
        funcs.setdefault(key, []).append((sym["st_info"]["bind"] != "STB_GLOBAL",
                                          sym.name if kind == "STT_FUNC" else sym.name + "_ifunc"))
        sizes[key] = max(sizes.get(key, 0), sym["st_size"])
    if tables is not None:
        _data_tables(elf, arch, symtab, tables)
    out = []
    for (shndx, value), names in funcs.items():
        sec = elf.get_section(shndx)
        size = sizes[shndx, value]
        if arch == "arm":
            value &= ~1                          # (a Thumb function's symbol has bit 0 set)
        code = sec.data()[value:value + min(size, MAX_LEN)]
        cut = min((o - value for o in moves.get(shndx, ()) if value <= o < value + len(code)), default=None)
        if cut is not None:
            code = code[:cut]
            if not code:
                continue
        m = masks.get(shndx)
        mask = bytes(m[value:value + len(code)]) if m is not None else b"\xff" * len(code)
        own = sorted((o - value, n) for o, n in refs.get(shndx, ()) if value <= o < value + len(code))
        out.append(Signature([[n for _weak, n in sorted(set(names))]], bytes(code), mask, own, cut is not None))
    return arch, out


def _data_tables(elf, arch: str, symtab, tables: dict) -> None:
    """The pointers each data object of `elf` holds (relocations storing a whole pointer):
    tables[name] = [size, [[offset, name pointed to, 1 for a function], ...]]."""
    import struct
    from elftools.elf.relocation import RelocationSection
    kind, size = _ABS_PTR.get(arch), _PTR_SIZE.get(arch)
    if kind is None:
        return
    objects: dict[int, list] = {}            # section -> [(start, end, name)]
    funcs_at: dict[tuple[int, int], str] = {}
    for sym in symtab.iter_symbols():
        shndx, t = sym["st_shndx"], sym["st_info"]["type"]
        if not isinstance(shndx, int) or not sym.name:
            continue
        if t == "STT_OBJECT" and sym["st_size"]:
            objects.setdefault(shndx, []).append((sym["st_value"], sym["st_value"] + sym["st_size"], sym.name))
        elif t == "STT_FUNC":
            funcs_at.setdefault((shndx, sym["st_value"] & (~1 if arch == "arm" else ~0)), sym.name)
    little = elf.little_endian
    for rs in elf.iter_sections():
        if not isinstance(rs, RelocationSection) or rs["sh_info"] not in objects:
            continue
        target = elf.get_section(rs["sh_info"])
        if target["sh_flags"] & 4:               # (code)
            continue
        body = target.data() if target["sh_type"] == "SHT_PROGBITS" else b""
        rsym = elf.get_section(rs["sh_link"])
        spans = sorted(objects[rs["sh_info"]])
        for r in rs.iter_relocations():
            if r["r_info_type"] != kind or not r["r_info_sym"]:
                continue
            off = r["r_offset"]
            owners = [sp for sp in spans if sp[0] <= off < sp[1]]   # (a section-wide object holds them all)
            if not owners:
                continue
            ts = rsym.get_symbol(r["r_info_sym"])
            if arch in _RELA:
                addend = r["r_addend"]
            elif off + size <= len(body):
                addend = struct.unpack_from(("<" if little else ">") + ("I" if size == 4 else "Q"), body, off)[0]
            else:
                continue
            if ts["st_info"]["type"] == "STT_SECTION":       # a static function in this object
                name = funcs_at.get((ts["st_shndx"], addend & (~1 if arch == "arm" else ~0)))
                is_func = name is not None
            else:
                name = ts.name if addend in (0, 1) else None
                is_func = ts["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC") or \
                    (ts["st_info"]["type"] == "STT_NOTYPE" and ts["st_shndx"] == "SHN_UNDEF" and
                     not ts.name.startswith("_ZT"))
            if name:
                for start, end, oname in owners:
                    tables.setdefault(oname, [end - start, []])[1].append([off - start, name, int(is_func)])


def build(paths: list[str]) -> SigDB:
    """Signatures of every function in the given static libraries / object files."""
    db: SigDB | None = None
    seen: dict[tuple, Signature] = {}
    for path in paths:
        with open(path, "rb") as fp:
            data = fp.read()
        members = ar_members(data) if data.startswith(b"!<arch>\n") else [(os.path.basename(path), data)]
        for _name, body in members:
            if not body.startswith(b"\x7fELF"):
                continue
            tables: dict = {}
            try:
                arch, sigs = object_signatures(body, tables)
            except Exception:  # noqa: BLE001 - one odd member must not stop the rest
                continue
            if db is None:
                db = SigDB(arch, source=", ".join(os.path.basename(p) for p in paths))
            if arch != db.arch:
                continue
            for name, (size, slots) in tables.items():
                entry = [size, sorted(slots)]
                if name in db.tables and db.tables[name] != entry:
                    db.tables[name] = None           # (two different objects of one name: unusable)
                elif name not in db.tables:
                    db.tables[name] = entry
            for s in sigs:
                key = (s.pattern, s.mask, tuple(s.refs), s.prefix)
                old = seen.get(key)
                if old is None:
                    seen[key] = s
                    db.sigs.append(s)
                elif s.groups[0] not in old.groups:     # the same code in another object
                    old.groups.append(s.groups[0])
    if db is None:
        raise ValueError("no ELF objects found")
    db.tables = {n: t for n, t in db.tables.items() if t and any(f for _, _, f in t[1])}
    return db


# ---------------------------------------------------------------- matching
class Matcher:
    def __init__(self, dbs: list[SigDB]):
        # (prefix length, prefix mask) -> masked prefix -> [(signature, mask int, masked pattern int)]
        self.groups: dict[tuple[int, int], dict[int, list]] = {}
        self.tables: dict[str, list] = {}
        for db in dbs:
            for name, slots in db.tables.items():
                self.tables.setdefault(name, slots)
            for s in db.sigs:
                # a short pattern is usable when what it refers to is checked too (see match)
                if s.fixed < MIN_FIXED and (not s.refs or s.fixed + REF_WEIGHT * len(s.refs) < MIN_SHORT):
                    continue
                if s.prefix and s.fixed + REF_WEIGHT * len(s.refs) < PREFIX_FIXED:
                    continue
                n = min(PREFIX, len(s.pattern))
                pm = int.from_bytes(s.mask[:n], "little")
                key = int.from_bytes(s.pattern[:n], "little") & pm
                mask = int.from_bytes(s.mask, "little")
                self.groups.setdefault((n, pm), {}).setdefault(key, []).append(
                    (s, mask, int.from_bytes(s.pattern, "little") & mask))

    def candidates(self, code: bytes, ends_ok=lambda size: True) -> list[Signature]:
        """Every signature the code at the start of a function matches whole (bytes, and where it
        may end), longest first."""
        found: list[Signature] = []
        heads = {}
        for (n, pm), table in self.groups.items():
            if len(code) < n:
                continue
            head = heads.get(n)
            if head is None:
                head = heads[n] = int.from_bytes(code[:n], "little")
            for s, mask, want in table.get(head & pm, ()):
                size = len(s.pattern)
                if len(code) >= size and int.from_bytes(code[:size], "little") & mask == want and \
                        (s.fixed >= LONG_FIXED or s.prefix or ends_ok(size)):
                    found.append(s)
        return sorted(found, key=lambda s: -len(s.pattern))

    def match(self, code: bytes, ends_ok=lambda size: True,
              refs_ok=lambda sig: True) -> tuple[str, set, list[Signature]] | None:
        """The library name for a function starting with `code`, if exactly one name fits, every
        name the code has (its aliases), and the signatures that say so.
        `ends_ok(size)`: whether the function can end `size` bytes in (a short pattern also
        matches the first bytes of a longer, different function). `refs_ok(sig)`: whether what
        the code refers to fits the signature's references, when several signatures fit (True,
        False, or None: nothing to check)."""
        found: dict[int, list[Signature]] = {}
        heads = {}
        for (n, pm), table in self.groups.items():
            if len(code) < n:
                continue
            head = heads.get(n)
            if head is None:
                head = heads[n] = int.from_bytes(code[:n], "little")
            for s, mask, want in table.get(head & pm, ()):
                size = len(s.pattern)
                # (a long match says enough: the analysis may not see where the function ends
                # when it calls one not yet known not to return)
                if len(code) < size or int.from_bytes(code[:size], "little") & mask != want or \
                        (s.fixed < LONG_FIXED and not s.prefix and not ends_ok(size)) or \
                        (s.fixed < MIN_FIXED and not refs_ok(s)):
                    continue
                found.setdefault(size, []).append(s)
        # the longest match; a shorter one only when what each longer one refers to is wrong
        for size in sorted(found, reverse=True):
            best = found[size]
            names = {s.name for s in best}
            if len(names) == 1 and None not in names and all(s.fixed >= MIN_FIXED for s in best):
                return names.pop(), {n for s in best for n in s.names}, best
            # the same bytes with different names: what each refers to tells them apart
            fits = {id(s): refs_ok(s) if s.refs else False for s in best}
            ok = [s for s in best if fits[id(s)]]
            names = {_public(g) for s in ok for g in s.groups}
            if len({_plain(n) for n in names}) == 1:
                return _public(sorted(names)), {n for s in ok for n in s.names}, ok
            if ok or any(v is None for v in fits.values()):
                return None                     # several fit, or some cannot be checked
        return None


def _ends_at(an: "Analysis", f, end: int) -> bool:
    """Whether `f` can end at `end`: past it come only padding and then another function (or
    nothing of `f`). Its blocks may run on regardless: a call to a function not yet known not
    to return lets the analysis fall through into the next function."""
    for _ in range(16):                       # padding: nop forms, int3, zero bytes
        if end in an.functions:
            return True
        i = an.dis.decode(end)
        raw = an.bin.read(end, 1)
        if i is not None and (i.mnemonic == "nop" or i.mnemonic == "int3"):
            end = i.end
        elif raw == b"\0":
            end += 1
        else:
            break
    if end in an.functions:
        return True
    return not any(b.addr <= end < b.end or b.addr == end for b in f.blocks.values())


def sig_dirs() -> list[str]:
    dirs = [d for d in os.environ.get("RELIC_SIGS", "").split(os.pathsep) if d]
    dirs.append(os.path.join(os.path.expanduser("~"), ".relic", "sigs"))
    return [d for d in dict.fromkeys(dirs) if os.path.isdir(d)]


def available(arch: str, paths: list[str] | None = None) -> list[SigDB]:
    """The signature databases for `arch`: the given files, else those in sig_dirs()."""
    if paths is None:
        paths = [os.path.join(d, f) for d in sig_dirs() for f in sorted(os.listdir(d)) if f.endswith(".sig")]
    out = []
    for p in paths:
        try:
            key = (os.path.abspath(p), os.path.getmtime(p))
            db = _LOADED.get(key)
            if db is None:
                db = _LOADED[key] = SigDB.load(p)
        except (OSError, ValueError, KeyError):
            continue
        if db.arch == arch:
            out.append(db)
    return out


_LOADED: dict[tuple[str, float], SigDB] = {}       # loaded databases, by path and modification time


def _ifunc_stubs(an: "Analysis", named: dict[int, str], aliases: dict[int, set]) -> None:
    """A static binary calls an IFUNC (`strlen`) through a stub jumping through a GOT slot the
    startup code fills with what the resolver picks (an IRELATIVE relocation, whose addend is
    the resolver). A stub whose resolver is named `strlen_ifunc` is `strlen`."""
    resolver = {r.addr: r.addend for r in an.bin.relocs if r.kind.endswith("IRELATIVE")}
    if not resolver:
        return
    for f in an.functions.values():
        if f.is_import or not f.name.startswith("sub_") or len(f.blocks) != 1:
            continue
        insns = [i for b in f.blocks.values() for i in b.insns]
        last = insns[-1] if insns else None
        if last is None or last.mnemonic.split()[-1] != "jmp" or last.mem_target not in resolver:
            continue
        r = resolver[last.mem_target]
        rname = named.get(r) or an.functions.get(r, f).name
        if rname.endswith("_ifunc"):
            f.name = rname[:-len("_ifunc")]
            f.library = True
            named[f.addr] = f.name
            aliases[f.addr] = {n.removesuffix("_ifunc") for n in aliases.get(r, {rname})}


def apply(an: "Analysis", dbs: list[SigDB], make_function=None) -> dict[int, str]:
    """Name the functions without a symbol whose code matches a signature; address -> name.
    `make_function(addr)`: analyse a function nothing calls (a virtual method, found in a
    vtable) and return it, to name it too."""
    if not dbs:
        return {}
    m = Matcher(dbs)
    named: dict[int, str] = {}
    aliases: dict[int, set] = {}            # every name of each function named: for references
    used: dict[int, list] = {}              # the signatures each was named by
    # names found make more references checkable: repeat while that names more
    for _ in range(4):
        before = len(named)
        for f in an.functions.values():
            if f.is_import or not f.name.startswith("sub_"):
                continue
            a = f.addr & ~1 if an.bin.arch == "arm" else f.addr
            code = an.bin.read(a, MAX_LEN) or b""
            if not code:
                continue
            found = m.match(code, lambda size, f=f, a=a: _ends_at(an, f, a + size),
                            lambda sig, a=a: _refs_fit(an, a, sig, aliases))
            if found is not None:
                f.name, aliases[f.addr], used[f.addr] = found
                f.library = True
                named[f.addr] = f.name
        _ifunc_stubs(an, named, aliases)
        if len(named) == before:
            break
    _resolve(an, m, named, aliases, used, make_function)
    return named


def _wanted(name: str) -> set[str]:
    return {_plain(name), _plain(name + "_ifunc"), _plain(name).removesuffix("_ifunc")}


def _known(an: "Analysis", t: int, aliases: dict[int, set]) -> set[str] | None:
    """The names (plain) of what is at `t`, when it has one."""
    f = an.functions.get(t)
    have = f.name if f is not None else an.bin.name_of(t)
    if not have or have.startswith("sub_"):
        return None
    return {_plain(n) for n in aliases.get(t, ())} | {_plain(have)}


def _resolve(an: "Analysis", m: Matcher, named: dict[int, str], aliases: dict[int, set], used: dict[int, list],
             make_function=None):
    """Functions whose code several signatures fit, and functions too short to match, named by
    what the code refers to, all together: a candidate is dropped when something it refers to
    has another name, a function is named when its candidates left agree, and what the
    signatures that named a function refer to is named after them (`__throw_length_error`'s
    call names `length_error`'s constructor, and that one tells the nine throw functions of
    identical code apart)."""
    pend: dict[int, list] = {}              # address -> [(signature, [(target, wanted name)])]
    for f in an.functions.values():
        if f.is_import or not f.name.startswith("sub_"):
            continue
        a = f.addr & ~1 if an.bin.arch == "arm" else f.addr
        code = an.bin.read(a, MAX_LEN) or b""
        cands = m.candidates(code, lambda size, f=f, a=a: _ends_at(an, f, a + size)) if code else []
        cands = [s for s in cands if len(s.pattern) == len(cands[0].pattern)] if cands else []
        if cands:
            pend[f.addr] = [(s, _ref_targets(an, a, s)) for s in cands]
    targets = {a: [(s, _ref_targets(an, a & ~1 if an.bin.arch == "arm" else a, s)) for s in sigs]
               for a, sigs in used.items()}

    def name(addr: int, public: str, names: set, cands: list):
        f = an.functions[addr]
        f.name, f.library = public, True
        named[addr] = public
        aliases[addr] = names
        targets[addr] = cands
        pend.pop(addr, None)

    done: set[int] = set()                  # named functions whose references were followed
    seen_tables: set[int] = set()
    for _ in range(8):
        changed = False
        for a, cands in list(pend.items()):
            keep = []
            for s, refs in cands:
                checked, bad = 0, False
                for t, want in refs:
                    k = _known(an, t, aliases) if t is not None else None
                    if k is None:
                        continue
                    if not k & _wanted(want):
                        bad = True
                        break
                    checked += 1
                if not bad:
                    keep.append((s, refs, checked))
            if not keep:
                del pend[a]
                continue
            if len(keep) < len(cands):
                pend[a] = [(s, refs) for s, refs, _ in keep]
            publics = {_public(g) for s, _, _ in keep for g in s.groups}
            if any(s.name is None for s, _, _ in keep) or len({_plain(n) for n in publics}) != 1:
                continue
            # enough evidence: the bytes, with each reference checked counting; when the bytes
            # alone fit several names, a reference must have told them apart
            several = len({_plain(_public(g)) for s, _ in cands for g in s.groups}) > 1 or \
                len(keep) < len(cands)
            if all((s.fixed >= MIN_FIXED or s.fixed + REF_WEIGHT * c >= MIN_SHORT) and (c or not several)
                   for s, _, c in keep):
                name(a, _public(sorted(publics)), {n for s, _, _ in keep for n in s.names},
                     [(s, refs) for s, refs, _ in keep])
                changed = True
        # what the functions named refer to, named after them (one name from every signature)
        for a, cands in list(targets.items()):
            if a in done:
                continue
            done.add(a)
            wants: dict[int, set] = {}
            for _s, refs in cands:
                for t, want in refs:
                    if t is not None:
                        wants.setdefault(t, set()).add(want)
            for t, ws in wants.items():
                g = an.functions.get(t)
                if g is None or g.is_import or not g.name.startswith("sub_") or \
                        len({_plain(w) for w in ws}) != 1 or any(len(r) != len(cands[0][1]) for _, r in cands):
                    continue
                want = sorted(ws)[0].removesuffix("_ifunc")
                if t in pend:                   # its own candidates must allow the name
                    ok = [(s, r) for s, r in pend[t] if _plain(want) in {_plain(n) for n in s.names}]
                    if not ok:
                        continue
                    name(t, want, {n for s, _ in ok for n in s.names}, ok)
                else:
                    name(t, want, {want}, [])
                changed = True
        if _name_from_tables(an, m, targets, pend, name, seen_tables, make_function):
            changed = True
        if not changed:
            break


def _table_base(an: "Analysis", t: int, table: list, word: int) -> int | None:
    """Where `table` ([size, slots]) starts, given an address the code refers to it by (a vtable
    past its first two words, a section-wide object anywhere in it): the one start at which
    every function pointer points into code (or is null: a weak reference nothing linked),
    every other pointer into data, most function pointers are set, and no other word of it
    points into code."""
    size, slots = table
    at = {off: is_func for off, _name, is_func in slots}
    funcs = sum(at.values())

    def word_at(a):
        raw = an.bin.read(a, word)
        if raw is None or len(raw) < word:
            return None
        return int.from_bytes(raw, an.bin.endian) & (~1 if an.bin.arch == "arm" else ~0)
    fit = []
    for d in range(max(4, size // word)):
        b = t - d * word
        ok, set_funcs = True, 0
        for off in range(0, size - word + 1, word):
            p = word_at(b + off)
            if p is None:
                ok = False
                break
            kind = at.get(off)
            if kind is None:
                ok = not (p and an.bin.is_exec(p))
            elif kind:
                ok = not p or an.bin.is_exec(p)
                set_funcs += bool(p)
            else:
                ok = not p or an.bin.is_mapped(p) and not an.bin.is_exec(p)
            if not ok:
                break
        if ok and set_funcs * 2 >= funcs:
            fit.append(b)
            if len(fit) > 1:
                return None
    return fit[0] if fit else None


def _inside_function(an: "Analysis", addr: int, starts: list[int]) -> bool:
    """Whether `addr` is in the code of the function starting before it (`starts`: sorted)."""
    k = bisect.bisect_right(starts, addr) - 1
    f = an.functions.get(starts[k]) if k >= 0 else None
    return f is not None and f.block_at(addr) is not None


def _name_from_tables(an: "Analysis", m: Matcher, targets: dict, pend: dict, name, seen: set,
                      make_function=None) -> bool:
    """The functions in a table (a vtable, a table of function pointers) a named function's
    signature refers to, named after what the library's table holds there (made first, with
    `make_function`, when nothing calls them)."""
    if not m.tables:
        return False
    word = an.bin.bits // 8
    changed = False
    starts = sorted(an.functions)
    for cands in list(targets.values()):
        for t, want in (cands[0][1] if len(cands) == 1 else ()):
            slots = m.tables.get(want)
            if t is None or slots is None or t in an.functions:
                continue
            base = _table_base(an, t, slots, word)
            if base is None or base in seen:
                continue
            seen.add(base)
            for off, fname, is_func in slots[1]:
                if not is_func:
                    continue
                p = int.from_bytes(an.bin.read(base + off, word), an.bin.endian)
                g = an.functions.get(p) or (an.functions.get(p | 1) if an.bin.arch == "arm" else None)
                if g is None and make_function is not None and p and an.bin.is_exec(p & ~1) and \
                        not _inside_function(an, p & ~1, starts):
                    g = make_function(p)
                    if g is not None and g.name.startswith("sub_"):
                        bisect.insort(starts, g.addr)
                        a = g.addr & ~1 if an.bin.arch == "arm" else g.addr
                        cands = m.candidates(an.bin.read(a, MAX_LEN) or b"",
                                             lambda size, g=g, a=a: _ends_at(an, g, a + size))
                        if cands:
                            pend[g.addr] = [(c, _ref_targets(an, a, c)) for c in cands]
                if g is None or g.is_import or not g.name.startswith("sub_"):
                    continue
                if g.addr in pend:
                    ok = [(s, r) for s, r in pend[g.addr] if _plain(fname) in {_plain(n) for n in s.names}]
                    if not ok:
                        continue
                    name(g.addr, fname, {n for s, _ in ok for n in s.names}, ok)
                else:
                    name(g.addr, fname, {fname}, [])
                changed = True
    return changed


def _ref_targets(an: "Analysis", addr: int, sig: Signature) -> list[tuple[int | None, str]]:
    """What the code at `addr` refers to where `sig` has references: (address or None, the
    name the signature wants there)."""
    insns = []
    a, end = addr, addr + len(sig.pattern)
    while a < end:
        i = an.dis.decode(a)
        if i is None:
            break
        insns.append(i)
        a = i.end
    out = []
    for off, want in sig.refs:
        i = next((i for i in insns if i.addr <= addr + off < i.end), None)
        t = None if i is None else i.target if i.target is not None else (i.refs[0] if i.refs else None)
        out.append((t, want))
    return out


def _refs_fit(an: "Analysis", addr: int, sig: Signature, aliases: dict[int, set] | None = None) -> bool | None:
    """Whether every reference of `sig` that can be checked names what the code at `addr`
    refers to there: True, False (one names something else), None (none can be checked)."""
    checked = 0
    for t, want in _ref_targets(an, addr, sig):
        names = _known(an, t, aliases or {}) if t is not None else None
        if names is None:
            continue
        if not names & _wanted(want):
            return False
        checked += 1
    return True if checked else None


__all__ = ["Matcher", "SigDB", "Signature", "apply", "ar_members", "available", "build", "object_signatures",
           "sig_dirs"]

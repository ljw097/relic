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

import gzip
import io
import json
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from . import Analysis

MIN_FIXED = 12      # known (unmasked) bytes a pattern needs to be used
REF_WEIGHT = 4      # ... where each checked reference counts as this many bytes
MIN_SHORT = 16      # (a shorter pattern needs this much with its references counted)
LONG_FIXED = 64     # known bytes past which a match needs no check of where the function ends
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
}

# x86-64 relocations the linker may rewrite the instruction around (GOT relaxation, TLS models)
_X64_RELAX = {41: 3, 42: 3, 9: 3}          # GOTPCREL(X): opcode / ModRM / REX before the field
_X64_TLS = {19, 20, 22, 23}                # TLSGD, TLSLD, GOTTPOFF, TPOFF32: whole sequences change


def _public(names: list[str]) -> str:
    """The public name of an alias set (global symbols first, then weak ones): the first
    without leading underscores (`strchr` before its weak alias `index`), else the shortest."""
    plain = [n for n in names if not n.startswith("_")]
    return plain[0] if plain else min(names, key=lambda n: (len(n), n))


def _plain(name: str) -> str:
    n = name.lstrip("_")
    return n[5:] if n.startswith("libc_") else n


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

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        data = {"arch": self.arch, "source": self.source,
                "sigs": [[s.groups, _encode(s.pattern, s.mask), s.refs]
                         + ([s.mask.hex()] if any(m not in (0, 0xFF) for m in s.mask) else [])
                         for s in self.sigs]}
        with gzip.open(path, "wt") as fp:
            json.dump(data, fp)

    @classmethod
    def load(cls, path: str) -> "SigDB":
        with gzip.open(path, "rt") as fp:
            data = json.load(fp)
        db = cls(data["arch"], source=data.get("source", path))
        for groups, text, *rest in data["sigs"]:
            pattern, mask = _decode(text)
            if len(rest) > 1:                    # some bytes only partly known
                mask = bytes.fromhex(rest[1])
            db.sigs.append(Signature(groups, pattern, mask, [tuple(r) for r in rest[0]] if rest else []))
        return db


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


def object_signatures(data: bytes) -> tuple[str, list[Signature]]:
    """The arch and the function signatures of one relocatable ELF object."""
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
                sym["st_info"]["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
            continue
        shndx = sym["st_shndx"]
        if not isinstance(shndx, int) or not sym["st_size"]:
            continue
        key = (shndx, sym["st_value"])
        # an IFUNC symbol names its resolver; callers reach the chosen code through a stub
        funcs.setdefault(key, []).append((sym["st_info"]["bind"] != "STB_GLOBAL",
                                          sym.name if kind == "STT_FUNC" else sym.name + "_ifunc"))
        sizes[key] = max(sizes.get(key, 0), sym["st_size"])
    out = []
    for (shndx, value), names in funcs.items():
        sec = elf.get_section(shndx)
        size = sizes[shndx, value]
        if arch == "arm":
            value &= ~1                          # (a Thumb function's symbol has bit 0 set)
        code = sec.data()[value:value + min(size, MAX_LEN)]
        m = masks.get(shndx)
        mask = bytes(m[value:value + len(code)]) if m is not None else b"\xff" * len(code)
        own = sorted((o - value, n) for o, n in refs.get(shndx, ()) if value <= o < value + len(code))
        out.append(Signature([[n for _weak, n in sorted(set(names))]], bytes(code), mask, own))
    return arch, out


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
            try:
                arch, sigs = object_signatures(body)
            except Exception:  # noqa: BLE001 - one odd member must not stop the rest
                continue
            if db is None:
                db = SigDB(arch, source=", ".join(os.path.basename(p) for p in paths))
            if arch != db.arch:
                continue
            for s in sigs:
                key = (s.pattern, s.mask, tuple(s.refs))
                old = seen.get(key)
                if old is None:
                    seen[key] = s
                    db.sigs.append(s)
                elif s.groups[0] not in old.groups:     # the same code in another object
                    old.groups.append(s.groups[0])
    if db is None:
        raise ValueError("no ELF objects found")
    return db


# ---------------------------------------------------------------- matching
class Matcher:
    def __init__(self, dbs: list[SigDB]):
        # (prefix length, prefix mask) -> masked prefix -> [(signature, mask int, masked pattern int)]
        self.groups: dict[tuple[int, int], dict[int, list]] = {}
        for db in dbs:
            for s in db.sigs:
                # a short pattern is usable when what it refers to is checked too (see match)
                if s.fixed < MIN_FIXED and (not s.refs or s.fixed + REF_WEIGHT * len(s.refs) < MIN_SHORT):
                    continue
                n = min(PREFIX, len(s.pattern))
                pm = int.from_bytes(s.mask[:n], "little")
                key = int.from_bytes(s.pattern[:n], "little") & pm
                mask = int.from_bytes(s.mask, "little")
                self.groups.setdefault((n, pm), {}).setdefault(key, []).append(
                    (s, mask, int.from_bytes(s.pattern, "little") & mask))

    def match(self, code: bytes, ends_ok=lambda size: True, refs_ok=lambda sig: True) -> tuple[str, set] | None:
        """The library name for a function starting with `code`, if exactly one name fits, and
        every name the code has (its aliases).
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
                        (s.fixed < LONG_FIXED and not ends_ok(size)) or (s.fixed < MIN_FIXED and not refs_ok(s)):
                    continue
                found.setdefault(size, []).append(s)
        # the longest match; a shorter one only when what each longer one refers to is wrong
        for size in sorted(found, reverse=True):
            best = found[size]
            names = {s.name for s in best}
            if len(names) == 1 and None not in names and all(s.fixed >= MIN_FIXED for s in best):
                return names.pop(), {n for s in best for n in s.names}
            # the same bytes with different names: what each refers to tells them apart
            fits = {id(s): refs_ok(s) if s.refs else False for s in best}
            ok = [s for s in best if fits[id(s)]]
            names = {_public(g) for s in ok for g in s.groups}
            if len({_plain(n) for n in names}) == 1:
                return _public(sorted(names)), {n for s in ok for n in s.names}
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


def apply(an: "Analysis", dbs: list[SigDB]) -> dict[int, str]:
    """Name the functions without a symbol whose code matches a signature; address -> name."""
    if not dbs:
        return {}
    m = Matcher(dbs)
    named: dict[int, str] = {}
    aliases: dict[int, set] = {}            # every name of each function named: for references
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
                f.name, aliases[f.addr] = found
                f.library = True
                named[f.addr] = f.name
        _ifunc_stubs(an, named, aliases)
        if len(named) == before:
            break
    return named


def _refs_fit(an: "Analysis", addr: int, sig: Signature, aliases: dict[int, set] | None = None) -> bool | None:
    """Whether every reference of `sig` that can be checked names what the code at `addr`
    refers to there: True, False (one names something else), None (none can be checked)."""
    insns = []
    a, end = addr, addr + len(sig.pattern)
    while a < end:
        i = an.dis.decode(a)
        if i is None:
            break
        insns.append(i)
        a = i.end
    checked = 0
    for off, want in sig.refs:
        i = next((i for i in insns if i.addr <= addr + off < i.end), None)
        if i is None:
            continue
        t = i.target if i.target is not None else (i.refs[0] if i.refs else None)
        if t is None:
            continue
        f = an.functions.get(t)
        have = f.name if f is not None else an.bin.name_of(t)
        if not have or have.startswith("sub_"):
            continue
        names = {_plain(n) for n in (aliases or {}).get(t, ())} | {_plain(have)}
        if not names & {_plain(want), _plain(want + "_ifunc"), _plain(want).removesuffix("_ifunc")}:
            return False
        checked += 1
    return True if checked else None


__all__ = ["Matcher", "SigDB", "Signature", "apply", "ar_members", "available", "build", "object_signatures",
           "sig_dirs"]

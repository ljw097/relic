"""Common binary model shared by every loader."""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    addr: int
    size: int
    offset: int
    r: bool = True
    w: bool = False
    x: bool = False
    loaded: bool = True  # False for .bss-like (no file data)

    @property
    def end(self) -> int:
        return self.addr + self.size

    def contains(self, addr: int) -> bool:
        return self.addr <= addr < self.end

    @property
    def perms(self) -> str:
        return ("r" if self.r else "-") + ("w" if self.w else "-") + ("x" if self.x else "-")


@dataclass
class Segment:
    addr: int
    memsz: int
    offset: int
    filesz: int
    r: bool = True
    w: bool = False
    x: bool = False


@dataclass
class Symbol:
    name: str
    addr: int
    size: int = 0
    kind: str = "func"  # func | object | other
    source: str = "symtab"  # symtab | dynsym | export | plt | iat | synthetic


@dataclass
class Import:
    name: str
    addr: int  # address that code calls (PLT stub / IAT slot)
    got: int = 0  # GOT / IAT slot address
    library: str = ""


@dataclass
class Relocation:
    addr: int
    name: str
    kind: str = ""


class Binary:
    """Format-independent view of a loaded executable."""

    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        self.format = "RAW"
        self.arch = "x64"  # x86 | x64 | arm | arm64 | mips | mips64 | riscv64 | ppc
        self.bits = 64
        self.endian = "little"
        self.entry = 0
        self.base = 0
        self.os = "linux"
        self.sections: list[Section] = []
        self.segments: list[Segment] = []
        self.symbols: dict[int, Symbol] = {}
        self.imports: list[Import] = []
        self.exports: list[Symbol] = []
        self.relocs: list[Relocation] = []
        self.libraries: list[str] = []
        self.interp = ""
        self.info: dict[str, str] = {}
        self._seg_starts: list[int] = []
        # ARM: where Thumb code starts (odd entry / symbol values) and the `$a`/`$t`/`$d`
        # mapping symbols (address -> "a" | "t" | "d")
        self.thumb_code: set[int] = set()
        self.arm_mapping: dict[int, str] = {}

    # ------------------------------------------------------------------ memory
    def _finalize(self):
        if not self.segments:
            for s in self.sections:
                if s.addr:
                    self.segments.append(Segment(s.addr, s.size, s.offset, s.size if s.loaded else 0, s.r, s.w, s.x))
        self.segments.sort(key=lambda s: s.addr)
        self._seg_starts = [s.addr for s in self.segments]
        self.sections.sort(key=lambda s: s.addr)
        self._sec_starts = [s.addr for s in self.sections]
        self.imports_by_addr = {i.addr: i for i in self.imports}
        self.imports_by_got = {i.got: i for i in self.imports if i.got}
        self.name_to_addr = {}
        for a, s in self.symbols.items():
            self.name_to_addr.setdefault(s.name, a)

    def segment_at(self, addr: int) -> Segment | None:
        i = bisect.bisect_right(self._seg_starts, addr) - 1
        if i >= 0:
            s = self.segments[i]
            if s.addr <= addr < s.addr + s.memsz:
                return s
        # overlapping segments: linear fallback
        for s in self.segments:
            if s.addr <= addr < s.addr + s.memsz:
                return s
        return None

    def section_at(self, addr: int) -> Section | None:
        i = bisect.bisect_right(self._sec_starts, addr) - 1
        while i >= 0:
            s = self.sections[i]
            if s.contains(addr):
                return s
            if s.addr + max(s.size, 0x100000) < addr:
                break
            i -= 1
        return None

    def section(self, name: str) -> Section | None:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def is_mapped(self, addr: int) -> bool:
        return self.segment_at(addr) is not None

    def is_exec(self, addr: int) -> bool:
        s = self.section_at(addr)
        if s is not None:
            return s.x
        g = self.segment_at(addr)
        return bool(g and g.x)

    def is_writable(self, addr: int) -> bool:
        g = self.segment_at(addr)
        return bool(g and g.w)

    def read(self, addr: int, size: int) -> bytes:
        out = bytearray()
        while size > 0:
            seg = self.segment_at(addr)
            if seg is None:
                break
            rel = addr - seg.addr
            avail = seg.addr + seg.memsz - addr
            n = min(size, avail)
            if rel < seg.filesz:
                fn = min(n, seg.filesz - rel)
                out += self.data[seg.offset + rel: seg.offset + rel + fn]
                if fn < n:
                    out += b"\0" * (n - fn)
            else:
                out += b"\0" * n
            addr += n
            size -= n
        return bytes(out)

    def read_ptr(self, addr: int) -> int | None:
        n = self.bits // 8
        b = self.read(addr, n)
        if len(b) != n:
            return None
        return int.from_bytes(b, self.endian)

    def read_int(self, addr: int, size: int, signed=False) -> int | None:
        b = self.read(addr, size)
        if len(b) != size:
            return None
        return int.from_bytes(b, self.endian, signed=signed)

    def read_cstring(self, addr: int, maxlen: int = 512) -> str | None:
        b = self.read(addr, maxlen)
        if not b:
            return None
        end = b.find(b"\0")
        if end < 0:
            end = len(b)
        raw = b[:end]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")

    def offset_to_addr(self, off: int) -> int | None:
        for s in self.segments:
            if s.offset <= off < s.offset + s.filesz:
                return s.addr + off - s.offset
        return None

    def addr_to_offset(self, addr: int) -> int | None:
        s = self.segment_at(addr)
        if s and addr - s.addr < s.filesz:
            return s.offset + addr - s.addr
        return None

    # ----------------------------------------------------------------- symbols
    def name_of(self, addr: int) -> str | None:
        s = self.symbols.get(addr)
        if s:
            return s.name
        imp = self.imports_by_addr.get(addr)
        if imp:
            return imp.name
        return None

    def add_symbol(self, sym: Symbol, override=False):
        if not sym.name or sym.addr == 0:
            return
        cur = self.symbols.get(sym.addr)
        if cur is None or override or (cur.kind != "func" and sym.kind == "func"):
            self.symbols[sym.addr] = sym

    @property
    def exec_sections(self) -> list[Section]:
        return [s for s in self.sections if s.x and s.size > 0 and s.loaded]

    def describe(self) -> str:
        return f"{self.format} {self.arch} ({self.bits}-bit {self.endian}-endian)"

"""Binary loaders. `load(path)` sniffs the format and returns a `Binary`."""
from __future__ import annotations

from .base import Binary, Import, Section, Segment, Symbol


def load(path: str, arch: str | None = None, base: int = 0) -> Binary:
    with open(path, "rb") as f:
        data = f.read()
    return load_bytes(data, path, arch, base)


def load_bytes(data: bytes, path: str = "<memory>", arch: str | None = None, base: int = 0) -> Binary:
    if data[:4] == b"\x7fELF":
        from .elf import load_elf
        b = load_elf(path, data)
    elif data[:2] == b"MZ":
        from .pe import load_pe
        b = load_pe(path, data)
    else:
        b = load_raw(path, data, arch or "x64", base)
    if arch and b.format != "RAW":
        b.arch = arch
    return b


def load_raw(path: str, data: bytes, arch: str = "x64", base: int = 0) -> Binary:
    """Flat shellcode / firmware blob."""
    b = Binary(path, data)
    b.format = "RAW"
    b.arch = arch
    b.bits = 32 if arch in ("x86", "arm", "mips", "riscv32", "ppc") else 64
    b.base = base
    b.entry = base
    b.sections.append(Section(".raw", base, len(data), 0, True, True, True))
    b.segments.append(Segment(base, len(data), 0, len(data), True, True, True))
    b.add_symbol(Symbol("start", base, 0, "func", "synthetic"))
    b._finalize()
    return b


__all__ = ["Binary", "Import", "Section", "Segment", "Symbol", "load", "load_bytes", "load_raw"]

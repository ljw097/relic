"""Binary loaders. `load(path)` sniffs the format and returns a `Binary`."""
from __future__ import annotations

from .base import Binary, Import, Section, Segment, Symbol


def load(path: str, arch: str | None = None, base: int | str = 0) -> Binary:
    """Load a file -- or one member of a static library, `lib.a:member.o`."""
    import os
    member = None
    if not os.path.exists(path) and ":" in path and os.path.exists(path.rsplit(":", 1)[0]):
        path, member = path.rsplit(":", 1)
    with open(path, "rb") as f:
        data = f.read()
    if member is not None or data.startswith(b"!<arch>\n"):
        from .archive import member as pick
        name, body = pick(data, member)
        b = load_bytes(body, f"{path}:{name}", arch, base)
        b.info["archive"] = f"{os.path.basename(path)} member {name}"
        return b
    return load_bytes(data, path, arch, base)


def load_bytes(data: bytes, path: str = "<memory>", arch: str | None = None, base: int | str = 0) -> Binary:
    try:
        return _load_bytes(data, path, arch, base)
    except (OSError, ValueError):
        raise
    except Exception as e:  # noqa: BLE001 - the format libraries' own errors on a malformed file
        raise ValueError(f"malformed or truncated file ({type(e).__name__}: {e})") from e


def _load_bytes(data: bytes, path: str, arch: str | None, base: int | str) -> Binary:
    from ..extend import LOADERS
    for ld in LOADERS:                       # plugins' loaders first (relic.extend)
        if ld.detect(data, path):
            b = ld.load(data, path)
            if arch:
                b.arch = arch
            return b
    if data[:4] == b"\x7fELF":
        from .elf import load_elf
        b = load_elf(path, data)
    elif data[:4] == b"\0asm":
        from .wasm import load_wasm
        return load_wasm(path, data)
    elif _is_macho(data):
        from .macho import load_macho
        b = load_macho(path, data, arch)
        arch = None                          # (picked the slice)
    elif data[:2] == b"MZ":
        from .pe import load_pe
        b = load_pe(path, data)
    elif _is_coff(data):
        from .coff import load_coff
        b = load_coff(path, data)
    elif _is_text_firmware(data):
        from .firmware import load_firmware
        return load_firmware(path, data, arch)
    else:
        b = load_raw(path, data, arch or "x64", base)
    if arch and b.format != "RAW":
        b.arch = arch
    return b


def _is_macho(data: bytes) -> bool:
    from .macho import is_macho
    return is_macho(data)


def _is_coff(data: bytes) -> bool:
    from .coff import is_coff
    return is_coff(data)


def _is_text_firmware(data: bytes) -> bool:
    from .firmware import is_ihex, is_srec
    return is_ihex(data) or is_srec(data)


def load_raw(path: str, data: bytes, arch: str = "x64", base: int | str = 0) -> Binary:
    """Flat shellcode / firmware blob, at `base` -- or, with base "auto", where `rawbase` guesses
    the image belongs."""
    b = Binary(path, data)
    b.format = "RAW"
    b.arch = arch
    from ..extend import PROCESSORS
    custom = PROCESSORS.get(arch)
    b.bits = custom.bits if custom else 32 if arch in ("x86", "arm", "mips", "riscv32", "ppc") else 64
    if custom:
        b.endian = custom.endian
    if base == "auto":
        from .rawbase import guess_base
        guesses = guess_base(data, b.bits, "big" if b.endian == "big" else "little", limit=1)
        base = guesses[0].base if guesses else 0
        b.info["base guess"] = f"{base:#x} ({guesses[0].reason})" if guesses else "none: loaded at 0"
    b.base = base
    b.entry = base
    b.sections.append(Section(".raw", base, len(data), 0, True, True, True))
    b.segments.append(Segment(base, len(data), 0, len(data), True, True, True))
    b.add_symbol(Symbol("start", base, 0, "func", "synthetic"))
    b._finalize()
    return b


__all__ = ["Binary", "Import", "Section", "Segment", "Symbol", "load", "load_bytes", "load_raw"]

"""`ar` archives (static libraries: `.a`, MSVC `.lib`): their members, and the object one of
them is (`lib.a:member.o`, or the first object member)."""
from __future__ import annotations

from typing import Iterator


def is_archive(data: bytes) -> bool:
    return data.startswith(b"!<arch>\n")


def ar_members(data: bytes) -> Iterator[tuple[str, bytes]]:
    """(name, contents) of every member of an `ar` archive (GNU / MSVC long names understood)."""
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
            end = min((i for i in (longnames.find(b"\n", off), longnames.find(b"\0", off)) if i >= 0),
                      default=len(longnames))
            name = longnames[off:end].decode("latin-1")
        yield name.rstrip("/"), body


def object_members(data: bytes) -> list[str]:
    """Names of the members that are objects (ELF or COFF), in order."""
    from .coff import is_coff
    return [n for n, body in ar_members(data) if body[:4] == b"\x7fELF" or is_coff(body)]


def member(data: bytes, name: str | None = None) -> tuple[str, bytes]:
    """(name, contents) of member `name`, or of the first object member."""
    from .coff import is_coff
    for n, body in ar_members(data):
        if (name is None and (body[:4] == b"\x7fELF" or is_coff(body))) or n == name:
            return n, body
    raise ValueError(f"no member {name!r} in the archive" if name else "no object member in the archive")


__all__ = ["ar_members", "is_archive", "member", "object_members"]

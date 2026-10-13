"""String extraction from loaded, non-executable sections."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..loader.base import Binary

_ASCII = re.compile(rb"[\x20-\x7e\t\r\n]{%d,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


@dataclass
class String:
    addr: int
    value: str
    encoding: str = "ascii"  # ascii | utf-16le
    section: str = ""


def find_strings(b: Binary, min_len: int = 4) -> list[String]:
    out: list[String] = []
    asc, wide = re.compile(_ASCII.pattern % min_len), re.compile(_UTF16.pattern % min_len)
    for sec in b.sections:
        if not sec.loaded or sec.size == 0 or (sec.x and b.format != "RAW"):
            continue
        if sec.name in (".dynstr", ".strtab", ".shstrtab", ".symtab", ".dynsym", ".gnu.version_r",
                        ".gnu.hash", ".hash", ".note.gnu.build-id", ".eh_frame", ".eh_frame_hdr", ".interp"):
            continue
        data = b.data[sec.offset:sec.offset + sec.size]
        for m in asc.finditer(data):
            out.append(String(sec.addr + m.start(), m.group().decode("latin-1"), "ascii", sec.name))
        if b.format == "PE":
            for m in wide.finditer(data):
                out.append(String(sec.addr + m.start(), m.group().decode("utf-16le"), "utf-16le", sec.name))
    out.sort(key=lambda s: s.addr)
    return out


def escape(s: str, limit: int = 80) -> str:
    r = s.encode("unicode_escape").decode("ascii").replace('"', '\\"')
    return r if len(r) <= limit else r[:limit - 3] + "..."

"""The listing of memory outside functions: data sections and executable bytes no function
covers. What each address holds comes from the user's definitions (`Analysis.data_defs`:
IDA's D / A / * / C / U) and otherwise from what the analysis knows -- a string, a pointer to
a named place, a run of zeros, plain bytes."""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING

from .listing import Line, insn_line

if TYPE_CHECKING:
    from .analysis import Analysis

SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
DIRECTIVE = {1: "db", 2: "dw", 4: "dd", 8: "dq"}
CYCLE = ["byte", "word", "dword", "qword"]          # D: the next size
WINDOW = 0x2000              # bytes shown on each side of the address in a large section
MAX_CODE = 4096              # bytes disassembled from one code mark at most
MAX_STRING = 1024


def item_size(an: "Analysis", addr: int, d: list) -> int:
    kind = d[0]
    if kind in SIZES:
        return SIZES[kind]
    if kind == "string":
        return max(int(d[1]), 1)
    if kind == "array":
        return SIZES.get(d[1], 1) * max(int(d[2]), 1)
    return 1


def string_length(an: "Analysis", addr: int) -> int:
    """Bytes of the NUL-terminated string at `addr`, the NUL included."""
    raw = an.bin.read(addr, MAX_STRING) or b""
    end = raw.find(b"\0")
    return end + 1 if end >= 0 else len(raw)


def _quote(raw: bytes) -> str:
    out = []
    for b in raw:
        if b == 0x22 or b == 0x5C:
            out.append("\\" + chr(b))
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append({9: "\\t", 10: "\\n", 13: "\\r"}.get(b, f"\\x{b:02x}"))
    return '"' + "".join(out) + '"'


def _value_text(an: "Analysis", v: int, size: int) -> str:
    if size == an.bin.bits // 8 and v and an.bin.is_mapped(v):
        name = an.name(v)
        if name:
            return f"offset {name}"
        return f"offset {an.label(v)}" if an.function_at(v) else f"{v:#x}"
    return f"{v:#x}" if v > 9 else str(v)


def window(an: "Analysis", addr: int) -> tuple[int, int] | None:
    """The part of the section holding `addr` that is listed: all of it when small."""
    sec = an.bin.section_at(addr)
    if sec is None or not sec.size:
        return None
    if sec.x:
        # code: the gap between the functions around it
        lo, hi = sec.addr, sec.end
        for f in an.functions.values():
            if f.is_import or not f.blocks:
                continue
            fa = f.addr & ~1
            if fa > addr:
                hi = min(hi, fa)
            else:
                end = max(b.end for b in f.blocks.values())
                if end <= addr:
                    lo = max(lo, end)
        if hi - lo > 2 * WINDOW:
            lo = max(lo, (addr - WINDOW) & ~0xF)
            hi = min(hi, lo + 2 * WINDOW)
        return (lo, hi) if lo < hi else None
    if sec.size <= 2 * WINDOW:
        return sec.addr, sec.end
    lo = max(sec.addr, (addr - WINDOW) & ~0xF)
    return lo, min(sec.end, lo + 2 * WINDOW)


def region_lines(an: "Analysis", start: int, end: int) -> list[Line]:
    """The items from `start` to `end`, one line each (and a label line before named or
    referenced addresses)."""
    defs = {**getattr(an, "code_data", {}), **an.data_defs}      # (the user's definitions win)
    stops = set(defs) | {s.addr for s in an.strings if start <= s.addr < end}
    stops |= {a for a in an.bin.symbols if start <= a < end}
    stops |= {a for a in an.xrefs_to if start <= a < end}
    stops |= {a for a in an.functions if start <= a < end}
    stops |= {a for a in an.renames if start <= a < end}
    stops = sorted(a for a in stops if start <= a < end)
    word = an.bin.bits // 8
    sec = an.bin.section_at(start)
    loaded = sec is None or sec.loaded

    def next_stop(a: int) -> int:
        k = bisect.bisect_right(stops, a)
        return min(stops[k] if k < len(stops) else end, end)

    out: list[Line] = []
    a = start
    while a < end:
        name = an.name(a)
        refs = an.xrefs_to.get(a, ())
        if a in an.functions and a != start:
            break                                  # a function: its own listing
        if name or refs:
            label = name or f"unk_{a:x}"
            note = ""
            if refs:
                first = ", ".join(an.location(x.frm) for x in refs[:2])
                note = f"; xref: {first}" + (f" (+{len(refs) - 2})" if len(refs) > 2 else "")
            out.append(Line("label", a, f"{label}:  {note}".rstrip()))
        d = defs.get(a)
        if d is not None and d[0] == "code":
            a = _code(an, a, min(end, a + MAX_CODE), defs, out)
            continue
        if d is not None and d[0] != "undef":
            size = min(item_size(an, a, d), end - a)
            raw = (an.bin.read(a, size) or b"") if loaded else bytes(size)
            if d[0] == "string":
                out.append(Line("data", a, raw=raw, mnemonic="db", operands=_quote(raw.rstrip(b"\0"))
                                + (", 0" if raw.endswith(b"\0") else ""), comment="string"))
            elif d[0] == "array":
                n = SIZES.get(d[1], 1)
                vals = [int.from_bytes(raw[k:k + n], "little") for k in range(0, len(raw) - n + 1, n)]
                shown = ", ".join(_value_text(an, v, n) for v in vals[:16]) + (", ..." if len(vals) > 16 else "")
                out.append(Line("data", a, raw=raw, mnemonic=DIRECTIVE[n], operands=shown,
                                comment=f"{d[1]}[{len(vals)}]"))
            else:
                v = int.from_bytes(raw, "little")
                out.append(Line("data", a, raw=raw, mnemonic=DIRECTIVE[size], operands=_value_text(an, v, size),
                                target=v if an.bin.is_mapped(v) else None))
            a += max(size, 1)
            continue
        stop = next_stop(a)
        s = an.string_at(a) if d is None else None
        if s is not None and s.encoding == "ascii" and loaded:
            n = min(string_length(an, a), end - a)
            raw = an.bin.read(a, n) or b""
            out.append(Line("data", a, raw=raw, mnemonic="db", operands=_quote(raw.rstrip(b"\0"))
                            + (", 0" if raw.endswith(b"\0") else ""), comment="string"))
            a += max(n, 1)
            continue
        if d is None and a % word == 0 and stop - a >= word and loaded:
            raw = an.bin.read(a, word) or b""
            v = int.from_bytes(raw, "little")
            if v and an.bin.is_mapped(v) and (an.name(v) or an.function_at(v)):
                out.append(Line("data", a, raw=raw, mnemonic=DIRECTIVE[word], operands=_value_text(an, v, word),
                                target=v))
                a += word
                continue
        # plain bytes up to the next item: runs of zeros as one line
        raw = (an.bin.read(a, stop - a) or b"") if loaded else bytes(stop - a)
        if not raw:
            raw = bytes(stop - a)
        k = 0
        while k < len(raw):
            z = len(raw[k:]) - len(raw[k:].lstrip(b"\0"))
            if z >= 16:
                out.append(Line("data", a + k, raw=raw[k:k + 8], mnemonic="db", operands=f"{z:#x} dup(0)"))
                k += z
                continue
            n = min(8, len(raw) - k)
            chunk = raw[k:k + n]
            out.append(Line("data", a + k, raw=chunk, mnemonic="db",
                            operands=", ".join(f"{b:#04x}" for b in chunk)))
            k += n
        a = stop
    return out


def _code(an: "Analysis", a: int, end: int, defs: dict, out: list[Line]) -> int:
    """Instructions from a code mark (C) until an unconditional jump or return, an undecodable
    byte, or the next item."""
    from .disasm import JMP, RET
    first = True
    while a < end:
        if not first and (a in defs or a in an.functions):
            break
        first = False
        i = an.dis.decode(a)
        if i is None:
            break
        out.append(insn_line(an, i))
        a = i.end
        if i.kind in (JMP, RET) and not i.cond:
            break
    return a


__all__ = ["CYCLE", "SIZES", "item_size", "region_lines", "string_length", "window"]

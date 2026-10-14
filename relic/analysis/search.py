"""Searches over a loaded binary: byte patterns, text, immediates and instructions.

The IDA equivalents are Search > sequence of bytes (Alt+B), text (Alt+T) and
immediate value (Alt+I). Byte and text searches scan the file-backed bytes of
every segment (so data, code and headers alike); immediate and instruction
searches look at the instructions of the discovered functions, the code the
analysis understands.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..disasm import OP_IMM, OP_MEM
from ..progress import checkpoint, report

if TYPE_CHECKING:
    from . import Analysis

MAX_HITS = 10000


@dataclass
class Hit:
    addr: int
    kind: str       # bytes | text | imm | insn
    text: str       # what is there: the instruction, or the bytes / string found


class PatternError(ValueError):
    pass


def parse_pattern(pattern: str) -> re.Pattern:
    """`48 8b ?? 05`, `488b??05` or `48 8B ? 05` -> a bytes regex (`?` / `??` is any byte)."""
    tokens = pattern.replace(",", " ").split()
    if len(tokens) == 1 and len(tokens[0]) > 2:
        t = tokens[0]
        tokens = [t[i:i + 2] for i in range(0, len(t), 2)]
    parts = []
    for t in tokens:
        if t in ("?", "??"):
            parts.append(b".")
        elif re.fullmatch(r"[0-9a-fA-F]{2}", t):
            parts.append(re.escape(bytes([int(t, 16)])))
        else:
            raise PatternError(f"bad byte {t!r} in pattern (use hex bytes and ?? for any byte)")
    if not parts:
        raise PatternError("empty pattern")
    return re.compile(b"".join(parts), re.DOTALL)


def _regions(an: "Analysis"):
    """(address, bytes) of every file-backed segment."""
    b = an.bin
    for seg in b.segments:
        if seg.filesz <= 0:
            continue
        yield seg.addr, b.data[seg.offset: seg.offset + seg.filesz]


def _scan(an: "Analysis", rx: re.Pattern, kind: str, show) -> list[Hit]:
    out: list[Hit] = []
    seen = set()
    for base, data in _regions(an):
        checkpoint()
        for m in rx.finditer(data):
            a = base + m.start()
            if a in seen:
                continue
            seen.add(a)
            out.append(Hit(a, kind, show(m.group())))
            if len(out) >= MAX_HITS:
                return out
    return sorted(out, key=lambda h: h.addr)


def find_bytes(an: "Analysis", pattern: str) -> list[Hit]:
    rx = parse_pattern(pattern)
    return _scan(an, rx, "bytes", lambda raw: raw.hex(" "))


def find_text(an: "Analysis", text: str, case: bool = False, utf16: bool = True) -> list[Hit]:
    if not text:
        raise PatternError("empty text")
    flags = 0 if case else re.IGNORECASE
    variants = [re.escape(text.encode("utf-8"))]
    if utf16:
        variants.append(re.escape(text.encode("utf-16-le")))
    rx = re.compile(b"|".join(variants), flags)

    def show(raw: bytes) -> str:
        try:
            return raw.decode("utf-16-le") if b"\0" in raw else raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1")
    return _scan(an, rx, "text", show)


def _insns(an: "Analysis"):
    seen = set()
    funcs = sorted(an.functions.values(), key=lambda f: f.addr)
    for k, f in enumerate(funcs):
        report("instructions", k, len(funcs))
        if f.is_import:
            continue
        for blk in sorted(f.blocks.values(), key=lambda b: b.addr):
            for i in blk.insns:
                if i.addr not in seen:
                    seen.add(i.addr)
                    yield i


def find_imm(an: "Analysis", value: int) -> list[Hit]:
    """Instructions with `value` as an immediate operand or a memory displacement
    (either as written, or as its two's complement at the instruction's width)."""
    m = (1 << an.bin.bits) - 1
    want = {value & m, value}
    out = []
    for i in _insns(an):
        c = i.cs
        if c is None:
            continue
        for op in c.operands:
            v = None
            if op.type == OP_IMM:
                v = op.imm
            elif op.type == OP_MEM and op.mem.disp:
                v = op.mem.disp
            if v is not None and (v in want or (v & m) in want):
                out.append(Hit(i.addr, "imm", f"{i.mnemonic} {i.op_str}".strip()))
                break
        if len(out) >= MAX_HITS:
            break
    return out


def find_insn(an: "Analysis", pattern: str) -> list[Hit]:
    """Instructions whose text matches the regular expression -- as the listing shows it, with
    symbol names (`call gets`), or as capstone prints it (`call 0x401050`)."""
    from ..listing import operands
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise PatternError(f"bad regular expression: {e}") from None
    out = []
    for i in _insns(an):
        text = f"{i.mnemonic} {operands(an, i)}".strip()
        if rx.search(text) or rx.search(f"{i.mnemonic} {i.op_str}"):
            out.append(Hit(i.addr, "insn", text))
            if len(out) >= MAX_HITS:
                break
    return out


__all__ = ["Hit", "PatternError", "find_bytes", "find_imm", "find_insn", "find_text", "parse_pattern"]

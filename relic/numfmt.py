"""How the user wants a number shown (IDA's H / R / B / O): in the listing per instruction
operand (`Analysis.op_formats`), in the pseudocode per constant of a function
(`Analysis.num_formats`)."""
from __future__ import annotations

import re

FORMATS = ("hex", "dec", "char", "bin", "offset")

# a number in operand text: `0x1f`, `-0x8`, `#0x10` (ARM), `$0x4` (AT&T), `16`, `-8`
_NUM = re.compile(r"(?<![\w.])([#$]?)(-?)(0x[0-9a-fA-F]+|\d+)(?![\w.])")
_ESC = {ord("\\"): "\\\\", ord("'"): "\\'", 9: "\\t", 10: "\\n", 13: "\\r", 0: "\\0"}


def char_literal(v: int, bits: int = 64) -> str | None:
    """`'ABCD'` for a value whose bytes (most significant first, as a C multi-character
    constant) are all printable; None otherwise."""
    v &= (1 << bits) - 1
    if not v:
        return None
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if len(raw) > 8 or not all(32 <= b < 127 or b in _ESC for b in raw):
        return None
    return "'" + "".join(_ESC.get(b, chr(b)) for b in raw) + "'"


def format_number(v: int, fmt: str, bits: int = 64, label=None) -> str | None:
    """`v` (signed, or unsigned in `bits`) in `fmt`; None when it cannot be shown so (a char
    constant of unprintable bytes, an offset to nothing)."""
    mask = (1 << bits) - 1
    u = v & mask
    s = u - (1 << bits) if u >> (bits - 1) else u
    if fmt == "hex":
        return f"-{-v:#x}" if v < 0 else f"{v:#x}"
    if fmt == "dec":                        # (a small negative number stored unsigned reads as one)
        return str(v if v < 0 else s if -0x10000 < s < 0 else u)
    if fmt == "char":
        return char_literal(u, bits)
    if fmt == "bin":
        return f"-0b{-v:b}" if v < 0 else f"0b{v:b}"
    if fmt == "offset":
        return label(u) if label is not None else None
    return None


def split_operands(op_str: str) -> list[tuple[int, int]]:
    """(start, end) of each operand in an operand string: commas inside `[]`, `{}` and `()` do
    not separate operands."""
    out, depth, start = [], 0, 0
    for k, ch in enumerate(op_str):
        if ch in "[{(":
            depth += 1
        elif ch in "]})":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append((start, k))
            start = k + 1
    out.append((start, len(op_str)))
    return out


def operand_at(op_str: str, pos: int) -> int:
    """Index of the operand at character `pos` of the operand string (past the end: the last)."""
    for k, (_s, e) in enumerate(split_operands(op_str)):
        if pos < e + 1:
            return k
    return max(len(split_operands(op_str)) - 1, 0)


def numbers_in(text: str) -> list[int]:
    out = []
    for m in _NUM.finditer(text):
        v = int(m.group(3), 0) if m.group(3).startswith("0x") else int(m.group(3))
        out.append(-v if m.group(2) else v)
    return out


def apply_formats(op_str: str, formats: dict, bits: int, label=None) -> str:
    """The operand string with the numbers of each formatted operand (`{index: fmt}`) rewritten."""
    if not formats:
        return op_str
    spans = split_operands(op_str)
    out, last = [], 0
    for k, (s, e) in enumerate(spans):
        fmt = formats.get(k) or formats.get(str(k))
        if not fmt:
            continue

        def sub(m):
            v = int(m.group(3), 16) if m.group(3).startswith("0x") else int(m.group(3))
            v = -v if m.group(2) else v
            t = format_number(v, fmt, bits, label)
            return m.group(0) if t is None else m.group(1) + t
        out.append(op_str[last:s])
        out.append(_NUM.sub(sub, op_str[s:e]))
        last = e
    out.append(op_str[last:])
    return "".join(out)


__all__ = ["FORMATS", "apply_formats", "char_literal", "format_number", "numbers_in", "operand_at",
           "split_operands"]

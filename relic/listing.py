"""Annotated disassembly listing shared by the CLI and the GUI."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .analysis import Analysis
from .analysis.functions import Function
from .disasm import CALL, Insn

_HEX = re.compile(r"0x[0-9a-fA-F]+")


@dataclass
class Line:
    kind: str  # func | label | insn | blank | xref
    addr: int
    text: str = ""
    raw: bytes = b""
    mnemonic: str = ""
    operands: str = ""
    comment: str = ""
    target: int | None = None  # navigable address for this line


def operands(an: Analysis, i: Insn) -> str:
    """Operand text with branch targets replaced by symbolic names."""
    op = i.op_str
    if i.target is not None and i.kind != "normal":
        name = an.label(i.target)
        op = _HEX.sub(lambda m: name if int(m.group(), 16) == i.target else m.group(), op)
    return op


def comment(an: Analysis, i: Insn) -> str:
    parts = []
    user = an.comments.get(i.addr)
    if user:
        parts.append(user)
    if i.kind == CALL and i.target is None and i.mem_target is not None:
        n = an.call_name(i)
        if n:
            parts.append(n)
    seen = set()
    for r in i.refs:
        if r in seen or r == i.target:
            continue
        seen.add(r)
        d = an.describe_ref(r)
        if d:
            parts.append(d)
        elif r != i.mem_target:
            parts.append(f"{r:#x}")
    return "; ".join(parts)


def function_lines(an: Analysis, f: Function) -> list[Line]:
    lines: list[Line] = []
    name = an.name(f.addr) or f.name
    callers = sorted({x.frm for x in an.xrefs_to.get(f.addr, []) if x.kind in ("call", "jmp")})
    lines.append(Line("func", f.addr, f"{name}:"))
    for c in callers[:8]:
        lines.append(Line("xref", f.addr, f"; XREF from {an.location(c)}", target=c))
    if len(callers) > 8:
        lines.append(Line("xref", f.addr, f"; ... {len(callers) - 8} more xrefs"))
    if f.is_import:
        lines.append(Line("insn", f.addr, comment="imported function"))
        return lines
    labels = set(f.blocks) - {f.addr}
    prev_end = None
    for a in sorted(f.blocks):
        blk = f.blocks[a]
        if prev_end is not None and prev_end != a:
            lines.append(Line("blank", prev_end))
        if a in labels:
            lines.append(Line("label", a, f"{an.label(a)}:"))
        for i in blk.insns:
            lines.append(insn_line(an, i))
        prev_end = blk.end
    return lines


def insn_line(an: Analysis, i: Insn) -> Line:
    tgt = i.target if i.target is not None else (i.refs[0] if i.refs else None)
    return Line("insn", i.addr, raw=i.raw, mnemonic=i.mnemonic, operands=operands(an, i),
                comment=comment(an, i), target=tgt)


def render(lines: list[Line], show_bytes: bool = True) -> str:
    out = []
    for ln in lines:
        if ln.kind == "func":
            out.append("")
            out.append(f"{ln.addr:016x}  {ln.text}" if ln.addr >> 32 else f"{ln.addr:08x}  {ln.text}")
        elif ln.kind in ("xref", "label"):
            out.append(f"{'':10}{ln.text}")
        elif ln.kind == "blank":
            out.append("")
        else:
            addr = f"{ln.addr:016x}" if ln.addr >> 32 else f"{ln.addr:08x}"
            raw = ln.raw.hex(" ")
            raw = (raw if len(raw) <= 23 else raw[:20] + "..").ljust(24) if show_bytes else ""
            ins = f"{ln.mnemonic} {ln.operands}".strip().ljust(36)
            c = f"; {ln.comment}" if ln.comment else ""
            out.append(f"  {addr}  {raw}{ins}{c}".rstrip())
    return "\n".join(out)

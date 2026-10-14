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
    for a, (old, new) in getattr(an, "patches", {}).items():
        if a <= i.addr < a + len(new):
            parts.append(f"patched (was {old.hex(' ')})" if a == i.addr else "patched")
            break
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
    data = code_data(an, f)
    items = sorted([(a, 0) for a in f.blocks] + [(a, 1) for a in data])
    prev_end = None
    for a, is_data in items:
        if prev_end is not None and prev_end != a:
            lines.append(Line("blank", prev_end))
        if is_data:
            lines.append(data_line(an, a, *data[a]))
            prev_end = a + data[a][0]
            continue
        blk = f.blocks[a]
        if a in labels:
            lines.append(Line("label", a, f"{an.label(a)}:"))
        for i in blk.insns:
            lines.append(insn_line(an, i))
        prev_end = blk.end
    return lines


_DATA_OPS = {1: ".byte", 2: ".short", 4: ".word", 8: ".quad"}


def code_data(an: Analysis, f: Function) -> dict[int, tuple[int, str, int | None]]:
    """Data the function keeps among code: address -> (size, kind, case target), kind "pool" (a literal
    loaded pc-relative: ARM `ldr r0, [pc, #n]`, AArch64 `ldr x0, #addr`) or "case" (an inline
    jump-table entry: Thumb `tbb` / `tbh`, ARM `ldr pc, [pc, rI, lsl #2]`)."""
    arch = an.bin.arch
    if arch not in ("arm", "arm64"):
        return {}
    out: dict[int, tuple[int, str, int | None]] = {}
    for blk in f.blocks.values():
        for i in blk.insns:
            m = i.mnemonic.split(".")[0]
            ops = i.op_str.replace(" ", "")
            if arch == "arm" and m in ("ldr", "ldrd", "ldrh", "ldrb", "ldrsh", "ldrsb", "vldr") and ",[pc" in ops:
                if ops.startswith("pc,"):                    # ldr pc, [pc, rI, lsl #2]: a table
                    for k, t in enumerate(f.jump_tables.get(i.addr, ())):
                        out[i.addr + 8 + 4 * k] = (4, "case", t)
                    continue
                mm = re.search(r"\[pc,#(-?0x[0-9a-f]+|-?\d+)\]", ops)
                if mm is None:
                    continue
                base = (i.addr + (4 if i.thumb else 8)) & ~3
                size = {"ldrd": 8, "ldrh": 2, "ldrsh": 2, "ldrb": 1, "ldrsb": 1}.get(m, 4)
                if m == "vldr" and ops.startswith("d"):
                    size = 8
                out[base + int(mm.group(1), 0)] = (size, "pool", None)
            elif arch == "arm" and m in ("tbb", "tbh"):
                size = 1 if m == "tbb" else 2
                for k, t in enumerate(f.jump_tables.get(i.addr, ())):
                    out[i.addr + 4 + size * k] = (size, "case", t)
            elif arch == "arm64" and m in ("ldr", "ldrsw") and "[" not in ops:
                mm = re.search(r",#(0x[0-9a-f]+)$", ops)
                if mm is not None:
                    out[int(mm.group(1), 16)] = (8 if ops[0] in "xd" else 4, "pool", None)
    # only what is in code and not code itself
    spans = [(b.addr, b.end) for b in f.blocks.values()]
    return {a: v for a, v in sorted(out.items()) if an.bin.is_exec(a) and
            not any(lo <= a < hi for lo, hi in spans) and an.function_at(a) in (None, f)}


def data_line(an: Analysis, addr: int, size: int, kind: str, case: int | None = None) -> Line:
    raw = an.bin.read(addr, size)
    v = int.from_bytes(raw, an.bin.endian)
    if kind == "case":
        note = f"jump table -> {an.label(case)}" if case is not None else "jump table"
        return Line("insn", addr, raw=raw, mnemonic=_DATA_OPS[size], operands=f"{v:#x}", comment=note,
                    target=case)
    tgt = v if size >= 4 and an.bin.is_mapped(v) else None
    text = an.label(v) if tgt is not None and an.name(v) else f"{v:#x}"
    note = an.describe_ref(v) if tgt is not None else ""
    return Line("insn", addr, raw=raw, mnemonic=_DATA_OPS[size], operands=text,
                comment="literal" + (f"; {note}" if note else ""), target=tgt)


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

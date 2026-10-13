"""String and cross-reference extraction over IR.

The disassembly-level analysis already tracks strings and xrefs
(`relic.analysis`). These helpers lift the same ideas onto the (optimised)
IR so decompiler output stays searchable: `ir_xrefs` reports the code and
data a function reaches by constant, and `format_ir` prints the IR with the
referenced strings and symbols spelled out inline.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .ir import CallStmt, Const, IndirectJump, IRFunction, Stmt, fmt_stmt, stmt_exprs, walk

if TYPE_CHECKING:
    from ..analysis import Analysis


@dataclass(frozen=True)
class IRRef:
    """A constant reference found in a function's IR."""
    frm: int      # address of the instruction the constant came from
    to: int       # referenced address
    kind: str     # call | jmp | code | string | data


def _kind(an: "Analysis", v: int) -> str | None:
    """How a constant address is used, or None if it isn't a meaningful reference."""
    b = an.bin
    if not b.is_mapped(v):
        return None
    if an.string_at(v) is not None:
        return "string"
    if an.function_at(v) is not None:
        return "code"
    sec = b.section_at(v)
    if sec is not None and sec.x:
        return "code"
    # a readable C string sitting in a data section
    if sec is not None and sec.loaded and not sec.x:
        s = b.read_cstring(v, 64)
        if s and len(s) >= 3 and s.isprintable():
            return "string"
    # otherwise only keep it when it resolves to something nameable
    return "data" if an.describe_ref(v) is not None else None


def ir_xrefs(fn: IRFunction, an: "Analysis") -> list[IRRef]:
    """Constant code/data references a function makes, most control-flow first."""
    refs: list[IRRef] = []
    seen: set[tuple[int, int, str]] = set()

    def add(frm: int, to: int, kind: str):
        key = (frm, to, kind)
        if key not in seen:
            seen.add(key)
            refs.append(IRRef(frm, to, kind))

    for b in fn.blocks.values():
        for s in b.stmts:
            if isinstance(s, CallStmt) and isinstance(s.call.target, Const):
                add(s.addr, s.call.target.value, "call")
            elif isinstance(s, IndirectJump):
                for t in s.targets:
                    add(s.addr, t, "jmp")
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, Const) and not (isinstance(s, CallStmt) and x is s.call.target):
                        k = _kind(an, x.value)
                        if k is not None:
                            add(s.addr, x.value, k)
    refs.sort(key=lambda r: ({"call": 0, "jmp": 1, "code": 2, "string": 3, "data": 4}[r.kind], r.frm))
    return refs


def _annotations(s: Stmt, an: "Analysis") -> str:
    """Inline notes for the constants a single statement references."""
    parts: list[str] = []
    done: set[int] = set()
    for top in stmt_exprs(s):
        for x in walk(top):
            if not isinstance(x, Const) or x.value == 0 or x.value in done:
                continue
            if isinstance(s, CallStmt) and x is s.call.target and s.name:
                continue  # already shown by the call's own tag
            desc = an.describe_ref(x.value)
            if desc is not None:
                done.add(x.value)
                parts.append(f"{x.value:#x} {desc}")
    return ", ".join(parts)


def format_ir(fn: IRFunction, an: "Analysis") -> str:
    """Like `str(fn)`, but with referenced strings and symbols spelled out."""
    out = [f"function {fn.name} @ {fn.addr:#x}"]
    for a in sorted(fn.blocks):
        b = fn.blocks[a]
        succs = ", ".join(f"{x:#x}" for x in b.succs) or "-"
        out.append(f"  block {a:#x}:  ; succs {succs}")
        for s in b.stmts:
            line = f"    {s.addr:8x}  {fmt_stmt(s)}"
            note = _annotations(s, an)
            if note:
                line += f"    ; {note}"
            out.append(line)
    return "\n".join(out)


__all__ = ["IRRef", "ir_xrefs", "format_ir"]

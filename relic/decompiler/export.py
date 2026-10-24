"""The whole binary's pseudocode as one C file.

Struct declarations come first, once each (every function's pseudocode repeats the ones it
uses); then each function in address order. A function that fails to decompile leaves a
comment saying why instead of stopping the export. Progress goes through `relic.progress`
(stage "export"), so a GUI can show it and cancel between functions.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, TextIO

from ..progress import Cancelled, checkpoint, report

if TYPE_CHECKING:
    from ..analysis import Analysis, Function


def _split(an: "Analysis", func: "Function", d) -> tuple[list[list[str]], list[str]]:
    """(the struct declaration blocks above the function, the function's own lines)."""
    lines = d.lines
    start = next((k for k, ln in enumerate(lines) if ln.addr == func.addr and ln.depth == 0), 0)
    blocks: list[list[str]] = []
    cur: list[str] = []
    for ln in lines[:start]:
        if not ln.text.strip():
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(ln.text)
    if cur:
        blocks.append(cur)
    body = [("    " * ln.depth + ln.text).rstrip() for ln in lines[start:]]
    return blocks, body


def export_c(an: "Analysis", out: TextIO, funcs: list["Function"] | None = None, batch: bool = False) -> dict:
    """Write the pseudocode of `funcs` (default: every function of the binary but imported
    stubs) to `out`. Returns {"functions": n written, "failed": [names], "structs": n}.
    `batch`: nothing edits the analysis meanwhile (the command line): see pipeline.prepared_once."""
    if batch:
        from .pipeline import prepared_once
        with prepared_once():
            return export_c(an, out, funcs)
    from .emit import decompile
    if funcs is None:
        funcs = [f for f in sorted(an.functions.values(), key=lambda f: f.addr) if not f.is_import]
    structs: dict[str, list[str]] = {}            # first line -> block (one per struct)
    bodies: list[list[str]] = []
    failed: list[str] = []
    total = len(funcs)
    for k, f in enumerate(funcs):
        checkpoint()
        report("export", k, total)
        name = an.name(f.addr) or f.name
        try:
            d = decompile(an, f)
        except Cancelled:
            raise
        except Exception as e:  # noqa: BLE001 - one function does not stop the export
            failed.append(name)
            bodies.append([f"// {name} @ {f.addr:#x}: not decompiled ({type(e).__name__}: {e})"])
            continue
        blocks, body = _split(an, f, d)
        for blk in blocks:
            structs.setdefault(blk[0], blk)
        bodies.append([f"// {name} @ {f.addr:#x}"] + body)
    report("export", total, total)
    out.write(f"/* {an.bin.path}: pseudocode by relic ({an.bin.describe()}) */\n\n")
    out.write("#include <stdint.h>\n\n")
    for blk in structs.values():
        out.write("\n".join(blk) + "\n\n")
    for body in bodies:
        out.write("\n".join(body) + "\n\n")
    return {"functions": total - len(failed), "failed": failed, "structs": len(structs)}


__all__ = ["export_c"]

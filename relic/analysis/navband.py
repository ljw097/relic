"""What each part of the loaded image is, for the navigation band: function code, library
code, import stubs, data, and executable bytes no function covers (unexplored)."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import Analysis

KINDS = ("code", "library", "import", "data", "unexplored")


def _merge(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for s, e, k in sorted(spans):
        if out and out[-1][2] == k and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e), k)
        elif out and s < out[-1][1]:
            s = out[-1][1]                    # (overlapping blocks of two functions: the first wins)
            if s < e:
                out.append((s, e, k))
        else:
            out.append((s, e, k))
    return out


def band_regions(an: "Analysis") -> list[tuple[int, int, str]]:
    """(start, end, kind) over every loaded section, in address order, covering each section
    exactly."""
    funcs = []
    starts = sorted(an.functions)
    for f in an.functions.values():
        kind = "import" if f.is_import else "library" if f.library else "code"
        for b in f.blocks.values():
            if b.end > b.addr:
                funcs.append((b.addr & ~1, b.end, kind))
        if f.is_import and not f.blocks:          # a PLT stub: up to the next function, one entry
            k = starts.index(f.addr)
            nxt = starts[k + 1] if k + 1 < len(starts) else f.addr + 16
            funcs.append((f.addr, min(nxt, f.addr + 16), "import"))
    funcs = _merge(funcs)
    out: list[tuple[int, int, str]] = []
    secs = sorted((s for s in an.bin.sections if s.size and s.addr), key=lambda s: s.addr)
    k = 0
    for sec in secs:
        if not sec.x:
            out.append((sec.addr, sec.end, "data"))
            continue
        if sec.name.startswith(".plt"):            # (the stubs and the resolver trampoline)
            out.append((sec.addr, sec.end, "import"))
            continue
        a = sec.addr
        while k < len(funcs) and funcs[k][1] <= a:
            k += 1
        j = k
        while a < sec.end:
            if j < len(funcs) and funcs[j][0] < sec.end:
                s, e, kind = funcs[j]
                if s > a:
                    out.append((a, s, "unexplored"))
                    a = s
                out.append((a, min(e, sec.end), kind))
                a = min(e, sec.end)
                j += 1
            else:
                out.append((a, sec.end, "unexplored"))
                a = sec.end
    return [r for r in out if r[1] > r[0]]


__all__ = ["KINDS", "band_regions"]

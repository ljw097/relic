"""The call graph around one function (IDA's xref graph / proximity browser): its callers to the
left, its callees to the right, `depth` levels each way."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import Analysis

MAX_PER_LEVEL = 40


def callees(an: "Analysis", addr: int) -> list[int]:
    f = an.functions.get(addr)
    if f is None:
        return []
    return sorted(t for t in f.calls | f.tail_calls if t in an.functions and t != addr)


def callers(an: "Analysis", addr: int) -> list[int]:
    f = an.functions.get(addr)
    if f is None:
        return []
    out = set()
    for site in f.callers:
        g = an.function_at(site)
        if g is not None and g.addr != addr:
            out.add(g.addr)
    # tail calls (`jmp f`) are calls too
    out |= {g.addr for g in an.functions.values() if addr in g.tail_calls and g.addr != addr}
    return sorted(out)


def call_graph(an: "Analysis", addr: int, depth: int = 1) -> tuple[dict[int, int], set[tuple[int, int]], set[int]]:
    """({function: level}, {(caller, callee)}, {functions left out at the edge of a level}).
    Level 0 is `addr`, negative levels its callers, positive its callees; a function reached
    both ways keeps the level it was reached at first."""
    levels = {addr: 0}
    edges: set[tuple[int, int]] = set()
    more: set[int] = set()
    for sign, step in ((1, callees), (-1, callers)):
        frontier = [addr]
        for d in range(1, depth + 1):
            nxt = []
            for a in frontier:
                found = step(an, a)
                if len(found) > MAX_PER_LEVEL:
                    more.add(a)
                    found = found[:MAX_PER_LEVEL]
                for b in found:
                    edges.add((a, b) if sign > 0 else (b, a))
                    if b not in levels:
                        levels[b] = sign * d
                        nxt.append(b)
            frontier = nxt
    return levels, edges, more


__all__ = ["call_graph", "callees", "callers"]

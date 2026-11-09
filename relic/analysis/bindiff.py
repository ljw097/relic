"""Binary diffing (BinDiff, Diaphora): which functions of an old build are which in a new one,
which of them changed and how much, and what was added or removed -- the starting point of
patch diffing (what did the vendor's fix change?) and of carrying work over to a new build.

Functions are compared by their position-independent code (`lumina.normalized`, with calls to
imported and library functions written as the name), so a function that only moved, or lost
its symbol, is identical. Matching
goes from the surest evidence to the weakest, each pass only among functions not matched yet:

1. identical code that occurs once on each side;
2. the same name (a symbol, a library signature's or the user's, not a generated `sub_...`)
   that occurs once on each side;
3. the call graph: the unmatched callees and callers of a matched pair, by similarity;
4. everything left, by similarity, with a higher bar.

Similarity is difflib's ratio of the two normalized instruction lists: 1.0 is the same code.
"""
from __future__ import annotations

import difflib
import hashlib
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .lumina import normalized

if TYPE_CHECKING:
    from . import Analysis
    from .functions import Function

NEIGHBOUR_MIN = 0.5     # a callee / caller of a matched pair: the call graph already points to it
GLOBAL_MIN = 0.7        # anywhere else: only clearly the same function
GLOBAL_PAIRS_MAX = 2_000_000    # size-compatible pairs the last pass compares at most


@dataclass
class Match:
    old: int                # function address in the old binary
    new: int                # ... and in the new one
    name: str               # the new side's name (else the old side's)
    how: str                # "code", "name", "calls" or "similar"
    similarity: float       # 1.0: the same code

    @property
    def identical(self) -> bool:
        return self.similarity == 1.0


@dataclass
class BinDiff:
    old: "Analysis"
    new: "Analysis"
    matches: list[Match] = field(default_factory=list)
    removed: list[int] = field(default_factory=list)    # only in the old binary
    added: list[int] = field(default_factory=list)      # only in the new binary

    def changed(self) -> list[Match]:
        """Matched functions whose code differs, the most changed first."""
        return sorted((m for m in self.matches if not m.identical), key=lambda m: (m.similarity, m.new))

    def find(self, name_or_addr: str) -> Match | None:
        """The match for a function named (or at an address) in either binary."""
        for an, side in ((self.new, "new"), (self.old, "old")):
            a = an.resolve(name_or_addr)
            f = an.function_at(a) if a is not None else None
            if f is not None:
                for m in self.matches:
                    if getattr(m, side) == f.addr:
                        return m
        return None

    def summary(self) -> dict:
        same = sum(1 for m in self.matches if m.identical)
        return {"identical": same, "changed": len(self.matches) - same,
                "added": len(self.added), "removed": len(self.removed)}

    def to_json(self) -> dict:
        def fn(an, a):
            return {"addr": a, "name": an.name(a) or f"sub_{a:x}"}
        return {"summary": self.summary(),
                "matches": [{"old": m.old, "new": m.new, "name": m.name, "how": m.how,
                             "similarity": round(m.similarity, 4)} for m in sorted(self.matches, key=lambda m: m.new)],
                "added": [fn(self.new, a) for a in self.added],
                "removed": [fn(self.old, a) for a in self.removed]}


class _Side:
    """One binary's comparable functions: their normalized code, real names and call graph."""

    def __init__(self, an: "Analysis"):
        self.an = an
        self.funcs: dict[int, Function] = {a: f for a, f in an.functions.items() if not f.is_import and f.blocks}
        self.lines = {a: code_lines(an, f) for a, f in self.funcs.items()}
        self.hash = {a: hashlib.sha256("\n".join(ls).encode()).hexdigest() for a, ls in self.lines.items()}
        self.real = {a: n for a in self.funcs if (n := real_name(an, a))}
        self.callees = {a: {t for t in f.calls | f.tail_calls if t in self.funcs} for a, f in self.funcs.items()}
        self.callers: dict[int, set[int]] = {a: set() for a in self.funcs}
        for a, ts in self.callees.items():
            for t in ts:
                self.callers[t].add(a)

    def size(self, a: int) -> int:
        return len(self.lines[a])


def real_name(an: "Analysis", addr: int) -> str | None:
    """A name that says which function this is: the user's, a symbol's or a library
    signature's; not a generated `sub_...` nor a guess from the code (auto names)."""
    n = an.renames.get(addr)
    if n:
        return n
    f = an.functions.get(addr)
    if f is None or not f.name or f.name.startswith("sub_"):
        return None
    return an.name(addr) if f.name.startswith("_Z") else f.name


def code_lines(an: "Analysis", f: "Function") -> list[str]:
    """`f`'s position-independent code, calls to imported and library functions written as
    their names (they are named in a stripped build too; the binary's own functions are not)."""
    def callee(t):
        g = an.functions.get(t)
        return g.name if g is not None and (g.is_import or g.library) else None
    return normalized(an, f, callee=callee)


def similarity(a: list[str], b: list[str]) -> float:
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def diff(old: "Analysis", new: "Analysis") -> BinDiff:
    """Match the functions of two analysed binaries (see the module docstring)."""
    A, B = _Side(old), _Side(new)
    pairs: dict[int, tuple[int, str]] = {}      # old addr -> (new addr, how)
    taken: set[int] = set()                     # new addresses matched
    sims: dict[tuple[int, int], float] = {}

    def take(a: int, b: int, how: str):
        pairs[a] = (b, how)
        taken.add(b)

    # 1. identical code, unique on both sides
    ha, hb = Counter(A.hash.values()), Counter(B.hash.values())
    by_hash = {h: b for b, h in B.hash.items() if hb[h] == 1}
    for a, h in A.hash.items():
        if ha[h] == 1 and h in by_hash and A.size(a) > 1:
            take(a, by_hash[h], "code")

    # 2. the same real name, unique on both sides
    na, nb = Counter(A.real.values()), Counter(B.real.values())
    by_name = {n: b for b, n in B.real.items() if nb[n] == 1}
    for a, n in A.real.items():
        b = by_name.get(n)
        if a not in pairs and na[n] == 1 and b is not None and b not in taken:
            take(a, b, "name")

    # 3. the call graph: neighbours of matched pairs, until nothing more is found
    work = list(pairs.items())
    while work:
        a, (b, _) = work.pop()
        for ga, gb in ((A.callees, B.callees), (A.callers, B.callers)):
            ca = [x for x in ga[a] if x not in pairs]
            cb = [y for y in gb[b] if y not in taken]
            for _, x, y in _best_pairs(ca, cb, A, B, sims, NEIGHBOUR_MIN):
                if x not in pairs and y not in taken:
                    take(x, y, "calls")
                    work.append((x, pairs[x]))

    # 4. what is left, anywhere
    ca = [x for x in A.funcs if x not in pairs]
    cb = [y for y in B.funcs if y not in taken]
    for _, x, y in _best_pairs(ca, cb, A, B, sims, GLOBAL_MIN, GLOBAL_PAIRS_MAX):
        if x not in pairs and y not in taken:
            take(x, y, "similar")

    out = BinDiff(old, new)
    for a, (b, how) in sorted(pairs.items(), key=lambda p: p[1][0]):
        s = 1.0 if A.hash[a] == B.hash[b] else \
            min(sims.get((a, b)) or similarity(A.lines[a], B.lines[b]), 0.9999)     # (1.0: only the same code)
        out.matches.append(Match(a, b, new.name(b) or old.name(a) or f"sub_{b:x}", how, s))
    out.removed = sorted(a for a in A.funcs if a not in pairs)
    out.added = sorted(b for b in B.funcs if b not in taken)
    return out


def _best_pairs(ca: list[int], cb: list[int], A: _Side, B: _Side, sims: dict, floor: float,
                limit: int | None = None) -> list[tuple[float, int, int]]:
    """Pairs of `ca` x `cb` at least `floor` alike, best first (to be taken greedily). `sims`
    caches ratios by (old, new); `limit` caps how many size-compatible pairs are compared."""
    cands = []
    n = 0
    sm = difflib.SequenceMatcher(None, autojunk=False)
    for y in cb:
        ly = B.size(y)
        sm.set_seq2(B.lines[y])                 # (the expensive side: indexed once per function)
        for x in ca:
            lx = A.size(x)
            if 2 * min(lx, ly) / (lx + ly) < floor:     # (the most two lists this long can share)
                continue
            n += 1
            if limit is not None and n > limit:
                break
            s = sims.get((x, y))
            if s is None:
                sm.set_seq1(A.lines[x])
                if sm.quick_ratio() < floor:
                    continue
                s = sims[(x, y)] = sm.ratio()
            if s >= floor:
                cands.append((s, x, y))
        else:
            continue
        break
    # best first; ties: the pair closest in address order (sorted lists keep the layout)
    cands.sort(key=lambda c: (-c[0], abs(c[1] - c[2])))
    return cands


def function_diff(d: BinDiff, m: Match, decompiled: bool = False) -> list[str]:
    """A unified diff of one matched function: its normalized code, or its pseudocode."""
    def text(an, a):
        f = an.functions[a]
        if decompiled:
            from ..decompiler.emit import decompile
            return decompile(an, f).text.splitlines()
        # (a block's line is the label its branches name: `B3` -> `L3:`)
        return [f"L{ln[1:]}:" if " " not in ln else "    " + ln for ln in code_lines(an, f)]
    old, new = text(d.old, m.old), text(d.new, m.new)
    return list(difflib.unified_diff(old, new, f"old:{d.old.name(m.old) or hex(m.old)} @ {m.old:#x}",
                                     f"new:{m.name} @ {m.new:#x}", lineterm=""))


__all__ = ["BinDiff", "Match", "diff", "function_diff", "similarity"]

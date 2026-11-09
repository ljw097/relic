"""Binary diffing (BinDiff, Diaphora): which functions of an old build are which in a new one,
which of them changed and how much, and what was added or removed -- the starting point of
patch diffing (what did the vendor's fix change?) and of carrying work over to a new build.

Functions are compared by their position-independent code (`lumina.normalized`, with calls to
imported and library functions written as the name), so a function that only moved, or lost
its symbol, is identical. Matching goes from the surest evidence to the weakest, each pass
only among functions not matched yet:

1. identical code that occurs once on each side;
2. the same name (a symbol, a library signature's or the user's, not a generated `sub_...`)
   that occurs once on each side;
3. everything left, by similarity, with a higher bar.

After the first two, and again after the third, the call graph: the unmatched callees and
callers of every new pair, by similarity, and theirs in turn.

Similarity is difflib's ratio of the two normalized instruction lists, block numbers left out
(`comparable`): 1.0 is the same code.
"""
from __future__ import annotations

import difflib
import hashlib
import re
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
NEIGHBOUR_PAIRS_MAX = 20_000    # ... one pair's callees (or callers) at most (a hub like xmalloc)


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
        self.keys = {a: comparable(ls) for a, ls in self.lines.items()}
        self.hash = {a: hashlib.sha256("\n".join(ls).encode()).hexdigest() for a, ls in self.lines.items()}
        self.real = {a: n for a in self.funcs if (n := real_name(an, a))}
        self.callees = {a: {t for t in f.calls | f.tail_calls if t in self.funcs} for a, f in self.funcs.items()}
        self.callers: dict[int, set[int]] = {a: set() for a in self.funcs}
        for a, ts in self.callees.items():
            for t in ts:
                self.callers[t].add(a)

    def size(self, a: int) -> int:
        return len(self.keys[a])


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


_LABEL = re.compile(r"\b[BL]\d+\b")


def comparable(lines: list[str]) -> list[str]:
    """`lines` without block numbers: one block inserted near the start renumbers every label
    after it, which is not a change of those lines."""
    return [_LABEL.sub(lambda m: m.group(0)[0], ln) for ln in lines]


def similarity(a: list[str], b: list[str]) -> float:
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def diff(old: "Analysis", new: "Analysis") -> BinDiff:
    """Match the functions of two analysed binaries (see the module docstring)."""
    m = _Matcher(_Side(old), _Side(new))
    m.propagate(m.by_code() + m.by_name())      # (names first: the call graph only guesses)
    m.propagate(m.by_similarity())
    return m.result()


class _Matcher:
    """The matching state: old address -> (new address, how), and the ratios computed so far."""

    def __init__(self, A: _Side, B: _Side):
        self.A, self.B = A, B
        self.pairs: dict[int, tuple[int, str]] = {}
        self.taken: set[int] = set()            # new addresses matched
        self.sims: dict[tuple[int, int], float] = {}

    def take(self, a: int, b: int, how: str) -> bool:
        if a in self.pairs or b in self.taken:
            return False
        self.pairs[a] = (b, how)
        self.taken.add(b)
        return True

    def take_best(self, ca: list[int], cb: list[int], floor: float, how: str, limit: int | None = None) -> list:
        """Greedily match the most alike of `ca` x `cb` (at least `floor`); the new pairs."""
        return [(x, y) for _, x, y in _best_pairs(ca, cb, self.A, self.B, self.sims, floor, limit)
                if self.take(x, y, how)]

    def by_code(self) -> list:
        """Identical code that occurs once on each side."""
        A, B = self.A, self.B
        ha, hb = Counter(A.hash.values()), Counter(B.hash.values())
        by_hash = {h: b for b, h in B.hash.items() if hb[h] == 1}
        return [(a, by_hash[h]) for a, h in A.hash.items()
                if ha[h] == 1 and h in by_hash and self.take(a, by_hash[h], "code")]

    def by_name(self) -> list:
        """The same real name, occurring once on each side."""
        A, B = self.A, self.B
        na, nb = Counter(A.real.values()), Counter(B.real.values())
        by_name = {n: b for b, n in B.real.items() if nb[n] == 1}
        return [(a, by_name[n]) for a, n in A.real.items()
                if na[n] == 1 and n in by_name and self.take(a, by_name[n], "name")]

    def by_similarity(self) -> list:
        """Whatever is left, anywhere, when clearly the same function."""
        ca = [x for x in self.A.funcs if x not in self.pairs]
        cb = [y for y in self.B.funcs if y not in self.taken]
        return self.take_best(ca, cb, GLOBAL_MIN, "similar", GLOBAL_PAIRS_MAX)

    def propagate(self, seeds: list):
        """The call graph: the unmatched callees and callers of each matched pair, by
        similarity, and theirs in turn, until nothing more is found."""
        A, B = self.A, self.B
        work = list(seeds)
        while work:
            a, b = work.pop()
            for ga, gb in ((A.callees, B.callees), (A.callers, B.callers)):
                ca = [x for x in ga[a] if x not in self.pairs]
                cb = [y for y in gb[b] if y not in self.taken]
                work += self.take_best(ca, cb, NEIGHBOUR_MIN, "calls", NEIGHBOUR_PAIRS_MAX)

    def result(self) -> BinDiff:
        A, B = self.A, self.B
        out = BinDiff(A.an, B.an)
        for a, (b, how) in sorted(self.pairs.items(), key=lambda p: p[1][0]):
            if A.hash[a] == B.hash[b]:
                s = 1.0
            else:
                s = self.sims.get((a, b))
                if s is None:
                    s = similarity(A.keys[a], B.keys[b])
                s = min(s, 0.9999)              # (1.0: only the same code)
            out.matches.append(Match(a, b, B.an.name(b) or A.an.name(a) or f"sub_{b:x}", how, s))
        out.removed = sorted(a for a in A.funcs if a not in self.pairs)
        out.added = sorted(b for b in B.funcs if b not in self.taken)
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
        sm.set_seq2(B.keys[y])                  # (the expensive side: indexed once per function)
        for x in ca:
            lx = A.size(x)
            if 2 * min(lx, ly) / (lx + ly) < floor:     # (the most two lists this long can share)
                continue
            n += 1
            if limit is not None and n > limit:
                break
            s = sims.get((x, y))
            if s is None:
                sm.set_seq1(A.keys[x])
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
    """A unified diff of one matched function: its normalized code, or its pseudocode. Lines
    are lined up by what they say without block numbers (see `comparable`), so a block added
    near the start shows as itself, not as every later label renumbered."""
    def text(an, a):
        f = an.functions[a]
        if decompiled:
            from ..decompiler.emit import decompile
            try:
                return decompile(an, f).text.splitlines()
            except Exception as e:  # noqa: BLE001 - one side not decompiled is still worth showing
                return [f"// not decompiled ({type(e).__name__}: {e})"]
        # (a block's line is the label its branches name: `B3` -> `L3:`)
        return [f"L{ln[1:]}:" if " " not in ln else "    " + ln for ln in code_lines(an, f)]
    old, new = text(d.old, m.old), text(d.new, m.new)
    sm = difflib.SequenceMatcher(None, comparable(old), comparable(new), autojunk=False)
    groups = list(sm.get_grouped_opcodes(3))
    if not groups:
        return []
    out = [f"--- old:{d.old.name(m.old) or hex(m.old)} @ {m.old:#x}", f"+++ new:{m.name} @ {m.new:#x}"]
    for g in groups:
        i1, i2, j1, j2 = g[0][1], g[-1][2], g[0][3], g[-1][4]
        out.append(f"@@ -{i1 + 1},{i2 - i1} +{j1 + 1},{j2 - j1} @@")
        for tag, a1, a2, b1, b2 in g:
            if tag == "equal":
                out += [" " + ln for ln in old[a1:a2]]
                continue
            out += ["-" + ln for ln in old[a1:a2]] + ["+" + ln for ln in new[b1:b2]]
    return out


__all__ = ["BinDiff", "Match", "comparable", "diff", "function_diff", "similarity"]

"""Where a raw firmware image is loaded, guessed from what it holds: absolute pointers to its
own strings (the base that makes the most pointer-sized words land on string starts) and a
Cortex-M vector table (Thumb handler addresses inside the image).

`guess_base(data, bits, endian)` returns candidates, best first; `relic ... --base auto` loads at
the best one and `relic info` on a raw image lists them."""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

ALIGN = 0x1000
_MIN_STR = 5
_STRING = re.compile(rb"(?:^|(?<=\0))([\t\n\r\x20-\x7e]{%d,})\0" % _MIN_STR)


@dataclass
class BaseGuess:
    base: int
    score: int
    reason: str


def _strings(data: bytes) -> list[int]:
    """Offsets of NUL-terminated printable strings that start after a NUL (or at 0)."""
    return [m.start(1) for m in _STRING.finditer(data)]


def _words(data: bytes, size: int, endian: str) -> set[int]:
    vals = set()
    for k in range(0, len(data) - size + 1, size):
        v = int.from_bytes(data[k:k + size], endian)
        if v >= 0x100 and v != (1 << 8 * size) - 1:
            vals.add(v)
    return vals


def _vector_table(data: bytes, endian: str, align: int) -> BaseGuess | None:
    """A Cortex-M vector table at the start: the stack pointer, then handlers (odd: Thumb) that
    all fall inside one aligned window as large as the image."""
    if len(data) < 64:
        return None
    words = [int.from_bytes(data[k:k + 4], endian) for k in range(0, 64, 4)]
    sp, handlers = words[0], [w for w in words[1:] if w]
    if sp & 3 or len(handlers) < 4 or not all(h & 1 for h in handlers):
        return None
    lo, hi = min(handlers) & ~1, max(handlers) & ~1
    if hi - lo >= len(data):
        return None
    base = lo & ~(align - 1)
    if hi >= base + len(data):
        return None
    return BaseGuess(base, len(handlers), f"Cortex-M vector table (reset {words[1]:#x})")


def guess_base(data: bytes, bits: int = 32, endian: str = "little", align: int = ALIGN,
               limit: int = 5) -> list[BaseGuess]:
    size = bits // 8
    strings = _strings(data)
    votes: dict[int, set[int]] = defaultdict(set)
    if strings:
        by_low = defaultdict(list)
        for s in strings:
            by_low[s % align].append(s)
        for v in _words(data, size, endian):
            for s in by_low.get(v % align, ()):
                b = v - s
                if b >= 0:
                    votes[b].add(s)
    guesses = {b: BaseGuess(b, len(hit), f"{len(hit)} pointers to strings") for b, hit in votes.items()
               if len(hit) >= 2}
    vt = _vector_table(data, endian, align) if bits == 32 else None
    if vt is not None:
        g = guesses.get(vt.base)
        if g is not None:
            g.score += vt.score
            g.reason += "; " + vt.reason
        else:
            guesses[vt.base] = vt
    # a base that is a common pointer target only because of small numbers is weaker than one
    # far from 0; ties go to the lower base
    return sorted(guesses.values(), key=lambda g: (-g.score, g.base))[:limit]


__all__ = ["BaseGuess", "guess_base"]

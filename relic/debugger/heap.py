"""The glibc heap of a stopped process (pwndbg's `heap` / `tcachebins`), without libc symbols.

The main arena's heap is the `[heap]` mapping: chunks follow one another from its start, each
a `prev_size` word and a `size` word whose low bits are flags (PREV_INUSE 1, IS_MMAPPED 2,
NON_MAIN_ARENA 4). A chunk is free when the next chunk's PREV_INUSE bit is clear -- except
tcache and fastbin chunks, which stay marked in use; the tcache lists name those. The first
chunk is the thread's `tcache_perthread_struct` (glibc 2.26+): `counts[64]` (uint16 since 2.30,
uint8 before) then `entries[64]`, each the user pointer of the first chunk of that size, chained
through the chunk's first word -- mangled since 2.32 (safe-linking: `next ^ (address >> 12)`).

Everything here works on a `read(addr, size) -> bytes | None` function, so it is the same on a
live process and on bytes in a test.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA = 1, 2, 4
TCACHE_BINS = 64
MAX_CHUNKS = 4096          # chunks listed at most
MAX_CHAIN = 64             # entries followed per tcache list at most

Reader = Callable[[int, int], "bytes | None"]


@dataclass
class Chunk:
    addr: int                       # the chunk header (prev_size)
    size: int                       # without the flag bits
    flags: int
    state: str = "used"             # used / free / tcache / top
    data: bytes = b""               # the first bytes of user data

    @property
    def user(self) -> int:
        """What malloc returned for it."""
        return self.addr + 2 * self._word

    _word: int = 8

    def flag_text(self) -> str:
        return "|".join(n for b, n in ((PREV_INUSE, "PREV_INUSE"), (IS_MMAPPED, "IS_MMAPPED"),
                                       (NON_MAIN_ARENA, "NON_MAIN_ARENA")) if self.flags & b)


@dataclass
class TcacheBin:
    size: int                       # chunk size of the bin
    count: int                      # what the struct says
    entries: list[int] = field(default_factory=list)   # user pointers, in list order
    broken: str = ""                # why the walk stopped early (a pointer outside the heap, a loop)


@dataclass
class Heap:
    start: int
    end: int
    word: int
    chunks: list[Chunk] = field(default_factory=list)
    tcache: list[TcacheBin] = field(default_factory=list)
    safe_linking: bool | None = None    # None: no list to tell by
    truncated: bool = False             # stopped before the end (corrupt size, or too many chunks)
    note: str = ""

    def chunk_of(self, user: int) -> Chunk | None:
        return next((c for c in self.chunks if c.user == user), None)


def _int(b: bytes, off: int, n: int) -> int:
    return int.from_bytes(b[off:off + n], "little")


def walk(read: Reader, start: int, end: int, word: int = 8, preview: int = 16) -> Heap:
    """Every chunk from `start` (the heap's first chunk) to the top chunk, and the tcache."""
    heap = Heap(start, end, word)
    align = 2 * word
    data = read(start, end - start) or b""
    if len(data) < 2 * word:
        heap.note = "cannot read the heap"
        return heap
    end = start + len(data)
    a = start
    if word == 4 and _int(data, word, word) & ~7 == 0:
        a += 8                                  # (i386: the first chunk is placed so user data is 16-aligned)
    while a + 2 * word <= end:
        raw = _int(data, a - start + word, word)
        size, flags = raw & ~7, raw & 7
        if size < 2 * word or size % align or a + size > end:
            if size >= 2 * word and size % align == 0 and a + size > end:   # the top chunk runs past
                heap.chunks.append(Chunk(a, size, flags, "top", _word=word))
            else:
                heap.truncated = True
                heap.note = f"bad chunk size {raw:#x} at {a:#x}"
            break
        off = a - start + 2 * word
        c = Chunk(a, size, flags, data=data[off:off + min(preview, size - 2 * word)], _word=word)
        heap.chunks.append(c)
        if a + size >= end:
            c.state = "top"
            break
        if len(heap.chunks) >= MAX_CHUNKS:
            heap.truncated = True
            heap.note = f"more than {MAX_CHUNKS} chunks"
            break
        a += size
    # free: the next chunk's PREV_INUSE is clear
    for k, c in enumerate(heap.chunks[:-1]):
        if not heap.chunks[k + 1].flags & PREV_INUSE:
            c.state = "free"
    _tcache(heap, data, word)
    return heap


def _tcache(heap: Heap, data: bytes, word: int):
    """The tcache lists, from the first chunk (`tcache_perthread_struct`)."""
    if not heap.chunks or heap.chunks[0].state == "top":
        return
    first = heap.chunks[0]
    body = first.size - 2 * word
    wide = body >= 2 * TCACHE_BINS + word * TCACHE_BINS     # uint16 counts (glibc 2.30+)
    cw = 2 if wide else 1
    if body < cw * TCACHE_BINS + word * TCACHE_BINS:
        return                                              # not a tcache (glibc < 2.26?)
    base = first.addr - heap.start + 2 * word
    counts = [_int(data, base + cw * k, cw) for k in range(TCACHE_BINS)]
    eoff = base + cw * TCACHE_BINS
    eoff += -eoff % word
    heads = [_int(data, eoff + word * k, word) for k in range(TCACHE_BINS)]
    if any(c > 0xFFFF for c in counts):
        return
    by_user = {c.user: c for c in heap.chunks}

    def inside(p: int) -> bool:
        return heap.start <= p < heap.end

    def chain(head: int, mangled: bool) -> tuple[list[int], str]:
        out, seen, p = [], set(), head
        while p and len(out) < MAX_CHAIN:
            if not inside(p):
                return out, f"{p:#x} is outside the heap"
            if p in seen:
                return out, f"loop at {p:#x}"
            seen.add(p)
            out.append(p)
            off = p - heap.start
            if off + word > len(data):
                return out, f"cannot read {p:#x}"
            nxt = _int(data, off, word)
            p = nxt ^ (p >> 12) if mangled else nxt
        return out, ""

    # safe-linking or not: the reading under which more lists stay inside the heap (a list's
    # last link is 0 stored as `address >> 12` when mangled, which the other reading leaves)
    heads_used = [h for k, h in enumerate(heads) if h and counts[k]]
    good = {m: sum(not chain(h, m)[1] for h in heads_used) for m in (True, False)}
    if good[True] != good[False]:
        heap.safe_linking = good[True] > good[False]
    mangled = bool(heap.safe_linking)
    for k, h in enumerate(heads):
        if not counts[k] and not h:
            continue
        entries, broken = chain(h, mangled)
        size = (k + 2) * 16 if word == 8 else (k + 1) * 16          # chunk size of bin k
        heap.tcache.append(TcacheBin(size, counts[k], entries, broken))
        for p in entries:
            c = by_user.get(p)
            if c is not None and c.state != "top":
                c.state = "tcache"


__all__ = ["Chunk", "Heap", "TcacheBin", "walk"]

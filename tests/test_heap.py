"""The glibc heap view (relic.debugger.heap): chunk walk and tcache lists."""
import os
import shutil
import subprocess

import pytest

from relic.debugger.heap import walk
from test_debugger import needs_gdb

HERE = os.path.dirname(__file__)
BASE = 0x555555559000


def _heap(chunks, word=8):
    """Bytes of a heap made of (size with flags, user bytes) chunks, then a top chunk."""
    out = bytearray()
    for size, body in chunks:
        hdr = (0).to_bytes(word, "little") + size.to_bytes(word, "little")
        out += hdr + body.ljust((size & ~7) - 2 * word, b"\0")
    out += (0).to_bytes(word, "little") + (0x20d51).to_bytes(word, "little")
    return bytes(out)


def _tcache_struct(heads: dict, counts: dict, word=8) -> bytes:
    c = b"".join(counts.get(k, 0).to_bytes(2, "little") for k in range(64))
    e = b"".join(heads.get(k, 0).to_bytes(word, "little") for k in range(64))
    return c + e


def _reader(data: bytes, base=BASE):
    return lambda a, n: data[a - base:a - base + n] or None


@pytest.mark.parametrize("mangled", [True, False])
def test_walk_chunks_and_tcache(mangled):
    # chunks: tcache struct (0x290), A used (0x20), B tcache (0x20), C free (0x30), D used (0x20)
    a, b, c, d = BASE + 0x290, BASE + 0x2b0, BASE + 0x2d0, BASE + 0x300
    link = (b + 0x10) >> 12 if mangled else 0          # B is the last entry: next = 0
    data = _heap([(0x291, _tcache_struct({0: b + 0x10}, {0: 1})), (0x21, b"AAAA"), (0x21, link.to_bytes(8, "little")),
                  (0x31, b"\x10" * 16), (0x20, b"DDDD")])          # D: PREV_INUSE clear -> C is free
    h = walk(_reader(data), BASE, BASE + len(data) + 0x20000)
    assert [(ch.addr, ch.size, ch.state) for ch in h.chunks] == [
        (BASE, 0x290, "used"), (a, 0x20, "used"), (b, 0x20, "tcache"), (c, 0x30, "free"), (d, 0x20, "used"),
        (d + 0x20, 0x20d50, "top")]
    assert h.chunks[1].data.startswith(b"AAAA") and h.chunks[1].user == a + 0x10
    assert h.chunks[1].flag_text() == "PREV_INUSE"
    assert [(t.size, t.count, t.entries) for t in h.tcache] == [(0x20, 1, [b + 0x10])]
    assert h.safe_linking is mangled and not h.truncated and h.chunk_of(b + 0x10).state == "tcache"


def test_corrupt_size_and_broken_list():
    b = BASE + 0x2b0
    data = _heap([(0x291, _tcache_struct({0: b + 0x10}, {0: 2})), (0x21, b""),
                  (0x21, (0x4141414141414141).to_bytes(8, "little"))])
    h = walk(_reader(data), BASE, BASE + len(data) + 0x20000)
    t = h.tcache[0]
    assert t.entries == [b + 0x10] and "outside the heap" in t.broken
    bad = bytearray(data)
    bad[0x298:0x2a0] = (0x19).to_bytes(8, "little")            # a size that is not a multiple of 16
    h = walk(_reader(bytes(bad)), BASE, BASE + len(bad))
    assert h.truncated and "bad chunk size 0x19" in h.note and len(h.chunks) == 1


@needs_gdb
def test_live_heap(tmp_path):
    from relic.debugger import Session
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("needs gcc")
    exe = str(tmp_path / "heap")
    subprocess.run([cc, "-O0", "-o", exe, os.path.join(HERE, "src", "heap.c")], check=True)
    s = Session(exe)
    try:
        s.start("entry")
        assert s.heap() is None                      # no malloc yet
        s.add_named_breakpoint("stop_here")
        assert s.cont(timeout=20).get("reason") == "breakpoint-hit"
        h = s.heap()
        assert h is not None and not h.truncated, h and h.note
        rdi = dict((n, v) for n, v, _ in s.gprs())["rdi"]
        used = h.chunk_of(rdi)
        assert used is not None and used.state == "used" and used.data.startswith(b"AAAABBBB")
        sizes = {t.size: t for t in h.tcache}
        assert sizes[0x20].count == 2 and len(sizes[0x20].entries) == 2      # e, then d
        assert sizes[0x30].count == 1 and not sizes[0x20].broken
        assert all(h.chunk_of(p).state == "tcache" for t in h.tcache for p in t.entries)
        assert any(c.state == "free" and c.size == 0x510 for c in h.chunks)
        assert h.chunks[-1].state == "top"
    finally:
        s.close()

import pytest

from relic.analysis import analyze
from relic.analysis.vulns import _unbounded_scanf
from relic.loader import load_bytes
from relic.analysis import Analysis

FUNCS = ("win", "menu", "add_note", "show_note", "del_note", "checksum", "classify", "vuln", "main")


@pytest.fixture(scope="module")
def an(vuln64):
    return analyze(vuln64)


def test_functions(an):
    names = {an.name(a) for a in an.functions}
    assert set(FUNCS) <= names
    main = an.function_by_name("main")
    callees = {an.name(t) for t in main.calls}
    assert {"vuln", "menu", "classify", "add_note", "show_note", "del_note"} <= callees


def test_noreturn_and_imports(an):
    exit_ = an.function_by_name("exit")
    assert exit_.is_import and exit_.noreturn
    menu = an.function_by_name("menu")
    call_exit = [b for b in menu.blocks.values() if an.call_name(b.last) == "exit"]
    assert call_exit and all(not b.succs for b in call_exit)


@pytest.mark.parametrize("fixture", ["vuln64", "vuln64_pie"])
def test_jump_table(request, fixture):
    a = analyze(request.getfixturevalue(fixture))
    f = a.function_by_name("classify")
    assert len(f.jump_tables) == 1
    targets = next(iter(f.jump_tables.values()))
    assert len(targets) == 6
    assert all(t in f.blocks for t in targets)


def test_xrefs(an):
    menu = an.function_by_name("menu").addr
    callers = {an.function_at(x.frm).name for x in an.xrefs_to[menu] if x.kind == "call"}
    assert callers == {"main"}
    binsh = next(s for s in an.strings if s.value == "/bin/sh")
    users = [an.function_at(x.frm) for x in an.xrefs_to[binsh.addr]]
    assert [f.name for f in users] == ["win"]


def test_stripped_recovers_functions(vuln64, vuln64_stripped):
    full = analyze(vuln64)
    bare = analyze(vuln64_stripped)
    assert bare.function_by_name("main").addr == full.function_by_name("main").addr
    want = {full.function_by_name(n).addr for n in FUNCS}
    assert want <= set(bare.functions)


def test_checksec(vuln64, vuln64_pie):
    weak = analyze(vuln64).checksec()
    assert weak["PIE"].startswith("No PIE")
    assert weak["Stack"] == "No canary found"
    assert weak["NX"] == "NX enabled"
    strong = analyze(vuln64_pie).checksec()
    assert strong["PIE"] == "PIE enabled"
    assert strong["RELRO"] == "Full RELRO"
    assert strong["Stack"] == "Canary found"


@pytest.mark.parametrize("fixture", ["vuln64", "vuln64_pie", "vuln64_stripped"])
def test_vulns(request, fixture):
    a = analyze(request.getfixturevalue(fixture))
    found = {(v.kind, a.function_at(v.addr).addr) for v in a.vulns()}
    by = lambda n: a.resolve(n) if fixture != "vuln64_stripped" else None
    kinds = {k for k, _ in found}
    assert {"format-string", "dangerous-call", "win-function"} <= kinds
    if by("show_note"):
        assert ("format-string", by("show_note")) in found
        assert ("dangerous-call", by("vuln")) in found
        assert ("win-function", by("win")) in found
    # constant formats such as printf("> ") must not be flagged
    assert ("format-string", a.function_by_name("menu").addr if a.function_by_name("menu") else -1) not in found


def test_scanf_width():
    assert _unbounded_scanf("%s")
    assert _unbounded_scanf("%d %[^\n]")
    assert not _unbounded_scanf("%31s")
    assert not _unbounded_scanf("%d")
    assert not _unbounded_scanf("100%%s")


def test_project_roundtrip(vuln64, tmp_path):
    a = analyze(vuln64)
    win = a.function_by_name("win").addr
    a.rename(win, "get_shell")
    a.comment(win, "ret2win")
    p = tmp_path / "proj.relic.json"
    a.save_project(str(p))
    b = analyze(vuln64)
    assert b.load_project(str(p))
    assert b.name(win) == "get_shell" and b.comments[win] == "ret2win"
    assert b.resolve("get_shell+4") == win + 4


def test_raw_shellcode():
    # xor eax,eax; jz +2; inc eax; inc eax; ret
    an = Analysis(load_bytes(bytes.fromhex("31c07402ffc0ffc0c3"), arch="x64", base=0x1000)).run()
    f = an.functions[0x1000]
    assert sorted(f.blocks) == [0x1000, 0x1004, 0x1006]
    assert sorted(f.blocks[0x1000].succs) == [0x1004, 0x1006]


def test_vulns_use_decompiled_arguments_on_x86_32(vuln32):
    """cdecl passes arguments on the stack: the format-string and ret2win checks need them."""
    from relic.analysis import analyze
    findings = analyze(vuln32).vulns()
    kinds = {(f.func, f.kind) for f in findings}
    assert ("show_note", "format-string") in kinds
    assert ("win", "win-function") in kinds
    assert ("vuln", "dangerous-call") in kinds
    assert not any(f.func == "menu" and f.kind == "format-string" for f in findings)   # scanf("%d")


def _plain_gap_walk(cover, first, end, probe, probed, tried, found):
    """The gap scan as the plain walk: every gap from where it resumes, skipping probed ones."""
    pos = first
    while True:
        gap = cover.next_gap(pos, end)
        if gap is None:
            return
        s, e = gap
        start = probed.get(gap, probed)
        if start is probed:
            start = probed[gap] = probe(s, e)
        if start is None or start in tried:
            pos = e
            continue
        tried.add(start)
        blocks = found(start)
        for bs, be in blocks:
            cover.add(bs, be)
        pos = max(first, min([s] + [bs for bs, _ in blocks]))


def test_gap_walk_skips_only_what_the_plain_walk_skips():
    """_walk_gaps visits only gaps not probed yet: the same probes, in the same order, and the same
    functions as walking every gap (random covers, probe results and functions found)."""
    import random

    from relic.analysis.functions import _Cover, _walk_gaps

    def run(seed, walk):
        rnd = random.Random(seed)
        first, end = rnd.randint(0, 10), rnd.choice([30, 80, 200, 600])
        cover = _Cover()
        for _ in range(rnd.randint(0, end // 8)):
            s = rnd.randint(first, end)
            cover.add(s, s + rnd.randint(1, 12))
        log = []

        def probe(s, e):
            log.append(("probe", s, e))
            r = random.Random(f"{seed} {s} {e}")
            x = r.random()
            return None if x < 0.45 else s if x < 0.55 else r.randint(s, max(s, e - 1))

        def found(start):
            log.append(("found", start))
            r = random.Random(f"{seed} {start}")
            out = []
            for _ in range(r.choice([0, 1, 1, 2, 3, 5])):
                bs = r.choice([start, start, r.randint(first, end - 1), max(first, start - r.randint(1, 40))])
                out.append((bs, bs + r.randint(1, 15)))
            return out
        walk(cover, first, end, probe, {}, set(), found)
        return log, cover.starts, cover.ends

    for seed in range(3000):
        assert run(seed, _walk_gaps) == run(seed, _plain_gap_walk), seed

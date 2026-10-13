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

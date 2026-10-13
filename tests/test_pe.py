"""Windows PE: loader, COFF symbols, IAT calls, checksec, vulns and decompilation (MinGW samples)."""
import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile


@pytest.fixture(scope="module", params=["vuln64_pe", "vuln32_pe"])
def pe(request):
    return request.param, analyze(request.getfixturevalue(request.param))


def test_loader_and_symbols(pe):
    name, an = pe
    b = an.bin
    assert b.format == "PE"
    assert b.arch == ("x64" if name.startswith("vuln64") else "x86")
    assert "msvcrt.dll" in [lib.lower() for lib in b.libraries]
    assert {"gets", "system"} <= {i.name for i in b.imports}
    # MinGW links its own printf statically: either way it must be known by name
    assert "printf" in {i.name for i in b.imports} or an.function_by_name("printf") is not None
    # COFF symbol table: user functions keep their names (x86 `_name` decoration dropped)
    for fn in ("main", "vuln", "checksum", "win", "show_note"):
        assert an.function_by_name(fn) is not None, fn


def test_iat_calls_are_named(pe):
    _, an = pe
    f = an.function_by_name("vuln")
    calls = {an.call_name(i) for blk in f.blocks.values() for i in blk.insns if i.kind == "call"}
    assert "gets" in {(c or "").split("@")[0] for c in calls}


def test_checksec(pe):
    _, an = pe
    cs = an.checksec()
    assert cs.get("DEP/NX") == "Yes" and "ASLR" in cs


def test_vulns(pe):
    _, an = pe
    kinds = {(f.func, f.kind) for f in an.vulns()}
    assert ("vuln", "dangerous-call") in kinds
    assert ("show_note", "format-string") in kinds
    assert ("win", "win-function") in kinds


def test_decompile(pe):
    name, an = pe
    code = decompile(an, an.function_by_name("vuln")).text
    assert code.startswith("void vuln(void)")
    assert "gets(buf_" in code and 'printf("hello %s (%d)\\n", buf_' in code and "checksum(buf_" in code
    code = decompile(an, an.function_by_name("checksum")).text
    assert code.startswith("int checksum(char *a1)")
    assert "> 100000" in code and "0x1337" in code

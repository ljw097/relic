"""Searches: byte patterns, text, immediates, instructions (relic.analysis.search, `relic search`)."""
import pytest

from relic.__main__ import main
from relic.analysis import analyze
from relic.analysis.search import PatternError, find_bytes, find_imm, find_insn, find_text, parse_pattern


@pytest.fixture(scope="module")
def an(vuln64):
    return analyze(vuln64)


def test_pattern_parsing():
    assert parse_pattern("48 8b ?? 05").match(b"\x48\x8b\x99\x05")
    assert not parse_pattern("48 8b ?? 05").match(b"\x48\x8c\x99\x05")
    assert parse_pattern("488b??05").match(b"\x48\x8b\x00\x05")
    assert parse_pattern("48 8B ? 05").match(b"\x48\x8b\xff\x05")
    with pytest.raises(PatternError):
        parse_pattern("48 zz")
    with pytest.raises(PatternError):
        parse_pattern("")


def test_bytes_with_wildcards_finds_every_call_site(an):
    calls = [i.addr for f in an.functions.values() if not f.is_import for b in f.blocks.values()
             for i in b.insns if i.raw[:1] == b"\xe8"]
    hits = {h.addr for h in find_bytes(an, "e8 ?? ?? ?? ??")}
    assert set(calls) <= hits


def test_text_ascii_and_case(an):
    s = next(s for s in an.strings if s.value == "/bin/sh")
    assert s.addr in {h.addr for h in find_text(an, "/BIN/SH")}
    assert s.addr not in {h.addr for h in find_text(an, "/BIN/SH", case=True)}


def test_immediate_and_displacement(an):
    assert any(an.function_at(h.addr).name == "checksum" for h in find_imm(an, 100000))
    assert find_imm(an, -0x40) or find_imm(an, 0x40)        # rbp - 0x40 buffer accesses


def test_instruction_regex_sees_symbol_names(an):
    hits = find_insn(an, r"call\s+(gets|system)\b")
    assert {an.function_at(h.addr).name for h in hits} == {"vuln", "win"}


@pytest.mark.parametrize("fixture", ["vuln_a64", "vuln_arm", "vuln_thumb", "vuln32_pie"])
def test_other_architectures(request, fixture):
    a = analyze(request.getfixturevalue(fixture))
    assert find_text(a, "name?")
    assert any(a.function_at(h.addr).name == "vuln" for h in find_insn(a, "gets"))


def test_cli(vuln64, capsys):
    assert main(["search", vuln64, "--insn", "call.*gets"]) == 0
    out = capsys.readouterr().out
    assert "vuln+0x" in out and "call gets" in out
    assert main(["search", vuln64, "--text", "/bin/sh"]) == 0
    assert ".rodata+0x" in capsys.readouterr().out

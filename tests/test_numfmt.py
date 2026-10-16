"""How numbers are shown (IDA's H / R / B / O): relic.numfmt, the listing and the pseudocode."""
import shutil

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.listing import function_lines
from relic.numfmt import apply_formats, char_literal, format_number, numbers_in, operand_at, split_operands


def test_format_number():
    assert format_number(16, "hex") == "0x10" and format_number(0x10, "dec") == "16"
    assert format_number(-8, "hex") == "-0x8" and format_number(0xfffffff8, "dec", 32) == "-8"
    assert format_number(0x41424344, "char", 32) == "'ABCD'" and format_number(2, "char") is None
    assert format_number(10, "bin") == "0b1010"
    assert format_number(0x401000, "offset", 64, lambda v: "main") == "main"
    assert char_literal(0x410A) == "'A\\n'"


def test_operands_split_and_rewrite():
    op = "qword ptr [rbp + rax*8 - 0x20], 0x41"
    assert split_operands(op) == [(0, 30), (31, 36)]
    assert operand_at(op, 3) == 0 and operand_at(op, 33) == 1
    assert numbers_in(op) == [8, 0x20, 0x41] and numbers_in("rax, -0x8") == [-8]   # (`- 0x20`: an operator)
    assert apply_formats(op, {"1": "char"}, 64) == "qword ptr [rbp + rax*8 - 0x20], 'A'"
    assert apply_formats(op, {"0": "dec"}, 64) == "qword ptr [rbp + rax*8 - 32], 0x41"
    assert apply_formats("r0, #0x10", {"1": "dec"}, 32) == "r0, #16"         # ARM immediates
    assert apply_formats("$a0, $zero, 16", {"2": "hex"}, 32) == "$a0, $zero, 0x10"   # MIPS
    assert apply_formats("eax, 0x2", {"1": "char"}, 32) == "eax, 0x2"       # (unprintable: unchanged)


def _add_note(an):
    f = an.function_by_name("add_note")
    i = next(i for b in f.blocks.values() for i in b.insns if i.mnemonic == "mov" and i.op_str == "edi, 0x10")
    return f, i.addr


def _operands(an, f, addr):
    return next(ln.operands for ln in function_lines(an, f) if ln.kind == "insn" and ln.addr == addr)


def test_listing_and_pseudocode_formats(vuln64, tmp_path):
    path = tmp_path / "vuln64"
    shutil.copy(vuln64, path)
    an = analyze(str(path))
    f, addr = _add_note(an)
    an.set_operand_format(addr, 1, "dec")
    assert _operands(an, f, addr) == "edi, 16"
    an.set_operand_format(addr, 1, "bin")
    assert _operands(an, f, addr) == "edi, 0b10000"
    assert "malloc(16)" in decompile(an, f).text
    an.set_number_format(f.addr, 16, "hex")
    assert "malloc(0x10)" in decompile(an, f).text
    # saved with the project, and undone one edit at a time
    an.save_project()
    again = analyze(str(path))
    assert _operands(again, f, addr) == "edi, 0b10000" and "malloc(0x10)" in decompile(again, f).text
    an.undo()
    assert "malloc(16)" in decompile(an, f).text
    an.undo()
    assert _operands(an, f, addr) == "edi, 16"
    an.set_operand_format(addr, 1, "")
    assert _operands(an, f, addr) == "edi, 0x10" and addr not in an.op_formats
    with pytest.raises(ValueError):
        an.set_operand_format(addr, 1, "roman")

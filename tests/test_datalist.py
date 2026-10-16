"""Memory outside functions (relic.datalist) and the code / data definitions (IDA's U C D A * P)."""
import shutil

import pytest

from relic.analysis import analyze
from relic.datalist import region_lines, window


@pytest.fixture
def an(vuln64, tmp_path):
    path = tmp_path / "vuln64"
    shutil.copy(vuln64, path)
    return analyze(str(path))


def _lines(an, addr):
    return [ln for ln in region_lines(an, *window(an, addr)) if ln.kind == "data" or ln.kind == "insn"]


def _at(an, addr):
    return next(ln for ln in _lines(an, addr) if ln.addr == addr)


def test_automatic_items(an):
    binsh = an.bin.read(0x402004, 8)
    assert binsh == b"/bin/sh\0"
    ln = _at(an, 0x402004)
    assert ln.mnemonic == "db" and ln.operands == '"/bin/sh", 0' and ln.comment == "string"
    labels = [ln.text for ln in region_lines(an, *window(an, 0x402004)) if ln.kind == "label"]
    assert any(t.startswith("unk_402004:") and "xref: win+" in t for t in labels)
    notes = an.resolve("notes")
    assert _at(an, notes).operands.endswith("dup(0)")          # .bss: a run of zeros


def test_definitions_and_undo(an, tmp_path):
    a = 0x402004
    an.define_data(a, "qword")
    ln = _at(an, a)
    assert ln.mnemonic == "dq" and ln.raw == b"/bin/sh\0"
    an.define_data(a, "array", count=2, element="dword")
    ln = _at(an, a)
    assert ln.mnemonic == "dd" and ln.comment == "dword[2]" and len(ln.operands.split(",")) == 2
    an.undefine(a)                                         # back to what the analysis shows
    assert _at(an, a).comment == "string"
    an.undefine(a)                                         # and again: plain bytes
    assert _at(an, a).operands.startswith("0x2f, 0x62")
    an.define_data(a, "string")
    assert an.data_defs[a] == ["string", 8] and _at(an, a).operands == '"/bin/sh", 0'
    an.save_project()
    again = analyze(an.bin.path)
    assert again.data_defs == {a: ["string", 8]}
    an.undo()
    assert an.data_defs[a] == ["undef"]
    with pytest.raises(ValueError):
        an.define_data(a, "array", count=0)


def test_code_mark_create_and_delete_function(an):
    win = an.function_by_name("win")
    an.delete_function(win.addr)
    assert win.addr not in an.functions and an.function_at(win.addr) is None
    an.define_data(win.addr, "code")                       # C: listed as instructions
    insns = [ln for ln in _lines(an, win.addr) if ln.kind == "insn"]
    assert insns and insns[0].addr == win.addr
    an.save_project()
    assert win.addr not in analyze(an.bin.path).functions  # (the deletion is saved)
    an.create_function(win.addr)                           # P: a function again
    assert win.addr in an.functions and win.addr not in an.data_defs
    an.undo()
    assert win.addr not in an.functions                    # (undo analyses again)
    an.redo()
    assert win.addr in an.functions
    with pytest.raises(ValueError):
        an.create_function(an.resolve("notes"))            # not code

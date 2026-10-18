"""Auto-analysis on gcc -O2 x86-64 code: switch tables whose base register is set out of sight of
the dispatch, a switch over negative cases, a tail call through a function pointer after the
epilogue, and `.eh_frame` as the list of functions (with `.cold` fragments kept out of it)."""
import io
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.disasm import JMP

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "jumps.c")


@pytest.fixture(scope="module", params=["plain", "stripped"])
def jumps(request, tmp_path_factory):
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("needs gcc")
    out = str(tmp_path_factory.mktemp("jumps") / "jumps")
    subprocess.run([cc, "-O2", "-w", "-o", out, SRC], check=True)
    if request.param == "stripped":
        subprocess.run(["strip", out], check=True)
    return request.param, out


def _fn(an, name, stripped, src_hint):
    """A function by name, or (stripped) the one whose pseudocode contains `src_hint`."""
    if not stripped:
        return an.function_by_name(name)
    for f in an.functions.values():
        if not f.is_import and src_hint in decompile(an, f).text:
            return f
    raise AssertionError(name)


def test_switch_tables_resolved(jumps):
    """Every `jmp reg` of the program's own functions is a resolved switch or a tail call."""
    kind, path = jumps
    an = analyze(path)
    for f in an.functions.values():
        crt = {an.bin.name_to_addr.get(n) for n in ("deregister_tm_clones", "register_tm_clones")}
        if f.is_import or f.addr in crt or f.name in ("deregister_tm_clones", "register_tm_clones"):
            continue
        for blk in f.blocks.values():
            i = blk.last
            if i.kind == JMP and i.target is None and i.addr not in f.jump_tables:
                text = decompile(an, f).text
                assert "unresolved" not in text, f"{f.name} {i.addr:#x}\n{text}"


def test_negative_case_switch(jumps):
    kind, path = jumps
    an = analyze(path)
    f = _fn(an, "neg", kind == "stripped", 'printf("dddd")')
    assert sorted(len(t) for t in f.jump_tables.values()) == [5]      # -5 .. -1, not 512 entries
    code = decompile(an, f).text
    assert "switch (" in code and "case -5:" in code and "case -1:" in code and "goto" not in code, code


def test_hoisted_table_base(jumps):
    """Two switches in a loop, their table bases loaded once ahead of it."""
    kind, path = jumps
    an = analyze(path)
    f = next(f for f in an.functions.values() if sorted(len(t) for t in f.jump_tables.values()) == [6, 7])
    if kind == "plain":
        assert f.name == "loop"
    code = decompile(an, f).text
    assert code.count("switch (") == 2 and "unresolved" not in code, code


def test_tail_call_through_pointer(jumps):
    kind, path = jumps
    an = analyze(path)
    f = _fn(an, "via", kind == "stripped", '"%d %d"')
    code = decompile(an, f).text
    assert "unresolved" not in code and ")(printf(" in code, code


def test_eh_frame_functions(jumps):
    """Every function entry `.eh_frame` describes is found (the PLT aside); `.cold` fragments
    have FDEs of their own but stay part of their function."""
    from elftools.elf.elffile import ELFFile
    kind, path = jumps
    an = analyze(path)
    with open(path, "rb") as f:
        dwarf = ELFFile(io.BytesIO(f.read())).get_dwarf_info()
    entries, cold = set(), set()
    for e in dwarf.EH_CFI_entries():
        if type(e).__name__ == "FDE":
            cfa = e.get_decoded().table[0]["cfa"]
            (entries if (cfa.reg, cfa.offset) == (7, 8) else cold).add(e.header["initial_location"])
    entries = {a for a in entries if not an.bin.section_at(a).name.startswith(".plt")}
    assert entries <= set(an.functions)
    cold = {a for a in cold if an.bin.section_at(a).name == ".text"}
    assert cold and not cold & set(an.functions)                # (neg.cold, loop.cold, ...)

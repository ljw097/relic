"""Auto-analysis on gcc -O2 x86-64 code: switch tables whose base register is set out of sight of
the dispatch, a switch over negative cases, a tail call through a function pointer after the
epilogue, `.eh_frame` as the list of functions (with `.cold` fragments kept out of it), and
functions found without it (noreturn functions, tail calls, pointers in data)."""
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


@pytest.fixture(scope="module")
def noeh(tmp_path_factory):
    """tests/src/noret.c without unwind info: (symbols of the plain build, stripped build)."""
    from elftools.elf.elffile import ELFFile
    cc = shutil.which("gcc")
    if cc is None or shutil.which("objcopy") is None:
        pytest.skip("needs gcc and objcopy")
    d = tmp_path_factory.mktemp("noret")
    plain, stripped = str(d / "noret"), str(d / "noret.stripped")
    subprocess.run([cc, "-O2", "-w", "-fno-asynchronous-unwind-tables", "-fcf-protection", "-o", plain,
                    os.path.join(HERE, "src", "noret.c")], check=True)
    subprocess.run(["objcopy", "--remove-section", ".eh_frame", "--remove-section", ".eh_frame_hdr",
                    "--strip-all", plain, stripped], check=True)
    with open(plain, "rb") as f:
        elf = ELFFile(io.BytesIO(f.read()))
        text = elf.get_section_by_name(".text")
        lo, hi = text["sh_addr"], text["sh_addr"] + text["sh_size"]
        syms = {s.name: s["st_value"] for s in elf.get_section_by_name(".symtab").iter_symbols()
                if s["st_info"]["type"] == "STT_FUNC" and lo <= s["st_value"] < hi}
    return syms, stripped


def test_functions_without_unwind_info(noeh):
    """Every function is found and none runs on into the next: past calls of functions that do not
    return (found from their code), tail calls of a function nothing else reaches, functions only
    in a table of pointers."""
    syms, path = noeh
    an = analyze(path)
    assert set(syms.values()) <= set(an.functions)
    starts = set(syms.values())
    for f in an.functions.values():
        for blk in f.blocks.values():
            for i in blk.insns:
                assert i.addr == f.addr or i.addr not in starts, f"{f.name} runs into {i.addr:#x}"
    assert an.functions[syms["fatal"]].noreturn and an.functions[syms["usage"]].noreturn
    assert not an.functions[syms["parse"]].noreturn and not an.functions[syms["main"]].noreturn
    assert syms["change_case"] in an.functions[syms["upcase"]].tail_calls


def test_calls_through_function_pointer_variables(noeh):
    """A variable's targets: its initial value and the functions the code stores to it. A call
    through one holding only a function that does not return does not return either."""
    syms, path = noeh
    an = analyze(path)
    checked = an.functions[syms["checked"]]
    sites = {a: v for a, v in an.icalls.items() if checked.block_at(a) is not None}
    assert sorted(sites.values(), key=len) == [
        (frozenset({syms["die_cb"]}), True), (frozenset({syms["log_plain"], syms["log_loud"]}), True)]
    fatal = next(a for a, (t, _) in sites.items() if syms["die_cb"] in t)
    assert not checked.block_at(fatal).succs                     # (the call ends its block)
    assert any(x.frm == fatal for x in an.xrefs_to[syms["die_cb"]])


def test_data_among_code(tmp_path):
    """What the code reads in `.text` is data: a string (not a function), numbers, a table of
    function pointers -- whose functions are found."""
    import platform
    cc = shutil.which("gcc")
    if cc is None or platform.machine() not in ("x86_64", "AMD64"):
        pytest.skip("needs gcc for x86-64")
    out = str(tmp_path / "datacode")
    subprocess.run([cc, "-o", out, os.path.join(HERE, "src", "datacode.S")],
                   check=True, capture_output=True)
    subprocess.run(["strip", out], check=True)
    an = analyze(out)
    main = an.function_by_name("main")
    lea = next(i for i in main.insns() if i.mnemonic == "lea")
    msg = lea.refs[0]
    assert an.code_data[msg] == ["string", 16] and msg not in an.functions
    assert 'puts("hello from text")' in decompile(an, main).text
    kinds = sorted(d[:2] for a, d in an.code_data.items() if a != msg)
    assert kinds == [["array", "byte"], ["array", "dword"], ["array", "qword"]]
    table = next(a for a, d in an.code_data.items() if d[:2] == ["array", "qword"])
    ptrs = [an.bin.read_ptr(table + 8 * k) for k in range(an.code_data[table][2])]
    assert len(ptrs) == 2 and all(p in an.functions for p in ptrs)
    from relic.datalist import region_lines, window
    text = "\n".join(f"{ln.mnemonic} {ln.operands}" for ln in region_lines(an, *window(an, msg)))
    assert 'db "hello from text", 0' in text and "dd 2, 3, 4" in text

"""ARM32: A32 and Thumb-2 lifting, interworking, AAPCS calls, PLT stubs, switch tables, vulns
(arm-linux-gnueabihf-gcc samples)."""
import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile


@pytest.fixture(scope="module", params=["vuln_arm", "vuln_thumb"])
def an(request):
    return request.param, analyze(request.getfixturevalue(request.param))


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


def test_functions_and_imports(an):
    _, a = an
    names = {f.name for f in a.functions.values() if not f.is_import}
    assert {"main", "menu", "vuln", "checksum", "add_note", "show_note", "win"} <= names
    assert not any(n.startswith("sub_") for n in names)            # no misdecoded Thumb / PLT
    imports = {f.name for f in a.functions.values() if f.is_import}
    assert {"puts", "gets", "malloc", "free", "read"} <= imports


def test_vuln(an):
    name, a = an
    code = _c(a, "vuln")
    assert code.startswith("void vuln(void)")
    assert "char buf_4c[64];  // sp0-0x4c" in code
    assert "gets(buf_4c)" in code and '"hello %s (%d)\\n"' in code
    assert "// stack canary at sp0-" in code and "__stack_chk" not in code.replace("// stack canary", "")


def test_menu_strings_and_scanf(an):
    _, a = an
    code = _c(a, "menu")
    assert 'puts("1. add");' in code and '__isoc99_scanf("%d", &var_10)' in code
    assert "__asm" not in code and "goto" not in code


def test_checksum(an):
    _, a = an
    code = _c(a, "checksum")
    assert code.startswith("int checksum(char *a1)") and "> 100000" in code


def test_main(an):
    _, a = an
    code = _c(a, "main")
    assert code.startswith("int main(int argc, ") and "while (1) {" in code
    assert "setvbuf(" in code and "stdout" in code
    assert " r3" not in code                                         # alignment push of r3 hidden


def test_classify_switch(vuln_arm):
    a = analyze(vuln_arm)
    code = _c(a, "classify")
    assert "switch (" in code and "case 5:" in code and "default:" in code    # addls pc, pc, rX, lsl #2


def test_vulns(an):
    _, a = an
    kinds = {(f.func, f.kind) for f in a.vulns()}
    assert ("vuln", "dangerous-call") in kinds
    assert ("win", "win-function") in kinds


def test_every_function_decompiles(an):
    _, a = an
    for f in a.functions.values():
        if not f.is_import:
            text = decompile(a, f).text
            assert text.count("{") == text.count("}"), f.name


@pytest.mark.parametrize("name", ["vuln_arm_stripped", "vuln_thumb_stripped", "vuln_a64_stripped",
                                  "vuln_a64_pie_stripped"])
def test_stripped_binary_finds_main_and_win(request, name):
    """No symbols at all: `main` from __libc_start_main's argument in `_start` (a GOT slot here),
    functions only reached through pointers (`win`) from a prologue scan of the gaps."""
    a = analyze(request.getfixturevalue(name))
    main = a.function_by_name("main")
    assert main is not None
    code = decompile(a, main).text
    assert code.startswith("int main(int argc, ") and "setvbuf(" in code and "while (1) {" in code
    kinds = {f.kind for f in a.vulns()}
    assert "win-function" in kinds and "dangerous-call" in kinds
    assert len([f for f in a.functions.values() if not f.is_import]) >= 14


def test_listing_shows_literal_pools_and_inline_tables(vuln_arm, flow_thumb_O2):
    """Data kept among code is listed as data, not left out (or decoded as instructions)."""
    from relic.listing import function_lines
    an = analyze(vuln_arm)
    f = an.function_by_name("main")
    lines = function_lines(an, f)
    pool = [ln for ln in lines if ln.mnemonic == ".word"]
    assert pool and all(ln.addr >= f.addr and "literal" in ln.comment for ln in pool)
    assert all(not any(b.addr <= ln.addr < b.end for b in f.blocks.values()) for ln in pool)
    an = analyze(flow_thumb_O2)
    f = next(g for g in an.functions.values() if any(an.dis.decode(j).mnemonic == "tbb" for j in g.jump_tables))
    cases = [ln for ln in function_lines(an, f) if ln.mnemonic == ".byte" and ln.target is not None]
    targets = [t for j, ts in f.jump_tables.items() if an.dis.decode(j).mnemonic == "tbb" for t in ts]
    assert [ln.target for ln in cases] == targets
    addrs = [ln.addr for ln in function_lines(an, f) if ln.kind == "insn"]
    assert addrs == sorted(addrs)


@pytest.mark.parametrize("mode", ["-marm", "-mthumb"])
def test_literal_pool_after_a_call_is_data(tmp_path, mode):
    import os
    import shutil
    import subprocess
    cc = shutil.which("arm-linux-gnueabihf-gcc")
    if cc is None:
        pytest.skip("needs arm-linux-gnueabihf-gcc")
    out = str(tmp_path / "armpool")
    subprocess.run([cc, mode, "-O2", "-o", out, os.path.join(os.path.dirname(__file__), "src", "armpool.c")],
                   check=True)
    a = analyze(out)
    f = a.function_by_name("check")
    # `bl fatal` is followed by the words its `ldr rX, [pc, #k]` loads: data, not instructions
    last = max(f.blocks.values(), key=lambda b: b.addr)
    code = [i.mnemonic for i in last.insns if i.mnemonic != "nop"]     # (Thumb: padding to the pool)
    assert code[-1] == "bl" and not last.succs
    assert a.code_data.get(last.end) == ["array", "dword", 1]
    assert 'fatal("too big: a long message here");' in decompile(a, f).text

"""MIPS32 (little- and big-endian) and MIPS64 (n64): GOT-based imports, branch delay slots,
$gp-relative data and calls through $t9."""
import pytest

from relic.analysis import analyze
from relic.disasm import CALL, CJMP, JMP, RET

VARIANTS = ["vuln_mips", "vuln_mips_pie", "vuln_mipsbe", "vuln_mipsbe_pie", "vuln_mips64", "vuln_mips64_pie"]


@pytest.mark.parametrize("variant", VARIANTS)
def test_imports_come_from_the_global_got(request, variant):
    an = analyze(request.getfixturevalue(variant))
    b = an.bin
    names = {i.name: i for i in b.imports}
    assert {"puts", "gets", "malloc", "free", "system", "__libc_start_main"} <= set(names)
    assert b.mips_gp == b.dynamic["DT_PLTGOT"] + 0x7FF0
    for name in ("puts", "gets", "system"):
        imp = names[name]
        assert b.imports_by_got[imp.got] is imp
        if imp.addr:                                     # a lazy-binding stub in .MIPS.stubs
            assert b.section_at(imp.addr).name == ".MIPS.stubs" and an.name(imp.addr) == name


@pytest.mark.parametrize("variant", VARIANTS)
def test_delay_slots_stay_with_their_branch(request, variant):
    an = analyze(request.getfixturevalue(variant))
    seen = set()             # functions do not overlap: noreturn calls through $t9 end their block
    for f in an.functions.values():
        for blk in f.blocks.values():
            for k, i in enumerate(blk.insns):
                assert i.addr not in seen, f"{i.addr:#x} in two blocks"
                seen.add(i.addr)
                if i.kind in (JMP, CJMP, RET) and i is not blk.insns[-1]:
                    # a branch is followed by its delay slot, which ends the block
                    assert blk.insns[k + 1].delay and k + 2 == len(blk.insns)
            last = blk.last
            if last.kind == CJMP:
                assert blk.insns[-1].delay and last.end + 4 in blk.succs     # falls through past the slot


@pytest.mark.parametrize("variant", VARIANTS)
def test_calls_through_t9_and_strings_through_gp(request, variant):
    an = analyze(request.getfixturevalue(variant))
    vuln = an.function_by_name("vuln")
    calls = [an.call_name(i) for blk in sorted(vuln.blocks.values(), key=lambda b: b.addr)
             for i in blk.insns if i.kind == CALL]
    printf = "__printf_chk" if variant.endswith("pie") else "printf"
    assert calls[:4] == ["puts", "gets", "checksum", printf]
    assert an.function_by_name("checksum").addr not in vuln.blocks          # `bal` is a call
    for text in ("name?", "hello %s (%d)\n"):
        s = next(s for s in an.strings if s.value == text)
        assert any(vuln.block_at(x.frm) for x in an.xrefs_to[s.addr]), text
    assert any(v.severity == "high" and "gets" in v.message and an.function_at(v.addr) is vuln
               for v in an.vulns())


def _c(an, name):
    from relic.decompiler.emit import decompile
    return decompile(an, an.function_by_name(name)).text


@pytest.mark.parametrize("variant", VARIANTS)
def test_decompile_vuln_menu_main(request, variant):
    an = analyze(request.getfixturevalue(variant))
    pie = variant.endswith("pie")
    code = _c(an, "vuln")
    assert code.startswith("void vuln(void)") and "gets(buf_" in code and "char buf_" in code
    assert "// stack canary at sp0-" in code and "__stack_chk" not in code.replace("// stack canary", "")
    printf = '__printf_chk(2, "hello %s (%d)\\n", buf_' if pie else 'printf("hello %s (%d)\\n", buf_'
    assert printf in code and ", checksum(buf_" in code, code
    code = _c(an, "menu")
    assert 'puts("1. add");' in code and '__isoc99_scanf("%d", &var_' in code and "exit(1);" in code
    assert "__asm" not in code and "goto" not in code and "(*" not in code
    code = _c(an, "main")
    assert code.startswith("int main(int argc, ") and "while (1) {" in code and "setvbuf(stdout, 0, _IONBF, 0)" in code
    assert "sp - " not in code and "gp" not in code


@pytest.mark.parametrize("variant", VARIANTS)
def test_decompile_switch_and_loops(request, variant):
    an = analyze(request.getfixturevalue(variant))
    code = _c(an, "classify")
    assert "switch (" in code and "case 5:" in code and "default:" in code and "goto" not in code
    code = _c(an, "checksum")
    assert code.startswith("int checksum(char *a1)") and "100000" in code.replace("0x186a1", "100000")
    for f in an.functions.values():
        if not f.is_import:
            text = _c(an, f.name) if an.function_by_name(f.name) is f else ""
            assert text.count("{") == text.count("}"), f.name


def test_vulns(vuln_mips):
    an = analyze(vuln_mips)
    kinds = {(f.func, f.kind) for f in an.vulns()}
    assert {("vuln", "dangerous-call"), ("show_note", "format-string"), ("win", "win-function")} <= kinds


def test_stripped_finds_main_and_win(vuln_mips_stripped):
    an = analyze(vuln_mips_stripped)
    main = an.function_by_name("main")
    assert main is not None
    from relic.decompiler.emit import decompile
    win = [f for f in an.functions.values() if not f.is_import and 'system("/bin/sh")' in decompile(an, f).text]
    assert len(win) == 1 and an.name(win[0].addr).startswith("sub_")      # found by the prologue scan


def test_static_binary_gets_gp_from_reginfo(tmp_path):
    """A static MIPS binary has no DT_PLTGOT: `$gp` comes from `.reginfo` (ri_gp_value), so
    `$gp`-relative strings and jump tables resolve."""
    import os
    import shutil
    import subprocess
    cc = shutil.which("mipsel-linux-gnu-gcc")
    if cc is None:
        pytest.skip("needs mipsel-linux-gnu-gcc")
    exe = tmp_path / "vuln_static"
    r = subprocess.run([cc, "-O2", "-static", "-o", str(exe), os.path.join(os.path.dirname(__file__), "src", "vuln.c")],
                       capture_output=True)
    if r.returncode:
        pytest.skip("static linking is not available")
    an = analyze(str(exe), sigs=[])
    assert an.bin.mips_gp is not None and an.bin.is_mapped(an.bin.mips_gp - 0x7FF0)
    referenced = sum(1 for s in an.strings if an.xrefs_to.get(s.addr))
    assert referenced > 0.2 * len(an.strings), (referenced, len(an.strings))
    assert sum(len(f.jump_tables) for f in an.functions.values()) >= 10


def test_branch_likely_annuls_its_delay_slot(tmp_path):
    """`bnel`: the delay slot runs only when the branch is taken. The pseudocode of a hand-written
    counter (tests/src/mips_likely.S), compiled for the host, counts like the original."""
    import os
    import shutil
    import subprocess
    cc, host = shutil.which("mipsel-linux-gnu-gcc"), shutil.which("gcc")
    if cc is None or host is None:
        pytest.skip("needs mipsel-linux-gnu-gcc and gcc")
    here = os.path.dirname(__file__)
    main = tmp_path / "m.c"
    main.write_text("int cnt(const char *s, int c);\nint main(int c, char **v) { return cnt(v[0], c); }\n")
    exe = tmp_path / "likely"
    subprocess.run([cc, "-O1", "-o", str(exe), str(main), os.path.join(here, "src", "mips_likely.S")], check=True)
    an = analyze(str(exe))
    code = _c(an, "cnt")
    assert "__asm" not in code and "?" in code, code             # the slot's effect, predicated
    src = tmp_path / "re.c"
    src.write_text('#include <stdio.h>\n#include <stdbool.h>\n' + code +
                   '\nint main(void) { const char *t[] = {"", "/", "a/b/c//", "abc", "////x"};\n'
                   '  for (int k = 0; k < 5; k++) printf("%d ", cnt((char *)t[k], 47)); return 0; }\n')
    re_exe = tmp_path / "re"
    subprocess.run([host, "-w", "-o", str(re_exe), str(src)], check=True)
    out = subprocess.run([str(re_exe)], capture_output=True, text=True).stdout.split()
    assert out == ["0", "1", "4", "0", "4"], (out, code)

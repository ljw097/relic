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
    assert code.startswith("int main(int a1, ") and "while (1) {" in code
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

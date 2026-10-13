"""AArch64: lifting, AAPCS64 calls, __stack_chk_guard canary, vulns (aarch64-linux-gnu-gcc samples)."""
import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile


@pytest.fixture(scope="module", params=["vuln_a64", "vuln_a64_pie"])
def an(request):
    return request.param, analyze(request.getfixturevalue(request.param))


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


def test_vuln(an):
    name, a = an
    code = _c(a, "vuln")
    assert code.startswith("void vuln(void)")
    assert "char buf_" in code and "[64];  // sp0-" in code     # no return address on the stack
    assert "gets(buf_" in code and "checksum(buf_" in code and '"hello %s (%d)\\n"' in code
    assert "__stack_chk" not in code.replace("// stack canary", "")


def test_canary_from_stack_chk_guard(an):
    _, a = an
    code = _c(a, "vuln")
    assert "// stack canary at sp0-" in code


def test_checksum_and_main(an):
    name, a = an
    code = _c(a, "checksum")
    assert code.startswith("int checksum(char *a1)") and "> 100000" in code and "0x1337" in code
    code = _c(a, "main")
    assert code.startswith("int main(int a1, ") and "while (1) {" in code and "break;" in code
    assert "goto" not in code


def test_vulns(an):
    _, a = an
    kinds = {(f.func, f.kind) for f in a.vulns()}
    assert ("show_note", "format-string") in kinds
    assert ("vuln", "dangerous-call") in kinds
    assert ("win", "win-function") in kinds


def test_conditional_compare(flow_a64_O2):
    """`cmp; ccmp; csel` -> a short-circuit condition."""
    a = analyze(flow_a64_O2)
    code = _c(a, "sc_or")
    assert "a1 <= 3 && a2 > 1 ? a1 - a2 : a1 * a2" in code


def test_every_function_decompiles(an):
    _, a = an
    for f in a.functions.values():
        if not f.is_import:
            text = decompile(a, f).text
            assert text.count("{") == text.count("}"), f.name

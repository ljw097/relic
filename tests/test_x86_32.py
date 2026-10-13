"""x86-32 decompilation: cdecl stack arguments, PC thunks, stack parameters, realigned main."""
import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.fixture(scope="module")
def an32(vuln32):
    return analyze(vuln32)


@pytest.fixture(scope="module")
def an32_pie(vuln32_pie):
    return analyze(vuln32_pie)


def test_vuln_arguments_from_the_stack(an32):
    code = _c(an32, "vuln")
    assert code.startswith("void vuln(void)")
    assert "char buf_4c[68];" in code                 # distance to the saved ebx
    assert "gets(buf_4c);" in code and 'puts("name?");' in code
    assert 'printf("hello %s (%d)\\n", buf_4c, checksum(buf_4c));' in code


def test_stack_parameters_are_named(an32):
    code = _c(an32, "checksum")
    assert code.startswith("int checksum(char *a1)")
    assert "var_4" not in code


def test_realigned_main(an32):
    code = _c(an32, "main")
    assert code.startswith("int main(int a1, ")
    assert "setvbuf(stdout, 0, 2, 0);" in code        # through the GOT slot
    assert "show_note(" in code and "del_note(" in code and "classify(atoi(a2[1]))" in code
    assert "esp" not in code                          # stack bookkeeping is gone
    assert "stack realigned" in code


def test_pie_pc_thunk_and_canary(an32_pie):
    code = _c(an32_pie, "vuln")
    assert "get_pc_thunk" not in code                 # the thunk loads its return address
    assert 'puts("name?");' in code
    assert "stack_chk_fail" not in code and "// stack canary" in code


def test_every_function_decompiles(an32, an32_pie):
    for an in (an32, an32_pie):
        for f in an.functions.values():
            if not f.is_import:
                text = decompile(an, f).text
                assert text.count("{") == text.count("}"), f.name


def test_parameter_and_local_slots_do_not_share_a_name(flow32_O0):
    """[esp0+8] (parameter y) and [esp0-8] (local r) once both printed as `var_8`, merging
    two variables; the recompile check missed it because y is dead after the call."""
    an = analyze(flow32_O0)
    code = decompile(an, an.function_by_name("sw_calls")).text
    assert "var_8 = sc_or(a2, 2);" in code
    assert "a2 = sc_or(" not in code

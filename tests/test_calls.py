"""Decompiler stage 3: call argument / return recovery."""
import pytest

from relic.analysis import analyze
from relic.decompiler import decompile_ir
from relic.decompiler.ir import Call, CallStmt, Const
from relic.decompiler.sigs import arg_count, base_name, count_conversions, lookup


def _calls(fn, an):
    out = {}
    for s in fn.stmts():
        if isinstance(s, CallStmt) and isinstance(s.call.target, Const):
            out.setdefault(an.name(s.call.target.value), []).append(s.call)
    return out


# ------------------------------------------------------------------ signatures
def test_count_conversions():
    assert count_conversions("hello %s (%d)\n") == 2
    assert count_conversions("100%% done") == 0
    assert count_conversions("%*d") == 2          # width arg + value
    assert count_conversions("%5.2f %c") == 2
    assert count_conversions("%p %ld %-10s") == 3


def test_base_name_and_lookup():
    assert base_name("printf@plt") == "printf"
    assert base_name("__printf_chk") == "__printf_chk"   # fortified names keep their own signature
    assert lookup("gets").argc == 1 and lookup("gets").ret == "char *"
    assert lookup("exit").noreturn
    assert lookup("printf").fmt == 0 and lookup("sprintf").fmt == 1
    assert lookup("__printf_chk").fmt == 1                # leading flag shifts the format arg


def test_arg_count_with_format():
    assert arg_count(lookup("printf"), "hello %s (%d)\n") == 3    # fmt + 2
    assert arg_count(lookup("printf"), None) == 1                 # unknown format -> fixed only
    assert arg_count(lookup("gets"), None) == 1


# ------------------------------------------------------------- argument recovery
@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_vuln_call_arguments(request, variant):
    an = analyze(request.getfixturevalue(variant))
    calls = _calls(decompile_ir(an, an.function_by_name("vuln")), an)
    assert len(calls["gets"][0].args) == 1
    assert len(calls["checksum"][0].args) == 1       # not the leftover scratch registers
    # plain printf (3 args) or fortified __printf_chk (leading flag -> 4 args)
    name = "printf" if "printf" in calls else "__printf_chk"
    printf = calls[name][0]
    fmt_idx = lookup(name).fmt
    assert len(printf.args) == fmt_idx + 1 + 2         # fmt + %s + %d
    fmt = printf.args[fmt_idx]
    assert isinstance(fmt, Const)
    assert an.bin.read_cstring(fmt.value, 64) == "hello %s (%d)\n"


def test_menu_scanf_and_puts(vuln64):
    an = analyze(vuln64)
    calls = _calls(decompile_ir(an, an.function_by_name("menu")), an)
    assert all(len(c.args) == 1 for c in calls["puts"])            # puts("1. add"), ...
    scanf = calls["__isoc99_scanf"][0]
    assert len(scanf.args) == 2                                     # "%d", &choice
    assert an.bin.read_cstring(scanf.args[0].value, 16) == "%d"


def test_exit_is_noreturn_with_one_arg(vuln64):
    an = analyze(vuln64)
    calls = _calls(decompile_ir(an, an.function_by_name("menu")), an)
    assert len(calls["exit"][0].args) == 1

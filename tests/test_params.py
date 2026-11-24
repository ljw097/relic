"""Parameters on x86-64: an unused one before one the code reads (`f(L, t)` that only reads t)
still counts, and registers moved into an internal callee's argument registers are read; a
parameter only passed on gets the type the callee gives it (`char *` for one that reaches
strlen); a variadic function has its fixed parameters and `...`, and its callers pass the rest."""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
@pytest.mark.parametrize("opt", ["-O1", "-O2"])
def test_parameters_read_after_an_unused_one_or_passed_on(tmp_path, opt):
    exe = tmp_path / "params"
    src = os.path.join(os.path.dirname(__file__), "src", "params.c")
    subprocess.run(["gcc", opt, "-w", "-o", str(exe), src], check=True)
    an = analyze(str(exe))
    for name, count in (("type_name", 2), ("forward", 3), ("second", 2), ("scale", 2)):
        text = decompile(an, an.function_by_name(name)).text
        sig = next(line for line in text.splitlines() if f"{name}(" in line)
        assert sig.count(",") == count - 1 and "rsi" not in text and "rdx" not in text, text


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_types_from_callees_and_variadic_functions(tmp_path, opt):
    exe = tmp_path / "params"
    src = os.path.join(os.path.dirname(__file__), "src", "params.c")
    subprocess.run(["gcc", opt, "-w", "-o", str(exe), src], check=True)
    an = analyze(str(exe))
    text = decompile(an, an.function_by_name("push_string")).text
    assert "char *a2" in text.splitlines()[0] or any("push_string(" in ln and "char *a2" in ln
                                                    for ln in text.splitlines()), text
    head = next(ln for ln in decompile(an, an.function_by_name("sum")).text.splitlines() if "sum(" in ln)
    assert head == "int sum(int a1, ...)", head
    assert "sum(3, a1, 2, 3)" in decompile(an, an.function_by_name("sum3")).text

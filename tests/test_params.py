"""Parameters on x86-64: an unused one before one the code reads (`f(L, t)` that only reads t)
still counts, and registers moved into an internal callee's argument registers are read."""
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

"""The pseudocode is C: what the benchmark against angr (docs/benchmarks.md) found gcc rejecting.

Pointer arithmetic C only allows on integers (two pointers of different types subtracted, a
pointer masked or shifted), a call through a local that isn't typed as a function pointer, a
struct whose only field is an array. Each function's pseudocode alone must pass
`gcc -fsyntax-only`; errors about what it uses without declaring (globals, callees) don't count.
"""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

SRC = os.path.join(os.path.dirname(__file__), "src", "ptrmath.c")
PRELUDE = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n"
FUNCS = ("tget", "tset", "rdist", "ldist", "bucket", "misal", "run", "skip")
_OK = ("undeclared", "implicit declaration", "unknown type name", "incomplete type", "storage size")


def _not_c(text: str, tmp_path) -> list[str]:
    path = tmp_path / "f.c"
    path.write_text(PRELUDE + text + "\n")
    r = subprocess.run(["gcc", "-fsyntax-only", "-w", "-std=gnu11", str(path)], capture_output=True, text=True)
    return [line for line in r.stderr.splitlines() if "error:" in line and not any(k in line for k in _OK)]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_pointer_arithmetic_is_c(tmp_path, opt):
    out = tmp_path / "ptrmath"
    subprocess.run(["gcc", opt, "-w", "-o", str(out), SRC], check=True)
    an = analyze(str(out))
    for name in FUNCS:
        text = decompile(an, an.function_by_name(name)).text
        assert _not_c(text, tmp_path) == [], f"{name}:\n{text}"


def test_struct_with_only_an_array_is_c():
    from relic.decompiler.structs import Field, Struct
    s = Struct("s_tab", ("var", 0, "a1"))
    s.fields[0] = Field(0, 32, name="f_0", array=True)
    assert s.declaration()[1] == "    int f_0[0];"
    s.fields[0].count = 64
    assert s.declaration()[1] == "    int f_0[64];"
    t = Struct("s_rec", ("var", 0, "a2"))
    t.fields[0] = Field(0, 64, name="f_0")
    t.fields[8] = Field(8, 32, name="f_8", array=True)
    assert t.declaration()[2] == "    int f_8[];"

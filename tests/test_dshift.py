"""x86 `shrd` / `shld` (double-precision shifts): lifted as the shifts and the or they are, not
an opaque `__shrd(...)` -- checked by compiling the pseudocode again (x86-64: 128-bit shifts)."""
import os
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

SRC = os.path.join(os.path.dirname(__file__), "src", "dshift.c")
FUNCS = ["hi_shift", "lo_shift", "fixed"]


@pytest.mark.parametrize("opt", ["O1", "O2"])
def test_double_shifts_recompile(opt, tmp_path):
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    exe = str(tmp_path / "s")
    subprocess.run(["gcc", f"-{opt}", "-o", exe, SRC], check=True)
    an = analyze(exe)
    if an.bin.arch != "x64":
        pytest.skip("x86-64 only")
    code = {f: decompile(an, an.function_by_name(f)).text for f in FUNCS}
    assert any("shrd" in i.mnemonic or "shld" in i.mnemonic
               for f in FUNCS for b in an.function_by_name(f).blocks.values() for i in b.insns)
    assert not any("__shrd" in c or "__shld" in c for c in code.values()), code
    with open(SRC) as fp:
        main = fp.read()
    main = main[main.index("int main"):]
    src = tmp_path / "re.c"
    src.write_text("#include <stdio.h>\n#include <stdint.h>\n#include <stdlib.h>\n" + "\n".join(code.values()) + main)
    out = str(tmp_path / "re")
    r = subprocess.run(["gcc", "-w", "-fwrapv", "-o", out, str(src)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for args in ([], ["a", "b"]):
        want = subprocess.run([exe, *args], capture_output=True, text=True).stdout
        assert subprocess.run([out, *args], capture_output=True, text=True).stdout == want and want
    assert re.search(r"<< \(?64 - ", code["hi_shift"]) or "<< 64 - " in code["hi_shift"]

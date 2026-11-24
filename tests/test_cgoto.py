"""GNU C's computed `goto` (Lua's interpreter loop): the labels its dispatch table holds belong to
the function that jumps through it -- x86-64 at -O0 and -O2 (CET puts `endbr64` on each label,
as on functions) and AArch64. Exactly the program's functions are found in the stripped build,
and the dispatching function keeps its labels."""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"))
from compare_tools import text_range, truth  # noqa: E402

from relic.analysis import analyze  # noqa: E402

SRC = os.path.join(os.path.dirname(__file__), "src", "cgoto.c")


def _cc(name: str) -> str | None:
    return shutil.which(name) or next((p for v in (14, 13, 12) if (p := shutil.which(f"{name}-{v}"))), None)


@pytest.mark.parametrize("cc,opt", [("gcc", "-O0"), ("gcc", "-O2"), ("aarch64-linux-gnu-gcc", "-O2")])
def test_computed_goto_labels_are_not_functions(tmp_path, cc, opt):
    compiler = _cc(cc)
    if compiler is None:
        pytest.skip(f"no {cc}")
    exe = tmp_path / "cgoto"
    flags = ["-fcf-protection"] if cc == "gcc" else []
    subprocess.run([compiler, opt, "-fpie", "-pie", *flags, "-w", "-o", str(exe), SRC], check=True)
    true = truth(str(exe))
    lo, hi = text_range(str(exe))
    strip = _cc(cc[: -len("gcc")] + "strip") if cc != "gcc" else shutil.which("strip")
    stripped = tmp_path / "cgoto.stripped"
    subprocess.run([strip, "-o", str(stripped), str(exe)], check=True)
    an = analyze(str(stripped))
    found = {a for a, f in an.functions.items() if not f.is_import and lo <= a < hi}
    assert found == true, (sorted(map(hex, found - true)), sorted(map(hex, true - found)))
    # the dispatching function jumps through its table: every label is one of its blocks
    tables = [t for f in an.functions.values() for t in f.jump_tables.values() if len(t) == 8]
    assert tables, "the dispatch table was not recovered"

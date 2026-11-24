"""The pseudocode behaves like the program: each function of tools/bench/equiv.c, decompiled from
the stripped build, compiled again and linked into a harness that calls it and the original on
the same 40 inputs, returns the same values and leaves the same memory (tools/decomp_quality.py,
the benchmark in docs/benchmarks.md).

Not yet: `powmod` (its 128-bit `%` is libgcc's `__umodti3`, not recognised in a stripped
binary), and at -O2 `bubble_sort` (two ints swapped with SSE shuffles). (`day_kind` at -O2 reads
a lookup table gcc made of the switch: the pseudocode declares it with its contents.)
"""
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"))
import decomp_quality as q  # noqa: E402

from relic.analysis import analyze  # noqa: E402
from relic.decompiler.emit import decompile  # noqa: E402

NOT_YET = {"-O0": {"powmod"}, "-O2": {"powmod", "bubble_sort"}}


@pytest.mark.skipif(shutil.which("gcc") is None or os.uname().machine != "x86_64", reason="needs gcc on x86-64")
@pytest.mark.parametrize("opt", ["-O0", "-O2"])
def test_pseudocode_behaves_like_the_program(tmp_path, opt):
    src = os.path.join(q.HERE, "bench", "equiv.c")
    exe = tmp_path / "equiv"
    subprocess.run(["gcc", opt, "-fno-stack-protector", "-w", "-o", str(exe), src], check=True)
    names = {name: addr for addr, name in q.symbol_names(str(exe)).items()}
    subprocess.run(["strip", str(exe)], check=True)
    original = q.build_original(opt, str(tmp_path))
    an = analyze(str(exe))
    failed = {}
    for name in q.EQUIV:
        if name in NOT_YET[opt]:
            continue
        text = decompile(an, an.functions[names[name]]).text
        work = tmp_path / name
        work.mkdir()
        ok, why = q.equivalent(text, "relic", name, original, str(work))
        if not ok:
            failed[name] = f"{why}\n{text}"
    assert not failed, "\n\n".join(f"{n}: {w}" for n, w in failed.items())

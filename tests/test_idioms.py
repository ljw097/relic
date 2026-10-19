"""Compiler idioms back to C: unsigned <-> float conversions (tests/src/uconv.c, gcc -O2) and
vectorized loops (tests/src/vector.c, gcc -O3) with Intel intrinsic names and element-scaled
pointer arithmetic."""
import os
import platform
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

HERE = os.path.dirname(__file__)


def _build(tmp_path_factory, name, opt):
    cc = shutil.which("gcc")
    if cc is None or platform.machine() not in ("x86_64", "AMD64"):
        pytest.skip("needs gcc for x86-64")
    out = str(tmp_path_factory.mktemp(name) / name)
    subprocess.run([cc, opt, "-w", "-o", out, os.path.join(HERE, "src", f"{name}.c")], check=True)
    return analyze(out)


@pytest.fixture(scope="module")
def uconv(tmp_path_factory):
    return _build(tmp_path_factory, "uconv", "-O2")


@pytest.fixture(scope="module")
def vector(tmp_path_factory):
    return _build(tmp_path_factory, "vector", "-O3")


@pytest.mark.parametrize("name,want", [("u2d", "return (double)(uint64_t)a1;"), ("u2f", "return (float)(uint64_t)a1;"),
                                       ("d2u", "return (uint64_t)a1;"), ("f2u", "return (uint64_t)a1;"),
                                       ("u32d", "return (double)(unsigned int)a1;")])
def test_unsigned_conversions(uconv, name, want):
    code = decompile(uconv, uconv.function_by_name(name)).text
    assert want in code and "if (" not in code, code


def test_vector_intrinsics(vector):
    code = decompile(vector, vector.function_by_name("sum")).text
    assert "_mm_add_epi32(" in code and "_mm_srli_si128(" in code, code
    assert "__int128 *" in code and " + 1;" in code and " + 16;" not in code       # (one vector, not 16)
    scale = decompile(vector, vector.function_by_name("scale")).text
    assert "_mm_mul_ps(" in scale and "__asm" not in scale, scale

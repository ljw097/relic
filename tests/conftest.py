"""Builds the sample binaries from tests/src on demand (needs gcc)."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "vuln.c")
FLOW_SRC = os.path.join(HERE, "src", "flow.c")
BINS = os.path.join(HERE, "bins")

VARIANTS = {
    "vuln64": ["-O0", "-fno-stack-protector", "-no-pie"],
    "vuln64_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE", "-Wl,-z,relro,-z,now", "-D_FORTIFY_SOURCE=2"],
    # control-flow sample, unoptimised and optimised (no vectorising: SIMD is not modelled precisely)
    "flow_O0": ["-O0", "-no-pie"],
    "flow_O2": ["-O2", "-fno-tree-vectorize", "-no-pie"],
    # x86-32 (cdecl, PC thunks); skipped where no -m32 toolchain is installed
    "vuln32": ["-m32", "-O0", "-fno-stack-protector", "-no-pie"],
    "vuln32_pie": ["-m32", "-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow32_O0": ["-m32", "-O0", "-no-pie"],
    "flow32_O2": ["-m32", "-O2", "-fno-tree-vectorize", "-no-pie"],
    # Windows PE with MinGW (skipped where the cross compilers are missing)
    "vuln64_pe": ["-O0"],
    "vuln32_pe": ["-O0"],
}
COMPILERS = {"vuln64_pe": "x86_64-w64-mingw32-gcc", "vuln32_pe": "i686-w64-mingw32-gcc"}
SOURCES = {"flow_O0": FLOW_SRC, "flow_O2": FLOW_SRC, "flow32_O0": FLOW_SRC, "flow32_O2": FLOW_SRC}


def _build(name: str) -> str:
    out = os.path.join(BINS, f"{name}.out")
    src_path = SOURCES.get(name, SRC)
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(src_path) and not name.endswith("_stripped"):
        return out
    cc = shutil.which(COMPILERS[name]) if name in COMPILERS else (shutil.which("gcc") or shutil.which("cc"))
    if cc is None:
        pytest.skip(f"no C compiler for {name}")
    os.makedirs(BINS, exist_ok=True)
    if name.endswith("_stripped"):
        src = _build(name[: -len("_stripped")])
        strip = shutil.which("strip")
        if strip is None:
            pytest.skip("strip not available")
        subprocess.run([strip, "-o", out, src], check=True)
        return out
    try:
        subprocess.run([cc, *VARIANTS[name], "-w", "-o", out, src_path], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        pytest.skip(f"cannot build {name}: {e.stderr.decode(errors='replace')[:200]}")
    return out


@pytest.fixture(scope="session")
def vuln64() -> str:
    return _build("vuln64")


@pytest.fixture(scope="session")
def vuln64_pie() -> str:
    return _build("vuln64_pie")


@pytest.fixture(scope="session")
def vuln64_stripped() -> str:
    return _build("vuln64_stripped")


@pytest.fixture(scope="session")
def flow_O0() -> str:
    return _build("flow_O0")


@pytest.fixture(scope="session")
def flow_O2() -> str:
    return _build("flow_O2")


def _fixture(name):
    def f() -> str:
        return _build(name)
    f.__name__ = name
    return pytest.fixture(scope="session")(f)


vuln32 = _fixture("vuln32")
vuln32_pie = _fixture("vuln32_pie")
flow32_O0 = _fixture("flow32_O0")
flow32_O2 = _fixture("flow32_O2")
vuln64_pe = _fixture("vuln64_pe")
vuln32_pe = _fixture("vuln32_pe")

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
    # AArch64 (cross compiler; skipped without it)
    "vuln_a64": ["-O0"],
    "vuln_a64_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_a64_O0": ["-O0"],
    "flow_a64_O2": ["-O2", "-fno-tree-vectorize"],
    # ARM32 (cross compiler; skipped without it): A32 and Thumb-2 (gnueabihf defaults to Thumb)
    "vuln_arm": ["-O0", "-marm"],
    "vuln_thumb": ["-O1", "-mthumb", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_arm_O0": ["-O0", "-marm"],
    "flow_arm_O2": ["-O2", "-marm", "-fno-tree-vectorize"],
    "flow_thumb_O0": ["-O0", "-mthumb"],
    "flow_thumb_O2": ["-O2", "-mthumb", "-fno-tree-vectorize"],
    # C++ (demangling)
    "shapes": ["-O0", "-no-pie", "-fno-inline"],
}
COMPILERS = {"vuln64_pe": "x86_64-w64-mingw32-gcc", "vuln32_pe": "i686-w64-mingw32-gcc", "shapes": "g++",
             **{n: "aarch64-linux-gnu-gcc" for n in ("vuln_a64", "vuln_a64_pie", "flow_a64_O0", "flow_a64_O2")},
             **{n: "arm-linux-gnueabihf-gcc" for n in ("vuln_arm", "vuln_thumb", "flow_arm_O0", "flow_arm_O2",
                                                       "flow_thumb_O0", "flow_thumb_O2")}}
SOURCES = {"flow_O0": FLOW_SRC, "flow_O2": FLOW_SRC, "flow32_O0": FLOW_SRC, "flow32_O2": FLOW_SRC,
           "shapes": os.path.join(HERE, "src", "shapes.cpp"), "flow_a64_O0": FLOW_SRC, "flow_a64_O2": FLOW_SRC,
           **{n: FLOW_SRC for n in ("flow_arm_O0", "flow_arm_O2", "flow_thumb_O0", "flow_thumb_O2")}}


def _build(name: str) -> str:
    out = os.path.join(BINS, f"{name}.out")
    src_path = SOURCES.get(name, SRC)
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(src_path) and not name.endswith("_stripped"):
        return out
    if name in COMPILERS:   # cross compilers may only exist under a versioned name (`...-gcc-14`)
        cc = shutil.which(COMPILERS[name]) or next(
            (p for v in (14, 13, 12) if (p := shutil.which(f"{COMPILERS[name]}-{v}"))), None)
    else:
        cc = shutil.which("gcc") or shutil.which("cc")
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
shapes = _fixture("shapes")
vuln_a64 = _fixture("vuln_a64")
vuln_a64_pie = _fixture("vuln_a64_pie")
flow_a64_O0 = _fixture("flow_a64_O0")
flow_a64_O2 = _fixture("flow_a64_O2")
vuln_arm = _fixture("vuln_arm")
vuln_thumb = _fixture("vuln_thumb")
flow_arm_O0 = _fixture("flow_arm_O0")
flow_arm_O2 = _fixture("flow_arm_O2")
flow_thumb_O0 = _fixture("flow_thumb_O0")
flow_thumb_O2 = _fixture("flow_thumb_O2")

"""Builds the sample binaries from tests/src on demand (needs gcc)."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "vuln.c")
BINS = os.path.join(HERE, "bins")

VARIANTS = {
    "vuln64": ["-O0", "-fno-stack-protector", "-no-pie"],
    "vuln64_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE", "-Wl,-z,relro,-z,now", "-D_FORTIFY_SOURCE=2"],
}


def _build(name: str) -> str:
    out = os.path.join(BINS, f"{name}.out")
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(SRC) and not name.endswith("_stripped"):
        return out
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler available")
    os.makedirs(BINS, exist_ok=True)
    if name.endswith("_stripped"):
        src = _build(name[: -len("_stripped")])
        strip = shutil.which("strip")
        if strip is None:
            pytest.skip("strip not available")
        subprocess.run([strip, "-o", out, src], check=True)
        return out
    try:
        subprocess.run([cc, *VARIANTS[name], "-w", "-o", out, SRC], check=True, capture_output=True)
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

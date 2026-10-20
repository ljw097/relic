"""Builds the sample binaries from tests/src on demand (needs gcc)."""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

# expectations are written in the generated names (`sub_XXXX`, `a1`, `v1`); tests of the names the
# analysis suggests turn them on themselves (tests/test_autonames.py)
os.environ["RELIC_AUTO_NAMES"] = "0"

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "vuln.c")
FLOW_SRC = os.path.join(HERE, "src", "flow.c")
BINS = os.path.join(HERE, "bins")
RV32 = ["-march=rv32gc", "-mabi=ilp32d", "-nostdlib", "-static", "-ffreestanding", "-Wl,-e,main"]
RV32_OBJ = ["-march=rv32gc", "-mabi=ilp32d", "-c", "-I", os.path.join(HERE, "src", "rv32inc")]

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
    # MIPS32 little-endian (cross compiler; skipped without it): non-PIC with .MIPS.stubs, and PIE
    "vuln_mips": ["-O0"],
    "vuln_mips_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_mips_O0": ["-O0"],
    "flow_mips_O2": ["-O2", "-fno-tree-vectorize"],
    # MIPS32 big-endian
    "vuln_mipsbe": ["-O0"],
    "vuln_mipsbe_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_mipsbe_O0": ["-O0"],
    "flow_mipsbe_O2": ["-O2", "-fno-tree-vectorize"],
    # PowerPC 32-bit (big-endian, SysV) and PowerPC64 little-endian (ELFv2)
    "vuln_ppc": ["-O0"],
    "vuln_ppc_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_ppc_O0": ["-O0"],
    "flow_ppc_O2": ["-O2", "-fno-tree-vectorize"],
    "vuln_ppc64": ["-O0"],
    "vuln_ppc64_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_ppc64_O0": ["-O0"],
    "flow_ppc64_O2": ["-O2", "-fno-tree-vectorize"],
    # MIPS64 little-endian, n64 ABI
    "vuln_mips64": ["-O0"],
    "vuln_mips64_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_mips64_O0": ["-O0"],
    "flow_mips64_O2": ["-O2", "-fno-tree-vectorize"],
    # RISC-V RV64GC (cross compiler; skipped without it): PIE by default
    "vuln_rv64": ["-O0"],
    "vuln_rv64_pie": ["-O1", "-fstack-protector-strong", "-pie", "-fPIE"],
    "flow_rv64_O0": ["-O0"],
    "flow_rv64_O2": ["-O2", "-fno-tree-vectorize"],
    "floats_rv64_O0": ["-O0"],
    "floats_rv64_O2": ["-O2", "-fno-tree-vectorize"],
    # RISC-V RV32GC (ILP32D): no 32-bit libc next to the RV64 cross compiler, so freestanding
    "flow_rv32_O0": ["-O0", *RV32],
    "flow_rv32_O2": ["-O2", "-fno-tree-vectorize", *RV32],
    # (floats.c calls libc: an object file, its calls relocations to the imports)
    "floats_rv32_O0": ["-O0", *RV32_OBJ],
    "floats_rv32_O2": ["-O2", "-fno-tree-vectorize", *RV32_OBJ],
    "floats_ppc_O0": ["-O0"],
    "floats_ppc_O2": ["-O2", "-fno-tree-vectorize"],
    "floats_ppc64_O0": ["-O0"],
    "floats_ppc64_O2": ["-O2", "-fno-tree-vectorize"],
    # struct recovery
    "structs_O0": ["-O0", "-fno-stack-protector", "-no-pie"],
    "structs_O2": ["-O2", "-fno-stack-protector", "-no-pie", "-fno-inline"],
    # library argument / result types
    "libtypes_O0": ["-O0", "-fno-stack-protector", "-no-pie"],
    "libtypes_O2": ["-O2", "-fno-stack-protector", "-no-pie"],
    # floating point (SSE scalar)
    "floats_O0": ["-O0", "-no-pie", "-fno-stack-protector"],
    "floats_O2": ["-O2", "-no-pie", "-fno-stack-protector", "-fno-tree-vectorize"],
    # names the analysis suggests (tests/test_autonames.py; built stripped too)
    "autonames_O0": ["-O0", "-fno-stack-protector"],
    "autonames_O2": ["-O2", "-fno-stack-protector"],
    # x86-32: floating point on the x87 stack (skipped where no -m32 toolchain is installed)
    "floats32_O0": ["-m32", "-O0", "-no-pie", "-fno-stack-protector"],
    "floats32_O2": ["-m32", "-O2", "-no-pie", "-fno-stack-protector", "-fno-tree-vectorize"],
    # (an i386 has no fcomi: comparisons go through fnstsw ax / sahf)
    "floats32_i386_O2": ["-m32", "-march=i386", "-O2", "-no-pie", "-fno-stack-protector", "-fno-tree-vectorize"],
    "floats_a64_O0": ["-O0"],
    "floats_arm_O0": ["-O0", "-marm"],
    "floats_arm_O2": ["-O2", "-marm", "-fno-tree-vectorize"],
    "floats_thumb_O2": ["-O2", "-mthumb", "-fno-tree-vectorize"],
    "floats_a64_O2": ["-O2", "-fno-tree-vectorize"],
    # C declarations imported from a header (enums, structs, prototypes)
    "types_O0": ["-O0", "-fno-stack-protector", "-no-pie"],
    "types_O2": ["-O2", "-fno-stack-protector", "-no-pie"],
    # library calls known only from the bundled prototypes
    "libcalls_O1": ["-O1", "-fno-stack-protector", "-no-pie"],
    # C++ (demangling)
    "shapes": ["-O0", "-no-pie", "-fno-inline"],
}
COMPILERS = {"vuln64_pe": "x86_64-w64-mingw32-gcc", "vuln32_pe": "i686-w64-mingw32-gcc", "shapes": "g++",
             **{n: "aarch64-linux-gnu-gcc" for n in ("vuln_a64", "vuln_a64_pie", "flow_a64_O0", "flow_a64_O2",
                                                     "floats_a64_O0", "floats_a64_O2")},
             **{n: "mipsel-linux-gnu-gcc" for n in ("vuln_mips", "vuln_mips_pie", "flow_mips_O0", "flow_mips_O2")},
             **{n: "mips-linux-gnu-gcc" for n in ("vuln_mipsbe", "vuln_mipsbe_pie", "flow_mipsbe_O0",
                                                  "flow_mipsbe_O2")},
             **{n: "powerpc-linux-gnu-gcc" for n in ("vuln_ppc", "vuln_ppc_pie", "flow_ppc_O0", "flow_ppc_O2",
                                                     "floats_ppc_O0", "floats_ppc_O2")},
             **{n: "powerpc64le-linux-gnu-gcc" for n in ("vuln_ppc64", "vuln_ppc64_pie", "flow_ppc64_O0",
                                                         "flow_ppc64_O2", "floats_ppc64_O0", "floats_ppc64_O2")},
             **{n: "mips64el-linux-gnuabi64-gcc" for n in ("vuln_mips64", "vuln_mips64_pie", "flow_mips64_O0",
                                                           "flow_mips64_O2")},
             **{n: "riscv64-linux-gnu-gcc" for n in ("vuln_rv64", "vuln_rv64_pie", "flow_rv64_O0", "flow_rv64_O2",
                                                     "floats_rv64_O0", "floats_rv64_O2", "flow_rv32_O0",
                                                     "flow_rv32_O2", "floats_rv32_O0", "floats_rv32_O2")},
             **{n: "arm-linux-gnueabihf-gcc" for n in ("vuln_arm", "vuln_thumb", "flow_arm_O0", "flow_arm_O2",
                                                       "flow_thumb_O0", "flow_thumb_O2", "floats_arm_O0",
                                                       "floats_arm_O2", "floats_thumb_O2")}}
SOURCES = {"structs_O0": os.path.join(HERE, "src", "structs.c"), "structs_O2": os.path.join(HERE, "src", "structs.c"),
           **{n: os.path.join(HERE, "src", "libtypes.c") for n in ("libtypes_O0", "libtypes_O2")},
           **{n: os.path.join(HERE, "src", "autonames.c") for n in ("autonames_O0", "autonames_O2")},
           **{n: os.path.join(HERE, "src", "floats.c") for n in ("floats_O0", "floats_O2", "floats32_O0",
                                                                "floats32_O2", "floats32_i386_O2", "floats_a64_O0",
                                                                "floats_a64_O2", "floats_arm_O0", "floats_arm_O2",
                                                                "floats_thumb_O2", "floats_rv64_O0",
                                                                "floats_rv64_O2", "floats_rv32_O0", "floats_rv32_O2",
                                                                "floats_ppc_O0", "floats_ppc_O2",
                                                                "floats_ppc64_O0", "floats_ppc64_O2")},
           "libcalls_O1": os.path.join(HERE, "src", "libcalls.c"),
           "types_O0": os.path.join(HERE, "src", "types.c"), "types_O2": os.path.join(HERE, "src", "types.c"),
           "flow_O0": FLOW_SRC, "flow_O2": FLOW_SRC, "flow32_O0": FLOW_SRC, "flow32_O2": FLOW_SRC,
           "shapes": os.path.join(HERE, "src", "shapes.cpp"), "flow_a64_O0": FLOW_SRC, "flow_a64_O2": FLOW_SRC,
           **{n: FLOW_SRC for n in ("flow_arm_O0", "flow_arm_O2", "flow_thumb_O0", "flow_thumb_O2",
                                    "flow_mips_O0", "flow_mips_O2", "flow_mipsbe_O0", "flow_mipsbe_O2",
                                    "flow_mips64_O0", "flow_mips64_O2", "flow_rv64_O0", "flow_rv64_O2",
                                    "flow_rv32_O0", "flow_rv32_O2", "flow_ppc_O0", "flow_ppc_O2", "flow_ppc64_O0",
                                    "flow_ppc64_O2")}}


# libraries go after the source: linkers drop the ones nothing before them uses
LIBS = {n: ["-lm"] for n in ("floats_O0", "floats_O2", "floats32_O0", "floats32_O2", "floats32_i386_O2",
                              "floats_a64_O0",
                              "floats_a64_O2", "floats_arm_O0",
                              "floats_arm_O2", "floats_thumb_O2", "floats_rv64_O0", "floats_rv64_O2",
                              "floats_ppc_O0", "floats_ppc_O2", "floats_ppc64_O0", "floats_ppc64_O2")}


def _build(name: str) -> str:
    out = os.path.join(BINS, f"{name}.out")
    base = name[: -len("_stripped")] if name.endswith("_stripped") else name
    src_path = SOURCES.get(base, SRC)
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(src_path):
        return out
    if name != base:
        src = _build(base)
        # the binutils of the target (`arm-linux-gnueabihf-strip`); the host's for native ones
        prefix = COMPILERS.get(base, "")[: -len("gcc")] if COMPILERS.get(base, "").endswith("gcc") else ""
        strip = shutil.which(f"{prefix}strip") or next(
            (p for v in (14, 13, 12) if (p := shutil.which(f"{prefix}strip-{v}"))), None) \
            if prefix else shutil.which("strip")
        if strip is None:
            pytest.skip(f"no strip for {base}")
        tmp = f"{out}.{os.getpid()}"
        subprocess.run([strip, "-o", tmp, src], check=True)
        os.replace(tmp, out)                    # (atomic: parallel test workers may build it too)
        return out
    if name in COMPILERS:   # cross compilers may only exist under a versioned name (`...-gcc-14`)
        cc = shutil.which(COMPILERS[name]) or next(
            (p for v in (14, 13, 12) if (p := shutil.which(f"{COMPILERS[name]}-{v}"))), None)
    else:
        cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip(f"no C compiler for {name}")
    os.makedirs(BINS, exist_ok=True)
    try:
        tmp = f"{out}.{os.getpid()}"
        subprocess.run([cc, *VARIANTS[name], "-w", "-o", tmp, src_path, *LIBS.get(name, ())], check=True,
                       capture_output=True)
        os.replace(tmp, out)
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
libtypes_O0 = _fixture("libtypes_O0")
libtypes_O2 = _fixture("libtypes_O2")
vuln_a64 = _fixture("vuln_a64")
vuln_a64_pie = _fixture("vuln_a64_pie")
flow_a64_O0 = _fixture("flow_a64_O0")
flow_a64_O2 = _fixture("flow_a64_O2")
vuln_arm = _fixture("vuln_arm")
vuln_thumb = _fixture("vuln_thumb")
vuln_arm_stripped = _fixture("vuln_arm_stripped")
vuln_thumb_stripped = _fixture("vuln_thumb_stripped")
vuln_a64_stripped = _fixture("vuln_a64_stripped")
vuln_a64_pie_stripped = _fixture("vuln_a64_pie_stripped")
flow_arm_O0 = _fixture("flow_arm_O0")
flow_arm_O2 = _fixture("flow_arm_O2")
flow_thumb_O0 = _fixture("flow_thumb_O0")
flow_thumb_O2 = _fixture("flow_thumb_O2")
vuln_mips = _fixture("vuln_mips")
vuln_mips_pie = _fixture("vuln_mips_pie")
vuln_mips_stripped = _fixture("vuln_mips_stripped")
structs_O0 = _fixture("structs_O0")
floats_O0 = _fixture("floats_O0")
floats_O2 = _fixture("floats_O2")
autonames_O0_stripped = _fixture("autonames_O0_stripped")
autonames_O2_stripped = _fixture("autonames_O2_stripped")
floats32_O0 = _fixture("floats32_O0")
floats32_O2 = _fixture("floats32_O2")
floats32_i386_O2 = _fixture("floats32_i386_O2")
floats_a64_O0 = _fixture("floats_a64_O0")
floats_a64_O2 = _fixture("floats_a64_O2")
floats_arm_O0 = _fixture("floats_arm_O0")
floats_arm_O2 = _fixture("floats_arm_O2")
floats_thumb_O2 = _fixture("floats_thumb_O2")
structs_O2 = _fixture("structs_O2")
vuln_rv64 = _fixture("vuln_rv64")
vuln_rv64_pie = _fixture("vuln_rv64_pie")
vuln_rv64_stripped = _fixture("vuln_rv64_stripped")
flow_rv64_O0 = _fixture("flow_rv64_O0")
flow_rv64_O2 = _fixture("flow_rv64_O2")
floats_rv64_O0 = _fixture("floats_rv64_O0")
floats_rv64_O2 = _fixture("floats_rv64_O2")
flow_rv32_O0 = _fixture("flow_rv32_O0")
flow_rv32_O2 = _fixture("flow_rv32_O2")
floats_rv32_O0 = _fixture("floats_rv32_O0")
floats_rv32_O2 = _fixture("floats_rv32_O2")
libcalls_O1 = _fixture("libcalls_O1")
types_O0 = _fixture("types_O0")
types_O2 = _fixture("types_O2")
flow_mips_O0 = _fixture("flow_mips_O0")
flow_mips_O2 = _fixture("flow_mips_O2")
vuln_mipsbe = _fixture("vuln_mipsbe")
vuln_mipsbe_pie = _fixture("vuln_mipsbe_pie")
flow_mipsbe_O0 = _fixture("flow_mipsbe_O0")
flow_mipsbe_O2 = _fixture("flow_mipsbe_O2")
floats_ppc_O0 = _fixture("floats_ppc_O0")
floats_ppc_O2 = _fixture("floats_ppc_O2")
floats_ppc64_O0 = _fixture("floats_ppc64_O0")
floats_ppc64_O2 = _fixture("floats_ppc64_O2")
vuln_ppc_stripped = _fixture("vuln_ppc_stripped")
vuln_ppc64_stripped = _fixture("vuln_ppc64_stripped")
vuln_ppc = _fixture("vuln_ppc")
vuln_ppc_pie = _fixture("vuln_ppc_pie")
flow_ppc_O0 = _fixture("flow_ppc_O0")
flow_ppc_O2 = _fixture("flow_ppc_O2")
vuln_ppc64 = _fixture("vuln_ppc64")
vuln_ppc64_pie = _fixture("vuln_ppc64_pie")
flow_ppc64_O0 = _fixture("flow_ppc64_O0")
flow_ppc64_O2 = _fixture("flow_ppc64_O2")
vuln_mips64 = _fixture("vuln_mips64")
vuln_mips64_pie = _fixture("vuln_mips64_pie")
flow_mips64_O0 = _fixture("flow_mips64_O0")
flow_mips64_O2 = _fixture("flow_mips64_O2")


@pytest.fixture(autouse=True)
def _no_user_signatures(monkeypatch):
    """Analyses in tests use no library signature files of the user's (~/.relic/sigs)."""
    from relic.analysis import libsigs
    monkeypatch.setattr(libsigs, "sig_dirs", lambda: [])

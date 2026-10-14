"""Control-flow structuring checked by recompilation.

tests/src/flow.c holds pure functions with short-circuit conditions,
multi-exit loops, nested break/continue/goto, switch fall-through,
do-while and ternaries. Each variant (-O0, -O2) is decompiled, the
pseudocode compiled again, and every function must agree with the
original source on a grid of inputs. This is what keeps goto reduction
and other structuring changes honest.
"""
import itertools
import os
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

HERE = os.path.dirname(__file__)
FUNCS = ["sc_or", "sc_and3", "find", "collatz", "nested", "sw_fall", "dowhile", "clamp", "gcd", "classify2", "scan",
         "div3", "udiv10", "mod10", "ldiv1000", "div_neg7", "is_mult6", "digsum", "div16", "mod8", "sw_calls"]

_HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

/* decompiled */
%(code)s

/* reference: the original source with every function renamed ref_* */
%(defines)s
#define main ref_main
#include "%(src)s"
#undef main

static const int ARR[] = {5, -2, 9, 9, 0, 13, -7, 4};
static const char *TEXTS[] = {"", " ", "a", "two words", "  lead  and trail ", "\ttab\tsep x", "x y z w v"};

int main(void) {
    int bad = 0;
    int vals[] = {-2147483647 - 1, -200, -101, -9, -3, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 27, 100, 101, 150, 1000,
                  2147483647};
    int nv = sizeof vals / sizeof *vals;
    for (int i = 0; i < nv; i++) {
        int a = vals[i];
#define CHK1(f, x) if (f(x) != ref_##f(x)) { printf(#f "(%%d) = %%d, want %%d\n", x, (int)f(x), ref_##f(x)); bad++; }
        CHK1(collatz, a < 0 ? -a : a)
        CHK1(sw_fall, a)
        if (a > -100000 && a < 100000) { CHK1(dowhile, a) }   /* n/3 iterations */
        CHK1(div3, a) CHK1(mod10, a) CHK1(div_neg7, a) CHK1(div16, a) CHK1(mod8, a)
        CHK1(udiv10, (unsigned)a) CHK1(is_mult6, (unsigned)a) CHK1(digsum, (unsigned)a)
        if (ldiv1000((long)a * 1000003) != ref_ldiv1000((long)a * 1000003)) { printf("ldiv1000 %%d\n", a); bad++; }
        for (int j = 0; j < nv; j++) {
            int b = vals[j];
#define CHK2(f, x, y) if (f(x, y) != ref_##f(x, y)) { printf(#f "(%%d,%%d) = %%d, want %%d\n", x, y, (int)f(x, y), ref_##f(x, y)); bad++; }
            CHK2(sc_or, a, b)
            CHK2(classify2, a, b)
            if (b > -100000 && b < 100000 && b != 0 && b != -2147483647 - 1) { CHK2(sw_calls, a & 15, b) }
            if (a > 0 && b > 0 && a < 60 && b < 60) { CHK2(nested, a, b) }
            if (b != 0 && a != -2147483647 - 1 && b != -2147483647 - 1) { CHK2(gcd, a, b) }
            for (int k = 0; k < nv; k += 3) {
                int c = vals[k];
                if (sc_and3(a, b, c) != ref_sc_and3(a, b, c)) { printf("sc_and3 %%d %%d %%d\n", a, b, c); bad++; }
                if (clamp(a, b, c) != ref_clamp(a, b, c)) { printf("clamp %%d %%d %%d\n", a, b, c); bad++; }
            }
        }
        for (int n = 0; n <= 8; n++)
            if (find((int *)ARR, n, a) != ref_find(ARR, n, a)) { printf("find n=%%d key=%%d\n", n, a); bad++; }
    }
    for (unsigned t = 0; t < sizeof TEXTS / sizeof *TEXTS; t++)
        if (scan((char *)TEXTS[t]) != ref_scan(TEXTS[t])) { printf("scan '%%s'\n", TEXTS[t]); bad++; }
    if (!bad)
        puts("ok");
    return bad != 0;
}
"""


@pytest.fixture(scope="module", params=["flow_O0", "flow_O2", "flow32_O0", "flow32_O2", "flow_a64_O0", "flow_a64_O2",
                                              "flow_arm_O0", "flow_arm_O2", "flow_thumb_O0", "flow_thumb_O2"])
def flow(request):
    path = request.getfixturevalue(request.param)
    return request.param, analyze(path)


def test_flow_functions_decompile_without_goto_soup(flow):
    name, an = flow
    for fn in FUNCS:
        text = decompile(an, an.function_by_name(fn)).text
        labels = re.findall(r"^\s*(loc_[0-9a-f]+):", text, re.M)
        for target in re.findall(r"goto (loc_[0-9a-f]+);", text):
            assert target in labels, f"{name}/{fn}: goto {target} without label\n{text}"


def _host_m32(cc, tmp_path) -> bool:
    probe = tmp_path / "m32.c"
    probe.write_text("#include <stdio.h>\nint main(void) { return 0; }\n")
    return subprocess.run([cc, "-m32", "-o", str(tmp_path / "m32"), str(probe)], capture_output=True).returncode == 0


def test_flow_recompiles_and_matches_source(flow, tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    name, an = flow
    code = "\n\n".join(decompile(an, an.function_by_name(fn)).text for fn in FUNCS)
    defines = "\n".join(f"#define {fn} ref_{fn}" for fn in FUNCS)
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"code": code, "defines": defines, "src": os.path.join(HERE, "src", "flow.c")})
    exe = tmp_path / "re"
    m32 = ["-m32"] if name.startswith(("flow32", "flow_arm", "flow_thumb")) else []
    if m32 and not _host_m32(cc, tmp_path):
        pytest.skip("no -m32 host toolchain (gcc-multilib) to run 32-bit pseudocode")
    if name.startswith(("flow_arm", "flow_thumb")):
        m32.append("-funsigned-char")          # plain char is unsigned on ARM
    r = subprocess.run([cc, *m32, "-w", "-fwrapv", "-o", str(exe), str(src)], capture_output=True, text=True)
    assert r.returncode == 0, f"{name}: pseudocode does not compile:\n{r.stderr[:3000]}\n{code}"
    r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip().endswith("ok"), f"{name}: mismatches:\n{r.stdout[:3000]}\n{code}"


@pytest.mark.parametrize("fn,shape", [("div3", "/ 3"), ("udiv10", "/ 10"), ("mod10", "% 10"),
                                      ("ldiv1000", "/ 1000"), ("is_mult6", "% 6 == 0"), ("digsum", "% 10"),
                                      ("div_neg7", "/ -7"), ("div16", "/ 16"), ("mod8", "% 8")])
def test_division_by_constant_recovered(flow, fn, shape):
    name, an = flow
    text = decompile(an, an.function_by_name(fn)).text
    assert shape in text, f"{name}/{fn}:\n{text}"
    body = "\n".join(ln.split("//")[0] for ln in text.split("{", 1)[1].splitlines())
    assert "0x" not in body, f"{name}/{fn}: magic constant left\n{text}"


def test_jump_table_switch(flow):
    """sw_calls is a dense switch: a jump table at every optimisation level."""
    name, an = flow
    text = decompile(an, an.function_by_name("sw_calls")).text
    if not name.startswith("flow_a64"):
        assert "switch (" in text and "default:" in text, f"{name}:\n{text}"
    # (AArch64 gcc compiles this switch to a compare tree, not a table: an if-chain is right)
    for callee in ("sc_or(", "gcd(", "clamp(", "collatz(", "mod10("):
        assert callee in text, f"{name}: {callee}\n{text}"
    assert "goto" not in text, f"{name}:\n{text}"

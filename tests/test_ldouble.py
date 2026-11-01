"""long double on x86 and x86-64: the x87's 80-bit values in memory (`fld tbyte`, `fstp tbyte`),
as parameters on the stack, results on the x87 stack (x86-64 too) and `%Lf` arguments -- checked
by recompiling the pseudocode and running it against the original source."""
import os
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.decompiler.fp import from_float, literal, to_float

HERE = os.path.dirname(__file__)
FUNCS = ["ld_scale", "ld_to_d", "ld_from_d", "ld_half", "ld_abs", "ld_cmp", "ld_mix", "ld_call", "ld_sum",
         "ld_store"]        # callees first


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.fixture(scope="module", params=["ldouble_O0", "ldouble_O2", "ldouble32_O0", "ldouble32_O2"])
def an(request):
    return request.param, analyze(request.getfixturevalue(request.param))


def test_signatures(an):
    name, a = an
    sig = {f: _c(a, f).splitlines()[0] for f in FUNCS}
    if a.bin.bits == 32:            # cdecl: every argument on the stack, in C order
        assert sig["ld_scale"] == "long double ld_scale(long double a1, int a2)", sig
        assert sig["ld_mix"] == "long double ld_mix(int a1, long double a2, double a3)", sig
    else:                           # x86-64: registers first, then the long double from the stack
        assert sig["ld_scale"] == "long double ld_scale(int a1, long double a2)", sig
        assert sig["ld_mix"] == "long double ld_mix(int a1, double a2, long double a3)", sig
    assert sig["ld_to_d"] == "double ld_to_d(long double a1)", sig
    assert sig["ld_half"] == "long double ld_half(long double a1)", sig
    assert sig["ld_abs"] == "long double ld_abs(long double a1)", sig
    assert sig["ld_cmp"] == "int ld_cmp(long double a1, long double a2)", sig
    # (forwarded word by word to ld_scale at -O2, never loaded itself)
    assert sig["ld_call"] == "long double ld_call(long double a1)", sig
    assert sig["ld_sum"] == "long double ld_sum(int a1)", sig
    assert sig["ld_store"] == "void ld_store(long double *a1, double a2)", sig
    if a.bin.bits == 64:            # (x86 returns a double on the x87 stack too: no telling them apart)
        assert sig["ld_from_d"] == "long double ld_from_d(double a1)", sig


def test_expressions(an):
    name, a = an
    for f in FUNCS + ["main"]:
        text = _c(a, f)
        assert "__asm" not in text and "int80_t" not in text and "x87" not in text, f"{name} {f}:\n{text}"
    assert "g_ld" in _c(a, "ld_scale") and "*a1 = " in _c(a, "ld_store")
    # (the x87 `fabs`: the long double form, by its argument on x86)
    assert "fabsl(" in _c(a, "ld_abs"), _c(a, "ld_abs")
    assert re.search(r"\b0\.25L?\b", _c(a, "ld_half")), _c(a, "ld_half")
    assert "ld_scale(" in _c(a, "ld_call") and "ld_from_d(1.5)" in _c(a, "ld_call")
    main = _c(a, "main")
    # the long double results go to printf as long doubles: one argument each, no halves
    m = re.search(r'printf(_chk)?\((2, )?"%Lf %f %d\\n", ld_call\(', main)
    assert m and "ld_to_d(ld_mix(" in main and "ld_cmp(" in main, main
    assert re.search(r'"%Lf\\n", ld_sum\(', main), main


def test_long_double_sums_step_whole_elements(an):
    name, a = an
    text = _c(a, "ld_sum")
    assert "long double *" in text or "table[" in text, text
    assert "+= 16" not in text and "+= 12" not in text, text


_HARNESS = r"""
#include <math.h>
#include <stdio.h>
#include <string.h>

%(defines)s
#define main ref_main
#include "%(src)s"
#undef main
%(undefs)s

%(code)s

static int bad;
#define SAME(what, x, y) do { __typeof__(x) a_ = (x), b_ = (y); \
    if (!(a_ == b_ || (a_ != a_ && b_ != b_))) { \
        printf("mismatch %%s line %%d: %%Lg %%Lg\n", what, __LINE__, (long double)a_, (long double)b_); \
        bad = 1; } } while (0)

int main(void)
{
    static const long double xs[] = {0.0L, -0.0L, 1.5L, -2.25L, 3.7L, -3.7L, 1e300L, 1e-4000L, 0.1L, 1e4000L};
    static const int is[] = {0, 1, -1, 7, -100000};
    int n = sizeof xs / sizeof *xs, m = sizeof is / sizeof *is;
%(ptrs)s
    for (int i = 0; i < n; i++) {
        long double x = xs[i], y = xs[(i + 3) %% n];
        SAME("to_d", ref_ld_to_d(x), p_ld_to_d(x));
        SAME("from_d", ref_ld_from_d((double)x), p_ld_from_d((double)x));
        SAME("half", ref_ld_half(x), p_ld_half(x));
        SAME("abs", ref_ld_abs(x), p_ld_abs(x));
        SAME("cmp", ref_ld_cmp(x, y), p_ld_cmp(x, y));
        SAME("call", ref_ld_call(x), p_ld_call(x));
        for (int j = 0; j < m; j++) {
            SAME("scale", ref_ld_scale(x, is[j]), p_ld_scale(x, is[j]));
            SAME("mix", ref_ld_mix(is[j], x, (double)y), p_ld_mix(is[j], x, (double)y));
        }
        long double r1, r2;
        ref_ld_store(&r1, (double)x);
        p_ld_store(&r2, (double)x);
        SAME("store", r1, r2);
    }
    for (int k = -1; k < 6; k++)
        SAME("sum", ref_ld_sum(k), p_ld_sum(k));
    puts(bad ? "bad" : "ok");
    return bad;
}
"""


def test_recompiled_pseudocode_matches(an, tmp_path):
    """The pseudocode, compiled again and called through the original prototypes (the ABI fixes
    where each argument goes, not the order C wrote them in), gives the same values."""
    name, a = an
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler")
    m32 = ["-m32"] if a.bin.bits == 32 else []
    code = "\n\n".join(_c(a, f) for f in FUNCS)
    ptrs = "\n".join(f"    __typeof__(ref_{f}) *volatile p_{f} = (__typeof__(ref_{f}) *)(void *){f};" for f in FUNCS)
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"code": code, "src": os.path.join(HERE, "src", "ldouble.c"), "ptrs": ptrs,
                               "defines": "\n".join(f"#define {f} ref_{f}" for f in FUNCS),
                               "undefs": "\n".join(f"#undef {f}" for f in FUNCS)})
    exe = tmp_path / "re"
    r = subprocess.run([cc, "-O1", "-w", "-fwrapv", "-fno-builtin", *m32, "-o", str(exe), str(src), "-lm"],
                       capture_output=True, text=True)
    if r.returncode and m32 and "cannot find" in r.stderr:
        pytest.skip("no -m32 toolchain")
    assert r.returncode == 0, f"{name}: does not compile:\n{r.stderr[:3000]}\n{code}"
    r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
    assert r.stdout.strip().endswith("ok"), f"{name}:\n{r.stdout[:2000]}\n{code}"


# ------------------------------------------------------------------ the 80-bit format
@pytest.mark.parametrize("x", [0.0, -0.0, 1.5, -3.25, 0.1, 1e300, -1e-300, 5e-324, float("inf"), float("-inf")])
def test_extended_precision_round_trips(x):
    v = from_float(x, 80)
    assert to_float(v, 80) == x and (v >> 79) == (1 if str(x).startswith("-") else 0)


def test_extended_precision_patterns():
    # 1.5L as the x87 stores it: exponent 0x3fff, significand 1.1000... with its explicit integer bit
    assert from_float(1.5, 80) == 0x3FFF_C000000000000000
    assert to_float(0x4000_C000000000000000, 80) == 3.0
    nan = to_float(0x7FFF_C000000000000000, 80)
    assert nan != nan
    assert literal(from_float(2.5, 80), 80) == "2.5L"

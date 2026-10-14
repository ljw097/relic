"""Floating point (x86-64 SSE scalar): float / double arguments and results, arithmetic,
conversions, comparisons and constants -- checked by recompiling the pseudocode and running it
against the original source."""
import os
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.decompiler.fp import FCMP, LT, EQ, GT, UN, fold_fcmp, from_float, literal
from relic.decompiler.interp import apply_binop
from relic.decompiler.ir import BinOp, Const, UnOp, Var

HERE = os.path.dirname(__file__)
FUNCS = ["poly", "avg", "scale", "cmpd", "to_long", "to_int", "mix", "clampd", "narrow", "absneg",
         "count_above", "sum_f", "is_equal", "hyp", "twice"]     # callees first


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.fixture(scope="module", params=["floats_O0", "floats_O2", "floats_a64_O0", "floats_a64_O2"])
def an(request):
    return request.param, analyze(request.getfixturevalue(request.param))


def test_signatures(an):
    name, a = an
    sig = {f: _c(a, f).splitlines()[0] for f in FUNCS}
    assert sig["poly"] == "double poly(double a1)", sig
    assert sig["scale"] == "float scale(float a1, float a2)", sig
    assert sig["cmpd"] == "int cmpd(double a1, double a2)", sig
    assert sig["to_long"] == "int64_t to_long(double a1)", sig
    assert sig["to_int"] == "int to_int(float a1)", sig
    assert sig["clampd"] == "double clampd(double a1, double a2, double a3)", sig
    assert sig["narrow"] == "float narrow(double a1)", sig
    assert sig["avg"].startswith("double avg(int *a1, int a2)"), sig
    assert sig["count_above"] == "int count_above(double *a1, int a2, double a3)", sig
    assert sig["sum_f"] == "double sum_f(float *a1, int a2)", sig
    # integer parameters first, then the float ones (the registers do not say how C interleaved them)
    assert sig["mix"] == "double mix(int a1, int64_t a2, double a3, float a4)", sig


def test_expressions(an):
    name, a = an
    assert ("3.0 * " in _c(a, "poly") or " * 3.0" in _c(a, "poly")) and "0.5" in _c(a, "poly")
    assert "1.5f" in _c(a, "scale")
    assert "sqrt(" in _c(a, "hyp")
    assert "(int64_t)" in _c(a, "to_long") and "(int)" in _c(a, "to_int")
    assert "(float)" in _c(a, "narrow") and "0.5f" in _c(a, "narrow")
    assert "-" in _c(a, "absneg") and "__" not in _c(a, "absneg")
    assert "== " in _c(a, "is_equal")
    for f in FUNCS:
        text = _c(a, f)
        assert "__asm" not in text and "__f" not in text and "xmm" not in text, f"{name} {f}:\n{text}"


def test_call_arguments_and_results(an):
    name, a = an
    text = _c(a, "main")
    assert "poly(2.0)" in text or re.search(r"poly\(v\d+\)", text), text
    assert "scale(2.0f, 3.0f)" in text, text
    assert "mix(3, 10, 1.5, 0.25f)" in text, text
    assert "to_long(3.7)" in text, text
    assert re.search(r"\w+ = twice\(", text), text           # the result is kept (xmm0 / d0)


_HARNESS = r"""
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* the reference compiled like the sample (an AArch64 build fuses a*b+c into one rounding:
   the pseudocode says fma() for those), the pseudocode without contraction */
#pragma GCC push_options
#pragma GCC optimize ("%(opt)s", "fp-contract=fast", "no-tree-vectorize")
%(defines)s
#define main ref_main
#include "%(src)s"
#undef main
%(undefs)s
#pragma GCC pop_options

%(code)s

static int bad;
/* the same bits; any two NaNs match (which NaN `a + b` keeps depends on the operand order, and
   the recompiler may commute) */
#define SAME(what, x, y) do { __typeof__(x) a_ = (x), b_ = (y); \
    if (memcmp(&a_, &b_, sizeof a_) && !(a_ != a_ && b_ != b_)) { \
        printf("mismatch %%s line %%d\n", what, __LINE__); bad = 1; } } while (0)

int main(void)
{
    static const double ds[] = {0.0, -0.0, 1.5, -2.25, 3.7, -3.7, 1e300, -1e-300, 0.1, 1234.5678, INFINITY};
    static const int is[] = {0, 1, -1, 7, -100000, 2147483647};
    int n = sizeof ds / sizeof *ds;
%(ptrs)s
    for (int i = 0; i < n; i++) {
        double x = ds[i];
        float f = (float)x;
        SAME("poly", ref_poly(x), p_poly(x));
        SAME("scale", ref_scale(f, (float)ds[(i + 1) %% n]), p_scale(f, (float)ds[(i + 1) %% n]));
        SAME("to_long", ref_to_long(x / 1e290), p_to_long(x / 1e290));
        SAME("to_int", ref_to_int(f / 1e30f), p_to_int(f / 1e30f));
        SAME("narrow", ref_narrow(x), p_narrow(x));
        SAME("absneg", ref_absneg(x), p_absneg(x));
        SAME("hyp", ref_hyp(x, ds[(i + 2) %% n]), p_hyp(x, ds[(i + 2) %% n]));
        SAME("twice", ref_twice(x), p_twice(x));
        for (int j = 0; j < n; j++) {
            double y = ds[j];
            SAME("cmpd", ref_cmpd(x, y), p_cmpd(x, y));
            SAME("is_equal", ref_is_equal(x, y), p_is_equal(x, y));
            SAME("clampd", ref_clampd(x, -y, y), p_clampd(x, -y, y));
            SAME("count_above", ref_count_above(ds, n, y), p_count_above(ds, n, y));
            for (int k = 0; k < 6; k++)
                SAME("mix", ref_mix(is[k], x, (float)y, is[(k + j) %% 6]), p_mix(is[k], x, (float)y, is[(k + j) %% 6]));
        }
    }
    int a[6] = {3, -4, 5, 100, -7, 2};
    float fs[5] = {0.5f, 1.25f, -3.0f, 1e10f, 2.0f};
    for (int m = 0; m <= 6; m++) {
        SAME("avg", ref_avg(a, m), p_avg(a, m));
        if (m <= 5)
            SAME("sum_f", ref_sum_f(fs, m), p_sum_f(fs, m));
    }
    puts(bad ? "FAIL" : "ok");
    return bad;
}
"""


def test_recompiled_pseudocode_matches(an, tmp_path):
    """The pseudocode, compiled again and called through the original prototypes (the ABI is what
    the registers fix; the order C wrote mixed int / float parameters in is not), gives the same bits."""
    name, a = an
    run = []
    if "a64" in name:
        cc, qemu = shutil.which("aarch64-linux-gnu-gcc"), shutil.which("qemu-aarch64")
        if cc is None or qemu is None:
            pytest.skip("no aarch64-linux-gnu-gcc / qemu-aarch64 to run AArch64 pseudocode")
        run, static = [qemu], ["-static"]
    else:
        cc, static = shutil.which("gcc"), []
    if cc is None:
        pytest.skip("no C compiler")
    code = "\n\n".join(_c(a, f) for f in FUNCS)
    # through a volatile pointer: gcc would otherwise turn the call into a direct one with the
    # pseudocode's own prototype
    ptrs = "\n".join(f"    __typeof__(ref_{f}) *volatile p_{f} = (__typeof__(ref_{f}) *)(void *){f};" for f in FUNCS)
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"code": code, "src": os.path.join(HERE, "src", "floats.c"), "ptrs": ptrs,
                               "opt": "O2" if name.endswith("O2") else "O0",
                               "defines": "\n".join(f"#define {f} ref_{f}" for f in FUNCS),
                               "undefs": "\n".join(f"#undef {f}" for f in FUNCS)})
    exe = tmp_path / "re"
    r = subprocess.run([cc, "-O1", "-w", "-fwrapv", "-ffp-contract=off", "-fno-builtin", *static, "-o", str(exe),
                        str(src), "-lm"], capture_output=True, text=True)
    assert r.returncode == 0, f"{name}: does not compile:\n{r.stderr[:3000]}\n{code}"
    r = subprocess.run([*run, str(exe)], capture_output=True, text=True, timeout=120)
    assert r.stdout.strip().endswith("ok"), f"{name}:\n{r.stdout[:2000]}\n{code}"


# ------------------------------------------------------------------ IR level
def test_fp_operators_evaluate():
    d = lambda x: from_float(x, 64)
    assert apply_binop("f+", d(1.5), d(2.25), 64, 64) == d(3.75)
    assert apply_binop("f/", d(1.0), d(0.0), 64, 64) == d(float("inf"))
    assert apply_binop("f<", d(1.0), d(2.0), 64, 64) == 1
    nan = d(float("nan"))
    assert apply_binop("f<", nan, d(2.0), 64, 64) == 0 and apply_binop("f<u", nan, d(2.0), 64, 64) == 1
    assert apply_binop("f!=", nan, nan, 64, 64) == 1 and apply_binop("funord", nan, d(0.0), 64, 64) == 1


def test_comparison_folding():
    """Flag tests after `comisd a, b` (ZF = a ==u b, PF = unordered, CF = a <u b) fold to one comparison."""
    a, b = Var("x", 1, 64), Var("y", 1, 64)
    zf, pf, cf = BinOp("f==u", a, b, 1), BinOp("funord", a, b, 1), BinOp("f<u", a, b, 1)
    n = lambda e: UnOp("!", e, 1)
    assert fold_fcmp(BinOp("&", n(cf), n(zf), 1)) == BinOp("f<", b, a, 1)        # ja: a > b
    assert fold_fcmp(n(cf)) == BinOp("f<=", b, a, 1)                              # jae
    assert fold_fcmp(BinOp("&", n(pf), zf, 1)) == BinOp("f==", a, b, 1)           # jnp + je
    assert fold_fcmp(BinOp("|", pf, n(zf), 1)) == BinOp("f!=", a, b, 1)           # jp or jne
    assert fold_fcmp(BinOp("&", cf, n(cf), 1)) == Const(0, 1)
    assert set(FCMP.values()) <= set(range(16)) and LT | EQ | GT | UN == 15


def test_literals():
    assert literal(from_float(0.5, 64), 64) == "0.5"
    assert literal(from_float(3.0, 64), 64) == "3.0"
    assert literal(from_float(0.1, 32), 32) == "0.1f"
    assert literal(from_float(-2.0, 32), 32) == "-2.0f"
    assert literal(from_float(1e300, 64), 64) == "1e+300"


@pytest.mark.parametrize("fname", ["poly", "cmpd", "clampd", "absneg", "is_equal", "scale", "narrow", "to_long"])
def test_optimisation_preserves_meaning(an, fname):
    """The lifted IR and the optimised IR (comparison folding included) agree under the IR
    interpreter, NaNs and signed zeros among the inputs."""
    import math
    import random
    from relic.decompiler import lift
    from relic.decompiler.arch import arch_for
    from relic.decompiler.interp import Interpreter, Machine
    from relic.decompiler.ir import Return, stmt_exprs, walk
    from relic.decompiler.passes import optimize
    from relic.decompiler.ssa import to_ssa
    name, a = an
    arch = arch_for(a.bin)
    f = a.function_by_name(fname)
    from relic.decompiler.fpabi import set_fp_returns

    def lifted():
        fn = lift(a, f)
        set_fp_returns(a, f, fn)
        return fn
    base = to_ssa(lifted(), arch)
    opt = optimize(to_ssa(lifted(), arch), arch)
    values = [0.0, -0.0, 1.5, -2.25, 3.0, math.inf, -math.inf, math.nan, 1e-310, 7.0]
    rnd = random.Random(3)

    def run(fn, args):
        m = Machine(a.bin)
        for x in {x.name for s in fn.stmts() for t in stmt_exprs(s) for x in walk(t)
                  if isinstance(x, Var) and x.version == 0}:
            m.regs[x] = 0                         # entry registers the test does not set
        m.regs.update({k: 0 for k in ("rax", "rdi", "rsi", "rbp", "x0", "x29", "x30")}, rsp=0x7FFF0000,
                      sp=0x7FFF0000)
        m.write(0x7FFF0000, 0xDEAD0000, 8)
        for k, v in enumerate(args):
            reg = f"v{k}" if a.bin.arch == "arm64" else f"xmm{k}"
            m.regs[reg] = from_float(v, 64) if fname not in ("scale",) else from_float(v, 32)
        it = Interpreter(fn, m)
        it.run()
        return it.result

    assert any(isinstance(s, Return) for s in opt.stmts())
    if fname == "poly":
        assert run(opt, [2.0]) == from_float(8.5, 64) == run(base, [2.0])
    for _ in range(60):
        args = [rnd.choice(values) for _ in range(3)]
        r1, r2 = run(base, args), run(opt, args)
        if r1 != r2:            # equal, or both NaN
            from relic.decompiler.fp import to_float
            w = 32 if fname == "scale" else 64
            assert math.isnan(to_float(r1, w)) and math.isnan(to_float(r2, w)), (fname, args, r1, r2)

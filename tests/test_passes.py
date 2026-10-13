"""Decompiler stage 2: SSA optimisation passes.

The passes are checked dynamically by running each function through the IR
interpreter before and after optimisation and comparing the result -- if a
pass changed the meaning of the code, these tests fail.
"""
import random

import pytest

from relic.analysis import Analysis, analyze
from relic.decompiler import decompile_ir, lift
from relic.decompiler.arch import arch_for
from relic.decompiler.interp import Interpreter, Machine
from relic.decompiler.ir import (Assign, BinOp, Cast, Const, Load, Store, Var, stmt_defs, stmt_exprs, walk)
from relic.decompiler.passes import optimize
from relic.decompiler.refs import format_ir, ir_xrefs
from relic.decompiler.ssa import to_ssa
from relic.loader import load_bytes

M64 = (1 << 64) - 1
STACK = 0x7FFF0000
RET = 0xDEAD0000
FLAG_VARS = ("zf_", "cf_", "sf_", "of_", "pf_")


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


def _entry_regs(fn):
    return {x.name for s in fn.stmts() for top in stmt_exprs(s) for x in walk(top)
            if isinstance(x, Var) and x.version == 0}


def run_ssa(an, fn, args=(), setup=None):
    """Execute an SSA function; entry registers default to 0 so both variants seed alike."""
    m = Machine(an.bin)
    for name in _entry_regs(fn):
        m.regs[name] = 0
    m.regs.update(rsp=STACK, rbp=0)
    m.write(STACK, RET, 8)
    for reg, v in zip(("rdi", "rsi", "rdx", "rcx"), args):
        m.regs[reg] = v & M64
    if setup:
        setup(m)
    it = Interpreter(fn, m)
    it.run()
    return it.result, dict(m.mem)


# --------------------------------------------------------- condition recovery
# cmp rdi, rsi ; set<cc> al ; movzx eax, al ; ret   -- returns the predicate
_SETCC = {
    "4839f70f9cc00fb6c0c3": lambda a, b: s64(a) < s64(b),     # setl
    "4839f70f9fc00fb6c0c3": lambda a, b: s64(a) > s64(b),     # setg
    "4839f70f9dc00fb6c0c3": lambda a, b: s64(a) >= s64(b),    # setge
    "4839f70f9ec00fb6c0c3": lambda a, b: s64(a) <= s64(b),    # setle
    "4839f70f97c00fb6c0c3": lambda a, b: (a & M64) > (b & M64),   # seta
    "4839f70f92c00fb6c0c3": lambda a, b: (a & M64) < (b & M64),   # setb
    "4839f70f96c00fb6c0c3": lambda a, b: (a & M64) <= (b & M64),  # setbe
    "4839f70f95c00fb6c0c3": lambda a, b: (a & M64) != (b & M64),  # setne
    "4839f70f94c00fb6c0c3": lambda a, b: (a & M64) == (b & M64),  # sete
}

_PAIRS = [(1, 2), (2, 1), (5, 5), (-3, 4), (4, -3), (-7, -7), (M64, 0), (1 << 63, 1), (0x7FFFFFFFFFFFFFFF, -1)]


@pytest.mark.parametrize("code", list(_SETCC))
def test_condition_recovery(code):
    ref = _SETCC[code]
    an = Analysis(load_bytes(bytes.fromhex(code), "<cc>", "x64", 0x1000)).run()
    arch = arch_for(an.bin)
    base = to_ssa(lift(an, an.functions[0x1000]), arch)
    opt = optimize(to_ssa(lift(an, an.functions[0x1000]), arch), arch)
    text = format_ir(opt, an)
    # the flag soup is gone: no zf/cf/sf/of/pf variables survive
    assert not any(f in text for f in FLAG_VARS), text
    assert any(op in text for op in ("<s", "<=s", "<u", "<=u", "==", "!=")), text
    for a, b in _PAIRS:
        want = int(ref(a, b))
        assert run_ssa(an, base, (a, b))[0] == want
        assert run_ssa(an, opt, (a, b))[0] == want


# ---------------------------------------------- semantic preservation on samples
def _callfree(fn):
    from relic.decompiler.ir import CallStmt, Effect, Unknown
    return not any(isinstance(s, (CallStmt, Effect, Unknown)) for s in fn.stmts())


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
@pytest.mark.parametrize("name", ["checksum", "classify"])
def test_optimisation_preserves_meaning(request, variant, name):
    an = analyze(request.getfixturevalue(variant))
    arch = arch_for(an.bin)
    f = an.function_by_name(name)
    base = to_ssa(lift(an, f), arch)
    opt = optimize(to_ssa(lift(an, f), arch), arch)
    assert _callfree(base)
    rnd = random.Random(1)
    for _ in range(50):
        if name == "checksum":
            data = bytes(rnd.randrange(1, 256) for _ in range(rnd.randrange(0, 24)))
            buf = 0x500000

            def setup(m, data=data):
                m.write_bytes(buf, data + b"\0")

            assert run_ssa(an, base, (buf,), setup) == run_ssa(an, opt, (buf,), setup)
        else:
            x = rnd.randrange(-6, 14)
            assert run_ssa(an, base, (x,)) == run_ssa(an, opt, (x,))


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_optimisation_is_a_fixpoint(request, variant):
    """Running the passes again changes nothing (they converge)."""
    an = analyze(request.getfixturevalue(variant))
    arch = arch_for(an.bin)
    for f in an.functions.values():
        if f.is_import:
            continue
        once = optimize(to_ssa(lift(an, f), arch), arch)
        before = str(once)
        optimize(once, arch)
        assert str(once) == before, f"{f.name} not at a fixpoint"


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_ssa_still_valid_and_smaller(request, variant):
    an = analyze(request.getfixturevalue(variant))
    arch = arch_for(an.bin)
    for f in an.functions.values():
        if f.is_import:
            continue
        base = to_ssa(lift(an, f), arch)
        opt = optimize(to_ssa(lift(an, f), arch), arch)
        # optimisation never grows the statement count
        assert sum(len(b.stmts) for b in opt.blocks.values()) <= sum(len(b.stmts) for b in base.blocks.values())
        # SSA is preserved: one definition per variable, every use defined
        defined = set()
        for s in opt.stmts():
            for d in stmt_defs(s):
                assert isinstance(d, Var) and d not in defined
                defined.add(d)
        for s in opt.stmts():
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, Var):
                        assert x.version == 0 or x in defined


def test_checksum_folds_to_hash_expression(vuln64_pie):
    """h = h * 31 + s[i] is recovered: a shift-by-5 minus h, with the byte load forwarded."""
    an = analyze(vuln64_pie)
    arch = arch_for(an.bin)
    opt = optimize(to_ssa(lift(an, an.function_by_name("checksum")), arch), arch)
    text = format_ir(opt, an)
    assert "<< 5" in text                         # h * 31 == (h << 5) - h
    assert not any(f in text for f in FLAG_VARS)   # dead flags removed

    # the string byte is loaded straight into an arithmetic expression (load forwarding)
    def load_inside_arith(e):
        return any(isinstance(n, (BinOp, Cast)) and any(isinstance(m, Load) for m in walk(n))
                   and not isinstance(n, Load) for n in walk(e))
    assert any(load_inside_arith(top) for s in opt.stmts() for top in stmt_exprs(s)), text


# ----------------------------------------------------------- strings and xrefs
def test_ir_xrefs_and_string_annotations(vuln64):
    an = analyze(vuln64)
    f = an.function_by_name("menu")
    fn = decompile_ir(an, f)
    refs = ir_xrefs(fn, an)
    called = {an.name(r.to) for r in refs if r.kind == "call"}
    assert {"puts", "printf"} <= called
    assert any(r.kind == "string" for r in refs)
    # the menu strings are spelled out inline in the listing
    text = format_ir(fn, an)
    assert '"4. exit"' in text or "4. exit" in text


def test_string_search_filter(vuln64):
    from relic.analysis.strings import find_strings
    from relic.loader import load
    b = load(vuln64)
    hits = [s for s in find_strings(b) if "sh" in s.value.lower()]
    assert any(s.value == "/bin/sh" for s in hits)

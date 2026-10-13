"""Leaving SSA: phi copies + coalescing must keep the function's meaning."""
import random

import pytest

from relic.analysis import analyze
from relic.decompiler.arch import arch_for
from relic.decompiler.interp import Interpreter, Machine
from relic.decompiler.ir import (Assign, BinOp, Branch, Const, IRBlock, IRFunction, Jump, Phi, Return, Var,
                                 stmt_defs, stmt_exprs, walk)
from relic.decompiler.lift import lift_function
from relic.decompiler.outssa import out_of_ssa
from relic.decompiler.passes import optimize
from relic.decompiler.ssa import to_ssa

from test_passes import run_ssa


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
@pytest.mark.parametrize("name", ["checksum", "classify"])
def test_out_of_ssa_preserves_meaning(request, variant, name):
    an = analyze(request.getfixturevalue(variant))
    arch = arch_for(an.bin)
    opt = optimize(to_ssa(lift_function(an, an.function_by_name(name)), arch), arch)
    conv = out_of_ssa(opt)
    rnd = random.Random(2)
    for _ in range(50):
        if name == "checksum":
            data = bytes(rnd.randrange(1, 256) for _ in range(rnd.randrange(0, 24)))

            def setup(m, data=data):
                m.write_bytes(0x500000, data + b"\0")

            assert run_ssa(an, opt, (0x500000,), setup) == run_ssa(an, conv, (0x500000,), setup)
        else:
            x = rnd.randrange(-6, 14)
            assert run_ssa(an, opt, (x,)) == run_ssa(an, conv, (x,))


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_no_phis_and_few_copies(request, variant):
    an = analyze(request.getfixturevalue(variant))
    arch = arch_for(an.bin)
    for f in an.functions.values():
        if f.is_import:
            continue
        conv = out_of_ssa(optimize(to_ssa(lift_function(an, f), arch), arch))
        copies = 0
        for s in conv.stmts():
            assert not (isinstance(s, Assign) and isinstance(s.src, Phi)), f.name
            for top in stmt_exprs(s):
                assert not any(isinstance(x, Phi) for x in walk(top))
            # every phi temporary was coalesced away (none left as a `x = y` copy)
            if isinstance(s, Assign) and isinstance(s.src, Var):
                copies += 1
        assert copies <= 2, f"{f.name}: {copies} copies left\n{conv}"


def _swap_loop():
    """a, b = 1, 2; loop n times { a, b = b, a } -- the classic lost-swap trap."""
    a0, b0, n0 = Var("a", 1, 64), Var("b", 1, 64), Var("rdi", 0, 64)
    a1, b1, i1, i2 = Var("a", 2, 64), Var("b", 2, 64), Var("i", 1, 64), Var("i", 2, 64)
    i0 = Var("i", 0, 64)
    fn = IRFunction(0x10, "swap")
    fn.blocks[0x10] = IRBlock(0x10, [Assign(0x10, a0, Const(1, 64)), Assign(0x10, b0, Const(2, 64)),
                                     Assign(0x10, i0, Const(0, 64)), Jump(0x10, 0x20)], [0x20], [])
    fn.blocks[0x20] = IRBlock(0x20, [
        Assign(0x20, a1, Phi(((0x10, a0), (0x20, b1)), 64)),
        Assign(0x20, b1, Phi(((0x10, b0), (0x20, a1)), 64)),
        Assign(0x20, i1, Phi(((0x10, i0), (0x20, i2)), 64)),
        Assign(0x20, i2, BinOp("+", i1, Const(1, 64), 64)),
        Branch(0x20, BinOp("<u", i2, n0, 1), 0x20, 0x30)], [0x20, 0x30], [0x10, 0x20])
    fn.blocks[0x30] = IRBlock(0x30, [Return(0x30, BinOp("-", a1, b1, 64))], [], [0x20])
    return fn


def test_parallel_phi_swap():
    fn = _swap_loop()
    conv = out_of_ssa(fn)
    for n in range(1, 6):
        res = []
        for f in (fn, conv):
            m = Machine()
            m.regs["rdi"] = n
            it = Interpreter(f, m)
            it.run()
            res.append(it.result)
        assert res[0] == res[1], (n, str(conv))

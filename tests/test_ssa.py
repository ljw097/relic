"""Decompiler stage 2 (in progress): SSA construction invariants."""
import pytest

from relic.analysis import analyze
from relic.decompiler import lift
from relic.decompiler.arch import arch_for
from relic.decompiler.ir import Assign, CallStmt, Phi, Var, stmt_defs, stmt_exprs, walk
from relic.decompiler.ssa import dominators, reachable_order, to_ssa


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_single_assignment(request, variant):
    an = analyze(request.getfixturevalue(variant))
    arch = arch_for(an.bin)
    for f in an.functions.values():
        if f.is_import:
            continue
        raw = lift(an, f)
        ssa = to_ssa(raw, arch)
        defined = set()
        for s in ssa.stmts():
            for d in stmt_defs(s):
                assert isinstance(d, Var) and d.version > 0
                assert d not in defined, f"{ssa.name}: {d} defined twice"
                defined.add(d)
        for s in ssa.stmts():
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, Var):
                        assert x.version == 0 or x in defined, f"{ssa.name}: {x} used but never defined"
        # the input IR is not modified
        assert not any(isinstance(s, Assign) and isinstance(s.src, Phi) for s in raw.stmts())


def test_loop_header_gets_phis(vuln64):
    an = analyze(vuln64)
    f = an.function_by_name("checksum")
    ssa = to_ssa(lift(an, f), arch_for(an.bin))
    header = next(a for a, b in ssa.blocks.items() if len(b.preds) == 2)
    phis = [s for s in ssa.blocks[header].stmts if isinstance(s, Assign) and isinstance(s.src, Phi)]
    assert phis and all(len(p.src.sources) == 2 for p in phis)


def test_dominators_and_call_effects(vuln64):
    an = analyze(vuln64)
    f = an.function_by_name("classify")
    fn = lift(an, f)
    rpo = reachable_order(fn)
    idom = dominators(fn, rpo)
    assert rpo[0] == f.addr and all(idom[a] == f.addr for a in rpo if len(fn.blocks[a].preds) <= 1 and a != f.addr
                                    and fn.blocks[a].preds == [f.addr])
    ssa = to_ssa(lift(an, an.function_by_name("vuln")), arch_for(an.bin))
    calls = [s for s in ssa.stmts() if isinstance(s, CallStmt)]
    assert calls and all(any(r == "rax" for r, _ in c.defs) for c in calls)
    assert all(any(r == "rdi" for r, _ in c.uses) for c in calls)

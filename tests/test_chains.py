"""Compare chains on one value -> switch (decompiler/chains.py), on hand-built trees."""
from relic.decompiler.chains import switchify
from relic.decompiler.ir import BinOp, Const, Return, Var
from relic.decompiler.structure import Block, If, Jump1, Loop, Ret, Seq, Switch

X = Var("x", 1, 32)


def eq(c):
    return BinOp("==", X, Const(c, 32), 1)


def ret(v):
    return Seq([Ret(Return(0, Const(v, 32)))])


def body(n):
    return Seq([Block(0x100 + n, [])])


def test_leaving_run_becomes_switch_and_the_rest_stays_after():
    tail = Ret(Return(0, Const(-1, 32)))
    tree = Seq([If(1, eq(3), ret(30)), If(2, eq(1), ret(10)), If(3, eq(2), ret(20)), tail])
    out = switchify(tree)
    assert isinstance(out.items[0], Switch) and out.items[-1] is tail
    assert [c.values for c in out.items[0].cases] == [[1], [2], [3]]
    assert not any(c.default for c in out.items[0].cases)


def test_range_split_merges_only_consistent_branches():
    gt4 = BinOp("<s", Const(4, 32), X, 1)                  # 4 < x
    tree = If(1, gt4, Seq([If(2, eq(6), ret(60)), If(3, eq(8), ret(80))]),
              Seq([If(4, eq(1), ret(10)), If(5, eq(2), ret(20))]))
    out = switchify(tree)
    sw = out.items[0]
    assert isinstance(sw, Switch) and sorted(v for c in sw.cases for v in c.values) == [1, 2, 6, 8]
    # a test that contradicts the split (x == 1 under 4 < x) is dead code: no merge
    bad = If(1, gt4, Seq([If(2, eq(1), ret(10)), If(3, eq(8), ret(80))]), Seq([If(4, eq(2), ret(20))]))
    res = switchify(bad)
    assert not isinstance(res, Switch) and not (isinstance(res, Seq) and isinstance(res.items[0], Switch))


def test_else_if_chain_gets_breaks_and_default():
    tree = If(1, eq(1), body(1), If(2, eq(2), body(2), If(3, eq(3), body(3), body(9))))
    sw = switchify(tree)
    assert isinstance(sw, Switch)
    assert [c.default for c in sw.cases] == [False, False, False, True]
    assert all(isinstance(c.body.items[-1], Jump1) and c.body.items[-1].kind == "break" for c in sw.cases)


def test_loop_break_in_a_body_keeps_the_if_chain():
    """`break` inside a case would leave the switch, not the loop."""
    brk = Seq([Jump1("break")])
    chain = If(1, eq(1), brk, If(2, eq(2), body(2), If(3, eq(3), body(3), None)))
    out = switchify(Loop("inf", None, Seq([chain])))
    assert not any(isinstance(x, Switch) for x in out.body.items)


def test_two_cases_stay_ifs():
    tree = Seq([If(1, eq(1), ret(10)), If(2, eq(2), ret(20)), Ret(Return(0, None))])
    assert not any(isinstance(x, Switch) for x in switchify(tree).items)


def test_nested_loop_break_is_fine():
    inner = Loop("inf", None, Seq([Jump1("break")]))
    tree = If(1, eq(1), Seq([inner]), If(2, eq(2), body(2), If(3, eq(3), body(3), None)))
    assert isinstance(switchify(tree), Switch)


def test_range_tests_into_the_default_join_an_else_if_chain():
    """-O0 compare trees: `else if (x > 8) D` where D is also the final `else`."""
    d = Seq([Block(0x500, [])])
    gt = lambda k: BinOp("<s", Const(k, 32), X, 1)
    tree = If(1, eq(8), body(8), If(2, gt(8), d, If(3, eq(6), body(6), If(4, eq(5), body(5), d))))
    sw = switchify(tree)
    assert isinstance(sw, Switch) and [c.values for c in sw.cases if not c.default] == [[5], [6], [8]]
    other = Seq([Block(0x600, [])])
    tree = If(1, eq(8), body(8), If(2, gt(8), other, If(3, eq(6), body(6), If(4, eq(5), body(5), d))))
    assert not isinstance(switchify(tree), Switch)

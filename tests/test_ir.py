"""Expression traversal (decompiler.ir): children, walk, transform."""
import pytest

from relic.decompiler.ir import BinOp, Call, Const, Load, Phi, Var, children, transform, walk


def _tree():
    a, b = Var("a", 0, 64), Var("b", 0, 64)
    return BinOp("+", Load(BinOp("+", a, Const(8, 64), 64), 64), Call(Const(0x401000, 64), (b, Const(1, 64)), 64),
                 64), a, b


def test_walk_is_preorder_left_to_right():
    e, a, b = _tree()
    kinds = [type(x).__name__ for x in walk(e)]
    assert kinds == ["BinOp", "Load", "BinOp", "Var", "Const", "Call", "Const", "Var", "Const"]
    assert list(walk(a)) == [a]


def test_transform_rebuilds_only_what_changed():
    e, a, b = _tree()
    assert transform(e, lambda x: x) is e                  # nothing changed: the same object
    swapped = transform(e, lambda x: b if x == a else x)
    assert swapped is not e and a not in list(walk(swapped)) and b in list(walk(swapped))
    assert swapped.b is e.b                                # (an untouched subtree is shared)


def test_children_of_every_kind():
    e, a, b = _tree()
    assert children(e) == (e.a, e.b) and children(a) == ()
    p = Phi(((0x10, a), (0x20, b)), 64)
    assert children(p) == (a, b)
    with pytest.raises(TypeError):
        children(object())

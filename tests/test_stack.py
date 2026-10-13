"""Decompiler stage 3: stack frame reconstruction."""
import pytest

from relic.analysis import analyze
from relic.decompiler import decompile_ir
from relic.decompiler.arch import arch_for
from relic.decompiler.stack import analyze_frame


def _frame(an, name):
    fn = decompile_ir(an, an.function_by_name(name))
    return analyze_frame(fn, arch_for(an.bin))


@pytest.mark.parametrize("variant,buf_size", [("vuln64", 0x40), ("vuln64_pie", 0x48)])
def test_vuln_buffer_size(request, variant, buf_size):
    """vuln's gets() target is a buffer sized by the distance to the next slot."""
    an = analyze(request.getfixturevalue(variant))
    frame = _frame(an, "vuln")
    buffers = frame.buffers()
    assert len(buffers) == 1
    buf = buffers[0]
    assert buf.kind == "buffer" and buf.taken
    assert buf.size == buf_size              # overflow-to-canary / overflow-to-saved distance


def test_pie_canary_detected(vuln64_pie):
    an = analyze(vuln64_pie)
    frame = _frame(an, "vuln")
    assert frame.canary is not None
    assert frame.slots[frame.canary].kind == "canary"
    assert frame.name_at(frame.canary) == "canary"


def test_non_pie_has_no_canary(vuln64):
    an = analyze(vuln64)
    assert _frame(an, "vuln").canary is None


def test_saved_register_slot(vuln64):
    an = analyze(vuln64)
    frame = _frame(an, "vuln")
    saved = [s for s in frame.slots.values() if s.kind == "saved"]
    assert saved and saved[0].offset == -8
    assert saved[0].name().startswith("saved_")


def test_scanf_scalar_is_taken_but_not_a_buffer(vuln64):
    """&choice passed to scanf("%d", ...) is address-taken, but a 4-byte scalar, not a char[]."""
    an = analyze(vuln64)
    frame = _frame(an, "menu")
    taken = [s for s in frame.slots.values() if s.taken]
    assert taken and all(s.kind != "buffer" for s in taken)
    assert any(s.width == 4 for s in taken)


def test_offsets_are_relative_to_entry_sp(vuln64):
    an = analyze(vuln64)
    frame = _frame(an, "vuln")
    assert frame.slots[0].kind == "retaddr"          # return address at offset 0
    assert all(s.offset <= 0 for s in frame.slots.values())

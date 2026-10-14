"""Data inside functions in the listing: ARM literal pools, Thumb `tbb` tables, x86 padding."""
import pytest

from relic.analysis import analyze
from relic.listing import function_lines, render


def _data(a, name):
    return [ln for ln in function_lines(a, a.function_by_name(name)) if ln.kind == "data"]


def test_arm_literal_pool_resolves_pic_offsets(vuln_arm):
    """`ldr r3, [pc, #n]; add r3, pc, r3`: the pool word is an offset; the listing shows what it makes."""
    a = analyze(vuln_arm)
    pool = _data(a, "vuln")
    assert pool and all(ln.mnemonic == ".word" for ln in pool)
    notes = " | ".join(ln.comment for ln in pool)
    assert '= "name?"' in notes and '= "hello %s (%d)\\n"' in notes
    assert "[__stack_chk_guard@got]" in notes            # a GOT offset, added to the GOT base
    assert all("<- vuln+" in ln.comment for ln in pool)   # each slot names the load that uses it
    s = next(s for s in a.strings if s.value == "name?")
    assert any(ln.target == s.addr for ln in pool)        # double-click follows to the string
    # the pool follows the last instruction and is not decoded as code
    vuln = a.function_by_name("vuln")
    assert min(ln.addr for ln in pool) >= vuln.end


@pytest.mark.parametrize("sample", ["vuln_arm", "vuln_thumb_stripped"])
def test_pool_found_without_mapping_symbols(sample, request):
    a = analyze(request.getfixturevalue(sample))
    if sample.endswith("stripped"):
        a.bin.arm_mapping.clear()
    pool = _data(a, "main") + _data(a, "vuln" if a.function_by_name("vuln") else "main")
    assert any("pc + " in ln.comment for ln in pool)


def test_thumb_tbb_table(flow_thumb_O2):
    a = analyze(flow_thumb_O2)
    f = a.function_by_name("sw_calls")
    lines = function_lines(a, f)
    table = [ln for ln in lines if ln.kind == "data" and ln.comment.startswith("case ")]
    jmp = next(j for j in f.jump_tables if a.dis.decode(j).mnemonic in ("tbb", "tbh"))
    targets = f.jump_tables[jmp]
    assert len(table) == len(targets)
    assert [ln.target for ln in table] == targets
    assert any(ln.kind == "label" and ln.text.startswith("jumptable_") for ln in lines)
    # nothing after the table is shown twice or lost: every block start still has its row
    rows = {ln.addr for ln in lines if ln.kind == "insn"}
    assert set(f.blocks) <= rows


def test_x86_padding_is_align(flow_O2):
    a = analyze(flow_O2)
    aligns = [ln for f in a.functions.values() if not f.is_import
              for ln in function_lines(a, f) if ln.kind == "data"]
    assert aligns and all(ln.mnemonic == "align" for ln in aligns)
    assert not any("not reached" in ln.comment for f in a.functions.values() if not f.is_import
                   for ln in function_lines(a, f))


def test_render_and_user_comment(vuln_arm):
    a = analyze(vuln_arm)
    pool = _data(a, "vuln")
    a.comments[pool[0].addr] = "GOT offset"
    text = render(function_lines(a, a.function_by_name("vuln")))
    assert f"{pool[0].addr:08x}" in text and ".word" in text and "; GOT offset; " in text

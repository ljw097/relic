"""Decompiler stage 4: control-flow structuring."""
import pytest

from relic.analysis import analyze
from relic.decompiler import decompile_ir
from relic.decompiler.ssa import reachable_order
from relic.decompiler.structure import Block, Seq, Structurer, to_pseudocode


def _pseudo(an, name):
    return to_pseudocode(decompile_ir(an, an.function_by_name(name)), an)


def _block_addrs(node, out):
    if isinstance(node, Seq):
        for it in node.items:
            _block_addrs(it, out)
    elif isinstance(node, Block):
        out.append(node.addr)
    else:
        for v in getattr(node, "__dict__", {}).values():
            if isinstance(v, (Seq, Block)):
                _block_addrs(v, out)
            elif isinstance(v, list):
                for x in v:
                    if hasattr(x, "__dict__") or isinstance(x, (Seq, Block)):
                        _block_addrs(x, out)
                    elif isinstance(x, tuple):
                        for y in x:
                            if hasattr(y, "__dict__"):
                                _block_addrs(y, out)


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_every_block_emitted_once(request, variant):
    """Structuring visits every reachable block exactly once; gotos target visited blocks."""
    an = analyze(request.getfixturevalue(variant))
    for f in an.functions.values():
        if f.is_import:
            continue
        fn = decompile_ir(an, f)
        st = Structurer(fn)
        st.run()
        assert st.emitted == set(reachable_order(fn)), f"{f.name}: blocks not all emitted"
        assert st.gotos <= st.emitted


def test_checksum_is_a_loop_with_if(vuln64):
    code = _pseudo(analyze(vuln64), "checksum")
    assert "while (" in code and "if (" in code
    assert "phi(" not in code                 # SSA bookkeeping suppressed
    assert "goto" not in code                  # fully structured
    assert "0x1337" in code                    # the h ^= 0x1337 body survived


def test_classify_is_a_switch(vuln64):
    code = _pseudo(analyze(vuln64), "classify")
    assert "switch (" in code and "case 0:" in code and "default:" in code


def test_main_has_infinite_menu_loop(vuln64):
    code = _pseudo(analyze(vuln64), "main")
    assert "while (1) {" in code
    assert "menu" in code


def test_vuln_is_straight_line(vuln64):
    code = _pseudo(analyze(vuln64), "vuln")
    assert "while" not in code and "goto" not in code
    assert "; gets" in code and "; checksum" in code


def test_condition_negation_reads_naturally(vuln64):
    # the `h > 100000` test should not print as `!(... <=s ...)`
    code = _pseudo(analyze(vuln64), "checksum")
    assert "!(" not in code


def test_menu_loop_breaks_out(vuln64):
    """The `else break` leaving main's menu loop is explicit, not a fall-through."""
    from relic.decompiler.outssa import out_of_ssa
    an = analyze(vuln64)
    code = to_pseudocode(out_of_ssa(decompile_ir(an, an.function_by_name("main"))), an)
    assert "break;" in code and "goto" not in code


def test_pie_classify_switch_has_default(vuln64_pie):
    code = _pseudo(analyze(vuln64_pie), "classify")
    assert "default:" in code and "case 5:" in code and "goto" not in code

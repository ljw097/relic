"""Data references built over several instructions (register constant propagation)."""
import pytest

from relic.analysis import analyze
from relic.listing import function_lines, render


@pytest.fixture(scope="module", params=["vuln_a64", "vuln_a64_pie", "vuln_arm", "vuln_thumb", "vuln32_pie",
                                        "vuln32"])
def an(request):
    return request.param, analyze(request.getfixturevalue(request.param))


def test_string_xrefs(an):
    """adrp + add / literal pool + add pc / pc thunk + lea: the string is referenced from vuln."""
    name, a = an
    s = next(s for s in a.strings if s.value == "name?")
    frm = [x.frm for x in a.xrefs_to.get(s.addr, [])]
    assert frm, f"{name}: no xref to 'name?'"
    vuln = a.function_by_name("vuln")
    assert any(vuln.block_at(f) is not None for f in frm), name


def test_every_menu_string_is_referenced(an):
    name, a = an
    for text in ("1. add", "2. show", "3. delete", "4. exit"):
        s = next(s for s in a.strings if s.value == text)
        assert a.xrefs_to.get(s.addr), f"{name}: {text!r}"


def test_listing_names_the_string(an):
    name, a = an
    text = render(function_lines(a, a.function_by_name("vuln")))
    assert '"name?"' in text, f"{name}:\n{text}"


def test_no_immediates_taken_for_addresses(vuln_a64_pie):
    """`mov w0, #0xffff` in a PIE is not a reference to address 0xffff."""
    a = analyze(vuln_a64_pie)
    assert not any(f.addr & 3 for f in a.functions.values() if not f.is_import)

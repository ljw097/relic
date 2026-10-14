"""Variable types from library calls: what a variable is passed as, or receives, names its type."""
import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.decompiler.sigs import format_types


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.mark.parametrize("variant", ["libtypes_O0", "libtypes_O2"])
def test_parameters_typed_by_library_calls(request, variant):
    an = analyze(request.getfixturevalue(variant))
    assert "name_size(char *a1)" in _c(an, "name_size")            # strlen(a1), inside `return`
    filled = _c(an, "filled")
    assert "void *filled(size_t a1, int a2)" in filled, filled      # malloc(a1); its result
    show = _c(an, "show")
    assert "show(FILE *a1, char *a2, int a3)" in show, show         # stream; the format's %s
    assert "joined(char *a1, char *a2)" in _c(an, "joined")
    lines = _c(an, "count_lines")
    assert "count_lines(char *a1)" in lines and "FILE *" in lines, lines    # fopen's result


def test_format_types():
    assert format_types("%s=%d\n") == ["char *", None]
    assert format_types("%*s %p %zu %%") == [None, "char *", "void *", "size_t"]
    assert format_types("%s %p", scan=True) == ["char *", None]

"""C++ demangling: names in the analysis, name resolution, and the pseudocode."""
import pytest

from relic.demangle import demangle, short_name

needs_demangler = pytest.mark.skipif(demangle("_Z5twicei") is None, reason="no C++ demangler on this system")


@needs_demangler
def test_demangle():
    assert demangle("_Z5twicei") == "twice(int)"
    assert demangle("_ZNK3geo4Rect4areaEv") == "geo::Rect::area() const"
    assert demangle("_ZNSt6vectorIiSaIiEE9push_backERKi@GLIBCXX_3.4").startswith("std::vector<int")
    assert demangle("main") is None and demangle("_Zgarbage") is None


def test_short_name():
    assert short_name("geo::Rect::area() const") == "geo::Rect::area"
    assert short_name("int biggest<int>(int, int)") == "biggest<int>"
    assert short_name("operator new(unsigned long)") == "operator new"
    assert short_name("f<std::pair<int, int> >(std::pair<int, int>)") == "f<std::pair<int, int> >"
    assert short_name("plain") == "plain"


@needs_demangler
def test_cpp_binary(shapes):
    from relic.analysis import analyze
    from relic.decompiler.emit import decompile
    an = analyze(shapes)
    names = {an.name(f.addr) for f in an.functions.values()}
    assert {"geo::total(geo::Rect const*, int)", "twice(int)", "twice(double)",
            "geo::Rect::area() const", "int biggest<int>(int, int)"} <= names
    # resolvable by raw symbol, full display name, or the short form
    total = an.resolve("geo::total")
    assert total is not None and total == an.resolve("_ZN3geo5totalEPKNS_4RectEi")
    assert an.resolve("geo::total(geo::Rect const*, int)") == total
    code = decompile(an, an.function_by_name("main")).text
    assert "geo::Rect::scale(" in code and "geo::total(" in code and "biggest<int>(" in code
    assert "int biggest<int>(" not in code
    code = decompile(an, an.function_by_name("geo::total")).text
    assert code.startswith("int geo::total(") and "geo::Rect::area(" in code

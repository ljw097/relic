"""Repeatable comments and the names list."""
import shutil

from relic.analysis import analyze
from relic.listing import function_lines


def _comments_at_calls(an, caller, callee):
    f = an.function_by_name(caller)
    target = an.function_by_name(callee).addr
    calls = [i.addr for b in f.blocks.values() for i in b.insns if i.target == target]
    return [ln.comment for ln in function_lines(an, f) if ln.kind == "insn" and ln.addr in calls]


def test_repeatable_comment_shows_where_it_is_referred_to(vuln64, tmp_path):
    path = tmp_path / "vuln64"
    shutil.copy(vuln64, path)
    an = analyze(str(path))
    menu = an.function_by_name("menu")
    an.repeatable_comment(menu.addr, "reads the choice")
    got = _comments_at_calls(an, "main", "menu")
    assert got and all("⇢ reads the choice" in c for c in got), got
    first = next(ln for ln in function_lines(an, menu) if ln.kind == "insn")
    assert "reads the choice" in first.comment and "⇢" not in first.comment     # at the address itself
    an.save_project()
    assert all("⇢ reads the choice" in c for c in _comments_at_calls(analyze(str(path)), "main", "menu"))
    an.undo()
    assert not any("reads the choice" in c for c in _comments_at_calls(an, "main", "menu"))


def test_names_list(vuln64):
    an = analyze(vuln64)
    an.rename(an.function_by_name("menu").addr, "show_menu")
    notes = an.resolve("notes")
    an.rename(notes + 8, "second_note")                        # a label of its own
    names = {n: (a, k) for a, n, k in an.names()}
    assert names["main"][1] == "function" and names["show_menu"][1] == "function" and "menu" not in names
    assert names["notes"] == (notes, "data") and names["second_note"] == (notes + 8, "label")
    assert any(k == "import" for _, k in names.values())
    assert [a for a, _, _ in an.names()] == sorted(a for a, _, _ in an.names())


def test_call_graph(vuln64):
    from relic.analysis.callgraph import call_graph, callees, callers
    an = analyze(vuln64)
    main = an.function_by_name("main").addr
    menu = an.function_by_name("menu").addr
    vuln = an.function_by_name("vuln").addr
    assert menu in callees(an, main) and vuln in callees(an, main) and main in callers(an, menu)
    levels, edges, more = call_graph(an, main, 1)
    assert levels[main] == 0 and levels[menu] == 1 and (main, menu) in edges and not more
    levels, edges, _ = call_graph(an, menu, 2)
    assert levels[main] == -1 and (main, menu) in edges
    # two levels of callers: main -> add_note -> (what add_note calls)
    add_note = an.function_by_name("add_note").addr
    leaf = callees(an, add_note)[0]
    levels, _, _ = call_graph(an, leaf, 2)
    assert levels[add_note] == -1 and levels[main] == -2


def test_navigation_band_regions(vuln64):
    from relic.analysis.navband import band_regions
    an = analyze(vuln64)
    regs = band_regions(an)
    kinds = {k for _, _, k in regs}
    assert {"code", "import", "data"} <= kinds
    assert all(s < e for s, e, _ in regs) and [r[0] for r in regs] == sorted(r[0] for r in regs)
    # every loaded section covered exactly once
    total = sum(e - s for s, e, _ in regs)
    assert total == sum(s.size for s in an.bin.sections if s.size and s.addr)
    main = an.function_by_name("main").addr
    assert next(k for s, e, k in regs if s <= main < e) == "code"

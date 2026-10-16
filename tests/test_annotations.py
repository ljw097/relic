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

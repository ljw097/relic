"""Undo / redo of every user edit (names, comments, types, structs, bookmarks, patches) and bookmarks."""
import json

from relic.analysis import analyze


def test_undo_redo_annotations_in_order(vuln64):
    an = analyze(vuln64)
    an.renames.clear(), an.comments.clear(), an.bookmarks.clear()
    an.edit_undo.clear()
    vuln = an.function_by_name("vuln").addr
    an.rename(vuln, "read_name")
    an.comment(vuln, "overflow here")
    an.rename_var(vuln, "var_c", "count")
    an.bookmark(vuln + 4, "look")
    assert an.name(vuln) == "read_name" and len(an.edit_undo) == 4
    assert an.undo() == ("notes", vuln + 4) and vuln + 4 not in an.bookmarks
    assert an.undo() == ("notes", vuln) and vuln not in an.var_names
    assert an.undo() == ("notes", vuln) and vuln not in an.comments
    assert an.undo() == ("notes", vuln) and an.name(vuln) == "vuln"
    assert an.undo() is None
    assert an.redo() == ("notes", vuln) and an.name(vuln) == "read_name"
    assert an.redo() and an.comments[vuln] == "overflow here"
    an.rename(vuln, "other")                       # a new edit drops what could be redone
    assert an.redo() is None
    assert an.undo() and an.name(vuln) == "read_name"


def test_no_op_and_failed_edits_are_not_recorded(vuln64):
    an = analyze(vuln64)
    an.edit_undo.clear()
    vuln = an.function_by_name("vuln").addr
    an.comment(vuln, "")                           # nothing to remove
    try:
        an.set_var_type(vuln, "var_c", "not a type !!")
    except ValueError:
        pass
    assert an.edit_undo == []
    an.add_field("s_x", 0x10, "char[8]", "tag")    # adds and names: one step
    assert len(an.edit_undo) == 1
    an.undo()
    assert "s_x" not in an.struct_names


def test_patch_and_notes_share_one_history(vuln64):
    an = analyze(vuln64)
    an.edit_undo.clear()
    win = an.function_by_name("win").addr
    orig = an.bin.read(win, 1)
    an.rename(win, "shell")
    an.patch(win, b"\xc3")
    an.comment(win, "patched to ret")
    assert an.undo() == ("notes", win) and win not in an.comments
    assert an.undo() == ("patch", win) and an.bin.read(win, 1) == orig and not an.patches
    assert an.name(win) == "shell"                 # kept across the re-analysis of the undo
    assert an.undo() == ("notes", win) and an.name(win) == "win"
    assert an.redo() == ("notes", win) and an.redo() == ("patch", win) and an.bin.read(win, 1) == b"\xc3"


def test_bookmarks_saved_in_project(vuln64, tmp_path):
    import shutil
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    an = analyze(str(path))
    main = an.function_by_name("main").addr
    an.bookmark(main, "  entry of the menu  ")
    an.bookmark(main + 8, "x")
    an.bookmark(main + 8, "")                      # empty removes
    an.save_project()
    assert json.load(open(an.project_path))["bookmarks"] == {f"{main:#x}": "entry of the menu"}
    again = analyze(str(path))
    assert again.bookmarks == {main: "entry of the menu"}

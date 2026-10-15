"""Project files: snapshots of the annotations, merging another analyst's project."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from relic.analysis import analyze
from relic.analysis.project import ProjectMismatch

HERE = os.path.dirname(__file__)


@pytest.fixture
def copies(vuln64, tmp_path):
    """Two copies of one binary, each with its own project file (two analysts)."""
    out = []
    for who in ("alice", "bob"):
        d = tmp_path / who
        d.mkdir()
        shutil.copy(vuln64, d / "vuln64")
        out.append(analyze(str(d / "vuln64")))
    return out


def _two(an):
    fs = sorted(f.addr for f in an.functions.values() if not f.is_import)
    return fs[0], fs[1]


def test_snapshot_restore_and_undo(copies):
    an, _ = copies
    f, g = _two(an)
    an.rename(f, "first")
    an.comment(g, "looked at")
    snap = an.take_snapshot("before")
    assert snap["notes"]["renames"] == {f"{f:#x}": "first"}
    an.rename(f, "changed")
    an.rename(g, "second")
    an.bookmark(g, "here")
    an.restore_snapshot("before")
    assert an.renames == {f: "first"} and an.comments == {g: "looked at"} and not an.bookmarks
    an.undo()                                    # the restore is one undo step
    assert an.renames == {f: "changed", g: "second"} and an.bookmarks == {g: "here"}
    # snapshots are saved with the project, and the snapshot is a copy (not changed by edits)
    an.save_project()
    again = analyze(an.bin.path)
    assert list(again.snapshots) == ["before"]
    again.restore_snapshot("before")
    assert again.renames == {f: "first"}
    with pytest.raises(KeyError):
        again.restore_snapshot("nope")
    assert again.delete_snapshot("before") and not again.delete_snapshot("before")
    with pytest.raises(ValueError):
        again.take_snapshot("  ")


def test_merge_adds_theirs_and_reports_conflicts(copies):
    alice, bob = copies
    f, g = _two(alice)
    alice.rename(f, "parse")
    alice.comment(f, "entry")
    bob.rename(f, "decode")                      # conflict
    bob.rename(g, "helper")                      # only bob's
    bob.comment(f, "entry")                      # the same: no conflict
    bob.rename_var(g, "a1", "buf")
    bob.bookmark(g, "check")
    bob.save_project()
    got = alice.merge_project(bob.project_path)
    assert got["added"] == {"renames": 1, "bookmarks": 1, "variables": 1}, got
    assert got["conflicts"] == [("renames", f, "parse", "decode")] and got["kept"] == "ours"
    assert alice.renames == {f: "parse", g: "helper"} and alice.var_names[g] == {"a1": "buf"}
    assert alice.bookmarks == {g: "check"}
    alice.undo()                                 # the merge is one undo step
    assert alice.renames == {f: "parse"} and g not in alice.var_names
    got = alice.merge_project(bob.project_path, theirs=True)
    assert alice.renames[f] == "decode" and got["kept"] == "theirs"
    # nothing new the second time
    again = alice.merge_project(bob.project_path)
    assert again["added"] == {} and again["conflicts"] == []


def test_merge_structs_and_c_types(copies, tmp_path):
    alice, bob = copies
    bob.import_header("enum color { RED, GREEN = 4 };\nstruct pt { int x; int y; };\n")
    bob.save_project()
    got = alice.merge_project(bob.project_path)
    assert alice.enum("color") == {"RED": 0, "GREEN": 4} and alice.struct_names["pt"]["imported"]
    assert got["added"]["enums"] == 1 and got["added"]["structs"] >= 1


def test_merge_refuses_another_binary(copies, flow_O0, tmp_path):
    alice, _ = copies
    other = tmp_path / "flow"
    shutil.copy(flow_O0, other)
    o = analyze(str(other))
    o.rename(o.function_by_name("main").addr, "entry")
    o.save_project()
    with open(o.project_path) as fp:
        assert json.load(fp)["sha256"]
    with pytest.raises(ProjectMismatch, match="another file"):
        alice.merge_project(o.project_path)
    assert not alice.edit_undo                   # (refused: nothing changed, nothing to undo)
    alice.merge_project(o.project_path, force=True)
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2]")
    with pytest.raises(ValueError, match="not a relic project"):
        alice.merge_project(str(bad))


def test_cli_project(copies):
    alice, bob = copies
    f, g = _two(alice)
    bob.rename(g, "helper")
    bob.save_project()

    def relic(*args):
        r = subprocess.run([sys.executable, "-m", "relic", "project", alice.bin.path, *args],
                           capture_output=True, text=True, cwd=os.path.dirname(HERE))
        return r.returncode, r.stdout + r.stderr
    assert relic("snapshots") == (0, "no snapshots\n")
    code, out = relic("snapshot", "empty")
    assert code == 0 and "snapshot 'empty': no annotations" in out
    code, out = relic("merge", bob.project_path)
    assert code == 0 and "added 1 renames" in out, out
    code, out = relic("snapshots")
    assert out.startswith("empty") and "no annotations" in out
    code, out = relic("restore", "empty")
    assert code == 0 and "restored 'empty'" in out
    assert analyze(alice.bin.path).renames == {}
    code, out = relic("restore", "missing")
    assert code != 0 and "no snapshot 'missing'" in out
    code, out = relic("merge")
    assert code != 0 and "needs a file" in out

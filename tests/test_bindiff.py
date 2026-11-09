"""Binary diffing (relic.analysis.bindiff, `relic diff`): two builds' functions matched."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from relic.analysis import analyze
from relic.analysis.bindiff import diff, function_diff, similarity

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "src", "vuln.c")


@pytest.fixture(scope="module")
def patched(tmp_path_factory):
    """vuln.c stripped, and the same with its `gets` fixed and one function added: (old, new)."""
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no gcc")
    d = tmp_path_factory.mktemp("bindiff")
    with open(VULN) as fp:
        src = fp.read()
    assert "    gets(buf); // stack overflow" in src
    fixed = d / "fixed.c"
    fixed.write_text(src.replace("    gets(buf); // stack overflow", "    fgets(buf, sizeof buf, stdin);")
                     + "\nint added_helper(int x) { return x * 3 + 1; }\n")
    out = []
    for name, path in (("old", VULN), ("new", str(fixed))):
        exe = str(d / name)
        subprocess.run([cc, "-O0", "-fno-stack-protector", "-no-pie", "-w", "-s", path, "-o", exe],
                       check=True, capture_output=True)
        out.append(exe)
    return out


def test_same_binary_is_identical(vuln64):
    an = analyze(vuln64)
    d = diff(an, analyze(vuln64))
    assert d.added == [] and d.removed == []
    assert all(m.identical and m.old == m.new for m in d.matches)
    assert d.summary()["identical"] == len([f for f in an.functions.values() if not f.is_import])


def test_patch_shows_the_one_function_that_changed(patched, vuln64):
    old, new = analyze(patched[0]), analyze(patched[1])
    d = diff(old, new)
    vuln = analyze(vuln64).function_by_name("vuln").addr      # (the stripped build lays out the same)
    changed = d.changed()
    assert [(m.old, m.new) for m in changed] == [(vuln, vuln)]
    assert changed[0].how == "calls" and 0.7 < changed[0].similarity < 1.0
    assert d.removed == [] and len(d.added) == 1
    assert d.summary() == {"identical": len(d.matches) - 1, "changed": 1, "added": 1, "removed": 0}
    lines = function_diff(d, changed[0])
    assert "-    call gets" in lines and "+    call fgets" in lines
    pseudo = "\n".join(function_diff(d, changed[0], decompiled=True))
    assert "-    gets(" in pseudo and "+    fgets(" in pseudo
    assert d.find(hex(vuln)) is changed[0]


def test_moved_functions_match_by_code(vuln64, vuln64_pie):
    """Another build (PIE, -O1): the functions are elsewhere and some differ; names find them."""
    a, b = analyze(vuln64), analyze(vuln64_pie)
    d = diff(a, b)
    by_name = {m.name: m for m in d.matches}
    for name in ("vuln", "add_note", "main", "checksum"):
        m = by_name[name]
        assert m.old == a.function_by_name(name).addr and m.new == b.function_by_name(name).addr


def test_stripped_copy_matches_by_code_and_calls(flow_O2, tmp_path):
    stripped = str(tmp_path / "flow_O2_stripped")
    shutil.copy(flow_O2, stripped)
    subprocess.run(["strip", stripped], check=True)
    a, b = analyze(flow_O2), analyze(stripped)
    d = diff(a, b)
    assert d.added == [] and d.removed == []
    assert all(m.old == m.new and m.identical for m in d.matches)
    assert {m.how for m in d.matches} <= {"code", "calls", "similar"}       # (no names on the stripped side)


def test_similarity():
    assert similarity(["a", "b"], ["a", "b"]) == 1.0
    assert similarity(["a", "b"], ["c", "d"]) == 0.0
    assert similarity(["a", "b", "c", "d"], ["a", "b", "c", "x"]) == 0.75


def _relic(*args):
    return subprocess.run([sys.executable, "-m", "relic", *args], capture_output=True, text=True,
                          env={**os.environ, "RELIC_SIGS": os.devnull})


def test_cli(patched, vuln64):
    vuln = analyze(vuln64).function_by_name("vuln").addr
    r = _relic("diff", *patched)
    assert r.returncode == 0, r.stderr
    assert "1 changed), 1 added, 0 removed" in r.stdout.splitlines()[0]
    assert f"{vuln:x}" in r.stdout and "added:" in r.stdout
    r = _relic("diff", *patched, "--json")
    got = json.loads(r.stdout)
    assert got["summary"]["changed"] == 1 and len(got["added"]) == 1
    r = _relic("diff", *patched, "-f", hex(vuln))
    assert r.returncode == 0 and "+    call fgets" in r.stdout
    r = _relic("diff", *patched, "-f", "nowhere_at_all")
    assert r.returncode != 0 and "not a function matched" in r.stderr


SHIFT = """#include <stdio.h>
int work(int x, int y) {
    int r = 0;
    if (x > 10) r += 1;
    if (y > 20) r += 2;
    if (x + y > 30) r += 4;
    if (x * y > 40) r += 8;
    if (x - y > 50) r += 16;
    if (y - x > 60) r += 32;
    for (int i = 0; i < x; i++) r ^= i;
    return r;
}
int main(int c, char **v) { printf("%d\\n", work(c, c * 3)); return 0; }
"""


def test_a_block_added_early_is_a_small_change(tmp_path):
    """One `if` at the top renumbers every later block: that alone is not a change of the
    lines that branch to them (similarity, and the lines the diff shows)."""
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no gcc")
    exes = []
    for k, src in enumerate((SHIFT, SHIFT.replace("    int r = 0;\n", "    int r = 0;\n    if (x < 0) return -1;\n"))):
        (tmp_path / f"s{k}.c").write_text(src)
        exes.append(str(tmp_path / f"s{k}"))
        subprocess.run([cc, "-O0", "-no-pie", str(tmp_path / f"s{k}.c"), "-o", exes[-1]], check=True)
    d = diff(analyze(exes[0]), analyze(exes[1]))
    [m] = d.changed()
    assert m.name == "work" and m.how == "name" and m.similarity > 0.9
    lines = function_diff(d, m)
    removed = [ln for ln in lines if ln.startswith("-") and not ln.startswith("---")]
    added = [ln for ln in lines if ln.startswith("+") and not ln.startswith("+++")]
    assert removed == [] and 4 <= len(added) <= 8          # the new compare, branch, return value, jump


def test_comparable_drops_block_numbers():
    from relic.analysis.bindiff import comparable
    assert comparable(["B3", "jle L12", "mov eax, 0xb1"]) == ["B", "jle L", "mov eax, 0xb1"]


def test_pseudocode_diff_survives_a_function_that_does_not_decompile(patched, monkeypatch):
    import relic.decompiler.emit as emit
    old, new = analyze(patched[0]), analyze(patched[1])
    d = diff(old, new)
    real = emit.decompile

    def new_side_fails(an, f):
        if an is new:
            raise NotImplementedError("no lifter")
        return real(an, f)
    monkeypatch.setattr(emit, "decompile", new_side_fails)
    lines = function_diff(d, d.changed()[0], decompiled=True)
    assert "+// not decompiled (NotImplementedError: no lifter)" in lines
    assert any(ln.startswith("-    gets(") for ln in lines)

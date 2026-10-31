"""Exporting the whole binary's pseudocode as one C file."""
import io
import os
import re
import shutil
import subprocess
import sys

import pytest

from relic.analysis import analyze
from relic.decompiler.export import export_c

HERE = os.path.dirname(__file__)


def test_export_lists_every_function_and_each_struct_once(vuln64):
    an = analyze(vuln64)
    out = io.StringIO()
    res = export_c(an, out)
    text = out.getvalue()
    funcs = [f for f in an.functions.values() if not f.is_import]
    assert res["functions"] == len(funcs) and not res["failed"]
    for f in funcs:
        assert f"// {an.name(f.addr) or f.name} @ {f.addr:#x}" in text
    assert text.count("struct s_notes {") == 1 and res["structs"] >= 1
    # struct declarations come before every function
    assert text.index("struct s_notes {") < text.index("// main @")
    assert "int main(int argc, char **argv)\n{" in text


def test_export_keeps_going_past_a_failure(vuln64, monkeypatch):
    an = analyze(vuln64)
    import relic.decompiler.emit as emit
    real = emit.decompile

    def flaky(an_, f):
        if (an_.name(f.addr) or f.name) == "win":
            raise RuntimeError("boom")
        return real(an_, f)
    monkeypatch.setattr(emit, "decompile", flaky)
    out = io.StringIO()
    res = export_c(an, out)
    assert res["failed"] == ["win"] and "not decompiled (RuntimeError: boom)" in out.getvalue()
    assert "int main(int argc" in out.getvalue()


def test_cli_writes_a_c_file(vuln64, tmp_path):
    target = tmp_path / "out.c"
    r = subprocess.run([sys.executable, "-m", "relic", "decompile", vuln64, "-a", "-o", str(target)],
                       capture_output=True, text=True, cwd=os.path.dirname(HERE))
    assert r.returncode == 0, r.stderr
    assert "functions" in r.stdout and target.read_text().count("// main @") == 1
    one = tmp_path / "main.c"
    subprocess.run([sys.executable, "-m", "relic", "decompile", vuln64, "main", "-o", str(one)], check=True,
                   capture_output=True, cwd=os.path.dirname(HERE))
    assert one.read_text().startswith("int main(")


def test_batch_export_reuses_preparations_and_writes_the_same(structs_O2, vuln64):
    """`batch`: a function prepared for another one's struct scan is not prepared again for its own
    pseudocode -- the same file, fewer preparations; nothing is kept once it is over."""
    import relic.decompiler.pipeline as pipeline
    for path in (structs_O2, vuln64):
        texts, counts = [], []
        for batch in (False, True):
            an = analyze(path)
            n = [0]
            real = pipeline.prepare

            def counting(an, f, real=real, n=n):
                n[0] += 1
                return real(an, f)
            pipeline.prepare = counting
            try:
                out = io.StringIO()
                export_c(an, out, batch=batch)
            finally:
                pipeline.prepare = real
            texts.append(out.getvalue())
            counts.append(n[0])
        assert texts[0] == texts[1]
        assert counts[1] < counts[0], counts
    assert pipeline._KEPT.get() is None


GROW_C = r"""
#include <stdlib.h>
#include <stdio.h>
struct node { struct node *next; long key; int a; int b; char *name; long c; };
__attribute__((noinline)) int first(struct node *n) { return n->a + (int)n->key; }
__attribute__((noinline)) void second(struct node *n) { n->b = 7; puts(n->name); }
__attribute__((noinline)) long third(struct node *n) { return n->c + (long)n->next; }
int main(int argc, char **argv) {
    struct node *n = malloc(sizeof *n);
    n->next = 0; n->key = argc; n->name = argv[0];
    int r = first(n); second(n); return r + (int)third(n);
}
"""


def test_export_declares_a_growing_struct_once(tmp_path):
    """A struct main hands to its callees grows as each callee is decompiled: the file declares it
    once, with every field (it used to repeat it, smaller, which does not compile)."""
    if not shutil.which("gcc"):
        pytest.skip("no gcc")
    src, exe = tmp_path / "grow.c", tmp_path / "grow"
    src.write_text(GROW_C)
    subprocess.run(["gcc", "-O1", "-o", str(exe), str(src)], check=True)
    an = analyze(str(exe))
    out = io.StringIO()
    res = export_c(an, out)
    text = out.getvalue()
    names = re.findall(r"^struct (\w+) \{", text, re.M)
    assert names and len(names) == len(set(names)) == res["structs"]
    decl = text[text.index("struct s_main_1 {"):]
    decl = decl[:decl.index("};")]
    for off in ("f_0", "f_8", "f_10", "f_14", "f_18", "f_20"):
        assert off in decl, decl

"""Exporting the whole binary's pseudocode as one C file."""
import io
import os
import subprocess
import sys

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

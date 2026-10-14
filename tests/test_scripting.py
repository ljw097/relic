"""Scripting API, interactive console, batch scripts (`relic script`)."""
import shutil
import subprocess
import sys

from relic.analysis import analyze
from relic.scripting import Console, namespace, run_script


def test_namespace_queries_and_edits(vuln64):
    an = analyze(vuln64)
    ns = namespace(an)
    main = an.function_by_name("main").addr
    assert ns["here"]() == main and ns["addr"]("main") == main and ns["addr"](an.functions[main]) == main
    assert ns["func"]("main+0x4").addr == main
    assert "puts(" in ns["decompile"]("menu") and ns["disasm"]("main", 1).startswith(f"{main:#x}")
    assert {x.frm for x in ns["xrefs_to"]("vuln")} and len(ns["functions"]()) >= 10
    assert ns["search"]("f3 0f 1e fa")                                  # endbr64
    ns["rename"]("win", "shell")
    assert ns["name"]("shell") == "shell" and an.function_by_name("shell") is not None
    ns["nop"]("vuln+0x8")
    assert vuln64 and an.patches


def test_console_keeps_state_and_shows_errors(vuln64):
    c = Console(namespace(analyze(vuln64)))
    assert c.push("x = len(functions())") == "" and c.prompt == ">>> "
    assert c.push("for f in functions()[:2]:") == "" and c.more and c.prompt == "... "
    c.push("    print(name(f.addr))")
    out = c.push("")
    assert len(out.splitlines()) == 2 and not c.more
    assert c.push("x > 5").strip() == "True"
    assert "NameError" in c.push("nope()")


def test_run_script_and_cli(vuln64, tmp_path):
    script = tmp_path / "s.py"
    script.write_text("import sys\nresult.append((sys.argv[1:], name(here())))\n")
    result = []
    ns = dict(namespace(analyze(vuln64)), result=result)
    run_script(str(script), ns, ["a", "b"])
    assert result == [(["a", "b"], "main")]
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    script.write_text("rename('win', 'shell')\nprint(decompile('shell').splitlines()[0])\n")
    r = subprocess.run([sys.executable, "-m", "relic", "script", "--save", str(path), str(script)],
                       capture_output=True, text=True)
    assert r.returncode == 0 and " shell(void)" in r.stdout.splitlines()[0], r.stderr
    assert analyze(str(path)).function_by_name("shell") is not None             # saved in the project

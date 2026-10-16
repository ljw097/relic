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


def test_reference_is_current_and_complete():
    import inspect
    import os

    from relic.scripting import Api, reference
    text = reference()
    with open(os.path.join(os.path.dirname(__file__), "..", "docs", "scripting.md")) as fp:
        assert fp.read() == text, "docs/scripting.md is stale: run tools/gen_scripting_docs.py"
    for n, fn in inspect.getmembers(Api, inspect.isfunction):
        if not n.startswith("_"):
            assert inspect.getdoc(fn), f"Api.{n} has no docstring"


def _toy_image():
    # 0x1000: nop; call 0x1008; nop; ret      0x1008: jz 0x100c; nop; ret
    return b"RLC1" + bytes([1, 0, 2, 2, 1, 0, 5, 0]) + bytes([4, 1, 1, 0, 5, 0])


def test_plugin_loader_and_processor(tmp_path):
    import importlib.util
    import os

    from relic import extend
    from relic.scripting import PluginAPI
    spec = importlib.util.spec_from_file_location("toy_plugin", os.path.join(os.path.dirname(__file__),
                                                                             "plugins_sdk", "toy.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        mod.register(PluginAPI(None, "toy"))                       # (headless: no window)
        path = tmp_path / "prog.rlc"
        path.write_bytes(_toy_image())
        an = analyze(str(path))
        assert an.bin.format == "RLC1" and an.bin.arch == "toy"
        assert sorted(an.functions) == [0x1000, 0x1008]            # the call made a function
        f = an.functions[0x1008]
        assert any(i.mnemonic == "jz" for b in f.blocks.values() for i in b.insns) and len(f.blocks) >= 2
        ns = namespace(an)
        assert ns["insn"](0x1002).mnemonic == "call" and ns["callees"](0x1000) == [0x1008]
        assert "call" in ns["disasm"](0x1000, 4)
    finally:
        extend.clear()


def test_cli_loads_plugins(tmp_path, monkeypatch):
    import os
    path = tmp_path / "prog.rlc"
    path.write_bytes(_toy_image())
    env = dict(os.environ, RELIC_PLUGINS=os.path.join(os.path.dirname(__file__), "plugins_sdk"))
    r = subprocess.run([sys.executable, "-m", "relic", "funcs", str(path)], capture_output=True, text=True,
                       env=env, cwd=os.path.join(os.path.dirname(__file__), ".."))
    assert r.returncode == 0 and "1008" in r.stdout, r.stdout + r.stderr


def test_decompile_hook(vuln64):
    from relic import extend
    from relic.decompiler.emit import Line, decompile
    an = analyze(vuln64)
    f = an.function_by_name("vuln")
    extend.register_decompile_hook(lambda an, func, lines: [Line(f"// hooked {func.name}", None, 0)] + lines)
    extend.register_decompile_hook(lambda an, func, lines: 1 / 0)            # (a broken hook is skipped)
    try:
        text = decompile(an, f).text
        assert text.startswith("// hooked vuln") and "gets(" in text
    finally:
        extend.clear()


def test_new_api_calls(vuln64, tmp_path):
    p = tmp_path / "vuln64"
    shutil.copy(vuln64, p)
    an = analyze(str(p))
    ns = namespace(an)
    main = an.function_by_name("main").addr
    assert ns["read"](main, 4) == an.bin.read(main, 4) and ns["read_int"](main, 1) == an.bin.read(main, 1)[0]
    assert any(s[0] == ".text" and s[3] == "r-x" for s in ns["sections"]())
    assert an.function_by_name("menu").addr in ns["callees"]("main") and main in ns["callers"]("menu")
    ns["define"](0x402004, "string")
    assert an.data_defs[0x402004] == ["string", 8]
    ns["undefine"](0x402004)
    win = an.function_by_name("win").addr
    ns["delete_function"](win)
    assert win not in an.functions
    ns["make_function"](win)
    assert win in an.functions
    ns["bookmark"](main, "start here")
    assert an.bookmarks[main] == "start here"

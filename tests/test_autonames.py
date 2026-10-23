"""Names the analysis suggests: functions of a stripped binary (analysis/autoname.py) and the
decompiler's variables (decompiler/varnames.py). The rest of the suite shows generated names
(conftest sets RELIC_AUTO_NAMES=0); these tests turn suggestions on."""
import os
import re
import shutil
import subprocess
import sys

import pytest

from relic.analysis import Analysis
from relic.decompiler.emit import decompile
from relic.loader import load

HERE = os.path.dirname(__file__)


def _analyze(path, on=True):
    an = Analysis(load(path))
    an.auto_names = on
    an.sig_paths = []
    return an.run()


def _named(an):
    return {an.name(a): an.auto_func_reasons[a] for a in an.auto_func_names}


@pytest.fixture(scope="module", params=["autonames_O0_stripped", "autonames_O2_stripped"])
def stripped(request):
    return request.param, _analyze(request.getfixturevalue(request.param))


def test_stripped_functions_are_named(stripped):
    variant, an = stripped
    named = _named(an)
    assert named.get("table_insert") == "assert() names it"            # the name the source gave it
    assert named.get("count_lines") == "its messages name it"          # "count_lines: cannot open %s"
    assert named.get("xmalloc") == "malloc() that dies on failure"
    assert named.get("usage") == 'prints "Usage:" and exits'
    assert named.get("fatal") == "prints a message and does not return"
    if variant.endswith("O2_stripped"):
        assert named.get("j_puts") == "a jump to puts"                  # `say` compiles to `jmp puts`
    assert all(not n.startswith("sub_") for n in named)


def test_names_reach_callers_and_listings(stripped):
    variant, an = stripped
    main = decompile(an, an.function_by_name("main")).text
    assert "usage(" in main and "fatal(" in main and "xmalloc(" in main and "count_lines(argv[1])" in main
    if variant.endswith("O0_stripped"):
        # (-O2 specialises the static xmalloc for its one caller: 400 is built in, no argument left)
        assert "xmalloc(400)" in main, main
    if variant.endswith("O2_stripped"):
        assert 'j_puts(' in main                # (a thunk takes its target's signature: one argument)


def test_assert_name_without_decompiling(autonames_O0_stripped, autonames_O2_stripped, monkeypatch):
    """x86-64 sets the assert's arguments in the call's own block: read there, not by decompiling
    the function (and every callee it reaches: half a minute on gdb)."""
    from relic.analysis import autoname

    def fail(an, f):
        raise AssertionError("decompiled")
    monkeypatch.setattr(autoname, "_assert_args_decompiled", fail)
    for path in (autonames_O0_stripped, autonames_O2_stripped):
        assert _named(_analyze(path)).get("table_insert") == "assert() names it"


def test_off_and_user_names_win(autonames_O0_stripped):
    an = _analyze(autonames_O0_stripped, on=False)
    assert not an.auto_func_names and not any(f.name == "xmalloc" for f in an.functions.values())
    an.set_auto_names(True)
    a = next(a for a, n in an.auto_func_names.items() if n == "xmalloc")
    an.rename(a, "alloc_or_die")
    assert an.name(a) == "alloc_or_die"
    an.set_auto_names(False)
    assert an.name(a) == "alloc_or_die" and an.name(an.function_by_name("main").addr) == "main"


def test_cli_flags_auto_names(autonames_O0_stripped):
    env = dict(os.environ, RELIC_AUTO_NAMES="1")
    run = lambda *a: subprocess.run([sys.executable, "-m", "relic", *a], capture_output=True, text=True, env=env,
                                    cwd=os.path.dirname(HERE)).stdout
    out = run("funcs", autonames_O0_stripped)
    assert re.search(r"table_insert \[auto: assert\(\) names it\]", out), out
    off = run("funcs", autonames_O0_stripped, "--no-auto-names")
    assert "table_insert" not in off and "sub_" in off


# ------------------------------------------------------------------ variables
def test_variables_are_named_by_their_use(autonames_O0_stripped):
    an = _analyze(autonames_O0_stripped)
    c = decompile(an, an.function_by_name("count_lines")).text
    assert c.startswith("int count_lines(char *path)"), c        # (-O0's copy of the parameter folded away)
    assert "fd = open(path, O_RDONLY);" in c, c
    assert "nread = read(fd, buf, 0x200);" in c, c
    assert re.search(r"for \(i = 0; i < nread; i\+\+\)", c), c
    assert "count++;" in c and "return result;" in c, c
    m = decompile(an, an.function_by_name("main")).text
    assert 'home = getenv("HOME");' in m, m
    assert re.search(r"for \(i = 0; i <= 9; i\+\+\)", m), m
    assert "lines = count_lines(argv[1]);" in m, m                 # the callee's name says what it returns
    t = decompile(an, next(f for f in an.functions.values() if not f.is_import and "strlen" in
                           {an.call_name(i) for b in f.blocks.values() for i in b.insns})).text
    assert re.search(r"total \+= strlen\(", t), t


def test_callee_verbs_are_words():
    """`get_config` / `readHeader` say what they return; `initialize_table` and `calculate_sum`
    do not start with `init` and `calc` as words of their own."""
    from relic.decompiler.varnames import _VERB
    rest = lambda name: name[m.end():] if (m := _VERB.match(name)) else None
    assert rest("get_config") == "config" and rest("readHeader") == "Header" and rest("calc_total") == "total"
    assert rest("calculate_sum") == "sum"
    assert rest("initialize_table") is None and rest("newton_step") is None and rest("copyright") is None


def test_variable_names_never_collide(autonames_O0_stripped):
    an = _analyze(autonames_O0_stripped)
    for f in an.functions.values():
        if f.is_import:
            continue
        d = decompile(an, f)
        lines = d.text.splitlines()
        k = max(i for i, ln in enumerate(lines) if ln == "{")      # (after any struct declarations)
        sig = lines[k - 1]
        head = "\n".join(lines[k + 1:]).split("\n\n", 1)[0]       # the declarations: up to a blank line
        decls = re.findall(r"^    [\w ]+?[\s*]+(\w+)(?:\[[^\]]*\])?;", head, re.M)
        params = re.findall(r"(\w+)(?=,|\))", sig[sig.index("("):])
        names = decls + [p for p in params if p != "void"]
        assert len(names) == len(set(names)), (an.name(f.addr), d.text)
        # every name shown maps back to the generated one renames are stored under
        assert all(g for g in d.variables.values())


def test_user_variable_names_win(autonames_O0_stripped):
    an = _analyze(autonames_O0_stripped)
    f = an.function_by_name("count_lines")
    d = decompile(an, f)
    gen = d.variables["fd"]                                    # shown -> generated (`var_1c`)
    an.rename_var(f.addr, gen, "handle")
    text = decompile(an, f).text
    assert "handle = open(path, O_RDONLY);" in text and " fd " not in text


def test_recompiled_with_suggested_names(tmp_path):
    """The floats sample's pseudocode, with suggested names, still compiles and computes the same
    bits (no name a suggestion takes shadows a function or another variable)."""
    sys.path.insert(0, HERE)
    import test_floats as T
    from conftest import _build
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler")
    an = _analyze(_build("floats_O0"))
    code = "\n\n".join(T._c(an, f) for f in T.FUNCS)
    ptrs = "\n".join(f"    __typeof__(ref_{f}) *volatile p_{f} = (__typeof__(ref_{f}) *)(void *){f};" for f in T.FUNCS)
    src = tmp_path / "re.c"
    src.write_text(T._HARNESS % {"code": code, "src": os.path.join(HERE, "src", "floats.c"), "ptrs": ptrs,
                                 "opt": "O0", "defines": "\n".join(f"#define {f} ref_{f}" for f in T.FUNCS),
                                 "undefs": "\n".join(f"#undef {f}" for f in T.FUNCS)})
    exe = tmp_path / "re"
    r = subprocess.run([cc, "-O1", "-w", "-fwrapv", "-ffp-contract=off", "-fno-builtin", "-o", str(exe), str(src),
                        "-lm"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[:2000] + code
    assert subprocess.run([str(exe)], capture_output=True, text=True).stdout.strip().endswith("ok")

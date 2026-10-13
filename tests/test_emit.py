"""Decompiler stage 5: C output.

Golden checks look for the key constructs (calls, conditions, loop shapes,
declarations) rather than whole-text equality, so formatting tweaks do not
break them. The recompilation test is the strongest one: the pseudocode for
`checksum` and `classify` is fed back to a C compiler and must compute the
same results as the original source.
"""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

VARIANTS = ["vuln64", "vuln64_pie"]


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.fixture(scope="module")
def ans(request):
    return {v: analyze(request.getfixturevalue(v)) for v in VARIANTS}


@pytest.mark.parametrize("variant,buf", [("vuln64", "char buf_48[64];"), ("vuln64_pie", "char buf_58[72];")])
def test_vuln(ans, variant, buf):
    code = _c(ans[variant], "vuln")
    assert code.startswith("void vuln(void)")
    assert buf in code                                   # buffer size and its distance to the return address
    name = buf.split()[1].split("[")[0]
    assert f"gets({name});" in code
    assert f"checksum({name})" in code                  # call result folded into the printf argument
    assert '"hello %s (%d)\\n"' in code
    assert "stack_chk_fail" not in code and "fs_base" not in code


def test_canary_is_reported_not_checked(ans):
    code = _c(ans["vuln64_pie"], "vuln")
    assert "// stack canary at ret-0x10" in code


@pytest.mark.parametrize("variant", VARIANTS)
def test_checksum(ans, variant):
    code = _c(ans[variant], "checksum")
    assert code.startswith("int checksum(char *a1)")
    assert "while (" in code and "> 100000" in code and "0x1337" in code
    assert "goto" not in code


@pytest.mark.parametrize("variant", VARIANTS)
def test_classify(ans, variant):
    code = _c(ans[variant], "classify")
    assert code.startswith("int classify(")
    assert "switch (" in code and "case 0:" in code and "case 5:" in code and "default:" in code
    assert "-1" in code and "0xffffffff" not in code
    assert "goto" not in code


@pytest.mark.parametrize("variant", VARIANTS)
def test_main(ans, variant):
    code = _c(ans[variant], "main")
    assert code.startswith("int main(int a1, ")
    assert "while (1) {" in code and "break;" in code
    assert "show_note(menu());" in code and "del_note(menu());" in code
    assert "setvbuf(stdout, 0, 2, 0);" in code
    assert "goto" not in code


def test_short_circuit_condition(ans):
    code = _c(ans["vuln64"], "show_note")
    assert "if (var_c >= 0 && var_c <= 15 && notes[var_c] != 0) {" in code


@pytest.mark.parametrize("variant", VARIANTS)
def test_short_strings_and_globals(ans, variant):
    code = _c(ans[variant], "menu")
    assert '"> "' in code and '"%d"' in code
    code = _c(ans[variant], "add_note")
    assert "notes[" in code and "malloc(16)" in code and 'puts("full")' in code


@pytest.mark.parametrize("variant", VARIANTS)
def test_every_function_decompiles(ans, variant):
    an = ans[variant]
    for f in an.functions.values():
        if f.is_import:
            continue
        d = decompile(an, f)
        text = d.text
        assert "phi(" not in text, f.name
        if not f.name.startswith("_"):                   # _start really does use the stack pointer
            assert "rsp" not in text, f.name
        assert text.count("{") == text.count("}"), f.name
        lo, hi = min(f.blocks), max(b.end for b in f.blocks.values())
        assert all(ln.addr is None or lo <= ln.addr < hi for ln in d.lines), f.name


def test_stripped_binary(vuln64_stripped):
    an = analyze(vuln64_stripped)
    for f in an.functions.values():
        if not f.is_import:
            decompile(an, f)
    main = an.function_by_name("main")
    assert "while (1) {" in decompile(an, main).text


def test_line_address_mapping(ans):
    an = ans["vuln64"]
    f = an.function_by_name("vuln")
    d = decompile(an, f)
    k = next(i for i, ln in enumerate(d.lines) if "gets(" in ln.text)
    addr = d.lines[k].addr
    assert an.function_at(addr) is f
    assert k in d.lines_at(addr)


# ------------------------------------------------------------ recompilation
_HARNESS = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

%(code)s

static int ref_checksum(const char *s) {
    int h = 0;
    for (int i = 0; s[i]; i++) {
        h = h * 31 + s[i];
        if (h > 100000)
            h ^= 0x1337;
    }
    return h;
}

static int ref_classify(int x) {
    switch (x) {
    case 0: return 10; case 1: return 22; case 2: return 37;
    case 3: return 41; case 4: return 59; case 5: return 63;
    default: return -1;
    }
}

int main(void) {
    const char *inputs[] = {"", "a", "hello", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "\x7f\x80\xff zz", "pwn!"};
    for (unsigned k = 0; k < sizeof inputs / sizeof *inputs; k++)
        if (checksum((char *)inputs[k]) != ref_checksum(inputs[k])) { printf("checksum %%u\n", k); return 1; }
    for (int x = -5; x < 12; x++)
        if (classify(x) != ref_classify(x)) { printf("classify %%d\n", x); return 1; }
    puts("ok");
    return 0;
}
"""


@pytest.mark.parametrize("variant", VARIANTS)
def test_recompiled_pseudocode_matches_source(ans, variant, tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    an = ans[variant]
    code = "\n\n".join(_c(an, n) for n in ("checksum", "classify"))
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"code": code})
    exe = tmp_path / "re"
    r = subprocess.run([cc, "-w", "-fwrapv", "-o", str(exe), str(src)], capture_output=True, text=True)
    assert r.returncode == 0, f"pseudocode does not compile:\n{r.stderr}\n{code}"
    r = subprocess.run([str(exe)], capture_output=True, text=True)
    assert r.stdout.strip() == "ok", f"{r.stdout}\n{code}"

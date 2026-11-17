"""Structs passed and returned by value (relic.decompiler.aggabi, x86-64 System V): with the
prototypes from a header, a function takes `struct pt a1` and reads `a1.x`; it returns
`(struct pt){ ... }`, or through the hidden result pointer; its callers pass compound literals
and local structs and read the result's fields. Checked by recompiling the pseudocode."""
import os
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

HERE = os.path.dirname(__file__)
SRC, HDR = (os.path.join(HERE, "src", n) for n in ("structval.c", "structval.h"))
FUNCS = ["add", "norm", "scale", "make", "total", "late", "build", "fill", "main"]


@pytest.fixture(scope="module", params=["O0", "O1", "O2"])
def built(request, tmp_path_factory):
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    d = tmp_path_factory.mktemp("structval")
    exe = str(d / f"sv_{request.param}")
    try:
        subprocess.run(["gcc", f"-{request.param}", "-fno-inline", "-fno-tree-vectorize", "-o", exe, SRC],
                       check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        pytest.skip(f"gcc cannot build it here: {e.stderr[-200:]!r}")
    an = analyze(exe)
    if an.bin.arch != "x64":
        pytest.skip("x86-64 only")
    with open(HDR) as fp:
        an.import_header(fp.read())
    return exe, an, {f: decompile(an, an.function_by_name(f)).text for f in FUNCS}


def test_signatures(built):
    _, _, code = built
    first = {f: code[f].splitlines()[0] for f in FUNCS if f != "main"}
    # (a struct the code makes a pointer to is declared above the function first)
    sig = {f: next(ln for ln in code[f].splitlines() if f + "(" in ln) for f in first}
    assert sig["add"] == "struct pt add(struct pt a1, struct pt a2)"
    assert sig["norm"] == "double norm(struct fpt a1)"
    assert sig["scale"] == "double scale(struct mix a1, int a2)"
    assert sig["make"] == "struct big make(long a1)"
    assert sig["total"] == "long total(struct big a1)"
    assert sig["late"] == "long late(long a1, long a2, long a3, long a4, long a5, struct q a6, struct q a7)"
    assert sig["build"] == "struct wide build(struct q a1, struct dq a2)"
    assert sig["fill"] == "struct five fill(int a1, struct five a2)"
    assert "a1.x" in code["add"] and "return (struct pt){" in code["add"]
    assert "a1.tag" in code["scale"] and "a1.v" in code["scale"]
    assert "return *result;" in code["make"]


def test_callers(built):
    _, _, code = built
    main = code["main"]
    assert re.search(r"r1 = add\(\(struct pt\)\{ .*\}, \(struct pt\)\{ .*\}\);", main), main
    assert re.search(r"\w+ = make\(", main) and "r1.x" in main and "r1.y" in main
    assert "(struct mix){" in main and "(struct fpt){" in main
    assert re.search(r"late\(1, 2, 3, 4, 5, ", main)


def test_recompiled_pseudocode_runs_like_the_program(built, tmp_path):
    exe, an, code = built
    with open(HDR) as fp:
        header = fp.read()
    body = []
    for f in FUNCS:
        # (the header declares the structs: drop the copies the pseudocode shows above a function)
        body.append(re.sub(r"(?ms)^struct \w+ \{.*?^\};\n\n?", "", code[f]))
    src = tmp_path / "re.c"
    src.write_text("#include <stdio.h>\n#include <stdint.h>\nextern int __printf_chk(int, const char *, ...);\n"
                   + header + "\n" + "\n".join(body))
    out = str(tmp_path / "re")
    r = subprocess.run(["gcc", "-w", "-o", out, str(src)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + src.read_text()
    for args in ([], ["x"], ["x", "y", "z", "w"]):
        want = subprocess.run([exe, *args], capture_output=True, text=True).stdout
        got = subprocess.run([out, *args], capture_output=True, text=True).stdout
        assert got == want, src.read_text()


def test_fields_sharing_a_register_keep_the_usual_parameters(tmp_path):
    """`struct pair { int a, b; }` travels in one register: not shown as a struct yet (its halves
    are spilled and read back separately at -O0, shifted apart at -O2), and its prototype puts no
    struct type on that register -- the pseudocode stays what it was, and consistent."""
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    src = tmp_path / "p.c"
    src.write_text("struct pair { int a; int b; };\n"
                   "__attribute__((noinline)) struct pair swap(struct pair p)\n"
                   "{ struct pair r = { p.b, p.a }; return r; }\n"
                   "int main(int c, char **v) { return swap((struct pair){ c, 7 }).a; }\n")
    exe = str(tmp_path / "p")
    subprocess.run(["gcc", "-O0", "-o", exe, str(src)], check=True)
    an = analyze(exe)
    an.import_header("struct pair { int a; int b; };\nstruct pair swap(struct pair p);\n")
    code = decompile(an, an.function_by_name("swap")).text
    assert "struct pair a1" not in code and not code.startswith("struct pair swap"), code
    assert "no struct pair to apply" not in code


def test_classify():
    """System V classes: two INTEGER eightbytes, two SSE, one of each; more than 16 bytes and
    floats packed in one register are not passed as parts."""
    from relic.decompiler.aggabi import _Struct, classify, packed
    assert classify(_Struct("pt", 16, 8, [(0, 8, "long", "x"), (8, 8, "long", "y")])) == \
        [("INTEGER", 0), ("INTEGER", 8)]
    assert classify(_Struct("mix", 16, 8, [(0, 4, "", "tag"), (8, 8, "double", "v")])) == \
        [("INTEGER", 0), ("SSE", 8)]
    assert classify(_Struct("big", 24, 8, [(0, 8, "long", "a"), (8, 8, "long", "b"), (16, 8, "long", "c")])) is None
    ff = _Struct("ff", 8, 4, [(0, 4, "float", "u"), (4, 4, "float", "v")])
    assert classify(ff) is None and packed(ff)
    assert packed(_Struct("pair", 8, 4, [(0, 4, "", "a"), (4, 4, "", "b")]))

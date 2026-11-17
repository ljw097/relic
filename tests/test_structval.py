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


@pytest.mark.parametrize("opt", ["O0", "O1", "O2"])
def test_fields_sharing_a_register(opt, tmp_path):
    """`struct pair { int a, b; }` travels in one register (`tri`'s first two ints too, `name`'s
    eight chars): its fields are that register's bits -- read back as `a1.b`, built as
    `(struct pair){ a1.b, a1.a + 1 }` -- and the pseudocode compiled again runs like the program."""
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    src, hdr = (os.path.join(HERE, "src", n) for n in ("structval_packed.c", "structval_packed.h"))
    exe = str(tmp_path / "p")
    subprocess.run(["gcc", f"-{opt}", "-fno-inline", "-fno-tree-vectorize", "-o", exe, src], check=True)
    an = analyze(exe)
    with open(hdr) as fp:
        header = fp.read()
    an.import_header(header)
    funcs = ["swap", "tsum", "first", "mk", "main"]
    code = {f: decompile(an, an.function_by_name(f)).text for f in funcs}
    assert code["swap"].splitlines()[0] == "struct pair swap(struct pair a1)"
    if opt != "O0":
        assert "return (struct pair){ a1.b, a1.a + 1 };" in code["swap"], code["swap"]
        assert "a1.x" in code["tsum"] and "a1.y" in code["tsum"] and "a1.z" in code["tsum"], code["tsum"]
    body = [re.sub(r"(?ms)^struct \w+ \{.*?^\};\n\n?", "", code[f]) for f in funcs]
    re_c = tmp_path / "re.c"
    re_c.write_text("#include <stdio.h>\n#include <stdint.h>\nextern int __printf_chk(int, const char *, ...);\n"
                    + header + "\n" + "\n".join(body))
    out = str(tmp_path / "re")
    r = subprocess.run(["gcc", "-w", "-o", out, str(re_c)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + re_c.read_text()
    for args in ([], ["x", "y", "z"]):
        want = subprocess.run([exe, *args], capture_output=True, text=True).stdout
        assert subprocess.run([out, *args], capture_output=True, text=True).stdout == want and want, re_c.read_text()


FUNCS2 = ["v2add", "v2dot", "v3cross", "v3scale", "span_from", "span_skip", "span_count", "parse", "rgba_sum", "main"]


@pytest.mark.parametrize("opt", ["O0", "O1", "O2"])
def test_everyday_program_recompiles(opt, tmp_path):
    """Vector math (two doubles in SSE registers, three in memory), a `const char *` + length
    span, a result with a flag, and a struct of four chars (shown the usual way): the pseudocode,
    compiled again, prints what the program prints."""
    src2, hdr2 = (os.path.join(HERE, "src", n) for n in ("structval2.c", "structval2.h"))
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    exe = str(tmp_path / "v")
    subprocess.run(["gcc", f"-{opt}", "-fno-inline", "-fno-tree-vectorize", "-o", exe, src2], check=True,
                   capture_output=True)
    an = analyze(exe)
    with open(hdr2) as fp:
        header = fp.read()
    an.import_header(header)
    body = [re.sub(r"(?ms)^struct \w+ \{.*?^\};\n\n?", "", decompile(an, an.function_by_name(f)).text)
            for f in FUNCS2]
    src = tmp_path / "re.c"
    src.write_text("#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n"
                   "extern int __printf_chk(int, const char *, ...);\n" + header + "\n" + "\n".join(body))
    out = str(tmp_path / "re")
    r = subprocess.run(["gcc", "-w", "-o", out, str(src)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + src.read_text()
    for args in ([], ["77,1,,2"], ["x", "9"]):
        want = subprocess.run([exe, *args], capture_output=True, text=True).stdout
        got = subprocess.run([out, *args], capture_output=True, text=True).stdout
        assert got == want, src.read_text()


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
    # two ints in one register: passed as that register's bits, shown as the struct
    assert not packed(_Struct("pair", 8, 4, [(0, 4, "", "a"), (4, 4, "", "b")]))


def _gcc(tmp_path, src: str, opt: str = "-O0") -> str:
    if shutil.which("gcc") is None:
        pytest.skip("no gcc")
    (tmp_path / "t.c").write_text(src)
    exe = str(tmp_path / "t")
    subprocess.run(["gcc", opt, "-w", "-o", exe, str(tmp_path / "t.c")], check=True)
    return exe


def test_header_types_decide_pointer_and_index(tmp_path):
    """`p[i]` at -O0 is `p + i` of two 64-bit values: the prototype's `const char *p` says which is
    the pointer (inference alone took the index for it: `count[a1]`), and the signature keeps
    the header's `const`."""
    exe = _gcc(tmp_path, "#include <stddef.h>\n__attribute__((noinline)) size_t cnt(const char *p, size_t n, char c)\n"
                         "{ size_t k = 0; for (size_t i = 0; i < n; i++) k += p[i] == c; return k; }\n"
                         "int main(int a, char **v) { return cnt(v[0], 3, 'x'); }\n")
    an = analyze(exe)
    an.import_header("#include <stddef.h>\nsize_t cnt(const char *p, size_t n, char c);\n")
    code = decompile(an, an.function_by_name("cnt")).text
    assert code.splitlines()[0] == "size_t cnt(const char *a1, size_t a2, char a3)", code
    assert re.search(r"a1\[\w+\]", code) and not re.search(r"\w+\[a1\]", code), code


def test_a_register_read_back_a_byte_at_a_time_is_one_variable(tmp_path):
    """-O0 spills a 4-byte struct (in edi) whole and reads its bytes back one at a time: those
    are bytes of that one slot, not variables of their own (which nothing writes)."""
    src = ("#include <stdio.h>\nstruct rgba { unsigned char r, g, b, a; };\n"
           "__attribute__((noinline)) unsigned sum(struct rgba c) { return c.r + c.g * 3 + c.b * 5 + c.a * 7; }\n"
           "int main(int n, char **v) { struct rgba c = { 1, 2, (unsigned char)n, 4 };"
           " printf(\"%u\\n\", sum(c)); return 0; }\n")
    exe = _gcc(tmp_path, src)
    an = analyze(exe)
    code = decompile(an, an.function_by_name("sum")).text
    assert "char var_" not in code, code              # (no byte variables beside the spilled word)
    want = subprocess.run([exe, "x", "y"], capture_output=True, text=True).stdout
    re_c = tmp_path / "re.c"
    re_c.write_text("#include <stdio.h>\n#include <stdint.h>\n" + code + "\n"
                    "int main(int n, char **v) { printf(\"%u\\n\", sum(1 | 2 << 8 | n << 16 | 4 << 24)); }\n")
    subprocess.run(["gcc", "-w", "-o", str(tmp_path / "re"), str(re_c)], check=True)
    assert subprocess.run([str(tmp_path / "re"), "x", "y"], capture_output=True, text=True).stdout == want


def test_other_abis_get_no_misplaced_types(tmp_path):
    """Win64 (MinGW): structs by value are not shown there yet, and the prototype must not type
    the registers by position either -- `make`'s first register is its hidden result pointer,
    not `long n`."""
    cc = shutil.which("x86_64-w64-mingw32-gcc")
    if cc is None:
        pytest.skip("needs x86_64-w64-mingw32-gcc")
    exe = str(tmp_path / "sv.exe")
    subprocess.run([cc, "-O1", "-o", exe, SRC], check=True)
    an = analyze(exe)
    with open(HDR) as fp:
        an.import_header(fp.read())
    code = decompile(an, an.function_by_name("make")).text
    sig = next(ln for ln in code.splitlines() if "make(" in ln)
    assert "long a1" not in sig and "struct big" not in sig, code
    assert "no struct" not in decompile(an, an.function_by_name("add")).text


@pytest.mark.parametrize("opt", ["O0", "O1", "O2"])
def test_cross_aarch64_fields_sharing_a_register(opt, tmp_path):
    """AArch64: `struct pair` in one x register (gcc packs it with `bfi`, takes it apart with
    `lsr` / `asr`): read and built as fields, and the pseudocode runs like the program."""
    cc, qemu = shutil.which("aarch64-linux-gnu-gcc"), shutil.which("qemu-aarch64")
    if cc is None or qemu is None or not os.path.isdir("/usr/aarch64-linux-gnu"):
        pytest.skip("needs aarch64-linux-gnu-gcc and qemu-aarch64")
    src, hdr = (os.path.join(HERE, "src", n) for n in ("structval_packed.c", "structval_packed.h"))
    exe = str(tmp_path / "p")
    subprocess.run([cc, f"-{opt}", "-fno-inline", "-fno-tree-vectorize", "-o", exe, src], check=True)
    an = analyze(exe)
    with open(hdr) as fp:
        header = fp.read()
    an.import_header(header)
    funcs = ["swap", "tsum", "first", "mk", "main"]
    code = {f: decompile(an, an.function_by_name(f)).text for f in funcs}
    assert code["swap"].splitlines()[0] == "struct pair swap(struct pair a1)"
    if opt != "O0":
        assert "a1.b" in code["swap"] and "a1.y" in code["tsum"], code
    body = [re.sub(r"(?ms)^struct \w+ \{.*?^\};\n\n?", "", code[f]) for f in funcs]
    re_c = tmp_path / "re.c"
    re_c.write_text("#include <stdio.h>\n#include <stdint.h>\nextern int __printf_chk(int, const char *, ...);\n"
                    + header + "\n" + "\n".join(body))
    out = str(tmp_path / "re")
    r = subprocess.run([cc, "-w", "-o", out, str(re_c)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + re_c.read_text()
    run = [qemu, "-L", "/usr/aarch64-linux-gnu"]
    for args in ([], ["x", "y"]):
        want = subprocess.run([*run, exe, *args], capture_output=True, text=True).stdout
        assert subprocess.run([*run, out, *args], capture_output=True, text=True).stdout == want and want


@pytest.mark.parametrize("opt", ["O0", "O1", "O2"])
def test_cross_aarch64_recompiles(opt, tmp_path):
    """AAPCS64: two-register structs in x0..x7, an HFA of doubles in v0.., a struct over 16 bytes
    by reference (the callee reads it through the pointer: `a1.b`), a big result through x8 --
    the pseudocode, built again for AArch64 and run under qemu, prints what the program prints."""
    cc, qemu = shutil.which("aarch64-linux-gnu-gcc"), shutil.which("qemu-aarch64")
    if cc is None or qemu is None or not os.path.isdir("/usr/aarch64-linux-gnu"):
        pytest.skip("needs aarch64-linux-gnu-gcc and qemu-aarch64")
    src, hdr = (os.path.join(HERE, "src", n) for n in ("structval_a64.c", "structval_a64.h"))
    exe = str(tmp_path / "a")
    subprocess.run([cc, f"-{opt}", "-fno-inline", "-fno-tree-vectorize", "-o", exe, src], check=True)
    an = analyze(exe)
    with open(hdr) as fp:
        header = fp.read()
    an.import_header(header)
    funcs = ["add", "norm", "make", "total", "fill", "main"]
    code = {f: decompile(an, an.function_by_name(f)).text for f in funcs}
    assert next(ln for ln in code["total"].splitlines() if "total(" in ln) == "long total(struct big a1)"
    assert "a1.b" in code["total"] and "return *result;" in code["make"], code
    assert re.search(r"\w+ = make\(", code["main"]), code["main"]
    body = [re.sub(r"(?ms)^struct \w+ \{.*?^\};\n\n?", "", code[f]) for f in funcs]
    re_c = tmp_path / "re.c"
    re_c.write_text("#include <stdio.h>\n#include <stdint.h>\n#include <math.h>\n"
                    "extern int __printf_chk(int, const char *, ...);\n" + header + "\n" + "\n".join(body))
    out = str(tmp_path / "re")
    r = subprocess.run([cc, "-w", "-o", out, str(re_c), "-lm"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + re_c.read_text()
    run = [qemu, "-L", "/usr/aarch64-linux-gnu"]
    for args in ([], ["x", "y"]):
        want = subprocess.run([*run, exe, *args], capture_output=True, text=True).stdout
        got = subprocess.run([*run, out, *args], capture_output=True, text=True).stdout
        assert got == want and want, re_c.read_text()

"""Type libraries (decompiler.typelibs) and type propagation through calls: prototypes'
struct types for results and stack structs, user-typed functions for their callers."""
import os
import shutil
import subprocess
import sys

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

SRC = r"""
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#define NI __attribute__((noinline))
NI long fsize(const char *p) { struct stat st; if (stat(p, &st)) return -1; return st.st_size; }
NI int year(void) { time_t t = time(0); struct tm *tm = localtime(&t); return tm->tm_year + 1900 + tm->tm_mon; }
NI long parse(long ctx, long n) { return *(unsigned char *)(ctx + n); }
NI long use(long x, long y) { long p = x + 16; long r = parse(p, y * 2); return r + 1; }
int main(int c, char **v) { printf("%ld %d %ld\n", fsize(v[0]), year(), use((long)v[0], c)); return 0; }
"""


@pytest.fixture(scope="module", params=["O0", "O2"])
def built(request, tmp_path_factory):
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("needs gcc")
    d = tmp_path_factory.mktemp("typelibs")
    (d / "t.c").write_text(SRC)
    exe = d / f"t_{request.param}"
    subprocess.run([cc, f"-{request.param}", "-fno-inline", "-o", str(exe), str(d / "t.c")], check=True)
    return str(exe)


def _c(an, name):
    t = decompile(an, an.function_by_name(name)).text
    return t[t.index(f"{name}("):]


def test_libc_layout_follows_the_abi(vuln64):
    an = analyze(vuln64)
    got = an.load_type_library("libc")
    assert {"stat", "tm", "timeval", "sockaddr_in", "dirent"} <= set(got["structs"])
    st = an.struct_names["stat"]
    assert st["layout"]["0x30"] == [64, "long"] and st["fields"]["f_30"] == "st_size"   # x86-64
    with pytest.raises(KeyError):
        an.load_type_library("win32")
    an.undo()                                              # one undo step
    assert "stat" not in an.struct_names


def test_struct_results_and_stack_structs(built):
    an = analyze(built)
    assert "tm_year" not in _c(an, "year")
    an.load_type_library("libc")
    code = _c(an, "year")
    assert "struct tm *" in code and "->tm_year" in code and "->tm_mon" in code, code
    code = _c(an, "fsize")
    assert "struct stat buf_" in code and "stat(" in code and ", &buf_" in code and ".st_size" in code, code


def test_user_types_reach_callers(built):
    an = analyze(built)
    p = an.function_by_name("parse")
    an.set_var_type(p.addr, "a1", "char *")
    code = _c(an, "use")
    if "var_" in code:                                     # -O0: the argument's variable
        assert "char *var_" in code, code
    assert "parse(" in code


def test_cli(vuln64, tmp_path):
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    r = subprocess.run([sys.executable, "-m", "relic", "types", str(path), "--lib", "libc"], capture_output=True,
                       text=True, cwd=os.path.join(os.path.dirname(__file__), ".."))
    assert r.returncode == 0 and "libc:" in r.stdout and "stat" in r.stdout
    assert "stat" in analyze(str(path)).struct_names

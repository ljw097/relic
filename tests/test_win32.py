"""The Windows API type library (decompiler.win32_h, typelibs `win32`): its struct layouts match
<windows.h> on 32- and 64-bit Windows, its prototypes give calls their arguments (Win64's past
the fourth on the stack too) and types, and stack structs passed to them read as fields."""
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.decompiler.sigs import lookup

SRC = r"""
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("page %lu cpus %lu\n", si.dwPageSize, si.dwNumberOfProcessors);
    char *p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return 1;
    HANDLE h = CreateFileA(argc > 1 ? argv[1] : "file.txt", GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { printf("err %lu\n", GetLastError()); return 2; }
    DWORD got = 0;
    ReadFile(h, p, 4095, &got, NULL);
    CloseHandle(h);
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("read %lu year>2000 %d\n", got, st.wYear > 2000);
    VirtualFree(p, 0, MEM_RELEASE);
    return 0;
}
"""

COMPILERS = {"w64": "x86_64-w64-mingw32-gcc", "w32": "i686-w64-mingw32-gcc"}


@pytest.fixture(scope="module", params=sorted(COMPILERS))
def built(request, tmp_path_factory):
    cc = shutil.which(COMPILERS[request.param])
    if cc is None:
        pytest.skip(f"needs {COMPILERS[request.param]}")
    d = tmp_path_factory.mktemp("win32")
    (d / "w.c").write_text(SRC)
    exe = d / f"{request.param}.exe"
    subprocess.run([cc, "-O2", "-o", str(exe), str(d / "w.c")], check=True)
    return cc, str(exe)


def _main(an):
    t = decompile(an, an.function_by_name("main")).text
    return t[t.index("main("):]


def test_layouts_match_windows_h(built, tmp_path):
    """Every struct of the library, laid out for the binary, has <windows.h>'s size and field
    offsets (the library's tags are <windows.h>'s typedef names; checked by the compiler: one
    static assertion per field)."""
    cc, exe = built
    an = analyze(exe)
    got = an.load_type_library()
    assert "SYSTEM_INFO" in got["structs"] and "STARTUPINFOA" in got["structs"]
    lines = ["#include <windows.h>", "#include <tlhelp32.h>", "#include <stddef.h>"]
    for name in got["structs"]:
        entry = an.struct_names[name]
        size = int(re.search(r"(\d+) bytes", entry["decl"][0]).group(1))
        lines.append(f'_Static_assert(sizeof({name}) == {size}, "{name} size");')
        fields = entry.get("fields") or entry["as_imported"]["fields"]
        for gen, field in fields.items():
            off = int(gen[2:], 16)
            lines.append(f'_Static_assert(offsetof({name}, {field}) == {off}, "{name}.{field}");')
    (tmp_path / "check.c").write_text("\n".join(lines) + "\n")
    r = subprocess.run([cc, "-fsyntax-only", str(tmp_path / "check.c")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_prototypes_without_importing_anything(built):
    """Calls to the Windows API get their arguments from the bundled prototypes: all seven of
    CreateFileA's (Win64 passes the last three on the stack), and pointer results."""
    _, exe = built
    an = analyze(exe)
    c = _main(an)
    assert "CreateFileA(" in c and ", 0x80000000, 1, 0, 3, 128, 0)" in c
    assert re.search(r"ReadFile\(\w+, \w+, 0xfff, &\w+, 0\)", c)
    assert "VirtualAlloc(0, 0x1000, 0x3000, 4)" in c and "VirtualFree(" in c
    assert re.search(r"void \*\w+;", c)            # the HANDLE / LPVOID results
    s = lookup("CreateWindowExA")
    assert s.argc == 12 and s.types[1] == "char *"
    assert lookup("wsprintfA").fmt == 1


def test_stack_structs_read_as_fields(built):
    """With the library imported, the structs GetSystemInfo / GetLocalTime fill are declared on
    the stack and read field by field, the first field included."""
    _, exe = built
    an = analyze(exe)
    an.load_type_library("win32")
    c = _main(an)
    assert re.search(r"struct SYSTEM_INFO (\w+);", c) and re.search(r"struct SYSTEMTIME (\w+);", c)
    si = re.search(r"struct SYSTEM_INFO (\w+);", c).group(1)
    st = re.search(r"struct SYSTEMTIME (\w+);", c).group(1)
    assert f"GetSystemInfo(&{si})" in c
    assert f"{si}.dwPageSize, {si}.dwNumberOfProcessors" in c
    assert f"{st}.wYear" in c


def test_default_library_follows_the_format(built):
    from relic.decompiler.typelibs import default_library
    _, exe = built
    an = analyze(exe)
    assert default_library(an.bin.format) == "win32" and default_library("ELF") == "libc"
    assert "STARTUPINFOA" in an.load_type_library()["structs"]
    with pytest.raises(KeyError):
        an.load_type_library("nope")

"""What built a binary (analysis.ident), and choosing / building library signature sets by it
(libsigs.select, system_libraries, build_system)."""
import os
import shutil
import struct
import subprocess

import pytest

from relic.analysis import analyze, libsigs
from relic.analysis.ident import Toolchain, identify, rich_header
from relic.loader import load

C_SRC = '#include <stdio.h>\nint main(int c, char **v) { printf("%d\\n", c); return 0; }\n'
CXX_SRC = '#include <string>\n#include <cstdio>\nint main(int c, char **v) { std::string s(v[0]); ' \
          'std::printf("%zu\\n", s.size() + c); return 0; }\n'


def _build(tmp_path, cc, src, name, *flags, ext="c"):
    if shutil.which(cc) is None:
        pytest.skip(f"needs {cc}")
    f = tmp_path / f"{name}.{ext}"
    f.write_text(src)
    out = tmp_path / name
    r = subprocess.run([cc, *flags, "-o", str(out), str(f)], capture_output=True)
    if r.returncode:
        pytest.skip(f"{cc} cannot build here: {r.stderr.decode()[:200]}")
    return str(out)


def test_gcc_dynamic(tmp_path):
    tc = identify(load(_build(tmp_path, "gcc", C_SRC, "c", "-O2")))
    assert tc.compiler.startswith("GCC ") and tc.libc.startswith("glibc 2.") and tc.linking == "dynamic"
    assert tc.libc_family == "glibc" and tc.libc_version.startswith("2.") and tc.languages == ["C"]
    assert any("GLIBC_" in e for e in tc.evidence)


def test_gcc_static_and_cxx(tmp_path):
    tc = identify(load(_build(tmp_path, "gcc", C_SRC, "cs", "-O2", "-static")))
    assert tc.libc == "glibc" and tc.linking == "static" and tc.libc_version is None
    tc = identify(load(_build(tmp_path, "g++", CXX_SRC, "cxx", "-O2", ext="cpp")))
    assert "C++" in tc.languages and tc.compiler.startswith("GCC ")


def test_clang(tmp_path):
    tc = identify(load(_build(tmp_path, "clang", C_SRC, "cl", "-O2")))
    assert tc.compiler.startswith("clang ") and tc.libc.startswith("glibc")


def test_go(tmp_path):
    if shutil.which("go") is None:
        pytest.skip("needs go")
    (tmp_path / "m.go").write_text('package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }\n')
    out = tmp_path / "gobin"
    env = dict(os.environ, GOCACHE=str(tmp_path / "cache"), GOPATH=str(tmp_path / "gopath"), GO111MODULE="off")
    r = subprocess.run(["go", "build", "-o", str(out), str(tmp_path / "m.go")], capture_output=True, env=env)
    if r.returncode:
        pytest.skip(f"go cannot build here: {r.stderr.decode()[:200]}")
    tc = identify(load(str(out)))
    assert "Go" in tc.languages and tc.compiler.startswith("Go 1.")


def test_rust(tmp_path):
    if shutil.which("rustc") is None:
        pytest.skip("needs rustc")
    tc = identify(load(_build(tmp_path, "rustc", 'fn main() { println!("hi"); }\n', "rs", "-O", ext="rs")))
    assert "Rust" in tc.languages and tc.compiler.startswith("rustc ")


def test_mingw(tmp_path):
    tc = identify(load(_build(tmp_path, "x86_64-w64-mingw32-gcc", C_SRC, "w.exe", "-O2")))
    assert tc.compiler.startswith("MinGW GCC") and tc.libc == "msvcrt" and tc.linking == "dynamic"


def test_musl_interpreter(vuln64):
    b = load(vuln64)
    b.interp = "/lib/ld-musl-x86_64.so.1"
    assert identify(b).libc == "musl"


def _rich(entries, key=0x1234ABCD):
    """A PE file's start with a Rich header holding these (product id, build, count)."""
    words = [0x536E6144 ^ key, key, key, key]               # "DanS" and three padding words
    for prod, build, count in entries:
        words += [((prod << 16) | build) ^ key, count ^ key]
    body = struct.pack(f"<{len(words)}I", *words) + b"Rich" + struct.pack("<I", key)
    data = bytearray(b"MZ" + b"\0" * 0x7E) + body
    pe_off = len(data) + 8
    struct.pack_into("<I", data, 0x3C, pe_off)
    return bytes(data) + b"\0" * 8 + b"PE\0\0"


def test_rich_header_names_visual_studio():
    from relic.analysis.ident import _msvc
    data = _rich([(0x0104, 33140, 12), (0x0105, 33140, 3), (0x00FF, 33140, 1)])
    assert rich_header(data) == [(0x0104, 33140, 12), (0x0105, 33140, 3), (0x00FF, 33140, 1)]
    assert _msvc(rich_header(data)) == "MSVC (Visual Studio 2022, build 33140)"
    assert _msvc([(0x0083, 30729, 4)]) == "MSVC (Visual Studio 2008, build 30729)"
    assert _msvc([(0x0104, 24215, 1)]).startswith("MSVC (Visual Studio 2015")
    assert rich_header(b"MZ" + b"\0" * 0x100) is None


def test_analysis_and_cli_show_the_toolchain(vuln64, capsys):
    from relic.__main__ import main
    an = analyze(vuln64)
    assert an.toolchain.compiler.startswith("GCC ") and an.toolchain.to_json()["libc"].startswith("glibc")
    main(["info", vuln64])
    out = capsys.readouterr().out
    assert "Compiler:  GCC " in out and "C library: glibc" in out and "Languages: C" in out


# ------------------------------------------------------------ signature sets
def _db(library, version="", fmt="ELF", arch="x64"):
    return libsigs.SigDB(arch, [], f"{library}.a", library=library, version=version, format=fmt)


def test_select_follows_the_toolchain():
    sets = [_db("glibc", "2.35"), _db("glibc", "2.39"), _db("libm", "2.39"), _db("musl"),
            _db("libstdc++", "13"), _db("libstdc++", "12"), _db("mingwex", fmt="PE"), _db("")]
    pick = lambda tc, fmt="ELF": sorted((d.library, d.version) for d in libsigs.select(sets, tc, fmt))  # noqa: E731
    assert pick(Toolchain(libc="glibc 2.35")) == [("", ""), ("glibc", "2.35"), ("libm", "2.39"), ("libstdc++", "13")]
    assert ("glibc", "2.39") in pick(Toolchain(libc="glibc"))                       # (static: no version: newest)
    musl = pick(Toolchain(libc="musl"))
    assert ("musl", "") in musl and not any(lib in ("glibc", "libm") for lib, _ in musl)
    assert pick(Toolchain(libc="msvcrt"), "PE") == [("mingwex", "")]                 # (ELF sets: not for a PE)
    assert len(libsigs.select(sets, None, "RAW")) == 6                               # (any format in a raw image)


def test_available_leaves_out_sets_for_other_binaries(tmp_path, monkeypatch):
    for db in (_db("glibc", "2.35"), _db("glibc", "2.39"), _db("glibc", "2.39", arch="arm64")):
        db.save(str(tmp_path / libsigs.set_name(db)))
    monkeypatch.setattr(libsigs, "sig_dirs", lambda: [str(tmp_path)])
    assert sorted(os.listdir(tmp_path)) == ["glibc-2.35-x64.sig", "glibc-2.39-arm64.sig", "glibc-2.39-x64.sig"]
    got = libsigs.available("x64", None, Toolchain(libc="glibc 2.35"), "ELF")
    assert [(d.version, d.arch) for d in got] == [("2.35", "x64")]
    assert libsigs.available("x64", None, Toolchain(libc="glibc"), "PE") == []
    explicit = [str(tmp_path / "glibc-2.35-x64.sig"), str(tmp_path / "glibc-2.39-x64.sig")]
    assert len(libsigs.available("x64", explicit, Toolchain(libc="musl"), "PE")) == 2     # (asked for: all)


def test_library_of_and_ld_scripts(tmp_path):
    assert libsigs.library_of(["/usr/lib/gcc/x86_64-linux-gnu/13/libstdc++.a"], b"") == ("libstdc++", "13")
    assert libsigs.library_of(["/usr/lib/gcc-cross/mipsel-linux-gnu/12/libgcc_eh.a"], b"") == ("libgcc", "12")
    banner = b"GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8) stable release version 2.39.\n"
    assert libsigs.library_of(["/x/libc.a"], banner) == ("glibc", "2.39")
    assert libsigs.library_of(["/x/libfoo.a"], b"") == ("libfoo", "")
    (tmp_path / "libm-2.39.a").write_bytes(b"!<arch>\n")
    (tmp_path / "libmvec.a").write_bytes(b"!<arch>\n")
    (tmp_path / "libm.a").write_text(f"/* GNU ld script\n*/\nOUTPUT_FORMAT(elf64-x86-64)\n"
                                     f"GROUP ( {tmp_path}/libm-2.39.a libmvec.a AS_NEEDED ( -lfoo ) )\n")
    assert libsigs._expand_scripts([str(tmp_path / "libm.a")]) == [str(tmp_path / "libm-2.39.a"),
                                                                   str(tmp_path / "libmvec.a")]


def test_build_metadata_and_system_sets(tmp_path, monkeypatch, capsys):
    if shutil.which("gcc") is None or shutil.which("ar") is None:
        pytest.skip("needs gcc")
    obj = tmp_path / "libdemo.o"
    (tmp_path / "d.c").write_text("int demo_add(int a, int b) { return a * 3 + b * 5 - (a ^ b); }\n")
    subprocess.run(["gcc", "-O2", "-c", "-o", str(obj), str(tmp_path / "d.c")], check=True)
    subprocess.run(["ar", "rc", str(tmp_path / "libdemo.a"), str(obj)], check=True)
    monkeypatch.setattr(libsigs, "system_libraries", lambda: [("x86_64-linux-gnu", [str(tmp_path / "libdemo.a")])])
    out = tmp_path / "sigs"
    done = libsigs.build_system(str(out))
    assert [os.path.basename(p) for p, _ in done] == ["libdemo-x64.sig"]
    back = libsigs.SigDB.load(done[0][0])
    assert back.library == "libdemo" and back.format == "ELF" and "demo_add" in back.sigs[0].names
    from relic.__main__ import main
    assert main(["sigs", "build", "--system", "-o", str(tmp_path / "cli")]) == 0
    assert (tmp_path / "cli" / "libdemo-x64.sig").exists() and "libdemo-x64.sig" in capsys.readouterr().out


def test_system_libraries_finds_the_native_toolchain():
    libc = "/usr/lib/x86_64-linux-gnu/libc.a"
    if not os.path.exists(libc) or not os.path.isdir("/usr/lib/gcc/x86_64-linux-gnu"):
        pytest.skip("needs the native static glibc and GCC")
    found = libsigs.system_libraries()
    assert ("x86_64-linux-gnu", [libc]) in found
    assert any(t == "x86_64-linux-gnu" and libs[0].endswith("libgcc.a") for t, libs in found)
    assert not any("mingw" in t for t, _ in found)

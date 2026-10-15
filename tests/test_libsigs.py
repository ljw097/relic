"""Library signatures: functions of a stripped static binary named from libc.a."""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.analysis import libsigs
from relic.decompiler.emit import decompile

HERE = os.path.dirname(__file__)
LIBC_A = "/usr/lib/x86_64-linux-gnu/libc.a"


@pytest.fixture(scope="module")
def static_bins(tmp_path_factory):
    if not os.path.exists(LIBC_A) or shutil.which("gcc") is None or shutil.which("strip") is None:
        pytest.skip("needs gcc, strip and a static x86-64 libc")
    d = tmp_path_factory.mktemp("static")
    full, stripped = str(d / "libtypes"), str(d / "libtypes_stripped")
    r = subprocess.run(["gcc", "-O2", "-static", "-o", full, os.path.join(HERE, "src", "libtypes.c")],
                       capture_output=True)
    if r.returncode:
        pytest.skip("static linking is not available")
    subprocess.run(["strip", "-o", stripped, full], check=True)
    sig = str(d / "glibc.sig")
    db = libsigs.build([LIBC_A])
    db.save(sig)
    truth = {f.addr: f.name for f in analyze(full, sigs=[]).functions.values()}
    return truth, analyze(stripped, sigs=[sig]), db


def test_static_stripped_binary_gets_library_names(static_bins):
    truth, an, db = static_bins
    names = set(an.lib_names.values())
    assert {"malloc", "free", "fopen", "fgetc", "fclose", "strlen"} <= names, sorted(names)[:80]
    assert all(an.functions[a].library for a in an.lib_names)
    # every name is the symbol's, or an alias of it (one address, several names in libc.a)
    aliases = {}
    for s in db.sigs:
        for n in s.names:
            aliases.setdefault(libsigs._plain(n.removesuffix("_ifunc")), set()).update(
                libsigs._plain(m.removesuffix("_ifunc")) for m in s.names)
    for a, n in an.lib_names.items():
        t = truth.get(a, "")
        if t.startswith("sub_"):           # an IFUNC stub: no symbol of its own
            continue
        assert libsigs._plain(t) in aliases.get(libsigs._plain(n), {libsigs._plain(n)}), (hex(a), n, t)
    # with names, user code reads as with symbols: main is found, calls are named
    main = an.function_by_name("main")
    assert main is not None and main.addr == next(a for a, n in truth.items() if n == "main")
    joined = decompile(an, an.functions[next(a for a, n in truth.items() if n == "joined")]).text
    assert "strlen(" in joined and "malloc(" in joined, joined


# arch -> (toolchain, libc.a, functions to be named, share of all functions named at least)
# (Thumb `fopen` is `movs r2, #1; b.n __fopen_internal`: 4 bytes, too few to tell; RISC-V
# signatures stop where the linker may relax a call, so they name fewer)
CROSS = {"arm": ("arm-linux-gnueabihf", "/usr/arm-linux-gnueabihf/lib/libc.a",
                 {"malloc", "free", "fgetc", "fclose"}, 0.5),
         "arm64": ("aarch64-linux-gnu", "/usr/aarch64-linux-gnu/lib/libc.a",
                   {"malloc", "free", "fgetc", "fclose", "fopen"}, 0.5),
         "mips": ("mipsel-linux-gnu", "/usr/mipsel-linux-gnu/lib/libc.a",
                  {"malloc", "free", "fgetc", "fclose", "fopen", "strlen"}, 0.5),
         "riscv64": ("riscv64-linux-gnu", "/usr/riscv64-linux-gnu/lib/libc.a", {"fgetc", "fclose", "strlen"}, 0.2)}


@pytest.mark.parametrize("arch", sorted(CROSS))
def test_cross_static_binaries_get_library_names(arch, tmp_path):
    """ARM (Thumb-2 libc: a symbol's address has bit 0 set), AArch64, MIPS and RISC-V signatures."""
    triple, libc, want, share = CROSS[arch]
    cc, strip = shutil.which(f"{triple}-gcc"), shutil.which(f"{triple}-strip")
    if cc is None or strip is None or not os.path.exists(libc):
        pytest.skip(f"needs {triple}-gcc, strip and a static libc")
    full, stripped = str(tmp_path / "libtypes"), str(tmp_path / "libtypes_stripped")
    r = subprocess.run([cc, "-O2", "-static", "-o", full, os.path.join(HERE, "src", "libtypes.c")], capture_output=True)
    if r.returncode:
        pytest.skip("static linking is not available")
    subprocess.run([strip, "-o", stripped, full], check=True)
    db = libsigs.build([libc])
    assert db.arch == arch
    sig = str(tmp_path / "libc.sig")
    db.save(sig)
    truth = {f.addr & ~1: f.name for f in analyze(full, sigs=[]).functions.values()}
    an = analyze(stripped, sigs=[sig])
    names = set(an.lib_names.values())
    assert want <= names, sorted(names)[:80]
    assert len(an.lib_names) > share * sum(1 for f in an.functions.values() if not f.is_import)
    aliases = {}
    for s in db.sigs:
        for n in s.names:
            aliases.setdefault(libsigs._plain(n), set()).update(libsigs._plain(m) for m in s.names)
    for a, n in an.lib_names.items():
        t = truth.get(a & ~1, "")
        # (a static function with the same code as a library one has a name libc.a does not export)
        if not t.startswith("sub_") and libsigs._plain(t) in aliases:
            assert libsigs._plain(t) in aliases.get(libsigs._plain(n), {libsigs._plain(n)}), (hex(a), n, t)
    if arch != "mips":                           # (MIPS `_start` calls through the GOT: no main yet)
        main = an.function_by_name("main")
        assert main is not None and main.addr & ~1 == next(a for a, n in truth.items() if n == "main")


def test_cross_riscv_signatures_stop_where_calls_may_be_relaxed(tmp_path):
    """`call f` (auipc + jalr) may become `jal f`: the code after it moves."""
    gcc = shutil.which("riscv64-linux-gnu-gcc")
    if gcc is None:
        pytest.skip("needs riscv64-linux-gnu-gcc")
    src = tmp_path / "f.c"
    src.write_text("int g(int);\nint f(int x) { x = x * 7 + 3; x ^= x >> 2; return g(x) + 1; }\n")
    obj = tmp_path / "f.o"
    subprocess.run([gcc, "-O2", "-c", "-o", str(obj), str(src)], check=True)
    arch, sigs = libsigs.object_signatures(obj.read_bytes())
    s = next(s for s in sigs if "f" in s.names)
    assert arch == "riscv64" and s.prefix and not s.refs        # cut before the call to g
    db = libsigs.SigDB(arch, [s])
    db.save(str(tmp_path / "f.sig"))
    assert libsigs.SigDB.load(str(tmp_path / "f.sig")).sigs[0].prefix


def test_signature_file_round_trip(tmp_path):
    s = libsigs.Signature([["strlen"], ["__strlen_alias"]], bytes.fromhex("f30f1efa4889f8"),
                          bytes.fromhex("ffffffff00ffff"), [(4, "x")])
    db = libsigs.SigDB("x64", [s], "test")
    db.save(str(tmp_path / "t.sig"))
    back = libsigs.SigDB.load(str(tmp_path / "t.sig"))
    assert back.arch == "x64" and back.sigs[0].groups == s.groups
    assert back.sigs[0].pattern[:4] == s.pattern[:4] and back.sigs[0].mask == s.mask
    assert back.sigs[0].refs == [(4, "x")]


def test_partly_known_bytes_round_trip(tmp_path):
    """AArch64 `bl`: the linker fills the low 26 bits, the opcode bits stay known."""
    s = libsigs.Signature([["f"]], bytes.fromhex("fd7bbfa9000000941f2003d5fd7bc1a8c0035fd6"),
                          bytes.fromhex("ffffffff000000fcffffffffffffffffffffffff"), [(4, "g")])
    db = libsigs.SigDB("arm64", [s], "test")
    db.save(str(tmp_path / "t.sig"))
    back = libsigs.SigDB.load(str(tmp_path / "t.sig")).sigs[0]
    assert back.mask == s.mask and back.fixed == 16
    m = libsigs.Matcher([libsigs.SigDB("arm64", [back])])
    tail = "1f2003d5fd7bc1a8c0035fd6"
    assert m.match(bytes.fromhex("fd7bbfa912345697" + tail))[0] == "f"         # another bl target
    assert m.match(bytes.fromhex("fd7bbfa912345614" + tail)) is None           # a `b`, not a `bl`


def test_matcher_prefers_longest_and_skips_ambiguous():
    fixed = bytes(range(1, 21))
    a = libsigs.Signature([["short_one"]], fixed[:14], b"\xff" * 14)
    b = libsigs.Signature([["long_one"]], fixed, b"\xff" * 20)
    m = libsigs.Matcher([libsigs.SigDB("x64", [a, b])])
    assert m.match(fixed + b"\0" * 8)[0] == "long_one"
    assert m.match(fixed[:14] + b"\xee" * 8)[0] == "short_one"
    # the same code under unrelated names: no name
    c = libsigs.Signature([["mq_close"], ["__close_nocancel"]], fixed, b"\xff" * 20)
    assert libsigs.Matcher([libsigs.SigDB("x64", [c])]).match(fixed) is None
    # aliases of one symbol: the public name
    d = libsigs.Signature([["__libc_malloc", "malloc"]], fixed, b"\xff" * 20)
    assert libsigs.Matcher([libsigs.SigDB("x64", [d])]).match(fixed)[0] == "malloc"


def test_matcher_falls_back_when_longer_matches_refer_elsewhere():
    """A longer pattern matching the start of the code (and of what follows it) whose references
    name other functions gives way to the shorter one that fits."""
    fixed = bytes(range(1, 25))
    short = libsigs.Signature([["wmemcpy"]], fixed[:20], b"\xff" * 20)
    longer = [libsigs.Signature([[n]], fixed, b"\xff" * 20 + b"\0" * 4, [(20, t)])
              for n, t in (("pthread_atfork", "__register_atfork"), ("at_quick_exit", "__cxa_at_quick_exit"))]
    m = libsigs.Matcher([libsigs.SigDB("arm64", [short, *longer])])
    assert m.match(fixed, refs_ok=lambda s: False)[0] == "wmemcpy"
    assert m.match(fixed, refs_ok=lambda s: None) is None           # (cannot tell: no name)
    assert m.match(fixed, refs_ok=lambda s: s.name == "at_quick_exit")[0] == "at_quick_exit"


def test_long_match_needs_no_end():
    """The analysis may run a function on past its end (a call to one not known not to return):
    a long match is enough; a short one must end where the function can."""
    code = bytes(range(1, 101))
    long_sig = libsigs.Signature([["mbrtowc"]], code, b"\xff" * 100)
    m = libsigs.Matcher([libsigs.SigDB("x64", [long_sig])])
    assert m.match(code + b"\0" * 8, ends_ok=lambda size: False)[0] == "mbrtowc"
    short = libsigs.Signature([["tiny"]], code[:20], b"\xff" * 20)
    m = libsigs.Matcher([libsigs.SigDB("x64", [short])])
    assert m.match(code, ends_ok=lambda size: False) is None


def test_ar_members(tmp_path):
    if shutil.which("ar") is None:
        pytest.skip("needs ar")
    for name, body in (("a.o", b"one"), ("a_rather_long_member_name.o", b"two!")):
        (tmp_path / name).write_bytes(body)
    subprocess.run(["ar", "rc", "lib.a", "a.o", "a_rather_long_member_name.o"], cwd=tmp_path, check=True)
    members = dict(libsigs.ar_members((tmp_path / "lib.a").read_bytes()))
    assert members == {"a.o": b"one", "a_rather_long_member_name.o": b"two!"}


@pytest.fixture
def vuln_sig(tmp_path):
    """Signatures of the test program's own functions, from its object file."""
    if shutil.which("gcc") is None:
        pytest.skip("needs gcc")
    obj = str(tmp_path / "vuln.o")
    subprocess.run(["gcc", "-O0", "-fno-stack-protector", "-w", "-c", "-o", obj,
                    os.path.join(HERE, "src", "vuln.c")], check=True)
    sig = str(tmp_path / "vuln.sig")
    libsigs.build([obj]).save(sig)
    return sig


def test_object_file_signatures_name_a_stripped_binary(vuln64_stripped, vuln_sig):
    an = analyze(vuln64_stripped, sigs=[vuln_sig])
    assert {"add_note", "checksum", "classify", "del_note", "menu", "show_note", "vuln", "win"} <= \
        set(an.lib_names.values())
    text = decompile(an, an.function_by_name("main")).text
    assert "menu(" in text, text

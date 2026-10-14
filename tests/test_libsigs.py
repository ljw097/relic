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


def test_signature_file_round_trip(tmp_path):
    s = libsigs.Signature([["strlen"], ["__strlen_alias"]], bytes.fromhex("f30f1efa4889f8"),
                          bytes.fromhex("ffffffff00ffff"), [(4, "x")])
    db = libsigs.SigDB("x64", [s], "test")
    db.save(str(tmp_path / "t.sig"))
    back = libsigs.SigDB.load(str(tmp_path / "t.sig"))
    assert back.arch == "x64" and back.sigs[0].groups == s.groups
    assert back.sigs[0].pattern[:4] == s.pattern[:4] and back.sigs[0].mask == s.mask
    assert back.sigs[0].refs == [(4, "x")]


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

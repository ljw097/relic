"""Library signatures: functions of a stripped static binary named from libc.a."""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.analysis import libsigs
from relic.decompiler.emit import decompile
from relic.loader import load

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
# (Thumb `fopen` is `movs r2, #1; b.n __fopen_internal`: 4 bytes, too few to tell -- on RISC-V
# `li a2, 1; tail __fopen_internal`, the tail call relaxed)
CROSS = {"arm": ("arm-linux-gnueabihf", "/usr/arm-linux-gnueabihf/lib/libc.a",
                 {"malloc", "free", "fgetc", "fclose"}, 0.75),
         "arm64": ("aarch64-linux-gnu", "/usr/aarch64-linux-gnu/lib/libc.a",
                   {"malloc", "free", "fgetc", "fclose", "fopen"}, 0.65),
         "mips": ("mipsel-linux-gnu", "/usr/mipsel-linux-gnu/lib/libc.a",
                  {"malloc", "free", "fgetc", "fclose", "fopen", "strlen"}, 0.8),
         "riscv64": ("riscv64-linux-gnu", "/usr/riscv64-linux-gnu/lib/libc.a",
                     {"malloc", "free", "fgetc", "fclose", "strlen"}, 0.7)}


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


def test_cross_riscv_signatures_model_linker_relaxation(tmp_path):
    """`call g` (auipc + jalr) may become `jal g`, an auipc building an address may go (the
    instruction using it then adds to gp): the signature keeps the whole function and the
    places that may change, and matches each form."""
    gcc = shutil.which("riscv64-linux-gnu-gcc")
    if gcc is None:
        pytest.skip("needs riscv64-linux-gnu-gcc")
    src = tmp_path / "f.c"
    src.write_text("int g(int);\nint f(int x) { x = x * 7 + 3; x ^= x >> 2; return g(x) + 1; }\n")
    obj = tmp_path / "f.o"
    subprocess.run([gcc, "-O2", "-c", "-o", str(obj), str(src)], check=True)
    arch, sigs = libsigs.object_signatures(obj.read_bytes())
    s = next(s for s in sigs if "f" in s.names)
    assert arch == "riscv64" and not s.prefix and ("g" in [n for _, n in s.refs])
    call = next(r for r in s.relax if r[1] == "call")
    assert call[2] == 8 and call[3] == 1                         # auipc ra + jalr ra: 8 bytes, rd = ra
    db = libsigs.SigDB(arch, [s])
    db.save(str(tmp_path / "f.sig"))
    back = libsigs.SigDB.load(str(tmp_path / "f.sig")).sigs[0]
    assert back.relax == s.relax and back.fixed == s.fixed
    # as linked unrelaxed: the pattern itself; relaxed: `jal ra, g` in place of the 8 bytes
    off = call[0]
    assert libsigs.match_relaxed(s.pattern, s)[0] == len(s.pattern)
    jal = (0x000000EF).to_bytes(4, "little")                     # jal ra, 0
    relaxed = s.pattern[:off] + jal + s.pattern[off + 8:]
    size, pieces = libsigs.match_relaxed(relaxed, s)
    assert size == len(s.pattern) - 4 and libsigs._code_offset(pieces, len(s.pattern) - 2) == size - 2
    assert libsigs.match_relaxed(s.pattern[:off] + (0x000000EF ^ 0x80).to_bytes(4, "little") +
                                 s.pattern[off + 8:], s) is None   # (jal with another rd: not it)


def test_relaxed_matcher_forms():
    """A synthetic pattern: a deletable auipc (kept or gone), a tail call (auipc t1 + jr t1, or
    `j`, or `c.j`), and alignment nops the linker may drop."""
    auipc = (0x00000297).to_bytes(4, "little")                   # auipc t0, 0
    use = (0x0002B503).to_bytes(4, "little")                      # ld a0, 0(t0)
    tail = (0x00000317).to_bytes(4, "little") + (0x00030067).to_bytes(4, "little")   # auipc t1; jr t1
    nops = b"\x01\x00" * 2
    body = bytes.fromhex("1305a500") * 4                          # addi a0, a0, 10 (x4): known bytes
    pat = auipc + use + body + nops + tail
    mask = bytearray(b"\xff" * len(pat))
    for k in range(4, 8):                                        # rs1 of the `ld` may become gp
        mask[k] = 0x07 if k == 6 else (0x7F if k == 5 else mask[k])
    for k in list(range(1, 4)) + list(range(len(pat) - 7, len(pat) - 4)) + list(range(len(pat) - 2, len(pat))):
        mask[k] = 0
    s = libsigs.Signature([["f"]], pat, bytes(mask), [],
                          relax=[[0, "del", 4, 0], [24, "align", 4, 0], [28, "call", 8, 0]])
    m = libsigs.match_relaxed
    assert m(pat, s)[0] == len(pat)
    no_auipc = pat[4:]
    assert m(no_auipc, s)[0] == len(pat) - 4
    j = (0x0000006F).to_bytes(4, "little")                       # j (jal x0)
    assert m(pat[:28] + j, s)[0] == len(pat) - 4
    assert m(pat[:28] + b"\x01\xa0", s)[0] == len(pat) - 6       # c.j
    assert m(pat[:24] + j, s)[0] == len(pat) - 8                  # (nops dropped too)
    assert m(pat[:8] + bytes.fromhex("1305b500") + pat[12:], s) is None   # a known byte differs
    db = libsigs.SigDB("riscv64", [s])
    mt = libsigs.Matcher([db])
    assert not mt.unindexed and mt.candidates(no_auipc)[0] is s and mt.candidates(pat)[0] is s


def test_ctor_dtor_variants_are_one_name():
    """The base-object constructor / destructor (C2 / D2) is the complete-object one's code."""
    p = libsigs._plain
    assert p("_ZNSt12length_errorC2EPKc") == p("_ZNSt12length_errorC1EPKc")
    assert p("_ZNSt12length_errorD2Ev") == p("_ZNSt12length_errorD1Ev")
    assert p("_ZNSt12length_errorD0Ev") != p("_ZNSt12length_errorD1Ev")       # (deleting: other code)
    assert p("__libc_malloc") == "malloc" and p("D2Ex") == "D2Ex"             # (not mangled: as it is)


def _all_symbols(path):
    """Every function symbol of an ELF file: address -> names (aliases share one)."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    out = {}
    with open(path, "rb") as fp:
        for sec in ELFFile(fp).iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym["st_info"]["type"] in ("STT_FUNC", "STT_GNU_IFUNC") and sym.name:
                        out.setdefault(sym["st_value"], set()).add(sym.name)
    return out


LIBSTDCXX_A = "/usr/lib/gcc/x86_64-linux-gnu/13/libstdc++.a"
LIBGCC_A = ["/usr/lib/gcc/x86_64-linux-gnu/13/libgcc.a", "/usr/lib/gcc/x86_64-linux-gnu/13/libgcc_eh.a"]


@pytest.fixture(scope="module")
def static_cxx(tmp_path_factory):
    libs = [LIBC_A, LIBSTDCXX_A, *LIBGCC_A]
    if not all(os.path.exists(p) for p in libs) or shutil.which("g++") is None or shutil.which("strip") is None:
        pytest.skip("needs g++, strip and static libc / libstdc++ / libgcc")
    d = tmp_path_factory.mktemp("static_cxx")
    full, stripped = str(d / "cxx"), str(d / "cxx_stripped")
    r = subprocess.run(["g++", "-O2", "-static", "-o", full, os.path.join(HERE, "src", "libsigs_cxx.cpp")],
                       capture_output=True)
    if r.returncode:
        pytest.skip("static linking is not available")
    subprocess.run(["strip", "-o", stripped, full], check=True)
    sigs = []
    for name, paths in (("libc", [LIBC_A]), ("libstdcxx", [LIBSTDCXX_A]), ("libgcc", LIBGCC_A)):
        sigs.append(str(d / f"{name}.sig"))
        libsigs.build(paths).save(sigs[-1])
    return _all_symbols(full), analyze(stripped, sigs=sigs), sigs


def test_static_cxx_names_through_references_and_tables(static_cxx):
    """Code several signatures fit (nine `__throw_*` functions alike but for what they call),
    functions too short to match, and virtual methods found through the vtables and function
    tables named functions refer to -- and none named wrongly."""
    truth, an, _ = static_cxx
    names = set(an.lib_names.values())
    # told apart by what they call: length_error's constructor (named itself as C1 from a C2 symbol)
    assert {"_ZSt20__throw_length_errorPKc", "_ZSt19__throw_logic_errorPKc",
            "_ZSt21__throw_runtime_errorPKc"} <= names
    # in vtables: deleting destructors and what()
    assert {"_ZNSt13runtime_errorD0Ev", "_ZNKSt11logic_error4whatEv", "_ZNSt9exceptionD0Ev"} <= names
    # in libc's stdio jump tables
    assert {"_IO_file_seek", "_IO_file_stat", "_IO_default_imbue"} <= names
    p = libsigs._plain
    for a, n in an.lib_names.items():
        t = truth.get(a)
        if t:
            assert p(n) in {p(x) for x in t}, (hex(a), n, sorted(t))
    with_symbols = [f for f in an.functions.values() if not f.is_import and f.addr in truth]
    assert sum(1 for f in with_symbols if f.library) > 0.7 * len(with_symbols)


def test_tables_are_kept_in_the_signature_file(static_cxx, tmp_path):
    _, _, sigs = static_cxx
    libc = libsigs.SigDB.load(sigs[0])
    size, slots = libc.tables["_IO_file_jumps"]
    assert size > 0 and ["_IO_file_seek", 1] in [s[1:] for s in slots]
    assert all(off % 8 == 0 and 0 <= off < size for off, _, _ in slots)
    cxx = libsigs.SigDB.load(sigs[1])
    vt = dict((n, off) for off, n, _ in cxx.tables["_ZTVSt13runtime_error"][1])
    assert vt["_ZTISt13runtime_error"] == 8 and "_ZNSt13runtime_errorD0Ev" in vt     # typeinfo, then methods
    libc.save(str(tmp_path / "again.sig"))
    assert libsigs.SigDB.load(str(tmp_path / "again.sig")).tables == libc.tables


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


MINGW = {"x64": "x86_64-w64-mingw32", "x86": "i686-w64-mingw32"}


@pytest.mark.parametrize("arch", sorted(MINGW))
def test_coff_object_signatures(arch, tmp_path):
    """MinGW library members are COFF: functions run to the next symbol (less the padding after
    them), aliases are one name, i386 names lose their `_` and a stdcall `@N`."""
    cc = shutil.which(f"{MINGW[arch]}-gcc")
    if cc is None:
        pytest.skip(f"needs {MINGW[arch]}-gcc")
    (tmp_path / "c.c").write_text(
        "int g(int);\n"
        "static int helper(int x) { return x * 7 + g(x); }\n"
        "int api(int x) { return helper(x) ^ helper(x + 1); }\n"
        "int api_alias(int x) __attribute__((alias(\"api\")));\n"
        "int __attribute__((stdcall)) Sum3(int a, int b, int c) { return a * 3 + b * 5 + c * 7 + g(a); }\n"
        "int tiny(void) { return 0; }\n")
    obj = tmp_path / "c.o"
    subprocess.run([cc, "-O1", "-fno-inline", "-c", "-o", str(obj), str(tmp_path / "c.c")], check=True)
    data = obj.read_bytes()
    assert libsigs.is_coff(data)
    got_arch, sigs = libsigs.coff_object_signatures(data)
    by = {n: s for s in sigs for n in s.names}
    assert got_arch == arch and {"api", "api_alias", "helper", "Sum3", "tiny"} <= set(by)
    assert by["api"] is by["api_alias"] and by["api"].name == "api"                # one alias set
    assert "g" in [n for _, n in by["helper"].refs]                                # (helper: no relocation)
    assert by["tiny"].pattern.endswith(b"\xc3") and len(by["tiny"].pattern) <= 6   # (no padding after `ret`)
    db = libsigs.build([str(obj)])
    assert db.format == "PE" and db.arch == arch and libsigs.set_name(db) == f"c-{arch}-pe.sig"


@pytest.mark.parametrize("arch", sorted(MINGW))
def test_static_mingw_binaries_get_library_names(arch, tmp_path):
    triple = MINGW[arch]
    cc, strip = shutil.which(f"{triple}-gcc"), shutil.which(f"{triple}-strip")
    libs = [libs for t, libs in libsigs.system_libraries() if t == triple]
    if cc is None or strip is None or not libs:
        pytest.skip(f"needs {triple}-gcc, strip and its static runtime")
    full, stripped = str(tmp_path / "libtypes.exe"), str(tmp_path / "stripped.exe")
    subprocess.run([cc, "-O2", "-static", "-o", full, os.path.join(HERE, "src", "libtypes.c")], check=True)
    subprocess.run([strip, "-o", stripped, full], check=True)
    sigs, aliases = [], {}
    for k, paths in enumerate(libs):
        db = libsigs.build(paths)
        assert db.format == "PE" and db.arch == arch
        sigs.append(str(tmp_path / f"{k}.sig"))
        db.save(sigs[-1])
        for s in db.sigs:
            for n in s.names:
                aliases.setdefault(libsigs._plain(n), set()).update(libsigs._plain(m) for m in s.names)
    an = analyze(stripped, sigs=sigs)
    assert an.toolchain.compiler.startswith("MinGW GCC")
    names = set(an.lib_names.values())
    assert {"__mingw_vfprintf", "__mingw_pformat", "_pei386_runtime_relocator"} <= names, sorted(names)
    # (`jmp [__imp_fwrite]`: an import thunk, named after its import before signatures run)
    assert an.function_by_name("fwrite") is not None
    truth = {a: s.name for a, s in load(full).symbols.items()}
    p = libsigs._plain
    for a, n in an.lib_names.items():
        t = truth.get(a)
        if t:
            assert p(t) in aliases.get(p(n), {p(n)}) | {p(n)}, (hex(a), n, t)
    with_symbols = [f for f in an.functions.values() if not f.is_import and f.addr in truth]
    assert sum(1 for f in with_symbols if f.library) > 0.7 * len(with_symbols)

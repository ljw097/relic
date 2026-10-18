"""Mach-O: macOS executables for x86-64 and arm64 built here with clang and ld64.lld (libc from a
text stub, tests/src/libSystem.tbd), a universal file of both, a dylib and a stripped copy."""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.loader import load

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "macho.c")
BINS = os.path.join(HERE, "bins")
TARGET = {"x64": "x86_64", "a64": "arm64"}


def _tool(name):
    return shutil.which(name) or shutil.which(f"{name}-18")


def _build(name: str, *extra: str, out_name: str | None = None) -> str:
    out = os.path.join(BINS, f"macho_{out_name or name}")
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(SRC):
        return out
    clang = _tool("clang")
    if clang is None or _tool("ld64.lld") is None:
        pytest.skip("needs clang and ld64.lld (lld) to build Mach-O samples")
    arch, opt = name.split("_")[:2]
    os.makedirs(BINS, exist_ok=True)
    tmp = f"{out}.{os.getpid()}"
    r = subprocess.run([clang, "-target", f"{TARGET[arch]}-apple-macos11", f"-{opt}", "-w", "-nostdlib",
                        "-fuse-ld=lld", "-L", os.path.join(HERE, "src"), "-lSystem",
                        "-Wl,-platform_version,macos,11.0,11.0", *extra, "-o", tmp, SRC],
                       capture_output=True, text=True)
    if r.returncode:
        pytest.skip(f"cannot build {name}: {r.stderr[:300]}")
    os.replace(tmp, out)
    return out


@pytest.fixture(scope="module", params=["x64_O0", "x64_O2", "a64_O0", "a64_O2"])
def exe(request):
    return request.param, _build(request.param)


@pytest.fixture(scope="module")
def fat():
    lipo = _tool("llvm-lipo")
    if lipo is None:
        pytest.skip("needs llvm-lipo")
    out = os.path.join(BINS, "macho_fat")
    parts = [_build("x64_O0"), _build("a64_O0")]
    if not os.path.exists(out) or os.path.getmtime(out) < max(os.path.getmtime(p) for p in parts):
        subprocess.run([lipo, "-create", "-output", out, *parts], check=True)
    return out


def test_headers_segments_sections(exe):
    name, path = exe
    b = load(path)
    assert b.format == "Mach-O" and b.os == "macos" and b.bits == 64
    assert b.arch == ("x64" if name.startswith("x64") else "arm64")
    assert b.info["type"] == "executable" and b.info["platform"].startswith("macOS 11.0")
    assert b.interp == "/usr/lib/dyld" and b.libraries == ["/usr/lib/libSystem.B.dylib"]
    assert b.base == 0x100000000 and b.section("__text").x and not b.section("__cstring").x
    assert b.section("__stubs").x and b.is_writable(b.section("__la_symbol_ptr").addr)
    assert b.entry == b.name_to_addr["main"]                     # LC_MAIN: main itself
    assert b.read_cstring(b.section("__cstring").addr) is not None


def test_symbols_and_imports(exe):
    name, path = exe
    b = load(path)
    for f in ("classify", "checksum", "win", "vuln", "main"):
        assert b.symbols[b.name_to_addr[f]].kind == "func", f
    assert b.symbols[b.name_to_addr["counter"]].kind == "object"
    imps = {i.name: i for i in b.imports}
    want = {"printf", "puts", "gets", "system"} | ({"malloc", "free", "exit"} if name.endswith("O0") else set())
    assert want <= set(imps), sorted(imps)               # (-O2 drops the unused malloc / free pair)
    for n in ("printf", "gets", "system"):
        i = imps[n]
        assert b.section_at(i.addr).name == "__stubs" and b.section_at(i.got).name == "__la_symbol_ptr"
        assert i.library == "libSystem.B.dylib" and b.got_names[i.got] == n
    assert all(b.is_exec(a) for a in b.function_starts) and b.name_to_addr["vuln"] in b.function_starts


def test_calls_resolve_to_imports(exe):
    name, path = exe
    an = analyze(path)
    vuln = an.function_by_name("vuln")
    calls = [an.call_name(i) for blk in sorted(vuln.blocks.values(), key=lambda b: b.addr) for i in blk.insns
             if i.kind == "call"]
    assert calls[:2] == ["puts", "gets"] and "printf" in calls, calls
    names = {f.name for f in an.functions.values() if not f.is_import}
    assert {"classify", "checksum", "win", "vuln", "main"} <= names and "_mh_execute_header" not in names


def test_decompile(exe):
    """Imports by name, Apple arm64's variadic arguments on the stack, the canary check hidden
    (clang -O0 reaches __stack_chk_fail through a jump), clang's division by a large constant."""
    name, path = exe
    an = analyze(path)
    code = decompile(an, an.function_by_name("vuln")).text
    assert 'puts("name?");' in code and "gets(" in code, code
    assert 'printf("hello %s (%d)\\n", ' in code and "__stack_chk" not in code and "canary)" not in code, code
    assert "checksum(" in code if name.endswith("O0") else "% 100000" in code, code
    code = decompile(an, an.function_by_name("checksum")).text
    assert "% 100000" in code and "0x14f8b589" not in code, code
    code = decompile(an, an.function_by_name("main")).text
    assert 'printf("%s %d\\n", names[' in code and "counter[0]" not in code, code
    if name.endswith("O0"):
        assert "switch (" in decompile(an, an.function_by_name("classify")).text
        assert 'system("/bin/sh");' in decompile(an, an.function_by_name("win")).text


def test_universal_file(fat):
    from relic.loader.macho import slices
    with open(fat, "rb") as f:
        data = f.read()
    assert [s[0] for s in slices(data)] == ["x64", "arm64"]
    b = load(fat)                                   # the host's slice by default
    assert b.arch == "x64" and "x64, arm64" in b.info["universal"]
    b = load(fat, arch="arm64")
    assert b.arch == "arm64" and b.entry == b.name_to_addr["main"]


def test_dylib_exports():
    path = _build("x64_O2", "-shared", "-Wl,-install_name,@rpath/libdemo.dylib", out_name="libdemo.dylib")
    b = load(path)
    assert b.info["type"] == "dylib" and b.info["install name"] == "@rpath/libdemo.dylib"
    assert {"classify", "checksum", "vuln"} <= {s.name for s in b.exports}


def test_stripped_keeps_function_starts():
    strip = _tool("llvm-strip")
    if strip is None:
        pytest.skip("needs llvm-strip")
    src = _build("x64_O2")
    out = os.path.join(BINS, "macho_x64_O2_stripped")
    subprocess.run([strip, "-o", out, src], check=True)
    an = analyze(out)
    assert an.bin.entry in an.functions and an.name(an.bin.entry) == "main"
    # every function LC_FUNCTION_STARTS lists is found, named or not
    assert set(an.bin.function_starts) <= set(an.functions)
    assert any('system("/bin/sh")' in decompile(an, f).text for f in an.functions.values() if not f.is_import)


def test_checksec(exe):
    name, path = exe
    cs = analyze(path).checksec()
    assert cs["PIE"] == "Yes" and cs["NX stack"] == "Yes" and cs["NX heap"] == "Yes" and cs["Canary"] == "Yes"
    assert cs["Code signature"] == ("Yes" if name.startswith("a64") else "No")    # (ld64 signs arm64 ad hoc)


@pytest.mark.parametrize("arch", ["x64", "a64"])
def test_chained_fixups(arch):
    """macOS 13 targets: pointers fixed through LC_DYLD_CHAINED_FIXUPS. A rebased pointer in data
    reads as its target, a bound one is named after its import."""
    path = _build(f"{arch}_O0", "-Wl,-platform_version,macos,13.0,13.0", "-Wl,-fixup_chains",
                  out_name=f"{arch}_O0_chained")
    with open(path, "rb") as f:
        assert (0x80000034).to_bytes(4, "little") in f.read(0x1000)        # (built with chained fixups)
    an = analyze(path)
    b = an.bin
    names = b.name_to_addr["names"]
    assert [b.read_cstring(b.read_ptr(names + 8 * k)) for k in range(3)] == ["zero", "one", "two"]
    assert {"printf", "gets", "__stack_chk_guard"} <= set(b.got_names.values())
    code = decompile(an, an.function_by_name("main")).text
    assert 'printf("%s %d\\n", names[' in code, code


@pytest.mark.parametrize("arch", ["x64", "a64"])
def test_relocatable_object(arch):
    """clang's .o: sections placed from a base, undefined symbols as import stubs with GOT slots,
    relocations applied (x86-64 branch / signed / GOT load; arm64 branch26 / page21 / pageoff12)."""
    clang = _tool("clang")
    if clang is None:
        pytest.skip("needs clang")
    out = os.path.join(BINS, f"macho_{arch}.o")
    if not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(SRC):
        subprocess.run([clang, "-target", f"{TARGET[arch]}-apple-macos11", "-O0", "-w", "-c", "-o", out, SRC],
                       check=True)
    an = analyze(out)
    b = an.bin
    assert b.info["type"] == "object" and b.base == 0x100000
    assert {"classify", "checksum", "vuln", "main", "counter", "names"} <= set(b.name_to_addr)
    assert not any(n.startswith(("ltmp", "l_.str")) for n in b.name_to_addr)
    imps = {i.name: i for i in b.imports}
    assert {"printf", "puts", "gets", "malloc", "system"} <= set(imps)
    assert b.got_names[imps["__stack_chk_guard"].got] == "__stack_chk_guard"
    names = b.name_to_addr["names"]
    assert [b.read_cstring(b.read_ptr(names + 8 * k)) for k in range(3)] == ["zero", "one", "two"]
    code = decompile(an, an.function_by_name("vuln")).text
    assert 'puts("name?");' in code and 'printf("hello %s (%d)\\n", ' in code and "checksum(" in code, code
    code = decompile(an, an.function_by_name("main")).text
    assert "malloc(32)" in code and 'printf("%s %d\\n", names[' in code and "% 3]" in code, code
    assert "counter = " in code and "exit(1);" in code, code


OBJC = os.path.join(HERE, "src", "objc.m")


def _objc(name: str, *extra: str) -> str:
    out = os.path.join(BINS, f"objc_{name}")
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(OBJC):
        return out
    clang = _tool("clang")
    if clang is None or _tool("ld64.lld") is None:
        pytest.skip("needs clang and ld64.lld (lld) to build Mach-O samples")
    arch, opt = name.split("_")[:2]
    os.makedirs(BINS, exist_ok=True)
    tmp = f"{out}.{os.getpid()}"
    subprocess.run([clang, "-target", f"{TARGET[arch]}-apple-macos11", f"-{opt}", "-w", "-nostdlib",
                    "-fuse-ld=lld", "-L", os.path.join(HERE, "src"), "-lSystem", "-lobjc",
                    "-Wl,-platform_version,macos,11.0,11.0", *extra, "-o", tmp, OBJC], check=True)
    os.replace(tmp, out)
    return out


@pytest.fixture(scope="module", params=["x64_O0", "x64_O2", "a64_O0", "a64_O2"])
def objc(request):
    return request.param, _objc(request.param)


def test_objc_metadata(objc):
    """Classes (superclass, instance and class methods, ivars, properties), a category, selector
    and class references; method implementations named the runtime's way."""
    name, path = objc
    b = load(path)
    classes = {(c.name, c.category): c for c in b.objc.classes}
    animal = classes[("Animal", "")]
    assert animal.superclass == "Base"
    assert {m.name for m in animal.methods if not m.meta} >= {"legs", "setLegs:", "speak:times:", "age", "setAge:"}
    assert [(n, t) for n, t, _ in animal.ivars] == [("legs", "i"), ("_age", "i")]
    assert animal.properties == [("age", "Ti,V_age")]
    tricks = classes[("Animal", "Tricks")]
    assert {(m.name, m.meta) for m in tricks.methods} == {("roll:", False), ("make", True)}
    assert {"setLegs:", "speak:times:"} <= set(b.objc.selrefs.values())
    for m in ("-[Animal speak:times:]", "+[Base alloc]", "-[Animal(Tricks) roll:]", "+[Animal(Tricks) make]"):
        assert m in b.name_to_addr, m


def test_objc_decompile(objc):
    """Message sends as `[receiver selector:args]`, methods with `self` and `_cmd`, ivars as
    `self->ivar`."""
    name, path = objc
    an = analyze(path)
    code = decompile(an, an.function_by_name("main")).text
    assert "[[Animal alloc] init]" in code and "setLegs:4]" in code and "speak:\"woof\" times:" in code, code
    assert "objc_msgSend" not in code, code
    code = decompile(an, an.function_by_name("-[Animal speak:times:]")).text
    assert code.startswith("void -[Animal speak:times:](Animal *self, SEL _cmd, char *a3, int a4)"), code
    assert "->legs" in code and "OBJC_IVAR" not in code, code
    code = decompile(an, an.function_by_name("-[Animal(Tricks) roll:]")).text
    assert "->legs" in code, code


def test_objc_stripped():
    """Method names come from the metadata, not the symbol table."""
    strip = _tool("llvm-strip")
    if strip is None:
        pytest.skip("needs llvm-strip")
    out = os.path.join(BINS, "objc_a64_O2_stripped")
    subprocess.run([strip, "-o", out, _objc("a64_O2")], check=True)
    b = load(out)
    assert "speak" not in " ".join(s.name for s in b.symbols.values() if s.source == "symtab")
    assert {"-[Animal speak:times:]", "-[Animal legs]", "-[Animal(Tricks) roll:]"} <= set(b.name_to_addr)

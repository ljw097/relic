"""File formats beyond linked ELF / PE: relocatable ELF objects (every architecture Relic
lifts), COFF objects, static-library members, Intel HEX and Motorola S-record images."""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.loader import load, load_bytes
from relic.loader.archive import object_members

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "obj_link.c")
# arch -> compiler and flags making an object
OBJECTS = {"x64": ["gcc"], "x86": ["gcc", "-m32", "-fno-pic"], "arm64": ["aarch64-linux-gnu-gcc"],
           "arm": ["arm-linux-gnueabihf-gcc"], "arm-a32": ["arm-linux-gnueabihf-gcc", "-marm"],
           "mips": ["mipsel-linux-gnu-gcc"], "riscv64": ["riscv64-linux-gnu-gcc"],
           "coff-x64": ["x86_64-w64-mingw32-gcc"], "coff-x86": ["i686-w64-mingw32-gcc"]}


def _object(tmp_path, key):
    cc, *flags = OBJECTS[key]
    if shutil.which(cc) is None:
        pytest.skip(f"needs {cc}")
    out = str(tmp_path / f"{key}.o")
    r = subprocess.run([cc, *flags, "-O1", "-fno-inline", "-c", "-o", out, SRC], capture_output=True)
    if r.returncode:
        pytest.skip(f"{cc} cannot build here")
    return out


@pytest.mark.parametrize("key", sorted(OBJECTS))
def test_relocatable_objects_link_alone(key, tmp_path):
    """Sections laid out, relocations applied, external symbols as imports: the code reads
    as in the linked program -- the call to the static helper, the library call with its
    string, the global."""
    path = _object(tmp_path, key)
    b = load(path)
    assert b.format == ("COFF" if key.startswith("coff") else "ELF")
    names = {s.name for s in b.symbols.values()}
    assert {"api", "helper", "main"} <= names
    # (MinGW's printf is a function of the object around the import __mingw_vfprintf)
    assert any("printf" in i.name for i in b.imports)
    starts = sorted((s.addr, s.end) for s in b.sections)
    assert all(a_end <= b_start for (_a, a_end), (b_start, _b) in zip(starts, starts[1:]))   # (no overlap)
    an = analyze(path)
    text = decompile(an, an.function_by_name("api")).text
    assert "helper(" in text and '"hello"' in text and "counter" in text, text
    assert "printf" in text and "%s %d" in text, text


def test_archive_members(tmp_path):
    path = _object(tmp_path, "x64")
    lib = tmp_path / "libdemo.a"
    other = tmp_path / "other.o"
    (tmp_path / "o.c").write_text("int other_fn(int x) { return x * 41; }\n")
    subprocess.run(["gcc", "-O1", "-c", "-o", str(other), str(tmp_path / "o.c")], check=True)
    subprocess.run(["ar", "rc", str(lib), str(other), path], check=True)
    assert object_members(lib.read_bytes()) == ["other.o", "x64.o"]
    first = load(str(lib))                                       # (the first object member)
    assert "other_fn" in {s.name for s in first.symbols.values()} and "other.o" in first.info["archive"]
    chosen = load(f"{lib}:x64.o")
    assert "api" in {s.name for s in chosen.symbols.values()}
    with pytest.raises(ValueError):
        load(f"{lib}:missing.o")


def test_intel_hex_and_srec_match_the_elf(tmp_path):
    """objcopy's Intel HEX and S-record forms of a program hold its bytes at its addresses."""
    cc, objcopy = shutil.which("arm-linux-gnueabihf-gcc"), shutil.which("arm-linux-gnueabihf-objcopy")
    if cc is None or objcopy is None:
        pytest.skip("needs the ARM cross toolchain")
    elf = str(tmp_path / "fw.elf")
    subprocess.run([cc, "-O1", "-nostdlib", "-static", "-Wl,-e,reset", "-Wl,-Ttext=0x8000", "-o", elf, "-x", "c", "-"],
                   input=b"int counter; void reset(void) { for (;;) counter += 3; }\n", check=True)
    ref = load(elf)
    for fmt, kind in (("ihex", "IHEX"), ("srec", "SREC")):
        out = str(tmp_path / f"fw.{fmt}")
        subprocess.run([objcopy, "-O", fmt, elf, out], check=True)
        b = load(out)
        assert b.format == kind and b.arch == "arm"
        assert b.entry == ref.entry                              # (the start-address record)
        text = ref.section(".text")
        assert b.read(text.addr, text.size) == ref.read(text.addr, text.size)
        an = analyze(out)
        assert an.function_at(ref.entry) is not None


def test_hex_records_checked():
    good = b":0400000001020304F2\n:00000001FF\n"
    b = load_bytes(good, "x.hex", "arm")
    assert b.format == "IHEX" and b.read(0, 4) == b"\x01\x02\x03\x04"
    with pytest.raises(ValueError):
        load_bytes(b":0400000001020304F3\n:00000001FF\n", "bad.hex", "arm")      # (checksum)
    # extended linear address and a Cortex-M vector table: the reset handler is the entry (Thumb)
    vec = bytes.fromhex("00100020") + (0x08000009).to_bytes(4, "little") + b"\x70\x47\x00\xbf"
    def rec(addr, kind, payload):
        body = bytes([len(payload)]) + addr.to_bytes(2, "big") + bytes([kind]) + payload
        return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()
    text = "\n".join([rec(0, 4, b"\x08\x00"), rec(0, 0, vec), ":00000001FF"]).encode()
    b = load_bytes(text, "fw.hex")
    assert b.base == 0x08000000 and b.entry == 0x08000008 and 0x08000008 in b.thumb_code


# ------------------------------------------------------------------ core dumps
def test_core_dump(tmp_path):
    """A gdb core file: the process's memory as sections named by the mapped file, the signal,
    pid and registers, the program counter in work(), and the executable's symbols on top;
    the toolchain is the executable's, not that of the libraries in the dump."""
    if shutil.which("gcc") is None or shutil.which("gdb") is None:
        pytest.skip("needs gcc and gdb")
    prog, core = str(tmp_path / "prog"), str(tmp_path / "core")
    subprocess.run(["gcc", "-O0", "-o", prog, os.path.join(HERE, "src", "dbg_target.c")], check=True)
    subprocess.run(["gdb", "-nx", "-batch", "-ex", "break work", "-ex", "run < /dev/null",
                    "-ex", f"gcore {core}", prog], capture_output=True, timeout=60)
    if not os.path.exists(core):
        pytest.skip("gdb cannot dump a core here")
    from relic.analysis.ident import identify
    b = load(core)
    assert b.elf_type == "ET_CORE" and b.info["signal"].startswith("SIGTRAP")
    work = next(s for s in b.symbols.values() if s.name == "work")
    assert b.entry == int(b.info["pc"], 16) and work.addr <= b.entry < work.addr + 32
    names = {s.name for s in b.sections}
    assert "prog" in names and "[stack]" in names and any(n.startswith("libc") for n in names)
    assert b.core_regs["rip"] == b.entry
    tc = identify(b)
    assert tc.compiler.startswith("GCC") and tc.libc.startswith("glibc") and "Rust" not in tc.languages
    an = analyze(core)
    assert "counter" in decompile(an, an.function_by_name("work")).text


# ------------------------------------------------------------------ PE extras
PE_SRC = r"""
#include <windows.h>
#include <stdio.h>
void NTAPI tls_cb(PVOID h, DWORD r, PVOID p) { if (r == DLL_PROCESS_ATTACH) puts("tls"); }
__attribute__((section(".CRT$XLB"))) PIMAGE_TLS_CALLBACK p_tls_cb = tls_cb;
const unsigned char clr[96] = "CLRHDRMARK";
int main(void) { MessageBoxA(0, "hi", (const char *)clr, 0); return 0; }
"""
PE_RC = r"""1 VERSIONINFO
FILEVERSION 1,2,3,4
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Relic Test Co"
      VALUE "ProductName", "relic-pe-test"
      VALUE "FileVersion", "1.2.3.4"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
2 RCDATA { "payload" }
"""


@pytest.fixture(scope="module")
def pe_extras(tmp_path_factory):
    cc, rc = shutil.which("x86_64-w64-mingw32-gcc"), shutil.which("x86_64-w64-mingw32-windres")
    if cc is None or rc is None:
        pytest.skip("needs MinGW-w64 gcc and windres")
    d = tmp_path_factory.mktemp("pe")
    (d / "t.c").write_text(PE_SRC)
    (d / "r.rc").write_text(PE_RC)
    subprocess.run([rc, str(d / "r.rc"), "-O", "coff", "-o", str(d / "r.o")], check=True)
    exe = d / "t.exe"
    r = subprocess.run([cc, "-O1", "-o", str(exe), str(d / "t.c"), str(d / "r.o"), "-Wl,--pdb=" + str(d / "t.pdb")],
                       capture_output=True)
    if r.returncode:
        pytest.skip("this MinGW linker cannot write a PDB")
    return str(exe)


def test_pe_tls_resources_pdb(pe_extras):
    b = load(pe_extras)
    cb = next(s for s in b.symbols.values() if s.name == "tls_cb")
    assert cb.addr in b.tls_callbacks and "tls_callbacks" in b.info
    assert "RT_VERSION" in b.info["resources"] and "RT_RCDATA" in b.info["resources"]
    assert b.version_info["CompanyName"] == "Relic Test Co" and b.info["FileVersion"] == "1.2.3.4"
    assert b.pdb["path"].endswith("t.pdb") and b.pdb["age"] >= 1
    assert len(b.pdb["guid"]) == 36 and b.pdb["guid"] in b.info["pdb"]
    assert not hasattr(b, "dotnet")


def test_pe_dotnet_header(pe_extras, tmp_path):
    """A CLR header in data directory 14 (written into the program's constant array) and the
    metadata's "BSJB" root it points at: the assembly's runtime version."""
    import struct

    import pefile
    data = bytearray(open(pe_extras, "rb").read())
    off = data.index(b"CLRHDRMARK")
    pe = pefile.PE(data=bytes(data))
    rva = pe.get_rva_from_offset(off)
    version = b"v4.0.30319\0\0"
    meta = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version
    hdr = struct.pack("<IHHIII", 72, 2, 5, rva + 72, len(meta), 1)          # cb, version, metadata, IL only
    data[off:off + 72 + len(meta)] = hdr.ljust(72, b"\0") + meta
    pe = pefile.PE(data=bytes(data))
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress = rva
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size = 72
    out = tmp_path / "net.exe"
    pe.write(str(out))
    b = load(str(out))
    assert b.dotnet == {"runtime": "v4.0.30319", "il_only": True}
    assert b.info["dotnet"] == "CLR v4.0.30319, IL only"


def test_pe_delay_imports(tmp_path):
    """Delay-loaded imports (a dlltool delay-import library): found through MinGW's descriptor
    symbols, and -- stripped, with data directory 13 pointing at them as MSVC's linker writes
    it -- through the directory; calls through their IAT slots name the function."""
    import pefile
    cc, tool = shutil.which("x86_64-w64-mingw32-gcc"), shutil.which("x86_64-w64-mingw32-dlltool")
    if cc is None or tool is None:
        pytest.skip("needs MinGW-w64 gcc and dlltool")
    (tmp_path / "u.def").write_text("LIBRARY user32.dll\nEXPORTS\nMessageBoxA\n")
    subprocess.run([tool, "-d", str(tmp_path / "u.def"), "-y", str(tmp_path / "libdu.a")], check=True)
    (tmp_path / "d.c").write_text('#include <windows.h>\nint main(void) { return MessageBoxA(0, "a", "b", 0); }\n')
    exe = str(tmp_path / "d.exe")
    r = subprocess.run([cc, "-O1", "-o", exe, str(tmp_path / "d.c"), "-L" + str(tmp_path), "-ldu", "-ldelayimp"],
                       capture_output=True)
    if r.returncode:
        pytest.skip("cannot link a delay-import library here")
    b = load(exe)
    imp = next(i for i in b.imports if i.name == "MessageBoxA")
    assert imp.library == "user32.dll" and b.info["delay imports"] == "user32.dll" and "user32.dll" in b.libraries
    an = analyze(exe)
    assert 'MessageBoxA(0, "a", "b", 0)' in decompile(an, an.function_by_name("main")).text
    desc = next(s.addr for s in b.symbols.values() if s.name.startswith("__DELAY_IMPORT_DESCRIPTOR_")) - b.base
    stripped = str(tmp_path / "s.exe")
    subprocess.run(["x86_64-w64-mingw32-strip", "-o", stripped, exe], check=True)
    pe = pefile.PE(stripped)
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = desc
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = 64
    pe.write(stripped + ".2")
    pe.close()
    b = load(stripped + ".2")
    assert not any(s.name.startswith("__DELAY") for s in b.symbols.values())
    assert any(i.name == "MessageBoxA" and i.got == imp.got for i in b.imports)


# ------------------------------------------------------------------ raw firmware base
FW_SRC = r"""
const char *msgs[] = {"booting firmware", "init clocks", "uart ready", "error: bad crc"};
void say(const char *s) { volatile const char *p = s; while (*p) p++; }
int run(int k) { say(msgs[k & 3]); say("done with step"); return k * 3; }
"""


def test_raw_firmware_base_from_string_pointers(tmp_path, capsys):
    """A flat Cortex-M image linked at 0x08004000: the base that puts its pointers on its
    strings; `--base auto` loads it there and `relic info` suggests it."""
    cc = shutil.which("arm-linux-gnueabihf-gcc")
    if cc is None:
        pytest.skip("needs arm-linux-gnueabihf-gcc")
    (tmp_path / "fw.c").write_text(FW_SRC)
    elf, raw = str(tmp_path / "fw.elf"), str(tmp_path / "fw.bin")
    r = subprocess.run([cc, "-O1", "-mcpu=cortex-m0", "-mthumb", "-mfloat-abi=soft", "-nostdlib", "-static",
                        "-no-pie", "-fno-pic", "-Wl,-N", "-Wl,-Ttext=0x08004000", "-Wl,-e,run", "-o", elf,
                        str(tmp_path / "fw.c")], capture_output=True)
    if r.returncode:
        pytest.skip("cannot link a bare-metal image here")
    subprocess.run(["arm-linux-gnueabihf-objcopy", "-O", "binary", "-j", ".text", "-j", ".rodata", "-j", ".data",
                    elf, raw], check=True)
    from relic.loader.rawbase import guess_base
    data = open(raw, "rb").read()
    best = guess_base(data)[0]
    assert best.base == 0x08004000 and best.score >= 4 and "strings" in best.reason
    b = load(raw, "arm", "auto")
    assert b.base == 0x08004000 and b.sections[0].addr == 0x08004000 and "0x8004000" in b.info["base guess"]
    from relic.__main__ import main
    main(["info", "--arch", "arm", raw])
    assert "Base?      0x8004000" in capsys.readouterr().out


def test_raw_firmware_base_from_vector_table():
    """No strings, just a Cortex-M vector table: Thumb handlers inside a 0x08000000 image."""
    import struct

    from relic.loader.rawbase import guess_base
    handlers = [0x08000101, 0x08000201, 0x08000203, 0x08000205, 0x08000207] + [0] * 6 + [0x08000209] * 4
    data = struct.pack("<16I", 0x20002000, *handlers) + b"\x70\x47" * 0x200
    g = guess_base(data)
    assert g[0].base == 0x08000000 and "vector table" in g[0].reason
    assert guess_base(b"\x00" * 64) == [] and load_bytes(data, arch="arm", base="auto").base == 0x08000000
    assert load_bytes(b"\x90" * 64, arch="x86", base="auto").info["base guess"] == "none: loaded at 0"

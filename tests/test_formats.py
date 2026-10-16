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

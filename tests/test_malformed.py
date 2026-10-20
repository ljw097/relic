"""Malformed, truncated and anti-analysis inputs: they load (or fail with a ValueError), and the
analysis neither crashes nor scans what a corrupted header claims."""
import struct
import time

import pytest

from relic.analysis import Analysis
from relic.loader import load, load_bytes


def _analyze(b):
    an = Analysis(b)
    an.sig_paths = []
    return an.run(load_project=False)


def _elf_header(data):
    from io import BytesIO

    from elftools.elf.elffile import ELFFile
    return ELFFile(BytesIO(data))


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(bytes(data))
    return str(p)


def test_truncated_files_raise_value_error(vuln64, tmp_path):
    data = open(vuln64, "rb").read()
    for n in (20, 100, len(data) // 3):
        with pytest.raises(ValueError):
            _analyze(load(_write(tmp_path, f"cut{n}", data[:n])))


@pytest.mark.parametrize("how", ["sstrip", "bad_shoff", "bad_shstrndx"])
def test_elf_without_usable_section_headers(vuln64, tmp_path, how):
    """The kernel runs these (it reads the program headers only); so must the analysis."""
    d = bytearray(open(vuln64, "rb").read())
    if how == "sstrip":
        struct.pack_into("<Q", d, 0x28, 0)                       # e_shoff
        struct.pack_into("<HH", d, 0x3C, 0, 0)                   # e_shnum, e_shstrndx
    elif how == "bad_shoff":
        struct.pack_into("<Q", d, 0x28, 0xDEADBEEF)
    else:
        struct.pack_into("<H", d, 0x3E, 0xFFFF)
    b = load(_write(tmp_path, how, d))
    assert "section headers" in b.info.get("sections", "")
    assert b.sections and all(s.name.startswith("LOAD") for s in b.sections)
    stubs = {i.name for i in b.imports if i.addr}
    assert {"puts", "gets", "system"} <= stubs
    an = _analyze(b)
    main = an.function_by_name("main")
    assert main is not None
    assert "gets" in {an.name(c) for f in an.functions.values() for c in f.calls}


def test_huge_init_array_size_is_not_scanned(vuln64, tmp_path):
    d = bytearray(open(vuln64, "rb").read())
    elf = _elf_header(bytes(d))
    k = next(i for i, s in enumerate(elf.iter_sections()) if s.name == ".init_array")
    struct.pack_into("<Q", d, elf["e_shoff"] + k * elf["e_shentsize"] + 0x20, 0x3500000000000008)
    t = time.time()
    an = _analyze(load(_write(tmp_path, "initarray", d)))
    assert time.time() - t < 60 and an.function_by_name("main") is not None


def test_huge_pe_virtual_size_is_not_scanned(vuln64_pe, tmp_path):
    import pefile
    d = bytearray(open(vuln64_pe, "rb").read())
    pe = pefile.PE(data=bytes(d), fast_load=True)
    rdata = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".rdata")
    struct.pack_into("<I", d, rdata.get_file_offset() + 8, 0x56000000)   # Misc_VirtualSize
    t = time.time()
    an = _analyze(load(_write(tmp_path, "vsize.exe", d)))
    assert time.time() - t < 60 and an.functions


def test_x86_call_cleanup_before_jmp_is_not_a_tail_call():
    """cdecl `call f; add esp, 4; jmp L` (L 16-aligned): the `add` pops the call's arguments,
    not the frame -- L is this function's own epilogue, not another function."""
    code = bytearray(b"\x90" * 0x50)

    def put(off, bs):
        code[off:off + len(bs)] = bs

    def call(at, to):
        return b"\xe8" + (to - (at + 5)).to_bytes(4, "little", signed=True)
    put(0x00, b"\x55\x89\xe5\x83\x7d\x08\x00\x74\x0e")      # push ebp; mov ebp,esp; cmp [ebp+8],0; je 0x17
    put(0x09, b"\x6a\x01" + call(0x0B, 0x40))               # push 1; call f
    put(0x10, b"\x83\xc4\x04\xeb" + bytes([0x30 - 0x15]))   # add esp,4; jmp 0x30
    put(0x17, b"\x6a\x02" + call(0x19, 0x40))               # push 2; call f
    put(0x1E, b"\x83\xc4\x04")                              # add esp,4 (nops on to 0x30)
    put(0x30, b"\xb8\x00\x00\x00\x00\x5d\xc3")              # mov eax,0; pop ebp; ret
    put(0x40, b"\x8b\x44\x24\x04\xc3")                      # f: mov eax,[esp+4]; ret
    an = _analyze(load_bytes(bytes(code), arch="x86", base=0x1000))
    assert sorted(an.functions) == [0x1000, 0x1040]
    assert not an.functions[0x1000].tail_calls

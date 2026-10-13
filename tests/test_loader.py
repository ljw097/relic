from relic.loader import load, load_bytes


def test_elf_plt_imports(vuln64):
    b = load(vuln64)
    assert b.format == "ELF" and b.arch == "x64" and b.bits == 64
    stubs = {i.name: i.addr for i in b.imports if i.addr}
    for name in ("puts", "printf", "gets", "system", "malloc", "free"):
        assert name in stubs
        assert b.section_at(stubs[name]).name.startswith(".plt")
    assert b.name_of(stubs["gets"]) == "gets"


def test_elf_relocation_names(vuln64):
    b = load(vuln64)
    kinds = {r.kind for r in b.relocs}
    assert "R_X86_64_JUMP_SLOT" in kinds
    data_imports = {i.name for i in b.imports if not i.addr}
    assert "__libc_start_main" in data_imports
    assert any(i.name == "__libc_start_main" for i in b.imports_by_got.values())


def test_memory_reads(vuln64):
    b = load(vuln64)
    win = b.name_to_addr["win"]
    assert b.is_exec(win)
    assert b.read(win, 4) == b"\xf3\x0f\x1e\xfa"  # endbr64
    bss = b.section(".bss")
    assert b.read(bss.addr, 8) == b"\0" * 8


def test_raw_blob():
    b = load_bytes(b"\x31\xc0\xc3", arch="x64", base=0x1000)
    assert b.format == "RAW" and b.entry == 0x1000
    assert b.read(0x1000, 3) == b"\x31\xc0\xc3"
    assert b.name_of(0x1000) == "start"

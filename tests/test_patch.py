"""Byte patches: NOP, branch inversion (every architecture), assembling, project persistence, export, CLI."""
import os
import shutil
import subprocess
import sys

import pytest

from relic.analysis import analyze
from relic.patch import PatchError, assemble, export, invert_bytes, nop_bytes, parse_hex, write

_INV = {"eq": "ne", "ne": "eq", "hs": "lo", "lo": "hs", "cs": "cc", "cc": "cs", "mi": "pl", "pl": "mi", "vs": "vc",
        "vc": "vs", "hi": "ls", "ls": "hi", "ge": "lt", "lt": "ge", "gt": "le", "le": "gt", "cbz": "cbnz",
        "cbnz": "cbz", "tbz": "tbnz", "tbnz": "tbz", "beq": "bne", "bne": "beq", "beqz": "bnez", "bnez": "beqz",
        "blez": "bgtz", "bgtz": "blez", "bltz": "bgez", "bgez": "bltz", "je": "jne", "jne": "je", "jl": "jge",
        "jge": "jl", "jle": "jg", "jg": "jle", "jb": "jae", "jae": "jb", "jbe": "ja", "ja": "jbe", "js": "jns",
        "jns": "js", "jo": "jno", "jno": "jo", "jp": "jnp", "jnp": "jp"}


def _cond(m: str) -> str:
    m = m.split(".")[0] if not m.startswith("b.") else m[2:]
    if m in _INV:
        return m
    if len(m) > 2 and m[-2:] in _INV:                  # A32 / Thumb `bne`, `bxeq`, `popne`
        return m[-2:]
    return m


@pytest.mark.parametrize("variant", ["vuln64", "vuln32", "vuln_arm", "vuln_thumb", "vuln_a64", "vuln_mips",
                                     "flow_O2", "flow_thumb_O2", "flow_a64_O2", "flow_mips_O2"])
def test_every_conditional_branch_inverts(request, variant):
    an = analyze(request.getfixturevalue(variant))
    n = 0
    for f in an.functions.values():
        for blk in f.blocks.values():
            for i in blk.insns:
                if i.kind != "cjmp" or i.mnemonic in ("jcxz", "jecxz", "jrcxz", "loop"):
                    continue
                data = invert_bytes(an, i.addr)
                old = write(an.bin, i.addr, data)
                an.dis._cache.clear()
                j = an.dis.decode(i.addr)
                write(an.bin, i.addr, old)
                an.dis._cache.clear()
                assert j.size == i.size and j.target == i.target, (i, j)
                assert _cond(j.mnemonic) == _INV[_cond(i.mnemonic)], f"{i.mnemonic} {i.op_str} -> {j.mnemonic}"
                n += 1
    assert n > 10


@pytest.mark.parametrize("variant", ["vuln64", "vuln_arm", "vuln_thumb", "vuln_a64", "vuln_mips"])
def test_nop_fills_the_instruction(request, variant):
    an = analyze(request.getfixturevalue(variant))
    vuln = an.function_by_name("vuln")
    call = next(i for b in vuln.blocks.values() for i in b.insns if i.kind == "call" and an.call_name(i) == "gets")
    data = nop_bytes(an, call.addr)
    assert len(data) == call.size
    an.patch(call.addr, data)
    a = call.addr
    while a < call.end:
        i = an.dis.decode(a)
        assert i.mnemonic.startswith("nop"), i
        a = i.end
    from relic.decompiler.emit import decompile
    assert "gets(" not in decompile(an, an.function_by_name("vuln")).text


def test_patch_persists_reverts_and_refuses_bad_ranges(vuln64, tmp_path):
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    an = analyze(str(path))
    win = an.function_by_name("win").addr
    an.rename(win, "shell")
    old = an.patch(win, b"\xc3")
    assert an.dis.decode(win).mnemonic == "ret" and an.name(win) == "shell"        # names survive
    with pytest.raises(PatchError):
        an.patch(win - 1, b"\x90\x90")                                            # overlaps
    with pytest.raises(PatchError):
        an.patch(an.resolve("notes"), b"\x41")                                    # .bss
    an.save_project()
    again = analyze(str(path))
    assert again.patches == {win: (old, b"\xc3")} and again.dis.decode(win).mnemonic == "ret"
    out = export(again.bin, str(tmp_path / "out"))
    data = open(out, "rb").read()
    assert data[again.bin.addr_to_offset(win)] == 0xC3 and os.access(out, os.X_OK)
    assert again.revert(win) and again.bin.read(win, len(old)) == old and again.patches == {}
    assert parse_hex("0x90, 0x90") == b"\x90\x90" and parse_hex("c3") == b"\xc3"


def test_assemble(vuln64):
    pytest.importorskip("keystone")
    an = analyze(vuln64)
    assert assemble(an, 0x401000, "xor eax, eax; ret") == bytes.fromhex("31c0c3")


def test_cli(vuln64, tmp_path):
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    main = analyze(vuln64).function_by_name("main")
    cj = next(i for b in sorted(main.blocks.values(), key=lambda b: b.addr) for i in b.insns if i.kind == "cjmp")

    def relic(*args):
        return subprocess.run([sys.executable, "-m", "relic", *args], capture_output=True, text=True)
    r = relic("patch", str(path), f"{cj.addr:#x}", "--invert")
    assert r.returncode == 0 and "wrote" in r.stdout, r.stderr
    assert os.path.exists(f"{path}.patched")
    assert f"{cj.addr:#x}" in relic("patch", str(path), "--list").stdout
    # the patched program takes the other side of `if (argc > 1)`: no argument now runs vuln()
    p = subprocess.run([f"{path}.patched"], input=b"x\n", capture_output=True, timeout=10)
    assert b"name?" in p.stdout
    r = relic("patch", str(path), "notes", "--bytes", "41")
    assert r.returncode != 0 and "not all in the file" in r.stderr

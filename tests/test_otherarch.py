"""Processors Relic disassembles without decompiling: SPARC (delay slots), SPARC V9, SystemZ,
M68K, eBPF (objects built by clang) and WebAssembly modules -- functions, control flow, names."""
import os
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.disasm import CALL, CJMP, JMP, RET
from relic.listing import function_lines, render

HERE = os.path.dirname(__file__)


@pytest.mark.parametrize("target,arch,flags", [("sparc", "sparc", []), ("sparcv9", "sparc64", []),
                                              ("s390x", "s390x", ["-mno-vx"]), ("m68k", "m68k", []),
                                              ("bpfel", "bpf", [])])
def test_disassembly_only(target, arch, flags, tmp_path):
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("needs clang")
    out = str(tmp_path / "o.o")
    r = subprocess.run([clang, f"--target={target}", "-O2", "-c", "-o", out, *flags,
                        os.path.join(HERE, "src", "otherarch.c")], capture_output=True)
    if r.returncode:
        pytest.skip(f"clang cannot build for {target}")
    an = analyze(out)
    assert an.bin.arch == arch
    work = an.function_by_name("work")
    assert work is not None and an.function_by_name("entry") is not None
    kinds = {i.kind for i in work.insns()}
    # (M68K: the store to `g` waits for a relocation no linker applied -- capstone cannot read it
    # and the paths through it end there)
    assert CJMP in kinds and (RET in kinds or arch == "m68k"), kinds   # (the loop and `s > 100`)
    assert len(work.blocks) >= 3
    # every branch inside the function goes somewhere in it (delay slots, relative offsets)
    for i in work.insns():
        if i.kind in (JMP, CJMP) and i.target is not None:
            assert work.block_at(i.target) is not None, (hex(i.addr), i.mnemonic, i.op_str)
    assert "work:" in render(function_lines(an, work))
    with pytest.raises(NotImplementedError, match="disassembly only"):
        decompile(an, work)


def test_wasm_module(tmp_path):
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("needs clang")
    out = str(tmp_path / "w.wasm")
    r = subprocess.run([clang, "--target=wasm32", "-O1", "-nostdlib", "-Wl,--no-entry", "-Wl,--allow-undefined",
                        "-o", out, os.path.join(HERE, "src", "wasm.c")], capture_output=True)
    if r.returncode:
        pytest.skip("clang cannot build wasm32")
    an = analyze(out)
    assert an.bin.format == "WASM" and an.bin.arch == "wasm"
    work = an.function_by_name("work")
    assert work is not None and [i.name for i in an.bin.imports] == ["printf"]
    call = next(i for i in work.insns() if i.kind == CALL)
    assert an.name(call.target) == "printf"
    assert "call printf" in render(function_lines(an, work))

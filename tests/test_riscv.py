"""RISC-V RV64GC: PLT imports, pc-relative calls and branches, auipc pairs, compressed forms."""
import re

import pytest

from relic.analysis import analyze
from relic.disasm import CALL, CJMP, JMP, RET
from relic.decompiler.emit import decompile

VARIANTS = ["vuln_rv64", "vuln_rv64_pie"]


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.mark.parametrize("variant", VARIANTS)
def test_plt_imports_and_got_data(request, variant):
    an = analyze(request.getfixturevalue(variant))
    b = an.bin
    names = {i.name: i for i in b.imports}
    assert {"puts", "gets", "malloc", "free", "system", "__libc_start_main", "stdout"} <= set(names)
    for name in ("puts", "gets", "system"):
        imp = names[name]
        assert b.section_at(imp.addr).name == ".plt" and an.name(imp.addr) == name
        assert b.imports_by_got[imp.got] is imp
    assert names["stdout"].addr == 0 and b.section_at(names["stdout"].got).name == ".got"
    assert any(r.kind == "R_RISCV_JUMP_SLOT" for r in b.relocs)


@pytest.mark.parametrize("variant", VARIANTS)
def test_branches_calls_and_returns(request, variant):
    an = analyze(request.getfixturevalue(variant))
    kinds = {}
    for f in an.functions.values():
        for blk in f.blocks.values():
            for i in blk.insns:
                kinds.setdefault(i.mnemonic, set()).add(i.kind)
                if i.kind in (CALL, JMP, CJMP) and i.target is not None and i.mnemonic in ("jal", "j", "c.j"):
                    assert an.bin.is_exec(i.target), f"{i.addr:#x} {i.mnemonic} {i.op_str}"
    assert kinds["c.jr"] >= {RET} and kinds["jal"] == {CALL}
    assert CJMP in kinds.get("c.beqz", set()) | kinds.get("bnez", set()) | kinds.get("beqz", set())
    # the PLT stubs (`jalr t1, t3`) are jumps, not calls: no import calls another import
    for f in an.functions.values():
        if f.is_import:
            assert not f.calls


@pytest.mark.parametrize("variant", VARIANTS)
def test_calls_and_strings_through_auipc(request, variant):
    an = analyze(request.getfixturevalue(variant))
    vuln = an.function_by_name("vuln")
    calls = [an.call_name(i) for blk in sorted(vuln.blocks.values(), key=lambda b: b.addr)
             for i in blk.insns if i.kind == CALL]
    printf = "__printf_chk" if variant.endswith("pie") else "printf"
    assert calls[:4] == ["puts", "gets", "checksum", printf]
    for text in ("name?", "hello %s (%d)\n"):
        s = next(s for s in an.strings if s.value == text)
        assert any(vuln.block_at(x.frm) for x in an.xrefs_to[s.addr]), text
    assert any(v.severity == "high" and "gets" in v.message and an.function_at(v.addr) is vuln
               for v in an.vulns())


@pytest.mark.parametrize("variant", VARIANTS)
def test_listing_names_call_targets(request, variant):
    from relic.listing import function_lines
    an = analyze(request.getfixturevalue(variant))
    calls = [f"{ln.mnemonic} {ln.operands}" for ln in function_lines(an, an.function_by_name("vuln"))
             if ln.kind == "insn" and ln.mnemonic == "jal"]
    assert calls[:3] == ["jal puts", "jal gets", "jal checksum"], calls


@pytest.mark.parametrize("variant", VARIANTS)
def test_decompile_vuln_menu_main(request, variant):
    an = analyze(request.getfixturevalue(variant))
    pie = variant.endswith("pie")
    code = _c(an, "vuln")
    assert code.startswith("void vuln(void)") and "gets(buf_" in code and "char buf_" in code
    assert "// stack canary at sp0-" in code
    printf = '__printf_chk(2, "hello %s (%d)\\n", buf_' if pie else 'printf("hello %s (%d)\\n", buf_'
    assert printf in code and ", checksum(buf_" in code, code
    code = _c(an, "menu")
    assert 'puts("1. add");' in code and '__isoc99_scanf("%d", &var_' in code and "exit(1);" in code
    assert "__asm" not in code and "goto" not in code and "(*" not in code
    code = _c(an, "main")
    assert code.startswith("int main(int argc, ") and "while (1) {" in code and "setvbuf(stdout, 0, _IONBF, 0)" in code
    assert "sp - " not in code and "(int64_t)" not in code, code


@pytest.mark.parametrize("variant", VARIANTS)
def test_decompile_switch_and_loops(request, variant):
    an = analyze(request.getfixturevalue(variant))
    code = _c(an, "classify")
    assert "switch (" in code and "case 5:" in code and "default:" in code and "goto" not in code
    code = _c(an, "checksum")
    assert code.startswith("int checksum(char *a1)") and "100000" in code.replace("0x186a1", "100000")
    code = _c(an, "show_note")
    # -O1 tests `0 <= i < 16` as one unsigned compare of the sign-extended index
    assert re.search(r"void show_note\((int|uint64_t) a1\)\n", code) and "(int64_t)" not in code, code
    for f in an.functions.values():
        if not f.is_import:
            text = _c(an, f.name) if an.function_by_name(f.name) is f else ""
            assert text.count("{") == text.count("}"), f.name
            assert "__asm" not in text or f.name.startswith(("_start", "sub_")), f"{f.name}\n{text}"


def test_vulns(vuln_rv64):
    an = analyze(vuln_rv64)
    kinds = {(f.func, f.kind) for f in an.vulns()}
    assert {("vuln", "dangerous-call"), ("show_note", "format-string"), ("win", "win-function")} <= kinds


def test_stripped_finds_main_and_win(vuln_rv64_stripped):
    an = analyze(vuln_rv64_stripped)
    assert an.function_by_name("main") is not None
    win = [f for f in an.functions.values() if not f.is_import and 'system("/bin/sh")' in decompile(an, f).text]
    assert len(win) == 1 and an.name(win[0].addr).startswith("sub_")


# ------------------------------------------------------------------ lifter units
def _lift_one(code: bytes, addr=0x1000):
    from relic.analysis import Analysis
    from relic.decompiler.lift.riscv import RiscVLifter
    from relic.loader import load_raw
    an = Analysis(load_raw("<rv>", code + bytes.fromhex("8280"), "riscv64", addr))      # + ret
    return [str(s) for s in RiscVLifter(an).lift_insn(an.dis.decode(addr))]


@pytest.mark.parametrize("asm,expect", [
    (bytes.fromhex("3305b500"), "a0 = a0 + a1"),                          # add a0, a0, a1
    (bytes.fromhex("3b05b500"), "a0 = sext64(low32(a0) + low32(a1))"),    # addw a0, a0, a1
    (bytes.fromhex("1b050500"), "a0 = sext64(low32(a0))"),                # sext.w a0, a0
    (bytes.fromhex("1385f5ff"), "a0 = a1 - 1"),                          # addi a0, a1, -1
    (bytes.fromhex("3335b500"), "a0 = zext64(a0 <u a1)"),                # sltu a0, a0, a1
    (bytes.fromhex("2fa5b500"), "[tmp1]:32 = tmp3 + tmp2"),              # amoadd.w a0, a1, (a1)
])
def test_lifter_semantics(asm, expect):
    out = _lift_one(asm)
    assert any(expect.replace(" ", "") in o.replace(" ", "") for o in out), out

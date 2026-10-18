"""PowerPC: 32-bit SysV (big-endian) and 64-bit ELFv2 (little-endian) -- PLT call stubs in
`.text`, the record forms and condition-register fields, `ctr` switches, the frame made by
`stwu r1` / `stdu r1`, the stack protector read through the thread pointer."""
import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile
from relic.disasm import CALL, CJMP, JMP, RET

VARIANTS = ["vuln_ppc", "vuln_ppc_pie", "vuln_ppc64", "vuln_ppc64_pie"]


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


@pytest.mark.parametrize("variant", VARIANTS)
def test_call_stubs_are_imports(request, variant):
    """Calls go through stubs in `.text` loading a `.plt` slot into ctr: absolute, or (PIE)
    indexed from the r30 each caller builds."""
    an = analyze(request.getfixturevalue(variant))
    b = an.bin
    names = {i.name: i for i in b.imports if i.addr}
    assert {"puts", "gets", "malloc", "free", "system"} <= set(names), sorted(names)
    for name in ("puts", "gets", "system"):
        imp = names[name]
        assert b.section_at(imp.addr).x and an.name(imp.addr) == name
        assert b.got_names[imp.got] == name


@pytest.mark.parametrize("variant", VARIANTS)
def test_branch_kinds(request, variant):
    an = analyze(request.getfixturevalue(variant))
    kinds = {}
    for f in an.functions.values():
        for blk in f.blocks.values():
            for i in blk.insns:
                kinds.setdefault(i.mnemonic, set()).add(i.kind)
    assert kinds["blr"] == {RET} and kinds["bl"] == {CALL} and CJMP in kinds.get("beq", set()) | \
        kinds.get("bne", set())
    assert JMP in kinds.get("bctr", {JMP})
    vuln = an.function_by_name("vuln")
    calls = [an.call_name(i) for blk in sorted(vuln.blocks.values(), key=lambda b: b.addr)
             for i in blk.insns if i.kind == CALL]
    printf = "__printf_chk" if variant.endswith("pie") else "printf"
    assert calls[:4] == ["puts", "gets", "checksum", printf], calls


@pytest.mark.parametrize("variant", VARIANTS)
def test_decompile_vuln_menu_main(request, variant):
    an = analyze(request.getfixturevalue(variant))
    pie = variant.endswith("pie")
    code = _c(an, "vuln")
    assert code.startswith("void vuln(void)") and "gets(buf_" in code and "char buf_" in code
    assert "// stack canary at sp0-" in code and "tp_base" not in code and "__stack_chk" not in code
    printf = '__printf_chk(2, "hello %s (%d)\\n", buf_' if pie else 'printf("hello %s (%d)\\n", buf_'
    assert printf in code and ", checksum(buf_" in code, code
    code = _c(an, "menu")
    assert 'puts("1. add");' in code and '__isoc99_scanf("%d", &var_' in code and "exit(1);" in code
    assert "__asm" not in code and "goto" not in code and "(*" not in code
    code = _c(an, "main")
    assert code.startswith("int main(int argc, ") and "while (1) {" in code and "setvbuf(stdout, 0, 2, 0)" in code
    assert "r1" not in code and "cr0" not in code, code


@pytest.mark.parametrize("variant", VARIANTS)
def test_decompile_switch_and_loops(request, variant):
    an = analyze(request.getfixturevalue(variant))
    code = _c(an, "classify")
    assert "switch (" in code and "case 5:" in code and "goto" not in code, code
    code = _c(an, "checksum")
    assert code.startswith("int checksum(char *a1)") and "100000" in code.replace("0x186a1", "100000")
    assert "& 255" not in code, code
    for f in an.functions.values():
        if not f.is_import and an.function_by_name(f.name) is f:
            text = _c(an, f.name)
            assert text.count("{") == text.count("}"), f.name
            assert "__asm" not in text or f.name.startswith(("_start", "sub_", "_init", "_fini")), \
                f"{f.name}\n{text}"


def test_vulns(vuln_ppc):
    an = analyze(vuln_ppc)
    kinds = {(f.func, f.kind) for f in an.vulns()}
    assert {("vuln", "dangerous-call"), ("show_note", "format-string"), ("win", "win-function")} <= kinds


@pytest.mark.parametrize("arch", ["ppc", "ppc64"])
def test_stripped_finds_main_and_win(request, arch):
    """`main` from the start-info block `_start` hands __libc_start_main in r8; `win` (only
    reached through nothing) from the prologue scan."""
    an = analyze(request.getfixturevalue(f"vuln_{arch}_stripped"))
    assert an.function_by_name("main") is not None
    win = [f for f in an.functions.values() if not f.is_import and 'system("/bin/sh")' in decompile(an, f).text]
    assert len(win) == 1 and an.name(win[0].addr).startswith("sub_")


# ------------------------------------------------------------------ lifter units
def _lift(words: list[int], addr=0x1000):
    from relic.analysis import Analysis
    from relic.decompiler.lift.ppc import PpcLifter
    from relic.loader import load_raw
    code = b"".join(w.to_bytes(4, "big") for w in words) + (0x4E800020).to_bytes(4, "big")      # + blr
    b = load_raw("<ppc>", code, "ppc", addr)
    b.endian = "big"
    an = Analysis(b)
    lifter = PpcLifter(an)
    out = []
    for k in range(len(words)):
        out += [str(s) for s in lifter.lift_insn(an.dis.decode(addr + 4 * k))]
    return out


@pytest.mark.parametrize("words,expect", [
    ([0x5469103A], "r9 = r3 << 2"),                         # slwi r9, r3, 2
    ([0x5469F0BE], "r9 = r3 >>u 2"),                        # srwi r9, r3, 2
    ([0x5469063E], "r9 = r3 & 0xff"),                       # clrlwi r9, r3, 24
    ([0x7C632214], "r3 = r3 + r4"),                         # add r3, r3, r4
    ([0x7C641850], "r3 = r3 - r4"),                         # subf r3, r4, r3
    ([0x3863FFFF], "r3 = r3 - 1"),                          # addi r3, r3, -1
    ([0x3C601000], "r3 = 0x10000000"),                      # lis r3, 0x1000
    ([0x2C030005], "cr0_lt = r3 <s 5"),                     # cmpwi r3, 5
    ([0x2B830005], "cr7_gt = 5 <u r3"),                     # cmplwi cr7, r3, 5
    ([0x7C631B79], "cr0_eq = r3 == 0"),                     # mr. r3, r3
    ([0x9421FFF0], "r1 = r1 - 0x10"),                       # stwu r1, -16(r1)
    ([0x7C6303D6], "r3 = r3 /s r0"),                        # divw r3, r3, r0
])
def test_lifter_semantics(words, expect):
    out = _lift(words)
    assert any(expect.replace(" ", "") in o.replace(" ", "") for o in out), out

"""MIPS32: GOT-based imports, branch delay slots, $gp-relative data and calls through $t9."""
import pytest

from relic.analysis import analyze
from relic.disasm import CALL, CJMP, JMP, RET

VARIANTS = ["vuln_mips", "vuln_mips_pie"]


@pytest.mark.parametrize("variant", VARIANTS)
def test_imports_come_from_the_global_got(request, variant):
    an = analyze(request.getfixturevalue(variant))
    b = an.bin
    names = {i.name: i for i in b.imports}
    assert {"puts", "gets", "malloc", "free", "system", "__libc_start_main"} <= set(names)
    assert b.mips_gp == b.dynamic["DT_PLTGOT"] + 0x7FF0
    for name in ("puts", "gets", "system"):
        imp = names[name]
        assert b.imports_by_got[imp.got] is imp
        if imp.addr:                                     # a lazy-binding stub in .MIPS.stubs
            assert b.section_at(imp.addr).name == ".MIPS.stubs" and an.name(imp.addr) == name


@pytest.mark.parametrize("variant", VARIANTS)
def test_delay_slots_stay_with_their_branch(request, variant):
    an = analyze(request.getfixturevalue(variant))
    seen = set()             # functions do not overlap: noreturn calls through $t9 end their block
    for f in an.functions.values():
        for blk in f.blocks.values():
            for k, i in enumerate(blk.insns):
                assert i.addr not in seen, f"{i.addr:#x} in two blocks"
                seen.add(i.addr)
                if i.kind in (JMP, CJMP, RET) and i is not blk.insns[-1]:
                    # a branch is followed by its delay slot, which ends the block
                    assert blk.insns[k + 1].delay and k + 2 == len(blk.insns)
            last = blk.last
            if last.kind == CJMP:
                assert blk.insns[-1].delay and last.end + 4 in blk.succs     # falls through past the slot


@pytest.mark.parametrize("variant", VARIANTS)
def test_calls_through_t9_and_strings_through_gp(request, variant):
    an = analyze(request.getfixturevalue(variant))
    vuln = an.function_by_name("vuln")
    calls = [an.call_name(i) for blk in sorted(vuln.blocks.values(), key=lambda b: b.addr)
             for i in blk.insns if i.kind == CALL]
    printf = "__printf_chk" if variant.endswith("pie") else "printf"
    assert calls[:4] == ["puts", "gets", "checksum", printf]
    assert an.function_by_name("checksum").addr not in vuln.blocks          # `bal` is a call
    for text in ("name?", "hello %s (%d)\n"):
        s = next(s for s in an.strings if s.value == text)
        assert any(vuln.block_at(x.frm) for x in an.xrefs_to[s.addr]), text
    assert any(v.severity == "high" and "gets" in v.message and an.function_at(v.addr) is vuln
               for v in an.vulns())

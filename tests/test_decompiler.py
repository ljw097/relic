"""Decompiler stage 1: IR lifting, checked by running the IR on concrete inputs."""
import random

import pytest

from relic.analysis import Analysis, analyze
from relic.decompiler import lift
from relic.decompiler.interp import Interpreter, Machine
from relic.decompiler.ir import CallStmt, IndirectJump, Unknown
from relic.loader import load_bytes

M64 = (1 << 64) - 1
STACK = 0x7FFF0000
RET = 0xDEAD0000


def s64(v):
    v &= M64
    return v - (1 << 64) if v >> 63 else v


# --------------------------------------------------------------- snippets
def run_snippet(code_hex: str, **regs) -> dict:
    """Lift a raw x64 snippet (ending in ret) and run it with the given registers."""
    an = Analysis(load_bytes(bytes.fromhex(code_hex), "<snippet>", "x64", 0x1000)).run()
    fn = lift(an, an.functions[0x1000])
    assert not fn.unknowns()
    m = Machine(an.bin)
    m.regs.update({k: v & M64 for k, v in regs.items()})
    m.regs["rsp"] = STACK
    m.write(STACK, RET, 8)
    Interpreter(fn, m).run()
    return m.regs


SHL_CL = "4839f748d3e20f94c00f92c3c3"

EDGE = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 1 << 63, M64, (1 << 63) - 1, 12345, -7]


@pytest.mark.parametrize("a", EDGE)
@pytest.mark.parametrize("b", EDGE[::3])
def test_cmp_condition_codes(a, b):
    # cmp rdi, rsi ; setl al ; setb bl ; setg cl ; seta dl ; sete r8b ; setle r9b ; setae r10b ; sets r11b ;
    # seto r12b ; setp r13b ; ret
    r = run_snippet("4839f70f9cc00f92c30f9fc10f97c2410f94c0410f9ec1410f93c2410f98c3410f90c4410f9ac5c3",
                    rdi=a, rsi=b, rax=0, rbx=0, rcx=0, rdx=0, r8=0, r9=0, r10=0, r11=0, r12=0, r13=0)
    ua, ub, sa, sb = a & M64, b & M64, s64(a), s64(b)
    diff = (ua - ub) & M64
    assert r["rax"] == (sa < sb)
    assert r["rbx"] == (ua < ub)
    assert r["rcx"] == (sa > sb)
    assert r["rdx"] == (ua > ub)
    assert r["r8"] == (ua == ub)
    assert r["r9"] == (sa <= sb)
    assert r["r10"] == (ua >= ub)
    assert r["r11"] == diff >> 63
    assert r["r12"] == (sa - sb != s64(sa - sb))
    assert r["r13"] == (bin(diff & 0xFF).count("1") % 2 == 0)


@pytest.mark.parametrize("a,b", [(5, 3), (M64, 1), ((1 << 63) - 1, 1), (1 << 63, 1 << 63), (0, 0)])
def test_add_flags(a, b):
    # add rdi, rsi ; setc al ; seto bl ; setz cl ; sets dl ; ret
    r = run_snippet("4801f70f92c00f90c30f94c10f98c2c3", rdi=a, rsi=b, rax=0, rbx=0, rcx=0, rdx=0)
    res = (a + b) & M64
    assert r["rdi"] == res
    assert r["rax"] == (a + b > M64)
    assert r["rbx"] == (s64(a) + s64(b) != s64(res))
    assert r["rcx"] == (res == 0)
    assert r["rdx"] == res >> 63


@pytest.mark.parametrize("a,b", [(100, 7), (-100, 7), (100, -7), (-100, -7), (7, 100), (1 << 62, 3)])
def test_signed_division(a, b):
    # mov rax, rdi ; cqo ; idiv rsi ; mov rcx, rdx ; ret
    r = run_snippet("4889f8489948f7fe4889d1c3", rdi=a, rsi=b)
    q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)  # C truncates toward zero
    assert s64(r["rax"]) == q
    assert s64(r["rcx"]) == a - q * b


def test_unsigned_division_32():
    # mov eax, edi ; xor edx, edx ; div esi ; ret
    r = run_snippet("89f831d2f7f6c3", rdi=0xFFFFFFF0_FFFFFFFF, rsi=10)
    assert r["rax"] == 0xFFFFFFFF // 10 and r["rdx"] == 0xFFFFFFFF % 10


def test_wide_multiply():
    # mov rax, rdi ; mul rsi ; ret
    a, b = 0xFEDCBA9876543210, 0x123456789
    r = run_snippet("4889f848f7e6c3", rdi=a, rsi=b)
    assert r["rax"] == (a * b) & M64 and r["rdx"] == (a * b) >> 64


def test_partial_registers():
    # mov rax, rdi ; mov rdx, rsi ; mov ah, dl ; mov bx, si ; mov ecx, edi ; movsx r8, al ; ret
    r = run_snippet("4889f84889f288d46689f389f94c0fbec0c3",
                    rdi=0x1122334455667788, rsi=0xAABBCCDDEEFF9900, rbx=0x0102030405060708)
    assert r["rax"] == 0x1122334455660088
    assert r["rbx"] == 0x0102030405069900
    assert r["rcx"] == 0x55667788  # 32-bit write clears the upper half
    assert r["r8"] == M64 & -0x78  # sign-extended 0x88


def test_stack_ops():
    # push rsp ; pop rax ; sub rax, rsp ; push rdi ; push rsi ; xchg rdi, rsi ; pop rcx ; pop rdx ; ret
    r = run_snippet("54584829e057564887f7595ac3", rdi=1, rsi=2)
    assert r["rax"] == 0  # push rsp stores the value before the decrement
    assert (r["rdi"], r["rsi"], r["rcx"], r["rdx"]) == (2, 1, 2, 1)
    assert r["rsp"] == STACK  # balanced; `ret` itself is not modelled as a pop


@pytest.mark.parametrize("a,b", [(1, 2), (2, 1), (-5, 3), (0x7FFFFFFF, -1)])
def test_cmov_and_sbb(a, b):
    # cmp edi, esi ; cmovl edi, esi ; mov eax, edi ; sbb rdx, rdx ; ret
    r = run_snippet("39f70f4cfe89f84819d2c3", rdi=a & 0xFFFFFFFF, rsi=b & 0xFFFFFFFF, rdx=7)
    assert r["rax"] == max(a, b) & 0xFFFFFFFF
    assert r["rdx"] == (M64 if (a & 0xFFFFFFFF) < (b & 0xFFFFFFFF) else 0)


def test_shifts_and_neg():
    # mov rax, rdi ; shl rax, 3 ; mov rbx, rdi ; sar rbx, cl ; mov rdx, rdi ; ror rdx, 8 ; neg rsi ; ret
    a = 0x8000_0000_0000_1234
    r = run_snippet("4889f848c1e0034889fb48d3fb4889fa48c1ca0848f7dec3", rdi=a, rcx=4, rsi=5)
    assert r["rax"] == (a << 3) & M64
    assert r["rbx"] == (s64(a) >> 4) & M64
    assert r["rdx"] == ((a >> 8) | (a << 56)) & M64
    assert r["rsi"] == -5 & M64


@pytest.mark.parametrize("count", [0, 1, 4])
def test_variable_shift_flags(count):
    # cmp rdi, rsi ; shl rdx, cl ; setz al ; setc bl ; ret  -- count 0 keeps the cmp flags
    r = run_snippet(SHL_CL, rdi=3, rsi=3, rdx=0x8000_0000_0000_0001, rcx=count, rax=0, rbx=0)
    if count == 0:
        assert (r["rax"], r["rbx"]) == (1, 0)
    else:
        assert r["rdx"] == (0x8000_0000_0000_0001 << count) & M64
        assert (r["rax"], r["rbx"]) == (0, 1 if count == 1 else 0)


# --------------------------------------------------------- sample binaries
def _lift_all(path):
    an = analyze(path)
    return an, {f.addr: lift(an, f) for f in an.functions.values() if not f.is_import}


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie", "vuln64_stripped"])
def test_every_function_lifts(request, variant):
    an, fns = _lift_all(request.getfixturevalue(variant))
    assert fns
    bad = {fn.name: [u.text for u in fn.unknowns()] for fn in fns.values() if fn.unknowns()}
    assert not bad
    for fn in fns.values():
        for b in fn.blocks.values():
            assert b.stmts, f"{fn.name}: empty block {b.addr:#x}"


def _call(an, name, *args, setup=None):
    fn = lift(an, an.function_by_name(name))
    m = Machine(an.bin)
    m.regs.update(rsp=STACK, rbp=0)
    m.write(STACK, RET, 8)
    for reg, v in zip(("rdi", "rsi", "rdx", "rcx"), args):
        m.regs[reg] = v & M64
    if setup:
        setup(m)
    Interpreter(fn, m).run()
    return m.regs["rax"]


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_classify_jump_table(request, variant):
    an = analyze(request.getfixturevalue(variant))
    expect = {0: 10, 1: 22, 2: 37, 3: 41, 4: 59, 5: 63}
    for x in range(-3, 9):
        assert s64(_call(an, "classify", x)) & 0xFFFFFFFF == expect.get(x, -1) & 0xFFFFFFFF
    if variant == "vuln64":
        fn = lift(an, an.function_by_name("classify"))
        ij = [s for s in fn.stmts() if isinstance(s, IndirectJump)]
        assert len(ij) == 1 and len(ij[0].targets) == 6


def _checksum_ref(s: bytes) -> int:
    h = 0
    for c in s:
        c = c - 256 if c >= 128 else c
        h = (h * 31 + c) & 0xFFFFFFFF
        h = h - (1 << 32) if h >> 31 else h
        if h > 100000:
            h ^= 0x1337
    return h & 0xFFFFFFFF


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_checksum_matches_c(request, variant):
    an = analyze(request.getfixturevalue(variant))
    rnd = random.Random(1)
    samples = [b"", b"a", b"hello", b"\xff\x80abc", bytes(rnd.randrange(1, 256) for _ in range(40))]
    for s in samples:
        buf = 0x500000

        def setup(m, s=s):
            m.write_bytes(buf, s + b"\0")

        assert _call(an, "checksum", buf, setup=setup) & 0xFFFFFFFF == _checksum_ref(s)


def test_calls_are_marked(vuln64):
    an = analyze(vuln64)
    fn = lift(an, an.function_by_name("menu"))
    calls = [s for s in fn.stmts() if isinstance(s, CallStmt)]
    names = {an.name(s.call.target.value) for s in calls}
    assert {"puts", "printf", "exit"} <= names
    assert any(s.noreturn for s in calls if an.name(s.call.target.value) == "exit")


def test_unknown_instructions_are_kept():
    # cpuid is an Effect; an x87 instruction (fld1) has no model and stays as Unknown
    an = Analysis(load_bytes(bytes.fromhex("0fa2d9e8c3"), "<snippet>", "x64", 0x1000)).run()
    fn = lift(an, an.functions[0x1000])
    assert [u.text for u in fn.unknowns()] == ["fld1"]
    assert isinstance(fn.unknowns()[0], Unknown)
    assert 'cpuid()' in str(fn) and '__asm("fld1")' in str(fn)

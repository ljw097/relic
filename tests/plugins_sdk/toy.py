"""A plugin adding a file format and a processor module (tests/test_scripting.py): a `RLC1`
file is a header, then code for the `toy` processor -- 2-byte instructions:
01 xx nop, 02 rr call +rr, 03 rr jmp +rr, 04 rr jz +rr, 05 00 ret (rr: signed offset in
instructions from the next one)."""
from relic.disasm import CALL, CJMP, JMP, NORMAL, RET, Insn
from relic.loader import load_raw

BASE = 0x1000


def detect(data, path):
    return data[:4] == b"RLC1"


def load(data, path):
    b = load_raw(path, data[4:], "toy", BASE)
    b.format = "RLC1"
    return b


def decode(code, addr):
    if len(code) < 2:
        return None
    op, arg = code[0], code[1]
    rel = (arg - 256 if arg & 0x80 else arg) * 2
    nxt = addr + 2
    if op == 1:
        return Insn(addr, 2, "nop", "", code[:2], NORMAL)
    if op in (2, 3, 4):
        t = nxt + rel
        kind = {2: CALL, 3: JMP, 4: CJMP}[op]
        return Insn(addr, 2, {2: "call", 3: "jmp", 4: "jz"}[op], f"{t:#x}", code[:2], kind, target=t)
    if op == 5:
        return Insn(addr, 2, "ret", "", code[:2], RET)
    return None


def register(api):
    api.add_loader("rlc1", detect, load)
    api.add_processor("toy", decode, bits=32)
    api.on_decompile(lambda an, func, lines: None)

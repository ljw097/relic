"""Pwnable-oriented heuristics: dangerous calls, format strings, win functions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..disasm import CALL, Insn

if TYPE_CHECKING:
    from . import Analysis

X64_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

DANGEROUS = {
    "gets": ("high", "gets() never checks bounds: stack/heap overflow"),
    "_gets": ("high", "gets() never checks bounds: stack/heap overflow"),
    "strcpy": ("medium", "strcpy() is unbounded"),
    "strcat": ("medium", "strcat() is unbounded"),
    "sprintf": ("medium", "sprintf() is unbounded"),
    "vsprintf": ("medium", "vsprintf() is unbounded"),
    "wcscpy": ("medium", "wcscpy() is unbounded"),
    "lstrcpyA": ("medium", "lstrcpyA() is unbounded"),
    "system": ("info", "system() call"),
    "execve": ("info", "execve() call"),
    "mprotect": ("info", "mprotect() call (may make memory executable)"),
    "free": ("info", "free() call (check for UAF / double free)"),
}

# function -> index of the format argument
FORMAT_ARG = {
    "printf": 0, "vprintf": 0, "wprintf": 0,
    "fprintf": 1, "dprintf": 1, "sprintf": 1, "vfprintf": 1, "vdprintf": 1, "vsprintf": 1, "syslog": 1,
    "snprintf": 2, "vsnprintf": 2, "__printf_chk": 1, "__fprintf_chk": 2,
    "scanf": 0, "__isoc99_scanf": 0, "__isoc23_scanf": 0,
    "fscanf": 1, "sscanf": 1, "__isoc99_fscanf": 1, "__isoc99_sscanf": 1,
}

_ALIAS = {}
for _r64, _rs in {
    "rax": ("eax", "ax", "al"), "rbx": ("ebx", "bx", "bl"), "rcx": ("ecx", "cx", "cl"),
    "rdx": ("edx", "dx", "dl"), "rsi": ("esi", "si", "sil"), "rdi": ("edi", "di", "dil"),
    "rbp": ("ebp", "bp", "bpl"), "rsp": ("esp", "sp", "spl"),
}.items():
    for _r in _rs:
        _ALIAS[_r] = _r64
for _n in range(8, 16):
    for _suf in ("d", "w", "b"):
        _ALIAS[f"r{_n}{_suf}"] = f"r{_n}"


def canon(reg: str) -> str:
    return _ALIAS.get(reg, reg)


@dataclass
class Finding:
    addr: int
    func: str
    severity: str  # high | medium | low | info
    kind: str
    message: str


def resolve_reg(insns: list[Insn], idx: int, reg: str, depth: int = 4) -> tuple[str, int | None]:
    """Walk back from insns[idx] to find what `reg` holds.

    Returns ("const", addr) for an address/immediate, ("var", None) for anything
    else that was written in-block, ("unknown", None) if nothing writes it."""
    reg = canon(reg)
    for k in range(idx - 1, -1, -1):
        i = insns[k]
        if i.kind == CALL:
            return "unknown", None
        if reg not in (canon(r) for r in i.regs_write):
            continue
        ops = i.cs.operands
        if i.mnemonic in ("lea", "mov", "movabs") and len(ops) == 2:
            src = ops[1]
            if src.type == 2:  # imm
                return "const", src.imm & ((1 << 64) - 1)
            if i.mnemonic == "lea" and i.refs:
                return "const", i.refs[0]
            if src.type == 1 and depth > 0:  # reg copy
                return resolve_reg(insns, k, i.cs.reg_name(src.reg), depth - 1)
        if i.mnemonic == "xor" and len(ops) == 2 and ops[0].type == 1 and ops[1].type == 1 and ops[0].reg == ops[1].reg:
            return "const", 0
        return "var", None
    return "unknown", None


def find_vulns(an: "Analysis") -> list[Finding]:
    b = an.bin
    out: list[Finding] = []
    for f in an.functions.values():
        if f.is_import:
            continue
        for blk in f.blocks.values():
            insns = blk.insns
            for idx, i in enumerate(insns):
                if i.kind != CALL:
                    continue
                name = an.call_name(i)
                if not name:
                    continue
                base = name.split("@")[0]
                if base in DANGEROUS:
                    sev, msg = DANGEROUS[base]
                    out.append(Finding(i.addr, f.name, sev, "dangerous-call", msg))
                if b.arch != "x64":
                    continue
                if base in FORMAT_ARG:
                    reg = X64_ARGS[FORMAT_ARG[base]]
                    state, val = resolve_reg(insns, idx, reg)
                    fmt = b.read_cstring(val) if state == "const" and val else None
                    if state == "var" or (state == "const" and fmt is None):
                        if "scanf" not in base:
                            out.append(Finding(i.addr, f.name, "high", "format-string",
                                               f"{base}() called with a non-constant format string"))
                    elif fmt is not None and "scanf" in base and _unbounded_scanf(fmt):
                        out.append(Finding(i.addr, f.name, "high", "scanf-overflow",
                                           f'{base}("{fmt}") reads a string without a width'))
                    elif fmt is not None and base == "printf" and b.is_writable(val):
                        out.append(Finding(i.addr, f.name, "medium", "format-string",
                                           f"{base}() format string lives in writable memory"))
                if base in ("system", "execve", "execl", "execv", "popen"):
                    state, val = resolve_reg(insns, idx, "rdi")
                    cmd = b.read_cstring(val) if state == "const" and val else None
                    if cmd and ("/sh" in cmd or "cat " in cmd or "flag" in cmd):
                        out.append(Finding(f.addr, f.name, "info", "win-function",
                                           f'{f.name} runs {base}("{cmd}") - ret2win target?'))
    sev = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda x: (sev.get(x.severity, 9), x.addr))
    return out


def _unbounded_scanf(fmt: str) -> bool:
    k = 0
    while True:
        k = fmt.find("%", k)
        if k < 0 or k + 1 >= len(fmt):
            return False
        j = k + 1
        if fmt[j] == "%":
            k = j + 1
            continue
        if fmt[j] == "*":
            j += 1
        width = j
        while j < len(fmt) and fmt[j].isdigit():
            j += 1
        while j < len(fmt) and fmt[j] in "hlLqjzt":
            j += 1
        if j < len(fmt) and (fmt[j] == "s" or fmt[j] == "[") and j == width:
            return True
        k = j

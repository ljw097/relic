"""Pwnable-oriented heuristics: dangerous calls, format strings, win functions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..disasm import CALL, Insn
from ..progress import Cancelled, report

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
            # the previous call's result (`mov rdi, rax` after it) is certainly not a constant
            return ("var", None) if reg in ("rax", "eax") else ("unknown", None)
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


def _ir_args(an: "Analysis", f, cache: dict) -> dict[int, tuple] | None:
    """Call arguments of `f` as the decompiler recovered them: call address -> args.

    Works for every calling convention the decompiler models (x64 SysV/Win64,
    x86 cdecl), seeing through register copies, stack slots and PIC thunks.
    None when the architecture has no lifter yet (the caller falls back to
    the in-block register walk).
    """
    if f.addr in cache:
        return cache[f.addr]
    res = None
    if an.bin.arch in ("x64", "x86", "arm64", "arm", "mips", "mips64", "riscv64"):
        try:
            from ..decompiler.cleanup import cached_ir
            from ..decompiler.ir import CallStmt
            res = {s.addr: s.call.args for s in cached_ir(an, f).stmts() if isinstance(s, CallStmt)}
        except Cancelled:
            raise
        except Exception:  # noqa: BLE001 - a decompiler failure must not hide the other findings
            res = None
    cache[f.addr] = res
    return res


def _arg_state(args: tuple, k: int) -> tuple[str, int | None]:
    from ..decompiler.ir import Const
    if k >= len(args):
        return "unknown", None
    a = args[k]
    return ("const", a.value) if isinstance(a, Const) else ("var", None)


def find_vulns(an: "Analysis") -> list[Finding]:
    b = an.bin
    out: list[Finding] = []
    ir_cache: dict = {}
    # integer argument registers of the binary's calling convention (SysV or Win64)
    regs = ("rcx", "rdx", "r8", "r9") if b.format in ("PE", "COFF") else X64_ARGS
    total = len(an.functions)
    for k, f in enumerate(an.functions.values()):
        report("vulns", k, total)
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
                if b.arch not in ("x64", "x86", "arm64", "arm", "mips", "mips64", "riscv64"):
                    continue

                def arg(k, reg, f=f, i=i, insns=insns, idx=idx):
                    # x64: the quick in-block register walk first; only when the value comes from
                    # outside the block ask the decompiler, which follows it across blocks
                    # (x86 passes arguments on the stack: always the decompiler)
                    if b.arch == "x64":
                        state, val = resolve_reg(insns, idx, reg)
                        if state != "unknown":          # settled within the block
                            return state, val
                    ir = _ir_args(an, f, ir_cache)
                    args = ir.get(i.addr) if ir else None
                    if args is None:
                        return resolve_reg(insns, idx, reg) if b.arch == "x64" else ("unknown", None)
                    return _arg_state(args, k)

                fmt_k = FORMAT_ARG.get(base, an.user_types.get("formats", {}).get(base))
                if fmt_k is not None:
                    k = fmt_k
                    state, val = arg(k, regs[k] if k < len(regs) else "")
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
                    state, val = arg(0, regs[0])
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

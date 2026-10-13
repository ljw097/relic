"""Per-architecture register conventions used by the architecture-neutral passes."""
from __future__ import annotations

from dataclasses import dataclass

FLAGS = ("zf", "cf", "sf", "of", "pf")


@dataclass(frozen=True)
class ArchInfo:
    name: str
    bits: int
    sp: str
    ret: str  # return value register
    call_reads: tuple[str, ...]  # registers a call may read (argument registers, stack pointer)
    call_clobbers: tuple[str, ...]  # registers whose value is unknown after a call
    syscall_reads: tuple[str, ...] = ()
    syscall_clobbers: tuple[str, ...] = ()


_X64_SCRATCH = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", *FLAGS,
                *(f"xmm{k}" for k in range(16)))

X64_SYSV = ArchInfo(
    "x64-sysv", 64, "rsp", "rax",
    call_reads=("rdi", "rsi", "rdx", "rcx", "r8", "r9", "rax", "rsp", *(f"xmm{k}" for k in range(8))),
    call_clobbers=_X64_SCRATCH,
    syscall_reads=("rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"),
    syscall_clobbers=("rax", "rcx", "r11"),
)

X64_WIN = ArchInfo(
    "x64-win", 64, "rsp", "rax",
    call_reads=("rcx", "rdx", "r8", "r9", "rsp", *(f"xmm{k}" for k in range(4))),
    call_clobbers=("rax", "rcx", "rdx", "r8", "r9", "r10", "r11", *FLAGS, *(f"xmm{k}" for k in range(6))),
)

X86_CDECL = ArchInfo(
    "x86-cdecl", 32, "esp", "eax",
    call_reads=("esp", "ecx", "edx"),  # ecx/edx: thiscall / fastcall
    call_clobbers=("eax", "ecx", "edx", *FLAGS),
    syscall_reads=("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"),
    syscall_clobbers=("eax",),
)


def arch_for(binary) -> ArchInfo:
    if binary.arch == "x64":
        return X64_WIN if binary.format == "PE" else X64_SYSV
    if binary.arch == "x86":
        return X86_CDECL
    raise NotImplementedError(f"no calling convention for {binary.arch} yet")

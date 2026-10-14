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


_A64_ARGS = tuple(f"x{k}" for k in range(8))
ARM64 = ArchInfo(
    "arm64-aapcs", 64, "sp", "x0",
    call_reads=(*_A64_ARGS, "sp", *(f"v{k}" for k in range(8))),
    # x0-x18 are caller-saved (x16/x17 are the linker's veneer scratch, x18 the platform
    # register); a call also overwrites the link register
    call_clobbers=(*(f"x{k}" for k in range(19)), "x30", *FLAGS, *(f"v{k}" for k in range(8)),
                   *(f"v{k}" for k in range(16, 32))),
    syscall_reads=("x8", "x0", "x1", "x2", "x3", "x4", "x5"),
    syscall_clobbers=("x0",),
)


_A32_ARGS = ("r0", "r1", "r2", "r3")
ARM = ArchInfo(
    "arm-aapcs", 32, "sp", "r0",
    call_reads=(*_A32_ARGS, "sp"),
    # r0-r3 and the intra-procedure scratch r12 are caller-saved; a call also overwrites lr
    call_clobbers=(*_A32_ARGS, "r12", "lr", *FLAGS),
    syscall_reads=("r7", "r0", "r1", "r2", "r3", "r4", "r5", "r6"),
    syscall_clobbers=("r0",),
)


_MIPS_ARGS = ("a0", "a1", "a2", "a3")
MIPS_O32 = ArchInfo(
    "mips-o32", 32, "sp", "v0",
    call_reads=(*_MIPS_ARGS, "sp"),
    # at, v0-v1, a0-a3, t0-t9 and hi/lo are caller-saved; a call also overwrites ra
    call_clobbers=("at", "v0", "v1", *_MIPS_ARGS, *(f"t{k}" for k in range(10)), "ra", "hi", "lo"),
    syscall_reads=("v0", *_MIPS_ARGS),
    syscall_clobbers=("v0", "a3"),
)


def arch_for(binary) -> ArchInfo:
    if binary.arch == "x64":
        return X64_WIN if binary.format == "PE" else X64_SYSV
    if binary.arch == "x86":
        return X86_CDECL
    if binary.arch == "arm64":
        return ARM64
    if binary.arch == "arm":
        return ARM
    if binary.arch == "mips" and binary.bits == 32:
        return MIPS_O32
    raise NotImplementedError(f"no calling convention for {binary.arch} yet")

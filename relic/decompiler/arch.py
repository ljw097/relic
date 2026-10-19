"""Per-architecture register conventions used by the architecture-neutral passes."""
from __future__ import annotations

from dataclasses import dataclass, replace

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
# Apple's arm64 ABI: the same registers, but variadic arguments always on the stack
ARM64_APPLE = replace(ARM64, name="arm64-aapcs-apple")


_A32_ARGS = ("r0", "r1", "r2", "r3")
ARM = ArchInfo(
    "arm-aapcs", 32, "sp", "r0",
    call_reads=(*_A32_ARGS, "sp"),
    # r0-r3 and the intra-procedure scratch r12 are caller-saved; a call also overwrites lr
    call_clobbers=(*_A32_ARGS, "r12", "lr", *FLAGS),
    syscall_reads=("r7", "r0", "r1", "r2", "r3", "r4", "r5", "r6"),
    syscall_clobbers=("r0",),
)


# hard-float (armhf): floats in s0-s15 / d0-d7 as well; d0-d7 and d16-d31 are caller-saved
ARM_VFP = ArchInfo(
    "arm-aapcs-vfp", 32, "sp", "r0",
    call_reads=(*_A32_ARGS, "sp", *(f"d{k}" for k in range(8))),
    call_clobbers=(*_A32_ARGS, "r12", "lr", *FLAGS, "fpscr_n", "fpscr_z", "fpscr_c", "fpscr_v",
                   *(f"d{k}" for k in range(8)), *(f"d{k}" for k in range(16, 32))),
    syscall_reads=ARM.syscall_reads,
    syscall_clobbers=ARM.syscall_clobbers,
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


_N64_ARGS = tuple(f"a{k}" for k in range(8))
MIPS_N64 = ArchInfo(
    "mips-n64", 64, "sp", "v0",
    call_reads=(*_N64_ARGS, "sp"),
    # n64: at, v0-v1, a0-a7, t0-t3, t8-t9 and hi/lo are caller-saved (gp is callee-saved)
    call_clobbers=("at", "v0", "v1", *_N64_ARGS, "t0", "t1", "t2", "t3", "t8", "t9", "ra", "hi", "lo"),
    syscall_reads=("v0", *_N64_ARGS[:6]),
    syscall_clobbers=("v0", "a3"),
)


_PPC_ARGS = tuple(f"r{k}" for k in range(3, 11))
_PPC_CR_SCRATCH = tuple(f"cr{n}_{b}" for n in (0, 1, 5, 6, 7) for b in ("lt", "gt", "eq", "so"))
PPC32 = ArchInfo(
    "ppc32-sysv", 32, "r1", "r3",
    call_reads=(*_PPC_ARGS, "r1", *(f"f{k}" for k in range(1, 9))),
    # r0, r3-r12, ctr, lr, the carry and cr0-1 / cr5-7 are caller-saved; f0-f13 too
    call_clobbers=("r0", *(f"r{k}" for k in range(3, 13)), "ctr", "lr", "ca", *_PPC_CR_SCRATCH,
                   *(f"f{k}" for k in range(14))),
    syscall_reads=("r0", *_PPC_ARGS[:6]),
    syscall_clobbers=("r3", "cr0_so"),
)
PPC64 = ArchInfo(
    "ppc64-elfv2", 64, "r1", "r3",
    call_reads=(*_PPC_ARGS, "r1", *(f"f{k}" for k in range(1, 14))),
    call_clobbers=("r0", *(f"r{k}" for k in range(3, 13)), "ctr", "lr", "ca", *_PPC_CR_SCRATCH,
                   *(f"f{k}" for k in range(14))),
    syscall_reads=("r0", *_PPC_ARGS[:6]),
    syscall_clobbers=("r3", "cr0_so"),
)


_RV_ARGS = tuple(f"a{k}" for k in range(8))
_RV_FARGS = tuple(f"fa{k}" for k in range(8))
RISCV64 = ArchInfo(
    "riscv64-lp64d", 64, "sp", "a0",
    call_reads=(*_RV_ARGS, "sp", *_RV_FARGS),
    # ra, t0-t6, a0-a7 and ft0-ft11, fa0-fa7 are caller-saved
    call_clobbers=("ra", *(f"t{k}" for k in range(7)), *_RV_ARGS, *(f"ft{k}" for k in range(12)), *_RV_FARGS),
    syscall_reads=("a7", *_RV_ARGS[:6]),
    syscall_clobbers=("a0",),
)
RISCV32 = ArchInfo(
    "riscv32-ilp32d", 32, "sp", "a0",
    call_reads=RISCV64.call_reads, call_clobbers=RISCV64.call_clobbers,
    syscall_reads=RISCV64.syscall_reads, syscall_clobbers=RISCV64.syscall_clobbers,
)


def sext_ints(arch: ArchInfo) -> bool:
    """Whether 32-bit integers live sign-extended in 64-bit registers (RISC-V, MIPS n64)."""
    return arch.name.startswith(("riscv64", "mips-n64", "ppc64"))


def arch_for(binary) -> ArchInfo:
    if binary.arch == "x64":
        return X64_WIN if binary.format in ("PE", "COFF") else X64_SYSV
    if binary.arch == "x86":
        return X86_CDECL
    if binary.arch == "arm64":
        return ARM64_APPLE if binary.format == "Mach-O" else ARM64
    if binary.arch == "arm":
        return ARM_VFP if getattr(binary, "arm_hard_float", False) else ARM
    if binary.arch == "mips" and binary.bits == 32:
        return MIPS_O32
    if binary.arch == "mips64":
        return MIPS_N64
    if binary.arch == "riscv64":
        return RISCV64
    if binary.arch == "riscv32":
        return RISCV32
    if binary.arch == "ppc":
        return PPC32
    if binary.arch == "ppc64":
        return PPC64
    from ..disasm import DISASM_ONLY
    if binary.arch in DISASM_ONLY:
        raise NotImplementedError(f"{binary.arch}: disassembly only, no decompiler for this processor")
    raise NotImplementedError(f"no calling convention for {binary.arch} yet")

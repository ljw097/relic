"""Names of the constants C library and system calls take: `open(path, O_WRONLY | O_CREAT)`,
`mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)`, `signal(SIGALRM, f)`,
`setvbuf(stdout, 0, _IONBF, 0)`. Values are Linux's; where a processor's differ (MIPS, and for a
few flags ARM / PowerPC), only the processors whose values are listed get names.
"""
from __future__ import annotations

_PROT = {"PROT_NONE": 0, "PROT_READ": 1, "PROT_WRITE": 2, "PROT_EXEC": 4}
_MAP = {"MAP_SHARED": 1, "MAP_PRIVATE": 2, "MAP_FIXED": 0x10, "MAP_ANONYMOUS": 0x20, "MAP_GROWSDOWN": 0x100,
        "MAP_DENYWRITE": 0x800, "MAP_EXECUTABLE": 0x1000, "MAP_LOCKED": 0x2000, "MAP_NORESERVE": 0x4000,
        "MAP_POPULATE": 0x8000, "MAP_NONBLOCK": 0x10000, "MAP_STACK": 0x20000, "MAP_HUGETLB": 0x40000,
        "MAP_FIXED_NOREPLACE": 0x100000}
_O_ACC = {"O_RDONLY": 0, "O_WRONLY": 1, "O_RDWR": 2}
_O = {"O_CREAT": 0x40, "O_EXCL": 0x80, "O_NOCTTY": 0x100, "O_TRUNC": 0x200, "O_APPEND": 0x400,
      "O_NONBLOCK": 0x800, "O_DSYNC": 0x1000, "O_ASYNC": 0x2000, "O_DIRECT": 0x4000, "O_DIRECTORY": 0x10000,
      "O_NOFOLLOW": 0x20000, "O_NOATIME": 0x40000, "O_CLOEXEC": 0x80000, "O_PATH": 0x200000}
_O_ARM = dict(_O, O_DIRECTORY=0x4000, O_NOFOLLOW=0x8000, O_DIRECT=0x10000)   # (ARM / AArch64 fcntl.h)
_SIG = {"SIGHUP": 1, "SIGINT": 2, "SIGQUIT": 3, "SIGILL": 4, "SIGTRAP": 5, "SIGABRT": 6, "SIGBUS": 7,
        "SIGFPE": 8, "SIGKILL": 9, "SIGUSR1": 10, "SIGSEGV": 11, "SIGUSR2": 12, "SIGPIPE": 13, "SIGALRM": 14,
        "SIGTERM": 15, "SIGCHLD": 17, "SIGCONT": 18, "SIGSTOP": 19, "SIGTSTP": 20, "SIGTTIN": 21, "SIGTTOU": 22,
        "SIGURG": 23, "SIGXCPU": 24, "SIGXFSZ": 25, "SIGVTALRM": 26, "SIGPROF": 27, "SIGWINCH": 28, "SIGSYS": 31}
_SEEK = {"SEEK_SET": 0, "SEEK_CUR": 1, "SEEK_END": 2}
_ACCESS = {"F_OK": 0, "X_OK": 1, "W_OK": 2, "R_OK": 4}
_AF = {"AF_UNSPEC": 0, "AF_UNIX": 1, "AF_INET": 2, "AF_INET6": 10, "AF_NETLINK": 16, "AF_PACKET": 17}
_SOCK = {"SOCK_STREAM": 1, "SOCK_DGRAM": 2, "SOCK_RAW": 3, "SOCK_SEQPACKET": 5}
_SOCK_FLAGS = {"SOCK_NONBLOCK": 0x800, "SOCK_CLOEXEC": 0x80000}
_VBUF = {"_IOFBF": 0, "_IOLBF": 1, "_IONBF": 2}
_WAIT = {"WNOHANG": 1, "WUNTRACED": 2, "WCONTINUED": 8}
_FCNTL = {"F_DUPFD": 0, "F_GETFD": 1, "F_SETFD": 2, "F_GETFL": 3, "F_SETFL": 4, "F_GETLK": 5, "F_SETLK": 6,
          "F_SETLKW": 7, "F_DUPFD_CLOEXEC": 1030}
_PRCTL = {"PR_SET_PDEATHSIG": 1, "PR_GET_DUMPABLE": 3, "PR_SET_DUMPABLE": 4, "PR_SET_NAME": 15, "PR_GET_NAME": 16,
          "PR_GET_SECCOMP": 21, "PR_SET_SECCOMP": 22, "PR_SET_NO_NEW_PRIVS": 38, "PR_GET_NO_NEW_PRIVS": 39}
_PTRACE = {"PTRACE_TRACEME": 0, "PTRACE_PEEKTEXT": 1, "PTRACE_PEEKDATA": 2, "PTRACE_PEEKUSER": 3,
           "PTRACE_POKETEXT": 4, "PTRACE_POKEDATA": 5, "PTRACE_CONT": 7, "PTRACE_KILL": 8, "PTRACE_SINGLESTEP": 9,
           "PTRACE_GETREGS": 12, "PTRACE_SETREGS": 13, "PTRACE_ATTACH": 16, "PTRACE_DETACH": 17, "PTRACE_SYSCALL": 24}
_CLOCK = {"CLOCK_REALTIME": 0, "CLOCK_MONOTONIC": 1, "CLOCK_PROCESS_CPUTIME_ID": 2, "CLOCK_THREAD_CPUTIME_ID": 3,
          "CLOCK_MONOTONIC_RAW": 4, "CLOCK_BOOTTIME": 7}
_SCMP = {"SCMP_ACT_KILL": 0, "SCMP_ACT_KILL_PROCESS": 0x80000000, "SCMP_ACT_TRAP": 0x30000,
         "SCMP_ACT_ERRNO": 0x50000, "SCMP_ACT_LOG": 0x7ffc0000, "SCMP_ACT_ALLOW": 0x7fff0000}
_SHUT = {"SHUT_RD": 0, "SHUT_WR": 1, "SHUT_RDWR": 2}
_LOCK = {"LOCK_SH": 1, "LOCK_EX": 2, "LOCK_NB": 4, "LOCK_UN": 8}

_NO_MIPS = ("x86", "x64", "riscv64", "riscv32", "arm", "arm64", "ppc", "ppc64")

# function -> [(argument index, kind, values, processors)]; kind: "value" (one of them),
# "flags" (an OR of bits), "open" (an access mode plus flags)
TABLE: dict[str, list[tuple]] = {
    "mmap": [(2, "flags", _PROT, None), (3, "flags", _MAP, ("x86", "x64", "riscv64", "riscv32", "arm", "arm64"))],
    "mmap64": [(2, "flags", _PROT, None), (3, "flags", _MAP, ("x86", "x64", "riscv64", "riscv32", "arm", "arm64"))],
    "mprotect": [(2, "flags", _PROT, None)],
    "pkey_mprotect": [(2, "flags", _PROT, None)],
    "open": [(1, "open", _O, ("x86", "x64", "riscv64", "riscv32"))],
    "open64": [(1, "open", _O, ("x86", "x64", "riscv64", "riscv32"))],
    "openat": [(2, "open", _O, ("x86", "x64", "riscv64", "riscv32"))],
    "__open_2": [(1, "open", _O, ("x86", "x64", "riscv64", "riscv32"))],
    "signal": [(0, "value", _SIG, _NO_MIPS)], "sigaction": [(0, "value", _SIG, _NO_MIPS)],
    "raise": [(0, "value", _SIG, _NO_MIPS)], "kill": [(1, "value", _SIG, _NO_MIPS)],
    "sysv_signal": [(0, "value", _SIG, _NO_MIPS)], "bsd_signal": [(0, "value", _SIG, _NO_MIPS)],
    "lseek": [(2, "value", _SEEK, None)], "lseek64": [(2, "value", _SEEK, None)], "fseek": [(2, "value", _SEEK, None)],
    "fseeko": [(2, "value", _SEEK, None)],
    "access": [(1, "flags", _ACCESS, None)], "faccessat": [(2, "flags", _ACCESS, None)],
    "socket": [(0, "value", _AF, None), (1, "socktype", _SOCK, _NO_MIPS)],
    "setvbuf": [(2, "value", _VBUF, None)],
    "waitpid": [(2, "flags", _WAIT, None)], "wait4": [(2, "flags", _WAIT, None)],
    "fcntl": [(1, "value", _FCNTL, _NO_MIPS)], "fcntl64": [(1, "value", _FCNTL, _NO_MIPS)],
    "prctl": [(0, "value", _PRCTL, None)],
    "ptrace": [(0, "value", _PTRACE, ("x86", "x64", "arm", "arm64", "riscv64", "riscv32"))],
    "clock_gettime": [(0, "value", _CLOCK, None)],
    "seccomp_init": [(0, "value", _SCMP, None)], "seccomp_rule_add": [(1, "value", _SCMP, None)],
    "shutdown": [(1, "value", _SHUT, None)], "flock": [(1, "flags", _LOCK, None)],
}
for _f in ("open", "open64", "openat", "__open_2"):
    TABLE[_f] = TABLE[_f] + [(TABLE[_f][0][0], "open", _O_ARM, ("arm", "arm64"))]


def _flags(values: dict[str, int], v: int) -> str | None:
    if v == 0:
        zero = next((n for n, x in values.items() if x == 0), None)
        return zero
    parts, rest = [], v
    for n, x in sorted(values.items(), key=lambda nx: -nx[1]):
        if x and rest & x == x:
            parts.append((x, n))
            rest &= ~x
    if rest or not parts:
        return None
    return " | ".join(n for _, n in sorted(parts))


def constant_name(func: str | None, k: int, value: int, bits: int, arch: str) -> str | None:
    """The symbolic text for constant argument `k` of a call to `func`, or None."""
    from .sigs import base_name
    rows = TABLE.get(base_name(func) or "")
    if not rows:
        return None
    v = value & ((1 << bits) - 1)
    if bits and v >> (bits - 1):
        v -= 1 << bits                          # (negative: none of these)
    if v < 0:
        return None
    for idx, kind, values, arches in rows:
        if idx != k or (arches is not None and arch not in arches):
            continue
        if kind == "value":
            name = next((n for n, x in values.items() if x == v), None)
            if name is not None:
                return name
        elif kind == "flags":
            text = _flags(values, v)
            if text is not None:
                return text
        elif kind == "socktype":
            base = next((n for n, x in values.items() if x == v & 0xff), None)
            extra = _flags(_SOCK_FLAGS, v & ~0xff) if v & ~0xff else None
            if base is not None and (extra is not None or not v & ~0xff):
                return base + (f" | {extra}" if extra else "")
        elif kind == "open":
            acc = next(n for n, x in _O_ACC.items() if x == v & 3)
            rest = v & ~3
            extra = _flags(values, rest) if rest else None
            if rest and extra is None:
                continue
            return acc + (f" | {extra}" if extra else "")
    return None

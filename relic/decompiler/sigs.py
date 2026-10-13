"""Signatures for common libc functions.

Used to recover how many arguments a call takes. Variadic format functions
(`printf`, `scanf`, ...) record the index of their format-string argument;
the argument count is then the fixed prefix plus the number of conversions
in the format literal, when it is a constant string.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Sig:
    argc: int            # number of fixed arguments (format arg included)
    fmt: int | None = None   # index of the printf/scanf-style format argument
    ret: str = "int"
    noreturn: bool = False


SIGS: dict[str, Sig] = {
    # output
    "puts": Sig(1), "putchar": Sig(1), "perror": Sig(1), "fputs": Sig(2), "putc": Sig(2),
    "printf": Sig(1, fmt=0), "fprintf": Sig(2, fmt=1), "dprintf": Sig(2, fmt=1),
    "sprintf": Sig(2, fmt=1, ret="int"), "snprintf": Sig(3, fmt=2),
    "vprintf": Sig(2, fmt=0), "vfprintf": Sig(3, fmt=1), "vsprintf": Sig(3, fmt=1),
    # input
    "gets": Sig(1, ret="char *"), "fgets": Sig(3, ret="char *"), "getchar": Sig(0),
    "scanf": Sig(1, fmt=0), "fscanf": Sig(2, fmt=1), "sscanf": Sig(2, fmt=1),
    "__isoc99_scanf": Sig(1, fmt=0), "__isoc99_fscanf": Sig(2, fmt=1), "__isoc99_sscanf": Sig(2, fmt=1),
    "read": Sig(3, ret="ssize_t"), "write": Sig(3, ret="ssize_t"),
    "fread": Sig(4, ret="size_t"), "fwrite": Sig(4, ret="size_t"),
    # strings / memory
    "strlen": Sig(1, ret="size_t"), "strcpy": Sig(2, ret="char *"), "strncpy": Sig(3, ret="char *"),
    "strcat": Sig(2, ret="char *"), "strncat": Sig(3, ret="char *"),
    "strcmp": Sig(2), "strncmp": Sig(3), "strchr": Sig(2, ret="char *"), "strstr": Sig(2, ret="char *"),
    "strdup": Sig(1, ret="char *"), "strtol": Sig(3, ret="long"), "atoi": Sig(1), "atol": Sig(1, ret="long"),
    "memcpy": Sig(3, ret="void *"), "memmove": Sig(3, ret="void *"), "memset": Sig(3, ret="void *"),
    "memcmp": Sig(3), "bzero": Sig(2, ret="void"),
    # heap / process
    "malloc": Sig(1, ret="void *"), "calloc": Sig(2, ret="void *"), "realloc": Sig(2, ret="void *"),
    "free": Sig(1, ret="void"), "exit": Sig(1, ret="void", noreturn=True),
    "_exit": Sig(1, ret="void", noreturn=True), "abort": Sig(0, ret="void", noreturn=True),
    "system": Sig(1), "setvbuf": Sig(4), "setbuf": Sig(2, ret="void"),
    "fopen": Sig(2, ret="FILE *"), "fclose": Sig(1), "open": Sig(2), "close": Sig(1),
    "sleep": Sig(1, ret="unsigned"), "srand": Sig(1, ret="void"), "rand": Sig(0), "time": Sig(1, ret="time_t"),
    # _FORTIFY_SOURCE variants carry an extra leading flag / trailing object-size argument,
    # so the format index and arg count differ from the plain function
    "__printf_chk": Sig(2, fmt=1), "__fprintf_chk": Sig(3, fmt=2),
    "__sprintf_chk": Sig(4, fmt=3), "__snprintf_chk": Sig(5, fmt=4),
    "__vprintf_chk": Sig(3, fmt=1), "__vfprintf_chk": Sig(4, fmt=2),
    "__memcpy_chk": Sig(4, ret="void *"), "__memmove_chk": Sig(4, ret="void *"),
    "__memset_chk": Sig(4, ret="void *"),
    "__strcpy_chk": Sig(3, ret="char *"), "__strncpy_chk": Sig(4, ret="char *"),
    "__strcat_chk": Sig(3, ret="char *"), "__strncat_chk": Sig(4, ret="char *"),
    "__gets_chk": Sig(2, ret="char *"), "__read_chk": Sig(4, ret="ssize_t"),
}

# %[flags][width][.precision][length]conversion   (width/precision may be `*` = an extra arg)
_CONV = re.compile(r"%([-+ 0#]*)(\*|\d+)?(\.(\*|\d+))?(hh|h|ll|l|j|z|t|L)?([diouxXeEfFgGaAcspn%])")


def base_name(name: str | None) -> str:
    """Strip PLT/version decoration (`printf@plt` -> `printf`).

    Fortified `__*_chk` names are kept intact: they have their own signatures
    because the extra flag / object-size arguments change the shape.
    """
    if not name:
        return ""
    return name.split("@", 1)[0]


def lookup(name: str | None) -> Sig | None:
    return SIGS.get(base_name(name))


def count_conversions(fmt: str) -> int:
    """Number of arguments a format string consumes (`%%` ignored, `*` counts as its own arg)."""
    n = 0
    for m in _CONV.finditer(fmt):
        if m.group(6) == "%":
            continue
        n += 1
        if m.group(2) == "*":
            n += 1
        if m.group(4) == "*":
            n += 1
    return n


def arg_count(sig: Sig, fmt: str | None) -> int:
    """Total argument count: fixed args, plus the format's conversions when known."""
    if sig.fmt is None or fmt is None:
        return sig.argc
    return sig.fmt + 1 + count_conversions(fmt)


__all__ = ["Sig", "SIGS", "base_name", "lookup", "count_conversions", "arg_count"]

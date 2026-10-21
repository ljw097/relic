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
    args: str = ""       # C types of the fixed arguments, one code each (see ARG_TYPES)
    types: tuple[str, ...] = ()   # exact C types of the fixed arguments (from a prototype)
    variadic: bool = False        # more arguments may follow the fixed ones (no format to count them)


# argument type codes: `s` string, `p` memory, `n` size, `F` stream, `i` int; `.` anything else
ARG_TYPES = {"s": "char *", "p": "void *", "n": "size_t", "F": "FILE *", "i": "int"}


def arg_type(sig: Sig, k: int) -> str | None:
    """The C type of fixed argument `k`, when the table knows it."""
    if k < len(sig.types):
        return sig.types[k]
    return ARG_TYPES.get(sig.args[k]) if k < len(sig.args) else None


SIGS: dict[str, Sig] = {
    # output
    "puts": Sig(1, args="s"), "putchar": Sig(1, args="i"), "perror": Sig(1, ret="void", args="s"),
    "fputs": Sig(2, args="sF"), "putc": Sig(2, args="iF"),
    "printf": Sig(1, fmt=0, args="s"), "fprintf": Sig(2, fmt=1, args="Fs"), "dprintf": Sig(2, fmt=1, args="is"),
    "sprintf": Sig(2, fmt=1, ret="int", args="ss"), "snprintf": Sig(3, fmt=2, args="sns"),
    "vprintf": Sig(2, fmt=0, args="s"), "vfprintf": Sig(3, fmt=1, args="Fs"), "vsprintf": Sig(3, fmt=1, args="ss"),
    # input
    "gets": Sig(1, ret="char *", args="s"), "fgets": Sig(3, ret="char *", args="siF"), "getchar": Sig(0),
    "scanf": Sig(1, fmt=0, args="s"), "fscanf": Sig(2, fmt=1, args="Fs"), "sscanf": Sig(2, fmt=1, args="ss"),
    "__isoc99_scanf": Sig(1, fmt=0, args="s"), "__isoc99_fscanf": Sig(2, fmt=1, args="Fs"),
    "__isoc99_sscanf": Sig(2, fmt=1, args="ss"),
    "read": Sig(3, ret="ssize_t", args="ipn"), "write": Sig(3, ret="ssize_t", args="ipn"),
    "fread": Sig(4, ret="size_t", args="pnnF"), "fwrite": Sig(4, ret="size_t", args="pnnF"),
    # strings / memory
    "strlen": Sig(1, ret="size_t", args="s"), "strcpy": Sig(2, ret="char *", args="ss"),
    "strncpy": Sig(3, ret="char *", args="ssn"),
    "strcat": Sig(2, ret="char *", args="ss"), "strncat": Sig(3, ret="char *", args="ssn"),
    "strcmp": Sig(2, args="ss"), "strncmp": Sig(3, args="ssn"), "strchr": Sig(2, ret="char *", args="si"),
    "strrchr": Sig(2, ret="char *", args="si"), "strstr": Sig(2, ret="char *", args="ss"),
    "strdup": Sig(1, ret="char *", args="s"), "strtol": Sig(3, ret="long", args="s.i"),
    "atoi": Sig(1, args="s"), "atol": Sig(1, ret="long", args="s"),
    "memcpy": Sig(3, ret="void *", args="ppn"), "memmove": Sig(3, ret="void *", args="ppn"),
    "memset": Sig(3, ret="void *", args="pin"), "memcmp": Sig(3, args="ppn"), "bzero": Sig(2, ret="void", args="pn"),
    # heap / process
    "malloc": Sig(1, ret="void *", args="n"), "calloc": Sig(2, ret="void *", args="nn"),
    "realloc": Sig(2, ret="void *", args="pn"), "free": Sig(1, ret="void", args="p"),
    "exit": Sig(1, ret="void", noreturn=True, args="i"),
    "_exit": Sig(1, ret="void", noreturn=True, args="i"), "abort": Sig(0, ret="void", noreturn=True),
    "system": Sig(1, args="s"), "setvbuf": Sig(4, args="Fsin"), "setbuf": Sig(2, ret="void", args="Fs"),
    "fopen": Sig(2, ret="FILE *", args="ss"), "fclose": Sig(1, args="F"), "fflush": Sig(1, args="F"),
    "fgetc": Sig(1, args="F"), "getc": Sig(1, args="F"), "fputc": Sig(2, args="iF"),
    "open": Sig(2, args="si", variadic=True), "close": Sig(1, args="i"),
    "sleep": Sig(1, ret="unsigned"), "srand": Sig(1, ret="void"), "rand": Sig(0), "time": Sig(1, ret="time_t"),
    # _FORTIFY_SOURCE variants carry an extra leading flag / trailing object-size argument,
    # so the format index and arg count differ from the plain function
    "__printf_chk": Sig(2, fmt=1, args="is"), "__fprintf_chk": Sig(3, fmt=2, args="Fis"),
    "__sprintf_chk": Sig(4, fmt=3, args="sins"), "__snprintf_chk": Sig(5, fmt=4, args="snins"),
    "__vprintf_chk": Sig(3, fmt=1, args="is"), "__vfprintf_chk": Sig(4, fmt=2, args="Fis"),
    "__memcpy_chk": Sig(4, ret="void *", args="ppnn"), "__memmove_chk": Sig(4, ret="void *", args="ppnn"),
    "__memset_chk": Sig(4, ret="void *", args="pinn"),
    "__strcpy_chk": Sig(3, ret="char *", args="ssn"), "__strncpy_chk": Sig(4, ret="char *", args="ssnn"),
    "__strcat_chk": Sig(3, ret="char *", args="ssn"), "__strncat_chk": Sig(4, ret="char *", args="ssnn"),
    "__gets_chk": Sig(2, ret="char *", args="sn"), "__read_chk": Sig(4, ret="ssize_t", args="ipnn"),
    # Objective-C runtime (objc_msgSend's own arguments are counted from its selector: calls.py)
    "objc_alloc": Sig(1, ret="id", types=("Class",)), "objc_alloc_init": Sig(1, ret="id", types=("Class",)),
    "objc_opt_new": Sig(1, ret="id", types=("Class",)), "objc_opt_class": Sig(1, ret="Class", types=("id",)),
    "objc_retain": Sig(1, ret="id", types=("id",)), "objc_release": Sig(1, ret="void", types=("id",)),
    "objc_autorelease": Sig(1, ret="id", types=("id",)),
    "objc_retainAutoreleasedReturnValue": Sig(1, ret="id", types=("id",)),
    "objc_autoreleaseReturnValue": Sig(1, ret="id", types=("id",)),
    "objc_storeStrong": Sig(2, ret="void", types=("id *", "id")),
    "objc_getProperty": Sig(4, ret="id", types=("id", "SEL", "ptrdiff_t", "BOOL")),
    "objc_setProperty_nonatomic": Sig(4, ret="void", types=("id", "SEL", "id", "ptrdiff_t")),
    "objc_autoreleasePoolPush": Sig(0, ret="void *"), "objc_autoreleasePoolPop": Sig(1, ret="void", args="p"),
}

# message sends: receiver, selector, then one argument per `:` of the selector
OBJC_SENDS = {"objc_msgSend", "objc_msgSendSuper", "objc_msgSendSuper2", "objc_msgSend_stret",
              "objc_msgSend_fpret", "objc_msgSendSuper2_stret"}

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


def lookup(name: str | None, an=None) -> Sig | None:
    """The signature of a library function: a prototype from a header imported into `an` (the
    user's word wins), else the table above, else the bundled libc / POSIX prototypes."""
    base = base_name(name)
    if not base:
        return None
    if an is not None:
        proto = an.user_types.get("prototypes", {}).get(base)
        if proto is not None:
            return sig_of(proto["params"], proto["ret"], proto.get("variadic", False), proto.get("names", ()))
    sig = SIGS.get(base) or bundled().get(base)
    if sig is None and base.startswith("j_") and len(base) > 2:
        return lookup(base[2:], an)             # a jump thunk (analysis/autoname.py) takes what its target does
    return sig


def sig_of(params: list[str], ret: str, variadic: bool, names=()) -> Sig:
    """A Sig for a prototype (C types of its parameters). A variadic function whose last fixed
    parameter is a `char *` named like a format (`fmt`, `format`) counts its arguments from it."""
    fmt = None
    if variadic and params and params[-1] == "char *" and \
            (not names or "fmt" in names[-1].lower() or "format" in names[-1].lower()):
        fmt = len(params) - 1
    return Sig(len(params), fmt, ret, False, "", tuple(params), variadic and fmt is None)


_BUNDLED: dict[str, Sig] | None = None


def bundled() -> dict[str, Sig]:
    """Signatures of the prototypes in `libc_h.LIBC_H` and `win32_h.WIN32_H` (parsed once; libc's
    win where both declare a name, as the sockets functions)."""
    global _BUNDLED
    if _BUNDLED is None:
        from .cheader import parse
        from .libc_h import LIBC_H
        from .win32_h import WIN32_H
        _BUNDLED = {}
        for text in (WIN32_H, LIBC_H):
            for n, p in parse(text).prototypes.items():
                _BUNDLED[n] = sig_of([t.spell() for _, t in p.params], p.ret.spell(), p.variadic,
                                     [pn for pn, _ in p.params])
    return _BUNDLED


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


def format_types(fmt: str, scan: bool = False) -> list[str | None]:
    """C types of the arguments a format string consumes, in order (None: not worth saying):
    `%s` a `char *`; for printf, `%p` a `void *` and `%zu` a `size_t` (scanf's take pointers)."""
    out: list[str | None] = []
    for m in _CONV.finditer(fmt):
        conv = m.group(6)
        if conv == "%":
            continue
        out += [None] * ((m.group(2) == "*") + (m.group(4) == "*"))
        if conv == "s":
            out.append("char *")
        elif conv == "p" and not scan:
            out.append("void *")
        elif m.group(5) == "z" and conv in "diouxX" and not scan:
            out.append("size_t")
        else:
            out.append(None)
    return out


__all__ = ["ARG_TYPES", "Sig", "SIGS", "arg_count", "arg_type", "base_name", "bundled", "count_conversions",
           "format_types", "lookup", "sig_of"]

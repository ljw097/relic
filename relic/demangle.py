"""C++ (Itanium ABI) symbol demangling.

Uses the system's own demangler -- `__cxa_demangle` from libstdc++ through
ctypes, else the `c++filt` tool -- so there is nothing to keep in sync with
the ABI. Without either, names stay mangled.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import functools
import shutil
import subprocess

_cxa = None
_free = None


def _load():
    global _cxa, _free
    if _cxa is not None:
        return _cxa
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("stdc++") or "libstdc++.so.6")
        f = lib.__cxa_demangle
        f.restype = ctypes.c_void_p
        f.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        libc = ctypes.CDLL(ctypes.util.find_library("c") or None)
        _free = libc.free
        _free.argtypes = [ctypes.c_void_p]
        _cxa = f
    except (OSError, AttributeError):
        _cxa = False
    return _cxa


def is_mangled(name: str | None) -> bool:
    return bool(name) and name.startswith("_Z")


@functools.lru_cache(maxsize=65536)
def demangle(name: str) -> str | None:
    """The demangled form of an Itanium C++ name, or None if it is not one / cannot be decoded."""
    if not is_mangled(name):
        return None
    core, _, version = name.partition("@")         # `_ZN...@GLIBCXX_3.4` from dynamic symbols
    f = _load()
    if f:
        status = ctypes.c_int()
        p = f(core.encode(), None, None, ctypes.byref(status))
        if p:
            try:
                return ctypes.string_at(p).decode("utf-8", "replace")
            finally:
                _free(p)
        return None
    tool = shutil.which("c++filt")
    if tool:
        from .sysenv import child_env
        out = subprocess.run([tool, core], capture_output=True, text=True, env=child_env()).stdout.strip()
        return out if out and out != core else None
    return None


def short_name(full: str) -> str:
    """`ns::Cls::method(int, char const*) const` -> `ns::Cls::method` (for call sites)."""
    s = full.strip()
    if s.endswith(" const"):
        s = s[: -len(" const")]
    if not s.endswith(")"):
        return s
    depth = 0
    for k in range(len(s) - 1, -1, -1):
        if s[k] == ")":
            depth += 1
        elif s[k] == "(":
            depth -= 1
            if depth == 0:
                head = s[:k]
                return _drop_return_type(head) if head else s
    return s


def _drop_return_type(head: str) -> str:
    """Template functions carry their return type: `int biggest<int>` -> `biggest<int>`."""
    if "operator" in head:
        return head                      # `operator new`, `operator()`: the space is the name
    depth = 0
    cut = -1
    for k, c in enumerate(head):
        if c in "<(":
            depth += 1
        elif c in ">)":
            depth -= 1
        elif c == " " and depth == 0:
            cut = k
    return head[cut + 1:] if cut >= 0 else head


__all__ = ["demangle", "short_name", "is_mangled"]

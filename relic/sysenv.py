"""The environment for the programs Relic starts: gdb, qemu-user, wine, c++filt.

The stand-alone executables (PyInstaller) point the library search path at their own bundled
libraries; a system program started with it loads those instead of its own and fails (gdb:
"libstdc++.so.6: version `GLIBCXX_3.4.32' not found"). PyInstaller keeps the original value
in `<VAR>_ORIG`: that, or nothing, is what a child process gets.
"""
from __future__ import annotations

import os
import sys

_SEARCH_PATHS = ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH", "LIBPATH")


def child_env(extra: dict | None = None) -> dict:
    """`os.environ` as it was before the bundle changed it (unchanged when run from source), plus
    `extra`."""
    env = dict(os.environ)
    if getattr(sys, "frozen", False):
        for var in _SEARCH_PATHS:
            orig = env.pop(var + "_ORIG", None)
            if orig is not None:
                env[var] = orig
            else:
                env.pop(var, None)
    if extra:
        env.update(extra)
    return env

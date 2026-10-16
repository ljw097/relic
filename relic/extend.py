"""Extension points for plugins (IDA's SDK, in Python): file loaders, processor modules
(instruction decoders) and pseudocode hooks. They work wherever Relic runs -- the GUI, the CLI,
`relic script` -- once a plugin's `register(api)` has added them (scripting.PluginAPI).

A loader is `detect(data, path) -> bool` and `load(data, path) -> Binary`; the first loader
whose `detect` says yes loads the file, before the built-in ELF / PE / raw loaders.

A processor module is `decode(code, addr) -> Insn | None` for an architecture name: `code` is
up to 16 bytes at `addr`. Set `insn.kind` (normal / call / jmp / cjmp / ret / halt) and
`insn.target` for branches so the analysis can follow them. A raw blob loaded with
`--arch NAME` (or a loader that sets `binary.arch = NAME`) is decoded with it.

A decompile hook is `fn(an, func, lines) -> lines or None`: it may change the pseudocode's
lines (`decompiler.emit.Line`: `text`, `addr`, `depth`) before they are shown.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass
class Loader:
    name: str
    detect: Callable
    load: Callable


@dataclass
class Processor:
    name: str
    decode: Callable
    bits: int = 32
    endian: str = "little"


LOADERS: list[Loader] = []
PROCESSORS: dict[str, Processor] = {}
DECOMPILE_HOOKS: list[Callable] = []


def register_loader(name: str, detect: Callable, load: Callable):
    LOADERS[:] = [x for x in LOADERS if x.name != name] + [Loader(name, detect, load)]


def register_processor(name: str, decode: Callable, bits: int = 32, endian: str = "little"):
    PROCESSORS[name] = Processor(name, decode, bits, endian)


def register_decompile_hook(fn: Callable):
    if fn not in DECOMPILE_HOOKS:
        DECOMPILE_HOOKS.append(fn)


def clear():
    """Forget every extension (tests; plugins loaded again)."""
    LOADERS.clear()
    PROCESSORS.clear()
    DECOMPILE_HOOKS.clear()


__all__ = ["DECOMPILE_HOOKS", "LOADERS", "PROCESSORS", "Loader", "Processor", "clear", "register_decompile_hook",
           "register_loader", "register_processor"]

"""Scripting: a Python API over an analysis, an interactive console, plugins and batch scripts.

The same names are available everywhere Python code runs against Relic --
the GUI's Python console, plugins, and `relic script FILE script.py`:

    an, bin             the Analysis and its Binary
    here()              the cursor address (GUI; the entry point / `main` in a script)
    goto(where)         move the GUI cursor (an address or a name)
    addr(where)         a name / `func+0x10` / hex text -> address
    name(a), rename(a, new), comment(a, text)
    func(where)         the Function containing an address or named so
    functions()         every function of the binary (imports excluded)
    xrefs_to(a), xrefs_from(a)
    disasm(where, n)    `n` instructions as text
    decompile(where)    pseudocode of a function
    strings(), search(pattern)   strings; byte-pattern search (`48 8b ?? 05`)
    patch(a, data), nop(a), invert(a), assemble(a, text), revert(a)
    save()              write the project file

Plugins are `.py` files in the directories of `RELIC_PLUGINS` (separated
like PATH) and in `~/.relic/plugins`. A plugin defines `register(api)`; the
`PluginAPI` it receives can add menu actions (`api.add_action("Rename
all", callback, "Ctrl+Alt+R")`) whose callbacks get the scripting
namespace. Hooks: `api.add_line_decorator(fn)` -- `fn(an, line)` returns a
comment and / or a background colour for a listing line (`{"comment": "...",
"color": "#402020"}`); `api.add_listing_comment(fn)` -- the simple form,
`fn(an, addr)` returns text for an instruction's comment; `api.on_analysis(fn)`
-- `fn(ns)` after a binary is analysed (and again after a patch re-analyses
it); `api.on_cursor(fn)` -- `fn(ns, addr)` when the cursor moves. Loading
errors are collected, not raised, and an exception in a hook is reported once
in the Python console: a broken plugin must not keep the GUI from starting.
"""
from __future__ import annotations

import code
import contextlib
import importlib.util
import io
import os
import re
import sys
import traceback
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .analysis import Analysis


class Api:
    """The functions scripts call. `win` is the GUI main window, when there is one."""

    def __init__(self, an: "Analysis", win=None):
        self.an = an
        self.win = win

    # --------------------------------------------------------- addresses
    def addr(self, where) -> int:
        """An address from an int, a name / `func+0x10` / hex text, or anything with `.addr`
        (a Function, a Block, an Xref's `.to` is an int already)."""
        if isinstance(where, int):
            return where
        if hasattr(where, "addr") and isinstance(where.addr, int):
            return where.addr
        a = self.an.resolve(str(where))
        if a is None:
            raise ValueError(f"cannot resolve {where!r}")
        return a

    def here(self) -> int:
        """The cursor address (GUI), else `main` / the entry point."""
        if self.win is not None and self.win.cur is not None:
            return self.win.cur
        main = self.an.function_by_name("main")
        return main.addr if main is not None else self.an.bin.entry

    def goto(self, where) -> bool:
        """Move the GUI cursor to an address or name; whether it could."""
        a = self.addr(where)
        return self.win.goto(a) if self.win is not None else False

    # --------------------------------------------------------- names
    def name(self, where) -> str | None:
        """The name shown for an address (the user's, a symbol, a library signature's), or None."""
        return self.an.name(self.addr(where))

    def rename(self, where, new: str):
        """Name an address (empty restores the original name)."""
        a = self.addr(where)
        if self.win is not None:
            self.win.rename(a, new)
        else:
            self.an.rename(a, new)

    def rename_struct(self, struct: str, name: str):
        """Name a recovered struct by its generated name (`s_notes`)."""
        if self.win is not None:
            self.win.rename_struct(struct, None, name)
        else:
            self.an.rename_struct(struct, name)

    def rename_field(self, struct: str, field: str, name: str):
        """Name a field (`f_8`) of a recovered struct (`s_notes`)."""
        if self.win is not None:
            self.win.rename_struct(struct, field, name)
        else:
            self.an.rename_field(struct, field, name)

    def set_type(self, func, var: str, ctype: str):
        """Give a variable / parameter (`a1`, `v3`, `var_10`) of a function a C type."""
        f = self.func(func)
        if f is None:
            raise ValueError(f"no function at {func!r}")
        self.an.set_var_type(f.addr, var, ctype)
        if self.win is not None:
            self.win._after_edit()

    def import_header(self, text_or_path: str) -> dict:
        """Import C declarations (structs, unions, enums, typedefs, prototypes) from header text or
        a file path; what was imported, by kind."""
        import os
        if "\n" not in text_or_path and os.path.exists(text_or_path):
            with open(text_or_path) as fp:
                text_or_path = fp.read()
        got = self.an.import_header(text_or_path)
        if self.win is not None:
            self.win._after_edit()
        return got

    def export(self, path: str) -> dict:
        """Write every function's pseudocode to a C file; what was written."""
        from .decompiler.export import export_c
        with open(path, "w") as fp:
            return export_c(self.an, fp)

    # -------------------------------------------------- memory and items
    def read(self, where, n: int) -> bytes:
        """`n` bytes of the loaded image (with patches) at an address or name."""
        return self.an.bin.read(self.addr(where), n) or b""

    def read_int(self, where, size: int | None = None, signed: bool = False) -> int | None:
        """A little/big-endian integer (the binary's byte order) of `size` bytes (default: a pointer)."""
        size = size or self.an.bin.bits // 8
        raw = self.an.bin.read(self.addr(where), size)
        return int.from_bytes(raw, self.an.bin.endian, signed=signed) if raw and len(raw) == size else None

    def sections(self) -> list[tuple[str, int, int, str]]:
        """(name, address, size, permissions) of every section."""
        return [(s.name, s.addr, s.size, ("r" if s.r else "-") + ("w" if s.w else "-") + ("x" if s.x else "-"))
                for s in self.an.bin.sections]

    def insn(self, where):
        """The decoded instruction (`relic.disasm.Insn`: `.mnemonic`, `.op_str`, `.size`, `.kind`,
        `.target`, `.refs`) at an address, or None."""
        return self.an.dis.decode(self.addr(where))

    def define(self, where, kind: str, count: int | None = None, element: str = "byte"):
        """Say what is at an address: byte / word / dword / qword / string / array / code (D / A / * / C)."""
        self.an.define_data(self.addr(where), kind, count, element)
        if self.win is not None:
            self.win._after_edit()

    def undefine(self, where):
        """Forget what was said about an address (U)."""
        self.an.undefine(self.addr(where))
        if self.win is not None:
            self.win._after_edit()

    def make_function(self, where):
        """A function starting at an address (P); the analysis runs again."""
        self.an.create_function(self.addr(where))
        if self.win is not None:
            self.win._after_patch(self.addr(where))

    def delete_function(self, where):
        """Remove the function starting at an address; the analysis runs again."""
        a = self.addr(where)
        self.an.delete_function(a)
        if self.win is not None:
            self.win._after_patch(a)

    def bookmark(self, where, text: str):
        """Bookmark an address (empty text removes it)."""
        self.an.bookmark(self.addr(where), text)
        if self.win is not None:
            self.win._after_edit()
            self.win._fill_bookmarks()

    def callers(self, where) -> list[int]:
        """Functions calling the function at / named `where`."""
        from .analysis.callgraph import callers
        f = self.func(where)
        return callers(self.an, f.addr) if f is not None else []

    def callees(self, where) -> list[int]:
        """Functions the function at / named `where` calls."""
        from .analysis.callgraph import callees
        f = self.func(where)
        return callees(self.an, f.addr) if f is not None else []

    def load_type_library(self, name: str | None = None) -> dict:
        """Import a bundled type library (`libc`: struct stat, tm, timeval, sockaddr_in, ...;
        `win32`: HANDLE, DWORD, SYSTEM_INFO, STARTUPINFOA, ... -- the default for a PE)."""
        got = self.an.load_type_library(name)
        if self.win is not None:
            self.win._after_edit()
        return got

    def lumina_pull(self, store: str | None = None, overwrite: bool = False) -> dict:
        """Names / comments / variable names of matching functions from a shared store."""
        got = self.an.lumina_pull(store, overwrite)
        if self.win is not None:
            self.win._after_edit()
        return got

    def lumina_push(self, store: str | None = None) -> dict:
        """Send the functions' names / comments / variable names to a shared store."""
        return self.an.lumina_push(store)

    def rcomment(self, addr, text: str):
        """A repeatable comment: shown at `addr` and wherever it is referred to ("" removes it)."""
        self.an.repeatable_comment(self.addr(addr), text)
        if self.win is not None:
            self.win._after_edit()

    def names(self) -> list[tuple[int, str, str]]:
        """Every named address: (address, name, kind)."""
        return self.an.names()

    def op_format(self, addr, index: int, fmt: str):
        """Show operand `index` of the instruction at `addr` as hex / dec / char / bin / offset
        ("" resets)."""
        self.an.set_operand_format(self.addr(addr), index, fmt)
        if self.win is not None:
            self.win._after_edit()

    def number_format(self, func, value: int, fmt: str):
        """Show the constant `value` in a function's pseudocode as hex / dec / char / bin."""
        f = self.func(func)
        if f is None:
            raise ValueError(f"no function at {func!r}")
        self.an.set_number_format(f.addr, value, fmt)
        if self.win is not None:
            self.win._after_edit()

    def snapshot(self, name: str) -> dict:
        """Keep a named copy of every annotation (saved with the project)."""
        return self.an.take_snapshot(name)

    def restore_snapshot(self, name: str):
        """Put snapshot `name`'s annotations back (undoable)."""
        self.an.restore_snapshot(name)
        if self.win is not None:
            self.win._after_edit()

    def merge(self, path: str, theirs: bool = False) -> dict:
        """Merge another project file of this binary: {"added", "conflicts", "kept"}."""
        got = self.an.merge_project(path, theirs)
        if self.win is not None:
            self.win._after_edit()
        return got

    def set_return_type(self, func, ctype: str):
        """The C type a function returns (`char *`, `void`; empty resets)."""
        f = self.func(func)
        if f is None:
            raise ValueError(f"no function at {func!r}")
        self.an.set_return_type(f.addr, ctype)
        if self.win is not None:
            self.win._after_edit()

    def set_field_type(self, struct: str, field: str, ctype: str):
        """Give a field (`f_8`) of a recovered struct (`s_notes`) a C type."""
        self.an.set_field_type(struct, field, ctype)
        if self.win is not None:
            self.win._after_edit()

    def add_field(self, struct: str, offset: int, ctype: str, name: str = ""):
        """Add a field by hand to a recovered struct (`char[16]`, `int`, `char *`)."""
        self.an.add_field(struct, offset, ctype, name)
        if self.win is not None:
            self.win._after_edit()

    def remove_field(self, struct: str, offset: int):
        """Drop a field of a recovered struct."""
        self.an.remove_field(struct, offset)
        if self.win is not None:
            self.win._after_edit()

    def comment(self, where, text: str):
        """Set the comment at an address (empty removes it)."""
        a = self.addr(where)
        if self.win is not None:
            self.win.comment(a, text)
        else:
            self.an.comment(a, text)

    # --------------------------------------------------------- queries
    def func(self, where=None):
        """The Function containing an address or named so (default: the cursor's), or None."""
        a = self.here() if where is None else self.addr(where)
        return self.an.function_at(a)

    def functions(self) -> list:
        """Every function of the binary, imports excluded, in address order."""
        return [f for f in sorted(self.an.functions.values(), key=lambda f: f.addr) if not f.is_import]

    def xrefs_to(self, where) -> list:
        """The cross references to an address (`.frm`, `.to`, `.kind`)."""
        return list(self.an.xrefs_to.get(self.addr(where), ()))

    def xrefs_from(self, where) -> list:
        """The cross references from an address (`.frm`, `.to`, `.kind`)."""
        return list(self.an.xrefs_from.get(self.addr(where), ()))

    def disasm(self, where=None, n: int = 10) -> str:
        """`n` instructions from an address (default: the cursor), as listing text."""
        a = self.here() if where is None else self.addr(where)
        out = []
        for _ in range(n):
            i = self.an.dis.decode(a)
            if i is None:
                break
            out.append(f"{i.addr:#x}  {i.mnemonic} {i.op_str}".rstrip())
            a = i.end
        return "\n".join(out)

    def decompile(self, where=None) -> str:
        """The pseudocode of the function at / named `where` (default: the cursor's), as text."""
        from .decompiler.emit import decompile
        f = self.func(where)
        if f is None:
            raise ValueError("no function there")
        return decompile(self.an, f).text

    def strings(self) -> list:
        """The strings found in the binary (`.addr`, `.value`, `.encoding`, `.section`)."""
        return list(self.an.strings)

    def search(self, pattern: str) -> list[int]:
        """Addresses where a byte pattern (`48 8b ?? 05`) occurs."""
        from .analysis.search import find_bytes
        return [h.addr for h in find_bytes(self.an, pattern)]

    # --------------------------------------------------------- patches
    def patch(self, where, data: bytes | str):
        """Write bytes (or hex text `90 90`) at an address; the analysis runs again."""
        from .patch import parse_hex
        a = self.addr(where)
        data = parse_hex(data) if isinstance(data, str) else bytes(data)
        if self.win is not None:
            return self.win.patch(a, data)
        return self.an.patch(a, data)

    def nop(self, where):
        """Replace the instruction at an address with NOPs (patch)."""
        from .patch import nop_bytes
        a = self.addr(where)
        return self.patch(a, nop_bytes(self.an, a))

    def invert(self, where):
        """Negate the conditional branch at an address (patch)."""
        from .patch import invert_bytes
        a = self.addr(where)
        return self.patch(a, invert_bytes(self.an, a))

    def assemble(self, where, text: str):
        """Assemble `text` (keystone) at an address and patch it in, NOP-padded to whole instructions."""
        from .patch import assemble, fit
        a = self.addr(where)
        return self.patch(a, fit(self.an, a, assemble(self.an, a, text)))

    def revert(self, where) -> bool:
        """Drop the patch at an address; whether there was one."""
        ok = self.an.revert(self.addr(where))
        if ok and self.win is not None:
            self.win._after_patch(self.win.cur)
        return ok

    def save(self):
        """Write the project file (`<binary>.relic.json`)."""
        if self.win is not None:
            return self.win.save_project()
        self.an.save_project()
        return True


def namespace(an: "Analysis", win=None) -> dict:
    """Globals for console / plugin / script code."""
    api = Api(an, win)
    ns = {"an": an, "bin": an.bin, "api": api, "win": win}
    for n in ("addr", "here", "goto", "name", "rename", "rename_struct", "rename_field", "set_type",
              "set_field_type", "add_field", "remove_field", "comment", "func", "import_header", "set_return_type",
              "export", "snapshot", "restore_snapshot", "merge", "op_format", "number_format", "rcomment", "names",
              "lumina_pull", "lumina_push", "read", "read_int", "sections", "insn", "define", "undefine",
              "make_function", "delete_function", "bookmark", "callers", "callees", "load_type_library",
              "functions", "xrefs_to", "xrefs_from",
              "disasm", "decompile", "strings", "search", "patch", "nop", "invert", "assemble", "revert", "save"):
        ns[n] = getattr(api, n)
    return ns


def reference() -> str:
    """The scripting reference (docs/scripting.md) from the API's docstrings: every name of the
    namespace, the plugin API and the extension points."""
    import inspect

    from . import extend
    names = [n for n in namespace.__code__.co_consts if isinstance(n, tuple)]
    api_names = next(t for t in names if "rename" in t)
    out = ["# Scripting reference", "",
           "Generated from the docstrings by `tools/gen_scripting_docs.py`; `tests/test_scripting.py` checks it",
           "is current.", "", "## The namespace", "",
           "Available in the GUI's Python console, in scripts (`relic script FILE script.py`, File > Run",
           "script) and in plugin callbacks. Besides these: `an` (the Analysis), `bin` (its Binary), `api`",
           "(the object behind them) and `win` (the main window, or None).", ""]
    def sig(fn) -> str:
        text = str(inspect.signature(fn)).replace("(self, ", "(").replace("(self)", "()")
        return re.sub(r"(: |-> )'([^']*)'", r"\1\2", text)     # (annotations are strings here)

    for n in sorted(api_names):
        fn = getattr(Api, n)
        doc = " ".join((inspect.getdoc(fn) or "").split())
        out.append(f"- `{n}{sig(fn)}` -- {doc}")
    out += ["", "## Plugins", "",
            "A plugin is a `.py` file in `~/.relic/plugins` (or a directory of `$RELIC_PLUGINS`) defining",
            "`register(api)`; `api` is a `PluginAPI`:", ""]
    for n, fn in sorted(inspect.getmembers(PluginAPI, inspect.isfunction)):
        if n.startswith("_"):
            continue
        out.append(f"- `{n}{sig(fn)}` -- {' '.join((inspect.getdoc(fn) or '').split())}")
    out += ["", "## Extension points", "", inspect.getdoc(extend), ""]
    return "\n".join(out)


class Console:
    """An interactive interpreter whose output is returned as text (for a GUI console)."""

    def __init__(self, ns: dict):
        self.interp = code.InteractiveConsole(ns)
        self.more = False

    @property
    def prompt(self) -> str:
        return "... " if self.more else ">>> "

    def push(self, line: str) -> str:
        """Run one line (a statement may span several); returns what it printed."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            self.more = self.interp.push(line)
        return buf.getvalue()


def run_script(path: str, ns: dict, argv: list[str] | None = None) -> None:
    """Run a script file with the scripting namespace; `sys.argv` is [path, *argv] meanwhile."""
    with open(path) as fp:
        src = fp.read()
    old = sys.argv
    sys.argv = [path, *(argv or [])]
    try:
        g = dict(ns, __name__="__main__", __file__=path)
        exec(compile(src, path, "exec"), g)
    finally:
        sys.argv = old


# ------------------------------------------------------------------ plugins
def plugin_dirs() -> list[str]:
    dirs = [d for d in os.environ.get("RELIC_PLUGINS", "").split(os.pathsep) if d]
    dirs.append(os.path.join(os.path.expanduser("~"), ".relic", "plugins"))
    return [d for d in dict.fromkeys(dirs) if os.path.isdir(d)]


class PluginAPI:
    """What a plugin's `register(api)` gets: menu actions, and the current scripting namespace."""

    def __init__(self, win, plugin: str):
        self.win = win
        self.plugin = plugin

    def namespace(self) -> dict | None:
        """The scripting namespace of the open binary, or None when nothing is open."""
        an = getattr(self.win, "an", None)
        return namespace(an, self.win) if an is not None else None

    def add_action(self, text: str, callback: Callable[[dict], object], shortcut: str | None = None):
        """A Plugins-menu item; `callback(ns)` runs with the scripting namespace of the open binary
        (GUI only: ignored when the plugin is loaded by the CLI)."""
        if self.win is None:
            return None

        def run():
            ns = self.namespace()
            if ns is None:
                self.win.statusBar().showMessage("open a binary first", 3000)
                return
            try:
                callback(ns)
            except Exception:  # noqa: BLE001 - a plugin bug is reported, the GUI stays up
                self.win.report_plugin_error(self.plugin, traceback.format_exc())
        return self.win.add_plugin_action(text, run, shortcut)

    def _guarded(self, fn, default=None):
        """`fn` with its exceptions reported (once per hook) instead of raised."""
        reported = []

        def call(*args):
            try:
                return fn(*args)
            except Exception:  # noqa: BLE001 - a plugin bug is reported, the GUI stays up
                if not reported:
                    reported.append(True)
                    if self.win is not None:
                        self.win.report_plugin_error(self.plugin, traceback.format_exc())
                    else:
                        print(f"relic: plugin {self.plugin}:\n{traceback.format_exc()}", file=sys.stderr)
                return default
        return call

    # ---------------------------------------------- extension points (relic.extend)
    def add_loader(self, name: str, detect: Callable[[bytes, str], bool], load: Callable[[bytes, str], object]):
        """A file format: `detect(data, path)` -> whether it is one; `load(data, path)` -> a
        `relic.loader.Binary`. Tried before the built-in loaders, in the GUI and the CLI."""
        from .extend import register_loader
        register_loader(name, detect, load)

    def add_processor(self, arch: str, decode: Callable[[bytes, int], object], bits: int = 32,
                      endian: str = "little"):
        """A processor module: `decode(code, addr)` -> a `relic.disasm.Insn` (or None) for the
        architecture `arch` (`relic disasm blob --arch NAME`, or a loader's `binary.arch`)."""
        from .extend import register_processor
        register_processor(arch, decode, bits, endian)

    def on_decompile(self, fn: Callable):
        """`fn(an, func, lines)` -> new lines or None, for every function's pseudocode."""
        from .extend import register_decompile_hook
        register_decompile_hook(self._guarded(fn))

    def on_edit(self, fn: Callable[[dict], object]):
        """`fn(ns)` after any annotation edit, undo or redo (GUI)."""
        if self.win is not None:
            self.win.plugin_hooks["edit"].append(self._guarded(fn))

    def on_debug_stop(self, fn: Callable[[dict, object], object]):
        """`fn(ns, snapshot)` each time the debugged program stops (`snapshot.pc`, `.regs`,
        `.stack`, `.maps`; GUI)."""
        if self.win is not None:
            self.win.plugin_hooks["debug"].append(self._guarded(fn))

    def add_line_decorator(self, fn: Callable):
        """`fn(an, line)` -> None, a comment, or {"comment": str, "color": "#rrggbb"} for each
        instruction / data line of the listing (`line.addr`, `line.mnemonic`, `line.operands`)."""
        if self.win is not None:
            self.win.add_line_decorator(self._guarded(fn))

    def on_analysis(self, fn: Callable[[dict], object]):
        """`fn(ns)` once a binary has been analysed, and after a patch re-analyses it (GUI)."""
        if self.win is not None:
            self.win.plugin_hooks["analysis"].append(self._guarded(fn))

    def on_cursor(self, fn: Callable[[dict, int], object]):
        """`fn(ns, addr)` whenever the cursor moves to another address (GUI)."""
        if self.win is not None:
            self.win.plugin_hooks["cursor"].append(self._guarded(fn))

    def add_listing_comment(self, fn: Callable[["Analysis", int], str | None]):
        """`fn(an, addr)` for every listed instruction; text it returns is added to the line's
        comment (`lambda an, a: "hot" if a in hot else None`) -- add_line_decorator's simple form."""
        self.add_line_decorator(lambda an, line: fn(an, line.addr) if line.kind == "insn" else None)


def load_plugins(win=None) -> tuple[list[str], list[tuple[str, str]]]:
    """Import every plugin and call its `register`; (loaded names, (name, error) failures).
    Without a window (the CLI) only the extension points take effect: loaders, processors,
    decompile hooks."""
    loaded, failed = [], []
    for d in plugin_dirs():
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".py") or fn.startswith("_"):
                continue
            name = fn[:-3]
            try:
                spec = importlib.util.spec_from_file_location(f"relic_plugin_{name}", os.path.join(d, fn))
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                reg = getattr(mod, "register", None)
                if reg is None:
                    raise AttributeError("no register(api) function")
                reg(PluginAPI(win, name))
                loaded.append(name)
            except Exception:  # noqa: BLE001
                failed.append((name, traceback.format_exc()))
    return loaded, failed


__all__ = ["Api", "Console", "PluginAPI", "load_plugins", "namespace", "plugin_dirs", "reference", "run_script"]

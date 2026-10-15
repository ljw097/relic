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
        if self.win is not None and self.win.cur is not None:
            return self.win.cur
        main = self.an.function_by_name("main")
        return main.addr if main is not None else self.an.bin.entry

    def goto(self, where) -> bool:
        a = self.addr(where)
        return self.win.goto(a) if self.win is not None else False

    # --------------------------------------------------------- names
    def name(self, where) -> str | None:
        return self.an.name(self.addr(where))

    def rename(self, where, new: str):
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
        a = self.addr(where)
        if self.win is not None:
            self.win.comment(a, text)
        else:
            self.an.comment(a, text)

    # --------------------------------------------------------- queries
    def func(self, where=None):
        a = self.here() if where is None else self.addr(where)
        return self.an.function_at(a)

    def functions(self) -> list:
        return [f for f in sorted(self.an.functions.values(), key=lambda f: f.addr) if not f.is_import]

    def xrefs_to(self, where) -> list:
        return list(self.an.xrefs_to.get(self.addr(where), ()))

    def xrefs_from(self, where) -> list:
        return list(self.an.xrefs_from.get(self.addr(where), ()))

    def disasm(self, where=None, n: int = 10) -> str:
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
        from .decompiler.emit import decompile
        f = self.func(where)
        if f is None:
            raise ValueError("no function there")
        return decompile(self.an, f).text

    def strings(self) -> list:
        return list(self.an.strings)

    def search(self, pattern: str) -> list[int]:
        from .analysis.search import find_bytes
        return [h.addr for h in find_bytes(self.an, pattern)]

    # --------------------------------------------------------- patches
    def patch(self, where, data: bytes | str):
        from .patch import parse_hex
        a = self.addr(where)
        data = parse_hex(data) if isinstance(data, str) else bytes(data)
        if self.win is not None:
            return self.win.patch(a, data)
        return self.an.patch(a, data)

    def nop(self, where):
        from .patch import nop_bytes
        a = self.addr(where)
        return self.patch(a, nop_bytes(self.an, a))

    def invert(self, where):
        from .patch import invert_bytes
        a = self.addr(where)
        return self.patch(a, invert_bytes(self.an, a))

    def assemble(self, where, text: str):
        from .patch import assemble, fit
        a = self.addr(where)
        return self.patch(a, fit(self.an, a, assemble(self.an, a, text)))

    def revert(self, where) -> bool:
        ok = self.an.revert(self.addr(where))
        if ok and self.win is not None:
            self.win._after_patch(self.win.cur)
        return ok

    def save(self):
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
              "export", "snapshot", "restore_snapshot", "merge",
              "functions", "xrefs_to", "xrefs_from",
              "disasm", "decompile", "strings", "search", "patch", "nop", "invert", "assemble", "revert", "save"):
        ns[n] = getattr(api, n)
    return ns


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
        an = getattr(self.win, "an", None)
        return namespace(an, self.win) if an is not None else None

    def add_action(self, text: str, callback: Callable[[dict], object], shortcut: str | None = None):
        """A Plugins-menu item; `callback(ns)` runs with the scripting namespace of the open binary."""
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
                    self.win.report_plugin_error(self.plugin, traceback.format_exc())
                return default
        return call

    def add_line_decorator(self, fn: Callable):
        """`fn(an, line)` -> None, a comment, or {"comment": str, "color": "#rrggbb"} for each
        instruction / data line of the listing (`line.addr`, `line.mnemonic`, `line.operands`)."""
        self.win.add_line_decorator(self._guarded(fn))

    def on_analysis(self, fn: Callable[[dict], object]):
        """`fn(ns)` once a binary has been analysed, and after a patch re-analyses it."""
        self.win.plugin_hooks["analysis"].append(self._guarded(fn))

    def on_cursor(self, fn: Callable[[dict, int], object]):
        """`fn(ns, addr)` whenever the cursor moves to another address."""
        self.win.plugin_hooks["cursor"].append(self._guarded(fn))

    def add_listing_comment(self, fn: Callable[["Analysis", int], str | None]):
        """`fn(an, addr)` for every listed instruction; text it returns is added to the line's
        comment (`lambda an, a: "hot" if a in hot else None`) -- add_line_decorator's simple form."""
        self.add_line_decorator(lambda an, line: fn(an, line.addr) if line.kind == "insn" else None)


def load_plugins(win) -> tuple[list[str], list[tuple[str, str]]]:
    """Import every plugin and call its `register`; (loaded names, (name, error) failures)."""
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


__all__ = ["Api", "Console", "PluginAPI", "load_plugins", "namespace", "plugin_dirs", "run_script"]

# Scripting reference

Generated from the docstrings by `tools/gen_scripting_docs.py`; `tests/test_scripting.py` checks it
is current.

## The namespace

Available in the GUI's Python console, in scripts (`relic script FILE script.py`, File > Run
script) and in plugin callbacks. Besides these: `an` (the Analysis), `bin` (its Binary), `api`
(the object behind them) and `win` (the main window, or None).

- `add_field(struct: str, offset: int, ctype: str, name: str = '')` -- Add a field by hand to a recovered struct (`char[16]`, `int`, `char *`).
- `addr(where) -> int` -- An address from an int, a name / `func+0x10` / hex text, or anything with `.addr` (a Function, a Block, an Xref's `.to` is an int already).
- `assemble(where, text: str)` -- Assemble `text` (keystone) at an address and patch it in, NOP-padded to whole instructions.
- `bookmark(where, text: str)` -- Bookmark an address (empty text removes it).
- `callees(where) -> list[int]` -- Functions the function at / named `where` calls.
- `callers(where) -> list[int]` -- Functions calling the function at / named `where`.
- `comment(where, text: str)` -- Set the comment at an address (empty removes it).
- `decompile(where=None) -> str` -- The pseudocode of the function at / named `where` (default: the cursor's), as text.
- `define(where, kind: str, count: int | None = None, element: str = 'byte')` -- Say what is at an address: byte / word / dword / qword / string / array / code (D / A / * / C).
- `delete_function(where)` -- Remove the function starting at an address; the analysis runs again.
- `disasm(where=None, n: int = 10) -> str` -- `n` instructions from an address (default: the cursor), as listing text.
- `export(path: str) -> dict` -- Write every function's pseudocode to a C file; what was written.
- `func(where=None)` -- The Function containing an address or named so (default: the cursor's), or None.
- `functions() -> list` -- Every function of the binary, imports excluded, in address order.
- `goto(where) -> bool` -- Move the GUI cursor to an address or name; whether it could.
- `here() -> int` -- The cursor address (GUI), else `main` / the entry point.
- `import_header(text_or_path: str) -> dict` -- Import C declarations (structs, unions, enums, typedefs, prototypes) from header text or a file path; what was imported, by kind.
- `insn(where)` -- The decoded instruction (`relic.disasm.Insn`: `.mnemonic`, `.op_str`, `.size`, `.kind`, `.target`, `.refs`) at an address, or None.
- `invert(where)` -- Negate the conditional branch at an address (patch).
- `load_type_library(name: str = 'libc') -> dict` -- Import a bundled type library (`libc`: struct stat, tm, timeval, sockaddr_in, ...).
- `lumina_pull(store: str | None = None, overwrite: bool = False) -> dict` -- Names / comments / variable names of matching functions from a shared store.
- `lumina_push(store: str | None = None) -> dict` -- Send the functions' names / comments / variable names to a shared store.
- `make_function(where)` -- A function starting at an address (P); the analysis runs again.
- `merge(path: str, theirs: bool = False) -> dict` -- Merge another project file of this binary: {"added", "conflicts", "kept"}.
- `name(where) -> str | None` -- The name shown for an address (the user's, a symbol, a library signature's), or None.
- `names() -> list[tuple[int, str, str]]` -- Every named address: (address, name, kind).
- `nop(where)` -- Replace the instruction at an address with NOPs (patch).
- `number_format(func, value: int, fmt: str)` -- Show the constant `value` in a function's pseudocode as hex / dec / char / bin.
- `op_format(addr, index: int, fmt: str)` -- Show operand `index` of the instruction at `addr` as hex / dec / char / bin / offset ("" resets).
- `patch(where, data: bytes | str)` -- Write bytes (or hex text `90 90`) at an address; the analysis runs again.
- `rcomment(addr, text: str)` -- A repeatable comment: shown at `addr` and wherever it is referred to ("" removes it).
- `read(where, n: int) -> bytes` -- `n` bytes of the loaded image (with patches) at an address or name.
- `read_int(where, size: int | None = None, signed: bool = False) -> int | None` -- A little/big-endian integer (the binary's byte order) of `size` bytes (default: a pointer).
- `remove_field(struct: str, offset: int)` -- Drop a field of a recovered struct.
- `rename(where, new: str)` -- Name an address (empty restores the original name).
- `rename_field(struct: str, field: str, name: str)` -- Name a field (`f_8`) of a recovered struct (`s_notes`).
- `rename_struct(struct: str, name: str)` -- Name a recovered struct by its generated name (`s_notes`).
- `restore_snapshot(name: str)` -- Put snapshot `name`'s annotations back (undoable).
- `revert(where) -> bool` -- Drop the patch at an address; whether there was one.
- `save()` -- Write the project file (`<binary>.relic.json`).
- `search(pattern: str) -> list[int]` -- Addresses where a byte pattern (`48 8b ?? 05`) occurs.
- `sections() -> list[tuple[str, int, int, str]]` -- (name, address, size, permissions) of every section.
- `set_field_type(struct: str, field: str, ctype: str)` -- Give a field (`f_8`) of a recovered struct (`s_notes`) a C type.
- `set_return_type(func, ctype: str)` -- The C type a function returns (`char *`, `void`; empty resets).
- `set_type(func, var: str, ctype: str)` -- Give a variable / parameter (`a1`, `v3`, `var_10`) of a function a C type.
- `snapshot(name: str) -> dict` -- Keep a named copy of every annotation (saved with the project).
- `strings() -> list` -- The strings found in the binary (`.addr`, `.value`, `.encoding`, `.section`).
- `undefine(where)` -- Forget what was said about an address (U).
- `xrefs_from(where) -> list` -- The cross references from an address (`.frm`, `.to`, `.kind`).
- `xrefs_to(where) -> list` -- The cross references to an address (`.frm`, `.to`, `.kind`).

## Plugins

A plugin is a `.py` file in `~/.relic/plugins` (or a directory of `$RELIC_PLUGINS`) defining
`register(api)`; `api` is a `PluginAPI`:

- `add_action(text: str, callback: Callable[[dict], object], shortcut: str | None = None)` -- A Plugins-menu item; `callback(ns)` runs with the scripting namespace of the open binary (GUI only: ignored when the plugin is loaded by the CLI).
- `add_line_decorator(fn: Callable)` -- `fn(an, line)` -> None, a comment, or {"comment": str, "color": "#rrggbb"} for each instruction / data line of the listing (`line.addr`, `line.mnemonic`, `line.operands`).
- `add_listing_comment(fn: "Callable[['Analysis', int], str | None]")` -- `fn(an, addr)` for every listed instruction; text it returns is added to the line's comment (`lambda an, a: "hot" if a in hot else None`) -- add_line_decorator's simple form.
- `add_loader(name: str, detect: Callable[[bytes, str], bool], load: Callable[[bytes, str], object])` -- A file format: `detect(data, path)` -> whether it is one; `load(data, path)` -> a `relic.loader.Binary`. Tried before the built-in loaders, in the GUI and the CLI.
- `add_processor(arch: str, decode: Callable[[bytes, int], object], bits: int = 32, endian: str = 'little')` -- A processor module: `decode(code, addr)` -> a `relic.disasm.Insn` (or None) for the architecture `arch` (`relic disasm blob --arch NAME`, or a loader's `binary.arch`).
- `namespace() -> dict | None` -- The scripting namespace of the open binary, or None when nothing is open.
- `on_analysis(fn: Callable[[dict], object])` -- `fn(ns)` once a binary has been analysed, and after a patch re-analyses it (GUI).
- `on_cursor(fn: Callable[[dict, int], object])` -- `fn(ns, addr)` whenever the cursor moves to another address (GUI).
- `on_debug_stop(fn: Callable[[dict, object], object])` -- `fn(ns, snapshot)` each time the debugged program stops (`snapshot.pc`, `.regs`, `.stack`, `.maps`; GUI).
- `on_decompile(fn: Callable)` -- `fn(an, func, lines)` -> new lines or None, for every function's pseudocode.
- `on_edit(fn: Callable[[dict], object])` -- `fn(ns)` after any annotation edit, undo or redo (GUI).

## Extension points

Extension points for plugins (IDA's SDK, in Python): file loaders, processor modules
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

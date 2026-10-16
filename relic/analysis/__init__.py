"""Whole-binary analysis: functions, CFGs, xrefs, strings and user annotations."""
from __future__ import annotations

import bisect
import copy
import functools
import json
import re
import os
from collections import defaultdict
from dataclasses import dataclass

from ..disasm import CALL, CJMP, JMP, Disassembler, Insn
from ..loader.base import Binary
from ..progress import report
from .functions import NORETURN, Block, Function, FunctionAnalyzer
from .strings import String, find_strings


@dataclass(frozen=True)
class Xref:
    frm: int
    to: int
    kind: str  # call | jmp | data


class Analysis:
    def __init__(self, binary: Binary):
        self.bin = binary
        self.dis = Disassembler(binary)
        self.functions: dict[int, Function] = {}
        self.strings: list[String] = []
        self.xrefs_to: dict[int, list[Xref]] = defaultdict(list)
        self.xrefs_from: dict[int, list[Xref]] = defaultdict(list)
        self.comments: dict[int, str] = {}
        self.renames: dict[int, str] = {}
        # decompiler variable names: function address -> {generated name: user name}
        self.var_names: dict[int, dict[str, str]] = {}
        # user types of decompiler variables: function address -> {generated name: C type}
        self.var_types: dict[int, dict[str, str]] = {}
        # recovered structs: generated struct name -> {"name": user name, "fields": {f_8: user name},
        # "types": {f_8: C type}}
        self.struct_names: dict[str, dict] = {}
        # imported C declarations: {"headers": [text, ...], "enums": {name: {constant: value}},
        # "typedefs": {name: C type}} (their structs live in struct_names, marked "imported")
        self.user_types: dict = {}
        # how numbers are shown: instruction address -> {operand index: "hex" | "dec" | "char" |
        # "bin" | "offset"} in the listing; function address -> {value: format} in the pseudocode
        self.op_formats: dict[int, dict[str, str]] = {}
        # repeatable comments: shown at the address and at every instruction referring to it
        self.rcomments: dict[int, str] = {}
        # what the user says memory holds (IDA's D / A / * / C / U): address -> ["byte"] /
        # ["word"] / ["dword"] / ["qword"] / ["string", n] / ["array", element, count] / ["code"]
        # / ["undef"]; and functions made or removed by hand: address -> "create" / "delete"
        self.data_defs: dict[int, list] = {}
        self.func_edits: dict[int, str] = {}
        self.num_formats: dict[int, dict[str, str]] = {}
        # byte patches: address -> (original bytes, new bytes), applied to `bin.data`
        self.patches: dict[int, tuple[bytes, bytes]] = {}
        # undo / redo of patch edits: (address, the patch there before the edit, or None)
        self.patch_undo: list[tuple[int, tuple | None]] = []
        self.patch_redo: list[tuple[int, tuple | None]] = []
        # bookmarked addresses -> description
        self.bookmarks: dict[int, str] = {}
        # undo / redo of every user edit, in order: ("notes", annotations before, address) for
        # names, comments, types, struct edits and bookmarks; ("patch",) for a patch edit
        self.edit_undo: list[tuple] = []
        self.edit_redo: list[tuple] = []
        self._in_edit = False
        # named copies of the annotations: name -> {"time": ..., "notes": project-file sections}
        self.snapshots: dict[str, dict] = {}
        # versions of the annotations (commit / log / diff / checkout): {"id", "time", "author",
        # "message", "notes"}, oldest first
        self.history: list[dict] = []
        self._sha256: str | None = None
        self._fstarts: list[int] = []
        self._strings_by_addr: dict[int, String] = {}
        # library signature files to name functions with (None: those in libsigs.sig_dirs())
        self.sig_paths: list[str] | None = None
        # functions named by a library signature: address -> name
        self.lib_names: dict[int, str] = {}
        self._toolchain = None

    # ------------------------------------------------------------------ run
    def run(self, load_project: bool = True) -> "Analysis":
        if load_project:
            self._apply_saved_patches()
        report("functions", 0, force=True)
        finder = self._find_functions()
        stops = self._library_names(finder)
        if stops:
            # library functions known not to return (exit, abort, __chk_fail) that the analysis
            # did not know: calls to them end their blocks, which changes where functions end --
            # find them again knowing that
            report("functions", 0, force=True)
            finder = self._find_functions(stops)
            self._library_names(finder)
        if "main" not in self.bin.name_to_addr and not any(f.name == "main" for f in self.functions.values()):
            # (after library names: a static binary's `__libc_start_main` has one only then)
            main = finder._find_main() if self.lib_names else None
            if main is None:
                main = self._main_from_start()
            if main is not None:
                finder.add_function(main, "main")
        self._apply_func_edits(finder, load_project)
        self._fstarts = sorted(self.functions)
        report("data references", 0, force=True)
        from .constprop import propagate_refs
        propagate_refs(self)     # addresses built over several instructions (adrp + add, ...)
        report("strings", 0, force=True)
        self.strings = find_strings(self.bin)
        self._strings_by_addr = {s.addr: s for s in self.strings}
        self._build_xrefs()
        if load_project:
            self.load_project()
        return self

    def _apply_func_edits(self, finder: FunctionAnalyzer, from_project: bool = False):
        """Functions the user made (P) or removed (Delete); on the first run (the project is
        loaded after the analysis) read from the project file."""
        edits = self.func_edits
        if from_project and os.path.exists(self.project_path):
            try:
                with open(self.project_path) as fp:
                    edits = {int(a, 16): v for a, v in json.load(fp).get("function_edits", {}).items()}
            except (OSError, ValueError):
                edits = {}
        for a, what in sorted(edits.items()):
            if what == "create" and a not in self.functions and self.bin.is_exec(a & ~1):
                finder.add_function(a)
        for a, what in edits.items():
            f = self.functions.get(a)
            if what == "delete" and f is not None and not f.is_import:
                del self.functions[a]

    def _find_functions(self, noreturn: set[int] = frozenset()) -> FunctionAnalyzer:
        finder = FunctionAnalyzer(self.bin, self.dis, noreturn)
        self.functions = finder.run()
        return finder

    def _library_names(self, finder: FunctionAnalyzer | None = None) -> set[int]:
        """Name functions without a symbol by library signatures (libsigs); the ones named as
        not returning that were not known to be so."""
        from .libsigs import apply, available
        dbs = available(self.bin.arch, self.sig_paths, self.toolchain, self.bin.format)
        make = None
        if finder is not None:
            def make(addr: int):                  # a virtual method found in a vtable
                return self.functions.get(finder.add_function(addr))
        self.lib_names = apply(self, dbs, make) if dbs else {}
        new = set()
        for a in self.lib_names:
            f = self.functions[a]
            if f.name in NORETURN and not f.noreturn:
                f.noreturn = True
                new.add(a)
        # only worth finding functions again if some call to one of them was taken to return
        falls = any(b.last.kind == CALL and b.last.target in new and b.succs
                    for g in self.functions.values() for b in g.blocks.values() if b.insns)
        return new if falls else set()

    def reanalyze(self) -> "Analysis":
        """Analyse again (after a patch), keeping names, comments, variable names and patches."""
        keep = (self.renames, self.comments, self.var_names, self.patches, self.struct_names, self.var_types,
                self.patch_undo, self.patch_redo, self.sig_paths, self.bookmarks, self.edit_undo, self.edit_redo,
                self.user_types, self.snapshots, self.op_formats, self.num_formats, self.rcomments,
                self.data_defs, self.func_edits, self.history)
        b = self.bin
        self.__dict__.clear()                    # decompiler caches live on the instance too
        self.__init__(b)
        (self.renames, self.comments, self.var_names, self.patches, self.struct_names, self.var_types,
         self.patch_undo, self.patch_redo, self.sig_paths, self.bookmarks, self.edit_undo, self.edit_redo,
         self.user_types, self.snapshots, self.op_formats, self.num_formats, self.rcomments,
         self.data_defs, self.func_edits, self.history) = keep
        return self.run(load_project=False)

    # ------------------------------------------------------------- patches
    def patch(self, addr: int, data: bytes, reanalyze: bool = True, _record: bool = True) -> bytes:
        """Write `data` at `addr` (see `relic.patch`); returns the bytes it replaced. Patching
        the same address again replaces the earlier patch; overlapping another one is refused."""
        from ..patch import PatchError, write
        end = addr + len(data)
        for a, (_old, new) in self.patches.items():
            if a != addr and a < end and addr < a + len(new):
                raise PatchError(f"overlaps the patch at {a:#x} (revert it first)")
        before = self.patches.get(addr)
        if before is not None:
            self.revert(addr, reanalyze=False, _record=False)
        old = write(self.bin, addr, data)
        self.patches[addr] = (old, bytes(data))
        if _record:
            self.patch_undo.append((addr, before))
            self.patch_redo.clear()
            self._record_edit(("patch",))
        if reanalyze:
            self.reanalyze()
        return old

    def revert(self, addr: int, reanalyze: bool = True, _record: bool = True) -> bool:
        """Put back the original bytes of the patch at `addr`."""
        from ..patch import write
        p = self.patches.pop(addr, None)
        if p is None:
            return False
        write(self.bin, addr, p[0])
        if _record:
            self.patch_undo.append((addr, p))
            self.patch_redo.clear()
            self._record_edit(("patch",))
        if reanalyze:
            self.reanalyze()
        return True

    def _set_patch(self, addr: int, state: tuple | None):
        """Make the patch at `addr` be `state` ((original, new) or None: none)."""
        if addr in self.patches:
            self.revert(addr, reanalyze=False, _record=False)
        if state is not None:
            self.patch(addr, state[1], reanalyze=False, _record=False)

    def undo_patch(self, reanalyze: bool = True) -> int | None:
        """Undo the last patch edit (a patch or a revert); its address, or None if nothing to undo."""
        if not self.patch_undo:
            return None
        addr, before = self.patch_undo.pop()
        self.patch_redo.append((addr, self.patches.get(addr)))
        self._set_patch(addr, before)
        if reanalyze:
            self.reanalyze()
        return addr

    def redo_patch(self, reanalyze: bool = True) -> int | None:
        """Redo the last undone patch edit."""
        if not self.patch_redo:
            return None
        addr, after = self.patch_redo.pop()
        self.patch_undo.append((addr, self.patches.get(addr)))
        self._set_patch(addr, after)
        if reanalyze:
            self.reanalyze()
        return addr

    # ------------------------------------------------------ undo of all edits
    UNDO_MAX = 500
    NOTES = ("renames", "comments", "var_names", "var_types", "struct_names", "bookmarks", "user_types",
             "op_formats", "num_formats", "rcomments", "data_defs", "func_edits")

    def _notes(self) -> tuple:
        return copy.deepcopy(tuple(getattr(self, k) for k in self.NOTES))

    def _set_notes(self, state: tuple):
        for k, v in zip(self.NOTES, copy.deepcopy(state)):
            setattr(self, k, v)

    def _restore_notes(self, state: tuple, reanalyze: bool):
        before = dict(self.func_edits)
        self._set_notes(state)
        if reanalyze and self.func_edits != before:      # functions made or removed: find them again
            self.reanalyze()

    def _record_edit(self, entry: tuple):
        self.edit_undo.append(entry)
        del self.edit_undo[:-self.UNDO_MAX]
        self.edit_redo.clear()

    def undo(self, reanalyze: bool = True) -> tuple[str, int | None] | None:
        """Undo the last edit of any kind: ("notes", address it was at) for a name / comment /
        type / struct / bookmark edit, ("patch", address) for a patch edit; None: nothing left."""
        while self.edit_undo:
            e = self.edit_undo.pop()
            if e[0] == "patch":
                addr = self.undo_patch(reanalyze)
                if addr is None:              # (undone directly with undo_patch)
                    continue
                self.edit_redo.append(e)
                return "patch", addr
            _, state, where = e
            self.edit_redo.append(("notes", self._notes(), where))
            self._restore_notes(state, reanalyze)
            return "notes", where
        return None

    def redo(self, reanalyze: bool = True) -> tuple[str, int | None] | None:
        while self.edit_redo:
            e = self.edit_redo.pop()
            if e[0] == "patch":
                addr = self.redo_patch(reanalyze)
                if addr is None:
                    continue
                self.edit_undo.append(e)
                return "patch", addr
            _, state, where = e
            self.edit_undo.append(("notes", self._notes(), where))
            self._restore_notes(state, reanalyze)
            return "notes", where
        return None

    def patched_at(self, addr: int) -> bool:
        return any(a <= addr < a + len(new) for a, (_, new) in self.patches.items())

    def _apply_saved_patches(self):
        """Patches kept in the project file, applied before the analysis sees the code. One whose
        original bytes no longer match (the binary changed) is skipped."""
        path = self.project_path
        if not os.path.exists(path):
            return
        try:
            with open(path) as fp:
                saved = json.load(fp).get("patches", {})
        except (OSError, ValueError):
            return
        from ..patch import PatchError, write
        for a, p in saved.items():
            addr, old, new = int(a, 16), bytes.fromhex(p["old"]), bytes.fromhex(p["new"])
            if self.bin.read(addr, len(old)) != old or addr in self.patches:
                continue
            try:
                write(self.bin, addr, new)
            except PatchError:
                continue
            self.patches[addr] = (old, new)

    def _main_from_start(self) -> int | None:
        """`main` of a stripped binary: the first argument `_start` passes to __libc_start_main,
        read from the lifted entry code (a constant, or a GOT / literal-pool slot holding it).
        The x86 finder recognises its own `_start` already; this covers the other lifters."""
        if self.bin.format != "ELF" or self.bin.arch in ("x86", "x64"):
            return None
        start = self.functions.get(self.bin.entry)
        if start is None:
            return None
        try:
            from ..decompiler.arch import arch_for
            from ..decompiler.calls import int_arg_regs
            from ..decompiler.ir import CallStmt, Const, Load
            from ..decompiler.lift import lift_function
            from ..decompiler.passes import optimize
            from ..decompiler.ssa import to_ssa
            arch = arch_for(self.bin)
            regs = int_arg_regs(arch)
            ir = optimize(to_ssa(lift_function(self, start), arch), arch)
        except Exception:  # noqa: BLE001 - no lifter for this target, or it failed: no main
            return None
        for s in ir.stmts():
            if not (isinstance(s, CallStmt) and (s.name or "").split("@")[0] == "__libc_start_main"):
                continue
            v = dict(s.uses).get(regs[0]) if regs else None
            if isinstance(v, Load) and isinstance(v.addr, Const):
                v = self.bin.read_int(v.addr.value, v.bits // 8)
                v = Const(v, arch.bits) if v is not None else None
            if isinstance(v, Const) and v.value and self.bin.is_exec(v.value & ~1):
                return self._through_trampoline(v.value)
        return None

    def _through_trampoline(self, addr: int) -> int:
        """Where code that only jumps on (nops, then one direct jump: AArch64 glibc's
        `__wrap_main`) goes; `addr` itself otherwise."""
        a = addr
        for _ in range(4):
            i = self.dis.decode(a)
            if i is None:
                break
            if i.mnemonic == "nop":
                a = i.end
                continue
            if i.kind == JMP and i.target is not None and self.bin.is_exec(i.target & ~1):
                return i.target
            break
        return addr

    def _build_xrefs(self):
        total = len(self.functions)
        for k, f in enumerate(self.functions.values()):
            report("xrefs", k, total)
            for blk in f.blocks.values():
                for i in blk.insns:
                    if i.kind in (CALL, JMP, CJMP) and i.target is not None:
                        self._add_xref(Xref(i.addr, i.target, "call" if i.kind == CALL else "jmp"))
                    for r in i.refs:
                        self._add_xref(Xref(i.addr, r, "data"))
            for jmp, targets in f.jump_tables.items():
                for t in set(targets):
                    self._add_xref(Xref(jmp, t, "jmp"))

    def _add_xref(self, x: Xref):
        self.xrefs_to[x.to].append(x)
        self.xrefs_from[x.frm].append(x)

    # -------------------------------------------------------------- queries
    def function_at(self, addr: int) -> Function | None:
        f = self.functions.get(addr)
        if f is not None:
            return f
        k = bisect.bisect_right(self._fstarts, addr) - 1
        while k >= 0:
            f = self.functions[self._fstarts[k]]
            if f.block_at(addr):
                return f
            if f.addr + 0x10000 < addr:
                break
            k -= 1
        return None

    def function_by_name(self, name: str) -> Function | None:
        """By raw symbol, display name, or -- for C++ -- the name without its argument list."""
        from ..demangle import short_name
        for f in self.functions.values():
            if self.name(f.addr) == name or f.name == name:
                return f
        for f in self.functions.values():
            shown = self.name(f.addr)
            if shown and "(" in shown and short_name(shown) == name:
                return f
        return None

    def resolve(self, text: str) -> int | None:
        """Address from `0x401000`, `401000`, `main`, or `main+0x10`."""
        text = text.strip()
        off = 0
        if "+" in text:
            text, o = text.split("+", 1)
            off = int(o, 0)
        f = self.function_by_name(text)
        if f is not None:
            return f.addr + off
        if text in self.bin.name_to_addr:
            return self.bin.name_to_addr[text] + off
        try:
            return int(text, 16 if not text.startswith("0x") else 0) + off
        except ValueError:
            return None

    def name(self, addr: int) -> str | None:
        """Display name: the user's rename, else the symbol (C++ names demangled)."""
        if addr in self.renames:
            return self.renames[addr]
        f = self.functions.get(addr)
        n = f.name if f is not None else self.bin.name_of(addr)
        if n and n.startswith("_Z"):
            from ..demangle import demangle
            return demangle(n) or n
        return n

    def label(self, addr: int) -> str:
        """Best human-readable name for an address (`sym`, `sym+0x4`, or hex)."""
        n = self.name(addr)
        if n:
            return n
        f = self.function_at(addr)
        if f is not None:
            if addr in f.blocks:
                return f"loc_{addr:x}"
            return f"{self.name(f.addr)}+{addr - f.addr:#x}"
        s = self.bin.symbols.get(addr)
        return s.name if s else f"{addr:#x}"

    def location(self, addr: int) -> str:
        """`func+0x12` form, for describing where an instruction lives."""
        f = self.function_at(addr)
        if f is None or addr == f.addr:
            lbl = self.label(addr)
            sec = self.bin.section_at(addr) if f is None and lbl.startswith("0x") else None
            return f"{sec.name}+{addr - sec.addr:#x}" if sec is not None and sec.name else lbl
        return f"{self.name(f.addr)}+{addr - f.addr:#x}"

    def call_name(self, i: Insn) -> str | None:
        if i.target is not None:
            return self.name(i.target)
        if i.mem_target is not None:
            imp = self.bin.imports_by_got.get(i.mem_target)
            if imp:
                return imp.name
        return None

    def string_at(self, addr: int) -> String | None:
        return self._strings_by_addr.get(addr)

    def describe_ref(self, addr: int) -> str | None:
        """Annotation for a data reference: string literal, symbol or import slot."""
        s = self.string_at(addr)
        if s is not None:
            from .strings import escape
            return f'"{escape(s.value)}"'
        imp = self.bin.imports_by_got.get(addr)
        if imp:
            return f"[{imp.name}@got]"
        n = self.name(addr)
        if n:
            return n
        sec = self.bin.section_at(addr)
        if sec is not None and not sec.x and sec.loaded:
            v = self.bin.read_cstring(addr, 64)
            if v and len(v) >= 3 and v.isprintable():
                from .strings import escape
                return f'"{escape(v)}"'
        return None

    def vulns(self):
        from .vulns import find_vulns
        return find_vulns(self)

    def checksec(self) -> dict[str, str]:
        from .checksec import checksec
        return checksec(self.bin)

    @property
    def toolchain(self):
        """What built the binary (ident.Toolchain): compiler, C library, linking, languages."""
        if self._toolchain is None:
            from .ident import identify
            self._toolchain = identify(self.bin)
        return self._toolchain

    # ------------------------------------------------------- annotations
    @property
    def project_path(self) -> str:
        return self.bin.path + ".relic.json"

    def rename(self, addr: int, name: str):
        if name:
            self.renames[addr] = name
        else:
            self.renames.pop(addr, None)

    def rename_var(self, func: int, generated: str, name: str):
        """Name a decompiler variable (`v3`, `a1`, `var_c`) of the function at `func`; empty resets."""
        names = self.var_names.setdefault(func, {})
        if name and name != generated:
            names[generated] = name
        else:
            names.pop(generated, None)
        if not names:
            self.var_names.pop(func, None)

    def rename_struct(self, generated: str, name: str):
        """Name a recovered struct (`s_notes`); empty resets."""
        d = self.struct_names.setdefault(generated, {})
        if name and name != generated:
            d["name"] = name
        else:
            d.pop("name", None)
        self._tidy_struct_names(generated)

    def rename_field(self, struct: str, generated: str, name: str):
        """Name a field (`f_8`) of a recovered struct (by its generated name); empty resets."""
        fields = self.struct_names.setdefault(struct, {}).setdefault("fields", {})
        if name and name != generated:
            fields[generated] = name
        else:
            fields.pop(generated, None)
        self._tidy_struct_names(struct)

    def set_var_type(self, func: int, generated: str, ctype: str):
        """Give a decompiler variable / parameter of the function at `func` a C type (`char *`,
        `struct note *`); empty resets to the inferred one. ValueError for what is not a type."""
        from ..decompiler.vartypes import parse_ctype
        ctype = self.resolve_type(ctype)
        t = parse_ctype(ctype) if ctype.strip() else None     # ValueError before anything changes
        types = self.var_types.setdefault(func, {})
        if t is not None:
            types[generated] = str(t)
            if t.base.startswith("struct "):
                # keep an entry (and so the struct's layout) for a struct applied by its own name
                name = t.base[7:]
                if not any(d.get("name") == name for d in self.struct_names.values()):
                    self.struct_names.setdefault(name, {})["applied"] = True
        else:
            types.pop(generated, None)
        if not types:
            self.var_types.pop(func, None)

    def set_field_type(self, struct: str, generated: str, ctype: str):
        """Give a field of a recovered struct a C type; empty resets it."""
        from ..decompiler.vartypes import parse_ctype
        ctype = self.resolve_type(ctype)
        t = parse_ctype(ctype) if ctype.strip() else None
        types = self.struct_names.setdefault(struct, {}).setdefault("types", {})
        if t is not None:
            types[generated] = str(t)
        else:
            types.pop(generated, None)
        self._tidy_struct_names(struct)

    def add_field(self, struct: str, offset: int, ctype: str, name: str = ""):
        """Add (or replace) a field of a recovered struct by hand: `int`, `char *`, `char[16]`."""
        from ..decompiler.structs import field_layout
        field_layout(ctype, self.bin.bits)                       # ValueError for what is not a type
        d = self.struct_names.setdefault(struct, {})
        d.setdefault("added", {})[f"{offset:#x}"] = [ctype.strip(), name.strip()]
        d["removed"] = [o for o in d.get("removed", []) if o != f"{offset:#x}"]
        if name.strip():
            self.rename_field(struct, f"f_{offset:x}", name)
        self._tidy_struct_names(struct)

    def remove_field(self, struct: str, offset: int):
        """Drop a field of a recovered struct (it is shown as a plain memory access again)."""
        d = self.struct_names.setdefault(struct, {})
        d.get("added", {}).pop(f"{offset:#x}", None)
        if f"{offset:#x}" not in d.setdefault("removed", []):
            d["removed"].append(f"{offset:#x}")
        self._tidy_struct_names(struct)

    def _tidy_struct_names(self, struct: str):
        d = self.struct_names.get(struct, {})
        for k in ("fields", "types", "added", "removed"):
            if not d.get(k):
                d.pop(k, None)
        if set(d) <= {"layout"}:                 # nothing the user set: no entry
            self.struct_names.pop(struct, None)

    # ------------------------------------------------------- C declarations
    def resolve_type(self, ctype: str) -> str:
        """A type written with an imported typedef name -> the type it stands for
        (`node_t *` -> `struct node *`); anything else unchanged."""
        t = ctype.strip()
        defs = self.user_types.get("typedefs", {})
        m = re.fullmatch(r"(?:const\s+)?([A-Za-z_]\w*)\s*((?:\*\s*)*)", t)
        seen = set()
        while m and m.group(1) in defs and m.group(1) not in seen:
            seen.add(m.group(1))
            stars = m.group(2).count("*")
            base = defs[m.group(1)]
            t = base + ("*" * stars if base.endswith("*") else (" " + "*" * stars if stars else ""))
            m = re.fullmatch(r"(?:const\s+)?([A-Za-z_]\w*)\s*((?:\*\s*)*)", t)
        return t

    def set_return_type(self, func: int, ctype: str):
        """The C type the function at `func` returns (`char *`, `void`); empty resets to the
        inferred one."""
        from ..decompiler.vartypes import parse_ctype
        ctype = self.resolve_type(ctype)
        if ctype.strip() and ctype.strip() != "void":
            ctype = str(parse_ctype(ctype))
        types = self.var_types.setdefault(func, {})
        if ctype.strip():
            types["@return"] = ctype.strip()
        else:
            types.pop("@return", None)
        if not types:
            self.var_types.pop(func, None)

    def clear_imported_types(self):
        """Forget every imported C declaration: headers, enums, typedefs, prototypes and the
        structs they defined (types the user set by hand stay)."""
        self.user_types = {}
        for name in [n for n, d in self.struct_names.items() if d.get("imported")]:
            del self.struct_names[name]

    def enum(self, name: str) -> dict[str, int] | None:
        return self.user_types.get("enums", {}).get(name)

    def import_header(self, text: str) -> dict:
        """Import C declarations (see `decompiler.cheader`): structs and unions become structs the
        decompiler shows (by their tag; apply one with `set_var_type(f, "a1", "struct node *")`),
        enums name constants compared with / assigned to / switched on variables of their type,
        typedefs can be used in types, and prototypes of this binary's functions type their
        parameters. Headers imported before stay usable (their typedefs, structs, enumerators).
        HeaderError (a ValueError) with the line for what cannot be parsed; nothing changes then.
        Returns what was imported: {"structs": [...], "enums": [...], "typedefs": [...],
        "functions": [...]}."""
        from ..decompiler.cheader import Model, declaration, parse, struct_layout
        from ..decompiler.vartypes import parse_ctype
        model = Model.for_binary(self.bin)
        headers = list(self.user_types.get("headers", []))
        h = None
        for old in headers:
            h = parse(old, model, h)
        before = (set(h.aggregates), set(h.enums), set(h.typedefs), set(h.prototypes)) if h else \
            (set(), set(), set(), set())
        from ..decompiler.cheader import Header
        h = parse(text, model, h if h is not None else Header())
        headers.append(text)
        self.user_types["headers"] = headers
        self.user_types["enums"] = {n: dict(v) for n, v in h.enums.items() if not n.startswith("__anon")}
        self.user_types["typedefs"] = {n: t.spell() for n, t in h.typedefs.items()}
        self.user_types["bare"] = sorted(h.bare)
        out = {"structs": [], "enums": sorted(n for n in set(h.enums) - before[1] if not n.startswith("__anon")),
               "typedefs": sorted(set(h.typedefs) - before[2]), "functions": [], "imports": []}
        for key, agg in h.aggregates.items():
            if not agg.complete or agg.name.startswith("__anon"):
                continue
            layout, names, types, bitfields = struct_layout(h, key, model)
            decl, deps = declaration(h, key)
            entry = {"imported": True, "layout": layout, "decl": decl,
                     "as_imported": {"fields": dict(names), "types": dict(types)}}
            if deps:
                entry["deps"] = deps
            if names:
                entry["fields"] = names
            if types:
                entry["types"] = types
            if bitfields:
                entry["bitfields"] = bitfields
            old = self.struct_names.get(agg.name, {})
            if old and not old.get("imported") and key not in before[0]:
                entry = {**old, **entry}
            self.struct_names[agg.name] = entry
            if key not in before[0]:
                out["structs"].append(agg.name)
        # prototypes: parameter types of the functions this binary defines (integer-class parameters
        # are a1, a2, ... in order, then the float ones -- the decompiler's parameter order)
        by_name = {}
        for f in self.functions.values():
            if not f.is_import:
                by_name.setdefault(self.name(f.addr) or f.name, f)
        from ..decompiler.sigs import sig_of
        protos = dict(self.user_types.get("prototypes", {}))
        formats = dict(self.user_types.get("formats", {}))
        for name, proto in h.prototypes.items():
            params = [t.spell() for _, t in proto.params]
            sig = sig_of(params, proto.ret.spell(), proto.variadic, [n for n, _ in proto.params])
            if sig.fmt is not None:
                formats[name] = sig.fmt              # a printf-like function (format-string checks)
            f = by_name.get(name)
            # how calls to it are shown: argument count and types (floats placed in their registers,
            # a printf-like function's arguments counted from its format), result
            protos[name] = {"ret": proto.ret.spell(), "params": params, "variadic": proto.variadic,
                            "names": [n for n, _ in proto.params]}
            if f is None:
                if name not in before[3]:
                    out["imports"].append(name)
                continue
            ints = [t for _, t in proto.params if t.ptr or t.base not in ("float", "double", "long double")]
            floats = [t for _, t in proto.params if not t.ptr and t.base in ("float", "double")]
            types = self.var_types.setdefault(f.addr, {})
            for k, t in enumerate(ints + floats):
                try:
                    types[f"a{k + 1}"] = str(parse_ctype(t.spell()))
                except ValueError:
                    continue
            try:
                types["@return"] = str(parse_ctype(proto.ret.spell()))
            except ValueError:
                pass
            if not types:
                self.var_types.pop(f.addr, None)
            elif name not in before[3]:
                out["functions"].append(name)
        if protos:
            self.user_types["prototypes"] = protos
        if formats:
            self.user_types["formats"] = formats
        out["structs"].sort()
        out["functions"].sort()
        out["imports"].sort()
        return out

    def comment(self, addr: int, text: str):
        if text:
            self.comments[addr] = text
        else:
            self.comments.pop(addr, None)

    def repeatable_comment(self, addr: int, text: str):
        """A comment shown at `addr` and at every instruction that refers to it (a call, a jump,
        a data reference); empty removes it."""
        if text:
            self.rcomments[addr] = text
        else:
            self.rcomments.pop(addr, None)

    # --------------------------------------------- code and data definitions
    def define_data(self, addr: int, kind: str, count: int | None = None, element: str = "byte"):
        """Say what is at `addr`: "byte" / "word" / "dword" / "qword", "string" (`count` bytes,
        default: up to and with the NUL), "array" (`count` elements of `element`), "code" (list
        it as instructions), "undef" (plain bytes)."""
        from ..datalist import SIZES, string_length
        if kind in SIZES or kind in ("code", "undef"):
            d = [kind]
        elif kind == "string":
            d = ["string", count or string_length(self, addr)]
        elif kind == "array":
            if element not in SIZES or not count or count < 1:
                raise ValueError("an array needs an element size (byte/word/dword/qword) and a count")
            d = ["array", element, count]
        else:
            raise ValueError(f"unknown data kind {kind!r}")
        self.data_defs[addr] = d

    def undefine(self, addr: int):
        """Forget what was said about `addr` (U): back to what the analysis shows; again on an
        address the analysis shows as something: plain bytes."""
        if addr in self.data_defs and self.data_defs[addr] != ["undef"]:
            del self.data_defs[addr]
        else:
            self.data_defs[addr] = ["undef"]

    def create_function(self, addr: int, reanalyze: bool = True):
        """Make a function start at `addr` (P)."""
        if not self.bin.is_exec(addr & ~1):
            raise ValueError(f"{addr:#x} is not in executable memory")
        if self.func_edits.get(addr) == "delete":
            del self.func_edits[addr]
        else:
            self.func_edits[addr] = "create"
        self.data_defs.pop(addr, None)
        if reanalyze:
            self.reanalyze()

    def delete_function(self, addr: int, reanalyze: bool = True):
        """Remove the function starting at `addr` (its code is listed as plain bytes)."""
        f = self.functions.get(addr)
        if f is None or f.is_import:
            raise ValueError(f"no function starts at {addr:#x}")
        if self.func_edits.get(addr) == "create":
            del self.func_edits[addr]
        else:
            self.func_edits[addr] = "delete"
        if reanalyze:
            self.reanalyze()

    def load_type_library(self, name: str | None = None) -> dict:
        """Import a bundled type library (decompiler.typelibs: the C library's structs, or the
        Windows API's types and structs -- the default for a PE --, laid out for this binary's
        ABI); one undo step. What was imported, as import_header."""
        from ..decompiler.typelibs import default_library, library_text
        return self.import_header(library_text(name or default_library(self.bin.format), self.bin.arch))

    def lumina_pull(self, store: str | None = None, overwrite: bool = False) -> dict:
        """Names, comments and variable names / types of matching functions from a shared store
        (lumina; one undo step)."""
        from .lumina import Store, pull
        return pull(self, Store(store), overwrite)

    def lumina_push(self, store: str | None = None) -> dict:
        """Send the functions' names, comments and variable names / types to a shared store."""
        from .lumina import Store, push
        return push(self, Store(store))

    def names(self) -> list[tuple[int, str, str]]:
        """Every named address: (address, name as shown, kind: function / import / library /
        data / label)."""
        out: dict[int, tuple[int, str, str]] = {}
        for a, f in self.functions.items():
            kind = "import" if f.is_import else "library" if getattr(f, "library", False) else "function"
            out[a] = (a, self.name(a) or f.name, kind)
        for a, sym in self.bin.symbols.items():
            if a not in out and sym.name and self.bin.is_mapped(a):
                out[a] = (a, self.name(a) or sym.name, "function" if sym.kind == "func" else "data")
        for a in self.renames:
            if a not in out:
                out[a] = (a, self.renames[a], "label")
        return sorted(out.values())

    def set_operand_format(self, addr: int, index: int, fmt: str):
        """Show operand `index` of the instruction at `addr` as hex / dec / char / bin / offset
        (empty: as disassembled)."""
        from ..numfmt import FORMATS
        if fmt and fmt not in FORMATS:
            raise ValueError(f"unknown number format {fmt!r} (one of {', '.join(FORMATS)})")
        ops = self.op_formats.setdefault(addr, {})
        if fmt:
            ops[str(index)] = fmt
        else:
            ops.pop(str(index), None)
        if not ops:
            del self.op_formats[addr]

    def set_number_format(self, func: int, value: int, fmt: str):
        """Show the constant `value` in function `func`'s pseudocode as hex / dec / char / bin
        (empty: chosen by the decompiler)."""
        from ..numfmt import FORMATS
        if fmt and fmt not in FORMATS[:4]:
            raise ValueError(f"unknown number format {fmt!r} (one of {', '.join(FORMATS[:4])})")
        nums = self.num_formats.setdefault(func, {})
        if fmt:
            nums[str(value)] = fmt
        else:
            nums.pop(str(value), None)
        if not nums:
            del self.num_formats[func]

    def bookmark(self, addr: int, text: str | None):
        """Bookmark `addr` with a description (None or empty removes the bookmark)."""
        if text is None or not text.strip():
            self.bookmarks.pop(addr, None)
        else:
            self.bookmarks[addr] = text.strip()

    def save_project(self, path: str | None = None):
        from .project import notes_to_json, sha256
        notes = notes_to_json(self)
        data = {"version": 1, "binary": os.path.basename(self.bin.path)}
        try:
            data["sha256"] = sha256(self)
        except OSError:
            pass
        data.update({k: notes[k] for k in ("renames", "comments", "variables")})
        data["patches"] = {f"{a:#x}": {"old": o.hex(), "new": n.hex()} for a, (o, n) in sorted(self.patches.items())}
        data.update({k: notes[k] for k in ("structs", "types", "bookmarks")})
        data.update({k: notes[k] for k in ("operands", "numbers", "repeatable", "data", "function_edits")
                     if notes[k]})
        if "c_types" in notes:
            data["c_types"] = notes["c_types"]
        if self.snapshots:
            data["snapshots"] = self.snapshots
        if self.history:
            data["history"] = self.history
        with open(path or self.project_path, "w") as fp:
            json.dump(data, fp, indent=2)

    def load_project(self, path: str | None = None) -> bool:
        path = path or self.project_path
        if not os.path.exists(path):
            return False
        with open(path) as fp:
            data = json.load(fp)
        from .project import notes_from_json
        notes_from_json(self, data)
        self.snapshots = dict(data.get("snapshots", {}))
        self.history = list(data.get("history", []))
        return True

    # ------------------------------------------------------------ snapshots
    def take_snapshot(self, name: str) -> dict:
        """Keep a named copy of every annotation (saved with the project); the same name
        replaces it."""
        from .project import take
        return take(self, name)

    def restore_snapshot(self, name: str):
        """Put the annotations of snapshot `name` back (one undo step)."""
        from .project import notes_from_json
        snap = self.snapshots.get(name)
        if snap is None:
            raise KeyError(f"no snapshot '{name}'")
        notes_from_json(self, snap["notes"])

    def delete_snapshot(self, name: str) -> bool:
        return self.snapshots.pop(name, None) is not None

    # ------------------------------------------------------------ history
    def commit(self, message: str, author: str | None = None) -> dict:
        """Record the annotations as a new version (saved with the project)."""
        from .project import commit
        return commit(self, message, author)

    def diff_versions(self, a: int | None = None, b: int | None = None) -> list:
        """Changes from version `a` (default: the latest) to version `b` (default: now):
        [(section, key, before, after)]."""
        from .project import diff, notes_to_json, version
        old = version(self, a)["notes"] if a is not None else (self.history[-1]["notes"] if self.history else {})
        new = version(self, b)["notes"] if b is not None else notes_to_json(self)
        return diff(old, new)

    def checkout(self, vid: int):
        """Put version `vid`'s annotations back (one undo step)."""
        from .project import notes_from_json, version
        notes_from_json(self, version(self, vid)["notes"])

    def merge_project(self, path: str, theirs: bool = False, force: bool = False) -> dict:
        """Merge another project file of this binary (another analyst's work) into the
        annotations (one undo step): see project.merge."""
        from .project import merge
        with open(path) as fp:
            data = json.load(fp)
        if not isinstance(data, dict) or "renames" not in data and "structs" not in data:
            raise ValueError(f"{path}: not a relic project file")
        return merge(self, data, theirs, force)


def _undoable(method):
    """Record the user annotations before an edit, so `Analysis.undo` can put them back (nested
    edits -- `add_field` naming the field -- are one step; an edit that changes nothing is none)."""
    @functools.wraps(method)
    def edit(self, *args, **kwargs):
        if self._in_edit:
            return method(self, *args, **kwargs)
        before = self._notes()
        self._in_edit = True
        try:
            result = method(self, *args, **kwargs)
        finally:
            self._in_edit = False
        if self._notes() != before:
            where = args[0] if args and isinstance(args[0], int) else None
            self._record_edit(("notes", before, where))
        return result
    return edit


for _name in ("rename", "rename_var", "rename_struct", "rename_field", "set_var_type", "set_field_type",
              "add_field", "remove_field", "comment", "bookmark", "import_header", "set_return_type",
              "clear_imported_types", "restore_snapshot", "merge_project", "set_operand_format",
              "set_number_format", "repeatable_comment", "define_data", "undefine", "create_function",
              "delete_function", "lumina_pull", "checkout", "load_type_library"):
    setattr(Analysis, _name, _undoable(getattr(Analysis, _name)))


def analyze(path: str, arch: str | None = None, base: int = 0, sigs: list[str] | None = None) -> Analysis:
    """Load and analyse a binary. `sigs`: library signature files to name functions with
    (default: the .sig files in libsigs.sig_dirs())."""
    from ..loader import load
    an = Analysis(load(path, arch, base))
    an.sig_paths = sigs
    return an.run()


__all__ = ["Analysis", "Block", "Function", "String", "Xref", "analyze"]

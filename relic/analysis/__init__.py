"""Whole-binary analysis: functions, CFGs, xrefs, strings and user annotations."""
from __future__ import annotations

import bisect
import json
import os
from collections import defaultdict
from dataclasses import dataclass

from ..disasm import CALL, CJMP, JMP, Disassembler, Insn
from ..loader.base import Binary
from ..progress import report
from .functions import Block, Function, FunctionAnalyzer
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
        # byte patches: address -> (original bytes, new bytes), applied to `bin.data`
        self.patches: dict[int, tuple[bytes, bytes]] = {}
        self._fstarts: list[int] = []
        self._strings_by_addr: dict[int, String] = {}

    # ------------------------------------------------------------------ run
    def run(self, load_project: bool = True) -> "Analysis":
        if load_project:
            self._apply_saved_patches()
        report("functions", 0, force=True)
        finder = FunctionAnalyzer(self.bin, self.dis)
        self.functions = finder.run()
        if "main" not in self.bin.name_to_addr:
            main = self._main_from_start()
            if main is not None:
                finder.add_function(main, "main")
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

    def reanalyze(self) -> "Analysis":
        """Analyse again (after a patch), keeping names, comments, variable names and patches."""
        keep = (self.renames, self.comments, self.var_names, self.patches, self.struct_names, self.var_types)
        b = self.bin
        self.__dict__.clear()                    # decompiler caches live on the instance too
        self.__init__(b)
        self.renames, self.comments, self.var_names, self.patches, self.struct_names, self.var_types = keep
        return self.run(load_project=False)

    # ------------------------------------------------------------- patches
    def patch(self, addr: int, data: bytes, reanalyze: bool = True) -> bytes:
        """Write `data` at `addr` (see `relic.patch`); returns the bytes it replaced. Patching
        the same address again replaces the earlier patch; overlapping another one is refused."""
        from ..patch import PatchError, write
        end = addr + len(data)
        for a, (_old, new) in self.patches.items():
            if a != addr and a < end and addr < a + len(new):
                raise PatchError(f"overlaps the patch at {a:#x} (revert it first)")
        if addr in self.patches:
            self.revert(addr, reanalyze=False)
        old = write(self.bin, addr, data)
        self.patches[addr] = (old, bytes(data))
        if reanalyze:
            self.reanalyze()
        return old

    def revert(self, addr: int, reanalyze: bool = True) -> bool:
        """Put back the original bytes of the patch at `addr`."""
        from ..patch import write
        p = self.patches.pop(addr, None)
        if p is None:
            return False
        write(self.bin, addr, p[0])
        if reanalyze:
            self.reanalyze()
        return True

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
                return v.value
        return None

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
        types = self.var_types.setdefault(func, {})
        if ctype.strip():
            t = parse_ctype(ctype)
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
        types = self.struct_names.setdefault(struct, {}).setdefault("types", {})
        if ctype.strip():
            types[generated] = str(parse_ctype(ctype))
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

    def comment(self, addr: int, text: str):
        if text:
            self.comments[addr] = text
        else:
            self.comments.pop(addr, None)

    def save_project(self, path: str | None = None):
        data = {
            "version": 1,
            "binary": os.path.basename(self.bin.path),
            "renames": {f"{a:#x}": n for a, n in sorted(self.renames.items())},
            "comments": {f"{a:#x}": c for a, c in sorted(self.comments.items())},
            "variables": {f"{a:#x}": dict(sorted(v.items())) for a, v in sorted(self.var_names.items())},
            "patches": {f"{a:#x}": {"old": o.hex(), "new": n.hex()} for a, (o, n) in sorted(self.patches.items())},
            "structs": dict(sorted(self.struct_names.items())),
            "types": {f"{a:#x}": dict(sorted(v.items())) for a, v in sorted(self.var_types.items())},
        }
        with open(path or self.project_path, "w") as fp:
            json.dump(data, fp, indent=2)

    def load_project(self, path: str | None = None) -> bool:
        path = path or self.project_path
        if not os.path.exists(path):
            return False
        with open(path) as fp:
            data = json.load(fp)
        self.renames = {int(a, 16): n for a, n in data.get("renames", {}).items()}
        self.comments = {int(a, 16): c for a, c in data.get("comments", {}).items()}
        self.var_names = {int(a, 16): dict(v) for a, v in data.get("variables", {}).items()}
        self.struct_names = {k: dict(v) for k, v in data.get("structs", {}).items()}
        self.var_types = {int(a, 16): dict(v) for a, v in data.get("types", {}).items()}
        return True


def analyze(path: str, arch: str | None = None, base: int = 0) -> Analysis:
    from ..loader import load
    return Analysis(load(path, arch, base)).run()


__all__ = ["Analysis", "Block", "Function", "String", "Xref", "analyze"]

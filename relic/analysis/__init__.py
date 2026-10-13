"""Whole-binary analysis: functions, CFGs, xrefs, strings and user annotations."""
from __future__ import annotations

import bisect
import json
import os
from collections import defaultdict
from dataclasses import dataclass

from ..disasm import CALL, CJMP, JMP, Disassembler, Insn
from ..loader.base import Binary
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
        self._fstarts: list[int] = []
        self._strings_by_addr: dict[int, String] = {}

    # ------------------------------------------------------------------ run
    def run(self) -> "Analysis":
        self.functions = FunctionAnalyzer(self.bin, self.dis).run()
        self._fstarts = sorted(self.functions)
        self.strings = find_strings(self.bin)
        self._strings_by_addr = {s.addr: s for s in self.strings}
        self._build_xrefs()
        self.load_project()
        return self

    def _build_xrefs(self):
        for f in self.functions.values():
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
        for f in self.functions.values():
            if self.name(f.addr) == name or f.name == name:
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
        if addr in self.renames:
            return self.renames[addr]
        f = self.functions.get(addr)
        if f is not None:
            return f.name
        return self.bin.name_of(addr)

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
            return self.label(addr)
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
        return True


def analyze(path: str, arch: str | None = None, base: int = 0) -> Analysis:
    from ..loader import load
    return Analysis(load(path, arch, base)).run()


__all__ = ["Analysis", "Block", "Function", "String", "Xref", "analyze"]

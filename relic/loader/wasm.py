"""WebAssembly modules (`.wasm`): disassembly and function discovery (no decompiler).

Addresses are offsets in the file. The code section is the one executable section; each
function starts at its first instruction (past its locals' declarations), named by the export
and `name` sections. Imported functions take one byte each in a synthetic `.imports` section
after the file, so a `call` of one reads `call printf`.
"""
from __future__ import annotations

from .base import Binary, Import, Section, Symbol


def is_wasm(data: bytes) -> bool:
    return data[:4] == b"\0asm" and len(data) >= 8


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    v = shift = 0
    while True:
        b = data[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, pos


def _name(data: bytes, pos: int) -> tuple[str, int]:
    n, pos = _uleb(data, pos)
    return data[pos:pos + n].decode("utf-8", "replace"), pos + n


def load_wasm(path: str, data: bytes) -> Binary:
    sections: list[tuple[int, int, int]] = []          # (id, payload offset, payload size)
    pos = 8
    while pos < len(data):
        sid = data[pos]
        size, p = _uleb(data, pos + 1)
        sections.append((sid, p, size))
        pos = p + size
    imports: list[tuple[str, str]] = []                # imported functions: (module, name)
    exports: dict[int, str] = {}
    names: dict[int, str] = {}
    bodies: list[tuple[int, int]] = []                 # (first instruction, end)
    start = None
    code_sec = None
    for sid, p, size in sections:
        try:
            if sid == 2:                               # imports
                n, q = _uleb(data, p)
                for _ in range(n):
                    mod, q = _name(data, q)
                    fld, q = _name(data, q)
                    kind = data[q]
                    q += 1
                    if kind == 0:
                        _, q = _uleb(data, q)
                        imports.append((mod, fld))
                    elif kind == 1:                    # table: elemtype, limits
                        q += 1
                        flag, q = _uleb(data, q)
                        _, q = _uleb(data, q)
                        if flag & 1:
                            _, q = _uleb(data, q)
                    elif kind == 2:                    # memory: limits
                        flag, q = _uleb(data, q)
                        _, q = _uleb(data, q)
                        if flag & 1:
                            _, q = _uleb(data, q)
                    elif kind == 3:                    # global: type, mutability
                        q += 2
            elif sid == 7:                             # exports
                n, q = _uleb(data, p)
                for _ in range(n):
                    nm, q = _name(data, q)
                    kind = data[q]
                    idx, q = _uleb(data, q + 1)
                    if kind == 0:
                        exports[idx] = nm
            elif sid == 8:                             # start function
                start, _ = _uleb(data, p)
            elif sid == 10:                            # code
                code_sec = (p, size)
                n, q = _uleb(data, p)
                for _ in range(n):
                    body, q = _uleb(data, q)
                    end = q + body
                    groups, r = _uleb(data, q)
                    for _ in range(groups):
                        _, r = _uleb(data, r)
                        r += 1
                    bodies.append((r, end))
                    q = end
            elif sid == 0:                             # custom: the `name` section
                nm, q = _name(data, p)
                if nm == "name":
                    while q < p + size:
                        sub = data[q]
                        sz, q = _uleb(data, q + 1)
                        if sub == 1:
                            n, r = _uleb(data, q)
                            for _ in range(n):
                                idx, r = _uleb(data, r)
                                names[idx], r = _name(data, r)
                        q += sz
        except IndexError:
            continue
    b = Binary(path, data + bytes(len(imports)))
    b.format, b.arch, b.bits, b.endian = "WASM", "wasm", 32, "little"
    if code_sec is not None:
        b.sections.append(Section(".code", code_sec[0], code_sec[1], code_sec[0], r=True, x=True))
    imp_base = len(data)
    if imports:
        b.sections.append(Section(".imports", imp_base, len(imports), imp_base, r=True, x=True))
    funcs: list[int] = []
    for k, (mod, fld) in enumerate(imports):
        b.imports.append(Import(fld, imp_base + k, 0, mod))
        funcs.append(imp_base + k)
    for k, (first, end) in enumerate(bodies):
        idx = len(imports) + k
        funcs.append(first)
        name = names.get(idx) or exports.get(idx) or f"func_{idx}"
        b.add_symbol(Symbol(name, first, end - first, "func", "export" if idx in exports else "symtab"))
    b.wasm_funcs = funcs
    if start is not None and start < len(funcs):
        b.entry = funcs[start]
    else:
        main = next((funcs[i] for i, n in exports.items() if n in ("_start", "main") and i < len(funcs)), None)
        b.entry = main or (funcs[len(imports)] if len(funcs) > len(imports) else 0)
    b.info["type"] = "WebAssembly module"
    b._finalize()
    return b

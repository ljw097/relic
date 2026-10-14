"""Struct recovery: memory reached at fixed offsets from one base becomes a struct with fields.

`*(int *)(notes[i] + 8) = n` reads better as `notes[i]->f_8 = n` with a
`struct s_notes { void *f_0; int f_8; }` beside it. A *base* is what an
access is relative to:

- a pointer variable or parameter (`p`, `a1`), per function;
- a global pointer (`*g`) or an element of a global array of pointers
  (`notes[i]`): the same struct in every function that touches the global,
  so the fields seen in `add_note` also explain `show_note`.

A base becomes a struct when it is accessed at fixed offsets with more than
one access width (an `int *` indexed with constants stays an array). Fields
are typed from what they hold: a pointer-sized field stored from `malloc`
is `void *`, one used as a format / string argument `char *`, one used as an
address `void *`, the rest are integers of their width. Gaps get padding
members, so the declarations compile with the recovered layout.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .ir import (Assign, BinOp, CallStmt, Const, Expr, IRFunction, Load, StackVar, Store, Var, stmt_exprs,
                 walk)
from .sigs import lookup
from .vartypes import int_type

if TYPE_CHECKING:
    from ..analysis import Analysis

MAX_SCAN = 48          # functions scanned for a global's struct


@dataclass
class Field:
    offset: int
    bits: int
    ctype: str = ""
    name: str = ""

    @property
    def end(self) -> int:
        return self.offset + self.bits // 8


@dataclass
class Struct:
    name: str
    key: tuple
    fields: dict[int, Field] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return max((f.end for f in self.fields.values()), default=0)

    def field_at(self, offset: int, bits: int) -> Field | None:
        f = self.fields.get(offset)
        return f if f is not None and f.bits == bits else None

    def declaration(self, sname=None, fname=None) -> list[str]:
        """C lines; `sname` / `fname(field)` give the names to show (user renames)."""
        fname = fname or (lambda f: f.name)
        out = [f"struct {sname or self.name} {{  // recovered, {self.size} bytes"]
        pos = 0
        for off in sorted(self.fields):
            f = self.fields[off]
            if off > pos:
                out.append(f"    char _pad_{pos:x}[{off - pos}];")
            elif off < pos:
                continue                     # overlaps the previous field: shown through casts
            t = f.ctype or int_type(f.bits)
            sep = "" if t.endswith("*") else " "
            out.append(f"    {t}{sep}{fname(f)};")
            pos = f.end
        out.append("};")
        return out


# ---------------------------------------------------------------- shapes
def split_addr(addr: Expr) -> tuple[Expr, int] | None:
    """(base, constant offset) for `base`, `base + k`, `base - k`; None for a constant address or
    an indexed one (`base + i*4`: an array)."""
    if isinstance(addr, Const):
        return None
    if isinstance(addr, BinOp) and addr.op in ("+", "-"):
        for base, off in ((addr.a, addr.b), (addr.b, addr.a)) if addr.op == "+" else ((addr.a, addr.b),):
            if isinstance(off, Const) and not isinstance(base, Const):
                k = off.signed if addr.op == "+" else -off.signed
                if 0 <= k < 0x10000 and not _indexed(base):
                    return base, k
        return None
    if isinstance(addr, (Var, StackVar, Load)):
        return addr, 0
    return None


def _indexed(e: Expr) -> bool:
    return isinstance(e, BinOp) and e.op in ("+", "-")


def _global_of(e: Expr, ptr_bits: int) -> tuple | None:
    """`Load(G)` -> ("gptr", G); `Load(G + i * ptr)` -> ("gelem", G)."""
    if not isinstance(e, Load) or e.bits != ptr_bits:
        return None
    a = e.addr
    if isinstance(a, Const):
        return ("gptr", a.value)
    if isinstance(a, BinOp) and a.op == "+":
        for g, i in ((a.a, a.b), (a.b, a.a)):
            if isinstance(g, Const) and isinstance(i, BinOp) and i.op in ("*", "<<") and isinstance(i.b, Const) \
                    and (i.b.value if i.op == "*" else 1 << i.b.value) == ptr_bits // 8:
                return ("gelem", g.value)
    return None


def _single_defs(fn: IRFunction) -> dict[str, Expr]:
    count: dict[str, int] = {}
    src: dict[str, Expr] = {}
    for s in fn.stmts():
        if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)):
            count[s.dst.name] = count.get(s.dst.name, 0) + 1
            src[s.dst.name] = s.src
        elif hasattr(s, "defs"):
            for _, d in getattr(s, "defs", ()):
                if isinstance(d, (Var, StackVar)):
                    count[d.name] = count.get(d.name, 0) + 2
    return {n: e for n, e in src.items() if count[n] == 1}


def _resolve(e: Expr, defs: dict[str, Expr], depth: int = 4) -> Expr:
    """`e` with single-definition variables in its address replaced by what they hold
    (`*v4` where `v4 = &notes + i*8` is `notes[i]`)."""
    if depth <= 0:
        return e
    if isinstance(e, Load) and isinstance(e.addr, (Var, StackVar)) and e.addr.name in defs:
        return Load(_resolve(defs[e.addr.name], defs, depth - 1), e.bits)
    if isinstance(e, BinOp) and e.op in ("+", "<<", "*"):
        return BinOp(e.op, _resolve(e.a, defs, depth - 1), _resolve(e.b, defs, depth - 1), e.bits)
    if isinstance(e, (Var, StackVar)) and e.name in defs and isinstance(defs[e.name], (BinOp, Var, StackVar)):
        return _resolve(defs[e.name], defs, depth - 1)
    return e


def base_key(base: Expr, fn_addr: int, defs: dict[str, Expr], ptr_bits: int,
             aliases: dict[str, tuple] | None = None) -> tuple | None:
    """What identifies the struct a base points to (see the module docstring). `aliases` are
    variables stored into a global's slot (`notes[i] = v3`): they point to the global's struct."""
    seen = 0
    while isinstance(base, (Var, StackVar)) and seen < 4:
        if aliases and base.name in aliases:
            return aliases[base.name]
        nxt = defs.get(base.name)
        if nxt is None or (_global_of(_resolve(nxt, defs), ptr_bits) is None
                           and not isinstance(nxt, (Var, StackVar))):
            break
        base, seen = nxt, seen + 1
    g = _global_of(_resolve(base, defs), ptr_bits)
    if g is not None:
        return g
    if isinstance(base, (Var, StackVar)) and base.bits == ptr_bits:
        return ("var", fn_addr, base.name)
    return None


def store_aliases(fn: IRFunction, defs: dict[str, Expr], ptr_bits: int) -> dict[str, tuple]:
    """Variables written into a global pointer slot: `notes[i] = v3` makes v3 a `notes` element."""
    out: dict[str, tuple] = {}
    for s in fn.stmts():
        if isinstance(s, Store) and isinstance(s.src, (Var, StackVar)) and s.src.bits == ptr_bits:
            g = _global_of(_resolve(Load(s.dst, ptr_bits), defs), ptr_bits)
            if g is not None:
                out.setdefault(s.src.name, g)
    return out


# ---------------------------------------------------------------- scanning
@dataclass
class _Use:
    sizes: dict[int, set] = field(default_factory=dict)      # offset -> widths
    hints: dict[int, str] = field(default_factory=dict)      # offset -> C type

    def add(self, off: int, bits: int):
        self.sizes.setdefault(off, set()).add(bits)

    def hint(self, off: int, t: str):
        if t and (off not in self.hints or self.hints[off] == "void *"):
            self.hints[off] = t


def scan(fn: IRFunction, fn_addr: int, ptr_bits: int) -> dict[tuple, _Use]:
    """Fixed-offset accesses per base key in one (non-SSA, prepared) function."""
    defs = _single_defs(fn)
    aliases = store_aliases(fn, defs, ptr_bits)
    uses: dict[tuple, _Use] = {}

    def access(addr: Expr, bits: int) -> tuple | None:
        sp = split_addr(addr)
        if sp is None:
            return None
        key = base_key(sp[0], fn_addr, defs, ptr_bits, aliases)
        if key is None:
            return None
        uses.setdefault(key, _Use()).add(sp[1], bits)
        return key, sp[1]

    loaded: dict[Expr, tuple] = {}         # Load expression -> (key, offset), for typing hints
    for s in fn.stmts():
        for top in stmt_exprs(s):
            for x in walk(top):
                if isinstance(x, Load):
                    r = access(x.addr, x.bits)
                    if r is not None:
                        loaded[x] = r
                    # a loaded value used as an address: the field holds a pointer
                    inner = split_addr(x.addr)
                    if inner is not None and inner[0] in loaded:
                        k, o = loaded[inner[0]]
                        uses[k].hint(o, "void *")
        if isinstance(s, Store):
            r = access(s.dst, s.bits)
            if r is not None and s.src.bits == ptr_bits:
                t = _call_ret_type(fn, s.src)
                if t:
                    uses[r[0]].hint(r[1], t)
        if isinstance(s, CallStmt):
            sig = lookup(s.name)
            for k, a in enumerate(s.call.args):
                if a in loaded and sig is not None and (sig.fmt == k or s.name and _string_arg(s.name, k)):
                    key, o = loaded[a]
                    uses[key].hint(o, "char *")
    return uses


def _string_arg(name: str, k: int) -> bool:
    from .sigs import base_name
    n = base_name(name)
    return (n in ("puts", "strlen", "strdup", "atoi", "atol", "strtol", "system", "fputs", "perror") and k == 0) or \
        (n in ("strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp") and k in (0, 1))


def _call_ret_type(fn: IRFunction, v: Expr) -> str:
    """`v = malloc(n)` -> "void *" (the library return type of the call defining v)."""
    for s in fn.stmts():
        if isinstance(s, CallStmt) and any(d == v for _, d in s.defs):
            sig = lookup(s.name)
            if sig is not None and sig.ret.endswith("*"):
                return sig.ret
    return ""


def _is_struct(use: _Use, global_elem: bool = False) -> bool:
    """Several offsets that do not look like an array: different widths, a pointer field next to
    a non-pointer one, or the elements of a global pointer array (`notes[i]->...`)."""
    if len(use.sizes) < 2:
        return False
    widths = {b for bs in use.sizes.values() for b in bs}
    kinds = {use.hints.get(o, "").endswith("*") for o in use.sizes}
    return len(widths) >= 2 or len(kinds) == 2 or global_elem


def _build(name: str, key: tuple, use: _Use, ptr_bits: int) -> Struct:
    st = Struct(name, key)
    for off in sorted(use.sizes):
        bits = max(use.sizes[off])
        t = use.hints.get(off, "")
        if bits != ptr_bits and t.endswith("*"):
            t = ""
        st.fields[off] = Field(off, bits, t, f"f_{off:x}")
    return st


# ---------------------------------------------------------------- per analysis
def _scan_function(an: "Analysis", f) -> dict[tuple, _Use]:
    cache = an.__dict__.setdefault("_struct_scan", {})
    if f.addr not in cache:
        from .pipeline import prepare
        try:
            prep = prepare(an, f)
            cache[f.addr] = scan(prep.fn, f.addr, prep.arch.bits)
        except Exception:  # noqa: BLE001 - a function that does not decompile adds nothing
            cache[f.addr] = {}
    return cache[f.addr]


def _global_name(an: "Analysis", g: int) -> str:
    # the binary's own symbol, not the user's rename: saved struct names are keyed by this
    n = an.bin.name_of(g) or f"{g:x}"
    return "s_" + "".join(c if c.isalnum() or c == "_" else "_" for c in n)


def global_struct(an: "Analysis", key: tuple, ptr_bits: int) -> Struct | None:
    """The struct behind a global (`gptr` / `gelem` key), from every function referencing it."""
    reg = an.__dict__.setdefault("_structs", {})
    if key in reg:
        return reg[key]
    reg[key] = None                          # (being computed: no recursion through prepare)
    funcs = []
    for x in an.xrefs_to.get(key[1], ()):
        f = an.function_at(x.frm)
        if f is not None and f not in funcs and not f.is_import:
            funcs.append(f)
    use = _Use()
    for f in funcs[:MAX_SCAN]:
        u = _scan_function(an, f).get(key)
        if u is None:
            continue
        for off, bs in u.sizes.items():
            use.sizes.setdefault(off, set()).update(bs)
        for off, t in u.hints.items():
            use.hint(off, t)
    st = _build(_global_name(an, key[1]), key, use, ptr_bits) if _is_struct(use, key[0] == "gelem") else None
    reg[key] = st
    return st


class StructView:
    """The structs one function's pseudocode uses, and how to print accesses through them."""

    def __init__(self, an: "Analysis", fn: IRFunction, ptr_bits: int):
        self.an = an
        self.fn = fn
        self.ptr_bits = ptr_bits
        self.defs = _single_defs(fn)
        self.aliases = store_aliases(fn, self.defs, ptr_bits)
        self.local: dict[tuple, Struct] = {}
        self.used: list[Struct] = []
        self._vars: dict[str, Expr] = {}
        for s in fn.stmts():
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, (Var, StackVar)) and x.bits == ptr_bits:
                        self._vars.setdefault(x.name, x)
        n = 0
        for key, use in scan(fn, fn.addr, ptr_bits).items():
            if key[0] == "var" and _is_struct(use):
                n += 1
                fname = "".join(c if c.isalnum() else "_" for c in (an.name(fn.addr) or f"{fn.addr:x}"))
                self.local[key] = _build(f"s_{fname}_{n}", key, use, ptr_bits)

    def struct_of(self, base: Expr) -> Struct | None:
        key = base_key(base, self.fn.addr, self.defs, self.ptr_bits, self.aliases)
        if key is None:
            return None
        st = self.local.get(key) if key[0] == "var" else global_struct(self.an, key, self.ptr_bits)
        if st is not None and st not in self.used:
            self.used.append(st)
        return st

    def var_struct(self, name: str) -> Struct | None:
        """The struct a pointer variable points to (for its declaration): its own, or that of the
        variable / global it is a copy of (`var_10 = a1` at -O0)."""
        v = self._vars.get(name)
        if v is None:
            return None
        if self.aliases.get(name) is None and name not in self.defs and \
                not any(k[2] == name for k in self.local if k[0] == "var"):
            return None
        return self.struct_of(v)

    def field(self, addr: Expr, bits: int) -> tuple[Expr, Struct, Field] | None:
        """(base, struct, field) when `bits` of memory at `addr` are a recovered field."""
        sp = split_addr(addr)
        if sp is None:
            return None
        st = self.struct_of(sp[0])
        if st is None:
            return None
        f = st.field_at(sp[1], bits)
        return (sp[0], st, f) if f is not None else None

    def field_addr(self, e: Expr) -> tuple[Expr, Struct, Field] | None:
        """(base, field) for `base + k` that is the address of a field (`&p->f_8`)."""
        sp = split_addr(e)
        if sp is None or sp[1] == 0 or not isinstance(e, BinOp):
            return None
        st = self.struct_of(sp[0])
        if st is None:
            return None
        f = st.fields.get(sp[1])
        return (sp[0], st, f) if f is not None else None


__all__ = ["Field", "Struct", "StructView", "global_struct", "scan", "split_addr"]

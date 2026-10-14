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

from .ir import (Assign, BinOp, Call, CallStmt, Const, Expr, IRFunction, Load, StackVar, Store, Var, stmt_exprs,
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
    child: "Struct | None" = None            # the struct a pointer field points to

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

    def declaration(self, sname=None, fname=None, ftype=None) -> list[str]:
        """C lines; `sname(struct)` / `fname(field)` give the names to show (user renames),
        `ftype(field)` a field's type when it is not the recovered one."""
        fname = fname or (lambda f: f.name)
        sname = sname or (lambda st: st.name)
        ftype = ftype or (lambda f: None)
        out = [f"struct {sname(self)} {{  // recovered, {self.size} bytes"]
        pos = 0
        for off in sorted(self.fields):
            f = self.fields[off]
            if off > pos:
                out.append(f"    char _pad_{pos:x}[{off - pos}];")
            elif off < pos:
                continue                     # overlaps the previous field: shown through casts
            t = ftype(f) or (f"struct {sname(f.child)} *" if f.child is not None else (f.ctype or int_type(f.bits)))
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
    # `a1 = a1->next` defines a1 once, but in terms of itself (a loop over a list): not a copy
    return {n: e for n, e in src.items() if count[n] == 1
            and not any(isinstance(x, (Var, StackVar)) and x.name == n for x in walk(e))}


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
             aliases: dict[str, tuple] | None = None, depth: int = 3) -> tuple | None:
    """What identifies the struct a base points to (see the module docstring). `aliases` are
    variables stored into a global's slot (`notes[i] = v3`): they point to the global's struct.
    A pointer read out of another struct's field is ("field", that struct's key, offset)."""
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
    # a pointer loaded from a field (`v4 = n->it`, or `n->it` used directly at -O0)
    loaded = defs.get(base.name) if isinstance(base, (Var, StackVar)) else base
    if depth and isinstance(loaded, Load) and loaded.bits == ptr_bits:
        sp = split_addr(loaded.addr)
        if sp is not None:
            parent = base_key(sp[0], fn_addr, defs, ptr_bits, aliases, depth - 1)
            if parent is not None:
                return ("field", parent, sp[1])
    if isinstance(base, (Var, StackVar)) and base.bits == ptr_bits:
        return ("var", fn_addr, base.name)
    return None


def root(key: tuple) -> tuple:
    while key[0] == "field":
        key = key[1]
    return key


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


def scan(fn: IRFunction, fn_addr: int, ptr_bits: int, name_of=None) -> dict[tuple, _Use]:
    """Fixed-offset accesses per base key in one (non-SSA, prepared) function. The entry
    ("links",) maps (key, offset) to the key of a variable assigned that field's pointer
    (`n = n->next`: the field points to the same struct)."""
    defs = _single_defs(fn)
    aliases = store_aliases(fn, defs, ptr_bits)
    uses: dict[tuple, _Use] = {}
    links: dict[tuple, tuple] = {}

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

    def call_args(name, args):
        sig = lookup(name)
        for k, a in enumerate(args):
            # the field itself, or a variable holding it (`v1 = it->name; strlen(v1)`)
            src = defs.get(a.name) if isinstance(a, (Var, StackVar)) else a
            if src in loaded and sig is not None and (sig.fmt == k or name and _string_arg(name, k)):
                key, o = loaded[src]
                uses[key].hint(o, "char *")

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
        if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)) and isinstance(s.src, Load) \
                and s.src in loaded and s.dst.name not in defs and s.dst.bits == ptr_bits:
            dst_key = base_key(s.dst, fn_addr, defs, ptr_bits, aliases)
            if dst_key is not None:
                links[loaded[s.src]] = dst_key
        if isinstance(s, CallStmt):
            call_args(s.name, s.call.args)
        elif name_of is not None:
            # calls folded into an expression (`return strlen(v1) + ...`)
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, Call) and isinstance(x.target, Const):
                        call_args(name_of(x.target.value), x.args)
    uses[("links",)] = links                 # type: ignore[assignment]
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


def _is_struct(use: _Use, global_elem: bool = False, field: bool = False) -> bool:
    """Several offsets that do not look like an array: different widths, a pointer field next to
    a non-pointer one, or the elements of a global pointer array (`notes[i]->...`). A pointer
    read out of a struct field is one already at a single access past its start."""
    if field and use.sizes and max(use.sizes) > 0:
        return True
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
            cache[f.addr] = scan(prep.fn, f.addr, prep.arch.bits, an.name)
        except Exception:  # noqa: BLE001 - a function that does not decompile adds nothing
            cache[f.addr] = {}
    return cache[f.addr]


def _global_name(an: "Analysis", g: int) -> str:
    # the binary's own symbol, not the user's rename: saved struct names are keyed by this
    n = an.bin.name_of(g) or f"{g:x}"
    return "s_" + "".join(c if c.isalnum() or c == "_" else "_" for c in n)


def _key_name(an: "Analysis", key: tuple, local_names: dict | None = None) -> str:
    if key[0] == "field":
        return f"{_key_name(an, key[1], local_names)}_{key[2]:x}"
    if key[0] in ("gptr", "gelem"):
        return _global_name(an, key[1])
    return (local_names or {}).get(key, "s_" + key[2])


def global_struct(an: "Analysis", key: tuple, ptr_bits: int) -> Struct | None:
    """The struct behind a global (`gptr` / `gelem` key, or a field chain from one), from every
    function referencing the global."""
    reg = an.__dict__.setdefault("_structs", {})
    if key in reg:
        return reg[key]
    reg[key] = None                          # (being computed: no recursion through prepare)
    g = root(key)
    funcs = []
    for x in an.xrefs_to.get(g[1], ()):
        f = an.function_at(x.frm)
        if f is not None and f not in funcs and not f.is_import:
            funcs.append(f)
    use = _Use()
    links: dict[tuple, tuple] = {}
    for f in funcs[:MAX_SCAN]:
        res = _scan_function(an, f)
        links.update(res.get(("links",), {}))
        u = res.get(key)
        if u is None:
            continue
        for off, bs in u.sizes.items():
            use.sizes.setdefault(off, set()).update(bs)
        for off, t in u.hints.items():
            use.hint(off, t)
    st = _build(_key_name(an, key), key, use, ptr_bits) \
        if _is_struct(use, key[0] == "gelem", key[0] == "field") else None
    reg[key] = st
    if st is not None:
        for off, f in st.fields.items():
            if f.bits == ptr_bits:
                target = links.get((key, off), ("field", key, off))
                f.child = st if target == key else global_struct(an, target, ptr_bits) if root(target)[0] != "var" \
                    else None
    return st


class StructView:
    """The structs one function's pseudocode uses, and how to print accesses through them."""

    def __init__(self, an: "Analysis", fn: IRFunction, ptr_bits: int, user_types: dict[str, str] | None = None):
        self.an = an
        self.fn = fn
        self.ptr_bits = ptr_bits
        self.defs = _single_defs(fn)
        self.aliases = store_aliases(fn, self.defs, ptr_bits)
        self.local: dict[tuple, Struct] = {}
        self.used: list[Struct] = []
        self._vars: dict[str, Expr] = {}
        self._copies: dict[str, list[str]] = {}
        for s in fn.stmts():
            if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)) and isinstance(s.src, (Var, StackVar)):
                self._copies.setdefault(s.src.name, []).append(s.dst.name)
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, (Var, StackVar)) and x.bits == ptr_bits:
                        self._vars.setdefault(x.name, x)
        n = 0
        res = scan(fn, fn.addr, ptr_bits, an.name)
        links = res.pop(("links",), {})
        fname = "".join(c if c.isalnum() else "_" for c in (an.name(fn.addr) or f"{fn.addr:x}"))
        names: dict[tuple, str] = {}
        for key in sorted((k for k in res if k[0] == "var"), key=str):
            n += 1
            names[key] = f"s_{fname}_{n}"
        self._res = res
        known = an.__dict__.setdefault("_local_structs", {})     # every local struct seen, by name
        for key, use in res.items():
            if root(key)[0] == "var" and _is_struct(use, field=key[0] == "field"):
                st = _build(_key_name(an, key, names), key, use, ptr_bits)
                old = known.get(st.name)
                if old is not None:
                    # decompiled again: keep the one object other functions may have grown
                    for off, f in st.fields.items():
                        if off not in old.fields and not any(g.offset < off < g.end for g in old.fields.values()):
                            old.fields[off] = f
                    st = old
                self.local[key] = known[st.name] = st
        # variables the user typed `struct X *`
        self.forced: dict[str, Struct] = {}
        for gen, ctype in (user_types or {}).items():
            if ctype.startswith("struct ") and ctype.endswith("*") and ctype.count("*") == 1:
                st = self.find(ctype[7:].rstrip(" *"))
                if st is not None:
                    self.forced[gen] = self._extended(st, ("var", fn.addr, gen))
        for key, st in self.local.items():
            for off, f in st.fields.items():
                if f.bits == ptr_bits:
                    target = links.get((key, off), ("field", key, off))
                    f.child = st if target == key else self._struct_for_key(target)

    def find(self, name: str) -> Struct | None:
        """A struct by the name shown (a user's rename) or its generated name; one the user named
        but that this session has not recovered yet comes from the layout saved in the project."""
        gen = next((g for g, d in self.an.struct_names.items() if d.get("name") == name), name)
        for st in list(self.local.values()) + list(self.an.__dict__.get("_structs", {}).values()) + \
                list(self.an.__dict__.get("_local_structs", {}).values()):
            if st is not None and st.name == gen:
                return st
        layout = self.an.struct_names.get(gen, {}).get("layout")
        if not layout:
            return None
        st = Struct(gen, ("saved", gen))
        for off, (bits, ctype) in layout.items():
            st.fields[int(off, 16)] = Field(int(off, 16), bits, ctype, f"f_{int(off, 16):x}")
        self.an.__dict__.setdefault("_local_structs", {})[gen] = st
        return st

    def _extended(self, st: Struct, key: tuple) -> Struct:
        """`st` grown with the fields this function reaches through `key` (in place: every
        function the user applied the struct to adds what it uses, one definition for all)."""
        use = self._res.get(key)
        if use is None:
            return st
        new = st
        for off, bs in use.sizes.items():
            if off not in new.fields and not any(f.offset < off < f.end for f in new.fields.values()):
                new.fields[off] = Field(off, max(bs), use.hints.get(off, "") if max(bs) == self.ptr_bits else "",
                                        f"f_{off:x}")
        return new

    def field_type(self, st: Struct, f: Field) -> str | None:
        """The user's type of a field, if any."""
        return self.an.struct_names.get(st.name, {}).get("types", {}).get(f.name)

    def _struct_for_key(self, key: tuple) -> Struct | None:
        if key[0] == "var" and key[2] in self.forced:
            return self.forced[key[2]]
        if key[0] == "field":
            # a field the user typed `struct X *`: its pointer reaches X
            parent = self._struct_for_key(key[1])
            f = parent.fields.get(key[2]) if parent is not None else None
            t = self.field_type(parent, f) if f is not None else None
            if t and t.startswith("struct ") and t.count("*") == 1:
                st = self.find(t[7:].rstrip(" *"))
                if st is not None:
                    return st
        return self.local.get(key) if root(key)[0] == "var" else global_struct(self.an, key, self.ptr_bits)

    def child(self, st: Struct, f: Field) -> Struct | None:
        """The struct a pointer field points to: the user's `struct X *` type, else recovered."""
        t = self.field_type(st, f)
        if t is not None:
            return self.find(t[7:].rstrip(" *")) if t.startswith("struct ") and t.count("*") == 1 else None
        return f.child

    def _use(self, st: Struct):
        """Record a struct shown, and those its fields point to (declared before it). A struct the
        user named keeps its layout in the project, so types that name it work in a new session."""
        if st in self.used:
            return
        d = self.an.struct_names.get(st.name)
        if d is not None:
            d["layout"] = {f"{o:#x}": [f.bits, f.ctype] for o, f in sorted(st.fields.items())}
        for f in st.fields.values():
            c = self.child(st, f)
            if c is not None and c is not st and c not in self.used and \
                    all(c.name != u.name for u in self.used):
                self._use(c)
        if st not in self.used:
            self.used.append(st)

    def struct_of(self, base: Expr) -> Struct | None:
        key = base_key(base, self.fn.addr, self.defs, self.ptr_bits, self.aliases)
        if key is None:
            return None
        st = self._struct_for_key(key)
        if st is not None:
            self._use(st)
        return st

    def var_struct(self, name: str) -> Struct | None:
        """The struct a pointer variable points to (for its declaration): its own, or that of the
        variable / global it is a copy of (`var_10 = a1` at -O0)."""
        if name in self.forced:
            self._use(self.forced[name])
            return self.forced[name]
        v = self._vars.get(name)
        if v is None:
            return None
        if self.aliases.get(name) is None and name not in self.defs and \
                not any(k[2] == name for k in self.local if k[0] == "var"):
            # copied into a variable that is one (`var_20 = a1`, var_20 walking a list)
            for dst in self._copies.get(name, ()):
                if dst != name and any(k[2] == dst for k in self.local if k[0] == "var"):
                    return self.struct_of(self._vars[dst])
            return None
        return self.struct_of(v)

    def var_field_type(self, name: str) -> str | None:
        """The pointer type of the field a variable is a copy of (`v1 = a1->name`: `char *`)."""
        d = self.defs.get(name)
        if not isinstance(d, Load):
            return None
        fa = self.field(d.addr, d.bits)
        if fa is None:
            return None
        _, st, f = fa
        t = self.field_type(st, f) or f.ctype
        return t if t.endswith("*") and not t.startswith("struct ") else None

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

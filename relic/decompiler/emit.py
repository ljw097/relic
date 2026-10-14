"""Stage 5: render the structured IR as C-like pseudocode.

`decompile(an, func)` runs `pipeline.prepare` and prints the result:

    int checksum(char *a1)
    {
        int var_c;      // ret-0xc
        ...
    }

Every output line carries the address of the instruction it came from, so
the CLI and the GUI can map between pseudocode and disassembly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from . import ir
from .ir import (Assign, BinOp, CallStmt, Cast, Const, Effect, Expr, Extract, Intrinsic, Ite, Load, Reg, Return,
                 StackAddr, StackVar, Store, UnOp, Unknown, Var)
from .sigs import base_name
from .structure import Block, If, Jump1, Loop, Ret, Seq, Switch, _negate, case_labels
from .vartypes import CType, infer_types, int_type, library_types, parse_ctype

if TYPE_CHECKING:
    from ..analysis import Analysis, Function
    from .pipeline import Prepared


@dataclass
class Line:
    text: str
    addr: int | None = None
    depth: int = 0


@dataclass
class Decompiled:
    name: str
    addr: int
    lines: list[Line] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)   # shown name -> generated name
    structs: dict[str, str] = field(default_factory=dict)     # shown struct name -> generated name
    fields: dict[str, list] = field(default_factory=dict)     # shown field -> [(struct, field), ...]
    types: dict[str, str] = field(default_factory=dict)       # generated variable name -> C type shown

    @property
    def text(self) -> str:
        return "\n".join(("    " * ln.depth + ln.text) if ln.text else "" for ln in self.lines)

    def __str__(self) -> str:
        return self.text

    def lines_at(self, addr: int) -> list[int]:
        """Line numbers produced from the instruction at `addr`."""
        return [k for k, ln in enumerate(self.lines) if ln.addr == addr]


# ----------------------------------------------------------------- constants
def number(v: int) -> str:
    """Decimal when it reads better (small, or rounder in decimal), else hex."""
    if v < 10:
        return str(v)
    dec, hx = str(v), f"{v:x}"
    zeros = lambda s: len(s) - len(s.rstrip("0"))
    return dec if v < 256 or zeros(dec) > zeros(hx) else f"{v:#x}"


def _bare(e: Expr) -> Expr:
    """Strip extensions C performs implicitly (argument passing, return)."""
    while isinstance(e, Cast) and e.kind in ("zext", "sext"):
        e = e.a
    return e


_NUMERIC_OPS = {"*", "/u", "/s", "%u", "%s", "<<", ">>u", ">>s", "&", "|", "^"}

# C precedence, larger binds tighter
PREC_TERNARY, PREC_UNARY, PREC_POSTFIX = 3, 14, 15
BIN = {"||": ("||", 4), "&&": ("&&", 5), "|": ("|", 6), "^": ("^", 7), "&": ("&", 8),
       "==": ("==", 9), "!=": ("!=", 9), "<s": ("<", 10), "<=s": ("<=", 10), "<u": ("<", 10), "<=u": ("<=", 10),
       "<<": ("<<", 11), ">>u": (">>", 11), ">>s": (">>", 11), "+": ("+", 12), "-": ("-", 12),
       "*": ("*", 13), "/u": ("/", 13), "/s": ("/", 13), "%u": ("%", 13), "%s": ("%", 13)}
FLIP = {"<": ">", "<=": ">="}


class CWriter:
    def __init__(self, an: "Analysis", prep: "Prepared"):
        self.an = an
        self.p = prep
        self.ptr_bits = prep.arch.bits
        self.types: dict[str, CType] = infer_types(prep.fn, self.ptr_bits, self.is_addr)
        # library calls name what plain integers really are (`strlen(a1)`: a1 is a `char *`); a
        # pointer type recovered from how memory is accessed says more and is kept
        for name, t in library_types(prep.fn, self.ptr_bits, prep.arch.ret, self._callee_name,
                                     lambda a: an.bin.read_cstring(a, 512)).items():
            cur = self.types.get(name)
            if cur is not None and cur.ptr == 0:
                self.types[name] = t
        self.shown_structs: dict[str, str] = {}
        self.shown_fields: dict[str, list] = {}
        self.names: dict[str, str] = {}
        # user names for variables (Analysis.var_names), keyed by the generated name
        self.user: dict[str, str] = dict(an.var_names.get(prep.fn.addr, {}))
        self.shown: dict[str, str] = {}
        self.commented: set[int] = set()
        self.out: list[Line] = []
        self._name_vars()
        # user types (Analysis.var_types, keyed by generated name) -> by the IR's variable names
        wanted = an.var_types.get(prep.fn.addr, {})
        user_types: dict[str, str] = {}
        for name in set(self.types) | set(self.p.params):
            gen = self.names.get(name, name)
            if gen in wanted:
                user_types[name] = wanted[gen]
        from .structs import StructView
        self.structs = StructView(an, prep.fn, self.ptr_bits, user_types)
        for name in list(self.types):
            st = self.structs.var_struct(name)
            if st is not None and self.types[name].ptr <= 1:
                self.types[name] = CType(f"struct {self.sname(st)}", 1)
            else:
                ft = self.structs.var_field_type(name)
                if ft is not None and self.types[name].ptr <= 1:
                    self.types[name] = parse_ctype(ft)
        self.notes: list[str] = []
        for name, t in user_types.items():
            try:
                ct = parse_ctype(t)
            except ValueError:
                continue
            st = self.structs.forced.get(name)
            if st is not None:
                self.types[name] = CType(f"struct {self.sname(st)}", 1)
            elif ct.base.startswith("struct "):
                # no struct by that name (yet): keep what was recovered rather than declare one
                self.notes.append(f"// {self.names.get(name, name)}: no struct {ct.base[7:]} to apply "
                                  "(rename a recovered struct to it first)")
            else:
                self.types[name] = ct

    # ------------------------------------------------------------- structs
    def sname(self, st) -> str:
        shown = self.an.struct_names.get(st.name, {}).get("name") or st.name
        self.shown_structs[shown] = st.name
        return shown

    def ftype(self, st, f) -> str | None:
        """The user's type of a field; a struct it names is shown by its current name."""
        t = self.structs.field_type(st, f)
        if t and t.startswith("struct "):
            target = self.structs.find(t[7:].rstrip(" *"))
            if target is not None:
                return f"struct {self.sname(target)} " + "*" * t.count("*")
        return t

    def fname(self, st, f) -> str:
        shown = self.an.struct_names.get(st.name, {}).get("fields", {}).get(f.name) or f.name
        pairs = self.shown_fields.setdefault(shown, [])
        if (st.name, f.name) not in pairs:
            pairs.append((st.name, f.name))
        return shown

    # ------------------------------------------------------------- naming
    def _name_vars(self):
        for k, r in enumerate(self.p.params):
            self.names[r] = f"a{k + 1}"
        n = 0
        for s in self.p.fn.stmts():
            for d in ir.stmt_defs(s):
                if isinstance(d, Var) and d.name.startswith("v") and d.name not in self.names:
                    n += 1
                    self.names[d.name] = f"v{n}"

    def vname(self, name: str) -> str:
        """Display name of a variable: the user's name, else the generated one (`v3`, `a1`, `var_c`)."""
        gen = self.names.get(name, name)
        shown = self.user.get(gen, gen)
        self.shown[shown] = gen
        return shown

    # -------------------------------------------------------- expressions
    def symbol(self, v: int) -> str | None:
        if not v:
            return None
        n = self.an.name(v)
        if n and "(" in n:                      # demangled C++: `Cls::method(int)` -> `Cls::method`
            from ..demangle import short_name
            n = short_name(n)
        return base_name(n) if n else None

    def const(self, c: Const) -> str:
        v = c.value
        if c.bits == self.ptr_bits and v and self.an.bin.is_mapped(v):
            lit = self.string(v)
            if lit is not None:
                return lit
            sym = self.symbol(v)
            if sym:
                return sym if v in self.an.functions else f"&{sym}"
        if c.bits == self.ptr_bits and v:
            inside = self._inside_object(v)
            if inside is not None:                # in or just past a data object (an end pointer)
                return f"(char *)&{inside[0]} + {number(inside[1])}"
        if c.bits >= 8 and v >> (c.bits - 1) and c.signed > -0x10000:
            return "-" + number(-c.signed)
        return number(v)

    def _inside_object(self, v: int) -> tuple[str, int] | None:
        """(object symbol, offset) for an address inside a sized data object or one past its
        end (`&pool[4]`, a loop's end pointer)."""
        objs = self.__dict__.get("_objs")
        if objs is None:
            import bisect
            objs = sorted((s.addr, s.size, s.name) for s in self.an.bin.symbols.values()
                          if s.kind == "object" and s.size)
            self._objs = objs
            self._obj_starts = [o[0] for o in objs]
            self._bisect = bisect
        k = self._bisect.bisect_left(self._obj_starts, v) - 1
        if k < 0:
            return None
        a, size, name = self._objs[k]
        if a < v <= a + size:
            return base_name(self.an.name(a) or name), v - a
        return None

    def string(self, v: int) -> str | None:
        from ..analysis.strings import escape
        from .refs import _kind
        s = self.an.string_at(v)
        if s is not None:
            return f'"{escape(s.value)}"'
        # other literals (short ones the string scan skips: "> ", "%d") must start a string:
        # a NUL before them -- not the middle of one, which a small integer in a PIE often hits
        prev = self.an.bin.read(v - 1, 1)
        if prev != b"\0":
            return None
        if _kind(self.an, v) == "string":
            return f'"{escape(self.an.bin.read_cstring(v, 256))}"'
        sec = self.an.bin.section_at(v)
        if sec is not None and sec.loaded and not sec.x and not getattr(sec, "w", False):
            text = self.an.bin.read_cstring(v, 256)
            if text and text.isprintable():
                return f'"{escape(text)}"'
        return None

    def _num(self, c: Const) -> str:
        if c.bits >= 8 and c.value >> (c.bits - 1) and c.signed > -0x10000:
            return "-" + number(-c.signed)
        return number(c.value)

    def is_addr(self, v: int) -> bool:
        return bool(v) and self.an.bin.is_mapped(v) and v >= 0x100

    def mem(self, addr: Expr, bits: int) -> str:
        """An lvalue/rvalue for the `bits`-wide memory at `addr`."""
        size = bits // 8
        if isinstance(addr, Const):
            sym = self.symbol(addr.value)
            if sym:
                # the first element of an array object (`pool[0]`): the bare name is the array
                s = self.an.bin.symbols.get(addr.value)
                if s is not None and s.kind == "object" and s.size > size and s.size % size == 0:
                    return f"{sym}[0]"
                return sym
            # a GOT slot read on its own (kept in a register): the address of the import
            imp = self.an.bin.imports_by_got.get(addr.value)
            if imp is not None and imp.name and bits == self.an.bin.bits:
                return f"&{base_name(imp.name)}"
        if isinstance(addr, Load) and isinstance(addr.addr, Const):
            # through a GOT slot: `*(*(stdout@got))` is the imported object itself
            imp = self.an.bin.imports_by_got.get(addr.addr.value)
            if imp is not None and imp.name:
                return base_name(imp.name)
        fa = self.structs.field(addr, bits)
        if fa is not None:
            return f"{self.expr(fa[0], PREC_POSTFIX)}->{self.fname(*fa[1:])}"
        ar = self.structs.array_ref(addr, bits)
        if ar is not None:
            base, st, f, idx = ar
            return f"{self.expr(base, PREC_POSTFIX)}->{self.fname(st, f)}[{self.expr(_bare(idx))}]"
        if self.an.bin.endian == "little":
            pa = self.structs.part_of_field(addr, bits)
            if pa is not None:                    # the low bytes of a wider field
                return f"*({int_type(bits)} *)&{self.expr(pa[0], PREC_POSTFIX)}->{self.fname(*pa[1:])}"
        idx = self._indexed(addr, size)
        if idx is not None:
            base, i = idx
            return f"{base}[{self.expr(i)}]"
        base = addr if isinstance(addr, (Var, StackVar)) else None
        if base is not None:
            t = self.types.get(base.name)
            if t is not None and t.ptr == 1 and t.base == int_type(bits):
                return f"*{self.expr(base, PREC_UNARY)}"
        return f"*({int_type(bits)} *){self.expr(addr, PREC_UNARY)}"

    def _indexed(self, addr: Expr, size: int):
        """(base text, index) for `base + i*size` where base is a symbol or a matching pointer."""
        if not (isinstance(addr, BinOp) and addr.op == "+"):
            return None
        for base, off in ((addr.a, addr.b), (addr.b, addr.a)):
            i = None
            if isinstance(off, BinOp) and off.op == "*" and isinstance(off.b, Const) and off.b.value == size:
                i = off.a
            elif isinstance(off, BinOp) and off.op == "<<" and isinstance(off.b, Const) and 1 << off.b.value == size:
                i = off.a
            elif size == 1 and not isinstance(off, Const):
                i = off
            elif isinstance(off, Const) and off.value % size == 0 and self._ptr_size(base) == size:
                i = Const(off.value // size, off.bits)
            if i is None:
                continue
            if isinstance(base, Const):
                sym = self.symbol(base.value)
                if sym:
                    return sym, _bare(i)
            if isinstance(base, (Var, StackVar)):
                t = self.types.get(base.name)
                if t is not None and t.ptr == 1 and t.base == int_type(size * 8):
                    return self.vname(base.name), _bare(i)
            if isinstance(base, StackAddr):
                return self.vname(base.name), _bare(i)
        return None

    def expr(self, e: Expr, prec: int = 0) -> str:
        text, p = self._expr(e)
        return f"({text})" if p < prec else text

    def _expr(self, e: Expr) -> tuple[str, int]:
        if isinstance(e, Const):
            return self.const(e), PREC_POSTFIX
        if isinstance(e, Var):
            return self.vname(e.name), PREC_POSTFIX
        if isinstance(e, Reg):
            return e.name, PREC_POSTFIX
        if isinstance(e, StackVar):
            return self.vname(e.name), PREC_POSTFIX
        if isinstance(e, StackAddr):
            slot = self.p.frame.slots.get(e.offset)
            if slot is not None and slot.kind == "buffer":
                return self.vname(e.name), PREC_POSTFIX
            return f"&{self.vname(e.name)}", PREC_UNARY
        if isinstance(e, Load):
            text = self.mem(e.addr, e.bits)
            return text, PREC_UNARY if text.startswith("*") else PREC_POSTFIX
        if isinstance(e, BinOp):
            return self._binop(e)
        if isinstance(e, UnOp):
            if e.op == "!":
                neg = _negate(e.a)
                if not (isinstance(neg, UnOp) and neg.op == "!"):
                    return self._expr(neg)
            return f"{e.op}{self.expr(e.a, PREC_UNARY)}", PREC_UNARY
        if isinstance(e, Cast):
            if e.a.bits == 1:                     # bool widened to an int: C does this already
                return self._expr(e.a)
            t = int_type(e.bits, e.kind == "zext")
            if e.kind == "zext" and e.a.bits in (8, 16, 32) and e.a.bits < e.bits and not self._unsigned(e.a) \
                    and not isinstance(e.a, Const):
                # C widens a signed value with its sign: zero-extend through the unsigned type
                inner = e.a.a if isinstance(e.a, Cast) and e.a.kind == "low" else e.a
                return f"({t})({int_type(e.a.bits, True)}){self.expr(inner, PREC_UNARY)}", PREC_UNARY
            return f"({t}){self.expr(e.a, PREC_UNARY)}", PREC_UNARY
        if isinstance(e, Extract):
            inner = self.expr(e.a, 11)
            return f"({int_type(e.bits, True)})({inner} >> {e.lo})", PREC_UNARY
        if isinstance(e, Ite) and e.bits == 1 and (isinstance(e.a, Const) or isinstance(e.b, Const)):
            from .passes import bool_ite
            return self._expr(bool_ite(e))            # `c ? x : 0` reads `c && x`
        if isinstance(e, Ite):
            return (f"{self.expr(e.cond, PREC_TERNARY + 1)} ? {self.expr(e.a, PREC_TERNARY + 1)} : "
                    f"{self.expr(e.b, PREC_TERNARY)}"), PREC_TERNARY
        if isinstance(e, Intrinsic):
            return f"__{e.name}({', '.join(self.expr(a) for a in e.args)})", PREC_POSTFIX
        if isinstance(e, ir.Call):
            return self.call(e), PREC_POSTFIX
        return str(e), PREC_POSTFIX

    def _binop(self, e: BinOp) -> tuple[str, int]:
        if e.op == "+" and e.bits == self.ptr_bits:
            fa = self.structs.field_addr(e)
            if fa is not None:                    # the address of a field: `&p->f_8`
                return f"&{self.expr(fa[0], PREC_POSTFIX)}->{self.fname(*fa[1:])}", PREC_UNARY
        if e.op not in BIN:                       # carry / sborrow ... : flag helpers
            return f"__{e.op}({self.expr(e.a)}, {self.expr(e.b)})", PREC_POSTFIX
        if e.op in _NUMERIC_OPS:
            # operands of *, /, %, shifts and bit operations are numbers, never addresses
            a = Const(e.a.value, e.a.bits) if isinstance(e.a, Const) else e.a
            b = e.b
            if isinstance(a, Const) or isinstance(b, Const):
                op, p = BIN[e.op]
                ta = self._num(a) if isinstance(a, Const) else self.expr(a, p)
                tb = self._num(b) if isinstance(b, Const) else self.expr(b, p + 1)
                return f"{ta} {op} {tb}", p
        op, p = BIN[e.op]
        a, b = e.a, e.b
        if p == 10:
            if isinstance(a, Const) and not isinstance(b, Const):   # `5 < x` reads as `x > 5`
                a, b, op = b, a, FLIP[op]
            if e.op.endswith("u") and not self._unsigned(a):
                left = f"(unsigned {int_type(a.bits)}){self.expr(a, PREC_UNARY)}" if a.bits in (8, 16, 32) \
                    else f"({int_type(a.bits, True)}){self.expr(a, PREC_UNARY)}"
                return f"{left} {op} {self.expr(b, p + 1)}", p
        if e.op in ("+", "-") and (self._struct_ptr(a) or e.op == "+" and self._struct_ptr(b)):
            # a byte offset from a struct pointer (not a field: a loop's end pointer, say)
            if self._struct_ptr(b) and not self._struct_ptr(a):
                a, b = b, a
            return f"(char *){self.expr(a, PREC_UNARY)} {op} {self.expr(b, p + 1)}", p
        if e.op in ("+", "-"):
            ptr = self._scaled(a, b)
            if ptr is not None:
                b = ptr
            elif e.op == "+" and self._ptr_size(b) and not self._ptr_size(a):
                ptr = self._scaled(b, a)
                if ptr is not None:
                    a, b = b, ptr
            elif self._ptr_size(a) > 1:   # byte offset that is not a whole element
                return f"(char *){self.expr(a, PREC_UNARY)} {op} {self.expr(b, p + 1)}", p
        if e.op == "+" and isinstance(b, Const) and b.signed < 0 and b.bits >= 8:
            return f"{self.expr(a, p)} - {number(-b.signed)}", p
        if e.op == "+" and isinstance(a, Const) and not isinstance(b, Const):
            a, b = b, a
        return f"{self.expr(a, p)} {op} {self.expr(b, p + 1)}", p

    _SIZES = {"char": 1, "unsigned char": 1, "short": 2, "unsigned short": 2, "int": 4, "unsigned int": 4,
              "int64_t": 8, "uint64_t": 8}

    def _struct_ptr(self, e: Expr) -> bool:
        if isinstance(e, (Var, StackVar)):
            t = self.types.get(e.name)
            # (a `FILE *` too: C would scale arithmetic on it by an unknown size)
            return t is not None and t.ptr >= 1 and (t.base.startswith("struct ") or t.base == "FILE")
        return False

    def _ptr_size(self, e: Expr) -> int:
        """Element size if `e` is a typed pointer variable (C scales arithmetic on it), else 0."""
        if isinstance(e, (Var, StackVar)):
            t = self.types.get(e.name)
            if t is not None and t.ptr == 1:
                return self._SIZES.get(t.base, 0)
        return 0

    def _scaled(self, ptr: Expr, off: Expr) -> Expr | None:
        """`off` in elements for `ptr + off` (byte offsets in the IR), when it divides evenly."""
        size = self._ptr_size(ptr)
        if size <= 1:
            return off if size == 1 else None
        if isinstance(off, Const) and off.value % size == 0:
            return Const(off.value // size, off.bits)
        if isinstance(off, BinOp) and off.op == "*" and isinstance(off.b, Const) and off.b.value == size:
            return off.a
        if isinstance(off, BinOp) and off.op == "<<" and isinstance(off.b, Const) and 1 << off.b.value == size:
            return off.a
        return None

    def _unsigned(self, e: Expr) -> bool:
        if isinstance(e, (Var, StackVar)):
            t = self.types.get(e.name)
            return t is not None and t.ptr == 0 and (t.base.startswith(("unsigned", "uint")) or t.base == "size_t")
        return isinstance(e, Cast) and e.kind == "zext"

    def _callee_name(self, c: ir.Call) -> str | None:
        t = c.target
        if isinstance(t, Load) and isinstance(t.addr, Const):
            imp = self.an.bin.imports_by_got.get(t.addr.value)
            if imp is not None:                 # through the import's GOT slot (MIPS `jalr $t9`)
                return base_name(imp.name)
        if isinstance(t, Const):
            return self.symbol(t.value) or f"sub_{t.value:x}"
        return None

    def call(self, c: ir.Call) -> str:
        name = self._callee_name(c) or f"(*{self.expr(c.target, PREC_UNARY)})"
        return f"{name}({', '.join(self.expr(_bare(a)) for a in c.args)})"

    # --------------------------------------------------------- statements
    def stmt(self, s) -> str | None:
        if isinstance(s, Assign):
            if isinstance(s.src, ir.Phi):
                return None
            lhs = self.expr(s.dst)
            src = s.src
            if isinstance(src, BinOp) and src.a == s.dst and src.op in ("+", "-", "*", "&", "|", "^", "<<"):
                b = src.b
                if src.op in ("+", "-") and self._ptr_size(s.dst):
                    b = self._scaled(s.dst, b)
                    if b is None:
                        return f"{lhs} = {self.expr(src)};"
                if src.op in ("+", "-") and isinstance(b, Const) and b.value == 1:
                    return f"{lhs}{src.op}{src.op};"
                return f"{lhs} {BIN[src.op][0]}= {self.expr(b)};"
            return f"{lhs} = {self.expr(_bare(src) if self._implicit(s.dst, src) else src)};"
        if isinstance(s, Store):
            return f"{self.mem(s.dst, s.bits)} = {self.expr(s.src)};"
        if isinstance(s, CallStmt):
            text = self.call(s.call)
            ret = next((v for r, v in s.defs if r == self.p.arch.ret), None)
            if ret is not None:
                text = f"{self.expr(ret)} = {text}"
            return text + ";"
        if isinstance(s, ir.IndirectJump):
            return f"goto *{self.expr(s.expr, PREC_UNARY)};  // unresolved jump"
        if isinstance(s, Effect):
            return f"__{s.name}({', '.join(self.expr(a) for a in s.args)});"
        if isinstance(s, Unknown):
            return f'__asm("{s.text}");'
        return f"/* {s} */"

    def _implicit(self, dst: Expr, src: Expr) -> bool:
        """Assignment converts integers implicitly: `int64_t x = (int64_t)i` -> `x = i`."""
        return isinstance(src, Cast) and src.kind in ("zext", "sext") and dst.bits == src.bits

    # ------------------------------------------------------------- blocks
    def emit(self, text: str, addr: int | None, depth: int):
        # a user comment on the instruction shows once, on the first line it produced
        note = self.an.comments.get(addr) if addr is not None and depth > 0 else None
        if note and addr not in self.commented:
            self.commented.add(addr)
            text = f"{text}  // {note}"
        self.out.append(Line(text, addr, depth))

    def node(self, n, depth: int):
        if isinstance(n, Seq):
            items = _tidy(_flatten(n))
            k = 0
            while k < len(items):
                it = items[k]
                nxt = items[k + 1] if k + 1 < len(items) else None
                parts = _for_parts(it, nxt, self.p.gotos) if isinstance(nxt, Loop) else None
                if parts is not None:
                    prev, init, step, body = parts
                    self.node(prev, depth)
                    self._for(nxt, init, step, body, depth)
                    k += 2
                    continue
                self.node(it, depth)
                k += 1
        elif isinstance(n, Block):
            if n.addr in self.p.gotos and not n.copy:
                self.emit(f"loc_{n.addr:x}:", n.addr, max(depth - 1, 0))
            for s in n.stmts:
                text = self.stmt(s)
                if text is not None:
                    self.emit(text, s.addr, depth)
        elif isinstance(n, Ret):
            v = n.stmt.value
            self.emit("return;" if v is None else f"return {self.expr(_bare(v))};", n.stmt.addr, depth)
        elif isinstance(n, Jump1):
            self.emit(f"goto loc_{n.addr:x};" if n.kind == "goto" else f"{n.kind};", None, depth)
        elif isinstance(n, If):
            addr = self._term_addr(n.addr)
            cond, then, els = n.cond, n.then, n.els
            # if (a) { if (b) { X } }  ->  if (a && b) { X }
            inner = _only_if(then, self.p.gotos) if els is None else None
            while inner is not None and inner.els is None:
                cond, then = BinOp("&&", cond, inner.cond, 1), inner.then
                inner = _only_if(then, self.p.gotos)
            # if (c) { ...; return; } else { Y }  ->  if (c) { ...; return; } Y
            if els is not None and _exits(then):
                self.node(If(n.addr, cond, then), depth)
                self.node(els, depth)
                return
            if els is not None and then is not None and _exits(els) and not _exits(then):
                self.node(If(n.addr, _negate(cond), els), depth)
                self.node(then, depth)
                return
            self.emit(f"if ({self.expr(cond)}) {{", addr, depth)
            self.node(then or Seq(), depth + 1)
            while els is not None:
                inner = _only_if(els, self.p.gotos)
                if inner is None:
                    self.emit("} else {", None, depth)
                    self.node(els, depth + 1)
                    break
                self.emit(f"}} else if ({self.expr(inner.cond)}) {{", self._term_addr(inner.addr), depth)
                self.node(inner.then or Seq(), depth + 1)
                els = inner.els
            self.emit("}", None, depth)
        elif isinstance(n, Loop):
            body = n.body
            if n.kind == "while" and n.header in self.p.gotos:
                # the header is only the test: a jump to it re-enters the loop before the test
                self.emit(f"loc_{n.header:x}:", n.header, max(depth - 1, 0))
            if n.kind == "while":
                self.emit(f"while ({self.expr(n.cond)}) {{", None, depth)
            elif n.kind == "dowhile":
                self.emit("do {", None, depth)
            else:
                self.emit("while (1) {", None, depth)
            self.node(_loop_body(body), depth + 1)
            self.emit(f"}} while ({self.expr(n.cond)});" if n.kind == "dowhile" else "}", None, depth)
        elif isinstance(n, Switch):
            self.emit(f"switch ({self.expr(_bare(n.expr))}) {{", self._term_addr(n.addr), depth)
            for case in n.cases:
                for label in case_labels(case, number):
                    self.emit(f"{label}:", case.addr, depth)
                self.node(case.body, depth + 1)
            self.emit("}", None, depth)

    def _for(self, loop: Loop, init, step, body, depth: int):
        text = lambda st: self.stmt(st).rstrip(";")
        self.emit(f"for ({text(init)}; {self.expr(loop.cond)}; {text(step)}) {{", init.addr, depth)
        self.node(body, depth + 1)
        self.emit("}", None, depth)

    def _term_addr(self, block_addr: int) -> int | None:
        b = self.p.fn.blocks.get(block_addr)
        return b.stmts[-1].addr if b is not None and b.stmts else block_addr

    # ------------------------------------------------------------ function
    def signature(self) -> str:
        fn = self.p.fn
        name = base_name(self.an.name(fn.addr) or fn.name)
        if "(" in name:
            from ..demangle import short_name
            name = short_name(name)
        params = []
        for r in self.p.params:
            t = self.types.get(r) or CType(int_type(self.ptr_bits))
            params.append(t.decl(self.vname(r)))
        ret = "void"
        if self.p.returns:
            vals = [s.value for s in fn.stmts() if isinstance(s, Return) and s.value is not None]
            if self.p.ret_bits is not None:
                ret = int_type(self.p.ret_bits)
            else:
                ret = self._ret_type(vals[0]) if vals else "int"
        return f"{ret}{'' if ret.endswith('*') else ' '}{name}({', '.join(params) or 'void'})"

    def _ret_type(self, v: Expr) -> str:
        v = _bare(v)
        if isinstance(v, (Var, StackVar)) and v.name in self.types:
            return str(self.types[v.name])
        if isinstance(v, ir.Call):               # `return strdup(s)`: the library's result type
            from .sigs import lookup
            sig = lookup(self._callee_name(v))
            if sig is not None and sig.ret.endswith("*") and v.bits == self.ptr_bits:
                return sig.ret
        return int_type(v.bits) if v.bits != 1 else "bool"

    @property
    def _base(self) -> str:
        """What stack offsets are relative to: the return address on x86 (it is on the stack
        at entry), the entry stack pointer elsewhere (the return address is in a register)."""
        return "ret" if self.p.arch.name.startswith(("x64", "x86")) else "sp0"

    def declarations(self, depth: int):
        for note in self.notes:
            self.emit(note, None, depth)
        frame = self.p.frame
        used = {x.name for s in self.p.fn.stmts() for top in ir.stmt_exprs(s) for x in ir.walk(top)
                if isinstance(x, (StackVar, StackAddr))}
        used |= {d.name for s in self.p.fn.stmts() for d in ir.stmt_defs(s) if isinstance(d, StackVar)}
        if frame.realigned:
            self.emit("// stack realigned on entry: ret-relative offsets are approximate", None, depth)
        for slot in frame.locals():
            if slot.name() in self.p.params:
                continue                       # a stack parameter: declared in the signature
            if slot.kind == "canary":
                self.emit(f"// stack canary at {self._base}-{-slot.offset:#x} (check hidden)", None, depth)
                continue
            gen = slot.name()
            if gen not in used:
                continue
            name = self.vname(gen)
            where = f"// {self._base}-{-slot.offset:#x}" if slot.offset < 0 else f"// {self._base}+{slot.offset:#x}"
            if slot.kind == "buffer":
                self.emit(f"char {name}[{number(slot.size)}];  {where}", None, depth)
            else:
                t = self.types.get(gen) or CType(int_type(slot.width * 8))
                self.emit(f"{t.decl(name)};  {where}", None, depth)
        regs = sorted({v for v in self.names if v.startswith("v") and v not in self.p.params},
                      key=lambda n: int(self.names[n][1:]))
        for v in regs:
            t = self.types.get(v)
            if t is not None:
                self.emit(f"{t.decl(self.vname(v))};", None, depth)
        if self.out and self.out[-1].depth == depth:
            self.emit("", None, depth)

    def render(self) -> list[Line]:
        self.emit(self.signature(), self.p.fn.addr, 0)
        self.emit("{", None, 0)
        self.declarations(1)
        body = _flatten(self.p.tree)
        if body and isinstance(body[-1], Ret) and body[-1].stmt.value is None:
            body.pop()            # `return;` at the end of a void function says nothing
        self.node(Seq(body), 1)
        # a `return;` that ends a void function says nothing
        if len(self.out) >= 2 and self.out[-1].text == "return;" and self.out[-1].depth == 1:
            self.out.pop()
        self.emit("}", None, 0)
        if self.structs.used:                     # the structs the body refers to, above it
            head = [Line(t, None, 0) for st in self.structs.used
                    for t in st.declaration(self.sname, lambda f, st=st: self.fname(st, f),
                                            lambda f, st=st: self.ftype(st, f)) + [""]]
            self.out[:0] = head
        return self.out


# ------------------------------------------------------------- tree tidying
def _only_if(n, gotos=()):
    """`n` if it is (a Seq of) exactly one If node -- an `else if` / `&&` candidate.

    Empty blocks are ignored unless they carry a label some `goto` jumps to:
    folding the If into `else if` / `&&` would lose that label.
    """
    items = [x for x in _flatten(n)
             if not (isinstance(x, Block) and not x.stmts and (x.copy or x.addr not in gotos))] \
        if n is not None else []
    return items[0] if len(items) == 1 and isinstance(items[0], If) else None


def _exits(n) -> bool:
    """Control never falls out of the end of `n` (return / break / continue / goto)."""
    items = _flatten(n) if n is not None else []
    return bool(items) and isinstance(items[-1], (Ret, Jump1))


def _ends_with(n, kind: str) -> bool:
    while isinstance(n, Seq) and n.items:
        n = n.items[-1]
    return isinstance(n, Jump1) and n.kind == kind


def _is_jump(n, kind: str) -> bool:
    while isinstance(n, Seq) and len(n.items) == 1:
        n = n.items[0]
    return isinstance(n, Jump1) and n.kind == kind


def _drop_last(n):
    if isinstance(n, Jump1):
        return Seq()
    if isinstance(n, Seq) and n.items:
        if isinstance(n.items[-1], Jump1):
            return Seq(n.items[:-1])
        return Seq(n.items[:-1] + [_drop_last(n.items[-1])])
    return n


def _loop_body(body):
    """Tidy a loop body: drop the trailing `continue`, and turn a final
    `if (c) { X; continue; } else { break; }` into `if (!c) break; X`."""
    items = _flatten(body)
    while items and isinstance(items[-1], Jump1) and items[-1].kind == "continue":
        items.pop()
    if items and isinstance(items[-1], If):
        last = items[-1]
        for keep, leave, cond in ((last.then, last.els, _negate(last.cond)), (last.els, last.then, last.cond)):
            # (only when `leave` does leave: falling out of it must not run X)
            if keep is not None and leave is not None and _ends_with(keep, "continue") and \
                    not _ends_with(leave, "continue") and _exits(leave):
                items[-1] = If(last.addr, cond, leave)
                items.append(_drop_last(keep))
                break
            if keep is not None and _is_jump(keep, "continue") and leave is not None:
                items[-1] = If(last.addr, cond, leave)
                break
    return Seq(items)


def _flatten(n) -> list:
    if isinstance(n, Seq):
        return [x for it in n.items for x in _flatten(it)]
    return [n]


def _for_parts(prev, loop, gotos):
    """Split `X = init; while (c(X)) { ...; X += k; }` into for-loop parts.

    Returns (block without the init, init statement, step statement, body
    without the step) or None. A `continue` of this loop in the body rules it
    out: in a `while` it skips the step, in a `for` it would run it.
    """
    if loop.kind != "while" or loop.header in gotos or not isinstance(prev, Block) or not prev.stmts:
        return None
    init = prev.stmts[-1]
    if not isinstance(init, Assign) or not isinstance(init.dst, (Var, StackVar)):
        return None
    x = init.dst
    if not any(v == x for v in ir.walk(loop.cond)):
        return None
    items = _flatten(_loop_body(loop.body))
    last = items[-1] if items else None
    if not isinstance(last, Block) or not last.stmts or (last.addr in gotos and not last.copy):
        return None
    step = last.stmts[-1]
    if not (isinstance(step, Assign) and step.dst == x and isinstance(step.src, BinOp)
            and step.src.op in ("+", "-") and step.src.a == x and isinstance(step.src.b, Const)):
        return None
    if _has_continue(Seq(items)):
        return None
    body = Seq(items[:-1] + ([Block(last.addr, last.stmts[:-1], last.copy)] if last.stmts[:-1] else []))
    return Block(prev.addr, prev.stmts[:-1], prev.copy), init, step, body


def _has_continue(n) -> bool:
    """A `continue` that belongs to the enclosing loop (not to a nested one)."""
    if isinstance(n, Jump1):
        return n.kind == "continue"
    if isinstance(n, Loop):
        return False
    if isinstance(n, Seq):
        return any(_has_continue(x) for x in n.items)
    if isinstance(n, If):
        return _has_continue(n.then) or _has_continue(n.els)
    if isinstance(n, Switch):
        return any(_has_continue(c.body) for c in n.cases)
    return False


def _tidy(items):
    """Drop an empty `else`, and an unreachable `break` right after a `return`."""
    out = []
    for it in items:
        if out and isinstance(it, Jump1) and isinstance(out[-1], (Ret, Jump1)):
            continue
        out.append(it)
    return out


# ----------------------------------------------------------------- entry
def decompile(an: "Analysis", func: "Function") -> Decompiled:
    from .pipeline import prepare
    prep = prepare(an, func)
    w = CWriter(an, prep)
    lines = w.render()
    types = {w.names.get(n, n): str(t) for n, t in w.types.items()}
    return Decompiled(an.name(func.addr) or func.name, func.addr, lines, dict(w.shown), dict(w.shown_structs),
                      {k: list(v) for k, v in w.shown_fields.items()}, types)


__all__ = ["Decompiled", "Line", "decompile", "number"]

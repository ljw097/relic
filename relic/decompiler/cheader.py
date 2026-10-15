"""C declarations -> types the decompiler can use: `struct` / `union` layouts, `enum`s,
`typedef`s and function prototypes, from header text.

The parser covers what headers declaring data structures need: nested and anonymous
aggregates, arrays (constant expressions, `sizeof`, enumerators), pointers, function pointers,
`const` / `volatile` / storage classes, `__attribute__((...))`, comments and preprocessor
lines (skipped; macros are not expanded). Bit-fields and variable-length arrays are refused
with a message naming the line.

Layout follows the target's C ABI: natural alignment, `long` of 64 bits on LP64 (Linux /
macOS 64-bit), 32 on LLP64 (Windows) and ILP32; i386 System V aligns 8-byte members to 4.
A union is laid out as its largest member (relic's structs hold one field per offset); a
nested struct by value is flattened into its parent with dotted field names
(`p->hdr.len`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


class HeaderError(ValueError):
    pass


@dataclass
class Model:
    """Sizes and alignments of a target's C types."""
    ptr: int = 8                # bytes
    long: int = 8
    wchar: int = 4
    align8: int = 8             # alignment of 8-byte scalars inside structs (i386 SysV: 4)
    long_double: int = 16

    @staticmethod
    def for_binary(b) -> "Model":
        if b.bits == 32:
            x86 = b.arch == "x86"
            return Model(4, 4, 2 if b.format == "PE" else 4, 4 if x86 and b.format != "PE" else 8,
                         12 if x86 and b.format != "PE" else 8)
        if b.format == "PE":
            return Model(8, 4, 2, 8, 8)
        return Model()


_SCALARS = {
    "char": 1, "signed char": 1, "unsigned char": 1, "_Bool": 1, "bool": 1,
    "short": 2, "short int": 2, "signed short": 2, "unsigned short": 2, "unsigned short int": 2,
    "int": 4, "signed": 4, "signed int": 4, "unsigned": 4, "unsigned int": 4,
    "long long": 8, "long long int": 8, "signed long long": 8, "unsigned long long": 8,
    "unsigned long long int": 8, "float": 4, "double": 8,
    "int8_t": 1, "uint8_t": 1, "int16_t": 2, "uint16_t": 2, "int32_t": 4, "uint32_t": 4,
    "int64_t": 8, "uint64_t": 8, "__int128": 16, "unsigned __int128": 16,
}
_LONGS = {"long", "long int", "signed long", "unsigned long", "unsigned long int", "long unsigned int"}
_PTRSIZED = {"size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t", "off_t", "time_t"}
# how relic's decompiler spells each base type
_SPELL = {"signed char": "char", "short int": "short", "signed short": "short", "unsigned short int": "unsigned short",
          "signed": "int", "signed int": "int", "unsigned": "unsigned int", "long long int": "long long",
          "signed long long": "long long", "unsigned long long int": "unsigned long long", "long int": "long",
          "signed long": "long", "unsigned long int": "unsigned long", "long unsigned int": "unsigned long",
          "_Bool": "bool"}
_QUALIFIERS = {"const", "volatile", "restrict", "__restrict", "__restrict__", "extern", "static", "inline",
               "__inline", "__inline__", "register", "__extension__", "_Noreturn", "__const"}
_TYPE_WORDS = {"unsigned", "signed", "short", "long", "int", "char", "float", "double", "void", "_Bool", "bool",
               "__int128"}


@dataclass
class CType:
    """A resolved type: base spelling (`int`, `struct node`, `enum color`), pointer depth,
    array dimensions (outermost first)."""
    base: str
    ptr: int = 0
    dims: tuple[int, ...] = ()
    func: bool = False          # a function (only behind a pointer: a function pointer)

    def spell(self) -> str:
        if self.func:
            return "void " + "*" * max(self.ptr, 1)       # function pointers: `void *` for relic
        return self.base + (" " + "*" * self.ptr if self.ptr else "")


@dataclass
class Member:
    name: str
    type: CType
    offset: int = 0


@dataclass
class Aggregate:
    kind: str                   # struct | union
    name: str
    members: list[Member] = field(default_factory=list)
    size: int = 0
    align: int = 1
    complete: bool = False


@dataclass
class Prototype:
    name: str
    ret: CType
    params: list[tuple[str, CType]]
    variadic: bool = False


@dataclass
class Header:
    """What a header declares."""
    aggregates: dict[str, Aggregate] = field(default_factory=dict)      # "struct node" -> ...
    enums: dict[str, dict[str, int]] = field(default_factory=dict)       # "color" -> {RED: 0, ...}
    typedefs: dict[str, CType] = field(default_factory=dict)
    prototypes: dict[str, Prototype] = field(default_factory=dict)
    constants: dict[str, int] = field(default_factory=dict)             # every enumerator
    bare: set[str] = field(default_factory=set)       # names of typedef'd anonymous aggregates / enums


# ------------------------------------------------------------------------ lexer
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<id>[A-Za-z_]\w*)
  | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|0[bB][01]+[uUlL]*|\d+[uUlL]*)
  | (?P<chr>'(?:\\.|[^\\'])')
  | (?P<str>"(?:\\.|[^\\"])*")
  | (?P<op><<|>>|\.\.\.|[{}()\[\];,*=:+\-~!/%&|^<>?.])
""", re.X)


def _strip(text: str) -> str:
    """Drop comments and preprocessor lines (keeping line numbers)."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    out = []
    cont = False
    for line in text.split("\n"):
        if cont or line.lstrip().startswith("#"):
            cont = line.rstrip().endswith("\\")
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def _tokens(text: str) -> list[tuple[str, str, int]]:
    out = []
    pos, line = 0, 1
    text = _strip(text)
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if m is None:
            raise HeaderError(f"line {line}: unexpected {text[pos]!r}")
        kind = m.lastgroup
        tok = m.group(0)
        if kind != "ws":
            out.append((kind, tok, line))
        line += tok.count("\n")
        pos = m.end()
    return out


_ESC = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, "'": 39, '"': 34, "a": 7, "b": 8, "f": 12, "v": 11}


# ------------------------------------------------------------------------ parser
class _Parser:
    def __init__(self, text: str, model: Model, into: Header):
        self.t = _tokens(text)
        self.k = 0
        self.m = model
        self.h = into

    # -- token helpers
    def peek(self, d: int = 0) -> str:
        k = self.k + d
        return self.t[k][1] if k < len(self.t) else ""

    def line(self) -> int:
        return self.t[min(self.k, len(self.t) - 1)][2] if self.t else 0

    def take(self) -> str:
        tok = self.peek()
        self.k += 1
        return tok

    def accept(self, tok: str) -> bool:
        if self.peek() == tok:
            self.k += 1
            return True
        return False

    def expect(self, tok: str) -> None:
        if not self.accept(tok):
            self.fail(f"expected {tok!r}, found {self.peek() or 'end of input'!r}")

    def fail(self, msg: str):
        raise HeaderError(f"line {self.line()}: {msg}")

    def ident(self) -> str:
        kind = self.t[self.k][0] if self.k < len(self.t) else ""
        if kind != "id":
            self.fail(f"expected a name, found {self.peek() or 'end of input'!r}")
        return self.take()

    def skip_attributes(self):
        while self.peek() in ("__attribute__", "__declspec", "__asm__", "__asm", "_Alignas", "alignas"):
            self.take()
            depth = 0
            while True:
                tok = self.take()
                if not tok:
                    self.fail("unterminated attribute")
                if tok == "(":
                    depth += 1
                elif tok == ")":
                    depth -= 1
                    if depth == 0:
                        break

    # -- top level
    def run(self):
        while self.k < len(self.t):
            if self.accept(";"):
                continue
            self.declaration()

    def declaration(self):
        self.skip_attributes()
        typedef = self.accept("typedef")
        base = self.specifiers()
        if self.accept(";"):
            return                                   # `struct node { ... };`
        while True:
            name, ctype, params = self.declarator(base)
            if typedef:
                if name is None:
                    self.fail("typedef without a name")
                if not ctype.ptr and not ctype.dims:
                    ctype = self._name_anonymous(ctype, name)
                    base = ctype
                self.h.typedefs[name] = ctype
            elif params is not None and name is not None and ctype.func:
                self.h.prototypes[name] = Prototype(name, params[2], params[0], params[1])
            if self.peek() == "{":                   # a function definition: skip its body
                self.skip_braces()
                return
            if self.accept("="):
                self.skip_initializer()
            if not self.accept(","):
                break
        self.expect(";")

    def _name_anonymous(self, t: CType, name: str) -> CType:
        """`typedef struct { ... } point;`: the anonymous struct / union / enum takes the name."""
        kind, _, tag = t.base.partition(" ")
        if not tag.startswith("__anon"):
            return t
        if kind == "enum" and tag in self.h.enums and name not in self.h.enums:
            self.h.enums[name] = self.h.enums.pop(tag)
        elif kind in ("struct", "union") and t.base in self.h.aggregates and f"{kind} {name}" not in self.h.aggregates:
            agg = self.h.aggregates.pop(t.base)
            agg.name = name
            self.h.aggregates[f"{kind} {name}"] = agg
        else:
            return t
        self.h.bare.add(name)                 # C knows it only as `name`, not `struct name`
        return CType(f"{kind} {name}", t.ptr, t.dims, t.func)

    def skip_braces(self):
        depth = 0
        while True:
            tok = self.take()
            if not tok:
                self.fail("unbalanced braces")
            depth += tok == "{"
            depth -= tok == "}"
            if depth == 0:
                return

    def skip_initializer(self):
        depth = 0
        while self.peek() and not (depth == 0 and self.peek() in (",", ";")):
            tok = self.take()
            depth += tok in "({["
            depth -= tok in ")}]"

    # -- type specifiers
    def specifiers(self) -> CType:
        words: list[str] = []
        base: CType | None = None
        while True:
            self.skip_attributes()
            tok = self.peek()
            if tok in _QUALIFIERS:
                self.take()
            elif tok in ("struct", "union"):
                if base is not None or words:
                    break
                base = self.aggregate()
            elif tok == "enum":
                if base is not None or words:
                    break
                base = self.enum()
            elif tok in _TYPE_WORDS:
                if base is not None:
                    break
                words.append(self.take())
            elif base is None and not words and tok in self.h.typedefs:
                self.take()
                t = self.h.typedefs[tok]
                base = CType(t.base, t.ptr, t.dims, t.func)
            elif base is None and not words and tok in _PTRSIZED | {"wchar_t", "FILE"} | set(_SCALARS):
                base = CType(self.take())
            else:
                break
        if base is not None:
            return base
        if not words:
            self.fail(f"expected a type, found {self.peek() or 'end of input'!r}")
        return CType(self.canonical(words))

    def canonical(self, words: list[str]) -> str:
        """`unsigned long int` -> `unsigned long`, `signed char` -> `char`, `short int` -> `short`."""
        unsigned = "unsigned" in words
        longs = words.count("long")
        rest = [w for w in words if w not in ("unsigned", "signed", "long", "int")]
        if len(rest) > 1 or rest and rest[0] == "short" and longs:
            self.fail(f"unknown type {' '.join(words)!r}")
        r = rest[0] if rest else ""
        u = "unsigned " if unsigned else ""
        if r in ("char", "short", "__int128"):
            return u + r
        if r in ("float", "void", "_Bool", "bool") and not unsigned and not longs:
            return "bool" if r == "_Bool" else r
        if r == "double" and not unsigned:
            return "long double" if longs == 1 else "double" if not longs else self.fail("long long double")
        if r:
            self.fail(f"unknown type {' '.join(words)!r}")
        if longs > 2:
            self.fail("long long long")
        return u + ("long long" if longs == 2 else "long" if longs else "int")

    def aggregate(self) -> CType:
        kind = self.take()
        self.skip_attributes()
        name = self.take() if self.t[self.k][0] == "id" else None
        self.skip_attributes()
        key = f"{kind} {name}" if name else None
        if self.peek() != "{":
            if key is None:
                self.fail(f"anonymous {kind} without a body")
            self.h.aggregates.setdefault(key, Aggregate(kind, name))
            return CType(key)
        if key is None:
            n = sum(1 for k in self.h.aggregates if k.startswith(f"{kind} __anon"))
            name, key = f"__anon{n}", f"{kind} __anon{n}"
        agg = self.h.aggregates.setdefault(key, Aggregate(kind, name))     # (a later definition wins)
        self.expect("{")
        members: list[Member] = []
        while not self.accept("}"):
            if self.accept(";"):
                continue
            base = self.specifiers()
            if self.accept(";"):                       # an anonymous struct / union member
                if base.base in self.h.aggregates and base.base.split()[1].startswith("__anon"):
                    members.append(Member("", base))
                continue
            while True:
                mname, mtype, _ = self.declarator(base)
                if self.accept(":"):
                    self.fail(f"bit-field {mname or ''!r} in {key}: bit-fields are not supported")
                if mname is None:
                    self.fail(f"member without a name in {key}")
                members.append(Member(mname, mtype))
                if not self.accept(","):
                    break
            self.expect(";")
        self.skip_attributes()
        agg.members = members
        self._layout(agg)
        return CType(key)

    def enum(self) -> CType:
        self.take()
        self.skip_attributes()
        name = self.take() if self.t[self.k][0] == "id" else None
        if self.accept(":"):                           # C23 / C++ underlying type
            self.specifiers()
        if self.peek() != "{":
            if name is None:
                self.fail("anonymous enum without a body")
            return CType(f"enum {name}")
        if name is None:
            n = sum(1 for k in self.h.enums if k.startswith("__anon"))
            name = f"__anon{n}"
        self.expect("{")
        values: dict[str, int] = {}
        nxt = 0
        while not self.accept("}"):
            const = self.ident()
            self.skip_attributes()
            if self.accept("="):
                nxt = self.const_expr(stop=(",", "}"))
            values[const] = nxt
            self.h.constants[const] = nxt
            nxt += 1
            if not self.accept(","):
                self.expect("}")
                break
        self.h.enums[name] = values
        return CType(f"enum {name}")

    # -- declarators
    def declarator(self, base: CType):
        """(name or None, type, (params, variadic, return type) for a function or None)."""
        ptr = 0
        while True:
            self.skip_attributes()
            if self.accept("*"):
                ptr += 1
            elif self.peek() in _QUALIFIERS:
                self.take()
            else:
                break
        name = None
        inner = None                                  # `(*fp)(int)`: the parenthesised part
        if self.peek() == "(" and self.peek(1) in ("*", "^"):
            self.take()
            inner_ptr = 0
            while self.accept("*") or self.accept("^"):
                inner_ptr += 1
                while self.peek() in _QUALIFIERS:
                    self.take()
            if self.t[self.k][0] == "id":
                name = self.take()
            inner_dims = self.dims()
            self.expect(")")
            inner = (inner_ptr, inner_dims)
        elif self.k < len(self.t) and self.t[self.k][0] == "id" and self.peek() not in _QUALIFIERS:
            name = self.take()
        self.skip_attributes()
        params = None
        if self.peek() == "(":
            params = self.parameters()
        dims = self.dims()
        self.skip_attributes()
        t = CType(base.base, base.ptr + ptr, base.dims, base.func)
        if inner is not None:                         # a pointer to a function / array
            if params is not None:
                return name, CType("void", inner[0], inner[1], func=True), None
            return name, CType(t.base, t.ptr + inner[0], inner[1] + dims + t.dims), None
        if params is not None:
            ret = t
            return name, CType(t.base, t.ptr, func=True), (params[0], params[1], ret)
        return name, CType(t.base, t.ptr, dims + t.dims, t.func), None

    def dims(self) -> tuple[int, ...]:
        out = []
        while self.accept("["):
            if self.accept("]"):
                out.append(0)                          # flexible array member
                continue
            out.append(self.const_expr(stop=("]",)))
            self.expect("]")
        return tuple(out)

    def parameters(self):
        self.expect("(")
        params: list[tuple[str, CType]] = []
        variadic = False
        if self.peek() == "void" and self.peek(1) == ")":
            self.k += 2
            return params, variadic
        while not self.accept(")"):
            if self.accept("..."):
                variadic = True
                continue
            base = self.specifiers()
            pname, ptype, _ = self.declarator(base)
            if ptype.dims:                             # array parameters are pointers
                ptype = CType(ptype.base, ptype.ptr + 1, ptype.dims[1:])
            params.append((pname or f"p{len(params) + 1}", ptype))
            if not self.accept(","):
                self.expect(")")
                break
        return params, variadic

    # -- constant expressions
    def const_expr(self, stop) -> int:
        toks = []
        depth = 0
        while self.peek() and not (depth == 0 and self.peek() in stop):
            tok = self.take()
            depth += tok in ("(", "[")
            depth -= tok in (")", "]")
            toks.append(self.t[self.k - 1])
        if not toks:
            self.fail("expected a constant")
        return _Eval(toks, self).run()

    # -- layout
    def size_align(self, t: CType) -> tuple[int, int]:
        n = 1
        for d in t.dims:
            n *= d
        if t.ptr or t.func:
            return self.m.ptr * n, self.m.ptr
        b = t.base
        if b in _SCALARS:
            s = _SCALARS[b]
            return s * n, min(s, self.m.align8) if s == 8 else (16 if s == 16 else s)
        if b in _LONGS:
            return self.m.long * n, min(self.m.long, self.m.align8)
        if b in _PTRSIZED:
            return self.m.ptr * n, self.m.ptr
        if b == "wchar_t":
            return self.m.wchar * n, self.m.wchar
        if b == "long double":
            return self.m.long_double * n, min(self.m.long_double, 16 if self.m.ptr == 8 else 4)
        if b.startswith("enum "):
            return 4 * n, 4
        if b in self.h.aggregates:
            a = self.h.aggregates[b]
            if not a.complete:
                self.fail(f"{b} is used by value before it is defined")
            return a.size * n, a.align
        if b == "void":
            self.fail("a void member")
        self.fail(f"{b!r} has no known size")

    def _layout(self, agg: Aggregate):
        off, align, size = 0, 1, 0
        for m in agg.members:
            s, a = self.size_align(m.type)
            align = max(align, a)
            if agg.kind == "union":
                m.offset = 0
                size = max(size, s)
            else:
                off = (off + a - 1) // a * a
                m.offset = off
                off += s
                size = off
        agg.size = (size + align - 1) // align * align
        agg.align = align
        agg.complete = True


class _Eval:
    """Integer constant expressions (C precedence), with enumerators and `sizeof(type)`."""

    _BIN = [("||",), ("&&",), ("|",), ("^",), ("&",), ("==", "!="), ("<", ">", "<=", ">="), ("<<", ">>"),
            ("+", "-"), ("*", "/", "%")]

    def __init__(self, toks, parser: _Parser):
        # re-join `<` `=` style pairs the lexer splits
        out = []
        for kind, tok, line in toks:
            if out and out[-1][1] in ("<", ">", "=", "!", "&", "|") and tok in ("=", "&", "|") and \
                    out[-1][1] + tok in ("<=", ">=", "==", "!=", "&&", "||"):
                out[-1] = ("op", out[-1][1] + tok, line)
            else:
                out.append((kind, tok, line))
        self.t = out
        self.k = 0
        self.p = parser

    def peek(self) -> str:
        return self.t[self.k][1] if self.k < len(self.t) else ""

    def run(self) -> int:
        v = self.ternary()
        if self.k != len(self.t):
            self.p.fail(f"unexpected {self.peek()!r} in a constant")
        return v

    def ternary(self) -> int:
        c = self.binary(0)
        if self.peek() == "?":
            self.k += 1
            a = self.ternary()
            if self.peek() != ":":
                self.p.fail("expected ':'")
            self.k += 1
            b = self.ternary()
            return a if c else b
        return c

    def binary(self, level: int) -> int:
        if level == len(self._BIN):
            return self.unary()
        v = self.binary(level + 1)
        while self.peek() in self._BIN[level]:
            op = self.t[self.k][1]
            self.k += 1
            w = self.binary(level + 1)
            if op in ("/", "%") and w == 0:
                self.p.fail("division by zero in a constant")
            v = {"||": lambda: int(bool(v or w)), "&&": lambda: int(bool(v and w)), "|": lambda: v | w,
                 "^": lambda: v ^ w, "&": lambda: v & w, "==": lambda: int(v == w), "!=": lambda: int(v != w),
                 "<": lambda: int(v < w), ">": lambda: int(v > w), "<=": lambda: int(v <= w),
                 ">=": lambda: int(v >= w), "<<": lambda: v << w, ">>": lambda: v >> w, "+": lambda: v + w,
                 "-": lambda: v - w, "*": lambda: v * w,
                 "/": lambda: int(v / w), "%": lambda: v - int(v / w) * w}[op]()
        return v

    def unary(self) -> int:
        tok = self.peek()
        if tok in ("-", "+", "~", "!"):
            self.k += 1
            v = self.unary()
            return {"-": -v, "+": v, "~": ~v, "!": int(not v)}[tok]
        if tok == "sizeof":
            self.k += 1
            if self.peek() != "(":
                self.p.fail("sizeof needs parentheses here")
            # parse `(type)` with the main parser on a copy of these tokens
            depth, j = 0, self.k
            while j < len(self.t):
                depth += self.t[j][1] == "("
                depth -= self.t[j][1] == ")"
                j += 1
                if depth == 0:
                    break
            sub = _Parser("", self.p.m, self.p.h)
            sub.t = self.t[self.k + 1:j - 1]
            base = sub.specifiers()
            _, t, _ = sub.declarator(base)
            self.k = j
            return sub.size_align(t)[0]
        if tok == "(":
            self.k += 1
            # a cast: `(unsigned)1`
            if self.peek() in _TYPE_WORDS or self.peek() in self.p.h.typedefs:
                while self.peek() != ")":
                    self.k += 1
                self.k += 1
                return self.unary()
            v = self.ternary()
            if self.peek() != ")":
                self.p.fail("expected ')'")
            self.k += 1
            return v
        if self.k >= len(self.t):
            self.p.fail("constant ends early")
        kind, tok, _ = self.t[self.k]
        self.k += 1
        if kind == "num":
            t = tok.rstrip("uUlL")
            if t.lower().startswith("0x"):
                return int(t, 16)
            if t.lower().startswith("0b"):
                return int(t[2:], 2)
            return int(t, 8) if len(t) > 1 and t.startswith("0") else int(t)
        if kind == "chr":
            body = tok[1:-1]
            return _ESC.get(body[1], ord(body[1])) if body.startswith("\\") else ord(body)
        if kind == "id" and tok in self.p.h.constants:
            return self.p.h.constants[tok]
        self.p.fail(f"{tok!r} is not a known constant (macros are not expanded)")


def parse(text: str, model: Model | None = None, into: Header | None = None) -> Header:
    """Parse header text; `into` adds to what an earlier header declared (its typedefs and
    structs can be used)."""
    h = into if into is not None else Header()
    _Parser(text, model or Model(), h).run()
    return h


# ------------------------------------------------------------- to relic's structs
def struct_layout(h: Header, key: str, model: Model) -> tuple[dict, dict, dict]:
    """A struct / union as relic's saved-struct entries: (layout {"0x8": [bits, ctype(, count)]},
    field names {"f_8": name}, field types {"f_8": ctype}). Nested structs by value are
    flattened (`hdr.len`); a union keeps its largest member."""
    layout: dict = {}
    names: dict = {}
    types: dict = {}
    p = _Parser("", model, h)

    def add(agg: Aggregate, base: int, prefix: str):
        members = agg.members
        if agg.kind == "union" and members:
            members = [max(members, key=lambda m: p.size_align(m.type)[0])]
        for m in members:
            off = base + m.offset
            t = m.type
            label = f"{prefix}{m.name}" if m.name else prefix.rstrip(".")
            if not t.ptr and not t.func and t.base in h.aggregates:
                inner = h.aggregates[t.base]
                if not t.dims:
                    add(inner, off, f"{label}." if m.name else prefix)
                    continue
                size = p.size_align(CType(t.base))[0]                  # an array of structs: bytes
                count = 1
                for d in t.dims:
                    count *= d
                layout[f"{off:#x}"] = [8, "char", size * count]
                names[f"f_{off:x}"] = label
                continue
            spell = t.spell()
            elem_bits = p.size_align(CType(t.base, t.ptr, (), t.func))[0] * 8
            count = None
            if t.dims:
                count = 1
                for d in t.dims:
                    count *= d
            entry = [elem_bits, "" if spell in _PLAIN.get(elem_bits, ()) else spell]
            if count is not None:
                entry.append(count if count else -1)
            layout[f"{off:#x}"] = entry
            names[f"f_{off:x}"] = label
            if spell not in _PLAIN.get(elem_bits, ()):
                types[f"f_{off:x}"] = spell
    add(h.aggregates[key], 0, "")
    return layout, names, types


def declaration(h: Header, key: str) -> tuple[list[str], list[str]]:
    """The C declaration of an aggregate as the header wrote it (anonymous members inline, function
    pointers as `void (*f)()`), and the tags of the structs it holds by value (to declare first)."""
    deps: list[str] = []
    agg = h.aggregates[key]

    def member(m: Member, ind: str) -> list[str]:
        t = m.type
        dims = "".join(f"[{d or ''}]" for d in t.dims)
        if not t.ptr and not t.func and t.base in h.aggregates and h.aggregates[t.base].name.startswith("__anon"):
            inner = h.aggregates[t.base]
            out = [f"{ind}{inner.kind} {{"]
            for x in inner.members:
                out += member(x, ind + "    ")
            return out + [f"{ind}}}{' ' + m.name if m.name else ''}{dims};"]
        if t.func:
            return [f"{ind}void ({'*' * max(t.ptr, 1)}{m.name}{dims})();"]
        if not t.ptr and t.base in h.aggregates:
            tag = h.aggregates[t.base].name
            if tag not in deps:
                deps.append(tag)
        stars = "*" * t.ptr
        return [f"{ind}{t.base} {stars}{m.name}{dims};"]
    if agg.name in h.bare:
        lines = [f"typedef {agg.kind} {{  // from a header, {agg.size} bytes"]
        end = f"}} {agg.name};"
    else:
        lines = [f"{agg.kind} {agg.name} {{  // from a header, {agg.size} bytes"]
        end = "};"
    for m in agg.members:
        lines += member(m, "    ")
    return lines + [end], deps


# field types relic shows on its own for a width (no need to record them)
_PLAIN = {8: ("char",), 16: ("short",), 32: ("int",), 64: ("int64_t",)}


def spell(t: CType) -> str:
    """The C type relic stores for a declared type (arrays decay to their element type)."""
    return t.spell()


__all__ = ["Header", "HeaderError", "Model", "parse", "struct_layout"]

"""Intermediate representation: bit-width-typed expressions and statements.

Expressions are immutable and hashable so later passes can compare and
substitute them freely. Every statement remembers the address of the
machine instruction it came from.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field


def mask(bits: int) -> int:
    return (1 << bits) - 1


# ------------------------------------------------------------------ expressions
class Expr:
    bits: int

    def __str__(self) -> str:
        return fmt(self)

    # expressions are immutable: copying an IR function can share them
    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self


@dataclass(frozen=True, slots=True)
class Const(Expr):
    value: int
    bits: int

    def __post_init__(self):
        object.__setattr__(self, "value", self.value & mask(self.bits))

    @property
    def signed(self) -> int:
        v = self.value
        return v - (1 << self.bits) if v >> (self.bits - 1) else v


@dataclass(frozen=True, slots=True)
class Reg(Expr):
    """Architectural register (full width; sub-registers are expressed with Cast/Extract)."""
    name: str
    bits: int


@dataclass(frozen=True, slots=True)
class Var(Expr):
    """SSA / local variable (produced by later passes)."""
    name: str
    version: int
    bits: int


@dataclass(frozen=True, slots=True)
class StackVar(Expr):
    """A stack slot read as a local variable (`var_14`), produced for output from `Load`s."""
    name: str
    offset: int  # signed offset from the entry stack pointer
    bits: int


@dataclass(frozen=True, slots=True)
class StackAddr(Expr):
    """Address of a stack slot (`&var_14`, or just `buf_48` for an array)."""
    name: str
    offset: int
    bits: int


@dataclass(frozen=True, slots=True)
class Load(Expr):
    addr: Expr
    bits: int


# binary operators. Comparisons and flag helpers produce 1-bit values.
ARITH = ("+", "-", "*", "/u", "/s", "%u", "%s", "&", "|", "^", "<<", ">>u", ">>s", "rol", "ror")
COMPARE = ("==", "!=", "<u", "<=u", "<s", "<=s")
FLAG_OPS = ("carry", "scarry", "borrow", "sborrow")  # add/sub unsigned / signed overflow
BOOL = ("&&", "||")


@dataclass(frozen=True, slots=True)
class BinOp(Expr):
    op: str
    a: Expr
    b: Expr
    bits: int


@dataclass(frozen=True, slots=True)
class UnOp(Expr):
    op: str  # "-" | "~" | "!"
    a: Expr
    bits: int


@dataclass(frozen=True, slots=True)
class Cast(Expr):
    kind: str  # "zext" | "sext" | "low" (truncate)
    a: Expr
    bits: int


@dataclass(frozen=True, slots=True)
class Extract(Expr):
    """Bits [lo, lo+bits) of a wider value (e.g. `ah` = Extract(rax, 8, 8))."""
    a: Expr
    lo: int
    bits: int


@dataclass(frozen=True, slots=True)
class Ite(Expr):
    """`cond ? a : b` (cmovcc)."""
    cond: Expr
    a: Expr
    b: Expr
    bits: int


@dataclass(frozen=True, slots=True)
class Intrinsic(Expr):
    """Operation the IR does not model precisely (parity, SIMD, cpuid, ...)."""
    name: str
    args: tuple[Expr, ...]
    bits: int


@dataclass(frozen=True, slots=True)
class Call(Expr):
    target: Expr
    args: tuple[Expr, ...] = ()
    bits: int = 64
    fargs: tuple = ()      # arguments passed as floats: (index in args, width)


@dataclass(frozen=True, slots=True)
class Phi(Expr):
    sources: tuple[tuple[int, Expr], ...]  # (pred block addr, value)
    bits: int


# ------------------------------------------------------------------- statements
@dataclass(slots=True)
class Stmt:
    addr: int

    def __str__(self) -> str:
        return fmt_stmt(self)


@dataclass(slots=True)
class Assign(Stmt):
    dst: Reg | Var
    src: Expr


@dataclass(slots=True)
class Store(Stmt):
    dst: Expr  # address
    src: Expr

    @property
    def bits(self) -> int:
        return self.src.bits


@dataclass(slots=True)
class Branch(Stmt):
    cond: Expr
    true: int
    false: int


@dataclass(slots=True)
class Jump(Stmt):
    target: int


@dataclass(slots=True)
class IndirectJump(Stmt):
    expr: Expr
    targets: list[int] = field(default_factory=list)  # empty when unresolved
    table: list[int] = field(default_factory=list)    # jump table in index order (with repeats)


@dataclass(slots=True)
class CallStmt(Stmt):
    call: Call
    tail: bool = False  # `jmp func` lifted as call + return
    noreturn: bool = False
    name: str | None = None  # callee name when known (display only)
    # implicit register traffic: (architectural name, value read / variable written)
    uses: list[tuple[str, Expr]] = field(default_factory=list)
    defs: list[tuple[str, Expr]] = field(default_factory=list)
    # registers the callee can change (a local function, see clobbers.py); None: the ABI's set
    clobbers: frozenset | None = None


@dataclass(slots=True)
class Return(Stmt):
    value: Expr | None = None


@dataclass(slots=True)
class Effect(Stmt):
    """Side effect without a result (hlt, ud2, int3, syscall, ...)."""
    name: str
    args: tuple[Expr, ...] = ()
    uses: list[tuple[str, Expr]] = field(default_factory=list)
    defs: list[tuple[str, Expr]] = field(default_factory=list)


@dataclass(slots=True)
class Unknown(Stmt):
    text: str  # original instruction text
    uses: list[tuple[str, Expr]] = field(default_factory=list)
    defs: list[tuple[str, Expr]] = field(default_factory=list)


TERMINATORS = (Branch, Jump, IndirectJump, Return)
BARRIERS = (Store, CallStmt, Effect, Unknown)  # statements that may write memory


# ------------------------------------------------------------------ traversal
# every expression kind's sub-expressions, in source order: a dict on the exact type (no class
# here has subclasses), since `children` runs tens of millions of times in one decompilation
_KIDS = {
    Const: lambda e: (),
    Reg: lambda e: (),
    Var: lambda e: (),
    StackVar: lambda e: (),
    StackAddr: lambda e: (),
    Load: lambda e: (e.addr,),
    UnOp: lambda e: (e.a,),
    Cast: lambda e: (e.a,),
    Extract: lambda e: (e.a,),
    BinOp: lambda e: (e.a, e.b),
    Ite: lambda e: (e.cond, e.a, e.b),
    Intrinsic: lambda e: e.args,
    Call: lambda e: (e.target, *e.args),
    Phi: lambda e: tuple(v for _, v in e.sources),
}


def children(e: Expr) -> tuple[Expr, ...]:
    kids = _KIDS.get(type(e))
    if kids is None:
        raise TypeError(e)
    return kids(e)


def rebuild(e: Expr, kids: tuple[Expr, ...]) -> Expr:
    if isinstance(e, Load):
        return Load(kids[0], e.bits)
    if isinstance(e, UnOp):
        return UnOp(e.op, kids[0], e.bits)
    if isinstance(e, Cast):
        return Cast(e.kind, kids[0], e.bits)
    if isinstance(e, Extract):
        return Extract(kids[0], e.lo, e.bits)
    if isinstance(e, BinOp):
        return BinOp(e.op, kids[0], kids[1], e.bits)
    if isinstance(e, Ite):
        return Ite(kids[0], kids[1], kids[2], e.bits)
    if isinstance(e, Intrinsic):
        return Intrinsic(e.name, tuple(kids), e.bits)
    if isinstance(e, Call):
        return Call(kids[0], tuple(kids[1:]), e.bits, e.fargs)
    if isinstance(e, Phi):
        return Phi(tuple((a, k) for (a, _), k in zip(e.sources, kids)), e.bits)
    return e


def transform(e: Expr, f) -> Expr:
    """Rebuild `e` bottom-up, applying `f` to every node after its children."""
    kids = children(e)
    if kids:
        new, changed = [], False
        for k in kids:                       # (no generator and zip per node: this is a hot path)
            x = transform(k, f)
            new.append(x)
            changed = changed or x is not k
        if changed:
            e = rebuild(e, tuple(new))
    return f(e)


def walk(e: Expr):
    """`e` and every sub-expression, in pre-order (an explicit stack, not nested generators)."""
    stack = [e]
    while stack:
        x = stack.pop()
        yield x
        kids = children(x)
        if kids:
            stack.extend(kids[::-1])


def size(e: Expr) -> int:
    return 1 + sum(size(k) for k in children(e))


def stmt_exprs(s: Stmt) -> list[Expr]:
    """Expressions a statement reads (not including the register/variable it assigns)."""
    if isinstance(s, Assign):
        return [s.src]
    if isinstance(s, Store):
        return [s.dst, s.src]
    if isinstance(s, Branch):
        return [s.cond]
    if isinstance(s, IndirectJump):
        return [s.expr]
    if isinstance(s, CallStmt):
        return [s.call, *(v for _, v in s.uses)]
    if isinstance(s, Return):
        return [s.value] if s.value is not None else []
    if isinstance(s, Effect):
        return [*s.args, *(v for _, v in s.uses)]
    if isinstance(s, Unknown):
        return [v for _, v in s.uses]
    return []


def map_stmt(s: Stmt, f):
    """Replace every expression a statement reads by `f(expr)` (in place)."""
    if isinstance(s, Assign):
        s.src = f(s.src)
    elif isinstance(s, Store):
        s.dst, s.src = f(s.dst), f(s.src)
    elif isinstance(s, Branch):
        s.cond = f(s.cond)
    elif isinstance(s, IndirectJump):
        s.expr = f(s.expr)
    elif isinstance(s, CallStmt):
        s.call = f(s.call)
        s.uses = [(r, f(v)) for r, v in s.uses]
    elif isinstance(s, Return):
        if s.value is not None:
            s.value = f(s.value)
    elif isinstance(s, Effect):
        s.args = tuple(f(a) for a in s.args)
        s.uses = [(r, f(v)) for r, v in s.uses]
    elif isinstance(s, Unknown):
        s.uses = [(r, f(v)) for r, v in s.uses]


def stmt_defs(s: Stmt) -> list[Expr]:
    if isinstance(s, Assign):
        return [s.dst]
    if isinstance(s, (CallStmt, Effect, Unknown)):
        return [v for _, v in s.defs]
    return []


# ----------------------------------------------------------------- containers
@dataclass
class IRBlock:
    addr: int
    stmts: list[Stmt] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)


def copy_stmt(s: Stmt) -> Stmt:
    """A statement to change independently of `s`: its own containers (`uses`, `defs`, jump
    tables), the same immutable expressions."""
    c = copy.copy(s)
    for cls in type(s).__mro__:
        for name in getattr(cls, "__slots__", ()):
            v = getattr(s, name, None)
            if isinstance(v, (list, dict, set)):
                setattr(c, name, type(v)(v))
    return c


class ConstWords(dict):
    """Memory words that hold link-time constants though their section is writable (a GOT the
    loader fills from relocations): address -> (size in bytes, value). Shared, never copied.
    `ro_reader(addr, size)`: also a word of read-only data (PowerPC64 loads 64-bit constants
    from there through the TOC), or None."""
    ro_reader = None

    def __deepcopy__(self, memo):
        return self

    def value(self, addr: int, size: int):
        w = self.get(addr)
        if w is not None:
            return w[1] if w[0] == size else None
        return self.ro_reader(addr, size) if self.ro_reader is not None else None


@dataclass
class IRFunction:
    addr: int
    name: str
    blocks: dict[int, IRBlock] = field(default_factory=dict)
    const_words: ConstWords | None = None

    def __deepcopy__(self, memo):
        # expressions are immutable: new blocks and statements share them (much faster than a
        # generic deep copy, which would rebuild every statement through copyreg)
        new = copy.copy(self)
        new.__dict__ = {k: copy.deepcopy(v, memo) for k, v in self.__dict__.items() if k != "blocks"}
        new.blocks = {a: IRBlock(b.addr, [copy_stmt(st) for st in b.stmts], list(b.succs), list(b.preds))
                      for a, b in self.blocks.items()}
        return new

    def stmts(self):
        for a in sorted(self.blocks):
            yield from self.blocks[a].stmts

    def unknowns(self) -> list[Unknown]:
        return [s for s in self.stmts() if isinstance(s, Unknown)]

    def __str__(self) -> str:
        out = [f"function {self.name} @ {self.addr:#x}"]
        for a in sorted(self.blocks):
            b = self.blocks[a]
            out.append(f"  block {a:#x}:  ; succs {', '.join(f'{s:#x}' for s in b.succs) or '-'}")
            out += [f"    {s.addr:8x}  {s}" for s in b.stmts]
        return "\n".join(out)


# ------------------------------------------------------------------ printing
_PREC = {"||": 1, "&&": 2, "|": 3, "^": 4, "&": 5, "==": 6, "!=": 6,
         "<u": 7, "<=u": 7, "<s": 7, "<=s": 7, "<<": 8, ">>u": 8, ">>s": 8,
         "+": 9, "-": 9, "*": 10, "/u": 10, "/s": 10, "%u": 10, "%s": 10}


def _hex(v: int) -> str:
    return str(v) if v < 10 else f"{v:#x}"


def fmt(e: Expr, prec: int = 0) -> str:
    if isinstance(e, Const):
        if e.bits > 1 and e.value >> (e.bits - 1) and e.bits >= 8 and e.signed > -0x10000:
            return f"-{_hex(-e.signed)}"
        return _hex(e.value)
    if isinstance(e, Reg):
        return e.name
    if isinstance(e, Var):
        return f"{e.name}_{e.version}"
    if isinstance(e, StackVar):
        return e.name
    if isinstance(e, StackAddr):
        return f"&{e.name}"
    if isinstance(e, Load):
        return f"[{fmt(e.addr)}]:{e.bits}"
    if isinstance(e, BinOp):
        p = _PREC.get(e.op)
        if p is None:
            return f"{e.op}({fmt(e.a)}, {fmt(e.b)})"
        s = f"{fmt(e.a, p)} {e.op} {fmt(e.b, p + 1)}"
        return f"({s})" if p < prec else s
    if isinstance(e, UnOp):
        return f"{e.op}({fmt(e.a)})" if e.op.isalpha() else f"{e.op}{fmt(e.a, 11)}"
    if isinstance(e, Cast):
        return f"{e.kind}{e.bits}({fmt(e.a)})"
    if isinstance(e, Extract):
        return f"{fmt(e.a, 11)}[{e.lo}:{e.lo + e.bits}]"
    if isinstance(e, Ite):
        s = f"{fmt(e.cond, 1)} ? {fmt(e.a, 1)} : {fmt(e.b, 1)}"
        return f"({s})" if prec else s
    if isinstance(e, Intrinsic):
        return f"{e.name}({', '.join(fmt(a) for a in e.args)})"
    if isinstance(e, Call):
        return f"call {fmt(e.target, 11)}({', '.join(fmt(a) for a in e.args)})"
    if isinstance(e, Phi):
        return "phi(" + ", ".join(f"{a:#x}: {fmt(v)}" for a, v in e.sources) + ")"
    return repr(e)


def fmt_stmt(s: Stmt) -> str:
    if isinstance(s, Assign):
        return f"{fmt(s.dst)} = {fmt(s.src)}"
    if isinstance(s, Store):
        return f"[{fmt(s.dst)}]:{s.bits} = {fmt(s.src)}"
    if isinstance(s, Branch):
        return f"if ({fmt(s.cond)}) goto {s.true:#x} else {s.false:#x}"
    if isinstance(s, Jump):
        return f"goto {s.target:#x}"
    if isinstance(s, IndirectJump):
        tg = ", ".join(f"{t:#x}" for t in s.targets) if s.targets else "unresolved"
        return f"goto *{fmt(s.expr, 11)}  ; {tg}"
    if isinstance(s, CallStmt):
        tags = [t for t, on in ((s.name, s.name), ("tail call", s.tail), ("noreturn", s.noreturn)) if on]
        lhs = ", ".join(fmt(v) for _, v in s.defs)
        uses = [f"{r}={fmt(v)}" for r, v in s.uses
                if not (isinstance(v, Var) and v.version == 0 and v.name == r)]
        if uses and not s.call.args:  # args, once recovered, already show the real arguments
            tags.append("uses " + ", ".join(uses))
        return (f"{lhs} = " if lhs else "") + fmt(s.call) + (f"  ; {'; '.join(tags)}" if tags else "")
    if isinstance(s, Return):
        return "return" + (f" {fmt(s.value)}" if s.value is not None else "")
    if isinstance(s, Effect):
        lhs = ", ".join(fmt(v) for _, v in s.defs)
        return (f"{lhs} = " if lhs else "") + f"{s.name}({', '.join(fmt(a) for a in s.args)})"
    if isinstance(s, Unknown):
        lhs = ", ".join(fmt(v) for _, v in s.defs)
        return (f"{lhs} = " if lhs else "") + f'__asm("{s.text}")'
    return repr(s)

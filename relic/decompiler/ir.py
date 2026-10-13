"""Intermediate representation: bit-width-typed expressions and statements.

Expressions are immutable and hashable so later passes can compare and
substitute them freely. Every statement remembers the address of the
machine instruction it came from.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def mask(bits: int) -> int:
    return (1 << bits) - 1


# ------------------------------------------------------------------ expressions
class Expr:
    bits: int

    def __str__(self) -> str:
        return fmt(self)


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


@dataclass(slots=True)
class CallStmt(Stmt):
    call: Call
    tail: bool = False  # `jmp func` lifted as call + return
    noreturn: bool = False
    name: str | None = None  # callee name when known (display only)


@dataclass(slots=True)
class Return(Stmt):
    value: Expr | None = None


@dataclass(slots=True)
class Effect(Stmt):
    """Side effect without a result (hlt, ud2, int3, syscall, ...)."""
    name: str
    args: tuple[Expr, ...] = ()


@dataclass(slots=True)
class Unknown(Stmt):
    text: str  # original instruction text


TERMINATORS = (Branch, Jump, IndirectJump, Return)


# ----------------------------------------------------------------- containers
@dataclass
class IRBlock:
    addr: int
    stmts: list[Stmt] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)


@dataclass
class IRFunction:
    addr: int
    name: str
    blocks: dict[int, IRBlock] = field(default_factory=dict)

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
    if isinstance(e, Load):
        return f"[{fmt(e.addr)}]:{e.bits}"
    if isinstance(e, BinOp):
        p = _PREC.get(e.op)
        if p is None:
            return f"{e.op}({fmt(e.a)}, {fmt(e.b)})"
        s = f"{fmt(e.a, p)} {e.op} {fmt(e.b, p + 1)}"
        return f"({s})" if p < prec else s
    if isinstance(e, UnOp):
        return f"{e.op}{fmt(e.a, 11)}"
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
        return fmt(s.call) + (f"  ; {', '.join(tags)}" if tags else "")
    if isinstance(s, Return):
        return "return" + (f" {fmt(s.value)}" if s.value is not None else "")
    if isinstance(s, Effect):
        return f"{s.name}({', '.join(fmt(a) for a in s.args)})"
    if isinstance(s, Unknown):
        return f'__asm("{s.text}")'
    return repr(s)

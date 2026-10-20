"""x87 floating point (32-bit x86: `fld`, `fstp`, `faddp`, `fcomip`, ...).

The x87 registers are a stack: `st(i)` names the i-th value from the top, so the
same name means a different value after every push and pop. The lifter renames
them by depth instead -- `x87_k` is the k-th value from the bottom -- which makes
data flow explicit for SSA: `st(i)` with `d` values on the stack is `x87_{d-1-i}`.

The depth before each instruction is worked out per function (`depths`): it is 0
at the entry and after a call (the cdecl ABI hands over an empty stack), 1 after
a call that returns a float -- which is then in `x87_0`, the convention's result
register (`fpabi.fp_ret_reg`). Whether a call returns a float comes from libc
signatures and the internal callee's own code, else from the code after the call
reading a value it did not push.

Values are modelled as doubles. The hardware keeps 80 bits and rounds when
storing; `long double` memory operands (`fld tbyte`) stay opaque.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...disasm import CALL, OP_MEM, OP_REG, RET
from ..ir import BinOp, Const, Intrinsic, Load, Reg, Store, UnOp

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function
    from ...disasm import Insn

# stack effect of each instruction: values pushed (+) or popped (-)
PUSH = {"fld", "fild", "fldz", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2"}
POP1 = {"fstp", "fistp", "fisttp", "faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp", "fcomp", "fucomp",
        "fcomip", "fucomip", "fcompi", "fucompi", "ficomp", "ffreep"}
POP2 = {"fcompp", "fucompp"}
OTHER = {"fst", "fist", "fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr", "fiadd", "fisub", "fisubr", "fimul",
         "fidiv", "fidivr", "fxch", "fchs", "fabs", "fsqrt", "frndint", "fcom", "fucom", "fcomi", "fucomi", "ficom",
         "fnstsw", "fstsw", "fnstcw", "fstcw", "fldcw", "fnclex", "fclex", "ffree", "fninit", "finit", "ftst",
         "fxam", "fcmovb", "fcmove", "fcmovbe", "fcmovu", "fcmovnb", "fcmovne", "fcmovnbe", "fcmovnu"}
X87 = PUSH | POP1 | POP2 | OTHER
CONSTS = {"fldz": 0.0, "fld1": 1.0, "fldpi": 3.141592653589793, "fldl2e": 1.4426950408889634,
          "fldl2t": 3.321928094887362, "fldlg2": 0.3010299956639812, "fldln2": 0.6931471805599453}
REGS = tuple(f"x87_{k}" for k in range(8))
# the condition codes `fcom` sets (C0, C2, C3: where comisd puts CF, PF and ZF)
C0, C2, C3 = (Reg(n, 1) for n in ("fpu_c0", "fpu_c2", "fpu_c3"))


def is_x87(mnemonic: str) -> bool:
    return mnemonic in X87


def _effect(m: str) -> int:
    return 1 if m in PUSH else -1 if m in POP1 else -2 if m in POP2 else 0


def _needs(i: "Insn") -> int:
    """How many values an instruction reads from the stack (an underflow below that means a
    call before it left its float result there)."""
    m = i.mnemonic
    if m in PUSH:
        k = _st_index(i)
        return k + 1 if m == "fld" and k is not None else 0
    if m in ("fnstsw", "fstsw", "fnstcw", "fstcw", "fldcw", "fnclex", "fclex", "fninit", "finit", "ffree"):
        return 0
    regs = [_st(i, o) for o in i.cs.operands if o.type == OP_REG]
    regs = [k for k in regs if k is not None]
    if m in POP2 or m in ("faddp", "fsubp", "fsubrp", "fmulp", "fdivp", "fdivrp") and not regs:
        return 2
    return max([k + 1 for k in regs] + [1])


def _st(i: "Insn", op) -> int | None:
    name = i.cs.reg_name(op.reg)
    if name.startswith("st(") and name.endswith(")"):
        return int(name[3:-1])
    return 0 if name == "st" else None


def _st_index(i: "Insn") -> int | None:
    ops = [o for o in i.cs.operands if o.type == OP_REG]
    return _st(i, ops[0]) if ops else None


def _call_returns_float(an: "Analysis", i: "Insn") -> bool:
    from ..fpabi import fp_return, ret_bits_of
    t = i.target
    if t is None:
        return False
    if ret_bits_of(an.name(t)) is not None:
        return True
    f = an.functions.get(t)
    if f is not None and not f.is_import:
        return fp_return(an, f) is not None
    return False


def depths(an: "Analysis", func: "Function") -> dict[int, int]:
    """The x87 stack depth before each instruction of `func` (only those the stack reaches)."""
    pushing: set[int] = {i.addr for b in func.blocks.values() for i in b.insns
                         if i.kind == CALL and _call_returns_float(an, i)}
    for _ in range(8):
        out, grow = _walk(func, pushing)
        if not grow:
            return out
        pushing |= grow
    return out


def _walk(func: "Function", pushing: set[int]) -> tuple[dict[int, int], set[int]]:
    out: dict[int, int] = {}
    grow: set[int] = set()
    entry: dict[int, int] = {func.addr: 0}
    work = [func.addr]
    while work:
        a = work.pop()
        b = func.blocks.get(a)
        if b is None:
            continue
        d = entry[a]
        call = None                     # the last call, while no x87 instruction followed it
        for i in b.insns:
            m = i.mnemonic
            out[i.addr] = d
            if i.kind == CALL:
                d = 1 if i.addr in pushing else 0
                call = i.addr
                continue
            if m not in X87:
                continue
            if d < _needs(i) and call is not None and call not in pushing:
                grow.add(call)          # the call left a float result: walk again with it
            call = None
            if m in ("fninit", "finit"):
                d = 0
            else:
                d = max(0, min(8, d + _effect(m)))
        if b.last.kind == RET:
            continue
        for s in b.succs:
            if s in func.blocks and s not in entry:
                entry[s] = d
                work.append(s)
    return out, grow


def control_word_slots(func: "Function") -> set[tuple]:
    """The memory operands (base, index, scale, displacement) `fnstcw` / `fldcw` use in `func`:
    the control word gcc saves, sets to truncate for a C cast (`(int)x`) and restores."""
    out = set()
    for b in func.blocks.values():
        for i in b.insns:
            if i.mnemonic in ("fnstcw", "fstcw", "fldcw"):
                out |= {_mem_key(o) for o in i.cs.operands if o.type == OP_MEM}
    return out


def _mem_key(op) -> tuple:
    m = op.mem
    return m.base, m.index, m.scale, m.disp


class X87Mixin:
    """The x87 instructions, for X86Lifter (`self.read`, `self.write`, `self.assign`, ...)."""

    def x87_control_word(self, op) -> bool:
        """`op` is a slot of the control word: reads give the default word, writes go nowhere
        (rounding is modelled per instruction: `fistp` truncates as a C cast does)."""
        func = self._func
        if func is None or op.type != OP_MEM:
            return False
        if getattr(self, "_cw_func", None) is not func.addr:
            self._cw_func = func.addr
            self._cw_slots = control_word_slots(func)
        return _mem_key(op) in self._cw_slots

    def _x87_depth(self) -> int:
        func = self._func
        if func is None:
            raise self._lift_error("x87 outside a function")
        if getattr(self, "_x87_func", None) is not func.addr:
            self._x87_func = func.addr
            self._x87_depths = depths(self.an, func)
        d = self._x87_depths.get(self.insn.addr)
        if d is None:
            raise self._lift_error("x87 depth unknown")
        return d

    def _lift_error(self, what: str):
        from .x86 import LiftError
        return LiftError(what)

    def _st_reg(self, k: int, d: int) -> Reg:
        slot = d - 1 - k
        if not 0 <= slot < 8:
            raise self._lift_error("x87 stack under/overflow")
        return Reg(REGS[slot], 64)

    def _fmem(self, op, integer: bool = False):
        """A memory operand as a double: a float widened, an integer converted."""
        w = op.size * 8
        v = Load(self.addr_of(op), w)
        if integer:
            return Intrinsic("sitofp", (v,), 64)
        if w == 32:
            return Intrinsic("fpconv", (v,), 64)
        if w == 64:
            return v
        raise self._lift_error("80-bit float")

    def lift_x87(self, i, m: str):
        d = self._x87_depth()
        ops = list(i.cs.operands)
        regs = [o for o in ops if o.type == OP_REG]
        mem = next((o for o in ops if o.type == OP_MEM), None)
        st = lambda k, depth=d: self._st_reg(k, depth)

        if m in CONSTS:
            self.assign(st(0, d + 1), Const(_bits(CONSTS[m]), 64))
        elif m == "fld":
            v = self._fmem(mem) if mem is not None else st(_st(i, regs[0]))
            self.assign(st(0, d + 1), v)
        elif m == "fild":
            self.assign(st(0, d + 1), self._fmem(mem, integer=True))
        elif m in ("fst", "fstp"):
            if mem is not None:
                w = mem.size * 8
                if w not in (32, 64):
                    raise self._lift_error("80-bit float")
                v = st(0) if w == 64 else Intrinsic("fpconv", (st(0),), 32)
                self.emit(Store(i.addr, self.addr_of(mem), v))
            else:
                k = _st(i, regs[0])
                if k:
                    self.assign(st(k), st(0))
        elif m in ("fist", "fistp", "fisttp"):
            w = mem.size * 8
            self.emit(Store(i.addr, self.addr_of(mem), Intrinsic("fptosi", (st(0),), w)))
        elif m in _ARITH or m in _IARITH:
            self._x87_arith(i, m, d, regs, mem)
        elif m == "fxch":
            k = _st(i, regs[-1]) if regs else 1
            t = Reg("x87_tmp", 64)          # (an x87 name: the FP-return scan follows copies of it)
            self.assign(t, st(0))
            self.assign(st(0), st(k))
            self.assign(st(k), t)
        elif m == "fchs":
            self.assign(st(0), UnOp("fneg", st(0), 64))
        elif m in ("fabs", "fsqrt", "frndint"):
            name = {"fabs": "fabs", "fsqrt": "sqrt", "frndint": "rint"}[m]
            self.assign(st(0), Intrinsic(name, (st(0),), 64))
        elif m in ("fcomi", "fucomi", "fcomip", "fucomip", "fcompi", "fucompi"):
            self._x87_flags(st(0), st(_st(i, regs[-1]) if regs else 1))
        elif m in ("fcom", "fucom", "fcomp", "fucomp", "fcompp", "fucompp", "ficom", "ficomp", "ftst"):
            if m == "ftst":
                other = Const(0, 64)
            elif mem is not None:
                other = self._fmem(mem, integer=m.startswith("fi"))
            else:
                other = st(_st(i, regs[-1]) if regs else 1)
            a = st(0)
            self.assign(C3, BinOp("f==u", a, other, 1))
            self.assign(C2, BinOp("funord", a, other, 1))
            self.assign(C0, BinOp("f<u", a, other, 1))
        elif m in ("fnstsw", "fstsw"):
            sw = Const(0, 16)
            for c, bit in ((C0, 8), (C2, 10), (C3, 14)):
                sw = BinOp("|", sw, BinOp("<<", self.resize(c, 16), Const(bit, 8), 16), 16)
            self.write(ops[0], sw)
        elif m in ("fnstcw", "fstcw"):
            pass                        # (see x87_control_word)
        elif m.startswith("fcmov"):
            cc = m[5:]
            from .x86 import _CC
            key = {"b": "b", "e": "e", "be": "be", "u": "p", "nb": "ae", "ne": "ne", "nbe": "a", "nu": "np"}[cc]
            from ..ir import Ite
            k = _st(i, regs[-1])
            self.assign(st(0), Ite(_CC[key](), st(k), st(0), 64))
        elif m in ("fldcw", "fnclex", "fclex", "ffree", "ffreep", "fninit", "finit", "fxam"):
            if m == "fxam":
                raise self._lift_error("fxam")
        else:
            raise self._lift_error(m)

    def _x87_flags(self, a, b):
        from .x86 import CF, OF, PF, SF, ZF
        self.assign(ZF, BinOp("f==u", a, b, 1))
        self.assign(PF, BinOp("funord", a, b, 1))
        self.assign(CF, BinOp("f<u", a, b, 1))
        self.assign(OF, Const(0, 1))
        self.assign(SF, Const(0, 1))

    def _x87_arith(self, i, m: str, d: int, regs, mem):
        st = lambda k: self._st_reg(k, d)
        integer = m in _IARITH
        op, rev = (_IARITH if integer else _ARITH)[m]
        if mem is not None:
            dst, src = st(0), self._fmem(mem, integer)
        else:
            # the opcode says which way round (capstone's spelling of the st(i) forms varies):
            # D8 writes st(0), DC / DE write st(i)
            raw = bytes(i.cs.bytes)
            code, k = (raw[-2], raw[-1] & 7) if len(raw) >= 2 else (0xDE, 1)
            if code == 0xD8:
                dst, src = st(0), st(k)
            else:
                dst, src = st(k), st(0)
        a, b = (src, dst) if rev else (dst, src)
        self.assign(dst, BinOp(op, a, b, 64))


# mnemonic -> (operator, reversed: the destination is the right operand)
_ARITH = {"fadd": ("f+", False), "faddp": ("f+", False), "fmul": ("f*", False), "fmulp": ("f*", False),
          "fsub": ("f-", False), "fsubp": ("f-", False), "fsubr": ("f-", True), "fsubrp": ("f-", True),
          "fdiv": ("f/", False), "fdivp": ("f/", False), "fdivr": ("f/", True), "fdivrp": ("f/", True)}
_IARITH = {"fiadd": ("f+", False), "fimul": ("f*", False), "fisub": ("f-", False), "fisubr": ("f-", True),
           "fidiv": ("f/", False), "fidivr": ("f/", True)}


def _bits(x: float) -> int:
    from ..fp import from_float
    return from_float(x, 64)

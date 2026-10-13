"""x86 / x86-64 lifter.

Registers are kept at full width: sub-register reads become `Cast`/`Extract`
and sub-register writes follow the hardware rules (32-bit writes zero the
upper half in 64-bit mode, 8/16-bit writes merge). Flags are separate 1-bit
registers (`zf`, `cf`, `sf`, `of`, `pf`); flags an instruction leaves
undefined are not assigned.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...analysis.functions import NORETURN
from ...disasm import OP_IMM, OP_MEM, OP_REG, Insn
from ..ir import (Assign, BinOp, Branch, Call, CallStmt, Cast, Const, Effect, Expr, Extract, IndirectJump,
                  Intrinsic, Ite, Jump, Load, Reg, Return, Stmt, Store, UnOp, Unknown, mask)

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function

_GPR = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")


def _reg_table(bits: int) -> dict[str, tuple[str, int, int]]:
    """sub-register name -> (full register, lo bit, width)."""
    t: dict[str, tuple[str, int, int]] = {}
    pre = "r" if bits == 64 else "e"
    for n in _GPR:
        full = pre + n
        t["r" + n] = (full, 0, 64)
        t["e" + n] = (full, 0, 32)
        t[n] = (full, 0, 16)
        if n in ("ax", "bx", "cx", "dx"):
            t[n[0] + "l"] = (full, 0, 8)
            t[n[0] + "h"] = (full, 8, 8)
        else:
            t[n + "l"] = (full, 0, 8)
    for k in range(8, 16):
        t[f"r{k}"] = (f"r{k}", 0, 64)
        t[f"r{k}d"] = (f"r{k}", 0, 32)
        t[f"r{k}w"] = (f"r{k}", 0, 16)
        t[f"r{k}b"] = (f"r{k}", 0, 8)
    for k in range(32):
        t[f"xmm{k}"] = (f"xmm{k}", 0, 128)
        t[f"ymm{k}"] = (f"xmm{k}", 0, 256)  # treated as one wide register
    t["rip"] = ("rip", 0, 64)
    t["eip"] = ("eip", 0, 32)
    if bits == 32:
        for n in list(t):
            if t[n][2] == 64 and t[n][0].startswith("r"):
                del t[n]
    return t


ZF, CF, SF, OF, PF = (Reg(n, 1) for n in ("zf", "cf", "sf", "of", "pf"))

_CC = {
    "o": lambda: OF, "no": lambda: UnOp("!", OF, 1),
    "b": lambda: CF, "c": lambda: CF, "nae": lambda: CF,
    "ae": lambda: UnOp("!", CF, 1), "nb": lambda: UnOp("!", CF, 1), "nc": lambda: UnOp("!", CF, 1),
    "e": lambda: ZF, "z": lambda: ZF, "ne": lambda: UnOp("!", ZF, 1), "nz": lambda: UnOp("!", ZF, 1),
    "be": lambda: BinOp("|", CF, ZF, 1), "na": lambda: BinOp("|", CF, ZF, 1),
    "a": lambda: BinOp("&", UnOp("!", CF, 1), UnOp("!", ZF, 1), 1),
    "nbe": lambda: BinOp("&", UnOp("!", CF, 1), UnOp("!", ZF, 1), 1),
    "s": lambda: SF, "ns": lambda: UnOp("!", SF, 1),
    "p": lambda: PF, "pe": lambda: PF, "np": lambda: UnOp("!", PF, 1), "po": lambda: UnOp("!", PF, 1),
    "l": lambda: BinOp("!=", SF, OF, 1), "nge": lambda: BinOp("!=", SF, OF, 1),
    "ge": lambda: BinOp("==", SF, OF, 1), "nl": lambda: BinOp("==", SF, OF, 1),
    "le": lambda: BinOp("|", ZF, BinOp("!=", SF, OF, 1), 1),
    "ng": lambda: BinOp("|", ZF, BinOp("!=", SF, OF, 1), 1),
    "g": lambda: BinOp("&", UnOp("!", ZF, 1), BinOp("==", SF, OF, 1), 1),
    "nle": lambda: BinOp("&", UnOp("!", ZF, 1), BinOp("==", SF, OF, 1), 1),
}

_PREFIXES = ("notrack ", "bnd ", "lock ", "rep ", "repe ", "repz ", "repne ", "repnz ")
_NOPS = {"nop", "endbr64", "endbr32", "pause", "prefetcht0", "prefetcht1", "prefetcht2", "prefetchnta",
         "prefetchw", "lfence", "sfence", "mfence", "fwait", "wait"}
_EFFECTS = {"hlt", "ud2", "int3", "syscall", "sysenter", "int", "cpuid", "rdtsc", "cld", "std", "into"}
_SSE_ZERO = {"pxor", "xorps", "xorpd", "vpxor", "vxorps", "vxorpd"}
_SSE_MOV = {"movaps", "movups", "movapd", "movupd", "movdqa", "movdqu", "vmovaps", "vmovups", "vmovdqa",
            "vmovdqu", "movd", "movq", "vmovd", "vmovq", "lddqu"}


class LiftError(Exception):
    pass


def cast(kind: str, v: Expr, bits: int) -> Expr:
    """`Cast` that folds constants and collapses nested extensions."""
    if v.bits == bits:
        return v
    if isinstance(v, Const):
        return Const(v.signed if kind == "sext" else v.value, bits)
    if isinstance(v, Cast) and kind in ("zext", "sext") and v.kind == kind:
        return Cast(kind, v.a, bits)
    if isinstance(v, Cast) and kind == "zext" and v.kind == "zext":
        return Cast("zext", v.a, bits)
    return Cast(kind, v, bits)


def mentions(e: Expr, r: Reg) -> bool:
    if e == r:
        return True
    for k in getattr(e, "__slots__", ()):
        v = getattr(e, k)
        if isinstance(v, Expr) and mentions(v, r):
            return True
        if isinstance(v, tuple) and any(isinstance(x, Expr) and mentions(x, r) for x in v):
            return True
    return False


class X86Lifter:
    def __init__(self, an: Analysis):
        self.an = an
        self.bits = an.bin.bits
        self.regs = _reg_table(self.bits)
        self.sp = Reg("rsp" if self.bits == 64 else "esp", self.bits)
        self.bp = Reg("rbp" if self.bits == 64 else "ebp", self.bits)
        self.word = self.bits // 8
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0

    # ---------------------------------------------------------- helpers
    def emit(self, s: Stmt):
        self.out.append(s)

    def assign(self, dst: Reg, src: Expr):
        self.emit(Assign(self.insn.addr, dst, src))

    def tmp(self, e: Expr) -> Reg:
        """Snapshot a value into a fresh temporary (for xchg, ...)."""
        self._tmp += 1
        t = Reg(f"t{self._tmp}", e.bits)
        self.assign(t, e)
        return t

    def full(self, name: str) -> Reg:
        f, _, _ = self.regs[name]
        return Reg(f, self._full_bits(f))

    def _full_bits(self, f: str) -> int:
        if f.startswith("xmm"):
            return 128
        return self.bits

    def read_reg(self, name: str) -> Expr:
        if name in ("fs", "gs", "cs", "ds", "es", "ss"):
            return Reg(name, 16)
        if name not in self.regs:
            raise LiftError(f"register {name}")
        f, lo, w = self.regs[name]
        r = Reg(f, self._full_bits(f))
        if w >= r.bits:
            return r
        if lo:
            return Extract(r, lo, w)
        return Cast("low", r, w)

    def write_reg(self, name: str, v: Expr):
        if name not in self.regs:
            raise LiftError(f"register {name}")
        f, lo, w = self.regs[name]
        r = Reg(f, self._full_bits(f))
        v = self.resize(v, w)
        if w >= r.bits:
            self.assign(r, v)
        elif w == 32 and r.bits == 64:
            self.assign(r, cast("zext", v, 64))
        elif f.startswith("xmm"):
            self.assign(r, BinOp("|", BinOp("&", r, Const(~mask(w) & mask(r.bits), r.bits), r.bits),
                                 Cast("zext", v, r.bits), r.bits))
        else:
            keep = Const(~(mask(w) << lo) & mask(r.bits), r.bits)
            new = cast("zext", v, r.bits)
            if lo:
                new = BinOp("<<", new, Const(lo, 8), r.bits)
            self.assign(r, BinOp("|", BinOp("&", r, keep, r.bits), new, r.bits))

    @staticmethod
    def resize(v: Expr, bits: int, signed: bool = False) -> Expr:
        if v.bits == bits:
            return v
        if v.bits > bits:
            return cast("low", v, bits) if not isinstance(v, Const) else Const(v.value, bits)
        return cast("sext" if signed else "zext", v, bits)

    def addr_of(self, op) -> Expr:
        import capstone.x86 as x86
        m = op.mem
        c = self.insn.cs
        e: Expr | None = None
        if m.base == x86.X86_REG_RIP or m.base == getattr(x86, "X86_REG_EIP", -1):
            return Const(self.insn.end + m.disp, self.bits)
        if m.base:
            e = self.read_reg(c.reg_name(m.base))
            e = self.resize(e, self.bits)
        if m.index:
            idx = self.resize(self.read_reg(c.reg_name(m.index)), self.bits)
            if m.scale != 1:
                idx = BinOp("*", idx, Const(m.scale, self.bits), self.bits)
            e = idx if e is None else BinOp("+", e, idx, self.bits)
        if m.disp or e is None:
            d = Const(m.disp, self.bits)
            if e is None:
                e = d
            elif d.signed < 0:
                e = BinOp("-", e, Const(-d.signed, self.bits), self.bits)
            else:
                e = BinOp("+", e, d, self.bits)
        if m.segment and c.reg_name(m.segment) in ("fs", "gs"):
            e = BinOp("+", Reg(c.reg_name(m.segment) + "_base", self.bits), e, self.bits)
        return e

    def read(self, op) -> Expr:
        if op.type == OP_REG:
            return self.read_reg(self.insn.cs.reg_name(op.reg))
        if op.type == OP_IMM:
            return Const(op.imm, op.size * 8 or self.bits)
        if op.type == OP_MEM:
            return Load(self.addr_of(op), op.size * 8)
        raise LiftError("operand type")

    def write(self, op, v: Expr):
        if op.type == OP_REG:
            self.write_reg(self.insn.cs.reg_name(op.reg), v)
        elif op.type == OP_MEM:
            self.emit(Store(self.insn.addr, self.addr_of(op), self.resize(v, op.size * 8)))
        else:
            raise LiftError("write to immediate")

    def push(self, v: Expr):
        v = self.resize(v, self.bits, signed=isinstance(v, Const))
        if mentions(v, self.sp):
            v = self.tmp(v)
        self.assign(self.sp, BinOp("-", self.sp, Const(self.word, self.bits), self.bits))
        self.emit(Store(self.insn.addr, self.sp, v))

    # ------------------------------------------------------------ flags
    def flags_result(self, res: Expr):
        b = res.bits
        self.assign(ZF, BinOp("==", res, Const(0, b), 1))
        self.assign(SF, BinOp("<s", res, Const(0, b), 1))
        self.assign(PF, Intrinsic("parity", (self.resize(res, 8),), 1))

    def flags_add(self, a: Expr, b: Expr, res: Expr, carry: bool = True):
        if carry:
            self.assign(CF, BinOp("carry", a, b, 1))
        self.assign(OF, BinOp("scarry", a, b, 1))
        self.flags_result(res)

    def flags_sub(self, a: Expr, b: Expr, res: Expr, carry: bool = True):
        if carry:
            self.assign(CF, BinOp("<u", a, b, 1))
        self.assign(OF, BinOp("sborrow", a, b, 1))
        self.flags_result(res)

    def flags_logic(self, res: Expr):
        self.assign(CF, Const(0, 1))
        self.assign(OF, Const(0, 1))
        self.flags_result(res)

    # ----------------------------------------------------------- driver
    def lift_insn(self, i: Insn, func: Function | None = None) -> list[Stmt]:
        """Statements for one instruction (control flow included)."""
        self.out = []
        self.insn = i
        m = i.mnemonic
        for p in _PREFIXES:
            if m.startswith(p):
                m = m[len(p):]
                if p.startswith("rep") and m not in ("ret", "jmp", "call"):
                    return self._rep(i, p.strip(), m)
        try:
            handler = getattr(self, "_i_" + m, None)
            if handler is not None:
                handler(i, i.cs.operands)
            elif m in _NOPS:
                pass
            elif m in _EFFECTS:
                self.emit(Effect(i.addr, m, tuple(self.read(o) for o in i.cs.operands)))
            elif m.startswith("cmov"):
                self._cmov(i, i.cs.operands, m[4:])
            elif m.startswith("set") and m[3:] in _CC:
                self.write(i.cs.operands[0], Cast("zext", _CC[m[3:]](), 8))
            elif m.startswith("j") and m[1:] in _CC:
                self.emit(Branch(i.addr, _CC[m[1:]](), i.target, i.end))
            elif m in _SSE_ZERO or m in _SSE_MOV:
                self._sse(i, i.cs.operands, m)
            elif i.cs.operands and i.cs.operands[0].type == OP_REG and \
                    i.cs.reg_name(i.cs.operands[0].reg).startswith(("xmm", "ymm")):
                # SIMD / scalar FP op: modelled as an opaque function of its operands
                ops = i.cs.operands
                srcs = tuple(self.read(o) for o in ops)
                dst = ops[0]
                self.write(dst, Intrinsic(m, srcs, dst.size * 8))
            else:
                self.out = [Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip())]
        except LiftError:
            self.out = [Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip())]
        return self.out

    # ------------------------------------------------------- data movement
    def _i_mov(self, i, ops):
        self.write(ops[0], self.read(ops[1]))

    _i_movabs = _i_mov

    def _i_movzx(self, i, ops):
        self.write(ops[0], self.resize(self.read(ops[1]), ops[0].size * 8))

    def _i_movsx(self, i, ops):
        self.write(ops[0], self.resize(self.read(ops[1]), ops[0].size * 8, signed=True))

    _i_movsxd = _i_movsx

    def _i_lea(self, i, ops):
        self.write(ops[0], self.resize(self.addr_of(ops[1]), ops[0].size * 8))

    def _i_xchg(self, i, ops):
        a, b = ops
        if a.type == OP_REG and b.type == OP_REG and a.reg == b.reg:
            return
        t = self.tmp(self.read(a))
        self.write(a, self.read(b))
        self.write(b, t)

    def _i_push(self, i, ops):
        self.push(self.read(ops[0]))

    def _i_pop(self, i, ops):
        v = Load(self.sp, ops[0].size * 8)
        if ops[0].type == OP_REG and self.full(i.cs.reg_name(ops[0].reg)) == self.sp:
            self.assign(self.sp, v)
            return
        if ops[0].type == OP_MEM:  # the destination address uses the incremented rsp
            t = self.tmp(v)
            self.assign(self.sp, BinOp("+", self.sp, Const(self.word, self.bits), self.bits))
            self.write(ops[0], t)
        else:
            self.write(ops[0], v)
            self.assign(self.sp, BinOp("+", self.sp, Const(self.word, self.bits), self.bits))

    def _i_leave(self, i, ops):
        self.assign(self.sp, self.bp)
        self.assign(self.bp, Load(self.sp, self.bits))
        self.assign(self.sp, BinOp("+", self.sp, Const(self.word, self.bits), self.bits))

    def _cmov(self, i, ops, cc):
        if cc not in _CC:
            raise LiftError(cc)
        w = ops[0].size * 8
        self.write(ops[0], Ite(_CC[cc](), self.read(ops[1]), self.read(ops[0]), w))

    def _sse(self, i, ops, m):
        if m in _SSE_ZERO:
            srcs = ops[-2:]
            if len(srcs) == 2 and srcs[0].type == OP_REG and srcs[1].type == OP_REG and srcs[0].reg == srcs[1].reg:
                self.write(ops[0], Const(0, ops[0].size * 8))
            else:
                self.write(ops[0], BinOp("^", self.read(srcs[0]), self.read(srcs[1]), ops[0].size * 8))
            return
        dst, src = ops[0], ops[1]
        v = self.read(src)
        w = dst.size * 8
        if dst.type == OP_REG and i.cs.reg_name(dst.reg).startswith("xmm") and m in ("movd", "movq", "vmovd", "vmovq"):
            # GPR/mem -> xmm zeroes the rest of the register
            self.write_reg(i.cs.reg_name(dst.reg), self.resize(v, 128))
            return
        self.write(dst, self.resize(v, w))

    # ---------------------------------------------------------- arithmetic
    def _binop(self, ops, op: str, flags: str | None):
        a, b = self.read(ops[0]), self.read(ops[1])
        w = a.bits
        b = self.resize(b, w, signed=True)
        res = BinOp(op, a, b, w)
        if flags == "add":
            self.flags_add(a, b, res)
        elif flags == "sub":
            self.flags_sub(a, b, res)
        elif flags == "logic":
            self.flags_logic(res)
        return res

    def _i_add(self, i, ops):
        self.write(ops[0], self._binop(ops, "+", "add"))

    def _i_sub(self, i, ops):
        if ops[0].type == OP_REG and ops[1].type == OP_REG and ops[0].reg == ops[1].reg:
            self._zero(ops[0])
            return
        self.write(ops[0], self._binop(ops, "-", "sub"))

    def _i_cmp(self, i, ops):
        self._binop(ops, "-", "sub")

    def _i_and(self, i, ops):
        self.write(ops[0], self._binop(ops, "&", "logic"))

    def _i_or(self, i, ops):
        self.write(ops[0], self._binop(ops, "|", "logic"))

    def _i_xor(self, i, ops):
        if ops[0].type == OP_REG and ops[1].type == OP_REG and ops[0].reg == ops[1].reg:
            self._zero(ops[0])
            return
        self.write(ops[0], self._binop(ops, "^", "logic"))

    def _zero(self, op):
        self.assign(CF, Const(0, 1))
        self.assign(OF, Const(0, 1))
        self.assign(ZF, Const(1, 1))
        self.assign(SF, Const(0, 1))
        self.assign(PF, Const(1, 1))
        self.write(op, Const(0, op.size * 8))

    def _i_test(self, i, ops):
        self._binop(ops, "&", "logic")

    def _carry_op(self, ops, op: str):
        a, b = self.read(ops[0]), self.read(ops[1])
        w = a.bits
        b = self.resize(b, w, signed=True)
        cf = self.tmp(CF)
        res = BinOp(op, BinOp(op, a, b, w), Cast("zext", cf, w), w)
        self.assign(CF, Intrinsic("adc_cf" if op == "+" else "sbb_cf", (a, b, cf), 1))
        self.assign(OF, Intrinsic("adc_of" if op == "+" else "sbb_of", (a, b, cf), 1))
        self.flags_result(res)
        self.write(ops[0], res)

    def _i_adc(self, i, ops):
        self._carry_op(ops, "+")

    def _i_sbb(self, i, ops):
        if ops[0].type == OP_REG and ops[1].type == OP_REG and ops[0].reg == ops[1].reg:
            w = ops[0].size * 8
            self.write(ops[0], UnOp("-", Cast("zext", CF, w), w))  # 0 or -1
            return
        self._carry_op(ops, "-")

    def _i_inc(self, i, ops):
        a = self.read(ops[0])
        one = Const(1, a.bits)
        res = BinOp("+", a, one, a.bits)
        self.flags_add(a, one, res, carry=False)
        self.write(ops[0], res)

    def _i_dec(self, i, ops):
        a = self.read(ops[0])
        one = Const(1, a.bits)
        res = BinOp("-", a, one, a.bits)
        self.flags_sub(a, one, res, carry=False)
        self.write(ops[0], res)

    def _i_neg(self, i, ops):
        a = self.read(ops[0])
        res = UnOp("-", a, a.bits)
        self.assign(CF, BinOp("!=", a, Const(0, a.bits), 1))
        self.assign(OF, BinOp("sborrow", Const(0, a.bits), a, 1))
        self.flags_result(res)
        self.write(ops[0], res)

    def _i_not(self, i, ops):
        a = self.read(ops[0])
        self.write(ops[0], UnOp("~", a, a.bits))

    def _i_imul(self, i, ops):
        if len(ops) == 1:
            self._widemul(ops[0], signed=True)
            return
        a, b = (self.read(ops[0]), self.read(ops[1])) if len(ops) == 2 else (self.read(ops[1]), self.read(ops[2]))
        w = ops[0].size * 8
        b = self.resize(b, w, signed=True)
        ovf = Intrinsic("smul_overflow", (a, b), 1)
        self.assign(CF, ovf)
        self.assign(OF, CF)
        self.write(ops[0], BinOp("*", a, b, w))

    def _i_mul(self, i, ops):
        self._widemul(ops[0], signed=False)

    def _pair(self, w: int) -> tuple[str, str]:
        return {8: ("al", "ah"), 16: ("ax", "dx"), 32: ("eax", "edx"), 64: ("rax", "rdx")}[w]

    def _widemul(self, op, signed: bool):
        src = self.read(op)
        w = src.bits
        lo_name, hi_name = self._pair(w)
        k = "sext" if signed else "zext"
        a = self.read_reg("al" if w == 8 else lo_name)
        prod = BinOp("*", Cast(k, a, 2 * w), Cast(k, src, 2 * w), 2 * w)
        t = self.tmp(prod)
        hi = Extract(t, w, w)
        ovf = BinOp("!=", hi, BinOp(">>s", Cast("low", t, w), Const(w - 1, 8), w), 1) if signed else \
            BinOp("!=", hi, Const(0, w), 1)
        self.assign(CF, ovf)
        self.assign(OF, CF)
        if w == 8:
            self.write_reg("ax", t)
        else:
            self.write_reg(lo_name, Cast("low", t, w))
            self.write_reg(hi_name, hi)

    def _div(self, op, signed: bool):
        src = self.read(op)
        w = src.bits
        lo_name, hi_name = self._pair(w)
        k = "sext" if signed else "zext"
        if w == 8:
            dividend = self.read_reg("ax")
        else:
            hi = Cast("zext", self.read_reg(hi_name), 2 * w)
            dividend = BinOp("|", BinOp("<<", hi, Const(w, 8), 2 * w),
                             Cast("zext", self.read_reg(lo_name), 2 * w), 2 * w)
        n = self.tmp(dividend)
        d = self.tmp(Cast(k, src, 2 * w))  # src may be the register the quotient overwrites
        q = Cast("low", BinOp("/s" if signed else "/u", n, d, 2 * w), w)
        r = Cast("low", BinOp("%s" if signed else "%u", n, d, 2 * w), w)
        if w == 8:
            self.write_reg("al", q)
            self.write_reg("ah", r)
        else:
            self.write_reg(lo_name, q)
            self.write_reg(hi_name, r)

    def _i_div(self, i, ops):
        self._div(ops[0], signed=False)

    def _i_idiv(self, i, ops):
        self._div(ops[0], signed=True)

    def _i_cdqe(self, i, ops):
        self.write_reg("rax", Cast("sext", self.read_reg("eax"), 64))

    def _i_cwde(self, i, ops):
        self.write_reg("eax", Cast("sext", self.read_reg("ax"), 32))

    def _i_cbw(self, i, ops):
        self.write_reg("ax", Cast("sext", self.read_reg("al"), 16))

    def _sign_fill(self, lo: str, hi: str):
        v = self.read_reg(lo)
        self.write_reg(hi, BinOp(">>s", v, Const(v.bits - 1, 8), v.bits))

    def _i_cqo(self, i, ops):
        self._sign_fill("rax", "rdx")

    def _i_cdq(self, i, ops):
        self._sign_fill("eax", "edx")

    def _i_cwd(self, i, ops):
        self._sign_fill("ax", "dx")

    def _shift(self, ops, op: str):
        a = self.read(ops[0])
        w = a.bits
        if len(ops) > 1:
            cnt = self.read(ops[1])
        else:
            cnt = Const(1, 8)
        cmask = 0x3F if w == 64 else 0x1F
        if isinstance(cnt, Const):
            n = cnt.value & cmask
            if n == 0:
                return
            cnt = Const(n, 8)
            if op in ("rol", "ror"):
                self.assign(CF, Extract(BinOp(op, a, cnt, w), 0 if op == "rol" else w - 1, 1))
            elif op == "<<":
                if n <= w:
                    self.assign(CF, Extract(a, w - n, 1))
            elif n <= w:
                self.assign(CF, Extract(a, n - 1, 1))
            res = BinOp(op, a, cnt, w)
            if op not in ("rol", "ror"):
                self.flags_result(res)
        else:
            # a zero count leaves every flag unchanged
            cnt = self.tmp(BinOp("&", self.resize(cnt, 8), Const(cmask, 8), 8))
            zero = BinOp("==", cnt, Const(0, 8), 1)
            res = BinOp(op, a, cnt, w)
            self.assign(CF, Intrinsic(f"shift_cf_{op}", (a, cnt, CF), 1))
            if op not in ("rol", "ror"):
                self.assign(ZF, Ite(zero, ZF, BinOp("==", res, Const(0, w), 1), 1))
                self.assign(SF, Ite(zero, SF, BinOp("<s", res, Const(0, w), 1), 1))
                self.assign(PF, Ite(zero, PF, Intrinsic("parity", (self.resize(res, 8),), 1), 1))
        self.write(ops[0], res)

    def _i_shl(self, i, ops):
        self._shift(ops, "<<")

    _i_sal = _i_shl

    def _i_shr(self, i, ops):
        self._shift(ops, ">>u")

    def _i_sar(self, i, ops):
        self._shift(ops, ">>s")

    def _i_rol(self, i, ops):
        self._shift(ops, "rol")

    def _i_ror(self, i, ops):
        self._shift(ops, "ror")

    def _double_shift(self, ops, name):
        a, b = self.read(ops[0]), self.read(ops[1])
        cnt = self.read(ops[2]) if len(ops) > 2 else self.read_reg("cl")
        self.write(ops[0], Intrinsic(name, (a, b, self.resize(cnt, 8)), a.bits))

    def _i_shld(self, i, ops):
        self._double_shift(ops, "shld")

    def _i_shrd(self, i, ops):
        self._double_shift(ops, "shrd")

    def _i_bswap(self, i, ops):
        a = self.read(ops[0])
        self.write(ops[0], Intrinsic("bswap", (a,), a.bits))

    def _bit_test(self, ops, update: str | None):
        a, b = self.read(ops[0]), self.read(ops[1])
        w = a.bits
        idx = BinOp("&", self.resize(b, w), Const(w - 1, w), w)
        bit = BinOp("<<", Const(1, w), idx, w)
        self.assign(CF, BinOp("!=", BinOp("&", a, bit, w), Const(0, w), 1))
        if update == "set":
            self.write(ops[0], BinOp("|", a, bit, w))
        elif update == "reset":
            self.write(ops[0], BinOp("&", a, UnOp("~", bit, w), w))
        elif update == "complement":
            self.write(ops[0], BinOp("^", a, bit, w))

    def _i_bt(self, i, ops):
        self._bit_test(ops, None)

    def _i_bts(self, i, ops):
        self._bit_test(ops, "set")

    def _i_btr(self, i, ops):
        self._bit_test(ops, "reset")

    def _i_btc(self, i, ops):
        self._bit_test(ops, "complement")

    def _count(self, ops, name):
        a = self.read(ops[1])
        self.assign(ZF, BinOp("==", a, Const(0, a.bits), 1))
        self.write(ops[0], Intrinsic(name, (a,), ops[0].size * 8))

    def _i_bsf(self, i, ops):
        self._count(ops, "bsf")

    def _i_bsr(self, i, ops):
        self._count(ops, "bsr")

    def _i_tzcnt(self, i, ops):
        self._count(ops, "tzcnt")

    def _i_lzcnt(self, i, ops):
        self._count(ops, "lzcnt")

    def _i_popcnt(self, i, ops):
        self._count(ops, "popcnt")

    def _rep(self, i, rep: str, m: str):
        """`rep stos` / `rep movs` as memset / memcpy-like effects (DF assumed clear)."""
        size = {"b": 1, "w": 2, "d": 4, "q": 8}.get(m[-1])
        if not m.startswith(("stos", "movs")) or size is None or rep not in ("rep",):
            self.out = [Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip())]
            return self.out
        r = "r" if self.bits == 64 else "e"
        di, si, cx = (self.read_reg(r + n) for n in ("di", "si", "cx"))
        n = BinOp("*", cx, Const(size, self.bits), self.bits)
        if m.startswith("stos"):
            val = self.read_reg({1: "al", 2: "ax", 4: "eax", 8: "rax"}[size])
            self.emit(Effect(i.addr, f"rep_stos{m[-1]}", (di, val, cx)))
        else:
            self.emit(Effect(i.addr, f"rep_movs{m[-1]}", (di, si, cx)))
            self.write_reg(r + "si", BinOp("+", si, n, self.bits))
        self.write_reg(r + "di", BinOp("+", di, n, self.bits))
        self.write_reg(r + "cx", Const(0, self.bits))
        return self.out

    # -------------------------------------------------------- control flow
    def _i_jmp(self, i, ops):
        pass  # resolved per block in `terminate`

    def _i_call(self, i, ops):
        target = Const(i.target, self.bits) if i.target is not None else self.read(ops[0])
        name = self.an.call_name(i)
        self.emit(CallStmt(i.addr, Call(target, (), self.bits), noreturn=self._noreturn(i), name=name))

    def _i_ret(self, i, ops):
        if ops:  # ret imm16 (stdcall)
            self.assign(self.sp, BinOp("+", self.sp, Const(ops[0].imm, self.bits), self.bits))
        self.emit(Return(i.addr))

    _i_retq = _i_ret

    def _i_loop(self, i, ops):
        cx = self.full("ecx")
        self.assign(cx, BinOp("-", cx, Const(1, cx.bits), cx.bits))
        self.emit(Branch(i.addr, BinOp("!=", cx, Const(0, cx.bits), 1), i.target, i.end))

    def _i_jrcxz(self, i, ops):
        self.emit(Branch(i.addr, BinOp("==", self.read_reg("rcx"), Const(0, 64), 1), i.target, i.end))

    def _i_jecxz(self, i, ops):
        self.emit(Branch(i.addr, BinOp("==", self.read_reg("ecx"), Const(0, 32), 1), i.target, i.end))

    def _noreturn(self, i: Insn) -> bool:
        an = self.an
        if i.target is not None:
            f = an.functions.get(i.target)
            if f is not None:
                return f.noreturn
            return (an.name(i.target) or "") in NORETURN
        return (an.call_name(i) or "") in NORETURN

    def lift_jmp(self, i: Insn, func: Function) -> list[Stmt]:
        """Direct, tail-call or indirect `jmp` at the end of a block."""
        self.out = []
        self.insn = i
        if i.target is not None:
            if i.target in func.blocks:
                self.emit(Jump(i.addr, i.target))
            else:
                self.emit(CallStmt(i.addr, Call(Const(i.target, self.bits), (), self.bits), tail=True,
                                   name=self.an.name(i.target)))
                self.emit(Return(i.addr))
            return self.out
        try:
            expr = self.read(i.cs.operands[0])
        except LiftError:
            return [Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip())]
        table = func.jump_tables.get(i.addr)
        if table:
            seen: list[int] = []
            for t in table:
                if t not in seen:
                    seen.append(t)
            self.emit(IndirectJump(i.addr, expr, seen))
        elif i.mem_target is not None and self.an.bin.imports_by_got.get(i.mem_target):
            self.emit(CallStmt(i.addr, Call(expr, (), self.bits), tail=True, name=self.an.call_name(i)))
            self.emit(Return(i.addr))
        else:
            self.emit(IndirectJump(i.addr, expr, []))
        return self.out

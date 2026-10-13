"""AArch64 lifter.

Registers are the 64-bit `x0`..`x30` and `sp` (`w` names are their low halves;
a 32-bit write zero-extends), the SIMD/FP registers are 128-bit `v0`..`v31`,
and NZCV live in the same 1-bit flag registers the x86 lifter uses
(`sf` = N, `zf` = Z, `cf` = C, `of` = V) so the condition-recovery passes
apply unchanged. Note ARM's carry after a subtraction is *not borrow*:
`cmp a, b` sets C = (a >=u b).

Shifted / extended register operands, pre- and post-indexed addressing
(`[sp, #-16]!`, `[sp], #16`), load/store pairs, PC-relative literals,
conditional select / compare and the bitfield instructions are modelled;
floating point and SIMD arithmetic stay opaque (`Intrinsic`).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import capstone.arm64 as a64

from ...analysis.functions import NORETURN
from ...disasm import Insn
from ..ir import (Assign, BinOp, Branch, Call, CallStmt, Cast, Const, Effect, Expr, IndirectJump, Intrinsic, Ite,
                  Jump, Load, Reg, Return, Stmt, Store, UnOp, Unknown, mask)
from .x86 import LiftError, cast

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function

OP_REG, OP_IMM, OP_MEM = 1, 2, 3
ZF, CF, SF, OF = (Reg(n, 1) for n in ("zf", "cf", "sf", "of"))
SP = Reg("sp", 64)


def _table() -> dict[str, tuple[str, int]]:
    """register name -> (full register, width)."""
    t: dict[str, tuple[str, int]] = {}
    for n in range(31):
        t[f"x{n}"] = (f"x{n}", 64)
        t[f"w{n}"] = (f"x{n}", 32)
    t.update({"fp": ("x29", 64), "lr": ("x30", 64), "sp": ("sp", 64), "wsp": ("sp", 32)})
    for n in range(32):
        for pre, w in (("b", 8), ("h", 16), ("s", 32), ("d", 64), ("q", 128), ("v", 128)):
            t[f"{pre}{n}"] = (f"v{n}", w)
    return t


_REGS = _table()
_ZERO = ("xzr", "wzr")

_CC = {
    a64.ARM64_CC_EQ: lambda: ZF,
    a64.ARM64_CC_NE: lambda: UnOp("!", ZF, 1),
    a64.ARM64_CC_HS: lambda: CF,
    a64.ARM64_CC_LO: lambda: UnOp("!", CF, 1),
    a64.ARM64_CC_MI: lambda: SF,
    a64.ARM64_CC_PL: lambda: UnOp("!", SF, 1),
    a64.ARM64_CC_VS: lambda: OF,
    a64.ARM64_CC_VC: lambda: UnOp("!", OF, 1),
    a64.ARM64_CC_HI: lambda: BinOp("&", CF, UnOp("!", ZF, 1), 1),
    a64.ARM64_CC_LS: lambda: BinOp("|", UnOp("!", CF, 1), ZF, 1),
    a64.ARM64_CC_GE: lambda: BinOp("==", SF, OF, 1),
    a64.ARM64_CC_LT: lambda: BinOp("!=", SF, OF, 1),
    a64.ARM64_CC_GT: lambda: BinOp("&", UnOp("!", ZF, 1), BinOp("==", SF, OF, 1), 1),
    a64.ARM64_CC_LE: lambda: BinOp("|", ZF, BinOp("!=", SF, OF, 1), 1),
    a64.ARM64_CC_AL: lambda: Const(1, 1),
    a64.ARM64_CC_NV: lambda: Const(1, 1),
}

_NOPS = {"nop", "hint", "bti", "paciasp", "autiasp", "pacibsp", "autibsp", "xpaclri", "prfm", "prfum",
         "dmb", "dsb", "isb", "yield", "sev", "sevl", "wfe", "wfi", "clrex", "csdb", "esb", "psb"}
_EFFECTS = {"svc", "brk", "hlt", "udf", "smc", "hvc"}


class Arm64Lifter:
    bits = 64

    def __init__(self, an: "Analysis"):
        self.an = an
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0

    # ----------------------------------------------------------- helpers
    def emit(self, s: Stmt):
        self.out.append(s)

    def assign(self, dst: Reg, src: Expr):
        self.emit(Assign(self.insn.addr, dst, src))

    def tmp(self, e: Expr) -> Reg:
        self._tmp += 1
        t = Reg(f"t{self._tmp}", e.bits)
        self.assign(t, e)
        return t

    def name(self, op) -> str:
        return self.insn.cs.reg_name(op.reg)

    @staticmethod
    def full(name: str) -> Reg:
        f, _ = _REGS[name]
        return Reg(f, 128 if f.startswith("v") else 64)

    def read_reg(self, name: str) -> Expr:
        if name in _ZERO:
            return Const(0, 64 if name == "xzr" else 32)
        if name not in _REGS:
            raise LiftError(f"register {name}")
        f, w = _REGS[name]
        r = self.full(name)
        return r if w == r.bits else Cast("low", r, w)

    def write_reg(self, name: str, v: Expr):
        if name in _ZERO:
            return                                   # writes to the zero register vanish
        if name not in _REGS:
            raise LiftError(f"register {name}")
        f, w = _REGS[name]
        r = self.full(name)
        v = self.resize(v, w)
        # 32-bit GPR writes and scalar FP writes zero the rest of the register
        self.assign(r, v if w == r.bits else cast("zext", v, r.bits))

    @staticmethod
    def resize(v: Expr, bits: int, signed: bool = False) -> Expr:
        if v.bits == bits:
            return v
        if v.bits > bits:
            return Const(v.value, bits) if isinstance(v, Const) else cast("low", v, bits)
        return cast("sext" if signed else "zext", v, bits)

    def width(self, op) -> int:
        return _REGS.get(self.name(op), ("", 64 if self.name(op) == "xzr" else 32))[1]

    def _shift(self, v: Expr, op, w: int) -> Expr:
        st, amount = op.shift.type, op.shift.value
        if st == 0 or (amount == 0 and st != a64.ARM64_SFT_ROR):
            return v
        if st == a64.ARM64_SFT_LSL:
            return BinOp("<<", v, Const(amount, 8), w)
        if st == a64.ARM64_SFT_LSR:
            return BinOp(">>u", v, Const(amount, 8), w)
        if st == a64.ARM64_SFT_ASR:
            return BinOp(">>s", v, Const(amount, 8), w)
        if st == a64.ARM64_SFT_ROR:
            return BinOp("ror", v, Const(amount, 8), w)
        raise LiftError("shift")

    def _extend(self, v: Expr, ext: int, w: int) -> Expr:
        if not ext:
            return self.resize(v, w)
        size = {a64.ARM64_EXT_UXTB: 8, a64.ARM64_EXT_SXTB: 8, a64.ARM64_EXT_UXTH: 16, a64.ARM64_EXT_SXTH: 16,
                a64.ARM64_EXT_UXTW: 32, a64.ARM64_EXT_SXTW: 32, a64.ARM64_EXT_UXTX: 64,
                a64.ARM64_EXT_SXTX: 64}[ext]
        signed = ext >= a64.ARM64_EXT_SXTB
        return self.resize(self.resize(v, size), w, signed)

    def operand(self, op, w: int) -> Expr:
        """Value of a register (shifted / extended) or immediate operand at width `w`."""
        if op.type == OP_REG:
            v = self._extend(self.read_reg(self.name(op)), op.ext, w)
            return self._shift(v, op, w)
        if op.type == OP_IMM:
            v = Const(op.imm, w)
            if op.shift.type == a64.ARM64_SFT_LSL and op.shift.value:
                v = Const(op.imm << op.shift.value, w)
            return v
        raise LiftError("operand")

    def address(self, op) -> Expr:
        m = op.mem
        c = self.insn.cs
        e: Expr = self.read_reg(c.reg_name(m.base)) if m.base else Const(0, 64)
        if m.index:
            idx = self._extend(self.read_reg(c.reg_name(m.index)), op.ext, 64)
            if op.shift.type == a64.ARM64_SFT_LSL and op.shift.value:
                idx = BinOp("<<", idx, Const(op.shift.value, 8), 64)
            e = BinOp("+", e, idx, 64)
        if m.disp:
            e = BinOp("+", e, Const(m.disp, 64), 64) if m.disp > 0 else BinOp("-", e, Const(-m.disp, 64), 64)
        return e

    def _mem_access(self, ops):
        """(address to access, writeback) for the memory operand of a load/store."""
        c = self.insn.cs
        mem = next(o for o in ops if o.type == OP_MEM)
        base = c.reg_name(mem.mem.base)
        if getattr(c, "post_index", False):
            imm = next((o.imm for o in ops if o.type == OP_IMM), 0)
            addr = self.read_reg(base)
            return addr, (base, BinOp("+", self.read_reg(base), Const(imm, 64), 64))
        addr = self.address(mem)
        if getattr(c, "writeback", False):
            t = self.tmp(addr)
            return t, (base, t)
        return addr, None

    # ------------------------------------------------------------- flags
    def _nz(self, res: Expr):
        b = res.bits
        self.assign(ZF, BinOp("==", res, Const(0, b), 1))
        self.assign(SF, BinOp("<s", res, Const(0, b), 1))

    def flags_sub(self, a: Expr, b: Expr):
        w = a.bits
        self._nz(BinOp("-", a, b, w))
        self.assign(CF, BinOp("<=u", b, a, 1))       # ARM: carry = no borrow
        self.assign(OF, BinOp("sborrow", a, b, 1))

    def flags_add(self, a: Expr, b: Expr):
        w = a.bits
        self._nz(BinOp("+", a, b, w))
        self.assign(CF, BinOp("carry", a, b, 1))
        self.assign(OF, BinOp("scarry", a, b, 1))

    def flags_logic(self, res: Expr):
        self._nz(res)
        self.assign(CF, Const(0, 1))
        self.assign(OF, Const(0, 1))

    def cond(self) -> Expr:
        cc = self.insn.cs.cc
        if cc not in _CC:
            raise LiftError(f"condition {cc}")
        return _CC[cc]()

    # ------------------------------------------------------------ driver
    def lift_insn(self, i: Insn, func: "Function | None" = None) -> list[Stmt]:
        self.out = []
        self.insn = i
        m = i.mnemonic
        try:
            h = getattr(self, "_i_" + m.replace(".", "_"), None)
            if m.startswith("b.") and len(m) > 2:
                self.emit(Branch(i.addr, self.cond(), i.target, i.end))
            elif h is not None:
                h(i, i.cs.operands)
            elif m in _NOPS:
                pass
            elif m in _EFFECTS:
                self._effect(i, m)
            elif i.cs.operands and i.cs.operands[0].type == OP_REG and \
                    _REGS.get(self.name(i.cs.operands[0]), ("x",))[0].startswith("v"):
                # FP / SIMD: opaque function of the operands
                ops = i.cs.operands
                srcs = tuple(self.operand(o, self.width(o)) for o in ops[1:] if o.type in (OP_REG, OP_IMM))
                self.write_reg(self.name(ops[0]), Intrinsic(m, srcs, self.width(ops[0])))
            else:
                self.out = [self.unknown(i)]
        except (LiftError, KeyError, StopIteration, AttributeError, IndexError):
            self.out = [self.unknown(i)]
        return self.out

    def unknown(self, i: Insn) -> Unknown:
        def regs(names):
            out = {}
            for n in names:
                if n in _REGS:
                    r = self.full(n)
                    out[r.name] = r
                elif n == "nzcv":
                    out.update({f.name: f for f in (ZF, CF, SF, OF)})
            return list(out.items())
        return Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip(), regs(i.regs_read), regs(i.regs_write))

    def _effect(self, i: Insn, m: str):
        if m == "svc":
            uses = [(r, Reg(r, 64)) for r in ("x8", "x0", "x1", "x2", "x3", "x4", "x5")]
            self.emit(Effect(i.addr, "syscall", (), uses, [("x0", Reg("x0", 64))]))
        else:
            self.emit(Effect(i.addr, m, ()))

    # ------------------------------------------------------- data movement
    def _i_mov(self, i, ops):
        w = self.width(ops[0])
        self.write_reg(self.name(ops[0]), self.operand(ops[1], w))

    _i_movz = _i_mov

    def _i_movn(self, i, ops):
        w = self.width(ops[0])
        self.write_reg(self.name(ops[0]), UnOp("~", self.operand(ops[1], w), w))

    def _i_movk(self, i, ops):
        w = self.width(ops[0])
        sh = ops[1].shift.value if ops[1].shift.type == a64.ARM64_SFT_LSL else 0
        dst = self.read_reg(self.name(ops[0]))
        keep = Const(~(0xFFFF << sh) & mask(w), w)
        self.write_reg(self.name(ops[0]), BinOp("|", BinOp("&", dst, keep, w), Const(ops[1].imm << sh, w), w))

    def _i_mvn(self, i, ops):
        w = self.width(ops[0])
        self.write_reg(self.name(ops[0]), UnOp("~", self.operand(ops[1], w), w))

    def _i_adr(self, i, ops):
        self.write_reg(self.name(ops[0]), Const(ops[1].imm, 64))

    _i_adrp = _i_adr

    def _ext(self, i, ops, size, signed):
        w = self.width(ops[0])
        v = self.resize(self.read_reg(self.name(ops[1])), size)
        self.write_reg(self.name(ops[0]), self.resize(v, w, signed))

    def _i_sxtb(self, i, ops):
        self._ext(i, ops, 8, True)

    def _i_sxth(self, i, ops):
        self._ext(i, ops, 16, True)

    def _i_sxtw(self, i, ops):
        self._ext(i, ops, 32, True)

    def _i_uxtb(self, i, ops):
        self._ext(i, ops, 8, False)

    def _i_uxth(self, i, ops):
        self._ext(i, ops, 16, False)

    # ------------------------------------------------------------ arithmetic
    def _arith(self, ops, op: str, flags: str | None = None, neg_first=False):
        w = self.width(ops[0])
        if len(ops) == 2:              # neg / negs / mvn-like 2-operand forms: 0 op b
            a, b = Const(0, w), self.operand(ops[1], w)
        else:
            a, b = self.operand(ops[1], w), self.operand(ops[2], w)
        if flags == "sub":
            self.flags_sub(a, b)
        elif flags == "add":
            self.flags_add(a, b)
        res = BinOp(op, a, b, w)
        if flags == "logic":
            self.flags_logic(res)
        self.write_reg(self.name(ops[0]), res)

    def _i_add(self, i, ops):
        self._arith(ops, "+")

    def _i_adds(self, i, ops):
        self._arith(ops, "+", "add")

    def _i_sub(self, i, ops):
        self._arith(ops, "-")

    def _i_subs(self, i, ops):
        self._arith(ops, "-", "sub")

    def _i_neg(self, i, ops):
        self._arith(ops, "-")

    def _i_negs(self, i, ops):
        self._arith(ops, "-", "sub")

    def _i_cmp(self, i, ops):
        w = self.width(ops[0])
        self.flags_sub(self.operand(ops[0], w), self.operand(ops[1], w))

    def _i_cmn(self, i, ops):
        w = self.width(ops[0])
        self.flags_add(self.operand(ops[0], w), self.operand(ops[1], w))

    def _i_tst(self, i, ops):
        w = self.width(ops[0])
        self.flags_logic(BinOp("&", self.operand(ops[0], w), self.operand(ops[1], w), w))

    def _i_and(self, i, ops):
        self._arith(ops, "&")

    def _i_ands(self, i, ops):
        self._arith(ops, "&", "logic")

    def _i_orr(self, i, ops):
        self._arith(ops, "|")

    def _i_eor(self, i, ops):
        self._arith(ops, "^")

    def _inv(self, ops, op, flags=None):
        w = self.width(ops[0])
        a, b = self.operand(ops[1], w), UnOp("~", self.operand(ops[2], w), w)
        res = BinOp(op, a, b, w)
        if flags:
            self.flags_logic(res)
        self.write_reg(self.name(ops[0]), res)

    def _i_bic(self, i, ops):
        self._inv(ops, "&")

    def _i_bics(self, i, ops):
        self._inv(ops, "&", "logic")

    def _i_orn(self, i, ops):
        self._inv(ops, "|")

    def _i_eon(self, i, ops):
        self._inv(ops, "^")

    def _shift_op(self, ops, op):
        w = self.width(ops[0])
        a = self.operand(ops[1], w)
        if ops[2].type == OP_IMM:
            b = Const(ops[2].imm, 8)
        else:                          # register amount is taken modulo the width
            b = BinOp("&", self.operand(ops[2], w), Const(w - 1, w), w)
        self.write_reg(self.name(ops[0]), BinOp(op, a, b, w))

    def _i_lsl(self, i, ops):
        self._shift_op(ops, "<<")

    def _i_lsr(self, i, ops):
        self._shift_op(ops, ">>u")

    def _i_asr(self, i, ops):
        self._shift_op(ops, ">>s")

    def _i_ror(self, i, ops):
        self._shift_op(ops, "ror")

    def _i_mul(self, i, ops):
        self._arith(ops, "*")

    def _i_madd(self, i, ops):
        w = self.width(ops[0])
        p = BinOp("*", self.operand(ops[1], w), self.operand(ops[2], w), w)
        self.write_reg(self.name(ops[0]), BinOp("+", self.operand(ops[3], w), p, w))

    def _i_msub(self, i, ops):
        w = self.width(ops[0])
        p = BinOp("*", self.operand(ops[1], w), self.operand(ops[2], w), w)
        self.write_reg(self.name(ops[0]), BinOp("-", self.operand(ops[3], w), p, w))

    def _i_mneg(self, i, ops):
        w = self.width(ops[0])
        p = BinOp("*", self.operand(ops[1], w), self.operand(ops[2], w), w)
        self.write_reg(self.name(ops[0]), UnOp("-", p, w))

    def _long_mul(self, ops, signed, acc=None):
        a = self.resize(self.read_reg(self.name(ops[1])), 64, signed)
        b = self.resize(self.read_reg(self.name(ops[2])), 64, signed)
        p = BinOp("*", a, b, 64)
        if acc:
            p = BinOp(acc, self.read_reg(self.name(ops[3])), p, 64)
        self.write_reg(self.name(ops[0]), p)

    def _i_smull(self, i, ops):
        self._long_mul(ops, True)

    def _i_umull(self, i, ops):
        self._long_mul(ops, False)

    def _i_smaddl(self, i, ops):
        self._long_mul(ops, True, "+")

    def _i_umaddl(self, i, ops):
        self._long_mul(ops, False, "+")

    def _i_smsubl(self, i, ops):
        self._long_mul(ops, True, "-")

    def _i_umsubl(self, i, ops):
        self._long_mul(ops, False, "-")

    def _mulh(self, ops, signed):
        ext = "sext" if signed else "zext"
        a = cast(ext, self.read_reg(self.name(ops[1])), 128)
        b = cast(ext, self.read_reg(self.name(ops[2])), 128)
        hi = BinOp(">>u", BinOp("*", a, b, 128), Const(64, 8), 128)
        self.write_reg(self.name(ops[0]), cast("low", hi, 64))

    def _i_smulh(self, i, ops):
        self._mulh(ops, True)

    def _i_umulh(self, i, ops):
        self._mulh(ops, False)

    def _i_sdiv(self, i, ops):
        self._arith(ops, "/s")

    def _i_udiv(self, i, ops):
        self._arith(ops, "/u")

    # ------------------------------------------------------------ bitfields
    def _field(self, ops):
        w = self.width(ops[0])
        return w, self.operand(ops[1], w), ops[2].imm, ops[3].imm

    def _i_ubfx(self, i, ops):
        w, src, lsb, width = self._field(ops)
        v = BinOp("&", BinOp(">>u", src, Const(lsb, 8), w), Const(mask(width), w), w)
        self.write_reg(self.name(ops[0]), v)

    def _i_sbfx(self, i, ops):
        w, src, lsb, width = self._field(ops)
        v = cast("low", BinOp(">>u", src, Const(lsb, 8), w), width) if width < w else src
        self.write_reg(self.name(ops[0]), self.resize(v, w, True))

    def _i_ubfiz(self, i, ops):
        w, src, lsb, width = self._field(ops)
        v = BinOp("<<", BinOp("&", src, Const(mask(width), w), w), Const(lsb, 8), w)
        self.write_reg(self.name(ops[0]), v)

    def _i_sbfiz(self, i, ops):
        w, src, lsb, width = self._field(ops)
        v = self.resize(cast("low", src, width) if width < w else src, w, True)
        self.write_reg(self.name(ops[0]), BinOp("<<", v, Const(lsb, 8), w))

    def _i_bfi(self, i, ops):
        w, src, lsb, width = self._field(ops)
        dst = self.read_reg(self.name(ops[0]))
        keep = Const(~(mask(width) << lsb) & mask(w), w)
        new = BinOp("<<", BinOp("&", src, Const(mask(width), w), w), Const(lsb, 8), w)
        self.write_reg(self.name(ops[0]), BinOp("|", BinOp("&", dst, keep, w), new, w))

    def _i_bfxil(self, i, ops):
        w, src, lsb, width = self._field(ops)
        dst = self.read_reg(self.name(ops[0]))
        keep = Const(~mask(width) & mask(w), w)
        new = BinOp("&", BinOp(">>u", src, Const(lsb, 8), w), Const(mask(width), w), w)
        self.write_reg(self.name(ops[0]), BinOp("|", BinOp("&", dst, keep, w), new, w))

    # --------------------------------------------------- conditional select
    def _i_csel(self, i, ops):
        w = self.width(ops[0])
        self.write_reg(self.name(ops[0]), Ite(self.cond(), self.operand(ops[1], w), self.operand(ops[2], w), w))

    def _cs(self, ops, f):
        w = self.width(ops[0])
        b = self.operand(ops[2], w)
        self.write_reg(self.name(ops[0]), Ite(self.cond(), self.operand(ops[1], w), f(b, w), w))

    def _i_csinc(self, i, ops):
        self._cs(ops, lambda b, w: BinOp("+", b, Const(1, w), w))

    def _i_csinv(self, i, ops):
        self._cs(ops, lambda b, w: UnOp("~", b, w))

    def _i_csneg(self, i, ops):
        self._cs(ops, lambda b, w: UnOp("-", b, w))

    def _i_cset(self, i, ops):
        w = self.width(ops[0])
        self.write_reg(self.name(ops[0]), cast("zext", self.cond(), w))

    def _i_csetm(self, i, ops):
        w = self.width(ops[0])
        self.write_reg(self.name(ops[0]), Ite(self.cond(), Const(mask(w), w), Const(0, w), w))

    def _i_cinc(self, i, ops):
        w = self.width(ops[0])
        s = self.operand(ops[1], w)
        self.write_reg(self.name(ops[0]), Ite(self.cond(), BinOp("+", s, Const(1, w), w), s, w))

    def _i_cinv(self, i, ops):
        w = self.width(ops[0])
        s = self.operand(ops[1], w)
        self.write_reg(self.name(ops[0]), Ite(self.cond(), UnOp("~", s, w), s, w))

    def _i_cneg(self, i, ops):
        w = self.width(ops[0])
        s = self.operand(ops[1], w)
        self.write_reg(self.name(ops[0]), Ite(self.cond(), UnOp("-", s, w), s, w))

    def _ccmp(self, ops, sub: bool):
        """Compare if the condition holds, else set NZCV from the immediate."""
        w = self.width(ops[0])
        a, b = self.operand(ops[0], w), self.operand(ops[1], w)
        nzcv = ops[2].imm
        c = self.tmp(self.cond())
        res = BinOp("-" if sub else "+", a, b, w)
        new = {
            ZF: BinOp("==", res, Const(0, w), 1),
            SF: BinOp("<s", res, Const(0, w), 1),
            CF: BinOp("<=u", b, a, 1) if sub else BinOp("carry", a, b, 1),
            OF: BinOp("sborrow" if sub else "scarry", a, b, 1),
        }
        bit = {SF: 8, ZF: 4, CF: 2, OF: 1}
        for f in (SF, ZF, CF, OF):
            self.assign(f, Ite(c, new[f], Const(1 if nzcv & bit[f] else 0, 1), 1))

    def _i_ccmp(self, i, ops):
        self._ccmp(ops, True)

    def _i_ccmn(self, i, ops):
        self._ccmp(ops, False)

    # --------------------------------------------------------- loads/stores
    _LOAD = {"ldr": (None, False), "ldur": (None, False), "ldrb": (8, False), "ldurb": (8, False),
             "ldrh": (16, False), "ldurh": (16, False), "ldrsb": (8, True), "ldursb": (8, True),
             "ldrsh": (16, True), "ldursh": (16, True), "ldrsw": (32, True), "ldursw": (32, True),
             "ldar": (None, False), "ldarb": (8, False), "ldarh": (16, False), "ldaxr": (None, False),
             "ldxr": (None, False), "ldtr": (None, False)}
    _STORE = {"str": None, "stur": None, "strb": 8, "sturb": 8, "strh": 16, "sturh": 16, "stlr": None,
              "stlrb": 8, "stlrh": 16}

    def _load(self, i, ops, size, signed):
        dst = ops[0]
        w = self.width(dst)
        size = size or w
        if ops[1].type == OP_IMM:                       # PC-relative literal
            v = Load(Const(ops[1].imm, 64), size)
            self.write_reg(self.name(dst), self.resize(v, w, signed))
            return
        addr, wb = self._mem_access(ops)
        v = Load(addr, size)
        if wb is not None and wb[0] == self.name(dst):
            wb = None                                   # the loaded value wins
        self.write_reg(self.name(dst), self.resize(v, w, signed))
        if wb is not None:
            self.write_reg(*wb)

    def _store(self, i, ops, size):
        src = ops[0]
        w = self.width(src)
        size = size or w
        val = self.read_reg(self.name(src))
        addr, wb = self._mem_access(ops)
        self.emit(Store(i.addr, addr, self.resize(val, size)))
        if wb is not None:
            self.write_reg(*wb)

    def lift_ldst(self, i, ops):
        m = i.mnemonic
        if m in self._LOAD:
            self._load(i, ops, *self._LOAD[m])
            return True
        if m in self._STORE:
            self._store(i, ops, self._STORE[m])
            return True
        return False

    def _pair(self, i, ops, load: bool, signed=False):
        r1, r2 = ops[0], ops[1]
        w = 32 if signed else self.width(r1)
        size = w // 8
        addr, wb = self._mem_access(ops)
        base = self.tmp(addr) if not isinstance(addr, Reg) else addr
        if load:
            dw = self.width(r1)
            v1 = self.tmp(Load(base, w))
            v2 = self.tmp(Load(BinOp("+", base, Const(size, 64), 64), w))
            self.write_reg(self.name(r1), self.resize(v1, dw, signed))
            self.write_reg(self.name(r2), self.resize(v2, dw, signed))
        else:
            a = self.read_reg(self.name(r1))
            b = self.read_reg(self.name(r2))
            self.emit(Store(i.addr, base, a))
            self.emit(Store(i.addr, BinOp("+", base, Const(size, 64), 64), b))
        if wb is not None:
            self.write_reg(*wb)

    def _i_ldp(self, i, ops):
        self._pair(i, ops, True)

    def _i_ldpsw(self, i, ops):
        self._pair(i, ops, True, signed=True)

    def _i_stp(self, i, ops):
        self._pair(i, ops, False)

    _i_ldnp = _i_ldp
    _i_stnp = _i_stp

    # --------------------------------------------------------- control flow
    def _i_bl(self, i, ops):
        target = Const(i.target, 64) if i.target is not None else self.operand(ops[0], 64)
        self.emit(CallStmt(i.addr, Call(target, (), 64), noreturn=self._noreturn(i), name=self.an.call_name(i)))

    def _i_blr(self, i, ops):
        self.emit(CallStmt(i.addr, Call(self.read_reg(self.name(ops[0])), (), 64), name=self.an.call_name(i)))

    def _i_ret(self, i, ops):
        self.emit(Return(i.addr))

    def _i_cbz(self, i, ops):
        w = self.width(ops[0])
        self.emit(Branch(i.addr, BinOp("==", self.operand(ops[0], w), Const(0, w), 1), i.target, i.end))

    def _i_cbnz(self, i, ops):
        w = self.width(ops[0])
        self.emit(Branch(i.addr, BinOp("!=", self.operand(ops[0], w), Const(0, w), 1), i.target, i.end))

    def _tb(self, i, ops, op):
        w = self.width(ops[0])
        bit = BinOp("&", BinOp(">>u", self.operand(ops[0], w), Const(ops[1].imm, 8), w), Const(1, w), w)
        self.emit(Branch(i.addr, BinOp(op, bit, Const(0, w), 1), i.target, i.end))

    def _i_tbz(self, i, ops):
        self._tb(i, ops, "==")

    def _i_tbnz(self, i, ops):
        self._tb(i, ops, "!=")

    def _noreturn(self, i: Insn) -> bool:
        if i.target is not None:
            f = self.an.functions.get(i.target)
            if f is not None:
                return f.noreturn
            return (self.an.name(i.target) or "") in NORETURN
        return (self.an.call_name(i) or "") in NORETURN

    def lift_jmp(self, i: Insn, func: "Function") -> list[Stmt]:
        """`b label` (jump or tail call) or `br xN` at the end of a block."""
        self.out = []
        self.insn = i
        if i.target is not None:
            if i.target in func.blocks:
                self.emit(Jump(i.addr, i.target))
            else:
                self.emit(CallStmt(i.addr, Call(Const(i.target, 64), (), 64), tail=True,
                                   name=self.an.name(i.target)))
                self.emit(Return(i.addr))
            return self.out
        try:
            expr = self.read_reg(self.name(i.cs.operands[0]))
        except (LiftError, IndexError):
            return [self.unknown(i)]
        table = func.jump_tables.get(i.addr)
        if table:
            seen = list(dict.fromkeys(t for t in table if t in func.blocks))
            self.emit(IndirectJump(i.addr, expr, seen, list(table)))
        else:
            self.emit(IndirectJump(i.addr, expr, []))
        return self.out


def _install_ldst():
    """Route every plain load/store mnemonic to `lift_ldst`."""
    for m in list(Arm64Lifter._LOAD) + list(Arm64Lifter._STORE):
        setattr(Arm64Lifter, "_i_" + m, lambda self, i, ops: self.lift_ldst(i, ops))


_install_ldst()

__all__ = ["Arm64Lifter"]

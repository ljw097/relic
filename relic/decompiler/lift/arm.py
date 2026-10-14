"""ARM (A32) lifter.

Registers are the 32-bit `r0`..`r12`, `sp` and `lr` (`fp`/`ip`/`sb`/`sl` are
aliases); reading `pc` gives the instruction's address + 8. NZCV share the
1-bit flag registers of the other lifters (`sf` = N, `zf` = Z, `cf` = C,
`of` = V, with ARM's carry: no borrow after a subtraction).

Almost every A32 instruction is conditional. A conditional data-processing
or load/store instruction becomes `dst = cond ? new : old` (`Store` keeps
the old memory value the same way); the condition is read before the
instruction updates any flag. Conditional calls and returns cannot be
expressed inside a block, so they branch to a small synthetic block
(`addr + 1`, never a real instruction address) holding the call or the
return -- `extra_blocks` hands those to `lift_function`.

Literal-pool loads (`ldr rX, [pc, #imm]`) read the constant at lift time:
code is immutable, and the constant is usually an address (PIC offsets,
strings) the later passes need to see. VFP / NEON arithmetic stays opaque.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import capstone.arm as A

from ...analysis.functions import NORETURN
from ...disasm import Insn
from ..ir import (Assign, BinOp, Branch, Call, CallStmt, Cast, Const, Effect, Expr, Extract, IndirectJump,
                  Intrinsic, Ite, Jump, Load, Reg, Return, Stmt, Store, UnOp, Unknown, mask)
from ..fp import from_float
from .x86 import LiftError, cast

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function

OP_REG, OP_IMM, OP_MEM = 1, 2, 3
ZF, CF, SF, OF = (Reg(n, 1) for n in ("zf", "cf", "sf", "of"))
SP = Reg("sp", 32)

_ALIAS = {"sb": "r9", "sl": "r10", "fp": "r11", "ip": "r12", "r13": "sp", "r14": "lr"}
_GPR = {f"r{k}" for k in range(13)} | {"sp", "lr"}

_CC = {
    A.ARM_CC_EQ: lambda: ZF,
    A.ARM_CC_NE: lambda: UnOp("!", ZF, 1),
    A.ARM_CC_HS: lambda: CF,
    A.ARM_CC_LO: lambda: UnOp("!", CF, 1),
    A.ARM_CC_MI: lambda: SF,
    A.ARM_CC_PL: lambda: UnOp("!", SF, 1),
    A.ARM_CC_VS: lambda: OF,
    A.ARM_CC_VC: lambda: UnOp("!", OF, 1),
    A.ARM_CC_HI: lambda: BinOp("&", CF, UnOp("!", ZF, 1), 1),
    A.ARM_CC_LS: lambda: BinOp("|", UnOp("!", CF, 1), ZF, 1),
    A.ARM_CC_GE: lambda: BinOp("==", SF, OF, 1),
    A.ARM_CC_LT: lambda: BinOp("!=", SF, OF, 1),
    A.ARM_CC_GT: lambda: BinOp("&", UnOp("!", ZF, 1), BinOp("==", SF, OF, 1), 1),
    A.ARM_CC_LE: lambda: BinOp("|", ZF, BinOp("!=", SF, OF, 1), 1),
}

_NOPS = {"nop", "dmb", "dsb", "isb", "pld", "pldw", "pli", "yield", "wfe", "wfi", "sev", "clrex", "dbg"}
_EFFECTS = {"svc", "bkpt", "udf", "hvc", "smc"}
_COND_SUFFIX = ("eq", "ne", "hs", "cs", "lo", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le")


class ArmLifter:
    bits = 32

    def __init__(self, an: "Analysis"):
        self.an = an
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0
        self.thumb = False
        # synthetic blocks for conditional calls / returns: addr -> (statements, successors)
        self.extra_blocks: dict[int, tuple[list[Stmt], list[int]]] = {}

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

    @staticmethod
    def canon(name: str) -> str:
        return _ALIAS.get(name, name) if name else name

    def pc_value(self) -> int:
        return self.insn.addr + (4 if self.thumb else 8)

    def reg_name(self, rid) -> str:
        return self.canon(self.insn.cs.reg_name(rid))

    def read_reg(self, name: str) -> Expr:
        if not name:
            raise LiftError("unnamed register")
        name = self.canon(name)
        if name == "pc":
            return Const(self.pc_value(), 32)
        if name in _GPR:
            return Reg(name, 32)
        if name[:1] == "s" and name[1:].isdigit():                    # s2k / s2k+1: halves of dk
            k = int(name[1:])
            d = Reg(f"d{k // 2}", 64)
            return Extract(d, 32, 32) if k & 1 else Cast("low", d, 32)
        if name[:1] in ("d", "q") and name[1:].isdigit():             # VFP / NEON
            return Reg(name, {"d": 64, "q": 128}[name[0]])
        raise LiftError(f"register {name}")

    def write_reg(self, name: str, v: Expr):
        name = self.canon(name)
        if name == "pc":
            raise LiftError("write to pc")
        if name[:1] == "s" and name[1:].isdigit():                    # merge into the d register
            k = int(name[1:])
            d = Reg(f"d{k // 2}", 64)
            v = v if v.bits == 32 else cast("low", v, 32) if v.bits > 32 else cast("zext", v, 32)
            new = cast("zext", v, 64)
            if k & 1:
                self.assign(d, BinOp("|", BinOp("&", d, Const(0xFFFFFFFF, 64), 64),
                                     BinOp("<<", new, Const(32, 8), 64), 64))
            else:
                self.assign(d, BinOp("|", BinOp("&", d, Const(0xFFFFFFFF00000000, 64), 64), new, 64))
            return
        r = self.read_reg(name)
        if v.bits != r.bits:
            v = cast("low", v, r.bits) if v.bits > r.bits else cast("zext", v, r.bits)
        self.assign(r, v)

    def cond(self) -> Expr:
        cc = self.insn.cs.cc
        if cc not in _CC:
            raise LiftError(f"condition {cc}")
        return _CC[cc]()

    def _shift(self, v: Expr, op) -> Expr:
        st, amount = op.shift.type, op.shift.value
        if st == 0:
            return v
        if st in (A.ARM_SFT_ASR_REG, A.ARM_SFT_LSL_REG, A.ARM_SFT_LSR_REG, A.ARM_SFT_ROR_REG):
            n = BinOp("&", self.read_reg(self.insn.cs.reg_name(amount)), Const(0xFF, 32), 32)
            kind = {A.ARM_SFT_ASR_REG: ">>s", A.ARM_SFT_LSL_REG: "<<", A.ARM_SFT_LSR_REG: ">>u",
                    A.ARM_SFT_ROR_REG: "ror"}[st]
            return BinOp(kind, v, n, 32)
        if st == A.ARM_SFT_RRX:
            return BinOp("|", BinOp(">>u", v, Const(1, 8), 32),
                         BinOp("<<", cast("zext", CF, 32), Const(31, 8), 32), 32)
        kind = {A.ARM_SFT_ASR: ">>s", A.ARM_SFT_LSL: "<<", A.ARM_SFT_LSR: ">>u", A.ARM_SFT_ROR: "ror"}.get(st)
        if kind is None:
            raise LiftError("shift")
        if amount == 0 and st in (A.ARM_SFT_LSR, A.ARM_SFT_ASR):
            amount = 32                          # encoded #0 means #32 for lsr/asr
        if amount >= 32:
            return Const(0, 32) if kind == ">>u" else BinOp(">>s", v, Const(31, 8), 32)
        return BinOp(kind, v, Const(amount, 8), 32)

    def operand(self, op) -> Expr:
        if op.type == OP_REG:
            v = self.read_reg(self.insn.cs.reg_name(op.reg))
            return self._shift(v, op)
        if op.type == OP_IMM:
            v = op.imm & mask(32)
            return Const(-v & mask(32) if getattr(op, "subtracted", False) else v, 32)
        raise LiftError("operand")

    def address(self, op) -> Expr:
        m = op.mem
        c = self.insn.cs
        base_name = self.reg_name(m.base)
        if base_name == "pc":
            base: Expr = Const((self.pc_value() & ~3) if self.thumb else self.pc_value(), 32)
        else:
            base = self.read_reg(base_name)
        e = base
        if m.index:
            idx = self._shift(self.read_reg(c.reg_name(m.index)), op)
            e = BinOp("-" if getattr(op, "subtracted", False) else "+", e, idx, 32)
        if m.disp:
            e = BinOp("+", e, Const(m.disp, 32), 32) if m.disp > 0 else BinOp("-", e, Const(-m.disp, 32), 32)
        return e

    def _mem_access(self, ops):
        """(address, writeback) for the memory operand; writeback is (register, new value) or None."""
        c = self.insn.cs
        mem = next(o for o in ops if o.type == OP_MEM)
        base = self.reg_name(mem.mem.base)
        if getattr(c, "post_index", False):
            off = next((o for o in ops[ops.index(mem) + 1:]), None)
            addr = self.read_reg(base)
            if off is None:
                return addr, None
            if off.type == OP_IMM:
                delta: Expr = Const(off.imm, 32)
                sub = getattr(off, "subtracted", False) or off.imm < 0
                if off.imm < 0:
                    delta = Const(-off.imm, 32)
            else:
                delta = self._shift(self.read_reg(c.reg_name(off.reg)), off)
                sub = getattr(off, "subtracted", False)
            return addr, (base, BinOp("-" if sub else "+", self.read_reg(base), delta, 32))
        addr = self.address(mem)
        if getattr(c, "writeback", False):
            t = self.tmp(addr)
            return t, (base, t)
        return addr, None

    # ------------------------------------------------------------- flags
    def _nz(self, res: Expr):
        self.assign(ZF, BinOp("==", res, Const(0, 32), 1))
        self.assign(SF, BinOp("<s", res, Const(0, 32), 1))

    def flags_sub(self, a: Expr, b: Expr):
        self._nz(BinOp("-", a, b, 32))
        self.assign(CF, BinOp("<=u", b, a, 1))      # ARM: carry = no borrow
        self.assign(OF, BinOp("sborrow", a, b, 1))

    def flags_add(self, a: Expr, b: Expr):
        self._nz(BinOp("+", a, b, 32))
        self.assign(CF, BinOp("carry", a, b, 1))
        self.assign(OF, BinOp("scarry", a, b, 1))

    # ------------------------------------------------------------ driver
    def lift_insn(self, i: Insn, func: "Function | None" = None) -> list[Stmt]:
        self.out = []
        self.insn = i
        self.thumb = i.thumb
        c = i.cs
        m = c.mnemonic.split(".")[0]
        conditional = c.cc not in (A.ARM_CC_AL, 0)
        base = m[:-2] if conditional and m.endswith(_COND_SUFFIX) and len(m) > 2 else m
        try:
            if base in ("cbz", "cbnz") and i.target is not None:            # Thumb compare and branch
                r = self.read_reg(self.reg_name(c.operands[0].reg))
                test = BinOp("==" if base == "cbz" else "!=", r, Const(0, 32), 1)
                self.emit(Branch(i.addr, test, i.target, i.end))
                return self.out
            if conditional and i.kind in ("cjmp",) and i.target is not None:
                self.emit(Branch(i.addr, self.cond(), i.target, i.end))       # b<cond>
                return self.out
            if conditional and (i.kind == "cjmp" or i.kind == "call"):
                return self._conditional_flow(i, base)
            cnd = self.tmp(self.cond()) if conditional else None
            self._dispatch(i, base, c.operands)
            if cnd is not None:
                self.out = self._predicate(self.out, cnd)
        except (LiftError, KeyError, StopIteration, AttributeError, IndexError, ValueError):
            self.out = [self.unknown(i)]
        return self.out

    def _dispatch(self, i, base, ops):
        upd = getattr(i.cs, "update_flags", False)
        name = base[:-1] if upd and base.endswith("s") and base not in ("mls", "smulls", "umulls") and \
            not base.startswith("v") else base
        h = getattr(self, "_i_" + name, None)
        if h is not None:
            h(i, ops, upd)
        elif name in self._LOAD or name in self._STORE:
            self._ldst(i, name, ops)
        elif name in _NOPS or name.startswith("pld") or (name[:2] == "it" and set(name[2:]) <= {"t", "e"}):
            pass
        elif name in _EFFECTS:
            self._effect(i, name)
        elif name.startswith("v") or (ops and ops[0].type == OP_REG and
                                       self.reg_name(ops[0].reg)[:1] in ("s", "d", "q")
                                       and self.reg_name(ops[0].reg)[1:].isdigit()):
            self._vfp(i, name, ops)
        elif ops and all(o.type in (OP_REG, OP_IMM) for o in ops) and ops[0].type == OP_REG and \
                self.reg_name(ops[0].reg) in _GPR and i.kind == "normal":
            # media / bit operations (`uqsub8`, `sel`, `rbit`, ...): an opaque value of the sources
            srcs = tuple(self.operand(o) for o in ops[1:])
            self.write_reg(self.reg_name(ops[0].reg), Intrinsic(name, srcs, 32))
        else:
            self.out = [self.unknown(i)]

    def _predicate(self, stmts: list[Stmt], cnd: Reg) -> list[Stmt]:
        """Make the effects of a conditional instruction depend on the (pre-computed) condition."""
        out = []
        for s in stmts:
            if isinstance(s, Assign) and isinstance(s.dst, Reg) and not s.dst.name.startswith("t"):
                out.append(Assign(s.addr, s.dst, Ite(cnd, s.src, s.dst, s.dst.bits)))
            elif isinstance(s, Store):
                out.append(Store(s.addr, s.dst, Ite(cnd, s.src, Load(s.dst, s.src.bits), s.src.bits)))
            elif isinstance(s, (CallStmt, Effect, Unknown, Return)):
                raise LiftError("conditional side effect")
            else:
                out.append(s)
        return out

    def _conditional_flow(self, i: Insn, base: str) -> list[Stmt]:
        """`blne f`, `bxeq lr`, `popne {..., pc}`: branch to a synthetic block that does it."""
        cnd = self.tmp(self.cond())
        synth = i.addr + 1
        if i.kind == "call":
            saved = self.out
            self.out = []
            self._dispatch(i, base, i.cs.operands)
            body = self.out + [Jump(i.addr, i.end)]
            self.out = saved
            self.extra_blocks[synth] = (body, [i.end])
        else:                                            # conditional return
            saved = self.out
            self.out = []
            if base in ("pop", "ldm", "ldmia", "ldmfd", "ldr"):
                self._dispatch(i, base, i.cs.operands)   # restores registers, ends in Return
            else:
                self.emit(Return(i.addr))
            body = self.out
            self.out = saved
            self.extra_blocks[synth] = (body, [])
        self.emit(Branch(i.addr, cnd, synth, i.end))
        return self.out

    def unknown(self, i: Insn) -> Unknown:
        def regs(names):
            out = {}
            for n in names:
                n = self.canon(n)
                if n in _GPR:
                    out[n] = Reg(n, 32)
                elif n in ("cpsr", "apsr"):
                    out.update({f.name: f for f in (ZF, CF, SF, OF)})
            return list(out.items())
        return Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip(), regs(i.regs_read), regs(i.regs_write))

    def _effect(self, i, name):
        if name == "svc":
            uses = [(r, Reg(r, 32)) for r in ("r7", "r0", "r1", "r2", "r3", "r4", "r5", "r6")]
            self.emit(Effect(i.addr, "syscall", (), uses, [("r0", Reg("r0", 32))]))
        else:
            self.emit(Effect(i.addr, name, ()))

    def _vfp(self, i, name, ops):
        """VFP: scalar floating point (`.f32` / `.f64`) per fp.py; NEON and the rest stay opaque."""
        h = getattr(self, "_v_" + name, None)
        if h is not None and h(i, ops) is not False:
            return
        dst = ops[0]
        if dst.type != OP_REG:
            raise LiftError("vfp store")
        srcs = tuple(self.operand(o) if o.type in (OP_REG, OP_IMM) else Load(self.address(o), 64)
                     for o in ops[1:])
        dn = self.reg_name(dst.reg)
        self.write_reg(dn, Intrinsic(name, srcs, self.read_reg(dn).bits))

    def _vtypes(self) -> list[str]:
        """The data types of a VFP mnemonic: `vcvt.f64.s32` -> ["f64", "s32"]."""
        return self.insn.cs.mnemonic.split(".")[1:]

    def _vw(self, op) -> int | None:
        """Width of a scalar VFP register operand: s 32, d 64."""
        if op.type != OP_REG:
            return None
        n = self.reg_name(op.reg)
        return {"s": 32, "d": 64}.get(n[:1]) if n[1:].isdigit() else None

    def _vsrc(self, op, w: int) -> Expr:
        if op.type == 4:                                       # ARM_OP_FP: `#3.0`, `#0`
            return Const(from_float(op.fp, w), w)
        if op.type == OP_IMM:
            return Const(from_float(float(op.imm), w), w)
        return self.read_reg(self.reg_name(op.reg))

    def _vscalar(self, ops) -> int | None:
        """The width when every register operand is a scalar of one width (not NEON)."""
        ws = {self._vw(o) for o in ops if o.type == OP_REG}
        return ws.pop() if len(ws) == 1 and None not in ws else None

    def _varith(self, i, ops, op):
        w = self._vscalar(ops)
        if w is None or len(ops) not in (2, 3):
            return False
        a, b = (ops[1], ops[2]) if len(ops) == 3 else (ops[0], ops[1])
        self.write_reg(self.reg_name(ops[0].reg), BinOp(op, self._vsrc(a, w), self._vsrc(b, w), w))

    def _v_vadd(self, i, ops):
        return self._varith(i, ops, "f+")

    def _v_vsub(self, i, ops):
        return self._varith(i, ops, "f-")

    def _v_vmul(self, i, ops):
        return self._varith(i, ops, "f*")

    def _v_vdiv(self, i, ops):
        return self._varith(i, ops, "f/")

    def _v_vnmul(self, i, ops):
        w = self._vscalar(ops)
        if w is None or len(ops) != 3:
            return False
        self.write_reg(self.reg_name(ops[0].reg),
                       UnOp("fneg", BinOp("f*", self._vsrc(ops[1], w), self._vsrc(ops[2], w), w), w))

    def _vacc(self, i, ops, neg_acc: bool, sub: bool):
        """vmla d += n*m, vmls d -= n*m, vnmla d = -d - n*m, vnmls d = -d + n*m: the product is
        rounded before the addition (unlike vfma)."""
        w = self._vscalar(ops)
        if w is None or len(ops) != 3:
            return False
        d = self.reg_name(ops[0].reg)
        acc = self.read_reg(d)
        if neg_acc:
            acc = UnOp("fneg", acc, w)
        prod = BinOp("f*", self._vsrc(ops[1], w), self._vsrc(ops[2], w), w)
        self.write_reg(d, BinOp("f-" if sub else "f+", acc, prod, w))

    def _v_vmla(self, i, ops):
        return self._vacc(i, ops, False, False)

    def _v_vmls(self, i, ops):
        return self._vacc(i, ops, False, True)

    def _v_vnmla(self, i, ops):
        return self._vacc(i, ops, True, True)

    def _v_vnmls(self, i, ops):
        return self._vacc(i, ops, True, False)

    def _vfused(self, i, ops, neg_product: bool, neg_acc: bool):
        w = self._vscalar(ops)
        if w is None or len(ops) != 3:
            return False
        d = self.reg_name(ops[0].reg)
        n, m = self._vsrc(ops[1], w), self._vsrc(ops[2], w)
        acc = self.read_reg(d)
        if neg_product:
            n = UnOp("fneg", n, w)
        if neg_acc:
            acc = UnOp("fneg", acc, w)
        self.write_reg(d, Intrinsic("fma" if w == 64 else "fmaf", (n, m, acc), w))

    def _v_vfma(self, i, ops):
        return self._vfused(i, ops, False, False)

    def _v_vfms(self, i, ops):
        return self._vfused(i, ops, True, False)

    def _v_vfnma(self, i, ops):
        return self._vfused(i, ops, True, True)

    def _v_vfnms(self, i, ops):
        return self._vfused(i, ops, False, True)

    def _vunary(self, i, ops, name):
        w = self._vscalar(ops)
        if w is None or len(ops) != 2:
            return False
        x = self._vsrc(ops[1], w)
        self.write_reg(self.reg_name(ops[0].reg), UnOp("fneg", x, w) if name is None else
                       Intrinsic(name if w == 64 else name + "f", (x,), w))

    def _v_vneg(self, i, ops):
        return self._vunary(i, ops, None)

    def _v_vabs(self, i, ops):
        return self._vunary(i, ops, "fabs")

    def _v_vsqrt(self, i, ops):
        return self._vunary(i, ops, "sqrt")

    def _v_vmov(self, i, ops):
        """Register moves (VFP <-> core: the same bits), FP immediates, pairs of core registers."""
        if len(ops) == 2 and ops[0].type == OP_REG:
            dn = self.reg_name(ops[0].reg)
            dw = self._vw(ops[0])
            src = ops[1]
            if src.type == 4 and dw:                               # vmov.f64 d6, #3.0
                self.write_reg(dn, Const(from_float(src.fp, dw), dw))
                return
            if src.type == OP_REG:
                sn = self.reg_name(src.reg)
                if dn in _GPR or sn in _GPR or dw is not None and dw == self._vw(src):
                    self.write_reg(dn, self.read_reg(sn))
                    return
            return False
        if len(ops) == 3 and all(o.type == OP_REG for o in ops):
            a, b, c = (self.reg_name(o.reg) for o in ops)
            if a.startswith("d") and b in _GPR and c in _GPR:      # vmov d0, r0, r1
                self.write_reg(a, BinOp("|", cast("zext", self.read_reg(b), 64),
                                        BinOp("<<", cast("zext", self.read_reg(c), 64), Const(32, 8), 64), 64))
                return
            if a in _GPR and b in _GPR and c.startswith("d"):      # vmov r0, r1, d0
                d = self.tmp(self.read_reg(c))
                self.write_reg(a, Cast("low", d, 32))
                self.write_reg(b, Extract(d, 32, 32))
                return
        return False

    def _v_vcvt(self, i, ops):
        """vcvt.<to>.<from>: int <-> float (fixed point with a third operand), float <-> double."""
        t = self._vtypes()
        if len(t) != 2 or len(ops) not in (2, 3):
            return False
        to, frm = t
        dn = self.reg_name(ops[0].reg)
        fbits = ops[2].imm if len(ops) == 3 and ops[2].type == OP_IMM else 0
        src = self.read_reg(self.reg_name(ops[1].reg))
        if to[0] == "f" and frm[0] == "f":
            self.write_reg(dn, Intrinsic("fpconv", (src,), int(to[1:])))
        elif to[0] == "f":                                         # from an integer
            w = int(to[1:])
            ibits = int(frm[1:])
            x = cast("low", src, ibits) if src.bits > ibits else src
            v = Intrinsic("sitofp" if frm[0] == "s" else "uitofp", (x,), w)
            if fbits:                                              # fixed point: / 2^fbits (exact)
                v = BinOp("f/", v, Const(from_float(float(1 << fbits), w), w), w)
            self.write_reg(dn, v)
        else:                                                      # to an integer (truncating)
            fw = int(frm[1:])
            x = src
            if fbits:
                x = BinOp("f*", x, Const(from_float(float(1 << fbits), fw), fw), fw)
            self.write_reg(dn, Intrinsic("fptosi" if to[0] == "s" else "fptoui", (x,), int(to[1:])))

    def _v_vcvtr(self, i, ops):
        t = self._vtypes()
        if len(t) != 2 or t[0][0] == "f":
            return False
        fw = int(t[1][1:])
        x = Intrinsic("rint" if fw == 64 else "rintf", (self.read_reg(self.reg_name(ops[1].reg)),), fw)
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("fptosi" if t[0][0] == "s" else "fptoui", (x,), 32))

    def _v_vcmp(self, i, ops):
        """The FPSCR flags of a compare (lt 1000, eq 0110, gt 0010, unordered 0011); `vmrs
        APSR_nzcv, fpscr` copies them to N Z C V."""
        w = self._vw(ops[0])
        if w is None or len(ops) != 2:
            return False
        a, b = self._vsrc(ops[0], w), self._vsrc(ops[1], w)
        lt = BinOp("f<", a, b, 1)
        self.assign(Reg("fpscr_n", 1), lt)
        self.assign(Reg("fpscr_z", 1), BinOp("f==", a, b, 1))
        self.assign(Reg("fpscr_c", 1), UnOp("!", lt, 1))
        self.assign(Reg("fpscr_v", 1), BinOp("funord", a, b, 1))

    _v_vcmpe = _v_vcmp

    def _v_vmrs(self, i, ops):
        if len(ops) == 2 and ops[0].type == OP_REG and self.insn.cs.reg_name(ops[0].reg).lower() == "apsr_nzcv":
            for flag, src in ((SF, "fpscr_n"), (ZF, "fpscr_z"), (CF, "fpscr_c"), (OF, "fpscr_v")):
                self.assign(flag, Reg(src, 1))
            return
        return False

    def _vmem_width(self, op) -> int:
        return 64 if self.reg_name(op.reg).startswith("d") else 32

    def _v_vldr(self, i, ops):
        dn = self.reg_name(ops[0].reg)
        w = self._vmem_width(ops[0])
        mem = ops[1]
        if self.reg_name(mem.mem.base) == "pc" and not mem.mem.index:   # a constant in the literal pool
            pc = self.pc_value() & ~3
            disp = mem.mem.disp if not getattr(mem, "subtracted", False) else -mem.mem.disp
            v = self.an.bin.read_int((pc + disp) & mask(32), w // 8)
            if v is not None:
                self.write_reg(dn, Const(v, w))
                return
        addr, wb = self._mem_access(ops)
        self.write_reg(dn, Load(addr, w))
        if wb is not None:
            self.write_reg(*wb)

    def _v_vstr(self, i, ops):
        addr, wb = self._mem_access(ops)
        self.emit(Store(i.addr, addr, self.read_reg(self.reg_name(ops[0].reg))))
        if wb is not None:
            self.write_reg(*wb)

    def _vlist(self, regs: list[str], base: Expr, load: bool) -> Expr:
        """Consecutive registers to / from memory from `base` up; the end address."""
        off = 0
        b = self.tmp(base)
        for r in regs:
            w = 64 if r.startswith("d") else 32
            a = BinOp("+", b, Const(off, 32), 32) if off else b
            if load:
                self.write_reg(r, Load(a, w))
            else:
                self.emit(Store(self.insn.addr, a, self.read_reg(r)))
            off += w // 8
        return BinOp("+", b, Const(off, 32), 32)

    def _v_vpush(self, i, ops):
        regs = [self.reg_name(o.reg) for o in ops]
        size = sum(8 if r.startswith("d") else 4 for r in regs)
        sp = Reg("sp", 32)
        self.assign(sp, BinOp("-", sp, Const(size, 32), 32))
        self._vlist(regs, sp, False)

    def _v_vpop(self, i, ops):
        regs = [self.reg_name(o.reg) for o in ops]
        sp = Reg("sp", 32)
        end = self._vlist(regs, sp, True)
        self.assign(sp, end)

    def _vldm(self, i, ops, load: bool):
        base = self.reg_name(ops[0].reg)
        regs = [self.reg_name(o.reg) for o in ops[1:]]
        end = self._vlist(regs, self.read_reg(base), load)
        if getattr(self.insn.cs, "writeback", False):
            self.write_reg(base, end)

    def _v_vldmia(self, i, ops):
        self._vldm(i, ops, True)

    def _v_vstmia(self, i, ops):
        self._vldm(i, ops, False)

    # ------------------------------------------------------- data processing
    def _i_mov(self, i, ops, upd):
        v = self.operand(ops[1])
        if upd:
            self._logic_flags(v, ops[1])
        self.write_reg(self.reg_name(ops[0].reg), v)

    def _i_mvn(self, i, ops, upd):
        v = UnOp("~", self.operand(ops[1]), 32)
        if upd:
            self._logic_flags(v, ops[1])
        self.write_reg(self.reg_name(ops[0].reg), v)

    def _i_movw(self, i, ops, upd):
        self.write_reg(self.reg_name(ops[0].reg), Const(ops[1].imm & 0xFFFF, 32))

    def _i_movt(self, i, ops, upd):
        d = self.read_reg(self.reg_name(ops[0].reg))
        self.write_reg(self.reg_name(ops[0].reg),
                       BinOp("|", BinOp("&", d, Const(0xFFFF, 32), 32), Const((ops[1].imm & 0xFFFF) << 16, 32), 32))

    def _two(self, ops):
        """(destination, first source, second source) of a 2- or 3-operand form."""
        d = self.reg_name(ops[0].reg)
        if len(ops) == 2:
            return d, self.read_reg(d), self.operand(ops[1])
        if self.thumb and ops[1].type == OP_REG and self.reg_name(ops[1].reg) == "pc" and ops[2].type == OP_IMM:
            # `add rd, pc, #imm` (adr) reads the word-aligned pc in Thumb
            return d, Const(self.pc_value() & ~3, 32), self.operand(ops[2])
        return d, self.operand(ops[1]), self.operand(ops[2])

    def _shifter_carry(self, op):
        """Carry out of operand 2 of a logical instruction with S (None: carry unchanged)."""
        if op.type == OP_IMM:
            v = op.imm & mask(32)
            return Const(v >> 31, 1) if v > 0xFF else None       # a rotated immediate
        if op.type != OP_REG:
            return None
        st, n = op.shift.type, op.shift.value
        src = self.read_reg(self.insn.cs.reg_name(op.reg))
        if st == A.ARM_SFT_LSL and 0 < n <= 32:
            bit = 32 - n
        elif st in (A.ARM_SFT_LSR, A.ARM_SFT_ASR):
            bit = (n or 32) - 1
        elif st == A.ARM_SFT_ROR and n:
            bit = n - 1
        elif st == A.ARM_SFT_RRX:
            bit = 0
        else:
            return None
        return cast("low", BinOp(">>u", src, Const(bit, 8), 32), 1)

    def _logic_flags(self, res, op):
        c = self._shifter_carry(op)
        self._nz(res)
        if c is not None:
            self.assign(CF, c)

    def _arith(self, ops, op, upd, flags=None, reverse=False, carry_in=False):
        d, a, b = self._two(ops)
        if reverse:
            a, b = b, a
        res = BinOp(op, a, b, 32)
        if carry_in:                                     # adc: + C ; sbc: - !C
            c = cast("zext", CF, 32)
            res = BinOp("+", res, c, 32) if op == "+" else BinOp("-", res, BinOp("^", c, Const(1, 32), 32), 32)
        if upd:
            if flags == "add":
                self.flags_add(a, b)
            elif flags == "sub":
                self.flags_sub(a, b)
            else:
                self._logic_flags(res, ops[-1])
        self.write_reg(d, res)

    def _i_add(self, i, ops, upd):
        self._arith(ops, "+", upd, "add")

    def _i_addw(self, i, ops, upd):
        self._arith(ops, "+", False)

    def _i_subw(self, i, ops, upd):
        self._arith(ops, "-", False)

    def _i_adc(self, i, ops, upd):
        self._arith(ops, "+", upd, "add", carry_in=True)

    def _i_sub(self, i, ops, upd):
        self._arith(ops, "-", upd, "sub")

    def _i_sbc(self, i, ops, upd):
        self._arith(ops, "-", upd, "sub", carry_in=True)

    def _i_rsb(self, i, ops, upd):
        self._arith(ops, "-", upd, "sub", reverse=True)

    def _i_rsc(self, i, ops, upd):
        self._arith(ops, "-", upd, "sub", reverse=True, carry_in=True)

    def _i_and(self, i, ops, upd):
        self._arith(ops, "&", upd)

    def _i_orr(self, i, ops, upd):
        self._arith(ops, "|", upd)

    def _i_eor(self, i, ops, upd):
        self._arith(ops, "^", upd)

    def _i_bic(self, i, ops, upd):
        d, a, b = self._two(ops)
        res = BinOp("&", a, UnOp("~", b, 32), 32)
        if upd:
            self._nz(res)
        self.write_reg(d, res)

    def _i_orn(self, i, ops, upd):
        d, a, b = self._two(ops)
        res = BinOp("|", a, UnOp("~", b, 32), 32)
        if upd:
            self._nz(res)
        self.write_reg(d, res)

    def _i_cmp(self, i, ops, upd):
        self.flags_sub(self.operand(ops[0]), self.operand(ops[1]))

    def _i_cmn(self, i, ops, upd):
        self.flags_add(self.operand(ops[0]), self.operand(ops[1]))

    def _i_tst(self, i, ops, upd):
        self._logic_flags(BinOp("&", self.operand(ops[0]), self.operand(ops[1]), 32), ops[1])

    def _i_teq(self, i, ops, upd):
        self._logic_flags(BinOp("^", self.operand(ops[0]), self.operand(ops[1]), 32), ops[1])

    def _shift_insn(self, ops, upd, kind):
        d = self.reg_name(ops[0].reg)
        a = self.operand(ops[1])
        if kind == "rrx":
            res = BinOp("|", BinOp(">>u", a, Const(1, 8), 32),
                        BinOp("<<", cast("zext", CF, 32), Const(31, 8), 32), 32)
        elif len(ops) < 3:                   # `lsl r3, r3, #5`: capstone folds the shift into operand 1
            res = a
        elif ops[2].type == OP_IMM:
            n = ops[2].imm
            res = BinOp(kind, a, Const(n, 8), 32) if n < 32 else (
                Const(0, 32) if kind in ("<<", ">>u") else BinOp(">>s", a, Const(31, 8), 32))
        else:
            res = BinOp(kind, a, BinOp("&", self.operand(ops[2]), Const(0xFF, 32), 32), 32)
        if upd:
            self._nz(res)
            # the carry is the last bit shifted out (immediate amounts; unchanged for #0)
            if len(ops) < 3 and kind != "rrx":
                src, n = self.read_reg(self.reg_name(ops[1].reg)), ops[1].shift.value
            elif len(ops) >= 3 and ops[2].type == OP_IMM:
                src, n = a, ops[2].imm
            else:
                src, n = (a, 0) if kind != "rrx" else (a, None)
            if kind == "rrx":
                self.assign(CF, cast("low", a, 1))
            elif n and kind in ("<<", ">>u", ">>s") and n <= 32:
                bit = 32 - n if kind == "<<" else n - 1
                self.assign(CF, cast("low", BinOp(">>u", src, Const(bit, 8), 32), 1))
        self.write_reg(d, res)

    def _i_lsl(self, i, ops, upd):
        self._shift_insn(ops, upd, "<<")

    def _i_lsr(self, i, ops, upd):
        self._shift_insn(ops, upd, ">>u")

    def _i_asr(self, i, ops, upd):
        self._shift_insn(ops, upd, ">>s")

    def _i_ror(self, i, ops, upd):
        self._shift_insn(ops, upd, "ror")

    def _i_rrx(self, i, ops, upd):
        self._shift_insn(ops[:2], upd, "rrx")

    def _i_mul(self, i, ops, upd):
        d, a, b = self._two(ops)
        res = BinOp("*", a, b, 32)
        if upd:
            self._nz(res)
        self.write_reg(d, res)

    def _i_mla(self, i, ops, upd):
        res = BinOp("+", BinOp("*", self.operand(ops[1]), self.operand(ops[2]), 32), self.operand(ops[3]), 32)
        if upd:
            self._nz(res)
        self.write_reg(self.reg_name(ops[0].reg), res)

    def _i_mls(self, i, ops, upd):
        res = BinOp("-", self.operand(ops[3]), BinOp("*", self.operand(ops[1]), self.operand(ops[2]), 32), 32)
        self.write_reg(self.reg_name(ops[0].reg), res)

    def _long_mul(self, ops, signed, accumulate):
        lo, hi = self.reg_name(ops[0].reg), self.reg_name(ops[1].reg)
        ext = "sext" if signed else "zext"
        p = BinOp("*", cast(ext, self.operand(ops[2]), 64), cast(ext, self.operand(ops[3]), 64), 64)
        if accumulate:
            acc = BinOp("|", BinOp("<<", cast("zext", self.read_reg(hi), 64), Const(32, 8), 64),
                        cast("zext", self.read_reg(lo), 64), 64)
            p = BinOp("+", p, acc, 64)
        t = self.tmp(p)
        self.write_reg(lo, cast("low", t, 32))
        self.write_reg(hi, cast("low", BinOp(">>u", t, Const(32, 8), 64), 32))

    def _i_umull(self, i, ops, upd):
        self._long_mul(ops, False, False)

    def _i_smull(self, i, ops, upd):
        self._long_mul(ops, True, False)

    def _i_umlal(self, i, ops, upd):
        self._long_mul(ops, False, True)

    def _i_smlal(self, i, ops, upd):
        self._long_mul(ops, True, True)

    def _i_smmul(self, i, ops, upd):
        p = BinOp("*", cast("sext", self.operand(ops[1]), 64), cast("sext", self.operand(ops[2]), 64), 64)
        self.write_reg(self.reg_name(ops[0].reg), cast("low", BinOp(">>u", p, Const(32, 8), 64), 32))

    def _i_sdiv(self, i, ops, upd):
        d, a, b = self._two(ops)
        self.write_reg(d, BinOp("/s", a, b, 32))

    def _i_udiv(self, i, ops, upd):
        d, a, b = self._two(ops)
        self.write_reg(d, BinOp("/u", a, b, 32))

    def _i_clz(self, i, ops, upd):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("clz", (self.operand(ops[1]),), 32))

    def _i_rev(self, i, ops, upd):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("bswap", (self.operand(ops[1]),), 32))

    def _i_rev16(self, i, ops, upd):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("rev16", (self.operand(ops[1]),), 32))

    def _extend(self, ops, size, signed, add=False):
        """uxtb/sxth/... (optionally rotated), and the accumulating uxtab/sxtah forms."""
        src = self.operand(ops[2] if add else ops[1])      # operand() applies the `ror #n`
        v = cast("sext" if signed else "zext", cast("low", src, size), 32)
        if add:
            v = BinOp("+", self.operand(ops[1]), v, 32)
        self.write_reg(self.reg_name(ops[0].reg), v)

    def _i_uxtb(self, i, ops, upd):
        self._extend(ops, 8, False)

    def _i_uxth(self, i, ops, upd):
        self._extend(ops, 16, False)

    def _i_sxtb(self, i, ops, upd):
        self._extend(ops, 8, True)

    def _i_sxth(self, i, ops, upd):
        self._extend(ops, 16, True)

    def _i_uxtab(self, i, ops, upd):
        self._extend(ops, 8, False, add=True)

    def _i_uxtah(self, i, ops, upd):
        self._extend(ops, 16, False, add=True)

    def _i_sxtab(self, i, ops, upd):
        self._extend(ops, 8, True, add=True)

    def _i_sxtah(self, i, ops, upd):
        self._extend(ops, 16, True, add=True)

    def _i_ubfx(self, i, ops, upd):
        src, lsb, width = self.operand(ops[1]), ops[2].imm, ops[3].imm
        v = BinOp("&", BinOp(">>u", src, Const(lsb, 8), 32), Const(mask(width), 32), 32)
        self.write_reg(self.reg_name(ops[0].reg), v)

    def _i_sbfx(self, i, ops, upd):
        src, lsb, width = self.operand(ops[1]), ops[2].imm, ops[3].imm
        v = cast("low", BinOp(">>u", src, Const(lsb, 8), 32), width) if width < 32 else src
        self.write_reg(self.reg_name(ops[0].reg), cast("sext", v, 32))

    def _i_bfc(self, i, ops, upd):
        d = self.reg_name(ops[0].reg)
        lsb, width = ops[1].imm, ops[2].imm
        self.write_reg(d, BinOp("&", self.read_reg(d), Const(~(mask(width) << lsb) & mask(32), 32), 32))

    def _i_bfi(self, i, ops, upd):
        d = self.reg_name(ops[0].reg)
        src, lsb, width = self.operand(ops[1]), ops[2].imm, ops[3].imm
        keep = Const(~(mask(width) << lsb) & mask(32), 32)
        new = BinOp("<<", BinOp("&", src, Const(mask(width), 32), 32), Const(lsb, 8), 32)
        self.write_reg(d, BinOp("|", BinOp("&", self.read_reg(d), keep, 32), new, 32))

    def _i_adr(self, i, ops, upd):
        # the immediate is an offset from the (word-aligned in Thumb) pc
        base = (self.pc_value() & ~3) if self.thumb else self.pc_value()
        self.write_reg(self.reg_name(ops[0].reg), Const((base + ops[1].imm) & mask(32), 32))

    def _i_mrs(self, i, ops, upd):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("mrs", (), 32))

    def _i_mrc(self, i, ops, upd):
        # coprocessor read; `mrc p15, 0, rX, c13, c0, 3` is the thread pointer (TPIDRURO)
        reg = next((o for o in ops if o.type == OP_REG), None)
        if reg is None:
            raise LiftError("mrc")
        self.write_reg(self.reg_name(reg.reg), Intrinsic("mrc", (), 32))

    # --------------------------------------------------------- loads/stores
    _LOAD = {"ldr": (32, False), "ldrb": (8, False), "ldrh": (16, False), "ldrsb": (8, True), "ldrsh": (16, True),
             "ldrex": (32, False), "ldrexb": (8, False), "ldrexh": (16, False), "ldrt": (32, False),
             "ldrbt": (8, False)}
    _STORE = {"str": 32, "strb": 8, "strh": 16, "strt": 32, "strbt": 8}

    def _strex(self, i, ops, size):
        """`strex rd, rt, [rn]`: the store, and rd = 0 (the exclusive store is taken to succeed)."""
        status = self.reg_name(ops[0].reg)
        val = self.read_reg(self.reg_name(ops[1].reg))
        addr = self.address(next(o for o in ops if o.type == OP_MEM))
        self.emit(Store(i.addr, addr, val if size == 32 else cast("low", val, size)))
        self.write_reg(status, Const(0, 32))

    def _i_strex(self, i, ops, upd):
        self._strex(i, ops, 32)

    def _i_strexb(self, i, ops, upd):
        self._strex(i, ops, 8)

    def _i_strexh(self, i, ops, upd):
        self._strex(i, ops, 16)

    def _ldst(self, i, name, ops):
        if name in self._LOAD:
            size, signed = self._LOAD[name]
            dst = self.reg_name(ops[0].reg)
            mem = next(o for o in ops if o.type == OP_MEM)
            if self.reg_name(mem.mem.base) == "pc" and not mem.mem.index and size == 32:
                # literal pool: the constant is part of the (immutable) code
                pc = (self.pc_value() & ~3) if self.thumb else self.pc_value()
                lit = self.an.bin.read_int((pc + mem.mem.disp) & mask(32), 4)
                if lit is not None and dst != "pc":
                    self.write_reg(dst, Const(lit, 32))
                    return
            addr, wb = self._mem_access(ops)
            v = Load(addr, size)
            v = v if size == 32 else cast("sext" if signed else "zext", v, 32)
            if dst == "pc":
                if i.kind != "ret":
                    raise LiftError("load into pc")
                if wb is not None:                       # `ldr pc, [sp], #4`: pop {pc}
                    self.write_reg(*wb)
                self.emit(Return(i.addr))
                return
            if wb is not None and wb[0] == dst:
                wb = None
            self.write_reg(dst, v)
            if wb is not None:
                self.write_reg(*wb)
            return
        size = self._STORE[name]
        val = self.read_reg(self.reg_name(ops[0].reg))
        addr, wb = self._mem_access(ops)
        self.emit(Store(i.addr, addr, val if size == 32 else cast("low", val, size)))
        if wb is not None:
            self.write_reg(*wb)

    def _i_ldrd(self, i, ops, upd):
        r1, r2 = self.reg_name(ops[0].reg), self.reg_name(ops[1].reg)
        addr, wb = self._mem_access(ops)
        a = self.tmp(addr)
        v1 = self.tmp(Load(a, 32))
        v2 = self.tmp(Load(BinOp("+", a, Const(4, 32), 32), 32))
        self.write_reg(r1, v1)
        self.write_reg(r2, v2)
        if wb is not None:
            self.write_reg(*wb)

    def _i_strd(self, i, ops, upd):
        r1, r2 = self.reg_name(ops[0].reg), self.reg_name(ops[1].reg)
        addr, wb = self._mem_access(ops)
        a = self.tmp(addr)
        self.emit(Store(i.addr, a, self.read_reg(r1)))
        self.emit(Store(i.addr, BinOp("+", a, Const(4, 32), 32), self.read_reg(r2)))
        if wb is not None:
            self.write_reg(*wb)

    def _multi(self, base: str, regs: list[str], load: bool, mode: str, writeback: bool):
        """ldm/stm: `mode` is ia/ib/da/db; registers occupy ascending addresses, lowest first."""
        n = len(regs)
        b = self.tmp(self.read_reg(base))
        start = {"ia": 0, "ib": 4, "da": -4 * n + 4, "db": -4 * n}[mode]
        ret = False
        for k, r in enumerate(regs):
            a = BinOp("+", b, Const((start + 4 * k) & mask(32), 32), 32)
            if load:
                if r == "pc":
                    ret = True
                    continue
                self.write_reg(r, Load(a, 32))
            else:
                self.emit(Store(self.insn.addr, a, self.read_reg(r)))
        if writeback and not (load and base in regs):
            delta = 4 * n
            self.write_reg(base, BinOp("+" if mode in ("ia", "ib") else "-", b, Const(delta, 32), 32))
        if ret:
            self.emit(Return(self.insn.addr))

    def _reglist(self, ops) -> list[str]:
        return [self.reg_name(o.reg) for o in ops if o.type == OP_REG]

    def _i_push(self, i, ops, upd):
        self._multi("sp", self._reglist(ops), False, "db", True)

    def _i_pop(self, i, ops, upd):
        self._multi("sp", self._reglist(ops), True, "ia", True)

    def _ldm_stm(self, i, ops, load, mode):
        base = self.reg_name(ops[0].reg)
        self._multi(base, self._reglist(ops[1:]), load, mode, getattr(i.cs, "writeback", False))

    def _i_ldm(self, i, ops, upd):
        self._ldm_stm(i, ops, True, "ia")

    _i_ldmia = _i_ldmfd = _i_ldm

    def _i_ldmib(self, i, ops, upd):
        self._ldm_stm(i, ops, True, "ib")

    def _i_ldmda(self, i, ops, upd):
        self._ldm_stm(i, ops, True, "da")

    def _i_ldmdb(self, i, ops, upd):
        self._ldm_stm(i, ops, True, "db")

    def _i_stm(self, i, ops, upd):
        self._ldm_stm(i, ops, False, "ia")

    _i_stmia = _i_stmea = _i_stm

    def _i_stmib(self, i, ops, upd):
        self._ldm_stm(i, ops, False, "ib")

    def _i_stmda(self, i, ops, upd):
        self._ldm_stm(i, ops, False, "da")

    def _i_stmdb(self, i, ops, upd):
        self._ldm_stm(i, ops, False, "db")

    _i_stmfd = _i_stmdb

    # --------------------------------------------------------- control flow
    def _i_bl(self, i, ops, upd):
        if i.target is not None and self._aeabi_div(self.an.name(i.target) or ""):
            return
        target = Const(i.target, 32) if i.target is not None else self.operand(ops[0])
        self.emit(CallStmt(i.addr, Call(target, (), 32), noreturn=self._noreturn(i), name=self.an.call_name(i)))

    def _i_blx(self, i, ops, upd):
        if i.target is not None:
            self._i_bl(i, ops, upd)
            return
        self.emit(CallStmt(i.addr, Call(self.operand(ops[0]), (), 32), name=self.an.call_name(i)))

    def _i_bx(self, i, ops, upd):
        if self.reg_name(ops[0].reg) == "lr":
            self.emit(Return(i.addr))
        else:
            raise LiftError("bx to a register outside a block end")

    def _i_b(self, i, ops, upd):
        self.emit(Jump(i.addr, i.target))

    def _aeabi_div(self, name: str) -> bool:
        """libgcc's EABI division helpers (cores without a divide instruction) are plain `/` and `%`:
        `__aeabi_idivmod` returns the quotient in r0 and the remainder in r1, the 64-bit
        `__aeabi_ldivmod` the quotient in r0:r1 and the remainder in r2:r3."""
        name = name.lstrip("_")
        if name not in ("aeabi_idiv", "aeabi_uidiv", "aeabi_idivmod", "aeabi_uidivmod",
                        "aeabi_ldivmod", "aeabi_uldivmod"):
            return False
        sign = "u" if name.startswith("aeabi_u") else "s"
        if name.startswith(("aeabi_ldiv", "aeabi_uldiv")):
            def pair(lo, hi):
                return BinOp("|", BinOp("<<", cast("zext", Reg(hi, 32), 64), Const(32, 8), 64),
                             cast("zext", Reg(lo, 32), 64), 64)
            a, b = self.tmp(pair("r0", "r1")), self.tmp(pair("r2", "r3"))
            q, r = self.tmp(BinOp("/" + sign, a, b, 64)), self.tmp(BinOp("%" + sign, a, b, 64))
            for v, lo, hi in ((q, "r0", "r1"), (r, "r2", "r3")):
                self.write_reg(lo, cast("low", v, 32))
                self.write_reg(hi, cast("low", BinOp(">>u", v, Const(32, 8), 64), 32))
            return True
        a, b = self.tmp(Reg("r0", 32)), self.tmp(Reg("r1", 32))
        self.write_reg("r0", BinOp("/" + sign, a, b, 32))
        if name.endswith("mod"):
            self.write_reg("r1", BinOp("%" + sign, a, b, 32))
        return True

    def _noreturn(self, i: Insn) -> bool:
        if i.target is not None:
            f = self.an.functions.get(i.target)
            if f is not None:
                return f.noreturn
            return (self.an.name(i.target) or "") in NORETURN
        return (self.an.call_name(i) or "") in NORETURN

    def lift_jmp(self, i: Insn, func: "Function") -> list[Stmt]:
        """`b label` (jump or tail call) or `bx rN` / `mov pc, rN` at the end of a block."""
        self.out = []
        self.insn = i
        if i.target is not None:
            if i.target in func.blocks:
                self.emit(Jump(i.addr, i.target))
            else:
                self.emit(CallStmt(i.addr, Call(Const(i.target, 32), (), 32), tail=True, name=self.an.name(i.target)))
                self.emit(Return(i.addr))
            return self.out
        ops = i.cs.operands
        self.thumb = i.thumb
        m = i.mnemonic.split(".")[0]
        table = func.jump_tables.get(i.addr)
        try:
            if m.startswith(("tbb", "tbh")):
                mem = ops[0].mem
                idx = self.read_reg(i.cs.reg_name(mem.index))
                scale = 1 if m.startswith("tbb") else 2
                expr: Expr = Load(BinOp("+", Const(i.addr + 4, 32), BinOp("*", idx, Const(scale, 32), 32), 32),
                                  8 * scale)
            elif m.startswith("add") and len(ops) == 3:           # `add pc, pc, rX, lsl #2`
                expr = BinOp("+", Const(self.pc_value(), 32), self.operand(ops[2]), 32)
            elif m.startswith("mov") and ops and ops[-1].type == OP_REG:
                expr = self.operand(ops[-1])
            else:
                expr = self.operand(ops[-1]) if ops and ops[-1].type == OP_REG else Load(self.address(ops[-1]), 32)
            cnd = self.tmp(self.cond()) if i.cond else None
        except (LiftError, IndexError, StopIteration, KeyError):
            return [self.unknown(i)]
        if table:
            seen = list(dict.fromkeys(t for t in table if t in func.blocks))
            jump = IndirectJump(i.addr, expr, seen, list(table))
        else:
            jump = IndirectJump(i.addr, expr, [])
        if cnd is not None:
            # `addls pc, pc, ...`: the dispatch is a block of its own, the default falls through
            self.extra_blocks[i.addr + 1] = ([jump], list(jump.targets))
            self.emit(Branch(i.addr, cnd, i.addr + 1, i.end))
        else:
            self.emit(jump)
        return self.out


__all__ = ["ArmLifter"]

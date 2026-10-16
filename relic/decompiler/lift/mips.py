"""MIPS32 (o32) lifter.

Registers are the 32-bit `zero`, `at`, `v0`-`v1`, `a0`-`a3`, `t0`-`t9`,
`s0`-`s7`, `fp` (= `s8`), `sp`, `ra`, and `hi` / `lo` for multiply and
divide results. `$zero` reads as 0 and ignores writes.

`$gp` is the module's constant `_gp` (GOT + 0x7ff0): it reads as that
constant and every write to it -- the PIC prologue that rebuilds it from
`$t9`, the reload after a call, the "cprestore" spill -- is dropped, so
`lw $t9, -0x7fc0($gp)` becomes a load from a constant GOT slot.

Every branch, jump, call and return has a delay slot: the next instruction
runs before control moves. `lift_delayed` lifts the pair: the branch
condition (or call target) is computed first into a temporary, then the
delay-slot instruction, then the transfer -- so `bnez $v0, L; move $v0, $0`
tests the old `$v0`, and arguments set up in the slot of a `jalr` reach the
call. Branch-likely forms (`beql`, ...) annul the slot when not taken: its
writes are predicated on the condition (`x = cond ? new : x`).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...analysis.functions import NORETURN
from ...disasm import Insn
from ..ir import (Assign, BinOp, Branch, Call, CallStmt, Const, Effect, Expr, IndirectJump, Intrinsic, Ite, Jump,
                  Load, Reg, Return, Stmt, Store, UnOp, Unknown, mask)
from .x86 import LiftError, cast

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function

OP_REG, OP_IMM, OP_MEM = 1, 2, 3
HI, LO = Reg("hi", 32), Reg("lo", 32)

_ALIAS = {"s8": "fp", "30": "fp", "29": "sp", "28": "gp", "31": "ra", "25": "t9", "0": "zero"}
_GPR = ({"at", "v0", "v1", "a0", "a1", "a2", "a3", "fp", "sp", "ra"} | {f"t{k}" for k in range(10)}
        | {f"s{k}" for k in range(8)} | {"k0", "k1", "hi", "lo"})

_NOPS = {"nop", "ssnop", "ehb", "sync", "pause", "synci", "pref", "cache",
         # trap if (divide by zero, overflow checks gcc inserts after `div`)
         "teq", "tne", "tge", "tgeu", "tlt", "tltu", "teqi", "tnei", "tgei", "tgeiu", "tlti", "tltiu"}

# conditional branches: mnemonic -> (comparison, compares with zero)
_BRANCH = {"beq": "==", "bne": "!=", "beqz": "==", "bnez": "!=",
           "blez": "<=s", "bgtz": ">s", "bltz": "<s", "bgez": ">=s"}


def _likely(m: str) -> bool:
    """A branch-likely (`beql`, `bnezl`, ...: MIPS II-V): its delay slot is annulled when the
    branch is not taken."""
    return m.endswith("l") and m[:-1] in _BRANCH


def _predicated(stmts: list[Stmt], cond: Expr) -> list[Stmt]:
    """A branch-likely's delay slot: its effects happen only when `cond` holds. A register write
    keeps the old value otherwise, a store writes back what was there; a call or another side
    effect in the slot is beyond this."""
    out = []
    for s in stmts:
        if isinstance(s, Assign):
            out.append(Assign(s.addr, s.dst, Ite(cond, s.src, s.dst, s.dst.bits)))
        elif isinstance(s, Store):
            out.append(Store(s.addr, s.dst, Ite(cond, s.src, Load(s.dst, s.src.bits), s.src.bits)))
        else:
            raise LiftError("branch likely with a side effect in its delay slot")
    return out


def _cmp(op: str, a: Expr, b: Expr) -> Expr:
    if op == ">s":
        return BinOp("<s", b, a, 1)
    if op == ">=s":
        return BinOp("<=s", b, a, 1)
    return BinOp(op, a, b, 1)


class MipsLifter:
    bits = 32

    def __init__(self, an: "Analysis"):
        self.an = an
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0
        self.gp = an.bin.mips_gp

    # ----------------------------------------------------------- helpers
    def emit(self, s: Stmt):
        self.out.append(s)

    def assign(self, dst: Reg, src: Expr):
        self.emit(Assign(self.insn.addr, dst, src))

    def tmp(self, e: Expr) -> Reg:
        self._tmp += 1
        t = Reg(f"tmp{self._tmp}", e.bits)
        self.assign(t, e)
        return t

    @staticmethod
    def canon(name: str) -> str:
        name = name.lstrip("$") if name else name
        return _ALIAS.get(name, name) if name else name

    def reg_name(self, rid) -> str:
        return self.canon(self.insn.cs.reg_name(rid))

    def read_reg(self, name: str) -> Expr:
        name = self.canon(name)
        if name == "zero":
            return Const(0, 32)
        if name == "gp":
            if self.gp is None:
                raise LiftError("$gp without a GOT")
            return Const(self.gp, 32)
        if name in _GPR:
            return Reg(name, 32)
        if name[:1] == "f" and name[1:].isdigit():                    # FPU
            return Reg(name, 32)
        raise LiftError(f"register {name}")

    def write_reg(self, name: str, v: Expr):
        name = self.canon(name)
        if name in ("zero", "gp"):
            return
        r = self.read_reg(name)
        if v.bits != r.bits:
            v = cast("low", v, r.bits) if v.bits > r.bits else cast("zext", v, r.bits)
        self.assign(r, v)

    def operand(self, op) -> Expr:
        if op.type == OP_REG:
            return self.read_reg(self.insn.cs.reg_name(op.reg))
        if op.type == OP_IMM:
            return Const(op.imm & mask(32), 32)
        raise LiftError("operand")

    def address(self, op) -> Expr:
        base = self.read_reg(self.insn.cs.reg_name(op.mem.base))
        d = op.mem.disp
        if isinstance(base, Const):
            return Const((base.value + d) & mask(32), 32)
        if not d:
            return base
        return BinOp("+", base, Const(d, 32), 32) if d > 0 else BinOp("-", base, Const(-d, 32), 32)

    def unknown(self, i: Insn) -> Unknown:
        def regs(names):
            out = {}
            for n in names:
                n = self.canon(n)
                if n in _GPR:
                    out[n] = Reg(n, 32)
            return list(out.items())
        return Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip(), regs(i.regs_read), regs(i.regs_write))

    # ----------------------------------------------------------- entry points
    def lift_insn(self, i: Insn, func: "Function | None" = None) -> list[Stmt]:
        self.out = []
        self.insn = i
        try:
            self._dispatch(i, i.mnemonic, i.cs.operands)
        except (LiftError, KeyError, StopIteration, AttributeError, IndexError, ValueError):
            self.out = [self.unknown(i)]
        return self.out

    def lift_delayed(self, i: Insn, slot: Insn, func: "Function", last: bool) -> list[Stmt]:
        """A branch / call / return and its delay-slot instruction, in execution order."""
        ctl = self.lift_jmp(i, func) if last and i.kind == "jmp" else self.lift_insn(i, func)
        k = next((n for n, s in enumerate(ctl) if not isinstance(s, Assign)), len(ctl))
        prefix, transfer = ctl[:k], ctl[k:]
        if isinstance(slot, Insn) and slot.mnemonic != "nop":
            body = self.lift_insn(slot, func)
            br = next((s for s in transfer if isinstance(s, Branch)), None)
            if _likely(i.mnemonic) and br is not None:
                body = _predicated(body, br.cond)
            prefix += body
        return prefix + transfer

    def _dispatch(self, i, m, ops):
        h = getattr(self, "_i_" + m.replace(".", "_"), None)
        if h is not None:
            h(i, ops)
        elif m in self._LOAD or m in self._STORE:
            self._ldst(i, m, ops)
        elif m in _BRANCH:
            self._branch(i, m, ops)
        elif m in _NOPS:
            pass
        elif m in ("syscall", "break", "sdbbp", "wait", "eret", "deret"):
            self._effect(i, m)
        elif _likely(m):
            self._branch(i, m[:-1], ops)        # its delay slot runs only when it is taken (lift_delayed)
        elif ops and ops[0].type == OP_REG and self.reg_name(ops[0].reg) in _GPR and i.kind == "normal" and \
                all(o.type in (OP_REG, OP_IMM) for o in ops):
            # FPU moves and the rest (`mfc1`, `cfc1`, `rdhwr`, ...): an opaque value of the sources
            srcs = tuple(self.operand(o) for o in ops[1:] if o.type == OP_IMM or
                         self.reg_name(o.reg) in _GPR or self.reg_name(o.reg)[:1] == "f")
            self.write_reg(self.reg_name(ops[0].reg), Intrinsic(m, srcs, 32))
        else:
            self.out = [self.unknown(i)]

    def _effect(self, i, name):
        if name == "syscall":
            uses = [(r, Reg(r, 32)) for r in ("v0", "a0", "a1", "a2", "a3")]
            self.emit(Effect(i.addr, "syscall", (), uses, [("v0", Reg("v0", 32)), ("a3", Reg("a3", 32))]))
        else:
            self.emit(Effect(i.addr, name, ()))

    # ------------------------------------------------------- data processing
    def _three(self, ops, op: str):
        self.write_reg(self.reg_name(ops[0].reg), BinOp(op, self.operand(ops[1]), self.operand(ops[2]), 32))

    def _i_addu(self, i, ops):
        a, b = self.operand(ops[1]), self.operand(ops[2])
        if isinstance(b, Const) and b.value >> 31:              # `addiu sp, sp, -8`: sp - 8
            e: Expr = BinOp("-", a, Const(-b.value & mask(32), 32), 32)
        elif isinstance(a, Const) and a.value == 0:              # `addiu v0, $zero, 5`: li
            e = b
        else:
            e = BinOp("+", a, b, 32)
        self.write_reg(self.reg_name(ops[0].reg), e)

    _i_add = _i_addiu = _i_addi = _i_addu

    def _i_subu(self, i, ops):
        self._three(ops, "-")

    _i_sub = _i_subu

    def _i_and(self, i, ops):
        self._three(ops, "&")

    _i_andi = _i_and

    def _i_or(self, i, ops):
        a = self.operand(ops[1])
        if isinstance(a, Const) and a.value == 0:                # `ori v0, $zero, 5` / `or v0, $zero, a0`
            self.write_reg(self.reg_name(ops[0].reg), self.operand(ops[2]))
            return
        self._three(ops, "|")

    _i_ori = _i_or

    def _i_xor(self, i, ops):
        self._three(ops, "^")

    _i_xori = _i_xor

    def _i_nor(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg),
                       UnOp("~", BinOp("|", self.operand(ops[1]), self.operand(ops[2]), 32), 32))

    def _i_not(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), UnOp("~", self.operand(ops[1]), 32))

    def _i_negu(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), BinOp("-", Const(0, 32), self.operand(ops[1]), 32))

    _i_neg = _i_negu

    def _i_move(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.operand(ops[1]))

    def _i_li(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Const(ops[1].imm & mask(32), 32))

    def _i_lui(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Const((ops[1].imm << 16) & mask(32), 32))

    def _shift(self, ops, op: str, variable: bool):
        v = self.operand(ops[1])
        n = BinOp("&", self.operand(ops[2]), Const(31, 32), 32) if variable else Const(ops[2].imm & 31, 8)
        self.write_reg(self.reg_name(ops[0].reg), BinOp(op, v, n, 32))

    def _i_sll(self, i, ops):
        self._shift(ops, "<<", False)

    def _i_srl(self, i, ops):
        self._shift(ops, ">>u", False)

    def _i_sra(self, i, ops):
        self._shift(ops, ">>s", False)

    def _i_rotr(self, i, ops):
        self._shift(ops, "ror", False)

    def _i_sllv(self, i, ops):
        self._shift(ops, "<<", True)

    def _i_srlv(self, i, ops):
        self._shift(ops, ">>u", True)

    def _i_srav(self, i, ops):
        self._shift(ops, ">>s", True)

    def _i_rotrv(self, i, ops):
        self._shift(ops, "ror", True)

    def _set(self, ops, op: str):
        b = self.operand(ops[2])
        if isinstance(b, Const) and ops[2].type == OP_IMM:
            b = Const(ops[2].imm & mask(32), 32)            # slti / sltiu: sign-extended immediate
        self.write_reg(self.reg_name(ops[0].reg), cast("zext", BinOp(op, self.operand(ops[1]), b, 1), 32))

    def _i_slt(self, i, ops):
        self._set(ops, "<s")

    _i_slti = _i_slt

    def _i_sltu(self, i, ops):
        self._set(ops, "<u")

    _i_sltiu = _i_sltu

    def _i_movn(self, i, ops):
        d = self.reg_name(ops[0].reg)
        c = BinOp("!=", self.operand(ops[2]), Const(0, 32), 1)
        self.write_reg(d, Ite(c, self.operand(ops[1]), self.read_reg(d), 32))

    def _i_movz(self, i, ops):
        d = self.reg_name(ops[0].reg)
        c = BinOp("==", self.operand(ops[2]), Const(0, 32), 1)
        self.write_reg(d, Ite(c, self.operand(ops[1]), self.read_reg(d), 32))

    def _i_seb(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), cast("sext", cast("low", self.operand(ops[1]), 8), 32))

    def _i_seh(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), cast("sext", cast("low", self.operand(ops[1]), 16), 32))

    def _i_ext(self, i, ops):
        pos, size = ops[2].imm, ops[3].imm
        v = BinOp(">>u", self.operand(ops[1]), Const(pos, 8), 32) if pos else self.operand(ops[1])
        self.write_reg(self.reg_name(ops[0].reg), BinOp("&", v, Const(mask(size), 32), 32))

    def _i_ins(self, i, ops):
        d = self.reg_name(ops[0].reg)
        pos, size = ops[2].imm, ops[3].imm
        field = mask(size) << pos
        keep = BinOp("&", self.read_reg(d), Const(~field & mask(32), 32), 32)
        put = BinOp("&", BinOp("<<", self.operand(ops[1]), Const(pos, 8), 32), Const(field, 32), 32)
        self.write_reg(d, BinOp("|", keep, put, 32))

    def _i_clz(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("clz", (self.operand(ops[1]),), 32))

    def _i_wsbh(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("wsbh", (self.operand(ops[1]),), 32))

    # ------------------------------------------------------- multiply / divide
    def _i_mul(self, i, ops):
        self._three(ops, "*")

    def _mult(self, ops, signed: bool, acc: str = ""):
        kind = "sext" if signed else "zext"
        a, b = ops[-2:]
        p = BinOp("*", cast(kind, self.operand(a), 64), cast(kind, self.operand(b), 64), 64)
        if acc:
            cur = BinOp("|", BinOp("<<", cast("zext", HI, 64), Const(32, 8), 64), cast("zext", LO, 64), 64)
            p = BinOp(acc, cur, p, 64)
        p = self.tmp(p)
        self.assign(LO, cast("low", p, 32))
        self.assign(HI, cast("low", BinOp(">>u", p, Const(32, 8), 64), 32))

    def _i_mult(self, i, ops):
        self._mult(ops, True)

    def _i_multu(self, i, ops):
        self._mult(ops, False)

    def _i_madd(self, i, ops):
        self._mult(ops, True, "+")

    def _i_maddu(self, i, ops):
        self._mult(ops, False, "+")

    def _i_msub(self, i, ops):
        self._mult(ops, True, "-")

    def _i_msubu(self, i, ops):
        self._mult(ops, False, "-")

    def _div(self, ops, sign: str):
        a, b = (self.tmp(self.operand(o)) for o in ops[-2:])
        self.assign(LO, BinOp("/" + sign, a, b, 32))
        self.assign(HI, BinOp("%" + sign, a, b, 32))

    def _i_div(self, i, ops):
        self._div(ops, "s")

    def _i_divu(self, i, ops):
        self._div(ops, "u")

    def _i_mfhi(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), HI)

    def _i_mflo(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), LO)

    def _i_mthi(self, i, ops):
        self.assign(HI, self.operand(ops[0]))

    def _i_mtlo(self, i, ops):
        self.assign(LO, self.operand(ops[0]))

    # --------------------------------------------------------- loads/stores
    _LOAD = {"lw": (32, False), "lb": (8, True), "lbu": (8, False), "lh": (16, True), "lhu": (16, False),
             "ll": (32, False)}
    _STORE = {"sw": 32, "sb": 8, "sh": 16}

    def _ldst(self, i, m, ops):
        mem = next(o for o in ops if o.type == OP_MEM)
        dst = self.reg_name(ops[0].reg)
        if m in self._LOAD:
            size, signed = self._LOAD[m]
            addr = self.address(mem)
            lo, hi = self.an.bin.mips_local_got
            if m == "lw" and isinstance(addr, Const) and lo <= addr.value < hi:
                # a local GOT entry (`lw $a0, %got(page)($gp)`): a link-time constant
                v = self.an.bin.read_int(addr.value, 4)
                if v is not None:
                    self.write_reg(dst, Const(v, 32))
                    return
            v: Expr = Load(addr, size)
            if size < 32:
                v = cast("sext" if signed else "zext", v, 32)
            self.write_reg(dst, v)
            return
        if dst == "gp" and self.reg_name(mem.mem.base) in ("sp", "fp"):
            return                              # `sw $gp, 16($sp)`: the cprestore slot
        size = self._STORE[m]
        val = self.read_reg(dst)
        self.emit(Store(i.addr, self.address(mem), val if size == 32 else cast("low", val, size)))

    def _i_sc(self, i, ops):
        """`sc rt, off(base)`: the store, and rt = 1 (the conditional store is taken to succeed)."""
        mem = next(o for o in ops if o.type == OP_MEM)
        r = self.reg_name(ops[0].reg)
        self.emit(Store(i.addr, self.address(mem), self.read_reg(r)))
        self.write_reg(r, Const(1, 32))

    def _fpu_ldst(self, i, ops, size: int, load: bool):
        mem = next(o for o in ops if o.type == OP_MEM)
        r = self.reg_name(ops[0].reg)
        if load:
            self.assign(Reg(r, size), Load(self.address(mem), size))
        else:
            self.emit(Store(i.addr, self.address(mem), Reg(r, size)))

    def _i_lwc1(self, i, ops):
        self._fpu_ldst(i, ops, 32, True)

    def _i_swc1(self, i, ops):
        self._fpu_ldst(i, ops, 32, False)

    def _i_ldc1(self, i, ops):
        self._fpu_ldst(i, ops, 64, True)

    def _i_sdc1(self, i, ops):
        self._fpu_ldst(i, ops, 64, False)

    # --------------------------------------------------------- control flow
    def _branch(self, i, m, ops):
        a = self.operand(ops[0])
        b = Const(0, 32) if m.endswith("z") or len(ops) == 2 else self.operand(ops[1])
        test = self.tmp(_cmp(_BRANCH[m], a, b))
        self.emit(Branch(i.addr, test, i.target, i.end + 4))      # falls through past the delay slot

    def _noreturn(self, i: Insn) -> bool:
        if i.target is not None:
            f = self.an.functions.get(i.target)
            if f is not None:
                return f.noreturn
            return (self.an.name(i.target) or "") in NORETURN
        return (self.an.call_name(i) or "") in NORETURN

    def _call(self, i, target: Expr):
        if not isinstance(target, Const):
            target = self.tmp(target)
        self.emit(CallStmt(i.addr, Call(target, (), 32), noreturn=self._noreturn(i), name=self.an.call_name(i)))

    def _i_jal(self, i, ops):
        if i.target is None:
            raise LiftError("call without a target")
        self._call(i, Const(i.target, 32))

    def _i_bal(self, i, ops):
        if i.kind == "normal":                      # `bal .+8`: only reads pc into $ra
            self.write_reg("ra", Const(i.addr + 8, 32))
            return
        self._i_jal(i, ops)

    def _i_jalr(self, i, ops):
        self._call(i, self.operand(ops[-1]))

    _i_jalr_hb = _i_jalr

    def _i_jr(self, i, ops):
        if self.reg_name(ops[0].reg) == "ra":
            self.emit(Return(i.addr))
        else:
            raise LiftError("jr to a register outside a block end")

    _i_jr_hb = _i_jr

    def _i_b(self, i, ops):
        self.emit(Jump(i.addr, i.target))

    _i_j = _i_b

    def lift_jmp(self, i: Insn, func: "Function") -> list[Stmt]:
        """`b` / `j` (a jump or tail call) or `jr rN` (a switch or a tail call through `$t9`)."""
        self.out = []
        self.insn = i
        if i.target is not None:
            if i.target in func.blocks:
                self.emit(Jump(i.addr, i.target))
            else:
                self.emit(CallStmt(i.addr, Call(Const(i.target, 32), (), 32), tail=True, name=self.an.name(i.target)))
                self.emit(Return(i.addr))
            return self.out
        try:
            r = self.reg_name(i.cs.operands[0].reg)
            if r == "ra":
                self.emit(Return(i.addr))
                return self.out
            target = self.tmp(self.read_reg(r))
        except (LiftError, IndexError, AttributeError):
            return [self.unknown(i)]
        table = func.jump_tables.get(i.addr)
        if table:
            seen = list(dict.fromkeys(t for t in table if t in func.blocks))
            self.emit(IndirectJump(i.addr, target, seen, list(table)))
        elif r == "t9":
            self.emit(CallStmt(i.addr, Call(target, (), 32), tail=True, name=self.an.call_name(i)))
            self.emit(Return(i.addr))
        else:
            self.emit(IndirectJump(i.addr, target, []))
        return self.out


__all__ = ["MipsLifter"]

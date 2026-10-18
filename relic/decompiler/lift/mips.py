"""MIPS32 (o32) and MIPS64 (n64) lifter.

Registers are `zero`, `at`, `v0`-`v1`, `a0`-`a3`, `t0`-`t9`, `s0`-`s7`,
`fp` (= `s8`), `sp`, `ra`, and `hi` / `lo` for multiply and divide results,
32 or 64 bits wide. `$zero` reads as 0 and ignores writes. n64 names
registers 8-11 `a4`-`a7` (arguments) and 12-15 `t0`-`t3`; capstone prints the
o32 names, which `canon` renames. On MIPS64 the 32-bit operations (`addu`,
`sll`, `lw`, `mult`, ...) sign-extend their result to the register; the
`d...` forms (`daddu`, `dsll`, `ld`, ...) work on all 64 bits.

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
# o32 names capstone prints for registers 8-15 -> their n64 names
_N64 = {"t0": "a4", "t1": "a5", "t2": "a6", "t3": "a7", "t4": "t0", "t5": "t1", "t6": "t2", "t7": "t3",
        "12": "t0", "13": "t1", "14": "t2", "15": "t3", "8": "a4", "9": "a5", "10": "a6", "11": "a7"}

_ALIAS = {"s8": "fp", "30": "fp", "29": "sp", "28": "gp", "31": "ra", "25": "t9", "0": "zero"}
_GPR = ({"at", "v0", "v1", "a0", "a1", "a2", "a3", "fp", "sp", "ra"} | {f"t{k}" for k in range(10)}
        | {f"s{k}" for k in range(8)} | {"k0", "k1", "hi", "lo"} | {f"a{k}" for k in range(4, 8)})

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
    def __init__(self, an: "Analysis"):
        self.an = an
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0
        self.gp = an.bin.mips_gp
        self.bits = W = 64 if an.bin.bits == 64 else 32
        self.W = W
        self.n64 = W == 64
        self.HI, self.LO = Reg("hi", W), Reg("lo", W)

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
    def canon(name: str, n64: bool = False) -> str:
        name = name.lstrip("$") if name else name
        if not name:
            return name
        if n64 and name in _N64:
            return _N64[name]
        return _ALIAS.get(name, name)

    def reg_name(self, rid) -> str:
        return self.canon(self.insn.cs.reg_name(rid), self.n64)

    def read_reg(self, name: str, canon: bool = False) -> Expr:
        """A register by its canonical name (`reg_name`); `canon`: by capstone's name."""
        W = self.W
        name = self.canon(name, self.n64) if canon else name
        if name == "zero":
            return Const(0, W)
        if name == "gp":
            if self.gp is None:
                raise LiftError("$gp without a GOT")
            return Const(self.gp, W)
        if name in _GPR:
            return Reg(name, W)
        if name[:1] == "f" and name[1:].isdigit():                    # FPU
            return Reg(name, 32)
        raise LiftError(f"register {name}")

    def write_reg(self, name: str, v: Expr, canon: bool = False):
        name = self.canon(name, self.n64) if canon else name
        if name in ("zero", "gp"):
            return
        r = self.read_reg(name)
        if v.bits != r.bits:
            v = cast("low", v, r.bits) if v.bits > r.bits else cast("sext", v, r.bits)
        self.assign(r, v)

    def operand(self, op) -> Expr:
        if op.type == OP_REG:
            return self.read_reg(self.reg_name(op.reg))
        if op.type == OP_IMM:
            return Const(op.imm & mask(self.W), self.W)
        raise LiftError("operand")

    def address(self, op) -> Expr:
        W = self.W
        base = self.read_reg(self.reg_name(op.mem.base))
        d = op.mem.disp
        if isinstance(base, Const):
            return Const((base.value + d) & mask(W), W)
        if not d:
            return base
        return BinOp("+", base, Const(d, W), W) if d > 0 else BinOp("-", base, Const(-d, W), W)

    def unknown(self, i: Insn) -> Unknown:
        def regs(names):
            out = {}
            for n in names:
                n = self.canon(n, self.n64)
                if n in _GPR:
                    out[n] = Reg(n, self.W)
            return list(out.items())
        return Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip(), regs(i.regs_read), regs(i.regs_write))

    # 32-bit operations on MIPS64: on the low words, the result sign-extended
    def lo32(self, e: Expr) -> Expr:
        if e.bits == 32:
            return e
        return Const(e.value & mask(32), 32) if isinstance(e, Const) else cast("low", e, 32)

    def word(self, op: str, a: Expr, b: Expr) -> Expr:
        """`a op b` as a 32-bit operation (sign-extended into a MIPS64 register)."""
        if self.W == 32:
            return BinOp(op, a, b, 32)
        return cast("sext", BinOp(op, self.lo32(a), self.lo32(b), 32), 64)

    # ----------------------------------------------------------- entry points
    def entry_stmts(self, f: "Function") -> list[Stmt]:
        """PIC code finds `_gp` from `$t9`, which holds the function's address on entry (o32 builds
        it straight into `$gp`, whose writes are dropped; n64 leaf functions into another register)."""
        return [Assign(f.addr, Reg("t9", self.W), Const(f.addr, self.W))]

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
            self.write_reg(self.reg_name(ops[0].reg), Intrinsic(m, srcs, self.W))
        else:
            self.out = [self.unknown(i)]

    def _effect(self, i, name):
        if name == "syscall":
            W = self.W
            args = ("v0", "a0", "a1", "a2", "a3", "a4", "a5") if self.n64 else ("v0", "a0", "a1", "a2", "a3")
            uses = [(r, Reg(r, W)) for r in args]
            self.emit(Effect(i.addr, "syscall", (), uses, [("v0", Reg("v0", W)), ("a3", Reg("a3", W))]))
        else:
            self.emit(Effect(i.addr, name, ()))

    # ------------------------------------------------------- data processing
    def _three(self, ops, op: str):
        W = self.W
        self.write_reg(self.reg_name(ops[0].reg), BinOp(op, self.operand(ops[1]), self.operand(ops[2]), W))

    def _add(self, ops, wide: bool):
        a, b = self.operand(ops[1]), self.operand(ops[2])
        w = self.W if wide else 32
        if not wide:
            a, b = self.lo32(a), self.lo32(b)
        if isinstance(b, Const) and b.value >> (w - 1):          # `addiu sp, sp, -8`: sp - 8
            e: Expr = BinOp("-", a, Const(-b.value & mask(w), w), w)
        elif isinstance(a, Const) and a.value == 0:              # `addiu v0, $zero, 5`: li
            e = b
        elif isinstance(b, Const) and b.value == 0 and wide:     # `daddiu a0, a1, 0`: move
            e = a
        else:
            e = BinOp("+", a, b, w)
        self.write_reg(self.reg_name(ops[0].reg), e)

    def _i_addu(self, i, ops):
        self._add(ops, False)

    _i_add = _i_addiu = _i_addi = _i_addu

    def _i_daddu(self, i, ops):
        self._add(ops, True)

    _i_dadd = _i_daddiu = _i_daddi = _i_daddu

    def _i_subu(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.word("-", self.operand(ops[1]), self.operand(ops[2])))

    _i_sub = _i_subu

    def _i_dsubu(self, i, ops):
        self._three(ops, "-")

    _i_dsub = _i_dsubu

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
        W = self.W
        self.write_reg(self.reg_name(ops[0].reg),
                       UnOp("~", BinOp("|", self.operand(ops[1]), self.operand(ops[2]), W), W))

    def _i_not(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), UnOp("~", self.operand(ops[1]), self.W))

    def _i_negu(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.word("-", Const(0, 32), self.operand(ops[1])))

    _i_neg = _i_negu

    def _i_dnegu(self, i, ops):
        W = self.W
        self.write_reg(self.reg_name(ops[0].reg), BinOp("-", Const(0, W), self.operand(ops[1]), W))

    _i_dneg = _i_dnegu

    def _i_move(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.operand(ops[1]))

    def _i_li(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Const(ops[1].imm & mask(self.W), self.W))

    _i_dli = _i_li

    def _i_lui(self, i, ops):
        v = (ops[1].imm << 16) & mask(32)
        if self.W == 64 and v >> 31:                              # (sign-extended on MIPS64)
            v |= mask(64) ^ mask(32)
        self.write_reg(self.reg_name(ops[0].reg), Const(v, self.W))

    def _shift(self, ops, op: str, variable: bool, wide: bool = False, plus: int = 0):
        w = self.W if wide else 32
        v = self.operand(ops[1])
        if not wide:
            v = self.lo32(v)
        if variable:
            n: Expr = BinOp("&", self.lo32(self.operand(ops[2])) if not wide else self.operand(ops[2]),
                            Const(w - 1, w), w)
        else:
            n = Const((ops[2].imm + plus) & (w - 1), 8)
        e = BinOp(op, v, n, w)
        self.write_reg(self.reg_name(ops[0].reg), e)

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

    def _i_dsll(self, i, ops):
        self._shift(ops, "<<", False, True)

    def _i_dsrl(self, i, ops):
        self._shift(ops, ">>u", False, True)

    def _i_dsra(self, i, ops):
        self._shift(ops, ">>s", False, True)

    def _i_drotr(self, i, ops):
        self._shift(ops, "ror", False, True)

    def _i_dsll32(self, i, ops):
        self._shift(ops, "<<", False, True, 32)

    def _i_dsrl32(self, i, ops):
        self._shift(ops, ">>u", False, True, 32)

    def _i_dsra32(self, i, ops):
        self._shift(ops, ">>s", False, True, 32)

    def _i_drotr32(self, i, ops):
        self._shift(ops, "ror", False, True, 32)

    def _i_dsllv(self, i, ops):
        self._shift(ops, "<<", True, True)

    def _i_dsrlv(self, i, ops):
        self._shift(ops, ">>u", True, True)

    def _i_dsrav(self, i, ops):
        self._shift(ops, ">>s", True, True)

    def _i_drotrv(self, i, ops):
        self._shift(ops, "ror", True, True)

    def _set(self, ops, op: str):
        W = self.W
        b = self.operand(ops[2])
        if isinstance(b, Const) and ops[2].type == OP_IMM:
            b = Const(ops[2].imm & mask(W), W)              # slti / sltiu: sign-extended immediate
        self.write_reg(self.reg_name(ops[0].reg), cast("zext", BinOp(op, self.operand(ops[1]), b, 1), W))

    def _i_slt(self, i, ops):
        self._set(ops, "<s")

    _i_slti = _i_slt

    def _i_sltu(self, i, ops):
        self._set(ops, "<u")

    _i_sltiu = _i_sltu

    def _i_movn(self, i, ops):
        W = self.W
        d = self.reg_name(ops[0].reg)
        c = BinOp("!=", self.operand(ops[2]), Const(0, W), 1)
        self.write_reg(d, Ite(c, self.operand(ops[1]), self.read_reg(d), W))

    def _i_movz(self, i, ops):
        W = self.W
        d = self.reg_name(ops[0].reg)
        c = BinOp("==", self.operand(ops[2]), Const(0, W), 1)
        self.write_reg(d, Ite(c, self.operand(ops[1]), self.read_reg(d), W))

    def _i_seb(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), cast("sext", cast("low", self.operand(ops[1]), 8), self.W))

    def _i_seh(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), cast("sext", cast("low", self.operand(ops[1]), 16), self.W))

    def _extract(self, ops, pos: int, size: int, wide: bool):
        w = self.W if wide else 32
        v = self.operand(ops[1]) if wide else self.lo32(self.operand(ops[1]))
        if pos:
            v = BinOp(">>u", v, Const(pos, 8), w)
        e = BinOp("&", v, Const(mask(size), w), w) if size < w else v
        self.write_reg(self.reg_name(ops[0].reg), cast("zext", e, self.W) if size < 32 or wide else e)

    def _i_ext(self, i, ops):
        self._extract(ops, ops[2].imm, ops[3].imm, False)

    def _i_dext(self, i, ops):
        self._extract(ops, ops[2].imm, ops[3].imm, True)

    def _i_dextm(self, i, ops):              # (size 33-64; capstone gives it as is or minus 32)
        size = ops[3].imm if ops[3].imm > 32 else ops[3].imm + 32
        self._extract(ops, ops[2].imm, size, True)

    def _i_dextu(self, i, ops):              # (position 32-63)
        pos = ops[2].imm if ops[2].imm >= 32 else ops[2].imm + 32
        self._extract(ops, pos, ops[3].imm, True)

    def _insert(self, ops, pos: int, size: int, wide: bool):
        w = self.W if wide else 32
        d = self.reg_name(ops[0].reg)
        cur = self.read_reg(d)
        src = self.operand(ops[1])
        if not wide:
            cur, src = self.lo32(cur), self.lo32(src)
        field = mask(size) << pos
        keep = BinOp("&", cur, Const(~field & mask(w), w), w)
        put = BinOp("&", BinOp("<<", src, Const(pos, 8), w) if pos else src, Const(field, w), w)
        self.write_reg(d, BinOp("|", keep, put, w))

    def _i_ins(self, i, ops):
        self._insert(ops, ops[2].imm, ops[3].imm, False)

    def _i_dins(self, i, ops):
        self._insert(ops, ops[2].imm, ops[3].imm, True)

    def _i_dinsm(self, i, ops):
        size = ops[3].imm if ops[3].imm > 32 else ops[3].imm + 32
        self._insert(ops, ops[2].imm, size, True)

    def _i_dinsu(self, i, ops):
        pos = ops[2].imm if ops[2].imm >= 32 else ops[2].imm + 32
        self._insert(ops, pos, ops[3].imm, True)

    def _i_clz(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("clz", (self.lo32(self.operand(ops[1])),), 32))

    def _i_dclz(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("clzll", (self.operand(ops[1]),), 64))

    def _i_wsbh(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), Intrinsic("wsbh", (self.lo32(self.operand(ops[1])),), 32))

    # ------------------------------------------------------- multiply / divide
    def _i_mul(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.word("*", self.operand(ops[1]), self.operand(ops[2])))

    def _i_dmul(self, i, ops):
        self._three(ops, "*")

    def _hilo(self, lo: Expr, hi: Expr):
        """Write hi / lo (32-bit halves sign-extended on MIPS64)."""
        self.assign(self.LO, cast("sext", lo, self.W))
        self.assign(self.HI, cast("sext", hi, self.W))

    def _mult(self, ops, signed: bool, acc: str = ""):
        kind = "sext" if signed else "zext"
        a, b = ops[-2:]
        p = BinOp("*", cast(kind, self.lo32(self.operand(a)), 64), cast(kind, self.lo32(self.operand(b)), 64), 64)
        if acc:
            cur = BinOp("|", BinOp("<<", cast("zext", self.lo32(self.HI), 64), Const(32, 8), 64),
                        cast("zext", self.lo32(self.LO), 64), 64)
            p = BinOp(acc, cur, p, 64)
        p = self.tmp(p)
        self._hilo(cast("low", p, 32), cast("low", BinOp(">>u", p, Const(32, 8), 64), 32))

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

    def _dmult(self, ops, signed: bool):
        kind = "sext" if signed else "zext"
        a, b = ops[-2:]
        p = self.tmp(BinOp("*", cast(kind, self.operand(a), 128), cast(kind, self.operand(b), 128), 128))
        self.assign(self.LO, cast("low", p, 64))
        self.assign(self.HI, cast("low", BinOp(">>u", p, Const(64, 8), 128), 64))

    def _i_dmult(self, i, ops):
        self._dmult(ops, True)

    def _i_dmultu(self, i, ops):
        self._dmult(ops, False)

    def _div(self, ops, sign: str):
        a, b = (self.tmp(self.lo32(self.operand(o))) for o in ops[-2:])
        self._hilo(BinOp("/" + sign, a, b, 32), BinOp("%" + sign, a, b, 32))

    def _i_div(self, i, ops):
        if len(ops) == 3 and ops[0].type == OP_REG and self.reg_name(ops[0].reg) != "zero":
            # MIPS R6 / the `div rd, rs, rt` macro: the quotient in rd
            self.write_reg(self.reg_name(ops[0].reg), self.word("/s", self.operand(ops[1]), self.operand(ops[2])))
            return
        self._div(ops, "s")

    def _i_divu(self, i, ops):
        if len(ops) == 3 and ops[0].type == OP_REG and self.reg_name(ops[0].reg) != "zero":
            self.write_reg(self.reg_name(ops[0].reg), self.word("/u", self.operand(ops[1]), self.operand(ops[2])))
            return
        self._div(ops, "u")

    def _ddiv(self, ops, sign: str):
        W = self.W
        a, b = (self.tmp(self.operand(o)) for o in ops[-2:])
        self.assign(self.LO, BinOp("/" + sign, a, b, W))
        self.assign(self.HI, BinOp("%" + sign, a, b, W))

    def _i_ddiv(self, i, ops):
        self._ddiv(ops, "s")

    def _i_ddivu(self, i, ops):
        self._ddiv(ops, "u")

    def _i_mfhi(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.HI)

    def _i_mflo(self, i, ops):
        self.write_reg(self.reg_name(ops[0].reg), self.LO)

    def _i_mthi(self, i, ops):
        self.assign(self.HI, self.operand(ops[0]))

    def _i_mtlo(self, i, ops):
        self.assign(self.LO, self.operand(ops[0]))

    # --------------------------------------------------------- loads/stores
    _LOAD = {"lw": (32, True), "lb": (8, True), "lbu": (8, False), "lh": (16, True), "lhu": (16, False),
             "ll": (32, True), "lwu": (32, False), "ld": (64, False), "lld": (64, False)}
    _STORE = {"sw": 32, "sb": 8, "sh": 16, "sd": 64}

    def _ldst(self, i, m, ops):
        W = self.W
        mem = next(o for o in ops if o.type == OP_MEM)
        dst = self.reg_name(ops[0].reg)
        if m in self._LOAD:
            size, signed = self._LOAD[m]
            if size > W:
                raise LiftError(f"{m} on a 32-bit MIPS")
            addr = self.address(mem)
            lo, hi = self.an.bin.mips_local_got
            if size == W and isinstance(addr, Const) and lo <= addr.value < hi:
                # a local GOT entry (`lw $a0, %got(page)($gp)`): a link-time constant
                v = self.an.bin.read_int(addr.value, W // 8)
                if v is not None:
                    self.write_reg(dst, Const(v, W))
                    return
            v: Expr = Load(addr, size)
            if size < W:
                v = cast("sext" if signed else "zext", v, W)
            self.write_reg(dst, v)
            return
        if dst == "gp" and self.reg_name(mem.mem.base) in ("sp", "fp"):
            return                              # `sw $gp, 16($sp)`: the cprestore slot
        size = self._STORE[m]
        if size > W:
            raise LiftError(f"{m} on a 32-bit MIPS")
        val = self.read_reg(dst)
        self.emit(Store(i.addr, self.address(mem), val if size == W else cast("low", val, size)))

    def _i_sc(self, i, ops):
        """`sc rt, off(base)`: the store, and rt = 1 (the conditional store is taken to succeed)."""
        mem = next(o for o in ops if o.type == OP_MEM)
        r = self.reg_name(ops[0].reg)
        v = self.read_reg(r)
        self.emit(Store(i.addr, self.address(mem), self.lo32(v) if i.mnemonic == "sc" else v))
        self.write_reg(r, Const(1, self.W))

    _i_scd = _i_sc

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
        b = Const(0, self.W) if m.endswith("z") or len(ops) == 2 else self.operand(ops[1])
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
        self.emit(CallStmt(i.addr, Call(target, (), self.W), noreturn=self._noreturn(i), name=self.an.call_name(i)))

    def _i_jal(self, i, ops):
        if i.target is None:
            raise LiftError("call without a target")
        self._call(i, Const(i.target, self.W))

    def _i_bal(self, i, ops):
        if i.kind == "normal":                      # `bal .+8`: only reads pc into $ra
            self.write_reg("ra", Const(i.addr + 8, self.W))
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
        W = self.W
        if i.target is not None:
            if i.target in func.blocks:
                self.emit(Jump(i.addr, i.target))
            else:
                self.emit(CallStmt(i.addr, Call(Const(i.target, W), (), W), tail=True, name=self.an.name(i.target)))
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
            self.emit(CallStmt(i.addr, Call(target, (), W), tail=True, name=self.an.call_name(i)))
            self.emit(Return(i.addr))
        else:
            self.emit(IndirectJump(i.addr, target, []))
        return self.out


__all__ = ["MipsLifter"]

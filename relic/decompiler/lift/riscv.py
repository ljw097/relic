"""RISC-V (RV64GC, LP64D) lifter.

Registers are the 64-bit `ra`, `sp`, `gp`, `tp`, `t0`-`t6`, `s0`-`s11`
(`fp` = `s0`) and `a0`-`a7`; `zero` reads as 0 and ignores writes. The
floating-point registers `ft0`-`ft11`, `fa0`-`fa7`, `fs0`-`fs11` are 64-bit
too: a double fills one, a single its low half.

The `w` forms (`addw`, `slliw`, `divuw`, `sext.w` = `addiw rd, rs, 0`, ...)
compute on the low 32 bits and sign-extend the result, which is how 32-bit
`int` arithmetic looks. There are no flags: branches compare two registers
(`blt a0, a1, L`), and `slt` / `sltu` / `seqz` / `snez` produce 0 or 1.

Addresses come as `auipc` (pc + upper immediate) or `lui` pairs with an
`addi` / load / store; both lift to constants that fold. Compressed forms
(`c.ldsp ra, 8(sp)`, `c.addi16sp`, `c.addi4spn`, ...) are the same
operations; capstone gives their memory operand as an immediate and a base
register. `__global_pointer$`, when the binary has the symbol, is the
constant value of `gp`. Calls are `jal` / `jalr` with the link register
`ra`, returns `ret` (`jalr zero, 0(ra)`), jumps and tail calls `j` / `jr`.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ...analysis.functions import NORETURN
from ...disasm import Insn
from ..ir import (Assign, BinOp, Branch, Call, CallStmt, Cast, Const, Effect, Expr, IndirectJump, Intrinsic, Ite,
                  Jump, Load, Reg, Return, Stmt, Store, UnOp, Unknown, mask)
from .x86 import LiftError, cast

if TYPE_CHECKING:
    from ...analysis import Analysis
    from ...analysis.functions import Function

OP_REG, OP_IMM, OP_MEM = 1, 2, 3
M64 = mask(64)

_GPR = ({"ra", "sp", "gp", "tp"} | {f"t{k}" for k in range(7)} | {f"s{k}" for k in range(12)}
        | {f"a{k}" for k in range(8)})
_FPR = {f"ft{k}" for k in range(12)} | {f"fa{k}" for k in range(8)} | {f"fs{k}" for k in range(12)}
_ALIAS = {"fp": "s0", "x0": "zero", "x1": "ra", "x2": "sp", "x3": "gp", "x4": "tp", "x8": "s0"}

_NOPS = {"nop", "c.nop", "fence", "fence.i", "fence.tso", "pause", "prefetch.i", "prefetch.r", "prefetch.w"}

# conditional branches: mnemonic -> (comparison, operands swapped, compares with zero)
_BRANCH = {"beq": "==", "bne": "!=", "blt": "<s", "bge": ">=s", "bltu": "<u", "bgeu": ">=u",
           "bgt": ">s", "ble": "<=s", "bgtu": ">u", "bleu": "<=u",
           "beqz": "==", "bnez": "!=", "bltz": "<s", "bgez": ">=s", "blez": "<=s", "bgtz": ">s",
           "c.beqz": "==", "c.bnez": "!="}

# loads / stores: mnemonic -> (bits, signed, floating point)
_LOAD = {"lb": (8, True), "lh": (16, True), "lw": (32, True), "ld": (64, True),
         "lbu": (8, False), "lhu": (16, False), "lwu": (32, False),
         "c.lw": (32, True), "c.ld": (64, True), "c.lwsp": (32, True), "c.ldsp": (64, True)}
_FLOAD = {"flw": 32, "fld": 64, "c.flw": 32, "c.fld": 64, "c.flwsp": 32, "c.fldsp": 64}
_STORE = {"sb": 8, "sh": 16, "sw": 32, "sd": 64, "c.sw": 32, "c.sd": 64, "c.swsp": 32, "c.sdsp": 64}
_FSTORE = {"fsw": 32, "fsd": 64, "c.fsw": 32, "c.fsd": 64, "c.fswsp": 32, "c.fsdsp": 64}

# register-register / register-immediate operations: mnemonic -> (operator, 32-bit `w` form)
_ALU = {"add": ("+", False), "addi": ("+", False), "c.add": ("+", False), "c.addi": ("+", False),
        "addw": ("+", True), "addiw": ("+", True), "c.addw": ("+", True), "c.addiw": ("+", True),
        "sub": ("-", False), "c.sub": ("-", False), "subw": ("-", True), "c.subw": ("-", True),
        "and": ("&", False), "andi": ("&", False), "c.and": ("&", False), "c.andi": ("&", False),
        "or": ("|", False), "ori": ("|", False), "c.or": ("|", False),
        "xor": ("^", False), "xori": ("^", False), "c.xor": ("^", False),
        "sll": ("<<", False), "slli": ("<<", False), "c.slli": ("<<", False),
        "srl": (">>u", False), "srli": (">>u", False), "c.srli": (">>u", False),
        "sra": (">>s", False), "srai": (">>s", False), "c.srai": (">>s", False),
        "sllw": ("<<", True), "slliw": ("<<", True), "srlw": (">>u", True), "srliw": (">>u", True),
        "sraw": (">>s", True), "sraiw": (">>s", True),
        "mul": ("*", False), "mulw": ("*", True), "div": ("/s", False), "divu": ("/u", False),
        "divw": ("/s", True), "divuw": ("/u", True), "rem": ("%s", False), "remu": ("%u", False),
        "remw": ("%s", True), "remuw": ("%u", True),
        # Zbb
        "andn": ("&~", False), "orn": ("|~", False), "xnor": ("^~", False),
        "rol": ("rol", False), "ror": ("ror", False), "rori": ("ror", False),
        "rolw": ("rol", True), "rorw": ("ror", True), "roriw": ("ror", True)}
_SHIFTS = {"<<", ">>u", ">>s", "rol", "ror"}


def _hi20(imm: int) -> int:
    """`lui` / `auipc` immediate (the upper 20 bits) -> its sign-extended value."""
    imm &= 0xFFFFF
    if imm & 0x80000:
        imm -= 1 << 20
    return imm << 12


class RiscVLifter:
    bits = 64

    def __init__(self, an: "Analysis"):
        self.an = an
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0
        self.gp = an.bin.name_to_addr.get("__global_pointer$")

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
        return _ALIAS.get(name, name) if name else name

    def name(self, op) -> str:
        return self.canon(self.insn.cs.reg_name(op.reg))

    def read_reg(self, name: str) -> Expr:
        name = self.canon(name)
        if name == "zero":
            return Const(0, 64)
        if name == "gp" and self.gp is not None:
            return Const(self.gp, 64)
        if name in _GPR or name in _FPR:
            return Reg(name, 64)
        raise LiftError(f"register {name}")

    def write_reg(self, name: str, v: Expr, signed: bool = False):
        name = self.canon(name)
        if name == "zero" or name == "gp" and self.gp is not None:
            return
        r = self.read_reg(name)
        if v.bits != 64:
            v = cast("low", v, 64) if v.bits > 64 else cast("sext" if signed else "zext", v, 64)
        self.assign(r, v)

    def freg(self, op, bits: int) -> Expr:
        r = self.read_reg(self.name(op))
        return r if bits == 64 else Cast("low", r, bits)

    def operand(self, op) -> Expr:
        if op.type == OP_REG:
            return self.read_reg(self.name(op))
        if op.type == OP_IMM:
            return Const(op.imm & M64, 64)
        raise LiftError("operand")

    def address(self, ops) -> Expr:
        """The memory operand: `off(base)`, or immediate + base register (compressed forms)."""
        mem = next((o for o in ops if o.type == OP_MEM), None)
        if mem is not None:
            base, d = self.read_reg(self.insn.cs.reg_name(mem.mem.base)), mem.mem.disp
        else:
            base, d = self.read_reg(self.name(ops[2])), ops[1].imm
        if isinstance(base, Const):
            return Const((base.value + d) & M64, 64)
        if not d:
            return base
        return BinOp("+", base, Const(d, 64), 64) if d > 0 else BinOp("-", base, Const(-d, 64), 64)

    def unknown(self, i: Insn) -> Unknown:
        def regs(names):
            out = {}
            for n in names:
                n = self.canon(n)
                if n in _GPR or n in _FPR:
                    out[n] = Reg(n, 64)
            return list(out.items())
        try:
            r, w = i.cs.regs_access()
            reads = [i.cs.reg_name(x) for x in r]
            writes = [i.cs.reg_name(x) for x in w]
        except Exception:                           # noqa: BLE001 - capstone cannot always tell
            reads, writes = i.regs_read, i.regs_write
        return Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip(), regs(reads), regs(writes))

    # ----------------------------------------------------------- entry points
    def lift_insn(self, i: Insn, func: "Function | None" = None) -> list[Stmt]:
        self.out = []
        self.insn = i
        try:
            self._dispatch(i, i.mnemonic, i.cs.operands)
        except (LiftError, KeyError, StopIteration, AttributeError, IndexError, ValueError):
            self.out = [self.unknown(i)]
        return self.out

    def _dispatch(self, i, m, ops):
        h = getattr(self, "_i_" + m.replace(".", "_"), None)
        if h is not None:
            h(i, ops)
        elif m in _ALU:
            self._alu(ops, *_ALU[m])
        elif m in _LOAD or m in _FLOAD or m in _STORE or m in _FSTORE:
            self._ldst(i, m, ops)
        elif m in _BRANCH:
            self._branch(i, m, ops)
        elif m in _NOPS:
            pass
        elif m.startswith(("lr.", "sc.", "amo")):
            self._atomic(i, m, ops)
        elif m.startswith("f") and "." in m:
            self._fp(i, m, ops)
        else:
            self.out = [self.unknown(i)]

    # ------------------------------------------------------- data processing
    def _alu(self, ops, op: str, word: bool):
        d = self.name(ops[0])
        if len(ops) == 2:                           # compressed: `c.addi a5, 8` = `addi a5, a5, 8`
            a, b = self.read_reg(d), self.operand(ops[1])
        else:
            a, b = self.operand(ops[1]), self.operand(ops[2])
        w = 32 if word else 64
        if word:
            a = Const(a.value & mask(32), 32) if isinstance(a, Const) else cast("low", a, 32)
            b = Const(b.value & mask(32), 32) if isinstance(b, Const) else cast("low", b, 32)
        if op in _SHIFTS:
            if isinstance(b, Const):
                b = Const(b.value & (w - 1), 8)
            else:
                b = BinOp("&", b, Const(w - 1, w), w)
        if op == "+" and isinstance(b, Const) and b.value >> (w - 1):     # `addi sp, sp, -16`: sp - 16
            e: Expr = BinOp("-", a, Const(-b.value & mask(w), w), w)
        elif op in ("+", "|", "^") and isinstance(a, Const) and a.value == 0:   # `addi a0, zero, 5`: li
            e = b
        elif op in ("+", "|", "^", "-", "<<", ">>u", ">>s") and isinstance(b, Const) and b.value == 0:
            e = a                                   # `addi a0, a1, 0`: mv; `addiw a0, a1, 0`: sext.w
        elif op in ("&~", "|~", "^~"):
            e = BinOp(op[0], a, UnOp("~", b, w), w)
        else:
            e = BinOp(op, a, b, w)
        self.write_reg(d, e, signed=True)

    def _i_mv(self, i, ops):
        self.write_reg(self.name(ops[0]), self.operand(ops[1]))

    _i_c_mv = _i_mv

    def _i_li(self, i, ops):
        self.write_reg(self.name(ops[0]), Const(ops[1].imm & M64, 64))

    _i_c_li = _i_li

    def _i_lui(self, i, ops):
        self.write_reg(self.name(ops[0]), Const(_hi20(ops[1].imm) & M64, 64))

    _i_c_lui = _i_lui

    def _i_auipc(self, i, ops):
        self.write_reg(self.name(ops[0]), Const((i.addr + _hi20(ops[1].imm)) & M64, 64))

    def _i_c_addi16sp(self, i, ops):
        self._alu([ops[0], ops[0], ops[1]], "+", False)

    def _i_c_addi4spn(self, i, ops):
        self._alu(ops, "+", False)

    def _unary(self, ops, f, word: bool = False):
        v = self.operand(ops[1])
        if word:
            v = cast("low", v, 32)
        self.write_reg(self.name(ops[0]), f(v, 32 if word else 64), signed=True)

    def _i_not(self, i, ops):
        self._unary(ops, lambda v, w: UnOp("~", v, w))

    def _i_c_not(self, i, ops):
        self.write_reg(self.name(ops[0]), UnOp("~", self.read_reg(self.name(ops[0])), 64))

    def _i_neg(self, i, ops):
        self._unary(ops, lambda v, w: BinOp("-", Const(0, w), v, w))

    def _i_negw(self, i, ops):
        self._unary(ops, lambda v, w: BinOp("-", Const(0, w), v, w), word=True)

    def _i_sext_w(self, i, ops):
        self._unary(ops, lambda v, w: v, word=True)

    def _ext(self, ops, bits: int, signed: bool):
        v = cast("low", self.operand(ops[1]), bits)
        self.write_reg(self.name(ops[0]), cast("sext" if signed else "zext", v, 64))

    def _i_sext_b(self, i, ops):
        self._ext(ops, 8, True)

    def _i_sext_h(self, i, ops):
        self._ext(ops, 16, True)

    def _i_zext_b(self, i, ops):
        self._ext(ops, 8, False)

    def _i_zext_h(self, i, ops):
        self._ext(ops, 16, False)

    def _i_zext_w(self, i, ops):
        self._ext(ops, 32, False)

    _i_c_zext_b, _i_c_zext_h, _i_c_zext_w, _i_c_sext_b, _i_c_sext_h = \
        _i_zext_b, _i_zext_h, _i_zext_w, _i_sext_b, _i_sext_h

    def _set(self, d: str, cond: Expr):
        self.write_reg(d, cast("zext", cond, 64))

    def _i_slt(self, i, ops):
        self._set(self.name(ops[0]), BinOp("<s", self.operand(ops[1]), self.operand(ops[2]), 1))

    _i_slti = _i_slt

    def _i_sltu(self, i, ops):
        self._set(self.name(ops[0]), BinOp("<u", self.operand(ops[1]), self.operand(ops[2]), 1))

    _i_sltiu = _i_sltu

    def _i_seqz(self, i, ops):
        self._set(self.name(ops[0]), BinOp("==", self.operand(ops[1]), Const(0, 64), 1))

    def _i_snez(self, i, ops):
        self._set(self.name(ops[0]), BinOp("!=", self.operand(ops[1]), Const(0, 64), 1))

    def _i_sltz(self, i, ops):
        self._set(self.name(ops[0]), BinOp("<s", self.operand(ops[1]), Const(0, 64), 1))

    def _i_sgtz(self, i, ops):
        self._set(self.name(ops[0]), BinOp("<s", Const(0, 64), self.operand(ops[1]), 1))

    def _mulh(self, ops, ka: str, kb: str):
        a, b = cast(ka, self.operand(ops[1]), 128), cast(kb, self.operand(ops[2]), 128)
        p = BinOp("*", a, b, 128)
        self.write_reg(self.name(ops[0]), cast("low", BinOp(">>u", p, Const(64, 8), 128), 64))

    def _i_mulh(self, i, ops):
        self._mulh(ops, "sext", "sext")

    def _i_mulhu(self, i, ops):
        self._mulh(ops, "zext", "zext")

    def _i_mulhsu(self, i, ops):
        self._mulh(ops, "sext", "zext")

    def _minmax(self, ops, op: str, smaller: bool):
        a, b = self.operand(ops[1]), self.operand(ops[2])
        self.write_reg(self.name(ops[0]), Ite(BinOp(op, a, b, 1), a, b, 64) if smaller else
                       Ite(BinOp(op, a, b, 1), b, a, 64))

    def _i_min(self, i, ops):
        self._minmax(ops, "<s", True)

    def _i_max(self, i, ops):
        self._minmax(ops, "<s", False)

    def _i_minu(self, i, ops):
        self._minmax(ops, "<u", True)

    def _i_maxu(self, i, ops):
        self._minmax(ops, "<u", False)

    def _i_czero_eqz(self, i, ops):
        a, c = self.operand(ops[1]), self.operand(ops[2])
        self.write_reg(self.name(ops[0]), Ite(BinOp("==", c, Const(0, 64), 1), Const(0, 64), a, 64))

    def _i_czero_nez(self, i, ops):
        a, c = self.operand(ops[1]), self.operand(ops[2])
        self.write_reg(self.name(ops[0]), Ite(BinOp("!=", c, Const(0, 64), 1), Const(0, 64), a, 64))

    def _shadd(self, ops, n: int, uw: bool = False):
        a = self.operand(ops[1])
        if uw:
            a = cast("zext", cast("low", a, 32), 64)
        self.write_reg(self.name(ops[0]), BinOp("+", self.operand(ops[2]),
                                                BinOp("<<", a, Const(n, 8), 64) if n else a, 64))

    def _i_sh1add(self, i, ops):
        self._shadd(ops, 1)

    def _i_sh2add(self, i, ops):
        self._shadd(ops, 2)

    def _i_sh3add(self, i, ops):
        self._shadd(ops, 3)

    def _i_add_uw(self, i, ops):
        self._shadd(ops, 0, True)

    def _i_clz(self, i, ops):
        self.write_reg(self.name(ops[0]), Intrinsic("clz", (self.operand(ops[1]),), 64))

    def _i_ctz(self, i, ops):
        self.write_reg(self.name(ops[0]), Intrinsic("ctz", (self.operand(ops[1]),), 64))

    def _i_cpop(self, i, ops):
        self.write_reg(self.name(ops[0]), Intrinsic("popcount", (self.operand(ops[1]),), 64))

    # --------------------------------------------------------- loads/stores
    def _ldst(self, i, m, ops):
        r = self.name(ops[0])
        addr = self.address(ops)
        if m in _LOAD:
            size, signed = _LOAD[m]
            v: Expr = Load(addr, size)
            self.write_reg(r, v if size == 64 else cast("sext" if signed else "zext", v, 64))
        elif m in _FLOAD:
            size = _FLOAD[m]
            self.write_reg(r, Load(addr, size))
        elif m in _STORE:
            size = _STORE[m]
            val = self.read_reg(r)
            self.emit(Store(i.addr, addr, val if size == 64 else cast("low", val, size)))
        else:
            self.emit(Store(i.addr, addr, self.freg(ops[0], _FSTORE[m])))

    _AMO = {"amoswap": None, "amoadd": "+", "amoand": "&", "amoor": "|", "amoxor": "^",
            "amomin": ("<s", True), "amomax": ("<s", False), "amominu": ("<u", True), "amomaxu": ("<u", False)}

    def _atomic(self, i, m, ops):
        """`lr.w rd, (rs1)`, `sc.w rd, rs2, (rs1)` (taken to succeed: rd = 0), `amo<op>.w rd, rs2,
        (rs1)` (rd = the old value, memory = old <op> rs2), acquire / release orderings aside."""
        parts = m.split(".")
        size = {"w": 32, "d": 64}[parts[1]]
        regs = [self.name(o) for o in ops if o.type == OP_REG]
        addr = self.read_reg(regs[-1])
        if not isinstance(addr, Const):
            addr = self.tmp(addr)
        if parts[0] == "lr":
            v: Expr = Load(addr, size)
            self.write_reg(regs[0], v if size == 64 else cast("sext", v, 64))
            return
        src = self.read_reg(regs[1])
        src = src if size == 64 else cast("low", src, size)
        if parts[0] == "sc":
            self.emit(Store(i.addr, addr, src))
            self.write_reg(regs[0], Const(0, 64))
            return
        if parts[0] not in self._AMO:
            raise LiftError(m)
        src = self.tmp(src)
        old = self.tmp(Load(addr, size))
        op = self._AMO[parts[0]]
        if op is None:
            new: Expr = src
        elif isinstance(op, tuple):
            cmp, smaller = op
            new = Ite(BinOp(cmp, old, src, 1), old, src, size) if smaller else \
                Ite(BinOp(cmp, old, src, 1), src, old, size)
        else:
            new = BinOp(op, old, src, size)
        self.emit(Store(i.addr, addr, new))
        self.write_reg(regs[0], old if size == 64 else cast("sext", old, 64))

    def _effect(self, i, name):
        if name == "syscall":
            uses = [(r, Reg(r, 64)) for r in ("a7", "a0", "a1", "a2", "a3", "a4", "a5")]
            self.emit(Effect(i.addr, "syscall", (), uses, [("a0", Reg("a0", 64))]))
        else:
            self.emit(Effect(i.addr, name, ()))

    def _i_ecall(self, i, ops):
        self._effect(i, "syscall")

    def _i_ebreak(self, i, ops):
        self._effect(i, "ebreak")

    _i_c_ebreak = _i_ebreak

    def _i_unimp(self, i, ops):
        self._effect(i, "trap")

    _i_c_unimp = _i_unimp

    # --------------------------------------------------------- floating point
    def _fp(self, i, m, ops):
        """`fadd.d fa0, fa1, fa2`, `fcvt.w.d a0, fa0, rtz`, `feq.s a0, fa0, fa1`, `fmv.x.d a0, fa0`, ..."""
        parts = m.split(".")
        op, fmt = parts[0], parts[-1]
        bits = {"s": 32, "d": 64}.get(fmt)
        h = getattr(self, "_f_" + op, None)
        if h is None:
            raise LiftError(m)
        h(i, parts, bits, ops)

    def _farith(self, ops, op, bits):
        self.write_reg(self.name(ops[0]), BinOp(op, self.freg(ops[1], bits), self.freg(ops[2], bits), bits))

    def _f_fadd(self, i, parts, bits, ops):
        self._farith(ops, "f+", bits)

    def _f_fsub(self, i, parts, bits, ops):
        self._farith(ops, "f-", bits)

    def _f_fmul(self, i, parts, bits, ops):
        self._farith(ops, "f*", bits)

    def _f_fdiv(self, i, parts, bits, ops):
        self._farith(ops, "f/", bits)

    def _fcall(self, ops, name: str, bits: int, n: int):
        name = name + ("f" if bits == 32 else "")
        self.write_reg(self.name(ops[0]), Intrinsic(name, tuple(self.freg(o, bits) for o in ops[1:1 + n]), bits))

    def _f_fsqrt(self, i, parts, bits, ops):
        self._fcall(ops, "sqrt", bits, 1)

    def _f_fmin(self, i, parts, bits, ops):
        self._fcall(ops, "fmin", bits, 2)

    def _f_fmax(self, i, parts, bits, ops):
        self._fcall(ops, "fmax", bits, 2)

    def _fma(self, ops, bits, neg_prod: bool, neg_add: bool):
        a, b, c = (self.freg(o, bits) for o in ops[1:4])
        if neg_prod:
            a = UnOp("fneg", a, bits)
        if neg_add:
            c = UnOp("fneg", c, bits)
        self.write_reg(self.name(ops[0]), Intrinsic("fma" + ("f" if bits == 32 else ""), (a, b, c), bits))

    def _f_fmadd(self, i, parts, bits, ops):
        self._fma(ops, bits, False, False)

    def _f_fmsub(self, i, parts, bits, ops):
        self._fma(ops, bits, False, True)

    def _f_fnmsub(self, i, parts, bits, ops):
        self._fma(ops, bits, True, False)

    def _f_fnmadd(self, i, parts, bits, ops):
        self._fma(ops, bits, True, True)

    def _f_fneg(self, i, parts, bits, ops):
        self.write_reg(self.name(ops[0]), UnOp("fneg", self.freg(ops[1], bits), bits))

    def _f_fabs(self, i, parts, bits, ops):
        self._fcall(ops, "fabs", bits, 1)

    def _f_fmv(self, i, parts, bits, ops):
        if len(parts) == 2:                         # fmv.d fa0, fa1
            self.write_reg(self.name(ops[0]), self.freg(ops[1], bits))
            return
        # fmv.x.d / fmv.d.x / fmv.x.w / fmv.w.x: the bits, unchanged
        bits = 64 if "d" in parts[1:] else 32
        src = self.operand(ops[1])
        v = src if bits == 64 else cast("low", src, 32)
        self.write_reg(self.name(ops[0]), v, signed=parts[1] == "x")

    def _f_fsgnj(self, i, parts, bits, ops):
        if ops[1].reg != ops[2].reg:
            raise LiftError("fsgnj")
        self.write_reg(self.name(ops[0]), self.freg(ops[1], bits))

    def _f_fsgnjn(self, i, parts, bits, ops):
        if ops[1].reg != ops[2].reg:
            raise LiftError("fsgnjn")
        self._f_fneg(i, parts, bits, ops)

    def _f_fsgnjx(self, i, parts, bits, ops):
        if ops[1].reg != ops[2].reg:
            raise LiftError("fsgnjx")
        self._f_fabs(i, parts, bits, ops)

    def _fcmp(self, ops, op, bits):
        c = BinOp(op, self.freg(ops[1], bits), self.freg(ops[2], bits), 1)
        self.write_reg(self.name(ops[0]), cast("zext", c, 64))

    def _f_feq(self, i, parts, bits, ops):
        self._fcmp(ops, "f==", bits)

    def _f_flt(self, i, parts, bits, ops):
        self._fcmp(ops, "f<", bits)

    def _f_fle(self, i, parts, bits, ops):
        self._fcmp(ops, "f<=", bits)

    _INT = {"w": (32, True), "wu": (32, False), "l": (64, True), "lu": (64, False)}

    def _f_fcvt(self, i, parts, bits, ops):
        """fcvt.<dst>.<src>: between the two float formats, or float <-> integer."""
        dst, src = parts[1], parts[2]
        rm = i.op_str.rsplit(",", 1)[-1].strip() if i.op_str.count(",") >= 2 else "dyn"
        d = self.name(ops[0])
        if dst in ("s", "d") and src in ("s", "d"):
            self.write_reg(d, Intrinsic("fpconv", (self.freg(ops[1], 32 if src == "s" else 64),),
                                        32 if dst == "s" else 64))
        elif dst in ("s", "d"):
            ib, signed = self._INT[src]
            v = self.operand(ops[1])
            v = v if ib == 64 else cast("low", v, 32)
            self.write_reg(d, Intrinsic("sitofp" if signed else "uitofp", (v,), 32 if dst == "s" else 64))
        else:
            ib, signed = self._INT[dst]
            fb = 32 if src == "s" else 64
            x: Expr = self.freg(ops[1], fb)
            if rm != "rtz":                         # C casts truncate; other modes round first
                rnd = {"rdn": "floor", "rup": "ceil", "rmm": "round"}.get(rm)
                if rnd is None:
                    raise LiftError(f"fcvt rounding {rm}")
                x = Intrinsic(rnd + ("f" if fb == 32 else ""), (x,), fb)
            v = Intrinsic("fptosi" if signed else "fptoui", (x,), ib)
            self.write_reg(d, v, signed=True)

    def _f_fclass(self, i, parts, bits, ops):
        raise LiftError("fclass")

    def _f_fli(self, i, parts, bits, ops):
        raise LiftError("fli")

    # --------------------------------------------------------- control flow
    def _branch(self, i, m, ops):
        a = self.operand(ops[0])
        b = self.operand(ops[1]) if len(ops) == 3 else Const(0, 64)
        op = _BRANCH[m]
        if op[0] == ">":                            # a > b: b < a
            a, b, op = b, a, "<" + op[1:]
        test = self.tmp(BinOp(op, a, b, 1))
        self.emit(Branch(i.addr, test, i.target, i.end))

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
        self.emit(CallStmt(i.addr, Call(target, (), 64), noreturn=self._noreturn(i), name=self.an.call_name(i)))

    def _i_jal(self, i, ops):
        if i.kind != "call":
            raise LiftError("jal outside a call")
        self._call(i, Const(i.target, 64))

    _i_c_jal = _i_jal

    def _reg_target(self, ops) -> Expr:
        """`jalr rd, off(rs)` / `jr rs` / `c.jalr rs`: rs + off."""
        mem = next((o for o in ops if o.type == OP_MEM), None)
        if mem is not None:
            base, d = self.read_reg(self.insn.cs.reg_name(mem.mem.base)), mem.mem.disp
        else:
            regs = [o for o in ops if o.type == OP_REG]
            base = self.read_reg(self.name(regs[-1]))
            d = next((o.imm for o in ops if o.type == OP_IMM), 0)
        if isinstance(base, Const):
            return Const((base.value + d) & M64, 64)
        return BinOp("+", base, Const(d & M64, 64), 64) if d else base

    def _i_jalr(self, i, ops):
        if i.kind == "ret":
            self.emit(Return(i.addr))
        elif i.kind == "call":
            self._call(i, self._reg_target(ops))
        else:
            raise LiftError("jalr jump outside a block end")

    _i_c_jalr = _i_jalr

    def _i_ret(self, i, ops):
        self.emit(Return(i.addr))

    _i_c_ret = _i_ret

    def _i_jr(self, i, ops):
        if i.kind == "ret":
            self.emit(Return(i.addr))
        else:
            raise LiftError("jr outside a block end")

    _i_c_jr = _i_jr

    def _i_j(self, i, ops):
        self.emit(Jump(i.addr, i.target))

    _i_c_j = _i_j

    def lift_jmp(self, i: Insn, func: "Function") -> list[Stmt]:
        """`j` (a jump or tail call) or `jr rs` (a switch, or a tail call)."""
        self.out = []
        self.insn = i
        if i.target is not None:
            if i.target in func.blocks:
                self.emit(Jump(i.addr, i.target))
            else:
                self.emit(CallStmt(i.addr, Call(Const(i.target, 64), (), 64), tail=True, name=self.an.name(i.target)))
                self.emit(Return(i.addr))
            return self.out
        try:
            target = self._reg_target(i.cs.operands)
            if not isinstance(target, Const):
                target = self.tmp(target)
        except (LiftError, IndexError, AttributeError, StopIteration):
            return [self.unknown(i)]
        table = func.jump_tables.get(i.addr)
        if table:
            seen = list(dict.fromkeys(t for t in table if t in func.blocks))
            self.emit(IndirectJump(i.addr, target, seen, list(table)))
        else:
            # an indirect jump that is not a switch leaves the function: a tail call
            self.emit(CallStmt(i.addr, Call(target, (), 64), tail=True, name=self.an.call_name(i)))
            self.emit(Return(i.addr))
        return self.out


__all__ = ["RiscVLifter"]

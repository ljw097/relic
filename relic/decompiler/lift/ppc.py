"""PowerPC lifter: 32-bit (SysV) and 64-bit (ELFv2 / ELFv1).

Instructions are decoded from their fields, not capstone's simplified mnemonics
(`slwi`, `clrlwi`, `rotlwi`, ... are all `rlwinm`; `bcl 20,31,.+4` reads as
`bdnzl`). Registers are `r0`-`r31` (`r1` is the stack pointer), `lr`, `ctr`,
the carry `ca` and the condition register as 1-bit fields `crN_lt`,
`crN_gt`, `crN_eq`, `crN_so` (`cmpw cr7, a, b` sets `cr7_lt = a < b`, ...);
a record form (`add.`, `andi.`) compares its result with 0 into `cr0`.
`f0`-`f31` hold doubles; a single-precision operation reads its operands as
floats (`fpsingle`, a conversion that also says the value is a float -- what
tells a float parameter from a double one; `frsp`, an explicit rounding, is a
plain `fpconv`) and writes its result widened to double.

`r0` as the base of an address or the source of `addi` / `addis` means 0.
The frame is made by `stwu r1, -N(r1)` (`stdu` on 64-bit): the back chain it
stores is dropped and only `r1 -= N` kept, so `lwz r1, 0(r1)` (the epilogue
of a frame of unknown size) undoes the last such adjustment. The thread
pointer (`r2` on 32-bit, `r13` on 64-bit) reads as `tp_base`, where the
stack protector keeps its value; on 64-bit `r2` is the TOC (a constant, its
writes dropped, like MIPS' `$gp`). Calls are `bl` and `bctrl` (through
`ctr`), returns `blr` -- also conditional ones (`beqlr`), which branch to a
synthetic block (`addr + 1`) holding the return.
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

_CR_BITS = ("lt", "gt", "eq", "so")


def _sx(v: int, bits: int) -> int:
    v &= (1 << bits) - 1
    return v - (1 << bits) if v >> (bits - 1) else v


def _rotmask(mb: int, me: int, w: int) -> int:
    """The mask of bits mb..me (big-endian bit numbering, wrapping) of a w-bit word."""
    def bit(k):
        return 1 << (w - 1 - k)
    m = 0
    k = mb
    while True:
        m |= bit(k)
        if k == me:
            break
        k = (k + 1) % w
    return m


def _const_words(b, ranges, skip, size):
    """The GOT / TOC words (`.got2`, `.got`, `.toc`) as link-time constants, per binary."""
    cached = getattr(b, "_ppc_const_words", None)
    if cached is not None:
        return cached
    from ..ir import ConstWords
    words = ConstWords()
    for lo, hi in ranges:
        for a in range(lo, hi - size + 1, size):
            if a not in skip:
                v = b.read_int(a, size)
                if v is not None:
                    words[a] = (size, v)
    if True:
        def ro(addr, n):
            """A 64-bit constant gcc keeps in read-only data and loads through the TOC."""
            if n != 8:
                return None
            sec = b.section_at(addr)
            return b.read_int(addr, 8) if sec is not None and not sec.w and not sec.x else None
        words.ro_reader = ro
    b._ppc_const_words = words
    return words


class PpcLifter:
    def __init__(self, an: "Analysis"):
        self.an = an
        self.out: list[Stmt] = []
        self.insn: Insn | None = None
        self._tmp = 0
        b = an.bin
        self.W = W = 64 if b.bits == 64 else 32
        self.bits = W
        self.big = b.endian == "big"
        self.toc = getattr(b, "ppc_toc", None) if W == 64 else None
        self.tp = "r13" if W == 64 else "r2"
        self.frames: list[int] = []
        self._written: dict[int, int] = {}
        self._vsx_masks: dict[str, Expr] = {}      # FPR -> the condition a VSX compare left in it
        self._consts: dict[int, tuple[int, int]] = {}
        # stw: (base, disp) -> (register, store address, its constant value then or None)
        self._words: dict[tuple[int, int], tuple] = {}
        self.extra_blocks: dict[int, tuple[list[Stmt], list[int]]] = {}
        # data GOT words that hold link-time constants (`lwz r3, off(r30)` of a string address)
        self.const_got = []
        for s in b.sections:
            if s.name in (".got2", ".got", ".toc") and not s.x:
                self.const_got.append((s.addr, s.end))
        self.import_slots = set(getattr(b, "imports_by_got", {}) or ()) | {i.got for i in b.imports if i.got}
        self.const_words = _const_words(b, self.const_got, self.import_slots, W // 8)

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

    def gpr(self, n: int) -> Expr:
        W = self.W
        name = f"r{n}"
        if name == self.tp:
            return Reg("tp_base", W)
        if W == 64 and n == 2 and self.toc is not None:
            return Const(self.toc, W)
        return Reg(name, W)

    def ra0(self, n: int) -> Expr:
        """rA where 0 means the value 0 (addresses, addi / addis)."""
        return Const(0, self.W) if n == 0 else self.gpr(n)

    def set_gpr(self, n: int, v: Expr):
        W = self.W
        if W == 64 and n == 2 and self.toc is not None:
            return                                  # the TOC: rebuilt, restored, never changes
        if f"r{n}" == self.tp:
            return
        if v.bits != W:
            v = cast("low", v, W) if v.bits > W else cast("zext", v, W)
        self.assign(Reg(f"r{n}", W), v)
        # (for `_int_to_double`: register constants and when each register was last written)
        self._written[n] = self.insn.addr
        if isinstance(v, Const):
            self._consts[n] = (v.value, self.insn.addr)
        else:
            self._consts.pop(n, None)

    def cr(self, bi: int) -> Reg:
        return Reg(f"cr{bi // 4}_{_CR_BITS[bi % 4]}", 1)

    def set_cr_cmp(self, field: int, a: Expr, b: Expr, signed: bool):
        lt = "<s" if signed else "<u"
        a = a if isinstance(a, (Reg, Const)) else self.tmp(a)
        b = b if isinstance(b, (Reg, Const)) else self.tmp(b)
        self.assign(Reg(f"cr{field}_lt", 1), BinOp(lt, a, b, 1))
        self.assign(Reg(f"cr{field}_gt", 1), BinOp(lt, b, a, 1))
        self.assign(Reg(f"cr{field}_eq", 1), BinOp("==", a, b, 1))
        self.assign(Reg(f"cr{field}_so", 1), Const(0, 1))

    def record(self, n: int):
        """A record form's `cr0`: the result compared (signed) with 0."""
        self.set_cr_cmp(0, self.gpr(n), Const(0, self.W), True)

    def addr(self, ra: int, d: int) -> Expr:
        W = self.W
        base = self.ra0(ra)
        if isinstance(base, Const):
            return Const((base.value + d) & mask(W), W)
        if not d:
            return base
        return BinOp("+", base, Const(d, W), W) if d > 0 else BinOp("-", base, Const(-d, W), W)

    def addr_x(self, ra: int, rb: int) -> Expr:
        base = self.ra0(ra)
        idx = self.gpr(rb)
        if isinstance(base, Const) and base.value == 0:
            return idx
        return BinOp("+", base, idx, self.W)

    def lo32(self, e: Expr) -> Expr:
        if e.bits == 32:
            return e
        return Const(e.value & mask(32), 32) if isinstance(e, Const) else cast("low", e, 32)

    def unknown(self, i: Insn) -> Unknown:
        W = self.W
        reads, writes = {}, {}
        try:
            r, w = i.cs.regs_access()
            rn = [i.cs.reg_name(x) for x in r]
            wn = [i.cs.reg_name(x) for x in w]
        except Exception:                           # noqa: BLE001 - capstone cannot always tell
            rn, wn = [], []
        for n in rn:
            if n.startswith("r") and n[1:].isdigit():
                reads[n] = Reg(n, W)
        for n in wn:
            if n.startswith("r") and n[1:].isdigit():
                writes[n] = Reg(n, W)
        return Unknown(i.addr, f"{i.mnemonic} {i.op_str}".strip(), list(reads.items()), list(writes.items()))

    # ----------------------------------------------------------- entry points
    def lift_insn(self, i: Insn, func: "Function | None" = None) -> list[Stmt]:
        self.out = []
        self.insn = i
        try:
            self._decode(i)
        except (LiftError, KeyError, StopIteration, AttributeError, IndexError, ValueError):
            self.out = [self.unknown(i)]
        return self.out

    def word(self, i: Insn) -> int:
        return int.from_bytes(i.raw, "big" if self.big else "little")

    def _decode(self, i: Insn):
        w = self.word(i)
        op = w >> 26
        rt, ra, rb = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
        simm, uimm = _sx(w, 16), w & 0xFFFF
        h = _PRIMARY.get(op)
        if h is None:
            raise LiftError(f"opcode {op}")
        getattr(self, h)(i, w, rt, ra, rb, simm, uimm)

    # ------------------------------------------------------- D-form integer
    def _addi(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        if ra == 0:
            self.set_gpr(rt, Const(simm & mask(W), W))
            return
        a = self.gpr(ra)
        if isinstance(a, Const):
            self.set_gpr(rt, Const((a.value + simm) & mask(W), W))
        elif simm < 0:
            self.set_gpr(rt, BinOp("-", a, Const(-simm, W), W))
        elif simm == 0:
            self.set_gpr(rt, a)
        else:
            self.set_gpr(rt, BinOp("+", a, Const(simm, W), W))

    def _addis(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        v = (simm << 16) & mask(W)
        if ra == 0:
            self.set_gpr(rt, Const(v, W))
            return
        a = self.gpr(ra)
        if isinstance(a, Const):
            self.set_gpr(rt, Const((a.value + v) & mask(W), W))
        else:
            self.set_gpr(rt, BinOp("+", a, Const(v, W), W))

    def _addic(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        a = self.gpr(ra)
        s = self.tmp(BinOp("+", a, Const(simm & mask(W), W), W))
        self.assign(Reg("ca", 1), BinOp("<u", s, a, 1) if simm >= 0 else
                    BinOp("<=u", Const(-simm & mask(W), W), a, 1))
        self.set_gpr(rt, s)
        if w >> 26 == 13:                           # addic.
            self.record(rt)

    def _subfic(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        a = self.gpr(ra)
        self.assign(Reg("ca", 1), BinOp("<=u", a, Const(simm & mask(W), W), 1))
        self.set_gpr(rt, BinOp("-", Const(simm & mask(W), W), a, W))

    def _mulli(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        self.set_gpr(rt, BinOp("*", self.gpr(ra), Const(simm & mask(W), W), W))

    def _cmpi(self, i, w, rt, ra, rb, simm, uimm):
        bf, l64 = rt >> 2, rt & 1
        signed = w >> 26 == 11
        a = self.gpr(ra) if l64 or self.W == 32 else self.lo32(self.gpr(ra))
        bits = a.bits
        imm = (simm if signed else uimm) & mask(bits)
        self.set_cr_cmp(bf, a, Const(imm, bits), signed)

    def _logic_imm(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        op = w >> 26
        shift = 16 if op in (25, 27, 29) else 0
        k = Const((uimm << shift) & mask(W), W)
        s = self.gpr(rt)
        o = {24: "|", 25: "|", 26: "^", 27: "^", 28: "&", 29: "&"}[op]
        if o in ("|", "^") and uimm == 0:
            if rt == ra == 0 and op == 24:
                return                              # nop (ori 0,0,0)
            self.set_gpr(ra, s)
            return
        if isinstance(s, Const):
            v = {"|": s.value | k.value, "^": s.value ^ k.value, "&": s.value & k.value}[o]
            self.set_gpr(ra, Const(v, W))
        else:
            self.set_gpr(ra, BinOp(o, s, k, W))
        if op in (28, 29):                          # andi. / andis.
            self.record(ra)

    # ------------------------------------------------------- loads / stores
    _LD = {32: (32, False, False), 33: (32, False, True), 34: (8, False, False), 35: (8, False, True),
           40: (16, False, False), 41: (16, False, True), 42: (16, True, False), 43: (16, True, True)}
    _ST = {36: (32, False), 37: (32, True), 38: (8, False), 39: (8, True), 44: (16, False), 45: (16, True)}

    def _load(self, rt: int, ea: Expr, size: int, signed: bool):
        W = self.W
        if size == W and isinstance(ea, Const) and ea.value not in self.import_slots and \
                any(lo <= ea.value < hi for lo, hi in self.const_got):
            v = self.an.bin.read_int(ea.value, W // 8)    # a GOT / TOC word: a link-time constant
            if v is not None:
                self.set_gpr(rt, Const(v, W))
                return
        if rt == 1 and isinstance(ea, Reg) and ea.name == "r1" and self.frames:
            # `lwz r1, 0(r1)`: back to the caller's frame (the back chain is not modelled)
            self.set_gpr(1, BinOp("+", Reg("r1", W), Const(self.frames[-1], W), W))
            return
        v: Expr = Load(ea, size)
        if size < W:
            v = cast("sext" if signed else "zext", v, W)
        self.set_gpr(rt, v)

    def _store(self, i, rs: int, ea: Expr, size: int):
        v = self.gpr(rs)
        self.emit(Store(i.addr, ea, v if size == self.W else cast("low", v, size)))

    def _word_read_back(self, i, base, d) -> bool:
        """The next few instructions read this stack doubleword's low word with `lwz` and nothing
        else touches the slot."""
        a = i.end
        n = (self.word(i) >> 21) & 31
        for _ in range(20):
            j = self.an.dis.decode(a)
            if j is None or j.kind != "normal":
                return False
            w = self.word(j)
            if w >> 26 == 32 and (w >> 16) & 31 == base and _sx(w, 16) == d + (4 if self.big else 0):
                return self._fpr_kept(i.addr, j.addr, n)
            if w >> 26 in (14, 15, 31) and (w >> 21) & 31 == base:
                return False                        # (the base register changes)
            if w >> 26 in (32, 33, 34, 36, 37, 38, 44, 48, 50, 52, 54, 58, 62) and (w >> 16) & 31 == base and \
                    d - 8 < _sx(w & ~3 if w >> 26 in (58, 62) else w, 16) < d + 8:
                return False
            a = j.end
        return False

    def _load_word_of_fpr(self, i, rt, ra, d) -> bool:
        """`stfd fX, d(rA)` shortly before `lwz rT, d+4(rA)` (big-endian; d on little-endian): the
        integer a conversion left in fX's low word -- read from the register, not memory."""
        st = getattr(self, "_stfd", None)
        if st is None or st[0] != ra or i.addr - st[3] > 80:
            return False
        if d != st[1] + (4 if self.big else 0) or not self._fpr_kept(st[3], i.addr, st[2]):
            return False
        self.set_gpr(rt, cast("low", Reg(f"f{st[2]}", 64), 32))
        return True

    def _fpr_kept(self, start: int, end: int, n: int) -> bool:
        """Straight-line code from `start` to `end` that writes neither fN nor the base register."""
        a = start + 4
        while a < end:
            j = self.an.dis.decode(a)
            if j is None or j.kind != "normal":
                return False
            w = self.word(j)
            if w >> 26 in (48, 49, 50, 51, 59, 63, 60) and (w >> 21) & 31 == n:
                return False
            a = j.end
        return True

    def _ld_d(self, i, w, rt, ra, rb, simm, uimm):
        size, signed, update = self._LD[w >> 26]
        if w >> 26 == 32 and self._load_word_of_fpr(i, rt, ra, simm):
            return
        ea = self.addr(ra, simm)
        if update:
            ea = self.tmp(ea)
        self._load(rt, ea, size, signed)
        if update and ra != rt:
            self.set_gpr(ra, ea)

    def _st_d(self, i, w, rt, ra, rb, simm, uimm):
        size, update = self._ST[w >> 26]
        if w >> 26 == 36:
            k = self._consts.get(rt)
            # (the value as stored: the register may change before an `lfd` reads the slot)
            snap = self.tmp(self.lo32(self.gpr(rt))) if ra in (1, 31) and k is None else None
            self._words[(ra, simm)] = (rt, i.addr, k[0] if k is not None else None, snap)
            if ra in (1, 31) and self._only_lfd_reads(i, ra, simm):
                return                              # half of an int -> double conversion's double
        if update and ra == 1 and rt == 1 and simm < 0:
            # `stwu r1, -N(r1)`: a new frame (the back-chain word it stores is not modelled)
            self.frames.append(-simm)
            self.set_gpr(1, BinOp("-", Reg("r1", self.W), Const(-simm, self.W), self.W))
            return
        ea = self.addr(ra, simm)
        if update:
            ea = self.tmp(ea)
        self._store(i, rt, ea, size)
        if update:
            self.set_gpr(ra, ea)

    def _lmw(self, i, w, rt, ra, rb, simm, uimm):
        for k, r in enumerate(range(rt, 32)):
            self._load(r, self.addr(ra, simm + 4 * k), 32, False)

    def _stmw(self, i, w, rt, ra, rb, simm, uimm):
        for k, r in enumerate(range(rt, 32)):
            self._store(i, r, self.addr(ra, simm + 4 * k), 32)

    def _vsx_ds(self, i, w, rt, ra, rb, simm, uimm):
        """lxsd / lxssp (opcode 57) and stxsd / stxssp (61): a scalar in a vector register (vs32+)."""
        xo = w & 3
        if xo not in (2, 3):
            raise LiftError("DS-form 57/61")
        ea = self.addr(ra, _sx(w & 0xFFFC, 16))
        r = Reg(f"vs{rt + 32}", 64)
        if w >> 26 == 57:
            v: Expr = Load(ea, 64) if xo == 2 else Intrinsic("fpconv", (Load(ea, 32),), 64)
            self.assign(r, v)
        else:
            self.emit(Store(i.addr, ea, r if xo == 2 else Intrinsic("fpsingle", (r,), 32)))

    def _x_vsxmem(self, i, w, rt, ra, rb, rc):
        """XX1 indexed scalar loads / stores: lxsdx, lxsspx, lxsiwax, lxsiwzx, stxsdx, stxsspx, stxsiwx."""
        xo = (w >> 1) & 0x3FF
        r = Reg(self._vsr(w, rt, 0), 64)
        ea = self.addr_x(ra, rb)
        if xo == 588:
            self.assign(r, Load(ea, 64))
        elif xo == 524:
            self.assign(r, Intrinsic("fpconv", (Load(ea, 32),), 64))
        elif xo in (76, 12):
            self.assign(r, cast("sext" if xo == 76 else "zext", Load(ea, 32), 64))
        elif xo == 716:
            self.emit(Store(i.addr, ea, r))
        elif xo == 652:
            self.emit(Store(i.addr, ea, Intrinsic("fpsingle", (r,), 32)))
        elif xo == 140:
            self.emit(Store(i.addr, ea, cast("low", r, 32)))
        else:
            raise LiftError(f"vsx mem {xo}")

    def _ds_load(self, i, w, rt, ra, rb, simm, uimm):
        xo = w & 3
        d = _sx(w & 0xFFFC, 16)
        if self.W != 64:
            raise LiftError("ld on 32-bit")
        ea = self.addr(ra, d)
        if xo == 1:
            ea = self.tmp(ea)
        self._load(rt, ea, 64 if xo < 2 else 32, xo == 2)
        if xo == 1 and ra != rt:
            self.set_gpr(ra, ea)

    def _ds_store(self, i, w, rt, ra, rb, simm, uimm):
        xo = w & 3
        d = _sx(w & 0xFFFC, 16)
        if self.W != 64:
            raise LiftError("std on 32-bit")
        if xo == 1 and ra == 1 and rt == 1 and d < 0:
            self.frames.append(-d)                  # `stdu r1, -N(r1)`
            self.set_gpr(1, BinOp("-", Reg("r1", 64), Const(-d, 64), 64))
            return
        if rt == 2 and ra == 1 and self.toc is not None:
            return                                  # `std r2, 24(r1)`: the TOC save slot
        ea = self.addr(ra, d)
        if xo == 1:
            ea = self.tmp(ea)
        self._store(i, rt, ea, 64)
        if xo == 1:
            self.set_gpr(ra, ea)

    # ------------------------------------------------------- floating point loads / stores
    def _only_lfd_reads(self, i, base: int, d: int) -> bool:
        """The next straight-line instructions read the stack word at d(base) only through an `lfd`
        of the doubleword holding it (the int -> double idiom, see `_int_to_double`), and that
        `lfd` sees the 0x43300000 word on its high half."""
        a = i.end
        for _ in range(12):
            j = self.an.dis.decode(a)
            if j is None or j.kind != "normal":
                return False
            w = self.word(j)
            op = w >> 26
            if (w >> 16) & 31 == base and op in (32, 33, 34, 35, 36, 37, 38, 40, 42, 44, 46, 47, 48, 50, 52, 54,
                                                  58, 62):
                dd = _sx(w & ~3 if op in (58, 62) else w, 16)
                if op == 50 and dd in (d, d - 4):
                    hi_at = dd if self.big else dd + 4
                    hi = self._words.get((base, hi_at))  # (this store's own entry when it is the high word)
                    if hi is not None and hi[2] is not None and hi[2] & 0xFFFFFFFF == 0x43300000:
                        return True
                    return hi_at != d and self._hi_store_ahead(i, base, hi_at, j.addr)
                size = {34: 1, 38: 1, 40: 2, 42: 2, 44: 2, 48: 4, 52: 4, 50: 8, 54: 8, 58: 8, 62: 8}.get(op, 4)
                if dd < d + 4 and d < dd + size and op not in (36,):
                    return False                    # (another access overlapping the word)
            if op == 31 and (w >> 16) & 31 == base:
                return False                        # an indexed access through the same base
            a = j.end
        return False

    def _hi_store_ahead(self, i, base: int, hi_at: int, end: int) -> bool:
        """Between `i` and `end`, `stw rX, hi_at(base)` of a register holding 0x43300000 now."""
        a = i.end
        while a < end:
            j = self.an.dis.decode(a)
            if j is None:
                return False
            w = self.word(j)
            if w >> 26 == 36 and (w >> 16) & 31 == base and _sx(w, 16) == hi_at:
                k = self._consts.get((w >> 21) & 31)
                return k is not None and k[0] & 0xFFFFFFFF == 0x43300000
            a = j.end
        return False

    def _int_to_double(self, i, ra: int, d: int) -> Expr | None:
        """`stw rH, d(rA); stw rL, d+4(rA); lfd fX, d(rA)` with rH = 0x43300000 (big-endian; the
        words swap on little-endian): the double 2^52 + rL, built in memory -- what 32-bit PowerPC
        converts an integer with (`(double)i` = that - (2^52 + 2^31), for rL = i ^ 0x80000000)."""
        hi_at, lo_at = (d, d + 4) if self.big else (d + 4, d)
        hi, lo = self._words.get((ra, hi_at)), self._words.get((ra, lo_at))
        if hi is None or lo is None or i.addr - lo[1] > 64:
            return None
        # (the high word may be stored once, before a loop that converts one integer per turn)
        if hi[2] is None or hi[2] & 0xFFFFFFFF != 0x43300000 or ra not in (1, 31) and i.addr - hi[1] > 64:
            return None
        if lo[3] is None and self._written.get(lo[0], -1) > lo[1] or self._written.get(ra, -1) > lo[1]:
            return None
        a = lo[1]
        while a < i.addr:                           # (straight-line code between the stores and here)
            j = self.an.dis.decode(a)
            if j is None or j.kind != "normal":
                return None
            a = j.end
        v = lo[3] if lo[3] is not None else self.lo32(self.gpr(lo[0]))
        return BinOp("|", Const(0x4330000000000000, 64), cast("zext", v, 64), 64)

    def _fld_d(self, i, w, rt, ra, rb, simm, uimm):
        op = w >> 26
        single = op in (48, 49)
        if op == 50:
            v0 = self._int_to_double(i, ra, simm)
            if v0 is not None:
                self.assign(Reg(f"f{rt}", 64), v0)
                return
        ea = self.addr(ra, simm)
        if op in (49, 51):
            ea = self.tmp(ea)
        v: Expr = Load(ea, 32 if single else 64)
        if single:
            v = Intrinsic("fpconv", (v,), 64)      # (an FPR holds a single as a double)
        self.assign(Reg(f"f{rt}", 64), v)
        if op in (49, 51):
            self.set_gpr(ra, ea)

    def _fst_d(self, i, w, rt, ra, rb, simm, uimm):
        op = w >> 26
        single = op in (52, 53)
        ea = self.addr(ra, simm)
        if op in (53, 55):
            ea = self.tmp(ea)
        v: Expr = Reg(f"f{rt}", 64)
        if single:
            v = Intrinsic("fpsingle", (v,), 32)
        elif op == 54:
            self._stfd = (ra, simm, rt, i.addr)     # (`fctiwz; stfd; lwz`: see `_load_word_of_fpr`)
            if ra in (1, 31) and self._word_read_back(i, ra, simm):
                return                              # the store only moves the integer to a GPR
        self.emit(Store(i.addr, ea, v))
        if op in (53, 55):
            self.set_gpr(ra, ea)

    # ------------------------------------------------------- rotates
    def _rotate32(self, v: Expr, n: Expr) -> Expr:
        if isinstance(n, Const) and n.value % 32 == 0:
            return v
        return BinOp("rol", v, n, 32)

    def _rlwinm(self, i, w, rt, ra, rb, simm, uimm):
        """rlwinm / rlwnm: rotate the low word, then mask (`slwi`, `srwi`, `clrlwi`, ...)."""
        op = w >> 26
        sh, mb, me, rc = rb, (w >> 6) & 31, (w >> 1) & 31, w & 1
        W = self.W
        m = _rotmask(mb, me, 32)
        last = getattr(self, "_mfcr", None)
        if op == 21 and mb == me and last is not None and last == (rt, i.addr):
            # `mfcr rS; rlwinm rA, rS, sh, b, b`: one condition-register bit
            crbit = (me + sh) % 32
            e0: Expr = cast("zext", self.cr(crbit), 32)
            if me != 31:
                e0 = BinOp("<<", e0, Const(31 - me, 8), 32)
            self.set_gpr(ra, e0 if W == 32 else cast("zext", e0, 64))
            if rc:
                self.record(ra)
            return
        s = self.lo32(self.gpr(rt))
        if op == 23:                                # rlwnm: by a register
            n: Expr = BinOp("&", self.lo32(self.gpr(rb)), Const(31, 32), 32)
            e = BinOp("&", BinOp("rol", s, n, 32), Const(m, 32), 32)
        elif mb <= me and me == 31 - sh and sh:     # slwi: a shift left
            e = BinOp("<<", s, Const(sh, 8), 32)
            if m != (mask(32) << sh) & mask(32):
                e = BinOp("&", e, Const(m, 32), 32)
        elif mb <= me and me == 31 and sh and mb == 32 - sh:     # srwi: a shift right
            e = BinOp(">>u", s, Const(mb, 8), 32)
        elif mb <= me and me == 31 and sh and mb > 32 - sh:      # extrwi: shift right, then mask
            e = BinOp("&", BinOp(">>u", s, Const(32 - sh, 8), 32), Const(m, 32), 32)
        elif sh == 0:                               # clrlwi / clrrwi / a mask
            e = s if m == mask(32) else BinOp("&", s, Const(m, 32), 32)
        else:
            r = self._rotate32(s, Const(sh, 8))
            e = r if m == mask(32) else BinOp("&", r, Const(m, 32), 32)
        self.set_gpr(ra, e if W == 32 else cast("zext", e, 64))
        if rc:
            self.record(ra)

    def _rlwimi(self, i, w, rt, ra, rb, simm, uimm):
        sh, mb, me, rc = rb, (w >> 6) & 31, (w >> 1) & 31, w & 1
        m = _rotmask(mb, me, 32)
        s = self._rotate32(self.lo32(self.gpr(rt)), Const(sh, 8))
        cur = self.lo32(self.gpr(ra))
        e = BinOp("|", BinOp("&", s, Const(m, 32), 32), BinOp("&", cur, Const(~m & mask(32), 32), 32), 32)
        if self.W == 64:
            hi = BinOp("&", self.gpr(ra), Const(mask(64) ^ mask(32), 64), 64)
            e = BinOp("|", hi, cast("zext", e, 64), 64)
        self.set_gpr(ra, e)
        if rc:
            self.record(ra)

    def _rld(self, i, w, rt, ra, rb, simm, uimm):
        """64-bit rotates: rldicl / rldicr / rldic / rldimi (sh = 6 bits, mb / me = 6 bits)."""
        if self.W != 64:
            raise LiftError("rld on 32-bit")
        xo = (w >> 2) & 7
        sh = ((w >> 11) & 31) | (((w >> 1) & 1) << 5)
        mx = (w >> 5) & 63
        mb = ((mx & 1) << 5) | (mx >> 1)
        rc = w & 1
        s = self.gpr(rt)
        if xo in (4, 5):                            # rldcl / rldcr (by a register): opaque
            raise LiftError("rldcl")
        rot = s if sh == 0 else BinOp("rol", s, Const(sh, 8), 64)
        if xo == 0:                                 # rldicl: mask mb..63
            m = mask(64 - mb)
            if sh and mb == 64 - sh:                # srdi
                e: Expr = BinOp(">>u", s, Const(mb, 8), 64)
            elif sh == 0:
                e = BinOp("&", s, Const(m, 64), 64) if mb else s
            else:
                e = BinOp("&", rot, Const(m, 64), 64) if mb else rot
                if mb and mb > 64 - sh:             # extrdi
                    e = BinOp("&", BinOp(">>u", s, Const(64 - sh, 8), 64), Const(m, 64), 64)
        elif xo == 1:                               # rldicr: mask 0..me (me encoded in mb's field)
            me = mb
            m = (mask(64) << (63 - me)) & mask(64)
            if sh and me == 63 - sh:                # sldi
                e = BinOp("<<", s, Const(sh, 8), 64)
            else:
                e = BinOp("&", rot, Const(m, 64), 64)
        elif xo == 2:                               # rldic: mask mb..63-sh
            m = _rotmask(mb, 63 - sh, 64)
            e = BinOp("&", BinOp("<<", s, Const(sh, 8), 64) if sh else s, Const(m, 64), 64)
        elif xo == 3:                               # rldimi
            m = _rotmask(mb, 63 - sh, 64)
            cur = self.gpr(ra)
            e = BinOp("|", BinOp("&", rot, Const(m, 64), 64), BinOp("&", cur, Const(~m & mask(64), 64), 64), 64)
        else:
            raise LiftError(f"rld xo {xo}")
        self.set_gpr(ra, e)
        if rc:
            self.record(ra)

    # ------------------------------------------------------- opcode 31
    def _x31(self, i, w, rt, ra, rb, simm, uimm):
        xo10 = (w >> 1) & 0x3FF
        xo9 = (w >> 1) & 0x1FF
        rc = w & 1
        h = _X31.get(xo10) or _XO31.get(xo9)
        if h is None:
            if xo10 in _X31_NOPS:
                return
            raise LiftError(f"x31 {xo10}")
        getattr(self, h)(i, w, rt, ra, rb, rc)

    def _arith(self, op: str, rt, ra, rb, rc, word=False):
        W = self.W
        a, b = self.gpr(ra), self.gpr(rb)
        if word and W == 64:
            e: Expr = cast("sext", BinOp(op, self.lo32(a), self.lo32(b), 32), 64)
        else:
            e = BinOp(op, a, b, W)
        self.set_gpr(rt, e)
        if rc:
            self.record(rt)

    def _x_add(self, i, w, rt, ra, rb, rc):
        self._arith("+", rt, ra, rb, rc)

    def _x_subf(self, i, w, rt, ra, rb, rc):
        self._arith("-", rt, rb, ra, rc)             # subf rt, ra, rb = rb - ra

    def _x_addc(self, i, w, rt, ra, rb, rc):
        W = self.W
        a, b = self.gpr(ra), self.gpr(rb)
        s = self.tmp(BinOp("+", a, b, W))
        self.assign(Reg("ca", 1), BinOp("<u", s, a, 1))
        self.set_gpr(rt, s)
        if rc:
            self.record(rt)

    def _x_subfc(self, i, w, rt, ra, rb, rc):
        W = self.W
        a, b = self.gpr(ra), self.gpr(rb)
        self.assign(Reg("ca", 1), BinOp("<=u", a, b, 1))
        self.set_gpr(rt, BinOp("-", b, a, W))
        if rc:
            self.record(rt)

    def _x_adde(self, i, w, rt, ra, rb, rc):
        W = self.W
        a, b = self.gpr(ra), self.gpr(rb)
        ca = cast("zext", Reg("ca", 1), W)
        s = self.tmp(BinOp("+", BinOp("+", a, b, W), ca, W))
        self.assign(Reg("ca", 1), Intrinsic("__carry_add", (a, b, Reg("ca", 1)), 1))
        self.set_gpr(rt, s)
        if rc:
            self.record(rt)

    def _x_subfe(self, i, w, rt, ra, rb, rc):
        W = self.W
        a, b = self.gpr(ra), self.gpr(rb)
        ca = cast("zext", Reg("ca", 1), W)
        s = self.tmp(BinOp("+", BinOp("+", UnOp("~", a, W), b, W), ca, W))
        self.assign(Reg("ca", 1), Intrinsic("__carry_add", (UnOp("~", a, W), b, Reg("ca", 1)), 1))
        self.set_gpr(rt, s)
        if rc:
            self.record(rt)

    def _x_addze(self, i, w, rt, ra, rb, rc):
        W = self.W
        a = self.gpr(ra)
        s = self.tmp(BinOp("+", a, cast("zext", Reg("ca", 1), W), W))
        self.assign(Reg("ca", 1), BinOp("<u", s, a, 1))
        self.set_gpr(rt, s)
        if rc:
            self.record(rt)

    def _x_addme(self, i, w, rt, ra, rb, rc):
        W = self.W
        a = self.gpr(ra)
        s = BinOp("-", BinOp("+", a, cast("zext", Reg("ca", 1), W), W), Const(1, W), W)
        self.set_gpr(rt, s)
        if rc:
            self.record(rt)

    def _x_subfze(self, i, w, rt, ra, rb, rc):
        W = self.W
        a = self.gpr(ra)
        self.set_gpr(rt, BinOp("+", UnOp("~", a, W), cast("zext", Reg("ca", 1), W), W))
        if rc:
            self.record(rt)

    def _x_neg(self, i, w, rt, ra, rb, rc):
        W = self.W
        self.set_gpr(rt, BinOp("-", Const(0, W), self.gpr(ra), W))
        if rc:
            self.record(rt)

    def _x_mullw(self, i, w, rt, ra, rb, rc):
        self._arith("*", rt, ra, rb, rc, word=True)

    def _x_mulld(self, i, w, rt, ra, rb, rc):
        self._arith("*", rt, ra, rb, rc)

    def _mulh(self, rt, ra, rb, rc, bits: int, signed: bool):
        kind = "sext" if signed else "zext"
        a, b = self.gpr(ra), self.gpr(rb)
        if bits == 32 and self.W == 64:
            a, b = self.lo32(a), self.lo32(b)
        p = BinOp("*", cast(kind, a, 2 * bits), cast(kind, b, 2 * bits), 2 * bits)
        hi = cast("low", BinOp(">>u", p, Const(bits, 8), 2 * bits), bits)
        self.set_gpr(rt, hi if bits == self.W else cast("sext" if signed else "zext", hi, self.W))
        if rc:
            self.record(rt)

    def _x_mulhw(self, i, w, rt, ra, rb, rc):
        self._mulh(rt, ra, rb, rc, 32, True)

    def _x_mulhwu(self, i, w, rt, ra, rb, rc):
        self._mulh(rt, ra, rb, rc, 32, False)

    def _x_mulhd(self, i, w, rt, ra, rb, rc):
        self._mulh(rt, ra, rb, rc, 64, True)

    def _x_mulhdu(self, i, w, rt, ra, rb, rc):
        self._mulh(rt, ra, rb, rc, 64, False)

    def _x_divw(self, i, w, rt, ra, rb, rc):
        self._arith("/s", rt, ra, rb, rc, word=True)

    def _x_divwu(self, i, w, rt, ra, rb, rc):
        W = self.W
        if W == 64:
            self.set_gpr(rt, cast("zext", BinOp("/u", self.lo32(self.gpr(ra)), self.lo32(self.gpr(rb)), 32), 64))
            if rc:
                self.record(rt)
            return
        self._arith("/u", rt, ra, rb, rc)

    def _x_divd(self, i, w, rt, ra, rb, rc):
        self._arith("/s", rt, ra, rb, rc)

    def _x_divdu(self, i, w, rt, ra, rb, rc):
        self._arith("/u", rt, ra, rb, rc)

    def _x_modsw(self, i, w, rt, ra, rb, rc):
        self._arith("%s", rt, ra, rb, False, word=True)

    def _x_moduw(self, i, w, rt, ra, rb, rc):
        self._arith("%u", rt, ra, rb, False, word=True)

    def _logic(self, op: str, rs, ra, rb, rc, invert=False, neg_b=False):
        W = self.W
        a, b = self.gpr(rs), self.gpr(rb)
        if neg_b:
            b = UnOp("~", b, W)
        if op == "|" and rs == rb and not invert and not neg_b:
            e: Expr = a                              # mr
        else:
            e = BinOp(op, a, b, W)
        if invert:
            e = UnOp("~", e, W)
        self.set_gpr(ra, e)
        if rc:
            self.record(ra)

    # X-form logical: rS is the first field, rA the destination
    def _x_and(self, i, w, rs, ra, rb, rc):
        self._logic("&", rs, ra, rb, rc)

    def _x_andc(self, i, w, rs, ra, rb, rc):
        self._logic("&", rs, ra, rb, rc, neg_b=True)

    def _x_or(self, i, w, rs, ra, rb, rc):
        self._logic("|", rs, ra, rb, rc)

    def _x_orc(self, i, w, rs, ra, rb, rc):
        self._logic("|", rs, ra, rb, rc, neg_b=True)

    def _x_xor(self, i, w, rs, ra, rb, rc):
        self._logic("^", rs, ra, rb, rc)

    def _x_nand(self, i, w, rs, ra, rb, rc):
        self._logic("&", rs, ra, rb, rc, invert=True)

    def _x_nor(self, i, w, rs, ra, rb, rc):
        if rs == rb:                                 # not
            W = self.W
            self.set_gpr(ra, UnOp("~", self.gpr(rs), W))
            if rc:
                self.record(ra)
            return
        self._logic("|", rs, ra, rb, rc, invert=True)

    def _x_eqv(self, i, w, rs, ra, rb, rc):
        self._logic("^", rs, ra, rb, rc, invert=True)

    def _shift_w(self, op: str, rs, ra, rb, rc):
        """slw / srw / sraw: by the low 6 bits of rB (32 and over: 0, or the sign for sraw)."""
        W = self.W
        s = self.lo32(self.gpr(rs))
        n = BinOp("&", self.lo32(self.gpr(rb)), Const(63, 32), 32)
        big = BinOp("<u", Const(31, 32), n, 1)
        sh = BinOp(op, s, BinOp("&", n, Const(31, 32), 32), 32)
        over = BinOp(">>s", s, Const(31, 8), 32) if op == ">>s" else Const(0, 32)
        e: Expr = Ite(big, over, sh, 32)
        self.set_gpr(ra, e if W == 32 else cast("sext" if op == ">>s" else "zext", e, 64))
        if op == ">>s":
            self.assign(Reg("ca", 1), Const(0, 1))   # (the carry of a negative shift: not modelled)
        if rc:
            self.record(ra)

    def _x_slw(self, i, w, rs, ra, rb, rc):
        self._shift_w("<<", rs, ra, rb, rc)

    def _x_srw(self, i, w, rs, ra, rb, rc):
        self._shift_w(">>u", rs, ra, rb, rc)

    def _x_sraw(self, i, w, rs, ra, rb, rc):
        self._shift_w(">>s", rs, ra, rb, rc)

    def _x_srawi(self, i, w, rs, ra, rb, rc):
        W = self.W
        s = self.lo32(self.gpr(rs))
        e: Expr = BinOp(">>s", s, Const(rb, 8), 32) if rb else s
        # ca: set when s is negative and any 1 bit was shifted out (`srawi; addze` = signed division)
        self.assign(Reg("ca", 1), BinOp("&", BinOp("<s", s, Const(0, 32), 1),
                                        BinOp("!=", BinOp("&", s, Const(mask(rb), 32), 32), Const(0, 32), 1), 1)
                    if rb else Const(0, 1))
        self.set_gpr(ra, e if W == 32 else cast("sext", e, 64))
        if rc:
            self.record(ra)

    def _shift_d(self, op: str, rs, ra, rb, rc):
        s = self.gpr(rs)
        n = BinOp("&", self.gpr(rb), Const(127, 64), 64)
        big = BinOp("<u", Const(63, 64), n, 1)
        sh = BinOp(op, s, BinOp("&", n, Const(63, 64), 64), 64)
        over = BinOp(">>s", s, Const(63, 8), 64) if op == ">>s" else Const(0, 64)
        self.set_gpr(ra, Ite(big, over, sh, 64))
        if rc:
            self.record(ra)

    def _x_sld(self, i, w, rs, ra, rb, rc):
        self._shift_d("<<", rs, ra, rb, rc)

    def _x_srd(self, i, w, rs, ra, rb, rc):
        self._shift_d(">>u", rs, ra, rb, rc)

    def _x_srad(self, i, w, rs, ra, rb, rc):
        self._shift_d(">>s", rs, ra, rb, rc)

    def _x_sradi(self, i, w, rs, ra, rb, rc):
        sh = rb | (((w >> 1) & 1) << 5)
        s = self.gpr(rs)
        self.assign(Reg("ca", 1), BinOp("&", BinOp("<s", s, Const(0, 64), 1),
                                        BinOp("!=", BinOp("&", s, Const(mask(sh), 64), 64), Const(0, 64), 1), 1)
                    if sh else Const(0, 1))
        self.set_gpr(ra, BinOp(">>s", s, Const(sh, 8), 64) if sh else s)
        if rc:
            self.record(ra)

    def _x_extswsli(self, i, w, rs, ra, rb, rc):
        """extswsli (POWER9): sign-extend the low word, then shift left (sh: 6 bits)."""
        sh = rb | (((w >> 1) & 1) << 5)
        v = cast("sext", self.lo32(self.gpr(rs)), 64)
        self.set_gpr(ra, BinOp("<<", v, Const(sh, 8), 64) if sh else v)
        if rc:
            self.record(ra)

    # VSX moves between GPRs and FPRs (vs0-vs31 are f0-f31; their doubleword 0 is the FPR)
    def _vsr(self, w, n: int, xbit: int) -> str:
        """VSX register n (plus 32 when its extension bit is set): vs0-31 are the FPRs, vs32-63
        (the vector registers) hold scalars in their doubleword 0 too (POWER9 `lxsd v12`)."""
        return f"vs{n + 32}" if (w >> xbit) & 1 else f"f{n}"

    def _x_mfvsrd(self, i, w, rs, ra, rb, rc):
        v = Reg(self._vsr(w, rs, 0), 64)
        self.set_gpr(ra, v if self.W == 64 else cast("low", v, 32))

    def _x_mtvsrd(self, i, w, rt, ra, rb, rc):
        self.assign(Reg(self._vsr(w, rt, 0), 64), cast("zext", self.gpr(ra), 64))

    def _x_mtvsrwa(self, i, w, rt, ra, rb, rc):
        self.assign(Reg(self._vsr(w, rt, 0), 64), cast("sext", self.lo32(self.gpr(ra)), 64))

    def _x_mtvsrwz(self, i, w, rt, ra, rb, rc):
        self.assign(Reg(self._vsr(w, rt, 0), 64), cast("zext", self.lo32(self.gpr(ra)), 64))

    def _x_mfvsrwz(self, i, w, rs, ra, rb, rc):
        self.set_gpr(ra, cast("zext", cast("low", Reg(self._vsr(w, rs, 0), 64), 32), self.W))

    def _x_cntlzw(self, i, w, rs, ra, rb, rc):
        self.set_gpr(ra, cast("zext", Intrinsic("clz", (self.lo32(self.gpr(rs)),), 32), self.W))
        if rc:
            self.record(ra)

    def _x_cntlzd(self, i, w, rs, ra, rb, rc):
        self.set_gpr(ra, Intrinsic("clzll", (self.gpr(rs),), 64))
        if rc:
            self.record(ra)

    def _ext(self, rs, ra, rc, bits):
        self.set_gpr(ra, cast("sext", cast("low", self.gpr(rs), bits), self.W))
        if rc:
            self.record(ra)

    def _x_extsb(self, i, w, rs, ra, rb, rc):
        self._ext(rs, ra, rc, 8)

    def _x_extsh(self, i, w, rs, ra, rb, rc):
        self._ext(rs, ra, rc, 16)

    def _x_extsw(self, i, w, rs, ra, rb, rc):
        self._ext(rs, ra, rc, 32)

    def _x_cmp(self, i, w, rt, ra, rb, rc):
        bf, l64 = rt >> 2, rt & 1
        signed = (w >> 1) & 0x3FF == 0
        a, b = self.gpr(ra), self.gpr(rb)
        if not l64 and self.W == 64:
            a, b = self.lo32(a), self.lo32(b)
        self.set_cr_cmp(bf, a, b, signed)

    _x_cmpl = _x_cmp

    # indexed loads / stores: xo -> (bits, signed, update, store)
    _XMEM = {23: (32, False, False, False), 55: (32, False, True, False), 87: (8, False, False, False),
             119: (8, False, True, False), 279: (16, False, False, False), 311: (16, False, True, False),
             343: (16, True, False, False), 375: (16, True, True, False), 21: (64, False, False, False),
             53: (64, False, True, False), 341: (32, True, False, False), 373: (32, True, True, False),
             151: (32, False, False, True), 183: (32, False, True, True), 215: (8, False, False, True),
             247: (8, False, True, True), 407: (16, False, False, True), 439: (16, False, True, True),
             149: (64, False, False, True), 181: (64, False, True, True),
             20: (32, False, False, False), 84: (64, False, False, False)}       # lwarx / ldarx

    def _x_mem(self, i, w, rt, ra, rb, rc):
        size, signed, update, store = self._XMEM[(w >> 1) & 0x3FF]
        if size > self.W:
            raise LiftError("64-bit access on 32-bit")
        ea = self.addr_x(ra, rb)
        if update:
            ea = self.tmp(ea)
        if store:
            self._store(i, rt, ea, size)
        else:
            self._load(rt, ea, size, signed)
        if update:
            self.set_gpr(ra, ea)

    # indexed floating-point loads / stores: xo -> (bits, store, update, how)
    _XFMEM = {535: (32, False, False, "single"), 567: (32, False, True, "single"),
              599: (64, False, False, "double"), 631: (64, False, True, "double"),
              663: (32, True, False, "single"), 695: (32, True, True, "single"),
              727: (64, True, False, "double"), 759: (64, True, True, "double"),
              855: (32, False, False, "sext"), 887: (32, False, False, "zext"), 983: (32, True, False, "word")}

    def _x_fmem(self, i, w, rt, ra, rb, rc):
        """lfsx / lfdx / stfsx / stfdx (and update forms); lfiwax / lfiwzx (an integer word into
        an FPR, for `fcfid`); stfiwx (an FPR's low word to memory)."""
        bits, store, update, how = self._XFMEM[(w >> 1) & 0x3FF]
        ea = self.addr_x(ra, rb)
        if update:
            ea = self.tmp(ea)
        f = Reg(f"f{rt}", 64)
        if store:
            v: Expr = f if how == "double" else Intrinsic("fpsingle", (f,), 32) if how == "single" \
                else cast("low", f, 32)
            self.emit(Store(i.addr, ea, v))
        else:
            v = Load(ea, bits)
            if how == "single":
                v = Intrinsic("fpconv", (v,), 64)
            elif how in ("sext", "zext"):
                v = cast(how, v, 64)
            self.assign(f, v)
        if update:
            self.set_gpr(ra, ea)

    def _x_stcx(self, i, w, rt, ra, rb, rc):
        """stwcx. / stdcx.: the store, taken to succeed (cr0.eq = 1)."""
        size = 32 if (w >> 1) & 0x3FF == 150 else 64
        self._store(i, rt, self.addr_x(ra, rb), size)
        for k, v in enumerate((0, 0, 1, 0)):
            self.assign(Reg(f"cr0_{_CR_BITS[k]}", 1), Const(v, 1))

    _SPR = {8: "lr", 9: "ctr"}

    def _x_mfspr(self, i, w, rt, ra, rb, rc):
        spr = ((w >> 16) & 31) | (((w >> 11) & 31) << 5)
        name = self._SPR.get(spr)
        if name is None:
            raise LiftError(f"mfspr {spr}")
        self.set_gpr(rt, Reg(name, self.W))

    def _x_mtspr(self, i, w, rt, ra, rb, rc):
        spr = ((w >> 16) & 31) | (((w >> 11) & 31) << 5)
        name = self._SPR.get(spr)
        if name is None:
            raise LiftError(f"mtspr {spr}")
        self.assign(Reg(name, self.W), self.gpr(rt))

    def _x_isel(self, i, w, rt, ra, rb, rc):
        bc = (w >> 6) & 31
        self.set_gpr(rt, Ite(self.cr(bc), self.ra0(ra), self.gpr(rb), self.W))

    def _x_mfcr(self, i, w, rt, ra, rb, rc):
        """The condition register as a word: cr0 in the top four bits (lt, gt, eq, so), cr7 in the
        lowest. A following `rlwinm` that keeps one bit reads that CR bit directly."""
        W = self.W
        e: Expr | None = None
        for n in range(8):
            for k, b in enumerate(_CR_BITS):
                bit = 31 - (4 * n + k)
                t: Expr = cast("zext", Reg(f"cr{n}_{b}", 1), 32)
                if bit:
                    t = BinOp("<<", t, Const(bit, 8), 32)
                e = t if e is None else BinOp("|", e, t, 32)
        self.set_gpr(rt, e if W == 32 else cast("zext", e, 64))
        self._mfcr = (rt, i.end)

    def _x_sync(self, i, w, rt, ra, rb, rc):
        pass

    def _x_tw(self, i, w, rt, ra, rb, rc):
        if rt == 31:
            self.emit(Effect(i.addr, "trap", ()))
            return
        raise LiftError("conditional trap")

    # ------------------------------------------------------- floating point (opcodes 59 / 63)
    def _fp(self, i, w, rt, ra, rb, simm, uimm):
        op = w >> 26
        single = op == 59
        xo5 = (w >> 1) & 31
        xo10 = (w >> 1) & 0x3FF
        rc_ = (w >> 6) & 31
        F = 64
        P = 32 if single else 64                    # the precision the operation rounds to

        def f(n):
            """An operand: single-precision operations read their (float-valued) inputs as floats."""
            r = Reg(f"f{n}", F)
            return Intrinsic("fpsingle", (r,), 32) if single else r

        def put(e):
            if e.bits == 32:
                e = Intrinsic("fpconv", (e,), 64)  # (an FPR holds a single as a double)
            self.assign(Reg(f"f{rt}", F), e)

        arith = {21: "f+", 20: "f-", 18: "f/"}
        if xo5 in arith:
            put(BinOp(arith[xo5], f(ra), f(rb), P))
            return
        if xo5 == 25:                               # fmul frt, fra, frc
            put(BinOp("f*", f(ra), f(rc_), P))
            return
        if xo5 in (28, 29, 30, 31):                 # fmsub / fmadd / fnmsub / fnmadd
            a, c, b = f(ra), f(rc_), f(rb)
            e: Expr = Intrinsic("fma" if P == 64 else "fmaf", (a, c, UnOp("fneg", b, P) if xo5 in (28, 30) else b), P)
            if xo5 in (30, 31):
                e = UnOp("fneg", e, P)
            put(e)
            return
        if xo5 == 22:                               # fsqrt / fsqrts
            put(Intrinsic("sqrt" if P == 64 else "sqrtf", (f(rb),), P))
            return
        if op != 63:
            raise LiftError(f"fp {op}/{xo5}")
        if xo10 == 72:                              # fmr
            self.assign(Reg(f"f{rt}", F), f(rb))
        elif xo10 == 40:                            # fneg
            self.assign(Reg(f"f{rt}", F), UnOp("fneg", f(rb), F))
        elif xo10 == 264:                           # fabs
            self.assign(Reg(f"f{rt}", F), Intrinsic("fabs", (f(rb),), F))
        elif xo10 == 12:                            # frsp: round to single
            self.assign(Reg(f"f{rt}", F), Intrinsic("fpconv", (Intrinsic("fpconv", (f(rb),), 32),), 64))
        elif xo10 in (15, 14, 815, 814, 143, 942, 943):
            # fctiwz / fctiw / fctidz / fctid / fctiwuz / fctidu(z): the integer in the FPR's bits
            signed = xo10 in (15, 14, 815, 814)
            bits = 64 if xo10 in (815, 814, 942, 943) else 32
            v = Intrinsic("fptosi" if signed else "fptoui", (f(rb),), bits)
            # the integer is the register's low bits (stored with `stfd`, read back with `lwz`)
            self.assign(Reg(f"f{rt}", F), cast("zext", v, F) if bits < F else v)
        elif xo10 in (846, 974):                    # fcfid / fcfidu: a 64-bit integer's bits -> double
            self.assign(Reg(f"f{rt}", F), Intrinsic("sitofp" if xo10 == 846 else "uitofp", (f(rb),), F))
        elif xo10 in (0, 32):                       # fcmpu / fcmpo
            bf = rt >> 2
            a, b = f(ra), f(rb)
            self.assign(Reg(f"cr{bf}_lt", 1), BinOp("f<", a, b, 1))
            self.assign(Reg(f"cr{bf}_gt", 1), BinOp("f<", b, a, 1))
            self.assign(Reg(f"cr{bf}_eq", 1), BinOp("f==", a, b, 1))
            self.assign(Reg(f"cr{bf}_so", 1), Const(0, 1))
        elif xo10 in (583, 711, 38, 70, 134):       # mffs / mtfsf / mtfsb1 / mtfsb0 / mtfsfi
            raise LiftError("fpscr")
        else:
            raise LiftError(f"fp xo {xo10}")

    # ------------------------------------------------------- VSX scalar (opcode 60)
    def _vsx(self, i, w, rt, ra, rb, simm, uimm):
        """The scalar double / single VSX forms gcc emits for POWER8+: arithmetic, compares and
        selects, conversions -- on vs0-vs31, which are the FPRs."""
        F = 64

        def vs(n, xbit):
            return Reg(self._vsr(w, n, xbit), F)
        t = self._vsr(w, rt, 0)
        if (w >> 4) & 3 == 3:                       # XX4: xxsel T, A, B, C
            rc_ = (w >> 6) & 31
            a, b = vs(ra, 2), vs(rb, 1)
            cname = self._vsr(w, rc_, 3)
            cond = self._vsx_masks.get(cname)
            if cond is not None:
                self.assign(Reg(t, F), Ite(cond, b, a, F))
            else:
                c = Reg(cname, F)
                self.assign(Reg(t, F), BinOp("|", BinOp("&", a, UnOp("~", c, F), F), BinOp("&", b, c, F), F))
            self._vsx_masks.pop(t, None)
            return
        xo8 = (w >> 3) & 0xFF
        xo9 = (w >> 2) & 0x1FF
        self._vsx_masks.pop(t, None)
        a, b = (lambda: vs(ra, 2)), (lambda: vs(rb, 1))
        arith = {32: ("f+", 64), 40: ("f-", 64), 48: ("f*", 64), 56: ("f/", 64),
                 0: ("f+", 32), 8: ("f-", 32), 16: ("f*", 32), 24: ("f/", 32)}
        if xo8 in arith:
            op, p = arith[xo8]
            x, y = a(), b()
            if p == 32:
                x, y = Intrinsic("fpsingle", (x,), 32), Intrinsic("fpsingle", (y,), 32)
            e: Expr = BinOp(op, x, y, p)
            self.assign(Reg(t, F), e if p == 64 else Intrinsic("fpconv", (e,), 64))
            return
        if xo8 in (154, 146) and ra == rb and not (w >> 2) & 1 ^ (w >> 1) & 1:
            if xo8 == 154:                          # xxlxor T, A, A: 0.0
                self.assign(Reg(t, F), Const(0, F))
            else:                                   # xxlor T, A, A: a copy
                self.assign(Reg(t, F), a())
            return
        cmps = {3: "f==", 11: "f>", 19: "f>="}
        if xo8 in cmps:                             # xscmp{eq,gt,ge}dp: an all-ones / zero mask
            x, y = a(), b()
            cond = BinOp("f<", y, x, 1) if cmps[xo8] == "f>" else BinOp("f<=", y, x, 1) \
                if cmps[xo8] == "f>=" else BinOp("f==", x, y, 1)
            c = self.tmp(cond)
            self._vsx_masks[t] = c
            self.assign(Reg(t, F), Ite(c, Const(mask(F), F), Const(0, F), F))
            return
        if xo8 in (33, 41, 49, 57, 161, 169, 177, 185):  # xs(n)m{add,sub}{a,m}dp
            neg = xo8 >= 161
            sub = xo8 in (49, 57, 177, 185)
            mform = xo8 in (41, 57, 169, 185)
            x, tt, y = a(), Reg(t, F), b()
            # A-form: T = A*B + T (the target is the addend); M-form: T = A*T + B (the multiplicand)
            m1, m2, add = (x, tt, y) if mform else (x, y, tt)
            e = Intrinsic("fma", (m1, m2, UnOp("fneg", add, F) if sub else add), F)
            self.assign(Reg(t, F), UnOp("fneg", e, F) if neg else e)
            return
        conv = {344: ("fptosi", 64), 328: ("fptoui", 64), 88: ("fptosi", 32), 72: ("fptoui", 32)}
        if xo9 in conv:
            kind, bits = conv[xo9]
            v = Intrinsic(kind, (b(),), bits)
            self.assign(Reg(t, F), v if bits == 64 else cast("zext", v, 64))
            return
        if xo9 in (376, 360):                       # xscvsxddp / xscvuxddp
            self.assign(Reg(t, F), Intrinsic("sitofp" if xo9 == 376 else "uitofp", (b(),), F))
            return
        if xo9 in (312, 296):                       # xscvsxdsp / xscvuxdsp: rounded to single
            v = Intrinsic("sitofp" if xo9 == 312 else "uitofp", (b(),), 32)
            self.assign(Reg(t, F), Intrinsic("fpconv", (v,), 64))
            return
        if xo9 == 265:                              # xscvdpsp: round to single (the double form kept)
            self.assign(Reg(t, F), Intrinsic("fpconv", (Intrinsic("fpconv", (b(),), 32),), 64))
            return
        if xo9 == 329:                              # xscvspdp: already the double form
            self.assign(Reg(t, F), b())
            return
        unary = {345: "fabs", 377: "fneg", 75: "sqrt"}
        if xo9 in unary:
            name = unary[xo9]
            self.assign(Reg(t, F), UnOp("fneg", b(), F) if name == "fneg" else Intrinsic(name, (b(),), F))
            return
        raise LiftError(f"vsx {xo8}/{xo9}")

    # ------------------------------------------------------- condition register
    def _x19(self, i, w, rt, ra, rb, simm, uimm):
        xo = (w >> 1) & 0x3FF
        if xo in (16, 528):                         # bclr / bcctr outside a block end
            if i.kind == "ret":
                self.emit(Return(i.addr))
                return
            if i.kind == "call":
                target = Reg("lr", self.W) if xo == 16 else Reg("ctr", self.W)
                self._call(i, self.tmp(target))
                return
            if i.kind == "cjmp" and xo == 16:
                self._cond_return(i, w)
                return
            raise LiftError("indirect jump outside a block end")
        if xo == 150:                               # isync
            return
        if xo == 0:                                 # mcrf
            for k in range(4):
                self.assign(Reg(f"cr{rt >> 2}_{_CR_BITS[k]}", 1), Reg(f"cr{ra >> 2}_{_CR_BITS[k]}", 1))
            return
        ops = {257: "&", 449: "|", 193: "^", 225: "~&", 33: "~|", 289: "~^", 129: "&~", 417: "|~"}
        o = ops.get(xo)
        if o is None:
            raise LiftError(f"x19 {xo}")
        a, b = self.cr(ra), self.cr(rb)
        if o in ("^", "~^") and ra == rb:           # crclr / crset
            self.assign(self.cr(rt), Const(1 if o == "~^" else 0, 1))
            return
        if o.endswith("~"):
            b = UnOp("!", b, 1)
            o = o[0]
        e: Expr = BinOp(o[-1], a, b, 1)
        if o.startswith("~"):
            e = UnOp("!", e, 1)
        self.assign(self.cr(rt), e)

    # ------------------------------------------------------- branches
    def _condition(self, bo: int, bi: int) -> Expr | None:
        """The taken-condition of BO / BI, after decrementing ctr when BO says so (None: always)."""
        conds = []
        W = self.W
        if not bo & 0x04:                           # decrement ctr, test it
            self.assign(Reg("ctr", W), BinOp("-", Reg("ctr", W), Const(1, W), W))
            conds.append(BinOp("==" if bo & 0x02 else "!=", Reg("ctr", W), Const(0, W), 1))
        if not bo & 0x10:                           # test a CR bit
            bit = self.cr(bi)
            conds.append(bit if bo & 0x08 else UnOp("!", bit, 1))
        if not conds:
            return None
        e = conds[0]
        for c in conds[1:]:
            e = BinOp("&", e, c, 1)
        return e

    def _bc(self, i, w, rt, ra, rb, simm, uimm):
        if w & 1:                                   # bcl
            if i.kind == "normal":                  # `bcl 20,31,.+4`: lr = the next address
                self.assign(Reg("lr", self.W), Const(i.end, self.W))
                return
            cond = self._condition(rt, ra)
            if cond is not None:
                raise LiftError("conditional call")
            self._call(i, Const(i.target, self.W))
            return
        cond = self._condition(rt, ra)
        if cond is None:
            self.emit(Jump(i.addr, i.target))
            return
        test = self.tmp(cond)
        self.emit(Branch(i.addr, test, i.target, i.end))

    def _cond_return(self, i, w):
        bo, bi = (w >> 21) & 31, (w >> 16) & 31
        cond = self._condition(bo, bi)
        synth = i.addr + 1
        self.extra_blocks[synth] = ([Return(i.addr)], [])
        self.emit(Branch(i.addr, self.tmp(cond) if cond is not None else Const(1, 1), synth, i.end))

    def _b(self, i, w, rt, ra, rb, simm, uimm):
        if w & 1:
            self._call(i, Const(i.target, self.W))
        else:
            self.emit(Jump(i.addr, i.target))

    def _sc(self, i, w, rt, ra, rb, simm, uimm):
        W = self.W
        uses = [(r, Reg(r, W)) for r in ("r0", "r3", "r4", "r5", "r6", "r7", "r8")]
        self.emit(Effect(i.addr, "syscall", (), uses, [("r3", Reg("r3", W))]))

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

    def lift_jmp(self, i: Insn, func: "Function") -> list[Stmt]:
        """`b` (a jump or a tail call) or `bctr` (a switch, or a tail call through ctr)."""
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
        w = self.word(i)
        if w >> 26 != 19 or (w >> 1) & 0x3FF != 528:
            return [self.unknown(i)]
        target = self.tmp(Reg("ctr", W))
        table = func.jump_tables.get(i.addr)
        if table:
            seen = list(dict.fromkeys(t for t in table if t in func.blocks))
            self.emit(IndirectJump(i.addr, target, seen, list(table)))
        else:
            self.emit(CallStmt(i.addr, Call(target, (), W), tail=True, name=self.an.call_name(i)))
            self.emit(Return(i.addr))
        return self.out


_PRIMARY = {14: "_addi", 15: "_addis", 12: "_addic", 13: "_addic", 8: "_subfic", 7: "_mulli", 11: "_cmpi",
            10: "_cmpi", 24: "_logic_imm", 25: "_logic_imm", 26: "_logic_imm", 27: "_logic_imm",
            28: "_logic_imm", 29: "_logic_imm", 32: "_ld_d", 33: "_ld_d", 34: "_ld_d", 35: "_ld_d", 40: "_ld_d",
            41: "_ld_d", 42: "_ld_d", 43: "_ld_d", 36: "_st_d", 37: "_st_d", 38: "_st_d", 39: "_st_d",
            44: "_st_d", 45: "_st_d", 46: "_lmw", 47: "_stmw", 58: "_ds_load", 62: "_ds_store",
            48: "_fld_d", 49: "_fld_d", 50: "_fld_d", 51: "_fld_d", 52: "_fst_d", 53: "_fst_d", 54: "_fst_d",
            55: "_fst_d", 21: "_rlwinm", 23: "_rlwinm", 20: "_rlwimi", 30: "_rld", 31: "_x31", 19: "_x19",
            16: "_bc", 18: "_b", 17: "_sc", 59: "_fp", 63: "_fp", 60: "_vsx", 57: "_vsx_ds", 61: "_vsx_ds"}

# opcode 31, 10-bit extended opcodes
_X31 = {28: "_x_and", 60: "_x_andc", 444: "_x_or", 412: "_x_orc", 316: "_x_xor", 476: "_x_nand", 124: "_x_nor",
        284: "_x_eqv", 24: "_x_slw", 536: "_x_srw", 792: "_x_sraw", 824: "_x_srawi", 27: "_x_sld", 539: "_x_srd",
        794: "_x_srad", 826: "_x_sradi", 827: "_x_sradi", 26: "_x_cntlzw", 58: "_x_cntlzd", 954: "_x_extsb",
        922: "_x_extsh", 986: "_x_extsw", 0: "_x_cmp", 32: "_x_cmpl", 339: "_x_mfspr", 467: "_x_mtspr",
        **{xo: "_x_fmem" for xo in (535, 567, 599, 631, 663, 695, 727, 759, 855, 887, 983)},
        **{xo: "_x_vsxmem" for xo in (588, 524, 76, 12, 716, 652, 140)},
        51: "_x_mfvsrd", 179: "_x_mtvsrd", 211: "_x_mtvsrwa", 243: "_x_mtvsrwz", 115: "_x_mfvsrwz",
        890: "_x_extswsli", 891: "_x_extswsli", 19: "_x_mfcr", 598: "_x_sync", 4: "_x_tw", 150: "_x_stcx",
        214: "_x_stcx", 779: "_x_modsw",
        267: "_x_moduw",
        **{xo: "_x_mem" for xo in (23, 55, 87, 119, 279, 311, 343, 375, 21, 53, 341, 373, 151, 183, 215, 247,
                                   407, 439, 149, 181, 20, 84)},
        **{xo: "_x_isel" for xo in range(15, 1024, 32)}}
# opcode 31, 9-bit XO-form opcodes (the OE bit aside)
_XO31 = {266: "_x_add", 10: "_x_addc", 138: "_x_adde", 202: "_x_addze", 234: "_x_addme", 40: "_x_subf",
         8: "_x_subfc", 136: "_x_subfe", 200: "_x_subfze", 104: "_x_neg", 235: "_x_mullw", 75: "_x_mulhw",
         11: "_x_mulhwu", 491: "_x_divw", 459: "_x_divwu", 233: "_x_mulld", 73: "_x_mulhd", 9: "_x_mulhdu",
         489: "_x_divd", 457: "_x_divdu"}
# cache / barrier hints: no effect on the program's values
_X31_NOPS = {278, 246, 54, 86, 470, 1014, 854, 982, 310, 438, 566, 758}

__all__ = ["PpcLifter"]

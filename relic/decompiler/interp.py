"""Concrete IR interpreter.

Used by the tests to check that lifting (and later, optimisation passes)
preserves the meaning of real functions: run the IR on concrete inputs and
compare with what the C source computes.
"""
from __future__ import annotations

from typing import Callable

from .ir import (Assign, BinOp, Branch, Call, CallStmt, Cast, Const, Effect, Expr, Extract, IndirectJump,
                 Intrinsic, IRFunction, Ite, Jump, Load, Reg, Return, Store, UnOp, Unknown, Var, mask)


class InterpError(Exception):
    pass


def _s(v: int, bits: int) -> int:
    v &= mask(bits)
    return v - (1 << bits) if bits and v >> (bits - 1) else v


class Machine:
    """Registers + sparse little-endian memory backed by the binary image."""

    def __init__(self, binary=None):
        self.bin = binary
        self.regs: dict[str, int] = {}
        self.mem: dict[int, int] = {}

    def read(self, addr: int, size: int) -> int:
        out = 0
        for k in range(size):
            a = addr + k
            if a in self.mem:
                b = self.mem[a]
            elif self.bin is not None and self.bin.is_mapped(a):
                data = self.bin.read(a, 1)
                b = data[0] if data else 0
            else:
                raise InterpError(f"read of uninitialised memory at {a:#x}")
            out |= b << (8 * k)
        return out

    def write(self, addr: int, value: int, size: int):
        for k in range(size):
            self.mem[addr + k] = (value >> (8 * k)) & 0xFF

    def write_bytes(self, addr: int, data: bytes):
        for k, b in enumerate(data):
            self.mem[addr + k] = b


CallHook = Callable[["Machine", int], None]


class Interpreter:
    def __init__(self, fn: IRFunction, machine: Machine, call_hook: CallHook | None = None, max_steps=100_000):
        self.fn = fn
        self.m = machine
        self.call_hook = call_hook
        self.max_steps = max_steps

    # ------------------------------------------------------------ exprs
    def eval(self, e: Expr) -> int:
        m = self.m
        if isinstance(e, Const):
            return e.value
        if isinstance(e, (Reg, Var)):
            key = e.name if isinstance(e, Reg) else f"{e.name}_{e.version}"
            if key not in m.regs:
                raise InterpError(f"read of undefined {key}")
            return m.regs[key] & mask(e.bits)
        if isinstance(e, Load):
            return m.read(self.eval(e.addr), e.bits // 8)
        if isinstance(e, BinOp):
            return self._binop(e) & mask(e.bits)
        if isinstance(e, UnOp):
            a = self.eval(e.a)
            if e.op == "-":
                return -a & mask(e.bits)
            if e.op == "~":
                return ~a & mask(e.bits)
            if e.op == "!":
                return int(a == 0)
        if isinstance(e, Cast):
            a = self.eval(e.a)
            if e.kind == "sext":
                return _s(a, e.a.bits) & mask(e.bits)
            return a & mask(e.bits)
        if isinstance(e, Extract):
            return (self.eval(e.a) >> e.lo) & mask(e.bits)
        if isinstance(e, Ite):
            return self.eval(e.a) if self.eval(e.cond) else self.eval(e.b)
        if isinstance(e, Intrinsic):
            return self._intrinsic(e)
        raise InterpError(f"cannot evaluate {e}")

    def _binop(self, e: BinOp) -> int:
        a, b = self.eval(e.a), self.eval(e.b)
        w = e.a.bits
        op = e.op
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        if op == "*":
            return a * b
        if op in ("/u", "%u", "/s", "%s"):
            if b == 0:
                raise InterpError("division by zero")
            if op[1] == "u":
                return a // b if op[0] == "/" else a % b
            sa, sb = _s(a, w), _s(b, e.b.bits)
            q = abs(sa) // abs(sb) * (1 if (sa < 0) == (sb < 0) else -1)
            return q if op[0] == "/" else sa - q * sb
        if op == "&":
            return a & b
        if op == "|":
            return a | b
        if op == "^":
            return a ^ b
        if op == "<<":
            return a << b
        if op == ">>u":
            return a >> b
        if op == ">>s":
            return _s(a, w) >> b
        if op in ("rol", "ror"):
            b %= w
            if op == "ror":
                b = (w - b) % w
            return (a << b | a >> (w - b)) & mask(w)
        if op == "==":
            return int(a == b)
        if op == "!=":
            return int(a != b)
        if op == "<u":
            return int(a < b)
        if op == "<=u":
            return int(a <= b)
        if op == "<s":
            return int(_s(a, w) < _s(b, w))
        if op == "<=s":
            return int(_s(a, w) <= _s(b, w))
        if op == "carry":
            return int(a + b > mask(w))
        if op == "scarry":
            r = _s(a, w) + _s(b, w)
            return int(r != _s(r, w))
        if op == "borrow":
            return int(a < b)
        if op == "sborrow":
            r = _s(a, w) - _s(b, w)
            return int(r != _s(r, w))
        if op == "&&":
            return int(bool(a) and bool(b))
        if op == "||":
            return int(bool(a) or bool(b))
        raise InterpError(f"operator {op}")

    def _intrinsic(self, e: Intrinsic) -> int:
        args = [self.eval(a) for a in e.args]
        if e.name == "parity":
            return int(bin(args[0] & 0xFF).count("1") % 2 == 0)
        if e.name == "smul_overflow":
            w = e.args[0].bits
            r = _s(args[0], w) * _s(args[1], w)
            return int(r != _s(r, w))
        if e.name == "bswap":
            n = e.bits // 8
            return int.from_bytes(args[0].to_bytes(n, "little"), "big")
        if e.name.startswith("shift_cf_"):
            a, n, cf = args
            w = e.args[0].bits
            if n == 0:
                return cf
            op = e.name[len("shift_cf_"):]
            if op == "<<":
                return (a >> (w - n)) & 1 if n <= w else 0
            if op == "rol":
                return ((a << n | a >> (w - n)) & mask(w)) & 1
            if op == "ror":
                return ((a >> n | a << (w - n)) & mask(w)) >> (w - 1)
            if n > w:
                return (a >> (w - 1)) & 1 if op == ">>s" else 0
            return (a >> (n - 1)) & 1
        if e.name == "popcnt":
            return bin(args[0]).count("1")
        raise InterpError(f"intrinsic {e.name}")

    # ------------------------------------------------------- statements
    def run(self) -> int | None:
        """Run from the entry block; returns the address of the Return reached."""
        blk = self.fn.blocks[self.fn.addr]
        steps = 0
        while True:
            nxt = None
            for s in blk.stmts:
                steps += 1
                if steps > self.max_steps:
                    raise InterpError("step limit")
                if isinstance(s, Assign):
                    key = s.dst.name if isinstance(s.dst, Reg) else f"{s.dst.name}_{s.dst.version}"
                    self.m.regs[key] = self.eval(s.src)
                elif isinstance(s, Store):
                    self.m.write(self.eval(s.dst), self.eval(s.src), s.bits // 8)
                elif isinstance(s, Branch):
                    nxt = s.true if self.eval(s.cond) else s.false
                    break
                elif isinstance(s, Jump):
                    nxt = s.target
                    break
                elif isinstance(s, IndirectJump):
                    nxt = self.eval(s.expr)
                    if s.targets and nxt not in s.targets:
                        raise InterpError(f"indirect jump to {nxt:#x} outside its table")
                    break
                elif isinstance(s, Return):
                    return s.addr
                elif isinstance(s, CallStmt):
                    self._call(s.call)
                    if s.tail:
                        continue
                elif isinstance(s, Effect):
                    raise InterpError(f"effect {s.name}")
                elif isinstance(s, Unknown):
                    raise InterpError(f"unknown instruction {s.text}")
            if nxt is None:
                raise InterpError(f"fell off block {blk.addr:#x}")
            if nxt not in self.fn.blocks:
                raise InterpError(f"jump outside function to {nxt:#x}")
            blk = self.fn.blocks[nxt]

    def _call(self, c: Call):
        target = self.eval(c.target)
        if self.call_hook is None:
            raise InterpError(f"call to {target:#x} without a hook")
        self.call_hook(self.m, target)

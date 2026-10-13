"""Output-oriented clean-ups between the SSA passes and structuring.

These rewrite the IR for reading rather than for analysis:

- `hide_canary`: drop the stack-protector store and the
  `if (canary != fs:[0x28]) __stack_chk_fail()` check (the frame summary
  still reports the canary).
- `returns_value`: decide whether a function returns anything, from how
  its callers use the return register.
- `rewrite_locals`: turn stack-slot loads/stores into named locals
  (`var_14`, `buf_48`) and stack addresses into `&var_14` / `buf_48`, and
  drop the callee-saved register spills of the prologue.
- `forward_empty_blocks`: bypass blocks that only jump elsewhere, so the
  structurer sees the real join points.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .ir import (Assign, BinOp, Branch, CallStmt, Const, Expr, IndirectJump, IRFunction, Jump, Load, Phi, Return,
                 StackAddr, StackVar, Store, Var, map_stmt, stmt_exprs, walk)
from .stack import Frame, Slot

if TYPE_CHECKING:
    from ..analysis import Analysis, Function


# --------------------------------------------------------------------- helpers
def _relink(fn: IRFunction):
    """Rebuild preds from succs and drop blocks no longer reachable from the entry."""
    from .ssa import reachable_order
    live = set(reachable_order(fn))
    fn.blocks = {a: b for a, b in fn.blocks.items() if a in live}
    for b in fn.blocks.values():
        b.succs = [s for s in b.succs if s in live]
        b.preds = []
    for b in fn.blocks.values():
        for s in b.succs:
            if b.addr not in fn.blocks[s].preds:
                fn.blocks[s].preds.append(b.addr)
    for b in fn.blocks.values():
        for s in b.stmts:
            if isinstance(s, Assign) and isinstance(s.src, Phi):
                s.src = Phi(tuple((p, v) for p, v in s.src.sources if p in b.preds), s.src.bits)


def _defs(fn: IRFunction) -> dict[Var, Expr]:
    return {s.dst: s.src for s in fn.stmts() if isinstance(s, Assign) and isinstance(s.dst, Var)}


def _reaches_tls(e: Expr, defs: dict[Var, Expr], depth: int = 4) -> bool:
    """Does `e` (through up to `depth` SSA definitions) read the thread pointer?"""
    for x in walk(e):
        if isinstance(x, Var):
            if x.name in ("fs_base", "gs_base"):
                return True
            if depth and x in defs and _reaches_tls(defs[x], defs, depth - 1):
                return True
    return False


def _is_fail_block(blk) -> bool:
    return any(isinstance(s, CallStmt) and s.name and "stack_chk_fail" in s.name for s in blk.stmts)


# ------------------------------------------------------------------ canary
def hide_canary(fn: IRFunction, frame: Frame) -> bool:
    """Remove the stack-protector prologue store and epilogue check (SSA input)."""
    if frame.canary is None:
        return False
    defs = _defs(fn)
    changed = False
    for b in list(fn.blocks.values()):
        if not b.stmts:
            continue
        last = b.stmts[-1]
        if isinstance(last, Branch) and _reaches_tls(last.cond, defs):
            for fail, ok in ((last.true, last.false), (last.false, last.true)):
                fb = fn.blocks.get(fail)
                if fb is not None and _is_fail_block(fb):
                    b.stmts[-1] = Jump(last.addr, ok)
                    b.succs = [ok]
                    changed = True
                    break
    for b in fn.blocks.values():
        kept = []
        for s in b.stmts:
            if isinstance(s, Store) and frame.offset_of(s.dst) == frame.canary:
                changed = True
                continue
            if isinstance(s, Return) and s.value is not None and _reaches_tls(s.value, defs):
                s.value = None   # `return canary - fs:[0x28]` is the check's leftover, not a result
            kept.append(s)
        b.stmts = kept
    if changed:
        _relink(fn)
    return changed


# ------------------------------------------------------------ return values
def _cache(an: "Analysis") -> dict:
    c = getattr(an, "_decompiler_cache", None)
    if c is None:
        c = an._decompiler_cache = {"ir": {}, "ret": {}}
    return c


def cached_ir(an: "Analysis", func: "Function") -> IRFunction:
    """Optimised SSA IR of `func`, computed once per analysis. Callers must not mutate it."""
    from . import decompile_ir
    c = _cache(an)["ir"]
    if func.addr not in c:
        c[func.addr] = decompile_ir(an, func)
    return c[func.addr]


def returns_value(an: "Analysis", func: "Function", fn: IRFunction, ret_reg: str) -> bool:
    """Whether `func` returns a value: its callers read the return register after the call.

    Without callers we fall back to the function itself: it returns something
    unless every `return` hands back an untouched entry register.
    """
    c = _cache(an)["ret"]
    if func.addr in c:
        return c[func.addr]
    name = an.name(func.addr) or ""
    result = None
    if name == "main":
        result = True
    else:
        callers = [f for f in an.functions.values()
                   if not f.is_import and f.addr != func.addr and (func.addr in f.calls or func.addr in f.tail_calls)]
        if any(func.addr in f.tail_calls for f in callers):
            result = True     # the caller hands our result on as its own
        elif callers:
            result = False
            for f in callers:
                try:
                    ir = cached_ir(an, f)
                except Exception:
                    result = True
                    break
                for s in ir.stmts():
                    if isinstance(s, CallStmt) and isinstance(s.call.target, Const) and \
                            s.call.target.value == func.addr and any(r == ret_reg for r, _ in s.defs):
                        result = True
                        break
                if result:
                    break
    if result is None:
        rets = [s.value for s in fn.stmts() if isinstance(s, Return)]
        result = any(v is not None and not (isinstance(v, Var) and v.version == 0) for v in rets)
    c[func.addr] = result
    return result


def drop_return_values(fn: IRFunction):
    for s in fn.stmts():
        if isinstance(s, Return):
            s.value = None


# ------------------------------------------------------------- stack locals
def _slot_for(frame: Frame, off: int) -> Slot | None:
    best = None
    for o, sl in frame.slots.items():
        if o <= off < o + max(sl.size, sl.width, 1):
            if best is None or o > best.offset:
                best = sl
    return best


def rewrite_locals(fn: IRFunction, frame: Frame) -> None:
    """Name stack slots: loads/stores become locals, addresses `&local` (SSA input, in place)."""
    bits = frame.arch.bits

    def addr(e: Expr) -> Expr | None:
        off = frame.offset_of(e)
        if off is None:
            return None
        sl = _slot_for(frame, off)
        if sl is None or sl.kind in ("retaddr", "saved"):
            return None
        base = StackAddr(sl.name(), sl.offset, bits)
        delta = off - sl.offset
        return base if delta == 0 else BinOp("+", base, Const(delta, bits), bits)

    def as_local(a: Expr, width: int) -> Expr | None:
        off = frame.offset_of(a)
        if off is None:
            return None
        sl = frame.slots.get(off)
        if sl is None or sl.kind in ("retaddr", "saved", "buffer") or width // 8 != sl.width:
            return None
        return StackVar(sl.name(), off, width)

    def rw(e: Expr) -> Expr:
        if isinstance(e, Load):
            v = as_local(e.addr, e.bits)
            if v is not None:
                return v
            return Load(rw(e.addr), e.bits)
        a = addr(e)
        if a is not None:
            return a
        from .ir import children, rebuild
        kids = children(e)
        if not kids:
            return e
        new = tuple(rw(k) for k in kids)
        return rebuild(e, new) if any(x is not y for x, y in zip(new, kids)) else e

    for b in fn.blocks.values():
        out = []
        for s in b.stmts:
            if isinstance(s, Store):
                off = frame.offset_of(s.dst)
                sl = frame.slots.get(off) if off is not None else None
                if sl is not None and sl.kind == "saved":
                    continue        # prologue spill of a callee-saved register
                v = as_local(s.dst, s.src.bits)
                if v is not None:
                    out.append(Assign(s.addr, v, rw(s.src)))
                    continue
            if isinstance(s, Assign) and isinstance(s.src, Phi):
                out.append(s)
                continue
            map_stmt(s, rw)
            out.append(s)
        b.stmts = out


# --------------------------------------------------------------- CFG tidying
def forward_empty_blocks(fn: IRFunction) -> None:
    """Point edges at the final destination of chains of blocks that only `goto` (non-SSA input)."""
    def final(a: int, seen=()) -> int:
        b = fn.blocks.get(a)
        if b is None or a == fn.addr or a in seen:
            return a
        if len(b.stmts) == 1 and isinstance(b.stmts[0], Jump):
            return final(b.stmts[0].target, (*seen, a))
        if not b.stmts and len(b.succs) == 1:
            return final(b.succs[0], (*seen, a))
        return a

    changed = False
    for b in fn.blocks.values():
        if not b.stmts:
            continue
        last = b.stmts[-1]
        if isinstance(last, Jump):
            t = final(last.target)
            if t != last.target:
                last.target, changed = t, True
        elif isinstance(last, Branch):
            t, f = final(last.true), final(last.false)
            if (t, f) != (last.true, last.false):
                last.true, last.false, changed = t, f, True
        elif isinstance(last, IndirectJump):
            new = [final(t) for t in last.targets]
            if new != last.targets:
                last.table = [final(t) for t in last.table]
                last.targets, changed = list(dict.fromkeys(new)), True
        else:
            continue
        b.succs = list(dict.fromkeys(_targets(last)))
    if changed:
        for b in fn.blocks.values():
            if b.stmts and isinstance(b.stmts[-1], Branch) and b.stmts[-1].true == b.stmts[-1].false:
                last = b.stmts[-1]
                b.stmts[-1] = Jump(last.addr, last.true)
        _relink(fn)


def _targets(s) -> list[int]:
    if isinstance(s, Jump):
        return [s.target]
    if isinstance(s, Branch):
        return [s.true, s.false]
    if isinstance(s, IndirectJump):
        return list(s.targets)
    return []


__all__ = ["hide_canary", "returns_value", "drop_return_values", "rewrite_locals", "forward_empty_blocks",
           "cached_ir"]

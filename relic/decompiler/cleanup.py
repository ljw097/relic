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

from ..progress import Cancelled
from .ir import (Assign, BinOp, Branch, CallStmt, Const, Expr, IndirectJump, IRFunction, Jump, Load, Phi, Return,
                 StackAddr, StackVar, Store, Var, map_stmt, stmt_defs, stmt_exprs, walk)
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


def _reaches_tls(e: Expr, defs: dict[Var, Expr], depth: int = 4, guards=frozenset(), memo=None) -> bool:
    """Does `e` (through up to `depth` SSA definitions) read the stack-protector value -- the
    thread pointer on x86, `__stack_chk_guard` (an address in `guards`) elsewhere?

    `memo` ((var, depth) -> answer) shares the work between calls over one function: phis make
    the definitions a graph, and walking it afresh from every use is exponential in `depth`."""
    if memo is None:
        memo = {}
    for x in walk(e):
        if isinstance(x, Const) and x.value in guards:
            return True
        if isinstance(x, Var):
            if x.name in ("fs_base", "gs_base", "tp_base"):
                return True
            if depth and x in defs:
                key = (x, depth)
                r = memo.get(key)
                if r is None:
                    memo[key] = False            # (a cycle through phis reads nothing new)
                    r = memo[key] = _reaches_tls(defs[x], defs, depth - 1, guards, memo)
                if r:
                    return True
    return False


def stack_guards(an: "Analysis") -> frozenset:
    """Addresses `__stack_chk_guard` is read through: its symbol and its GOT slots."""
    b = an.bin
    out = set()
    a = b.name_to_addr.get("__stack_chk_guard")
    if a:
        out.add(a)
    for imp in b.imports:
        if imp.name.split("@")[0] == "__stack_chk_guard":
            out |= {x for x in (imp.got, imp.addr) if x}
    return frozenset(out)


def _is_fail_block(blk) -> bool:
    return any(isinstance(s, CallStmt) and s.name and "stack_chk_fail" in s.name for s in blk.stmts)


# ------------------------------------------------------------------ canary
def hide_canary(fn: IRFunction, frame: Frame) -> bool:
    """Remove the stack-protector prologue store and epilogue check (SSA input)."""
    if frame.canary is None:
        return False
    defs = _defs(fn)
    memo: dict = {}
    changed = False
    for b in list(fn.blocks.values()):
        if not b.stmts:
            continue
        last = b.stmts[-1]
        if isinstance(last, Branch) and _reaches_tls(last.cond, defs, guards=frame.guards, memo=memo):
            for fail, ok in ((last.true, last.false), (last.false, last.true)):
                fb = fn.blocks.get(fail)
                for _ in range(3):              # (clang -O0: through a block that only jumps there)
                    if fb is not None and len(fb.stmts) == 1 and isinstance(fb.stmts[0], Jump):
                        fb = fn.blocks.get(fb.stmts[0].target)
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
            if isinstance(s, Return) and s.value is not None and \
                    _reaches_tls(s.value, defs, guards=frame.guards, memo=memo):
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


def _lifted(an: "Analysis", func: "Function") -> IRFunction:
    from .lift import lift_function
    c = _cache(an).setdefault("lift", {})
    if func.addr not in c:
        c[func.addr] = lift_function(an, func)
    return c[func.addr]


def _read_form(e: Expr, reg: str):
    """How expression `e` reads register `reg`: a low-bits width, "whole", or None (not at all)."""
    from .ir import Cast, Extract, Reg, children
    if isinstance(e, Cast) and e.kind == "low" and isinstance(e.a, Reg) and e.a.name == reg:
        return e.bits
    if isinstance(e, Extract) and isinstance(e.a, Reg) and e.a.name == reg:
        return "whole"
    if isinstance(e, Reg) and e.name == reg:
        return "whole"
    forms = [f for f in (_read_form(k, reg) for k in children(e)) if f is not None]
    if not forms:
        return None
    return forms[0] if all(f == forms[0] for f in forms) else "whole"


def _callee_args(an: "Analysis", call: CallStmt) -> set[str]:
    """Argument registers an internal callee reads (its parameters)."""
    from .arch import arch_for
    from .calls import livein_regs
    from .fpabi import fp_params, fp_part
    t = call.call.target
    if not isinstance(t, Const) or t.value not in an.functions:
        return set()
    try:
        arch = arch_for(an.bin)
    except NotImplementedError:
        return set()
    return livein_regs(an, arch, t.value) | {fp_part(r)[0] for r, _ in fp_params(an, arch, t.value)}


def result_reads(an: "Analysis", func: "Function", reg: str) -> list:
    """For every call to `func`, how the caller first reads the result register.

    Scans the caller's lifted (pre-SSA) IR forward from the call through the
    block and its successors until the register is read or overwritten.
    Entries are a width (`low32(rax)`), "whole", or "none" (overwritten or never
    read); falling into a `return` hands the value on, which says nothing.
    """
    from .ir import Reg, stmt_defs
    c = _cache(an).setdefault("reads", {})
    key = (func.addr, reg)
    if key in c:
        return c[key]
    out: list = []
    for f in an.functions.values():
        if f.is_import or func.addr not in f.calls:
            continue
        try:
            fn = _lifted(an, f)
        except Exception:
            out.append("whole")
            continue

        def scan(stmts, blk, depth) -> str | int | None:
            for t in stmts:
                if isinstance(t, Return):
                    return None
                if isinstance(t, CallStmt):
                    reads = [_read_form(a, reg) for a in [t.call.target, *t.call.args]]
                    reads = [r for r in reads if r is not None]
                    if reads:
                        return reads[0]
                    if t.clobbers is not None and reg not in t.clobbers and not t.tail:
                        # a local callee that leaves the register alone (gcc -fipa-ra keeps the
                        # result there across it), unless it takes it as an argument
                        if reg in _callee_args(an, t):
                            return "whole"
                        continue
                    return "none"                          # a call clobbers the result register
                forms = [r for r in (_read_form(x, reg) for x in stmt_exprs(t)) if r is not None]
                if forms:
                    return forms[0] if all(f == forms[0] for f in forms) else "whole"
                if any(isinstance(d, Reg) and d.name == reg for d in stmt_defs(t)):
                    return "none"
            if depth >= 3:
                return None
            results = [scan(fn.blocks[sb].stmts, fn.blocks[sb], depth + 1) for sb in blk.succs if sb in fn.blocks]
            results = [r for r in results if r is not None]
            if not results:
                return None
            reads = [r for r in results if r != "none"]
            return reads[0] if reads else "none"

        for b in fn.blocks.values():
            for k, s in enumerate(b.stmts):
                if isinstance(s, CallStmt) and isinstance(s.call.target, Const) and s.call.target.value == func.addr:
                    r = scan(b.stmts[k + 1:], b, 0)
                    if r is not None:
                        out.append(r)
    c[key] = out
    return out


def returns_value(an: "Analysis", func: "Function", fn: IRFunction, ret_reg: str) -> bool:
    """Whether `func` returns a value: some caller reads the return register after the call.

    Without informative callers we fall back to the function itself: it returns
    something unless every `return` hands back an untouched entry register.
    """
    if (an.name(func.addr) or "") == "main":
        return True
    if any(func.addr in f.tail_calls for f in an.functions.values() if not f.is_import):
        return True     # a caller hands our result on as its own
    reads = result_reads(an, func, ret_reg)
    if reads:
        return any(r != "none" for r in reads)
    rets = [s.value for s in fn.stmts() if isinstance(s, Return)]
    # a function that returns something sets the register on every path: one where the entry
    # value can still come back (through phis) only used it as scratch (-O0 x86 `rax`)
    phis = {s.dst: s.src for s in fn.stmts() if isinstance(s, Assign) and isinstance(s.dst, Var)
            and isinstance(s.src, Phi)}

    def entry(v, depth=8) -> bool:
        if isinstance(v, Var) and v.version == 0:
            return True
        if depth and v in phis:
            return any(entry(x, depth - 1) for _, x in phis[v].sources)
        return False
    return any(v is not None for v in rets) and not any(v is not None and entry(v) for v in rets)


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


# --------------------------------------------------------------- result widths
_INT_RETS = {"int": (32, "sext"), "unsigned": (32, "zext"), "unsigned int": (32, "zext"), "void": (0, "")}


def return_width(an: "Analysis", func: "Function", ret_reg: str) -> int | None:
    """Width of the result: what the callers read (`low32(rax)` everywhere -> 32), else what
    the function itself returns."""
    if (an.name(func.addr) or "") == "main":
        return 32
    reads = [r for r in result_reads(an, func, ret_reg) if r != "none"]
    if reads and all(isinstance(r, int) for r in reads) and len(set(reads)) == 1:
        return reads[0]
    return self_width(an, func, ret_reg)


def narrow_returns(fn: IRFunction, width: int):
    """`return x` of a function whose result is `width` bits: return `low_width(x)`."""
    from .ir import Cast
    from .vartypes import simplify_low
    for s in fn.stmts():
        if isinstance(s, Return) and s.value is not None and s.value.bits > width:
            s.value = simplify_low(Cast("low", s.value, width))


def narrow_library_results(fn: IRFunction):
    """Results of library calls returning `int` are 32-bit: read them as `sext64(low32(v))`."""
    from .ir import Cast, transform
    from .sigs import lookup
    defs: dict[Var, int] = {}
    for s in fn.stmts():
        for d in stmt_defs(s):
            if isinstance(d, Var):
                defs[d] = defs.get(d, 0) + 1
    for s in list(fn.stmts()):
        if not isinstance(s, CallStmt) or not s.defs:
            continue
        sig = lookup(s.name)
        if sig is None or sig.ret not in ("int", "unsigned"):
            continue
        bits, ext = _INT_RETS[sig.ret]
        for _, v in s.defs:
            if isinstance(v, Var) and v.bits > bits and defs.get(v) == 1:
                wrapped = Cast(ext, Cast("low", v, bits), v.bits)
                for b in fn.blocks.values():
                    for t in b.stmts:
                        map_stmt(t, lambda e, v=v, w=wrapped: transform(e, lambda x: w if x == v else x))


# ------------------------------------------------------------ expression inlining
def _reads(e: Expr) -> tuple[set, bool]:
    """(variables/locals read, whether memory is read)."""
    names, mem = set(), False
    for x in walk(e):
        if isinstance(x, (Var, StackVar)):
            names.add(x.name)
        elif isinstance(x, Load):
            mem = True
    return names, mem


def propagate_ro_loads(an: "Analysis", fn: IRFunction) -> int:
    """`v5 = [rodata]; f(v5); g(v5)` -> `f([rodata]); g([rodata])`: a temporary defined once, by
    a load from read-only memory (a float constant, which `fold_float_constants` then turns into
    a literal at each use)."""
    from .fpconst import _ro_value
    from .ir import map_stmt, stmt_defs, transform
    defs: dict[str, list] = {}
    for b in fn.blocks.values():
        for s in b.stmts:
            for d in stmt_defs(s):
                if isinstance(d, Var):
                    defs.setdefault(d.name, []).append(s)
    from .ir import Store
    copied = {s.src.name for s in fn.stmts() if isinstance(s, (Assign, Store)) and isinstance(s.src, Var)}
    sub = {}
    for name, ss in defs.items():
        s = ss[0]
        if len(ss) == 1 and isinstance(s, Assign) and s.dst.version == 0 and name.startswith("_v") and \
                _ro_value(an, s.src) is not None:
            sub[s.dst] = s.src
    if not sub:
        return 0

    def rewrite(e: Expr) -> Expr:
        return transform(e, lambda x: sub.get(x, x) if isinstance(x, Var) else x)
    for b in fn.blocks.values():
        # copies into locals keep reading the variable (its float type says what the local holds),
        # and its definition stays for them
        b.stmts = [s for s in b.stmts if not (isinstance(s, Assign) and s.dst in sub and s.dst.name not in copied)]
        for s in b.stmts:
            if isinstance(s, (Assign, Store)) and isinstance(s.src, Var) and s.src in sub:
                continue
            if isinstance(s, Assign) and s.dst in sub:
                continue
            map_stmt(s, rewrite)
    return len(sub)


def inline_single_use(fn: IRFunction) -> bool:
    """Fold a temporary defined once and used once later in the same block into its use.

    `v1 = notes[i]; free(v1)` -> `free(notes[i])`. Calls are only folded into
    the very next statement, and nothing that could change what the
    expression reads (a store, a call, a write to one of its variables) may
    sit between the definition and the use.
    """
    from .ir import Call, CallStmt as _CS, Effect, Unknown, stmt_defs, transform
    changed_any = False
    while True:
        uses: dict[str, int] = {}
        defs: dict[str, int] = {}
        for s in fn.stmts():
            # a call's recovered `uses` mirror its arguments: count the arguments once
            for top in ([s.call] if isinstance(s, _CS) else stmt_exprs(s)):
                for x in walk(top):
                    if isinstance(x, Var):
                        uses[x.name] = uses.get(x.name, 0) + 1
            for d in stmt_defs(s):
                if isinstance(d, Var):
                    defs[d.name] = defs.get(d.name, 0) + 1
        changed = False
        for b in fn.blocks.values():
            k = 0
            while k < len(b.stmts):
                s = b.stmts[k]
                cand = None
                if isinstance(s, Assign) and isinstance(s.dst, Var) and not isinstance(s.src, Phi):
                    cand = (s.dst, s.src)
                elif isinstance(s, _CS) and not s.tail and len(s.defs) == 1 and isinstance(s.defs[0][1], Var):
                    cand = (s.defs[0][1], s.call)
                if cand is None:
                    k += 1
                    continue
                v, src = cand
                if uses.get(v.name) != 1 or defs.get(v.name) != 1 or v.version != 0 or not v.name.startswith("_v"):
                    k += 1
                    continue
                names, mem = _reads(src)
                has_call = any(isinstance(x, Call) for x in walk(src))
                target = None
                # the statements after the definition: rest of this block, then on through
                # straight-line successors (one successor, which has only this predecessor)
                chain = [(b, j) for j in range(k + 1, len(b.stmts))]
                cur = b
                while len(cur.succs) == 1 and cur.succs[0] in fn.blocks and cur.succs[0] != b.addr:
                    nxt = fn.blocks[cur.succs[0]]
                    if len(nxt.preds) != 1 or nxt.addr == fn.addr:
                        break
                    chain += [(nxt, j) for j in range(len(nxt.stmts))]
                    cur = nxt
                for tb, j in chain:
                    t = tb.stmts[j]
                    if any(x == v for top in ([t.call] if isinstance(t, _CS) else stmt_exprs(t)) for x in walk(top)):
                        target = (tb, j)
                        break
                    if has_call:
                        break
                    if isinstance(t, (_CS, Effect, Unknown)) or (isinstance(t, Store) and (mem or names)):
                        break
                    if any(getattr(d, "name", None) in names for d in stmt_defs(t)):
                        break
                if target is None:
                    k += 1
                    continue
                t = target[0].stmts[target[1]]
                if has_call and isinstance(t, _CS) and any(x == v for x in walk(t.call.target)):
                    k += 1
                    continue
                map_stmt(t, lambda e, v=v, src=src: transform(e, lambda x: src if x == v else x))
                del b.stmts[k]
                changed = changed_any = True
        if not changed:
            return changed_any


def _clean(e: Expr, bits: int, defs: dict, an: "Analysis", ret_reg: str, seen: set) -> bool:
    """Is `e` a `bits`-wide value merely held in a wider register?"""
    from .ir import Cast
    from .sigs import lookup
    if isinstance(e, Const):
        # RISC-V / MIPS64 keep an int sign-extended: `li a0, -1` is the int -1
        return e.value < (1 << bits) or an.bin.arch in ("riscv64", "mips64") and e.value >> (bits - 1) == \
            (1 << (e.bits - bits + 1)) - 1
    if isinstance(e, Cast) and e.kind in ("zext", "sext"):
        return e.a.bits <= bits
    if isinstance(e, BinOp) and e.op in ("&", "|", "^"):
        return _clean(e.a, bits, defs, an, ret_reg, seen) and _clean(e.b, bits, defs, an, ret_reg, seen)
    if isinstance(e, Var):
        if e in seen:
            return True
        seen.add(e)
        d = defs.get(e)
        if d is None:
            return False
        if isinstance(d, CallStmt):
            sig = lookup(d.name, an)
            if sig is not None:
                return sig.ret in _INT_RETS and _INT_RETS[sig.ret][0] == bits
            f = an.functions.get(d.call.target.value) if isinstance(d.call.target, Const) else None
            return f is not None and not f.is_import and self_width(an, f, ret_reg) == bits
        if isinstance(d, Phi):
            return all(_clean(v, bits, defs, an, ret_reg, seen) for _, v in d.sources)
        return _clean(d, bits, defs, an, ret_reg, seen)
    return False


def self_width(an: "Analysis", func: "Function", ret_reg: str, bits: int = 32) -> int | None:
    """`bits` if every value `func` returns is a `bits`-wide integer (its own view of the result)."""
    c = _cache(an).setdefault("self", {})
    if func.addr in c:
        return c[func.addr]
    c[func.addr] = None          # recursion guard
    try:
        return _self_width(an, func, ret_reg, bits, c)
    except Cancelled:
        del c[func.addr]         # the guard is not an answer
        raise


def _self_width(an: "Analysis", func: "Function", ret_reg: str, bits: int, c: dict) -> int | None:
    try:
        fn = cached_ir(an, func)
    except Cancelled:
        raise
    except Exception:
        return None
    defs: dict = {}
    for s in fn.stmts():
        if isinstance(s, Assign) and isinstance(s.dst, Var):
            defs[s.dst] = s.src
        elif isinstance(s, CallStmt):
            for _r, v in s.defs:
                if isinstance(v, Var):
                    defs[v] = s
    vals = [s.value for s in fn.stmts() if isinstance(s, Return) and s.value is not None]
    ok = bool(vals) and all(_clean(v, bits, defs, an, ret_reg, set()) for v in vals)
    if not ok and bits == 32:
        # `mov eax, -1` leaves 0x00000000ffffffff in rax: a constant with bit 31 set and nothing
        # above bit 31 only makes sense as a negative 32-bit int
        consts = [_resolve_const(v, defs) for v in vals]
        ok = any(c is not None and c >> 31 == 1 for c in consts)
    c[func.addr] = bits if ok else None
    return c[func.addr]


# ----------------------------------------------------------- short-circuit conditions
def fold_short_circuits(fn: IRFunction) -> int:
    """Merge chained conditional branches into `&&` / `||` conditions (non-SSA input).

    When block `n` ends in `if (c1)` and one of its successors `m` holds nothing
    but `if (c2)`, has `n` as its only predecessor, and shares a target with
    `n`, the two tests are one short-circuit condition:

        n: if (c1) T else m;  m: if (c2) T else F   ->  n: if (c1 || c2) T else F
        n: if (c1) m else F;  m: if (c2) T else F   ->  n: if (c1 && c2) T else F

    (with `!c2` when `m` reaches the shared target on its false side). The
    evaluation order and laziness are exactly those of the original branches.
    Returns the number of merges.
    """
    from .ir import UnOp
    merged = 0
    changed = True
    while changed:
        changed = False
        for n in list(fn.blocks.values()):
            if n.addr not in fn.blocks or not n.stmts or not isinstance(n.stmts[-1], Branch):
                continue
            b1 = n.stmts[-1]
            for m_addr in (b1.true, b1.false):
                m = fn.blocks.get(m_addr)
                if m is None or m.addr == n.addr or m.addr == fn.addr or m.preds != [n.addr] or \
                        len(m.stmts) != 1 or not isinstance(m.stmts[0], Branch):
                    continue
                b2 = m.stmts[0]
                if m.addr in (b2.true, b2.false):
                    continue
                other = b1.false if m_addr == b1.true else b1.true     # n's target besides m
                if other not in (b2.true, b2.false):
                    continue
                c2 = b2.cond if b2.true == other else UnOp("!", b2.cond, 1)   # c2' true -> other
                rest = b2.false if b2.true == other else b2.true
                if m_addr == b1.false:      # n: if (c1) other else m  -> c1 || c2' -> other
                    cond, t, f = BinOp("||", b1.cond, c2, 1), other, rest
                else:                       # n: if (c1) m else other  -> c1 && !c2' -> rest
                    cond, t, f = BinOp("&&", b1.cond, UnOp("!", c2, 1), 1), rest, other
                n.stmts[-1] = Branch(b1.addr, _simplify_not(cond), t, f)
                n.succs = [t, f]
                del fn.blocks[m.addr]
                _relink(fn)
                merged += 1
                changed = True
                break
    return merged


def _simplify_not(e: Expr) -> Expr:
    """Push `!` into comparisons (`!(a < b)` -> `b <= a`) so conditions read naturally."""
    from .ir import UnOp, transform
    from .structure import _negate

    def node(x):
        if isinstance(x, UnOp) and x.op == "!":
            neg = _negate(x.a)
            if not (isinstance(neg, UnOp) and neg.op == "!" and neg.a == x.a):
                return neg
        return x
    return transform(e, node)


def _resolve_const(e: Expr, defs: dict, depth: int = 4):
    """The constant `e` evaluates to, following SSA copies / phis of a single constant."""
    if isinstance(e, Const):
        return e.value
    if isinstance(e, Var) and depth and e in defs:
        d = defs[e]
        if isinstance(d, Phi):
            vals = {_resolve_const(v, defs, depth - 1) for _, v in d.sources}
            vals.discard(None)
            return vals.pop() if len(vals) == 1 else None
        if isinstance(d, Expr):
            return _resolve_const(d, defs, depth - 1)
    return None


def drop_stack_pointer_chains(fn: IRFunction, frame: Frame) -> int:
    """Remove stack-pointer arithmetic nothing but more stack-pointer arithmetic reads (SSA input).

    Once arguments and locals are named, `esp` bookkeeping around calls survives
    only as a cycle through the loop-header phi (`v2 = v5 + 16`), which plain
    DCE keeps alive. Liveness here starts from every other statement.
    """
    sp_defs = {s.dst: s for s in fn.stmts() if isinstance(s, Assign) and s.dst in frame.spoff}
    live: set = set()
    for s in fn.stmts():
        if isinstance(s, Assign) and s.dst in sp_defs:
            continue
        live |= {x for e in stmt_exprs(s) for x in walk(e) if isinstance(x, Var)}
    work = [v for v in live if v in sp_defs]
    while work:
        for x in walk(sp_defs[work.pop()].src):
            if isinstance(x, Var) and x not in live:
                live.add(x)
                if x in sp_defs:
                    work.append(x)
    dead = {v for v in sp_defs if v not in live}
    for b in fn.blocks.values():
        b.stmts = [s for s in b.stmts if not (isinstance(s, Assign) and s.dst in dead)]
    return len(dead)


# ----------------------------------------------------------- unsigned <-> float conversions
def _bare_value(e: Expr) -> Expr:
    """`e` without the zero-extensions, truncations and bit extracts around it (`low64(zext128(x))`)."""
    from .ir import Cast, Extract
    while isinstance(e, (Cast, Extract)) and (not isinstance(e, Extract) or e.lo == 0):
        e = e.a
    return e


def _is_conv(e: Expr, name: str, x: Expr | None = None) -> bool:
    from .ir import Intrinsic
    e = _bare_value(e)
    return isinstance(e, Intrinsic) and e.name == name and (x is None or _bare_value(e.args[0]) == x)


def fold_unsigned_conversions(an, fn: IRFunction) -> int:
    """The compiler's code for conversions between 64-bit unsigned integers and floats, back to
    one conversion (non-SSA input):

        if (x < 0) { v = (double)(x >> 1 | x & 1); r = v + v; } else r = (double)x;
                                                                ->  r = (double)(uint64_t)x
        if (2^63 <= d) r = (int64_t)(d - 2^63) ^ 1 << 63; else r = (int64_t)d;
                                                                ->  r = (uint64_t)d

    on the branch's two sides ending in a `return` or in the same assignment.
    """
    from .ir import Cast, Intrinsic, Var, walk
    done = 0
    for a in list(fn.blocks.values()):
        if a.addr not in fn.blocks or not a.stmts or not isinstance(a.stmts[-1], Branch):
            continue
        br = a.stmts[-1]
        t, f = fn.blocks.get(br.true), fn.blocks.get(br.false)
        if t is None or f is None or t is f or t.preds != [a.addr] or f.preds != [a.addr]:
            continue
        local = {s.dst: s.src for s in a.stmts + t.stmts if isinstance(s, Assign) and isinstance(s.dst, Var)}

        def val(e):
            e = _bare_value(e)
            return _bare_value(local.get(e, e)) if isinstance(e, Var) else e
        # the value each side ends with: a return's, or one variable both assign last
        ends = []
        for b in (t, f):
            last = b.stmts[-1] if b.stmts else None
            if isinstance(last, Return) and last.value is not None:
                ends.append(("ret", None, last.value))
            elif isinstance(last, Jump) or last is None or not isinstance(last, (Branch, Return)):
                asg = [s for s in b.stmts if isinstance(s, Assign)]
                if not asg or not isinstance(asg[-1].dst, Var):
                    break
                ends.append(("asg", asg[-1].dst, asg[-1].src))
            else:
                break
        if len(ends) != 2 or ends[0][:2] != ends[1][:2] or t.succs != f.succs:
            continue
        tv, fv = ends[0][2], ends[1][2]
        new = None
        c = br.cond
        if isinstance(c, BinOp) and c.op == "<s" and isinstance(c.b, Const) and c.b.value == 0:
            x = _bare_value(c.a)
            s = val(tv)
            # (r = v + v of v = (double)(x >> 1 | x & 1))
            if isinstance(s, BinOp) and s.op == "f+" and val(s.a) == val(s.b) and _is_conv(val(s.a), "sitofp") and \
                    any(isinstance(n, BinOp) and n.op == ">>u" and _bare_value(n.a) == x and
                        isinstance(n.b, Const) and n.b.value == 1 for n in walk(val(s.a))) and \
                    _is_conv(fv, "sitofp", x):
                conv = _bare_value(fv)
                new = Intrinsic("uitofp", (x,), conv.bits)
        elif isinstance(c, BinOp) and c.op == "f<=":
            k, d = val(c.a), _bare_value(c.b)
            s = val(tv)
            big = _float_value(an, k)
            if big is not None and big == 2.0 ** 63 and isinstance(s, BinOp) and s.op == "^" and \
                    isinstance(s.b, Const) and s.b.value == 1 << 63 and _is_conv(fv, "fptosi", d):
                inner = _bare_value(s.a)
                if isinstance(inner, Intrinsic) and inner.name == "fptosi" and \
                        isinstance(_bare_value(inner.args[0]), BinOp) and _bare_value(inner.args[0]).op == "f-":
                    new = Intrinsic("fptoui", (d,), _bare_value(fv).bits)
        if new is None:
            continue
        # the false side does it all now; the branch goes there unconditionally
        last = f.stmts[-1]
        if isinstance(last, Return):
            last.value = new if new.bits == last.value.bits else Cast("zext", new, last.value.bits)
        else:
            asg = [s for s in f.stmts if isinstance(s, Assign)][-1]
            asg.src = new if new.bits == asg.src.bits else Cast("zext", new, asg.src.bits)
        a.stmts[-1] = Jump(br.addr, f.addr)
        a.succs = [f.addr]
        for s_addr in t.succs:
            sb = fn.blocks.get(s_addr)
            if sb is not None:
                sb.preds = [p for p in sb.preds if p != t.addr]
        del fn.blocks[t.addr]
        done += 1
    return done


def _float_value(an, e: Expr) -> float | None:
    """The float constant `e` is (a literal, or a load from read-only data)."""
    import struct as _st

    from .ir import Load
    e = _bare_value(e)
    if isinstance(e, Const) and e.bits in (32, 64):
        return _st.unpack("<d" if e.bits == 64 else "<f", e.value.to_bytes(e.bits // 8, "little"))[0]
    if isinstance(e, Load) and isinstance(e.addr, Const) and e.bits in (32, 64) and an is not None:
        raw = an.bin.read(e.addr.value, e.bits // 8)
        if raw and len(raw) == e.bits // 8:
            return _st.unpack(("<" if an.bin.endian == "little" else ">") + ("d" if e.bits == 64 else "f"), raw)[0]
    return None

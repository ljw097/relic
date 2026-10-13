"""Stage 3: recover call arguments and return values.

After optimisation each `CallStmt` still carries the full register traffic
the calling convention allows (`uses`). This pass works out how many of
those registers are real arguments -- from a libc signature for imports, or
from the callee's live-in registers for internal functions -- and records
them as `Call.args`, so the IR reads `printf("%s", buf)` instead of a wall
of register assignments.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .arch import ArchInfo
from .ir import Assign, Call, CallStmt, Const, IRFunction, Phi, Var, stmt_exprs, walk
from .sigs import arg_count, lookup

if TYPE_CHECKING:
    from ..analysis import Analysis

# integer argument registers, in order, per calling convention
_INT_ARGS = {
    "x64-sysv": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "x64-win": ("rcx", "rdx", "r8", "r9"),
    "x86-cdecl": (),  # arguments are passed on the stack (recovered with the frame, stage 3b)
    "arm64-aapcs": tuple(f"x{k}" for k in range(8)),
}


def int_arg_regs(arch: ArchInfo) -> tuple[str, ...]:
    return _INT_ARGS.get(arch.name, ())


def _read_format(an: "Analysis", value) -> str | None:
    if not isinstance(value, Const):
        return None
    s = an.bin.read_cstring(value.value, 256)
    return s if s else None


def _livein_arg_regs(an: "Analysis", arch: ArchInfo, target: int) -> list[str]:
    """Argument registers an internal callee reads on entry (its parameters, heuristically)."""
    cache = getattr(an, "_livein_cache", None)
    if cache is None:
        cache = an._livein_cache = {}
    if target not in cache:
        cache[target] = _compute_livein(an, arch, target)
    return cache[target]


def _compute_livein(an: "Analysis", arch: ArchInfo, target: int) -> list[str]:
    f = an.functions.get(target)
    if f is None or f.is_import:
        return []
    from .lift import lift_function
    from .ssa import to_ssa
    try:
        ssa = to_ssa(lift_function(an, f), arch)
    except Exception:
        return []
    # a call's implicit `uses` list every argument register the convention allows, which
    # would make every register look like a parameter; only count what the callee really
    # reads, plus the registers a known libc callee consumes (wrappers passing args along).
    # Phis are followed only from such real uses (clobbered registers merge at joins).
    phis: dict[Var, Phi] = {}
    used: set[Var] = set()
    for s in ssa.stmts():
        if isinstance(s, Assign) and isinstance(s.src, Phi):
            phis[s.dst] = s.src
            continue
        tops = stmt_exprs(s)
        if isinstance(s, CallStmt):
            tops = [s.call]
            sig = lookup(s.name or (an.name(s.call.target.value) if isinstance(s.call.target, Const) else None))
            if sig is not None:
                keep = set(int_arg_regs(arch)[:sig.argc])
                tops += [v for r, v in s.uses if r in keep]
        used |= {x for top in tops for x in walk(top) if isinstance(x, Var)}
    work = [v for v in used if v in phis]
    while work:
        for x in walk(phis[work.pop()]):
            if isinstance(x, Var) and x not in used:
                used.add(x)
                if x in phis:
                    work.append(x)
    livein = {v.name for v in used if v.version == 0}
    # take the contiguous prefix of argument registers: a gap means the later
    # ones are scratch (e.g. a partial write like `mov dl, al` reads rdx), not parameters
    params: list[str] = []
    for r in int_arg_regs(arch):
        if r not in livein:
            break
        params.append(r)
    return params


def _set_before_call(fn: IRFunction, argregs, uses: dict, params=()) -> list[str]:
    """Argument registers the caller evidently loaded for this call (callee unknown).

    A register counts when its value at the call was computed in this function:
    not the untouched entry value (unless it is one of the caller's own parameters,
    passed straight on), and not a leftover result of an earlier call.
    The contiguous prefix of such registers is taken as the argument list.
    """
    from .ir import Assign
    defined = {s.dst for s in fn.stmts() if isinstance(s, Assign) and isinstance(s.dst, Var)
               and not isinstance(s.src, Phi)}
    out: list[str] = []
    for r in argregs:
        v = uses.get(r)
        if not (isinstance(v, Const) or (isinstance(v, Var) and (v in defined or
                                                                  (v.version == 0 and v.name in params)))):
            break
        out.append(r)
    return out


# ------------------------------------------------------------------ cdecl (x86-32)
def stack_param_count(an: "Analysis", arch: ArchInfo, target: int) -> int:
    """How many 4-byte stack parameters an internal cdecl callee reads (`[esp_0 + 4k]`)."""
    cache = getattr(an, "_stack_params", None)
    if cache is None:
        cache = an._stack_params = {}
    if target in cache:
        return cache[target]
    cache[target] = 0          # recursion guard
    f = an.functions.get(target)
    if f is None or f.is_import:
        return 0
    from .lift import lift_function
    from .ssa import to_ssa
    from .stack import _build_spoff, Frame
    try:
        ssa = to_ssa(lift_function(an, f), arch)
    except Exception:
        return 0
    frame = Frame(arch, _build_spoff(ssa, arch))
    from .ir import Load
    word = arch.bits // 8
    top = 0
    for st in ssa.stmts():
        for e in stmt_exprs(st):
            for x in walk(e):
                if isinstance(x, Load):
                    off = frame.offset_of(x.addr)
                    if off is not None and off > 0:
                        top = max(top, (off + x.bits // 8 + word - 1) // word - 1)
    cache[target] = top
    return top


def _recover_cdecl(fn: IRFunction, an: "Analysis", arch: ArchInfo):
    """Arguments of x86-32 calls: the values stored at [esp], [esp+4], ... before the call."""
    from .ir import Store
    from .stack import Frame, _build_spoff
    frame = Frame(arch, _build_spoff(fn, arch))
    word = arch.bits // 8
    for b in fn.blocks.values():
        consumed: set[int] = set()
        for k, s in enumerate(b.stmts):
            if not isinstance(s, CallStmt) or s.call.args:
                continue
            sp = dict(s.uses).get(arch.sp)
            sp_off = frame.offset_of(sp) if sp is not None else None
            if sp_off is None:
                continue
            # a tail call (`jmp f`) pushes no return address: its arguments start one word up,
            # in the caller's own parameter slots
            base = sp_off + word if s.tail else sp_off
            # most recent store to each argument slot since the previous call in this block
            stores: dict[int, int] = {}
            for j in range(k - 1, -1, -1):
                t = b.stmts[j]
                if isinstance(t, CallStmt):
                    break
                if isinstance(t, Store):
                    off = frame.offset_of(t.dst)
                    if off is not None and off >= base and (off - base) % word == 0 and off not in stores:
                        stores[off] = j
            tgt = s.call.target.value if isinstance(s.call.target, Const) else None
            sig = lookup(s.name or (an.name(tgt) if tgt is not None else None))
            f = an.functions.get(tgt) if tgt is not None else None
            if sig is not None:
                fmt_val = b.stmts[stores[base + sig.fmt * word]].src \
                    if sig.fmt is not None and base + sig.fmt * word in stores else None
                n = arg_count(sig, _read_format(an, fmt_val))
            elif f is not None and not f.is_import:
                n = stack_param_count(an, arch, tgt)
            else:
                n = 0
                while base + n * word in stores:
                    n += 1
            idx = [stores.get(base + a * word) for a in range(n)]
            from .ir import BinOp, Load
            args = []
            for a, i in enumerate(idx):
                if i is not None:
                    args.append(b.stmts[i].src)
                elif s.tail:
                    # passed straight through: the caller's own parameter slot, unchanged
                    delta = base + a * word - sp_off
                    args.append(Load(BinOp("+", sp, Const(delta, arch.bits), arch.bits), arch.bits))
                else:
                    break
            idx = [i for i in idx[:len(args)] if i is not None]
            s.call = Call(s.call.target, tuple(args), s.call.bits)
            s.uses = []          # the stack pointer only located the arguments
            consumed |= set(idx)
        if consumed:
            b.stmts = [t for j, t in enumerate(b.stmts) if j not in consumed]


def recover_calls(fn: IRFunction, an: "Analysis", arch: ArchInfo) -> IRFunction:
    """Fill in `Call.args` for every call (mutates and returns `fn`).

    Library calls use their signature, internal calls the callee's live-in
    argument registers, and calls with neither (unknown imports, function
    pointers) the registers the caller visibly set up for them.
    """
    if arch.name == "x86-cdecl":
        _recover_cdecl(fn, an, arch)
        return fn
    argregs = int_arg_regs(arch)
    own: list[str] | None = None
    for b in fn.blocks.values():
        for s in b.stmts:
            if not isinstance(s, CallStmt) or s.call.args:
                continue
            uses = dict(s.uses)
            tgt = s.call.target.value if isinstance(s.call.target, Const) else None
            name = s.name or (an.name(tgt) if tgt is not None else None)
            sig = lookup(name)
            f = an.functions.get(tgt) if tgt is not None else None
            if sig is not None:
                fmt = _read_format(an, uses.get(argregs[sig.fmt])) if sig.fmt is not None and \
                    sig.fmt < len(argregs) else None
                selected = list(argregs[:arg_count(sig, fmt)])
            elif f is not None and not f.is_import:
                selected = _livein_arg_regs(an, arch, tgt)
            else:
                if own is None:
                    own = _livein_arg_regs(an, arch, fn.addr)
                selected = _set_before_call(fn, argregs, uses, own)
            args = [uses[r] for r in selected if r in uses]
            s.call = Call(s.call.target, tuple(args), s.call.bits)
            s.uses = [(r, uses[r]) for r in selected if r in uses]
    return fn


__all__ = ["recover_calls", "int_arg_regs"]

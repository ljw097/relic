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
from .ir import (Assign, Call, CallStmt, Cast, Const, Expr, Extract, IRFunction, Phi, Return, Var, children,
                 stmt_exprs, walk)
from .fpabi import arg_classes, float_int_params, fp_params, fp_part, fp_sig, is_fp_arch, is_fp_reg, place_args
from .sigs import arg_count, lookup

if TYPE_CHECKING:
    from ..analysis import Analysis

# integer argument registers, in order, per calling convention
_INT_ARGS = {
    "x64-sysv": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "x64-win": ("rcx", "rdx", "r8", "r9"),
    "x86-cdecl": (),  # arguments are passed on the stack (recovered with the frame, stage 3b)
    "arm64-aapcs": tuple(f"x{k}" for k in range(8)),
    "arm-aapcs": ("r0", "r1", "r2", "r3"),
    "arm-aapcs-vfp": ("r0", "r1", "r2", "r3"),
    "mips-o32": ("a0", "a1", "a2", "a3"),
    "mips-n64": tuple(f"a{k}" for k in range(8)),
    "riscv64-lp64d": tuple(f"a{k}" for k in range(8)),
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


def _entry_ssa(an: "Analysis", arch: ArchInfo, target: int):
    """The callee's lifted SSA (unoptimised, cached): what it does with its entry registers."""
    cache = an.__dict__.setdefault("_entry_ssa_cache", {})
    if target not in cache:
        f = an.functions.get(target)
        ssa = None
        if f is not None and not f.is_import:
            from .lift import lift_function
            from .ssa import to_ssa
            try:
                ssa = to_ssa(lift_function(an, f), arch)
            except Exception:  # noqa: BLE001 - no summary for a function that does not lift
                ssa = None
        cache[target] = ssa
    return cache[target]


def param_bits(an: "Analysis", arch: ArchInfo, target: int) -> dict[str, int]:
    """Argument register -> width the callee reads it at (32 for an `int` parameter on a 64-bit
    target: every read of the entry value is its low half). Registers it never reads are absent."""
    cache = an.__dict__.setdefault("_param_bits_cache", {})
    if target in cache:
        return cache[target]
    out: dict[str, int] = {}
    ssa = _entry_ssa(an, arch, target)
    regs = set(int_arg_regs(arch))
    if ssa is not None and regs:
        widths: dict[str, int] = {}

        def visit(e: Expr, under: int | None):
            if isinstance(e, Var) and e.version == 0 and e.name in regs:
                widths[e.name] = max(widths.get(e.name, 0), under if under is not None else e.bits)
                return
            if isinstance(e, Cast) and e.kind == "low":
                visit(e.a, e.bits)
                return
            for k in children(e):
                visit(k, None)
        for s in ssa.stmts():
            if isinstance(s, CallStmt):
                # implicit uses of a call list every argument register: not a read of a parameter,
                # unless the value really is an argument (args are recovered later)
                for k in children(s.call):
                    visit(k, None)
                continue
            for top in stmt_exprs(s):
                visit(top, None)
        out = widths
    cache[target] = out
    return out


def narrow_call_args(an: "Analysis", arch: ArchInfo, fn) -> int:
    """`gcd(v2, 0xfffffffb)` -> `gcd(v2, -5)`: a 64-bit constant passed in a register the local
    callee only reads as 32 bits is that 32-bit value (`mov w1, #-5` zero-extends into x1)."""
    if arch.bits != 64:
        return 0
    regs = int_arg_regs(arch)
    n = 0
    for s in fn.stmts():
        call = s.call if isinstance(s, CallStmt) else None
        if call is None:
            continue
        sig = lookup(s.name or (an.name(call.target.value) if isinstance(call.target, Const) else None), an)
        if sig is not None and sig.types:
            # a library function's `int` parameters (`mmap(..., -1, 0)`: `mov ecx, -1` zero-extends)
            widths = {regs[k]: 32 for k, t in enumerate(sig.types[:len(regs)]) if t in _INT32}
        elif isinstance(call.target, Const) and call.target.value in an.functions:
            widths = param_bits(an, arch, call.target.value)
        else:
            continue
        args = list(call.args)
        changed = False
        for k, a in enumerate(args):
            if k < len(regs) and widths.get(regs[k]) == 32 and isinstance(a, Const) and a.bits == 64 \
                    and a.value >> 32 == 0:
                args[k] = Const(a.value, 32)
                changed = True
        if changed:
            n += 1
            s.call = Call(call.target, tuple(args), call.bits, call.fargs)
    return n


_INT32 = ("int", "unsigned int", "uid_t", "gid_t", "pid_t", "mode_t", "socklen_t")


def livein_regs(an: "Analysis", arch: ArchInfo, target: int) -> set[str]:
    """Every argument register the callee really reads on entry (no prefix rule)."""
    return _compute_livein(an, arch, target, prefix=False)


def _entry_opt(an: "Analysis", arch: ArchInfo, target: int):
    """The callee's SSA after the optimisation passes (no call recovery, so no recursion into
    other callees): a register the code only seemed to read -- the old value a predicated
    `movgt r0, #1; movle r0, #0` keeps, a scratch read that folds away -- is not read there."""
    cache = an.__dict__.setdefault("_entry_opt_cache", {})
    from .fpabi import fp_return_pending
    if fp_return_pending(an, target):
        return _entry_ssa(an, arch, target)      # its float result is not known yet: do not keep this
    done = an.__dict__.setdefault("_entry_opt_done", set())
    if target not in cache:
        ssa = _entry_ssa(an, arch, target)
        cache[target] = ssa                 # (while this one is worked out: the unoptimised reads)
        opt = ssa
        f = an.functions.get(target)
        if ssa is not None and f is not None:
            from .fpabi import set_fp_returns
            from .lift import lift_function
            from .passes import optimize
            from .ssa import to_ssa
            try:
                from .fpabi import fp_return
                if fp_return(an, f) is None:
                    # no float result to keep alive: the same SSA as the unoptimised one
                    import copy
                    opt = optimize(copy.deepcopy(ssa), arch)
                else:
                    fn = lift_function(an, f)
                    set_fp_returns(an, f, fn)   # a float result keeps the computation of it alive
                    opt = optimize(to_ssa(fn, arch), arch)
                if not fp_return_pending(an, target):
                    done.add(target)
            except Exception:  # noqa: BLE001 - fall back to the unoptimised reads
                opt = ssa
        cache[target] = opt
    return cache[target]


def optimized_ssa(an: "Analysis", arch: ArchInfo, target: int):
    """The function's optimised SSA before call recovery -- what `decompile_ir` recovers calls
    in, and what its callers read its parameters from (computed once for both) -- or None when it
    is not settled yet (its float result is being worked out, it does not lift). Shared: copy it
    before changing it."""
    from .fpabi import fp_return_pending
    if fp_return_pending(an, target):
        return None
    opt = _entry_opt(an, arch, target)
    return opt if target in an.__dict__.get("_entry_opt_done", ()) else None


def _compute_livein(an: "Analysis", arch: ArchInfo, target: int, prefix: bool = True):
    ssa = _entry_opt(an, arch, target)
    if ssa is None:
        return [] if prefix else set()
    # a call's implicit `uses` list every argument register the convention allows, which
    # would make every register look like a parameter; only count what the callee really
    # reads, plus the registers a known libc callee consumes (wrappers passing args along).
    # Phis are followed only from such real uses (clobbered registers merge at joins).
    phis: dict[Var, Phi] = {}
    used: set[Var] = set()
    # a function returning a float does not return the integer register: its `return` (which
    # reads that register until the float result is known) is no use of an argument register
    float_result = None
    for s in ssa.stmts():
        if isinstance(s, Assign) and isinstance(s.src, Phi):
            phis[s.dst] = s.src
            continue
        tops = stmt_exprs(s)
        if isinstance(s, Return) and isinstance(s.value, Var) and s.value.name == arch.ret:
            if float_result is None:
                f = an.functions.get(target)
                from .fpabi import fp_return
                float_result = f is not None and fp_return(an, f) is not None
            if float_result:
                continue
        if isinstance(s, CallStmt):
            tops = [s.call]
            # a value computed for the call (folded into it by the optimiser) reads what it uses;
            # a register handed on untouched says nothing
            tops += [v for r, v in s.uses if not (isinstance(v, Var) and v.version == 0 and v.name == r)
                     and not isinstance(v, (Var, Const))]
            sig = lookup(s.name or (an.name(s.call.target.value) if isinstance(s.call.target, Const) else None), an)
            if sig is not None:
                argregs = int_arg_regs(arch)
                uses = dict(s.uses)
                fmt = _read_format(an, uses.get(argregs[sig.fmt])) if sig.fmt is not None and \
                    sig.fmt < len(argregs) else None
                n = len(argregs) if sig.variadic else arg_count(sig, fmt)
                keep = set(argregs[:n])
                if is_fp_arch(arch) and fmt is not None:
                    classes = arg_classes(sig, fmt, scan="scanf" in (s.name or ""))
                    keep = {r for r in place_args(arch, classes, argregs, variadic=True) if r in argregs}
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
    if not prefix:
        return livein & set(int_arg_regs(arch))
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
    """How many word-sized stack parameters an internal callee reads (cdecl `[esp_0 + 4k]`, the
    stack arguments past the registers on x86-64 / AArch64)."""
    cache = getattr(an, "_stack_params", None)
    if cache is None:
        cache = an._stack_params = {}
    if target in cache:
        return cache[target]
    cache[target] = 0          # recursion guard
    f = an.functions.get(target)
    if f is None or f.is_import:
        return 0
    from .stack import _build_spoff, Frame
    ssa = _entry_ssa(an, arch, target)           # (shared, read only)
    if ssa is None:
        return 0
    frame = Frame(arch, _build_spoff(ssa, arch))
    from .fpconst import float_operands
    from .ir import Load
    word = arch.bits // 8
    base = param_base(arch)
    top = 0
    floats: dict[int, int] = {}            # stack parameter index -> float width
    sizes: dict[int, int] = {}             # stack parameter offset (from the first) -> widest load, bytes
    shadow = 4 if arch.name == "x64-win" else 0   # the home slots of rcx, rdx, r8, r9
    defs = {st.dst: st.src for st in ssa.stmts() if isinstance(st, Assign) and isinstance(st.dst, Var)}

    def loaded(k):
        """The load a float operand comes from: directly, or through the register it went to."""
        for _ in range(3):
            while isinstance(k, Cast) and k.kind in ("low", "zext"):
                k = k.a
            if isinstance(k, Var) and k in defs:
                k = defs[k]
            else:
                break
        return k

    for st in ssa.stmts():
        for e in stmt_exprs(st):
            for x in walk(e):
                if isinstance(x, Load):
                    off = frame.offset_of(x.addr)
                    if off is not None and off >= base:
                        top = max(top, (off - base + x.bits // 8 + word - 1) // word)
                        rel = off - base - shadow * word
                        sizes[rel] = max(sizes.get(rel, 0), x.bits // 8)
                for k in float_operands(x):
                    k = loaded(k)
                    if isinstance(k, Load):
                        off = frame.offset_of(k.addr)
                        if off is not None and off >= base and off % word == 0:
                            floats[(off - base) // word - shadow] = k.bits
    top = max(0, top - shadow)
    an.__dict__.setdefault("_stack_param_floats", {})[target] = floats
    # the parameters as slots: a double on a 32-bit target spans two words
    slots, w = [], 0
    while w < top:
        rel = w * word
        size = word * 2 if word == 4 and (sizes.get(rel) == 8 or floats.get(w) == 64) else word
        slots.append((rel, size, floats.get(w)))
        w += size // word
    an.__dict__.setdefault("_stack_param_slots", {})[target] = slots
    cache[target] = top
    return top


def stack_param_slots(an: "Analysis", arch: ArchInfo, target: int) -> list[tuple[int, int, int | None]]:
    """The stack parameters of an internal callee: (offset from the first, size in bytes, float
    width or None). The program's entry point has none: the kernel's argc / argv block is not a
    C call's arguments."""
    if target == an.bin.entry:
        return []
    stack_param_count(an, arch, target)
    return an.__dict__.get("_stack_param_slots", {}).get(target, [])


def param_base(arch: ArchInfo) -> int:
    """Entry-stack-pointer offset of the first stack parameter: above the return address on x86,
    at the stack pointer itself where the return address is in a register (AArch64)."""
    return arch.bits // 8 if arch.name.startswith(("x86", "x64")) else 0


def stack_params_used(arch: ArchInfo) -> bool:
    """Whether calls on this convention get stack arguments recovered (cdecl has its own path)."""
    return arch.name.startswith(("x64", "arm64", "arm-aapcs", "riscv", "mips-n64"))


def stack_param_floats(an: "Analysis", arch: ArchInfo, target: int) -> dict[int, int]:
    """Which stack parameters of an internal callee it reads as floats: index -> width."""
    stack_param_count(an, arch, target)
    return an.__dict__.get("_stack_param_floats", {}).get(target, {})


def _arg_stores(b, k: int, frame, base: int, word: int) -> dict[int, int]:
    """Most recent store to each word-aligned outgoing argument slot at or above `base` (frame
    offsets) since the previous call in the block: offset -> statement index."""
    from .ir import Store
    stores: dict[int, int] = {}
    for j in range(k - 1, -1, -1):
        t = b.stmts[j]
        if isinstance(t, CallStmt):
            break
        if isinstance(t, Store):
            off = frame.offset_of(t.dst)
            if off is not None and off >= base and (off - base) % word == 0 and off not in stores:
                stores[off] = j
    return stores


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
            sig = lookup(s.name or (an.name(tgt) if tgt is not None else None), an)
            if sig is not None and sig.variadic:
                sig = None                       # (how many follow the fixed ones: the stores say)
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
    frame = None
    defs: dict | None = None
    for b in fn.blocks.values():
        consumed: set[int] = set()
        for k, s in enumerate(b.stmts):
            if not isinstance(s, CallStmt) or s.call.args:
                continue
            fps: list = []
            widths: dict = {}
            classes: list[str] = []
            stack_offs: list[int] | None = None      # offsets of the stack arguments (default: in order)
            stack_sizes: list[int] | None = None
            uses = dict(s.uses)
            tgt = s.call.target.value if isinstance(s.call.target, Const) else None
            name = s.name or (an.name(tgt) if tgt is not None else None)
            sig = lookup(name, an)
            f = an.functions.get(tgt) if tgt is not None else None
            fsig = fp_sig(name) if is_fp_arch(arch) else None
            placed: list | None = None          # per argument: register, or None (on the stack)
            if fsig is not None:
                classes = arg_classes(None, None, fsig)
                placed = place_args(arch, classes, argregs)
            elif sig is not None:
                fmt = _read_format(an, uses.get(argregs[sig.fmt])) if sig.fmt is not None and \
                    sig.fmt < len(argregs) else None
                if is_fp_arch(arch) and (fmt is not None or any(t in ("double", "float") for t in sig.types)):
                    classes = arg_classes(sig, fmt, scan="scanf" in (name or ""))
                    placed = place_args(arch, classes, argregs, variadic=fmt is not None)
                else:
                    n = arg_count(sig, fmt)
                    selected = list(argregs[:n]) + [None] * (n - len(argregs))   # the rest on the stack
                    if sig.variadic:                 # `execl(path, arg, ..., 0)`: what was set too
                        if own is None:
                            own = _livein_arg_regs(an, arch, fn.addr)
                        more = _set_before_call(fn, argregs, uses, own)
                        if len(more) > len(selected):
                            selected = more
            elif f is not None and not f.is_import:
                selected = _livein_arg_regs(an, arch, tgt)
                fps = fp_params(an, arch, tgt)
                widths = dict(fps)
                fints = dict(float_int_params(an, arch, tgt))      # RISC-V: floats past fa7
                selected = [r for r in selected if r not in fints]
                slots = stack_param_slots(an, arch, tgt) if stack_params_used(arch) else []
                if fps or slots:
                    placed = selected + [r for r, _ in fps] + ["=" + r for r in fints] + [None] * len(slots)
                    classes = ["i"] * len(selected) + ["d"] * len(fps) + \
                        ["f" if w == 32 else "d" for w in fints.values()] + \
                        [("f" if fw == 32 else "d") if fw else "i" for _, _, fw in slots]
                    stack_offs = [rel for rel, _, _ in slots]
                    stack_sizes = [size for _, size, _ in slots]
            else:
                if own is None:
                    own = _livein_arg_regs(an, arch, fn.addr)
                selected = _set_before_call(fn, argregs, uses, own)
            if placed is None:
                placed = selected
            stack_vals = iter(())
            if None in placed:
                if frame is None:
                    from .stack import Frame, _build_spoff
                    frame = Frame(arch, _build_spoff(fn, arch))
                if stack_offs is None:
                    on_stack = [c for c, r in zip(classes or ["i"] * len(placed), placed) if r is None]
                    stack_offs = stack_offsets(arch, on_stack)
                    stack_sizes = [8 if c == "d" else arch.bits // 8 for c in on_stack]
                stack_vals = _stack_values(b, k, s, frame, arch, stack_offs, consumed, stack_sizes)
            args = []
            fargs = []
            for pos, r in enumerate(placed):
                if r is None:                     # the next stack argument
                    v = next(stack_vals, None)
                    if v is None:
                        break
                    if pos < len(classes) and classes[pos] in "df":
                        fargs.append((len(args), 32 if classes[pos] == "f" else 64))
                        v = Cast("low", v, 64) if v.bits > 64 else v
                    args.append(v)
                    continue
                if ":" in r:                      # a double in a pair of core registers (variadic ARM)
                    lo_r, hi_r = r.split(":")
                    if lo_r not in uses or hi_r not in uses:
                        continue
                    if defs is None:
                        defs = {t.dst: t.src for t in fn.stmts() if isinstance(t, Assign) and isinstance(t.dst, Var)}
                    v = _pair_value(uses[lo_r], uses[hi_r], defs)
                    fargs.append((len(args), 64))
                    args.append(v)
                    continue
                if r[:1] == "=":                  # a float in a core register (variadic RISC-V)
                    if r[1:] not in uses:
                        continue
                    fargs.append((len(args), 32 if pos < len(classes) and classes[pos] == "f" else 64))
                    args.append(uses[r[1:]])
                    continue
                full, lo, part = fp_part(r) if is_fp_reg(r) else (r, 0, None)
                if full not in uses:
                    continue
                v = uses[full]
                if is_fp_reg(r):                  # the float in the register (its low lanes, or an ARM half)
                    w = widths.get(r) or part or (32 if pos < len(classes) and classes[pos] == "f" else 64)
                    v = Extract(v, lo, w) if lo else Cast("low", v, w) if v.bits > w else v
                    fargs.append((len(args), w))
                args.append(v)
            s.call = Call(s.call.target, tuple(args), s.call.bits, tuple(fargs))
            used = dict.fromkeys(x for r in placed if r is not None for x in fp_part(r)[0].split(":"))
            s.uses = [(r, uses[r]) for r in used if r in uses]
        if consumed:
            b.stmts = [t for j, t in enumerate(b.stmts) if j not in consumed]
    return fn


def _pair_value(lo: Expr, hi: Expr, defs: dict | None = None) -> Expr:
    """The 64-bit value two core registers carry: `lo | hi << 32` -- the double itself when they
    are its halves (`vmov r2, r3, d7`, or two loads of one double: `ldrd r2, r3, [sp, #8]`)."""
    from .ir import BinOp, Load
    if defs:
        rlo = defs.get(lo, lo) if isinstance(lo, Var) else lo
        rhi = defs.get(hi, hi) if isinstance(hi, Var) else hi
        if isinstance(rlo, Load) and isinstance(rhi, Load):
            la = defs.get(rlo.addr, rlo.addr) if isinstance(rlo.addr, Var) else rlo.addr
            ha = _split_addr(rhi.addr)
            ha = (defs.get(ha[0], ha[0]) if isinstance(ha[0], Var) else ha[0], ha[1])
            hb = _split_addr(ha[0])
            lb = _split_addr(la)
            if rlo.bits == rhi.bits == 32 and hb[0] == lb[0] and hb[1] + ha[1] == lb[1] + 4:
                return Load(la, 64)
    if isinstance(lo, Cast) and lo.kind == "low" and isinstance(hi, Extract) and hi.lo == 32 and lo.a == hi.a \
            and lo.a.bits == 64:
        return lo.a
    from .ir import Load
    if isinstance(lo, Load) and isinstance(hi, Load) and lo.bits == hi.bits == 32 and \
            _split_addr(hi.addr) == (_split_addr(lo.addr)[0], _split_addr(lo.addr)[1] + 4):
        return Load(lo.addr, 64)                     # the two halves of one double in memory
    return BinOp("|", Cast("zext", lo, 64), BinOp("<<", Cast("zext", hi, 64), Const(32, 8), 64), 64)


def _split_addr(a: Expr) -> tuple[Expr, int]:
    """`base + k` -> (base, k)."""
    from .ir import BinOp
    if isinstance(a, BinOp) and a.op in ("+", "-") and isinstance(a.b, Const):
        base, k0 = _split_addr(a.a)
        k = a.b.signed
        return base, k0 + (k if a.op == "+" else -k)
    return a, 0


def stack_offsets(arch: ArchInfo, classes: list[str]) -> list[int]:
    """Offsets of stack arguments of these classes, in order: a word each, a double two words
    aligned to eight bytes on 32-bit targets."""
    word = arch.bits // 8
    out, off = [], 0
    for c in classes:
        size = 8 if c == "d" else word
        if size == 8 and word == 4:
            off = (off + 7) & ~7
        out.append(off)
        off += size
    return out


def _stack_values(b, k: int, s: CallStmt, frame, arch: ArchInfo, offs: list[int], consumed: set[int],
                  sizes: list[int] | None = None):
    """The values stored to the outgoing stack argument slots at `offs` (from the stack pointer at
    the call) before call `s` (statement `k` of block `b`), in order, stopping at the first slot
    not written; their stores are marked consumed (they become the call's arguments)."""
    from .fpabi import stack_arg_base
    if s.tail:
        return
    sp = dict(s.uses).get(arch.sp)
    sp_off = frame.offset_of(sp) if sp is not None else None
    if sp_off is None:
        return
    word = arch.bits // 8
    base = sp_off + stack_arg_base(arch)
    stores = _arg_stores(b, k, frame, base, word)
    for n, rel in enumerate(offs):
        j = stores.get(base + rel)
        if j is None:
            return
        consumed.add(j)
        v = b.stmts[j].src
        if word == 4 and sizes is not None and sizes[n] == 8 and v.bits == 32:   # a double stored as two words
            j2 = stores.get(base + rel + 4)
            if j2 is None:
                return
            consumed.add(j2)
            v = _pair_value(v, b.stmts[j2].src)
        yield v


__all__ = ["recover_calls", "int_arg_regs"]

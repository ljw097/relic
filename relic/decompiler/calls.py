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
from .ir import (Assign, BinOp, Call, CallStmt, Cast, Const, Reg, Expr, Extract, IRFunction, Phi, Return, Var, children,
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
    "arm64-aapcs-apple": tuple(f"x{k}" for k in range(8)),
    "arm-aapcs": ("r0", "r1", "r2", "r3"),
    "arm-aapcs-vfp": ("r0", "r1", "r2", "r3"),
    "mips-o32": ("a0", "a1", "a2", "a3"),
    "mips-n64": tuple(f"a{k}" for k in range(8)),
    "ppc32-sysv": tuple(f"r{k}" for k in range(3, 11)),
    "ppc64-elfv2": tuple(f"r{k}" for k in range(3, 11)),
    "riscv64-lp64d": tuple(f"a{k}" for k in range(8)),
    "riscv32-ilp32d": tuple(f"a{k}" for k in range(8)),
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
        cache[target] = []                  # (while it is worked out: a recursive call takes none)
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
                from .aggabi import set_struct_returns
                fn = lift_function(an, f)
                set_struct_returns(an, f, fn)       # (a struct result in rax:rdx: all of it is returned)
                ssa = to_ssa(fn, arch)
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


RESULT_AT = "resultat:"      # Intrinsic: an indirect result's place (its one argument), `size` bytes


def indirect_result(an: "Analysis", arch: ArchInfo, target: int) -> int:
    """AArch64: the function uses x8 as it came in -- the indirect result location, where its
    caller wants a struct result too big for registers. Shown as a first parameter `result`.
    How many bytes it writes there (at least 1), or 0: it does not."""
    if arch.name not in ("arm64-aapcs", "arm64-apple"):
        return 0
    cache = an.__dict__.setdefault("_indirect_result", {})
    if target not in cache:
        cache[target] = _indirect_result_size(an, arch, target)
    return cache[target]


def _indirect_result_size(an: "Analysis", arch: ArchInfo, target: int) -> int:
    """How many bytes a function writes where x8 pointed on entry (directly, or -O0: through a
    copy of it spilled to the stack and loaded back); 0 when it does not write there at all
    (x8 only flowing into a phi is a scratch register's old value, not a result pointer)."""
    from .ir import Load, Store
    ssa = _entry_ssa(an, arch, target)
    if ssa is None:
        return 0
    x8 = Var("x8", 0, 64)
    defs = {t.dst: t.src for t in ssa.stmts() if isinstance(t, Assign) and isinstance(t.dst, Var)}

    def copy_of(v):
        for _ in range(8):                      # (through plain copies: `mov x3, x8`)
            if isinstance(v, Var) and isinstance(defs.get(v), Var):
                v = defs[v]
            else:
                break
        return v

    def base_off(a):
        """(base, offset) of an address `b` / `b + K`, its base through copies."""
        a = copy_of(a)
        a = defs.get(a, a) if isinstance(a, Var) else a
        if isinstance(a, BinOp) and a.op == "+" and isinstance(a.b, Const):
            return copy_of(a.a), a.b.value
        return copy_of(a), 0

    # where it is (x8 itself, the stack slots it was saved to, what is loaded back from them)
    spills = [base_off(st.dst) for st in ssa.stmts() if isinstance(st, Store) and st.src == x8]
    holders = {x8}
    for v, src in defs.items():
        if isinstance(src, Load) and base_off(src.addr) in spills:
            holders.add(v)
    size = 0
    for st in ssa.stmts():
        if isinstance(st, Store):
            b, off = base_off(st.dst)
            if b in holders and (b != x8 or st.src != x8):
                size = max(size, off + st.bits // 8)
    return size


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
                    from .aggabi import set_struct_returns
                    set_struct_returns(an, f, fn)
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
    passed: set[str] = set()        # argument registers handed on to a call as they came in
    moved: set[str] = set()         # ... or moved into another argument register a callee takes
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
            passed |= {r for r, v in s.uses if isinstance(v, Var) and v.version == 0 and v.name == r}
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
                    keep = {r for r in place_args(arch, classes, argregs, variadic=True, fixed=sig.fmt + 1)
                            if r in argregs}
                tops += [v for r, v in s.uses if r in keep]
                moved |= {v.name for r, v in s.uses if r in keep and isinstance(v, Var) and v.version == 0
                          and v.name != r}
            elif prefix and isinstance(s.call.target, Const) and s.call.target.value != target:
                # an internal callee: what it takes as parameters is read here too (a register
                # moved into its argument register, or handed on as it came in)
                callee = an.functions.get(s.call.target.value)
                if callee is not None and not callee.is_import:
                    keep = set(_livein_arg_regs(an, arch, callee.addr))
                    tops += [v for r, v in s.uses if r in keep]
                    moved |= {v.name for r, v in s.uses if r in keep and isinstance(v, Var) and v.version == 0
                              and v.name != r}
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
    gaps = 0
    if arch.name.startswith("ppc64"):
        # ELFv2 assigns registers by position: a floating-point argument also takes up the GPR of
        # its slot, so `f(int, double, float, long)` reads r3 and r6 -- a gap a parameter in an
        # FPR explains is no end of the list
        from .fpabi import fp_params
        gaps = len(fp_params(an, arch, target))
    regs = int_arg_regs(arch)
    real = _real_reads(ssa, set(regs)) | moved
    for k, r in enumerate(regs):
        if r not in livein:
            if gaps:
                gaps -= 1
                continue
            if r in passed and any(x in livein for x in regs[k + 1:]):
                params.append(r)        # (handed on to a call untouched, before one that is read)
                continue
            if any(x in real for x in regs[k + 1:]):
                params.append(r)        # (an unused parameter before one the code reads: `f(L, t)`)
                continue
            break
        params.append(r)
    return params


def _real_reads(ssa, regs: set[str]) -> set[str]:
    """Argument registers whose entry value the code computes with: not only handed on to a call
    (its `uses` list every argument register), nor only the bits a partial write keeps (`mov dl,
    al` merges al into rdx: `rdx & ~0xff | al`)."""
    real: set[str] = set()

    def visit(e, keep_only: bool):
        if isinstance(e, Var):
            if e.version == 0 and e.name in regs and not keep_only:
                real.add(e.name)
            return
        if isinstance(e, BinOp) and e.op == "&" and any(isinstance(k, Const) and k.value & 0xFF == 0
                                                         for k in (e.a, e.b)):
            for c in (e.a, e.b):
                visit(c, True)
            return
        for c in children(e):
            visit(c, False)
    for st in ssa.stmts():
        if isinstance(st, CallStmt):
            visit(st.call, False)
            continue
        if isinstance(st, Assign) and isinstance(st.src, Phi):
            continue
        for top in stmt_exprs(st):
            visit(top, False)
    return real



def positional_order(arch: ArchInfo, ints: list[str], fps: list) -> list[int] | None:
    """PowerPC64 ELFv2: the C order of a callee's parameters, as indexes into `ints + fps`.
    Argument k goes in r(3+k) if it is an integer, else in the next FPR (taking r(3+k) up too),
    so each integer parameter's register says where it was; the floats fill the other places.
    None elsewhere (integers first, then floats: the registers do not say)."""
    if not arch.name.startswith("ppc64"):
        return None
    pos = {int(r[1:]) - 3: k for k, r in enumerate(ints) if r[:1] == "r" and r[1:].isdigit()}
    order, f = [], 0
    for k in range(len(ints) + len(fps)):
        if k in pos:
            order.append(pos[k])
        elif f < len(fps):
            order.append(len(ints) + f)
            f += 1
    seen = set(order)
    order += [k for k in range(len(ints) + len(fps)) if k not in seen]
    return order


def _icall_params(an: "Analysis", arch: ArchInfo, site: int) -> list[str] | None:
    """The integer argument registers an indirect call's known targets all take (None when they
    differ, take floats, or are not known)."""
    hit = getattr(an, "icalls", {}).get(site)
    if not hit:
        return None
    lists = set()
    for t in hit[0]:
        f = an.functions.get(t)
        if f is None or f.is_import or fp_params(an, arch, t):
            return None
        lists.add(tuple(_livein_arg_regs(an, arch, t)))
    return list(lists.pop()) if len(lists) == 1 else None


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
        computed = v is not None and not isinstance(v, (Var, Const, Phi))     # (propagated into the call)
        if not (isinstance(v, Const) or computed or (isinstance(v, Var) and (v in defined or
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
    if word == 4:
        _paired_doubles(ssa, frame, base, word, floats, loaded)
    for rel in _forwarded_long_doubles(an, arch, ssa, frame, target, base):
        rel -= shadow * word
        sizes[rel] = 10
        floats[rel // word] = 80
    top = max(0, top - shadow)
    an.__dict__.setdefault("_stack_param_floats", {})[target] = floats
    # the parameters as slots: a double on a 32-bit target spans two words, a long double three
    # (sixteen bytes on x86-64)
    slots, w = [], 0
    while w < top:
        rel = w * word
        if sizes.get(rel) == 10 or floats.get(w) == 80:
            size = 12 if word == 4 else 16
            floats[w] = 80
        else:
            size = word * 2 if word == 4 and (sizes.get(rel) == 8 or floats.get(w) == 64) else word
        slots.append((rel, size, floats.get(w)))
        w += size // word
    an.__dict__.setdefault("_stack_param_slots", {})[target] = slots
    cache[target] = top
    return top


def _forwarded_long_doubles(an: "Analysis", arch: ArchInfo, ssa, frame, target: int, base: int) -> list[int]:
    """Stack parameters (offsets from `base`) only handed on, word by word, to a callee that
    takes a long double there (`push qword [rsp+0x28]` twice, then `call`): long doubles too."""
    from .fpabi import stack_arg_base
    from .ir import Load, Store
    if not arch.name.startswith(("x86", "x64-sysv")):
        return []
    word = arch.bits // 8
    out = []
    defs = None
    for b in ssa.blocks.values():
        for k, s in enumerate(b.stmts):
            if not isinstance(s, CallStmt) or not isinstance(s.call.target, Const) or s.call.target.value == target:
                continue
            g = an.functions.get(s.call.target.value)
            if g is None or g.is_import or g.addr not in _long_double_users(an):
                continue
            slots = [rel for rel, _, fw in stack_param_slots(an, arch, g.addr) if fw == 80]
            sp = dict(s.uses).get(arch.sp)
            sp_off = frame.offset_of(sp) if sp is not None and slots else None
            if sp_off is None:
                continue
            outgoing = sp_off + (stack_arg_base(arch) if arch.bits == 64 else 0)
            if defs is None:
                defs = {t.dst: t.src for t in ssa.stmts() if isinstance(t, Assign) and isinstance(t.dst, Var)}
            srcs: dict[int, int] = {}           # outgoing slot -> the parameter word copied there
            for t in reversed(b.stmts[:k]):
                if isinstance(t, CallStmt):
                    break
                v = defs.get(t.src, t.src) if isinstance(t, Store) else None     # (`push`: through a temporary)
                if isinstance(v, Load) and v.bits == word * 8:
                    d, p = frame.offset_of(t.dst), frame.offset_of(v.addr)
                    if d is not None and p is not None and p >= base and d not in srcs:
                        srcs[d] = p
            for rel in slots:
                p = srcs.get(outgoing + rel)
                if p is not None and all(srcs.get(outgoing + rel + n * word) == p + n * word
                                         for n in range(1, (10 + word - 1) // word)):
                    out.append(p - base)
    return out


def _long_double_users(an: "Analysis") -> set[int]:
    """The functions that may take a long double on the stack: the ones with an 80-bit memory
    operand (`fld xword ptr [rsp + 8]`), and their callers, which may only hand one on. Any
    other callee has no long double slot, and is not lifted (with all it calls) to find out."""
    got = an.__dict__.get("_long_double_users")
    if got is not None:
        return got
    out = {a for a, f in an.functions.items() if not f.is_import
           and any("xword" in i.op_str for b in f.blocks.values() for i in b.insns)}
    callers: dict[int, set[int]] = {}
    for a, f in an.functions.items():
        for t in f.calls | f.tail_calls:
            callers.setdefault(t, set()).add(a)
    work = list(out)
    while work:
        for c in callers.get(work.pop(), ()):
            if c not in out:
                out.add(c)
                work.append(c)
    an.__dict__["_long_double_users"] = out
    return out


def _paired_doubles(ssa, frame, base: int, word: int, floats: dict, loaded):
    """32-bit x86 at -O0: a double parameter copied word by word into a local that is then read
    whole as a float (`mov eax, [ebp+8]; mov [ebp-16], eax; mov eax, [ebp+12]; mov [ebp-12], eax;
    fld qword [ebp-16]`) -- the two words are one double."""
    from .fpconst import float_operands
    from .ir import Load, Store
    copies: dict[int, int] = {}            # local offset -> parameter word stored there
    for st in ssa.stmts():
        if isinstance(st, Store) and st.bits == 32:
            src = loaded(st.src)
            dst = frame.offset_of(st.dst)
            if isinstance(src, Load) and src.bits == 32 and dst is not None and dst < 0:
                off = frame.offset_of(src.addr)
                if off is not None and off >= base and (off - base) % word == 0:
                    copies[dst] = (off - base) // word
    if not copies:
        return
    wide = set()                           # locals read whole as a double
    for st in ssa.stmts():
        for e in stmt_exprs(st):
            for x in walk(e):
                for k in float_operands(x):
                    k = loaded(k)
                    if isinstance(k, Load) and k.bits == 64:
                        o = frame.offset_of(k.addr)
                        if o is not None:
                            wide.add(o)
    for o in wide:
        w = copies.get(o)
        if w is not None and copies.get(o + 4) == w + 1:
            floats.setdefault(w, 64)


def merge_word_copies(fn: IRFunction, arch: ArchInfo) -> int:
    """32-bit x86: a double copied word by word between stack slots (`[ebp-16] = [ebp+8];
    [ebp-12] = [ebp+12]`) and then read whole as a double is one 64-bit copy. How many merged."""
    from .fpconst import float_operands
    from .ir import Load, Store
    from .stack import Frame, _build_spoff
    frame = Frame(arch, _build_spoff(fn, arch))
    defs = {st.dst: st.src for st in fn.stmts() if isinstance(st, Assign) and isinstance(st.dst, Var)}
    load = lambda e: defs.get(e, e) if isinstance(e, Var) else e
    wide = set()
    for st in fn.stmts():
        for e in stmt_exprs(st):
            for x in walk(e):
                for k in float_operands(x):
                    k = load(k)
                    if isinstance(k, Load) and k.bits == 64:
                        o = frame.offset_of(k.addr)
                        if o is not None:
                            wide.add(o)
    if not wide:
        return 0
    n = 0
    for b in fn.blocks.values():
        first: dict[int, tuple[int, int]] = {}      # destination offset -> (statement index, source offset)
        drop = set()
        for k, st in enumerate(b.stmts):
            if isinstance(st, CallStmt):
                first.clear()
                continue
            if not isinstance(st, Store):
                continue
            dst = frame.offset_of(st.dst)
            v = load(st.src)
            src = frame.offset_of(v.addr) if isinstance(v, Load) and st.bits == 32 else None
            if dst is not None and src is not None and first.get(dst - 4, (0, None))[1] == src - 4:
                j, _ = first.pop(dst - 4)
                lo = b.stmts[j]
                b.stmts[j] = Store(lo.addr, lo.dst, Load(load(lo.src).addr, 64))
                drop.add(k)
                n += 1
                continue
            # any other store over a slot recorded so far ends that pair
            near = lambda x, o: x is not None and o - 8 < x < o + 8
            for o in [o for o in first if dst is None or near(dst, o) or near(src, o)]:
                del first[o]
            if dst is not None and src is not None and dst in wide:
                first[dst] = (k, src)
        if drop:
            b.stmts = [t for k, t in enumerate(b.stmts) if k not in drop]
    return n


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
    if arch.name.startswith("ppc32"):
        return 8                    # above the back chain and the callee's LR save word
    if arch.name.startswith("ppc64"):
        return 96                   # the parameter save area (32), past the 8 register doublewords
    return arch.bits // 8 if arch.name.startswith(("x86", "x64")) else 0


def stack_params_used(arch: ArchInfo) -> bool:
    """Whether calls on this convention get stack arguments recovered (cdecl has its own path)."""
    return arch.name.startswith(("x64", "arm64", "arm-aapcs", "riscv", "mips-n64", "ppc"))


def stack_param_floats(an: "Analysis", arch: ArchInfo, target: int) -> dict[int, int]:
    """Which stack parameters of an internal callee it reads as floats: index -> width."""
    stack_param_count(an, arch, target)
    return an.__dict__.get("_stack_param_floats", {}).get(target, {})


def _long_double_copy(b, stores: dict, off: int, word: int, frame) -> tuple[Expr, list[int]] | None:
    """A long double argument copied into its stack slot word by word (`push qword [rsp+0x18]`
    twice on x86-64, three dwords on x86): the long double those words were read from, and the
    stores of the words past the first."""
    from .ir import Load
    first = b.stmts[stores[off]].src
    if not isinstance(first, Load) or first.bits != word * 8:
        return None
    src = frame.offset_of(first.addr)
    split = _split_addr(first.addr)
    more = []
    for k in range(1, (10 + word - 1) // word):
        j = stores.get(off + k * word)
        if j is None:
            return None
        v = b.stmts[j].src
        if not isinstance(v, Load) or v.bits != word * 8:
            return None
        if src is not None:             # (a stack slot: by its frame offset, whatever register says so)
            if frame.offset_of(v.addr) != src + k * word:
                return None
        else:
            nxt = _split_addr(v.addr)
            if nxt[0] != split[0] or nxt[1] != split[1] + k * word:
                return None
        more.append(j)
    return Load(first.addr, 80), more


def _split_addr(addr: Expr) -> tuple[Expr, int]:
    """(base, constant offset) of an address: `p + 8` is (p, 8)."""
    if isinstance(addr, BinOp) and addr.op == "+" and isinstance(addr.b, Const):
        return addr.a, addr.b.value
    return addr, 0


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
    """Arguments of x86-32 calls: the values stored at [esp], [esp+4], ... before the call -- a
    word each, a double two (one 64-bit store, or its two halves)."""
    from .ir import BinOp, Load, Store
    from .stack import Frame, _build_spoff
    frame = Frame(arch, _build_spoff(fn, arch))
    word = arch.bits // 8
    defs = {t.dst: t.src for t in fn.stmts() if isinstance(t, Assign) and isinstance(t.dst, Var)}
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
            slots = _cdecl_slots(an, arch, s, b, stores, base)
            args, fargs, idx = [], [], []
            for rel, size, fw in slots:
                j = stores.get(base + rel)
                if j is None:
                    if not s.tail:
                        break
                    # passed straight through: the caller's own parameter slot, unchanged
                    delta = base + rel - sp_off
                    v = Load(BinOp("+", sp, Const(delta, arch.bits), arch.bits), 80 if fw == 80 else size * 8)
                else:
                    v = b.stmts[j].src
                    idx.append(j)
                    if fw == 80 and v.bits != 80:
                        copy = _long_double_copy(b, stores, base + rel, word, frame)
                        if copy is None:
                            break
                        v, more = copy
                        idx += more
                    elif size == 8 and v.bits == 32:            # a double stored as two words
                        j2 = stores.get(base + rel + 4)
                        if j2 is None:
                            break
                        idx.append(j2)
                        v = _pair_value(v, b.stmts[j2].src, defs)
                if fw:
                    fargs.append((len(args), fw))
                    if fw == 32 and v.bits == 32:
                        pass
                    elif fw == 32:
                        v = Cast("low", v, 32)
                args.append(v)
            s.call = Call(s.call.target, tuple(args), s.call.bits, tuple(fargs))
            s.uses = []          # the stack pointer only located the arguments
            consumed |= set(idx)
        if consumed:
            b.stmts = [t for j, t in enumerate(b.stmts) if j not in consumed]


def _cdecl_slots(an: "Analysis", arch: ArchInfo, s: CallStmt, b, stores: dict, base: int) -> list[tuple]:
    """(offset from the first argument, size in bytes, float width or None) of each argument of
    an x86-32 call: from the callee's own parameters, the libc signature (and format string), or
    -- for a call to an unknown function -- the stores before it."""
    from .fpabi import arg_classes
    word = arch.bits // 8
    tgt = s.call.target.value if isinstance(s.call.target, Const) else None
    name = s.name or (an.name(tgt) if tgt is not None else None)
    f = an.functions.get(tgt) if tgt is not None else None
    sig = lookup(name, an)
    fsig = fp_sig(name)
    classes = None
    if fsig is not None:
        classes = arg_classes(None, None, fsig, ldouble=True)
    elif sig is not None:
        fmt = None
        if sig.fmt is not None and base + sig.fmt * word in stores:
            fmt = _read_format(an, b.stmts[stores[base + sig.fmt * word]].src)
        if not sig.variadic or fmt is not None:
            classes = arg_classes(sig, fmt, scan="scanf" in (name or ""), wide=True, ldouble=True)
            if not sig.variadic or fmt is None:
                classes = classes[:arg_count(sig, fmt)]
    elif f is not None and not f.is_import:
        return stack_param_slots(an, arch, tgt)
    if classes is not None:
        out, off = [], 0
        for c in classes:
            size = 12 if c == "L" else 8 if c in "dq" else word
            out.append((off, size, {"d": 64, "f": 32, "L": 80}.get(c)))
            off += size
        return out
    # unknown callee: as many as were stored, a 64-bit store taking two words
    out, off = [], 0
    while base + off in stores:
        st = b.stmts[stores[base + off]]
        size = 8 if st.src.bits == 64 else word
        out.append((off, size, None))
        off += size
    return out


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
            sel = objc_selector(an, fn, name, uses.get(argregs[1]) if len(argregs) > 1 else None)
            if sel is not None:
                n = 2 + sel.count(":")
                placed = list(argregs[:n]) + [None] * (n - len(argregs))
            elif _agg_call(an, arch, fn, b, k, s, name, uses, consumed):
                continue                            # (structs by value: see aggabi)
            elif fsig is not None:
                classes = arg_classes(None, None, fsig, ldouble=arch.name == "x64-sysv")
                placed = place_args(arch, classes, argregs)
            elif sig is not None:
                fmt = _read_format(an, uses.get(argregs[sig.fmt])) if sig.fmt is not None and \
                    sig.fmt < len(argregs) else None
                if is_fp_arch(arch) and (fmt is not None or any(t in ("double", "float") for t in sig.types)):
                    classes = arg_classes(sig, fmt, scan="scanf" in (name or ""), ldouble=arch.name == "x64-sysv")
                    placed = place_args(arch, classes, argregs, variadic=fmt is not None,
                                        fixed=sig.fmt + 1 if sig.fmt is not None else None)
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
                if indirect_result(an, arch, tgt):
                    selected = ["x8"] + selected        # (where the struct result goes: first)
                fps = fp_params(an, arch, tgt)
                widths = dict(fps)
                fints = dict(float_int_params(an, arch, tgt))      # RISC-V: floats past fa7
                halves = {x for r in fints for x in r.split(":")}
                selected = [r for r in selected if r not in halves]
                slots = stack_param_slots(an, arch, tgt) if stack_params_used(arch) else []
                if fps or slots:
                    placed = selected + [r for r, _ in fps] + ["=" + r for r in fints] + [None] * len(slots)
                    classes = ["i"] * len(selected) + ["d"] * len(fps) + \
                        ["f" if w == 32 else "d" for w in fints.values()] + \
                        [{32: "f", 80: "L"}.get(fw, "d") if fw else "i" for _, _, fw in slots]
                    order = positional_order(arch, selected, fps)
                    if order is not None:            # (the parameters' C order: see pipeline)
                        head = len(selected) + len(fps)
                        placed = [placed[k] for k in order] + placed[head:]
                        classes = [classes[k] for k in order] + classes[head:]
                    stack_offs = [rel for rel, _, _ in slots]
                    stack_sizes = [size for _, size, _ in slots]
            elif tgt is None and _icall_params(an, arch, s.addr) is not None:
                # an indirect call whose possible targets are known (a function-pointer variable,
                # a virtual method): the arguments they take
                selected = _icall_params(an, arch, s.addr)
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
                    stack_sizes = [_stack_size(arch, c) for c in on_stack]
                stack_vals = _stack_values(b, k, s, frame, arch, stack_offs, consumed, stack_sizes)
            args = []
            fargs = []
            for pos, r in enumerate(placed):
                if r is None:                     # the next stack argument
                    v = next(stack_vals, None)
                    if v is None:
                        break
                    if pos < len(classes) and classes[pos] == "L":
                        fargs.append((len(args), 80))
                    elif pos < len(classes) and classes[pos] in "df":
                        fargs.append((len(args), 32 if classes[pos] == "f" else 64))
                        v = Cast("low", v, 64) if v.bits > 64 else v
                    args.append(v)
                    continue
                if ":" in r:                      # a double in a pair of core registers (variadic ARM, RV32)
                    lo_r, hi_r = r.lstrip("=").split(":")
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
                    if arch.name.startswith("ppc") and w < v.bits:
                        from .ir import Intrinsic     # PowerPC: a float travels in its double form
                        v = Intrinsic("fpconv", (v,), w)
                    else:
                        v = Extract(v, lo, w) if lo else Cast("low", v, w) if v.bits > w else v
                    fargs.append((len(args), w))
                args.append(v)
            target = s.call.target
            if isinstance(target, (Var, Reg)) and s.name:
                # through a register the lifter traced to an import (`call r14` = objc_msgSend)
                stub = next((i.addr for i in an.bin.imports if i.addr and i.name == s.name), None)
                slot = next((a for a, n in getattr(an.bin, "got_names", {}).items() if n == s.name), None)
                if stub is not None:
                    target = Const(stub, target.bits)
                elif slot is not None:                  # (called only through its GOT slot)
                    from .ir import Load
                    target = Load(Const(slot, target.bits), target.bits)
            if placed[:1] == ["x8"] and args and f is not None:
                size = indirect_result(an, arch, tgt)
                if size > 1:                        # (the caller's place for it: that many bytes, one object)
                    from .ir import Intrinsic
                    args[0] = Intrinsic(f"{RESULT_AT}{size}", (args[0],), args[0].bits)
            s.call = Call(target, tuple(args), s.call.bits, tuple(fargs))
            used = dict.fromkeys(x for r in placed if r is not None for x in fp_part(r.lstrip("="))[0].split(":"))
            s.uses = [(r, uses[r]) for r in used if r in uses]
        if consumed:
            b.stmts = [t for j, t in enumerate(b.stmts) if j not in consumed]
    return fn


def _agg_call(an: "Analysis", arch: ArchInfo, fn: IRFunction, b, k: int, s: CallStmt, name: str | None,
              uses: dict, consumed: set) -> bool:
    """A call to a function whose prototype passes or returns structs by value (aggabi): its
    arguments where the prototype puts them, a struct's parts gathered into one value
    (`Intrinsic("struct:pt", (x, y))`), the result pointer first. Whether it was one."""
    from .aggabi import STRUCT, STRUCT_COPY, plan
    from .ir import Intrinsic
    from .sigs import base_name
    p = plan(an, arch, base_name(name)) if name else None
    if p is None:
        return False
    stack = sorted({loc for loc in p.locs() if isinstance(loc, int)})
    got: dict[int, Expr] = {}
    frame = None
    if stack:
        from .stack import Frame, _build_spoff
        frame = Frame(arch, _build_spoff(fn, arch))
        vals = list(_stack_values(b, k, s, frame, arch, stack, set(), [8] * len(stack)))   # (consumed below)
        got = dict(zip(stack, vals))

    def value(loc, bits: int, fl: bool):
        v = got.get(loc) if isinstance(loc, int) else uses.get(loc)
        if v is None:
            return None
        if fl and v.bits > bits or not fl and v.bits > bits and bits < 64:
            v = Cast("low", v, bits)
        return v

    args, fargs = [], []
    if p.ret_memory:
        if p.ret_ptr not in uses:
            return False
        args.append(uses[p.ret_ptr])
    for prm in p.params:
        if prm.ref is not None:             # by reference (AArch64): the struct the pointer points to
            if prm.ref not in uses:
                return False
            from .aggabi import struct_of
            st = struct_of(an, prm.ctype)
            args.append(Intrinsic(STRUCT_COPY + an.resolve_type(prm.ctype).strip()[7:].strip(), (uses[prm.ref],),
                                  st.size * 8 if st is not None else 64))
            continue
        if prm.is_struct and isinstance(prm.pieces[0].loc, int):
            # on the stack: most often a copy of a local struct (`movdqa` + `movups`, ...)
            copied = _struct_copy(fn, b, k, s, frame, arch, prm.pieces[0].loc,
                                  prm.pieces[-1].loc + prm.pieces[-1].bits // 8 - prm.pieces[0].loc)
            if copied is not None:
                addr, js = copied
                consumed.update(js)
                args.append(Intrinsic(STRUCT_COPY + an.resolve_type(prm.ctype).strip()[7:].strip(), (addr,),
                                      sum(x.bits for x in prm.pieces)))
                continue
        if prm.is_struct and isinstance(prm.pieces[0].loc, int):
            # filled field by field (some copied from a local, some stored as they are)
            built = _stack_struct_fields(fn, b, k, s, frame, arch, prm.pieces)
            if built is None:
                return False
            vals, js = built
            consumed.update(js)
            args.append(Intrinsic(STRUCT + an.resolve_type(prm.ctype).strip()[7:].strip(), tuple(vals),
                                  sum(x.bits for x in prm.pieces)))
            continue
        if prm.is_struct:
            parts = [value(x.loc, x.bits, x.float) for x in prm.pieces]
            if any(v is None for v in parts):
                return False
            args.append(Intrinsic(STRUCT + an.resolve_type(prm.ctype).strip()[7:].strip(), tuple(parts),
                                  sum(x.bits for x in prm.pieces)))
            continue
        fl = isinstance(prm.loc, str) and prm.loc.startswith("xmm")
        v = value(prm.loc, 32 if an.resolve_type(prm.ctype).strip() == "float" else 64, fl)
        if v is None:
            return False
        if fl:
            fargs.append((len(args), v.bits))
        args.append(v)
    if got and not any(isinstance(a, Intrinsic) and a.name.startswith(STRUCT_COPY) for a in args):
        list(_stack_values(b, k, s, frame, arch, sorted(got), consumed, [8] * len(got)))  # (stores: arguments)
    s.call = Call(s.call.target, tuple(args), s.call.bits, tuple(fargs))
    s.struct_result = bool(p.ret_pieces) or p.ret_memory      # (the C writer shows it as one: see emit)
    regs = [loc for loc in p.locs() if isinstance(loc, str)]
    s.uses = [(r, uses[r]) for r in regs if r in uses]
    return True


def _stack_struct_fields(fn: IRFunction, b, k: int, s: CallStmt, frame, arch: ArchInfo, pieces):
    """The fields of a struct argument on the stack (aggabi pieces: one per field), from the stores
    before call `s` that fill its bytes: a field inside a copied word reads the source's bytes
    there, one stored on its own is that value. (values, the stores' indices), or None."""
    from .fpabi import stack_arg_base
    from .ir import BinOp, Load, Store
    sp = dict(s.uses).get(arch.sp)
    sp_off = frame.offset_of(sp) if sp is not None else None
    if sp_off is None or s.tail:
        return None
    base = sp_off + stack_arg_base(arch)
    lo, hi = base + pieces[0].loc, base + pieces[-1].loc + pieces[-1].bits // 8
    stores: dict[int, int] = {}
    for j in range(k - 1, -1, -1):
        t = b.stmts[j]
        if isinstance(t, CallStmt):
            break
        if isinstance(t, Store):
            off = frame.offset_of(t.dst)
            if off is not None and lo <= off < hi and off not in stores:
                stores[off] = j
    defs = {x.dst: x.src for x in fn.stmts() if isinstance(x, Assign) and isinstance(x.dst, Var)}
    vals, used = [], set()
    for x in pieces:
        at = base + x.loc
        cover = next(((o, j) for o, j in stores.items() if o <= at and at + x.bits // 8 <= o + b.stmts[j].bits // 8),
                     None)
        if cover is None:
            return None
        o, j = cover
        used.add(j)
        v = b.stmts[j].src
        for _ in range(4):
            if isinstance(v, Var) and v in defs:
                v = defs[v]
            elif isinstance(v, Cast) and v.kind in ("low", "zext", "sext") and isinstance(v.a, (Var, Load)):
                v = v.a
            else:
                break
        if isinstance(v, Load) and v.bits == b.stmts[j].bits:
            addr = v.addr if at == o else BinOp("+", v.addr, Const(at - o, v.addr.bits), v.addr.bits)
            vals.append(Load(addr, x.bits))
        elif at == o and b.stmts[j].bits == x.bits:
            vals.append(b.stmts[j].src)
        else:
            return None
    # every store into the argument is part of it (none left over to show on its own)
    return vals, sorted(used)


def _struct_copy(fn: IRFunction, b, k: int, s: CallStmt, frame, arch: ArchInfo, rel: int, size: int):
    """A struct argument on the stack copied from one place (a local struct, or memory a pointer
    points to): the stores before call `s` filling the `size` bytes from outgoing offset `rel`
    load, in order, from consecutive addresses. (the address of the source, the stores' indices)."""
    from .fpabi import stack_arg_base
    from .ir import Load
    sp = dict(s.uses).get(arch.sp)
    sp_off = frame.offset_of(sp) if sp is not None else None
    if sp_off is None or s.tail:
        return None
    base = sp_off + stack_arg_base(arch)
    stores = _arg_stores(b, k, frame, base, 8)
    defs = None
    first, start, js = None, None, []
    o = base + rel
    while o < base + rel + size:
        j = stores.get(o)
        if j is None:
            return None
        t = b.stmts[j]
        v = t.src
        for _ in range(4):          # (through a register, and `low32(zext64(...))` of a 32-bit word)
            if isinstance(v, Var):
                if defs is None:
                    defs = {x.dst: x.src for x in fn.stmts() if isinstance(x, Assign) and isinstance(x.dst, Var)}
                v = defs.get(v, v)
            elif isinstance(v, Cast) and v.kind in ("low", "zext", "sext"):
                v = v.a
            else:
                break
        if not isinstance(v, Load) or v.bits != t.bits:
            return None
        src = frame.offset_of(v.addr)
        if src is None:
            return None
        if first is None:
            first, start = v.addr, src
        elif src != start + (o - base - rel):
            return None
        js.append(j)
        o += t.bits // 8
    return (first, js) if first is not None and o == base + rel + size else None


def objc_selector(an: "Analysis", fn: IRFunction, name: str | None, sel_value) -> str | None:
    """The selector of an `objc_msgSend` call: what its selector register is loaded from (a
    `__objc_selrefs` slot), else None (not a send, or not known)."""
    from .ir import Load
    from .sigs import OBJC_SENDS, base_name
    objc = getattr(an.bin, "objc", None)
    if objc is None or base_name(name) not in OBJC_SENDS or sel_value is None:
        return None
    v = sel_value
    defs = None
    for _ in range(4):
        if isinstance(v, Load) and isinstance(v.addr, Const):
            return objc.selrefs.get(v.addr.value)
        if isinstance(v, Var):
            if defs is None:
                defs = {t.dst: t.src for t in fn.stmts() if isinstance(t, Assign) and isinstance(t.dst, Var)}
            v = defs.get(v)
        elif isinstance(v, Cast):
            v = v.a
        else:
            return None
    return None


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
        whole = _pair_value(rlo, rhi)
        if not (isinstance(whole, BinOp) and whole.op == "|"):
            return whole                             # (the halves of one value, through their variables)
    if isinstance(lo, Cast) and lo.kind == "low" and isinstance(hi, Extract) and hi.lo == 32 and lo.a == hi.a \
            and lo.a.bits == 64:
        return lo.a
    if isinstance(lo, Cast) and lo.kind == "low" and lo.a.bits == 64 and isinstance(hi, Cast) and hi.kind == "low" \
            and isinstance(hi.a, BinOp) and hi.a.op == ">>u" and hi.a.a == lo.a and hi.a.b == Const(32, hi.a.b.bits):
        return lo.a                                  # (the high half as `low(x >>u 32)`)
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
    aligned to eight bytes on 32-bit targets, a long double twelve bytes (x86) or sixteen aligned
    to sixteen (x86-64)."""
    word = arch.bits // 8
    out, off = [], 0
    for c in classes:
        size = _stack_size(arch, c)
        if size == 8 and word == 4:
            off = (off + 7) & ~7
        elif c == "L" and word == 8:
            off = (off + 15) & ~15      # (a long double: sixteen bytes, aligned to sixteen)
        out.append(off)
        off += size
    return out


def _stack_size(arch: ArchInfo, c: str) -> int:
    """Bytes a stack argument of class `c` takes (fpabi.arg_classes)."""
    word = arch.bits // 8
    if c == "L":
        return 12 if word == 4 else 16
    return 8 if c == "d" else word


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
        v = b.stmts[j].src
        if sizes is not None and sizes[n] == 16 and v.bits != 80:
            copy = _long_double_copy(b, stores, base + rel, word, frame)
            if copy is None:
                return
            v, more = copy
            consumed.update(more)
        consumed.add(j)
        if word == 4 and sizes is not None and sizes[n] == 8 and v.bits == 32:   # a double stored as two words
            j2 = stores.get(base + rel + 4)
            if j2 is None:
                return
            consumed.add(j2)
            v = _pair_value(v, b.stmts[j2].src)
        yield v


__all__ = ["recover_calls", "int_arg_regs"]

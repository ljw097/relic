"""The decompiler pipeline from a function to structured, non-SSA IR.

    lift -> SSA -> optimise -> calls     (decompile_ir)
    frame -> canary / return value -> stack locals -> DCE
    out-of-SSA -> forward empty blocks -> result widths -> narrow -> inline temporaries
    -> structure

`prepare` returns everything the C emitter needs.
"""
from __future__ import annotations

import contextlib
import copy
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .arch import ArchInfo, arch_for
from .arith import recover_division
from .cleanup import (cached_ir, drop_return_values, drop_stack_pointer_chains, fold_short_circuits,
                      forward_empty_blocks, hide_canary, inline_single_use, narrow_library_results, narrow_returns,
                      return_width, returns_value, rewrite_locals)
from .ir import IRFunction
from .outssa import out_of_ssa
from .passes import _dce, _fold_pass
from .stack import Frame, analyze_frame
from .structure import Structurer
from .vartypes import narrow

if TYPE_CHECKING:
    from ..analysis import Analysis, Function


@dataclass
class Prepared:
    fn: IRFunction          # structured-ready, non-SSA IR
    arch: ArchInfo
    frame: Frame
    params: list[str]       # parameter registers, in order
    returns: bool
    tree: object            # structure.Seq
    gotos: set
    ret_bits: int | None = None   # width of the result, when known
    ret_float: bool = False       # the result is a float / double (in xmm0)
    hidden: frozenset = frozenset()   # ids of statements the structurer made redundant


# functions prepared for another one's struct scan (structs._scan_function), kept for their own
# decompilation while `prepared_once` is in effect (in this thread only): function -> Prepared
_KEPT: ContextVar[dict | None] = ContextVar("relic_prepared_once", default=None)
KEEP_MAX = 256


@contextlib.contextmanager
def prepared_once():
    """Decompiling many functions in a row, nothing editing the analysis meanwhile (`relic
    decompile --all`, the C export): a function prepared for another one's struct scan is not
    prepared again for its own pseudocode (the same steps on the same analysis give the same
    result). The GUI does not use it: the user may edit between two decompilations."""
    token = _KEPT.set({})
    try:
        yield
    finally:
        _KEPT.reset(token)


def keep_prepared(func_addr: int, prep: Prepared) -> None:
    kept = _KEPT.get()
    if kept is None:
        return
    kept[func_addr] = prep
    while len(kept) > KEEP_MAX:                 # (the oldest goes: it is prepared again if needed)
        del kept[next(iter(kept))]


def prepared(an: "Analysis", func: "Function") -> Prepared:
    """`prepare(an, func)`, or the one a struct scan kept (see prepared_once), used once."""
    kept = _KEPT.get()
    prep = kept.pop(func.addr, None) if kept else None
    return prep if prep is not None else prepare(an, func)


def prepare(an: "Analysis", func: "Function") -> Prepared:
    from .calls import _livein_arg_regs
    arch = arch_for(an.bin)
    fn = copy.deepcopy(cached_ir(an, func))
    if arch.bits == 32 and arch.name.startswith("riscv"):
        from .fpabi import float_int_params, join_pair_params
        pairs = [r for r, _ in float_int_params(an, arch, func.addr) if ":" in r]
        if pairs:
            join_pair_params(fn, pairs)
    from .cleanup import stack_guards
    if arch.name == "x86-cdecl":
        from .calls import merge_word_copies
        if merge_word_copies(fn, arch):
            _dce(fn)
    frame = analyze_frame(fn, arch, stack_guards(an))
    hide_canary(fn, frame)
    from .fpabi import fp_params, fp_return
    fret = fp_return(an, func)
    rets = fret is not None or returns_value(an, func, fn, arch.ret)
    user_ret = an.var_types.get(func.addr, {}).get("@return")       # the user's / a header's type
    enc = getattr(an.bin, "objc_types", {}).get(func.addr, "").lstrip("rnNoORV")
    if user_ret is None and enc[:1] == "v":
        user_ret = "void"                       # an Objective-C method's type encoding says so
    if user_ret is not None and fret is None:
        rets = user_ret != "void"
    if not rets:
        drop_return_values(fn)
    rewrite_locals(fn, frame)
    drop_stack_pointer_chains(fn, frame)
    from .cleanup import drop_dead_locals
    drop_dead_locals(fn)
    _dce(fn)
    fn = out_of_ssa(fn)
    forward_empty_blocks(fn)
    if arch.name == "x86-cdecl":
        # stack parameters: [esp_0 + 4], [esp_0 + 8], ... are a1, a2, ...
        from .calls import stack_param_slots
        word = arch.bits // 8
        # (a double takes two words: one parameter)
        params = [frame.slots[word + rel].name() if word + rel in frame.slots else f"arg_{word + rel:x}"
                  for rel, _, _ in stack_param_slots(an, arch, func.addr)]
    elif (an.name(func.addr) or "") == "main":
        # main(argc, argv, envp): an unused argc before a used argv is still the first parameter
        from .calls import int_arg_regs, livein_regs
        regs = int_arg_regs(arch)[:3]
        live = livein_regs(an, arch, func.addr)
        params = list(regs[:max((k + 1 for k, r in enumerate(regs) if r in live), default=0)])
    else:
        from .fpabi import float_int_params
        fints = [r for r, _ in float_int_params(an, arch, func.addr)]       # RISC-V: floats past fa7
        halves = {x for r in fints for x in r.split(":")}
        ints = [r for r in _livein_arg_regs(an, arch, func.addr) if r not in halves]
        fpl = fp_params(an, arch, func.addr)
        fints = [r.split(":")[0] for r in fints]          # (RV32: a pair is named after its low register)
        from .emit import objc_method
        m = objc_method(an.name(func.addr) or "")
        if m is not None and not fpl:
            # an Objective-C method: self, _cmd, then one per `:` of its selector, used or not
            from .calls import int_arg_regs
            n = 2 + m[2].count(":")
            ints = list(int_arg_regs(arch)[:n]) + [r for r in ints if r not in int_arg_regs(arch)[:n]]
        params = ints + [r for r, _ in fpl] + fints
        from .calls import positional_order
        order = positional_order(arch, ints, fpl)
        if order is not None:                   # PowerPC64: in the order C had them
            params = [params[k] for k in order] + fints
        from .calls import param_base, stack_params_used
        if stack_params_used(arch):
            # parameters past the registers, on the stack (above the return address on x86-64,
            # and past Win64's home space for the four register parameters)
            from .fpabi import stack_arg_base
            word = arch.bits // 8
            # (PowerPC's offset from the caller's r1 is the same from this function's entry r1)
            first = param_base(arch) + (0 if arch.name.startswith("ppc") else stack_arg_base(arch))
            from .calls import stack_param_slots
            params += [frame.slots[first + rel].name() if first + rel in frame.slots else f"arg_{first + rel:x}"
                       for rel, _, _ in stack_param_slots(an, arch, func.addr)]
    from .cleanup import fold_param_spills
    fold_param_spills(fn, params)           # -O0: `var_1c = argc` once on entry, then var_1c read
    narrow_library_results(fn)
    from .calls import narrow_call_args
    narrow_call_args(an, arch, fn)
    w = None
    if fret is not None:
        w = fret
    elif user_ret is not None:
        w = _type_bits(user_ret, arch.bits)
        if w is not None and w < arch.bits:
            narrow_returns(fn, w)
    elif rets:
        w = return_width(an, func, arch.ret)
        if w is not None:
            narrow_returns(fn, w)
    from .calls import int_arg_regs
    # RISC-V and MIPS n64 pass an `int` sign-extended to 64 bits: a parameter read as its low half and
    # otherwise only compared is one
    from .arch import sext_ints
    narrow(fn, sext_params=set(int_arg_regs(arch)) if sext_ints(arch) else frozenset())
    from .passes import _redundant_masks
    _redundant_masks(fn)                    # (narrowing leaves `(int)c & 0xff` of a loaded byte)
    from .fpconst import fold_float_constants
    from .cleanup import propagate_ro_loads
    if arch.name.startswith("riscv"):
        propagate_ro_loads(an, fn)          # `fld` of a constant into a register used several times
    fold_float_constants(an, fn)
    if arch.name == "x86-cdecl":
        from .cleanup import drop_dead_locals, forward_local_constants
        if forward_local_constants(fn):         # x87 code keeps the constants of a call sequence in the frame
            drop_dead_locals(fn)
            _dce(fn)
    inline_single_use(fn)
    if arch.name == "x86-cdecl":
        from .fpconst import narrow_x87
        narrow_x87(fn)      # x87: float arithmetic computed as doubles of floats
    _fold_pass(fn)          # constants exposed by narrowing and inlining
    sext_params = frozenset(int_arg_regs(arch)) if sext_ints(arch) else frozenset()
    if recover_division(fn, sext_params):       # magic-number multiplies -> x / c, x % c
        _fold_pass(fn)
        if sext_params:                         # (a 32-bit dividend now read only as its low half)
            _dce(fn)
            narrow(fn, sext_params=set(sext_params))
            _fold_pass(fn)
    _dce(fn)
    from .cleanup import fold_unsigned_conversions
    if fold_unsigned_conversions(an, fn):       # `(double)(uint64_t)x` from the compiler's two-way code
        _dce(fn)
    fold_short_circuits(fn)
    st = Structurer(fn)
    tree = st.run()
    from .chains import switchify
    tree = switchify(tree, frozenset(st.gotos))     # compare chains on one value -> switch
    return Prepared(fn, arch, frame, params, rets, tree, st.gotos, w, fret is not None, frozenset(st.hidden))


def _type_bits(ctype: str, ptr_bits: int) -> int | None:
    """Width of an integer / pointer C type; None for what is not one (or unknown)."""
    if ctype.endswith("*"):
        return ptr_bits
    if ctype.startswith("enum "):
        return 32
    from .structs import _CTYPE_BITS
    return _CTYPE_BITS.get(ctype, 64 if ctype in ("long", "unsigned long", "size_t", "ssize_t") else None)


__all__ = ["Prepared", "prepare"]

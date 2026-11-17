"""Structs passed and returned by value (x86-64 System V).

A struct is passed in registers when it is at most 16 bytes: each eightbyte in the next integer
register (rdi, rsi, ...) or, when all it holds are floats / doubles, the next SSE register (xmm0,
...). Bigger ones, ones with a `long double`, and ones that no longer fit in the registers left
go on the stack, copied whole. A struct result comes back the same way in rax / rdx and xmm0 /
xmm1, or, when it would go in memory, through a pointer the caller passes in rdi (returned in rax).

Only prototypes say a function takes or returns a struct by value: an imported header's, with the
struct imported too (its layout is what is classified). `plan` gives where each C parameter and
the result are, which the pipeline (parameters), the C writer (the function's own signature and
body) and call recovery (its callers) use.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..analysis import Analysis
    from .arch import ArchInfo

_INT_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_SSE_REGS = tuple(f"xmm{n}" for n in range(8))
_FLOATS = ("float", "double")


@dataclass(frozen=True)
class Piece:
    """One part of a struct: a register (an eightbyte) or a stack word, and the field it holds
    (None: several fields share it -- shown as the struct's bytes there)."""
    loc: str | int          # a register, or an offset from the first stack parameter
    off: int                # its offset in the struct
    field: str | None
    bits: int
    float: bool = False
    ctype: str = ""         # the field's C type ("": a plain integer of `bits`)


@dataclass
class Param:
    ctype: str              # C type as the prototype spells it
    pieces: list[Piece] = field(default_factory=list)   # a struct by value: where its parts are
    loc: str | int | None = None                        # a scalar: its register / stack offset

    @property
    def is_struct(self) -> bool:
        return bool(self.pieces)


@dataclass
class Plan:
    params: list[Param]
    ret: str                            # the result's C type
    ret_pieces: list[Piece] = field(default_factory=list)   # a struct result in registers
    ret_memory: bool = False            # ... through the pointer passed in rdi

    def locs(self) -> list[str | int]:
        """Every register / stack offset a parameter (or the result pointer) arrives in, in C order."""
        out: list[str | int] = ["rdi"] if self.ret_memory else []
        for p in self.params:
            out += [x.loc for x in p.pieces] if p.is_struct else [p.loc]
        return out


@dataclass
class _Struct:
    name: str
    size: int
    align: int
    fields: list[tuple[int, int, str, str]]     # (offset, bytes, C type, name), arrays flattened


def struct_of(an: "Analysis", ctype: str) -> _Struct | None:
    """An imported struct named by `ctype` (`struct pt`, or a typedef of one), passed by value."""
    t = an.resolve_type(ctype).strip()
    if not t.startswith("struct ") or "*" in t or "[" in t:
        return None
    name = t[7:].strip()
    entry = an.struct_names.get(name) or {}
    layout = entry.get("layout")
    decl = entry.get("decl") or []
    if not layout or (decl and decl[0].lstrip().startswith("union")):
        return None
    names = entry.get("fields", {})
    fields = []
    for key, spec in sorted(layout.items(), key=lambda kv: int(kv[0], 16)):
        off, bits, ct = int(key, 16), spec[0], spec[1] or ""
        count = spec[2] if len(spec) > 2 and isinstance(spec[2], int) else 1
        label = names.get(f"f_{off:x}", f"f_{off:x}")
        for k in range(max(count, 1)):
            fields.append((off + k * bits // 8, bits // 8, ct, label if count == 1 else f"{label}[{k}]"))
    if not fields:
        return None
    align = max(min(b, 16) for _, b, _, _ in fields)
    end = max(o + b for o, b, _, _ in fields)
    size = end + (-end % align)
    return _Struct(name, size, align, fields)


def packed(st: _Struct) -> bool:
    """Passed in registers with fields sharing one (`struct { int a, b; }` in rdi, two floats in
    xmm0): their parts are bits of a register, which -O0 spills and reads back in halves and -O2
    takes apart with shifts -- not shown as a struct yet (the frame would need overlapping slots
    and the lifter `shrd`)."""
    return st.size <= 16 and classify(st) is not None and any(
        sum(1 for o, _, _, _ in st.fields if e <= o < e + 8) > 1 for e in range(0, st.size, 8)) or \
        st.size <= 16 and any(sum(1 for o, _, ct, _ in st.fields if e <= o < e + 8 and ct in _FLOATS) > 1
                              for e in range(0, st.size, 8))


def classify(st: _Struct) -> list[tuple[str, int]] | None:
    """System V: the eightbytes' classes, ("INTEGER" / "SSE", offset); None: in memory."""
    if st.size > 16 or any(b > 8 or o % b for o, b, _, _ in st.fields):
        return None                         # (a long double, an __int128, a packed field: memory)
    out = []
    for e in range(0, st.size, 8):
        inside = [f for f in st.fields if e <= f[0] < e + 8]
        if not inside:
            out.append(("SSE", e))          # (padding only: no register of its own -- treated as SSE)
            continue
        sse = all(ct in _FLOATS for _, _, ct, _ in inside)
        if sse and len(inside) > 1:
            return None         # (two floats in one SSE register: not shown as a struct -- see plan)
        out.append(("SSE" if sse else "INTEGER", e))
    return out


def _pieces(st: _Struct, classes, regs_int: list, regs_sse: list) -> list[Piece]:
    out = []
    for cls, e in classes:
        inside = [f for f in st.fields if e <= f[0] < e + 8]
        reg = regs_sse.pop(0) if cls == "SSE" else regs_int.pop(0)
        one = inside[0] if len(inside) == 1 and inside[0][0] == e else None
        bits = one[1] * 8 if one else min(64, (st.size - e) * 8)
        out.append(Piece(reg, e, one[3] if one else None, bits, cls == "SSE", one[2] if one else ""))
    return out


def _stack_pieces(st: _Struct, at: int) -> list[Piece]:
    return [Piece(at + o, o, name, b * 8, ct in _FLOATS, ct) for o, b, ct, name in st.fields]


def plan(an: "Analysis", arch: "ArchInfo", name: str) -> Plan | None:
    """Where the parameters and result of `name` are, from its prototype -- only when it takes or
    returns a struct by value (otherwise the usual parameter recovery stands)."""
    if arch.name != "x64-sysv" or not name:
        return None
    return plan_proto(an, arch, an.user_types.get("prototypes", {}).get(name))


def plan_proto(an: "Analysis", arch: "ArchInfo", proto: dict | None) -> Plan | None:
    """`plan` for a prototype ({"ret", "params", "variadic"}, as `user_types["prototypes"]` keeps
    them)."""
    if arch.name != "x64-sysv" or not proto or proto.get("variadic"):
        return None
    params = list(proto.get("params", []))
    if params == ["void"]:
        params = []
    ret = proto.get("ret", "int")
    structs = [struct_of(an, t) for t in params]
    rst = struct_of(an, ret)
    if not any(structs) and rst is None:
        return None
    if any(st is not None and packed(st) for st in structs + [rst]):
        return None             # (see `packed`: the usual parameters then)
    ints, sses = list(_INT_REGS), list(_SSE_REGS)
    out = Plan([], ret)
    if rst is not None:
        classes = classify(rst)
        if classes is None:
            out.ret_memory = True
            ints.pop(0)                     # (rdi: where the result goes)
        else:
            out.ret_pieces = _pieces(rst, classes, ["rax", "rdx"], ["xmm0", "xmm1"])
    stack = 0
    for t, st in zip(params, structs):
        if st is None:
            ct = an.resolve_type(t).strip()
            if ct == "long double":
                return None                 # (x87 stack argument: not handled here)
            wants_sse = ct in _FLOATS
            pool = sses if wants_sse else ints
            if pool:
                out.params.append(Param(t, loc=pool.pop(0)))
            else:
                out.params.append(Param(t, loc=stack))
                stack += 8
            continue
        classes = classify(st)
        need_i = sum(1 for c, _ in classes or () if c == "INTEGER")
        need_s = sum(1 for c, _ in classes or () if c == "SSE")
        if classes is not None and need_i <= len(ints) and need_s <= len(sses):
            out.params.append(Param(t, _pieces(st, classes, ints, sses)))
            continue
        stack += -stack % max(8, st.align)
        out.params.append(Param(t, _stack_pieces(st, stack)))
        stack += st.size + (-st.size % 8)
    return out


def func_plan(an: "Analysis", func) -> Plan | None:
    """`plan` for one of the binary's functions, by its name (cached per analysis: prototypes
    change only by an import, which starts a new analysis of the types)."""
    from .arch import arch_for
    from .sigs import base_name
    try:
        arch = arch_for(an.bin)
    except NotImplementedError:
        return None
    name = base_name(an.name(func.addr) or func.name)
    key = (func.addr, name, id(an.user_types.get("prototypes")), len(an.struct_names))
    cache = an.__dict__.setdefault("_agg_plans", {})
    if key not in cache:
        cache[key] = plan(an, arch, name)
    return cache[key]


def part_fields(an: "Analysis", name: str, n: int) -> list[list[tuple[int, int, str]]] | None:
    """The fields in each of the `n` parts of a `struct name` value, (shift in bits, bits, C type):
    its eightbytes when passed in registers, its fields when on the stack. None: not known."""
    st = struct_of(an, f"struct {name}")
    if st is None:
        return None
    classes = classify(st)
    if classes is not None and len(classes) == n:
        return [[((o - e) * 8, b * 8, ct) for o, b, ct, _ in st.fields if e <= o < e + 8] for _, e in classes]
    if len(st.fields) == n:
        return [[(0, b * 8, ct)] for _, b, ct, _ in st.fields]
    return None


def part_floats(an: "Analysis", name: str, n: int) -> list[bool]:
    """Which of the `n` parts of a `struct name` value are floating point: its eightbytes when
    passed in registers, its fields when passed on the stack."""
    st = struct_of(an, f"struct {name}")
    if st is None:
        return [False] * n
    classes = classify(st)
    if classes is not None and len(classes) == n:
        return [c == "SSE" for c, _ in classes]
    if len(st.fields) == n:
        return [ct in _FLOATS for _, _, ct, _ in st.fields]
    return [False] * n


STRUCT = "struct:"          # Intrinsic name prefix: a struct value made of its parts (`(struct pt){x, y}`)
STRUCT_COPY = "structat:"   # ... the struct at an address (its one argument), passed by value


def set_struct_returns(an: "Analysis", func, fn) -> bool:
    """A function returning a struct in registers (rax / rdx, xmm0 / xmm1): its lifted `return`s
    return all of it, so what goes in rdx is not dead code. Whether it did."""
    p = func_plan(an, func)
    if p is None or not p.ret_pieces:
        return False
    from .ir import Cast, Intrinsic, Reg, Return
    parts = []
    for x in p.ret_pieces:
        full = 128 if x.loc.startswith("xmm") else 64
        r = Reg(x.loc, full)
        parts.append(Cast("low", r, x.bits) if x.bits < full else r)
    name = STRUCT + an.resolve_type(p.ret).strip()[7:].strip()
    for s in fn.stmts():
        if isinstance(s, Return):
            s.value = Intrinsic(name, tuple(parts), 64 * len(parts))
    return True


__all__ = ["Piece", "Param", "Plan", "STRUCT", "STRUCT_COPY", "classify", "func_plan", "part_fields", "part_floats",
           "plan", "plan_proto", "set_struct_returns", "struct_of"]

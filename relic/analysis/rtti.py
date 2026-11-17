"""C++ classes from RTTI, stripped binaries included: Itanium (gcc, clang: ELF) and MSVC (PE).

A class's `typeinfo` object starts with a pointer into one of libstdc++'s typeinfo vtables -- the
dynamic relocation naming `__class_type_info` (no bases), `__si_class_type_info` (one base) or
`__vmi_class_type_info` (several) -- followed by its mangled name and its bases. A vtable is the
offset to the top of the object, the typeinfo, then the virtual methods; classes with several
bases have one per base, one after the other.

MSVC: the word before a vtable points at its RTTICompleteObjectLocator, which gives the offset
of that part of the object, the class's TypeDescriptor (its decorated name, `.?AVDog@@`) and its
ClassHierarchyDescriptor (all its bases).

Found: classes with their bases, vtables and virtual methods; names `typeinfo for X`,
`vtable for X` and `X::vfuncN` (methods without a name of their own).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..demangle import demangle
from ..disasm import CALL as CALL_KIND
from ..disasm import CJMP as CJMP_KIND
from ..disasm import JMP as JMP_KIND
from ..disasm import RET as RET_KIND
from ..loader.base import Symbol

_KINDS = {"_ZTVN10__cxxabiv117__class_type_infoE": "class", "_ZTVN10__cxxabiv120__si_class_type_infoE": "si",
          "_ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi"}
_PURE = ("__cxa_pure_virtual", "__cxa_deleted_virtual")


@dataclass
class VTable:
    addr: int                    # its address point: the first virtual method's slot
    offset: int                  # offset to the top of the object (0 for the primary one)
    slots: list[int] = field(default_factory=list)      # method addresses (0: pure virtual)
    start: int = 0               # where the vtable object starts (its RTTI header before `addr`)


@dataclass
class CppClass:
    name: str
    typeinfo: int
    bases: list[str] = field(default_factory=list)
    vtables: list[VTable] = field(default_factory=list)
    offsets: dict[str, int] = field(default_factory=dict)  # base -> where it lies in the object


def recover_classes(an, finder=None) -> dict[str, CppClass]:
    b = an.bin
    if b.format == "PE":
        classes = _msvc(an)
        if classes:
            _name(an, classes, finder, b.bits // 8)
        return classes
    if b.format != "ELF":
        return {}
    ptr = b.bits // 8
    kinds: dict[int, str] = {}
    pure: set[int] = set()
    copied: dict[int, str] = {}              # address point of a typeinfo vtable copied in -> kind
    for r in getattr(b, "relocs", ()):
        k = _KINDS.get(r.name)
        sym = b.symbols.get(r.addr)
        if k is not None and sym is not None and sym.name.split("@")[0] == r.name:
            copied[r.addr + 2 * ptr] = k         # (a copy relocation, non-PIC: typeinfos point at the copy)
        elif k is not None:
            kinds[r.addr] = k
        elif r.name in _PURE:
            pure.add(r.addr)
    if copied:
        for sec in b.sections:
            if not sec.loaded or sec.x or sec.size == 0 or sec.name.startswith((".bss", ".sbss", ".tbss")):
                continue
            for a in range(sec.addr + (-sec.addr % ptr), sec.end - ptr + 1, ptr):
                k = copied.get(b.read_ptr(a))
                if k is not None:
                    kinds.setdefault(a, k)
    if not kinds:
        return {}
    by_ti: dict[int, CppClass] = {}
    inside: set[int] = set()                 # words of typeinfo objects (not vtable candidates)
    for ti, kind in kinds.items():
        mangled = b.read_cstring(b.read_ptr(ti + ptr) or 0)
        if not mangled:
            continue
        name = (demangle("_ZTS" + mangled) or "").removeprefix("typeinfo name for ") or mangled
        by_ti[ti] = CppClass(name, ti)
        size = 2 * ptr
        if kind == "si":
            size = 3 * ptr
        elif kind == "vmi":
            size = 2 * ptr + 8 + 2 * ptr * (b.read_int(ti + 2 * ptr + 4, 4) or 0)
        inside.update(range(ti, ti + size, 4))
    for ti, kind in kinds.items():
        c = by_ti.get(ti)
        if c is None:
            continue
        offs: list[int | None] = []
        if kind == "si":
            bases = [b.read_ptr(ti + 2 * ptr)]
            offs = [0]
        elif kind == "vmi":
            n = b.read_int(ti + 2 * ptr + 4, 4) or 0
            bases, offs = [], []
            for k in range(min(n, 64)):
                e = ti + 2 * ptr + 8 + 2 * ptr * k
                bases.append(b.read_ptr(e))
                flags = b.read_int(e + ptr, ptr, signed=True) or 0
                offs.append(None if flags & 1 else flags >> 8)        # (virtual bases: not fixed)
        else:
            bases = []
        for t, o in zip(bases, offs):
            if t:
                name = by_ti[t].name if t in by_ti else _external(b, t)
                c.bases.append(name)
                if o is not None:
                    c.offsets[name] = o
    _vtables(an, by_ti, inside, pure, ptr)
    classes = {c.name: c for c in by_ti.values()}
    _name(an, classes, finder, ptr)
    return classes


def _msvc_name(decorated: str) -> str:
    """`.?AVDog@@` -> `Dog`, `.?AVInner@Outer@@` -> `Outer::Inner` (templates left as they are)."""
    core = decorated[4:] if decorated[:4] in (".?AV", ".?AU") else decorated
    if "?$" in core or not core.endswith("@@"):
        return core
    return "::".join(reversed([p for p in core[:-2].split("@") if p]))


def _msvc(an) -> dict[str, CppClass]:
    b = an.bin
    ptr = b.bits // 8
    base = getattr(b, "image_base", None)
    if base is None:
        base = min((s.addr for s in b.sections if s.loaded), default=0) & ~0xFFFF
    x64 = ptr == 8
    rdata = [s for s in b.sections if s.loaded and not s.x and s.size and not b.is_writable(s.addr)]

    def at(v: int) -> int:                  # an image-relative offset (x64) or an address (x86)
        return base + v if x64 else v

    def td_name(td: int) -> str | None:
        n = b.read_cstring(td + 2 * ptr)
        return n if n and n.startswith((".?AV", ".?AU")) else None

    cols: dict[int, tuple[int, int, int]] = {}         # locator -> (offset, type descriptor, hierarchy)
    for sec in rdata:
        for a in range(sec.addr + (-sec.addr % 4), b.file_end(sec) - 20, 4):
            sig = b.read_int(a, 4)
            if sig != (1 if x64 else 0):
                continue
            if x64 and b.read_int(a + 20, 4) != a - base:      # (pSelf: its own offset)
                continue
            td, chd = at(b.read_int(a + 12, 4) or 0), at(b.read_int(a + 16, 4) or 0)
            if not b.is_mapped(td) or td_name(td) is None or not b.is_mapped(chd):
                continue
            cols[a] = (b.read_int(a + 4, 4) or 0, td, chd)
    if not cols:
        return {}
    classes: dict[int, CppClass] = {}
    for _off, td, chd in cols.values():
        if td in classes:
            continue
        c = CppClass(_msvc_name(td_name(td)), td)
        n = b.read_int(chd + 8, 4) or 0
        arr = at(b.read_int(chd + 12, 4) or 0)
        for k in range(1, min(n, 64)):           # (entry 0: the class itself)
            bcd = at(b.read_int(arr + 4 * k, 4) or 0)
            btd = at(b.read_int(bcd, 4) or 0)
            name = td_name(btd) if b.is_mapped(btd) else None
            if name and _msvc_name(name) not in c.bases:
                c.bases.append(_msvc_name(name))        # (indirect ones too: `_direct` drops them)
                if (b.read_int(bcd + 12, 4, signed=True) or 0) < 0:     # (pdisp -1: not a virtual base)
                    c.offsets[_msvc_name(name)] = b.read_int(bcd + 8, 4, signed=True) or 0
        classes[td] = c
    # vtables: a pointer to a locator, then the methods
    for sec in rdata:
        for a in range(sec.addr + (-sec.addr % ptr), b.file_end(sec) - ptr, ptr):
            col = b.read_ptr(a)
            if col not in cols:
                continue
            off, td, _ = cols[col]
            vt = VTable(a + ptr, -off, start=a)
            s = a + ptr
            while s + ptr <= sec.end and s not in cols:
                v = b.read_ptr(s) or 0
                if not v or not b.is_exec(v) or b.read_ptr(s) in cols:
                    break
                vt.slots.append(v)
                s += ptr
            classes[td].vtables.append(vt)
    for c in classes.values():
        c.vtables.sort(key=lambda v: -v.offset)
        c.bases = _direct(c.bases, classes)
    return {c.name: c for c in classes.values()}


def _direct(bases: list[str], classes: dict[int, CppClass]) -> list[str]:
    """The hierarchy descriptor lists every base, indirect ones too: keep the direct ones -- those
    no other listed base derives from."""
    by_name = {c.name: c for c in classes.values()}
    indirect = set()
    for n in bases:
        stack = list(by_name[n].bases) if n in by_name else []
        while stack:
            m = stack.pop()
            if m not in indirect:
                indirect.add(m)
                stack.extend(by_name[m].bases if m in by_name else ())
    return [n for n in bases if n not in indirect]


def _external(b, ti: int) -> str:
    """A base class whose typeinfo lives in a library: the name of the symbol its pointer binds."""
    for r in getattr(b, "relocs", ()):
        if r.addr == ti and r.name.startswith("_ZTI"):
            return (demangle(r.name) or r.name).removeprefix("typeinfo for ")
    return f"class_{ti:x}"


def _vtables(an, by_ti: dict[int, CppClass], inside: set[int], pure: set[int], ptr: int):
    b = an.bin
    lim = 1 << (b.bits - 1)
    for sec in b.sections:
        if not sec.loaded or sec.x or sec.size == 0 or not (sec.name.startswith(".data") or sec.name == ".rodata"):
            continue
        a = sec.addr + ptr
        a += -a % ptr
        while a + ptr <= sec.end:
            ti = b.read_ptr(a)
            if ti not in by_ti or a in inside:
                a += ptr
                continue
            off = b.read_ptr(a - ptr) or 0
            off = off - (1 << b.bits) if off >= lim else off
            if off > 0 or off < -0x100000 or off % ptr:
                a += ptr
                continue
            vt = VTable(a + ptr, off, start=a - ptr)
            s = a + ptr
            descs = getattr(b, "func_descriptors", None) or {}
            while s + ptr <= sec.end and s not in inside:     # (a typeinfo object right after it)
                v = b.read_ptr(s) or 0
                v = descs.get(v, v)                      # (PowerPC64 ELFv1: a function descriptor)
                if s in pure:
                    vt.slots.append(0)
                elif v and b.is_exec(v & ~1):
                    vt.slots.append(v & ~1 if b.arch == "arm" else v)     # (Thumb: the address, not bit 0)
                else:
                    break
                s += ptr
            by_ti[ti].vtables.append(vt)
            a = s


def _ancestors(name: str, classes: dict[str, CppClass], seen=None) -> set[str]:
    seen = set() if seen is None else seen
    if name in seen:
        return seen
    seen.add(name)
    for n in classes[name].bases if name in classes else ():
        _ancestors(n, classes, seen)
    return seen


def _depth(name: str, classes: dict[str, CppClass]) -> int:
    return len(_ancestors(name, classes))


def _name(an, classes: dict[str, CppClass], finder, ptr: int):
    b = an.bin

    def symbol(name: str, addr: int, size: int):
        if b.symbols.get(addr) is None:
            b.add_symbol(Symbol(name, addr, size, "object", "rtti"))
            b.name_to_addr.setdefault(name, addr)

    users: dict[int, list[tuple[str, int, int]]] = {}       # method -> (class, slot, vtable offset)
    for c in classes.values():
        symbol(f"typeinfo for {c.name}", c.typeinfo, 0)
        for vt in c.vtables:
            if vt.offset == 0:
                symbol(f"vtable for {c.name}", vt.start, vt.addr - vt.start + len(vt.slots) * ptr)
            for k, m in enumerate(vt.slots):
                if m:
                    users.setdefault(m, []).append((c.name, k, vt.offset))
    for m, us in users.items():
        f = an.functions.get(m & ~1)
        if f is None and finder is not None:
            f = an.functions.get(finder.add_function(m))
        if f is None or not f.name.startswith("sub_"):
            continue
        # a method several classes share: named after the nearest class they all derive from
        common = set.intersection(*(_ancestors(n, classes) for n, _, _ in us))
        owner = max(common, key=lambda n: _depth(n, classes)) if common else us[0][0]
        _, k, off = next((u for u in us if u[0] == owner), us[0])
        f.name = f"{owner}::vfunc{k}" if off == 0 else f"{owner}::thunk{-off}_vfunc{k}"
        b.add_symbol(Symbol(f.name, f.addr, 0, "func", "rtti"), override=True)
        b.name_to_addr.setdefault(f.name, f.addr)


# ------------------------------------------------------------------ object types (x86)
# The classes an object pointer may point to, followed through registers and stack slots in each
# function: a constructor's object (a constructor stores a vtable in `[this]`), a vtable stored
# into a fresh object (inlined construction), `__dynamic_cast`'s result (the target class and those
# derived from it), what a function returns (its own objects, to its callers), `this` in a virtual
# method (its classes and those derived from them). A virtual call
# through such an object -- its vptr loaded, the slot read, called -- calls that slot's method of
# those classes.

_R64 = {f"e{r}": f"r{r}" for r in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")}
_R64.update({f"r{n}d": f"r{n}" for n in range(8, 16)})
_SAVED = {("x64", False): {"rbx", "rbp", "rsp", "r12", "r13", "r14", "r15"},
          ("x64", True): {"rbx", "rbp", "rsp", "rdi", "rsi", "r12", "r13", "r14", "r15"},
          ("x86", True): {"ebx", "ebp", "esp", "esi", "edi"}, ("x86", False): {"ebx", "ebp", "esp", "esi", "edi"}}


class _Types:
    """Values tracked: ("this",) a method's object; ("ptr", n) some pointer (a call's result);
    ("addr", a) an address; ("ti", class) its typeinfo; ("obj", classes, static) an object of one of
    `classes`, seen as a `static` (its base at some offset; None: the class itself);
    ("vptr", classes, static, off) its vtable pointer plus `off`; ("fn", targets) a method."""

    def __init__(self, an, classes: dict[str, CppClass]):
        b = an.bin
        self.an, self.b = an, b
        self.ptr = b.bits // 8
        self.x64 = b.arch == "x64"
        pe = b.format == "PE"
        self.a64 = b.arch == "arm64"
        self.this = {("x64", False): "rdi", ("x64", True): "rcx", ("x86", True): "ecx",
                     ("arm64", False): "x0", ("arm64", True): "x0"}.get((b.arch, pe))
        self.ret = "x0" if self.a64 else "rax" if self.x64 else "eax"
        self.saved = _SAVED.get((b.arch, pe), set()) if not self.a64 else \
            {f"x{n}" for n in range(19, 30)} | {"sp"}
        self.risc = _RISC.get(_risc_arch(b.arch))       # ARM, MIPS, RISC-V, PowerPC: one handler
        if self.risc is not None:
            self.this, self.ret = self.risc["args"][0], self.risc["ret"]
            self.saved = set(self.risc["saved"])
        self.classes = classes
        self.vt: dict[int, str] = {}             # primary vtable address point -> class
        # where vtable objects start (`_ZTV...`: what a GOT entry holds, the code adds the offset)
        self.vstarts = {v.start for c in classes.values() for v in c.vtables if v.start}
        self.ti: dict[int, str] = {c.typeinfo: c.name for c in classes.values()}
        methods = set()
        for c in classes.values():
            for v in c.vtables:
                methods.update(v.slots)
                if v.offset == 0:
                    self.vt[v.addr] = c.name
        self.methods = methods                   # (destructors store vtables too: not constructors)
        self.owners: dict[int, set[str]] = {}    # method -> classes with it in their primary vtable
        for c in classes.values():
            for v in c.vtables:
                if v.offset == 0:
                    for m in v.slots:
                        if m:
                            self.owners.setdefault(m, set()).add(c.name)
        self.derived: dict[str, set[str]] = {n: {n} for n in classes}
        for n in classes:
            for a in _ancestors(n, classes):
                if a in self.derived:
                    self.derived[a].add(n)
        self.ctors: dict[int, str] = {}          # function -> class whose vtable it stores in [this]
        self.returns: dict[int, tuple] = {}      # function -> ("obj", classes, static) it returns
        self.sites: dict[int, frozenset[int]] = {}
        self.dyncast = {imp.addr for imp in b.imports if imp.name == "__dynamic_cast"}
        self._tok = 0
        # arguments: the objects every call of a function passes it (functions only called directly)
        self.argregs = {("x64", False): ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                        ("x64", True): ["rcx", "rdx", "r8", "r9"], ("x86", True): ["ecx"]}.get((b.arch, pe), [])
        if self.a64:
            self.argregs = [f"x{n}" for n in range(8)]
        elif self.risc is not None:
            self.argregs = list(self.risc["args"])
        self.params: dict[int, dict[str, tuple]] = {}
        self._passed: dict[int, list[tuple]] = {}
        taken = {m for c in classes.values() for v in c.vtables for m in v.slots}
        taken |= {r.addend or 0 for r in getattr(b, "relocs", ())}
        for f in an.functions.values():
            taken |= f.tail_calls
            for blk in f.blocks.values():
                for i in blk.insns:
                    if i.kind != CALL_KIND:
                        taken.update(i.refs)
        self.taken = taken

    def reg(self, r: str) -> str:
        if self.a64:
            return "x" + r[1:] if r[:1] == "w" and r[1:].isdigit() else r
        return _R64.get(r, r) if self.x64 else r

    def offset_in(self, base: str, cls: str, depth: int = 0) -> int | None:
        if base == cls:
            return 0
        c = self.classes.get(cls)
        if c is None or depth > 16:
            return None
        if base in c.offsets:            # (MSVC lists every base with its offset, Itanium the direct ones)
            return c.offsets[base]
        for n in c.bases:
            o = c.offsets.get(n)
            sub = self.offset_in(base, n, depth + 1) if o is not None else None
            if sub is not None:
                return o + sub
        return None

    def slot(self, cls: frozenset[str], static: str | None, k: int) -> frozenset[int]:
        out = set()
        for n in cls:
            c = self.classes.get(n)
            off = 0 if static is None else self.offset_in(static, n)
            if c is None or off is None:
                continue
            vt = next((v for v in c.vtables if v.offset == -off), None)
            if vt is not None and 0 <= k < len(vt.slots) and vt.slots[k]:
                out.add(vt.slots[k])
        return frozenset(out)

    def run(self) -> dict[int, tuple[frozenset[int], bool]]:
        funcs = [f for f in self.an.functions.values() if not f.is_import]
        for _ in range(6):                       # constructors, then what functions return and are passed
            before = (dict(self.ctors), dict(self.returns), dict(self.params))
            self._passed = {}
            for f in funcs:
                self.function(f)
            self._params(funcs)
            if (self.ctors, self.returns, self.params) == before:
                break
        self.sites.clear()
        for f in funcs:
            self.function(f)
        return {a: (t, False) for a, t in self.sites.items()}

    def _params(self, funcs):
        params = {}
        for f in funcs:
            sites = self._passed.get(f.addr)
            if not sites or len(sites) != len(f.callers) or f.addr in self.taken:
                continue
            got = {}
            for k, r in enumerate(self.argregs):
                v = _merge_objs([s[k] for s in sites])
                if v is not None:
                    got[r] = v
            if got:
                params[f.addr] = got
        self.params = params

    def fresh(self):
        self._tok += 1
        return ("ptr", self._tok)

    def function(self, f):
        ends: dict[int, dict] = {}
        rets: list = []
        for a in sorted(f.blocks):
            blk = f.blocks[a]
            ins = [ends.get(p) for p in blk.preds]
            st = None
            if ins and all(x is not None for x in ins):
                st = _join(ins)
            elif a == f.addr:
                st = {self.this: ("this",)}
                if f.addr in self.owners:            # a virtual method: `this` is one of its classes
                    st = {self.this: ("obj", frozenset().union(*(self.derived[n] for n in self.owners[f.addr])),
                                      None)}
                st.update(self.params.get(f.addr, {}))
            ends[a] = self.block(f, blk.insns, dict(st or {}), rets)
        v = _merge_objs(rets) if rets else None
        if v is not None:
            self.returns[f.addr] = v
        else:
            self.returns.pop(f.addr, None)

    def construct(self, f, st: dict, base: str, a):
        """A vtable address (or one of several) stored in an object's first word."""
        addrs = a if isinstance(a, frozenset) else {a}
        found = {self.vt[x] for x in addrs if x in self.vt}
        if not found or len(found) != len(addrs):
            return
        if len(found) > 1:
            obj = st.get(base)
            new = ("obj", frozenset(found), None)
            if obj is not None and obj[0] in ("ptr", "obj"):
                for k, v in list(st.items()):
                    if v == obj:
                        st[k] = new
            else:
                st[base] = new
            return
        cls = found.pop()
        obj = st.get(base)
        if obj == ("this",) and f.addr not in self.methods:
            self.ctors[f.addr] = cls
        new = ("obj", frozenset({cls}), None)
        if obj is not None and obj[0] in ("ptr", "obj"):    # (a later store: a more derived class)
            for k, v in list(st.items()):
                if v == obj:
                    st[k] = new
        elif obj is None or obj[0] == "addr":
            st[base] = new

    def block(self, f, insns, st: dict, rets: list) -> dict:
        if self.a64:
            return self.block_a64(f, insns, st, rets)
        if self.risc is not None:
            return self.block_risc(f, insns, st, rets)
        ptr = self.ptr
        for i in insns:
            ops = [o.strip() for o in i.op_str.split(",")] if i.op_str else []
            m = i.mnemonic
            if i.kind == CALL_KIND:
                self.call(i, ops, st)
                continue
            if i.kind == RET_KIND:
                rets.append(st.get(self.ret))
                continue
            if len(ops) != 2:
                if ops and _is_reg(ops[0]):
                    st.pop(self.reg(ops[0]), None)
                continue
            dst, src = ops
            mem_d, mem_s = _inner(dst), _inner(src)
            word = (dst if mem_d is not None else src).startswith("qword" if self.x64 else "dword")
            if m == "lea" and _is_reg(dst):
                d = self.reg(dst)
                v = None
                if i.refs and ("rip" in src or not self.x64) and _base_disp(mem_s)[0] in (None, "rip"):
                    r = i.refs[0]
                    v = ("ti", self.ti[r]) if r in self.ti else ("addr", r)
                elif mem_s is not None:
                    base, disp = _base_disp(mem_s)
                    bv = st.get(self.reg(base)) if base else None
                    if bv and bv[0] == "addr" and disp is not None:
                        v = ("addr", bv[1] + disp)
                st.pop(d, None)
                if v is not None:
                    st[d] = v
                continue
            if m in ("movq", "movd") and dst.startswith("xmm") and _is_reg(src):
                v = st.get(self.reg(src))
                st.pop(dst, None)
                if v is not None:
                    st[dst] = v
                continue
            if m in ("punpcklqdq", "movlhps"):
                continue                        # (the low qword stays)
            if m in ("movups", "movaps", "movdqu", "movdqa") and mem_d is not None and src.startswith("xmm"):
                base, disp = _base_disp(mem_d)
                v = st.get(src)
                if v and v[0] == "addr" and base and disp == 0:     # (the low qword: the first word)
                    self.construct(f, st, self.reg(base), v[1])
                continue
            if m == "mov" and mem_d is not None:
                if not word:
                    continue
                v = st.get(self.reg(src)) if _is_reg(src) else None
                if v is None and src[:2] == "0x":
                    v = ("addr", int(src, 16))           # (non-PIC: an address stored as is)
                if _stack(mem_d):
                    if v is not None:
                        st[("slot", mem_d)] = v
                    else:
                        st.pop(("slot", mem_d), None)
                    continue
                base, disp = _base_disp(mem_d)
                if v is not None and v[0] == "addr" and base and disp == 0:
                    self.construct(f, st, self.reg(base), v[1])
                continue
            if (m == "mov" and _is_reg(dst) and src == "0") or (m == "xor" and dst == src):
                st[self.reg(dst)] = ("null",)
                continue
            if m == "mov" and _is_reg(dst):
                d = self.reg(dst)
                v = None
                if _is_reg(src):
                    v = st.get(self.reg(src))
                elif mem_s is not None and word:
                    if _stack(mem_s):
                        v = st.get(("slot", mem_s))
                    else:
                        base, disp = _base_disp(mem_s)
                        bv = st.get(self.reg(base)) if base else None
                        if bv and bv[0] == "obj" and disp == 0:
                            v = ("vptr", bv[1], bv[2], 0)
                        elif bv and bv[0] == "vptr" and disp is not None:
                            t = self.slot(bv[1], bv[2], (bv[3] + disp) // ptr)
                            v = ("fn", t) if t else None
                st.pop(d, None)
                if v is not None:
                    st[d] = v
                continue
            if m == "add" and _is_reg(dst) and src[:1].isdigit():
                d = self.reg(dst)
                v = st.get(d)
                if v and v[0] == "vptr":
                    st[d] = ("vptr", v[1], v[2], v[3] + int(src, 0))
                elif v and v[0] == "addr":
                    st[d] = ("addr", v[1] + int(src, 0))
                else:
                    st.pop(d, None)
                continue
            if _is_reg(dst) and m not in ("cmp", "test", "push"):
                st.pop(self.reg(dst), None)
        return st

    def block_a64(self, f, insns, st: dict, rets: list) -> dict:
        """AArch64: `adrp` + `add` (constant propagation gave the `add` its address), `ldr`/`str`
        (`stp` of two vtables: the first one is the object's), `mov` copies, `[sp, #n]` slots."""
        ptr = self.ptr
        for i in insns:
            ops = _a64_ops(i.op_str)
            m = i.mnemonic
            if i.kind == CALL_KIND:
                self.call(i, ops, st)
                continue
            if i.kind == RET_KIND:
                rets.append(st.get(self.ret))
                continue
            if not ops or i.kind in (CJMP_KIND, JMP_KIND):     # (`cbz x0, ...` reads x0)
                continue
            dst = self.reg(ops[0]) if _is_reg(ops[0]) else None
            if m in ("ldr", "ldur") and len(ops) == 2 and dst and dst.startswith("x"):
                base, disp = _a64_mem(ops[1])
                v = None
                if base in ("sp", "x29") and disp is not None:
                    v = st.get(("slot", f"{base} + {disp}"))
                elif base is not None and disp is not None:
                    bv = st.get(self.reg(base))
                    if bv and bv[0] == "obj" and disp == 0:
                        v = ("vptr", bv[1], bv[2], 0)
                    elif bv and bv[0] == "vptr":
                        t = self.slot(bv[1], bv[2], (bv[3] + disp) // ptr)
                        v = ("fn", t) if t else None
                st.pop(dst, None)
                if v is not None:
                    st[dst] = v
                continue
            if m in ("str", "stur", "stp") and len(ops) >= 2:
                src = self.reg(ops[0])
                base, disp = _a64_mem(ops[-1])
                v = st.get(src)
                if base in ("sp", "x29") and disp is not None and m != "stp":
                    if v is not None:
                        st[("slot", f"{base} + {disp}")] = v
                    else:
                        st.pop(("slot", f"{base} + {disp}"), None)
                elif base is not None and disp == 0 and v is not None and v[0] in ("addr", "addrs"):
                    self.construct(f, st, self.reg(base), v[1])
                continue
            if dst is None or m in ("cmp", "cmn", "tst"):
                continue
            v = None
            if m == "mov" and len(ops) == 2 and _is_reg(ops[1]):
                v = st.get(self.reg(ops[1]))
                if ops[1] in ("xzr", "wzr"):
                    v = ("null",)
            elif m == "mov" and len(ops) == 2 and ops[1] == "#0":
                v = ("null",)
            elif m == "add" and len(ops) == 3 and ops[2].startswith("#"):
                src = st.get(self.reg(ops[1]))
                k = int(ops[2][1:], 0)
                if i.refs and (src is None or src[0] != "vptr"):
                    r = i.refs[-1]
                    v = ("ti", self.ti[r]) if r in self.ti else ("addr", r)
                elif src and src[0] == "addr":
                    v = ("addr", src[1] + k)
                elif src and src[0] == "vptr":
                    v = ("vptr", src[1], src[2], src[3] + k)
            elif m == "adr" and i.refs:
                v = ("addr", i.refs[0])
            st.pop(dst, None)
            if v is not None:
                st[dst] = v
        return st

    def block_risc(self, f, insns, st: dict, rets: list) -> dict:
        """ARM / Thumb, MIPS, RISC-V, PowerPC: word loads and stores (`ldr r3, [r0]`,
        `lw $v0, 8($a0)`, `c.ld a5, 0x20(a5)`, `ld r9, 0(r3)`), copies, adding a constant (an
        address when constant propagation gave the instruction one), register calls (`blx r3`,
        `jalr $t9`, `c.jalr a5`, `mtctr r12; bctrl`), frame slots. A MIPS delay-slot
        instruction runs before the branch, call or return it follows."""
        r = self.risc
        ptr = self.ptr
        loads, stores = r["loads"][ptr], r["stores"][ptr]
        toc = getattr(self.b, "ppc_toc", None)
        if toc is not None:
            st["r2"] = ("addr", toc)                   # (PowerPC64: the TOC, however it is reloaded)
        insns = list(insns)
        for k in range(len(insns) - 1):
            if insns[k + 1].delay and not insns[k].delay:
                insns[k], insns[k + 1] = insns[k + 1], insns[k]
        for i in insns:
            ops = _a64_ops(i.op_str)
            m = i.mnemonic.removeprefix("c.").split(".")[0]
            if i.kind == CALL_KIND:
                reg = "ctr" if m.startswith("bctr") else (ops[-1] if ops and i.target is None else None)
                v = st.get(reg) if reg else None
                if i.target is None and v and v[0] == "fn":
                    self.sites[i.addr] = v[1]
                self.call(i, [], st, dyncast=bool(v and v == ("imp", "__dynamic_cast")))
                continue
            if i.kind == RET_KIND:
                rets.append(st.get(self.ret))
                continue
            if i.kind in (CJMP_KIND, JMP_KIND):
                continue
            if m in ("push", "pop", "ldm", "ldmia", "pop", "vpop"):
                for x in ops:
                    for reg in x.strip("{}").split(","):
                        if m != "push":
                            st.pop(reg.strip(), None)
                continue
            if m == "mtctr" and ops:
                v = st.get(ops[0])
                st.pop("ctr", None)
                if v is not None:
                    st["ctr"] = v
                continue
            if toc is not None and ops and ops[0] == "r2":
                continue
            if m in loads and len(ops) >= 2:
                base, disp = _risc_mem(", ".join(ops[1:]), r)
                v = None
                got = self.b.read_ptr(i.refs[-1]) if i.refs else None
                bv = st.get(base) if base is not None else None
                if bv is not None and bv[0] == "fn" and disp == 0 and getattr(self.b, "func_descriptors", None):
                    st[ops[0]] = bv                     # (ELFv1: the code address in the method's descriptor)
                    continue
                if bv is not None and bv[0] not in ("obj", "vptr"):
                    bv = None              # (r31, s0, r7: a frame base at -O0, an object's register at -O2)
                imp = self.b.imports_by_got.get(i.refs[-1]) if i.refs else None
                if imp is not None:
                    v = ("imp", imp.name)                # (MIPS: `lw $t9, ...($gp)`, then `jalr $t9`)
                elif got in self.vt or got in self.vstarts or got in self.ti:   # (PIC: from the GOT)
                    v = ("ti", self.ti[got]) if got in self.ti else ("addr", got)
                elif bv is None and base in r["frame"] and disp is not None:
                    v = st.get(("slot", base, disp))
                elif bv is not None and disp is not None:
                    if bv[0] == "obj" and disp == 0:
                        v = ("vptr", bv[1], bv[2], 0)
                    elif bv[0] == "vptr":
                        t = self.slot(bv[1], bv[2], (bv[3] + disp) // ptr)
                        v = ("fn", t) if t else None
                st.pop(ops[0], None)
                if v is not None:
                    st[ops[0]] = v
                continue
            if (m in stores and len(ops) == 2) or (m in ("strd", "stp") and len(ops) == 3):
                base, disp = _risc_mem(ops[-1], r)     # (`strd r2, r3, [r0]`: the first word is r2)
                v = st.get(ops[0])
                if ops[0] in r["zero"]:
                    v = ("null",)
                bv = st.get(base) if base is not None else None
                if base in r["frame"] and disp is not None and not (bv and bv[0] in ("obj", "ptr", "this")):
                    if v is not None:
                        st[("slot", base, disp)] = v
                    else:
                        st.pop(("slot", base, disp), None)
                elif base is not None and disp == 0 and v is not None and v[0] in ("addr", "addrs"):
                    self.construct(f, st, base, v[1])
                continue
            if not ops or not _risc_reg(ops[0]) or m.startswith(("cmp", "tst", "cmn", "st")):
                continue
            dst = ops[0]
            v = None
            if m in ("mov", "movs", "mv", "move", "mr", "li") and len(ops) == 2:
                if _risc_reg(ops[1]):
                    v = ("null",) if ops[1] in r["zero"] else st.get(ops[1])
                elif ops[1].lstrip("#") in ("0", "0x0"):
                    v = ("null",)
            elif m in ("add", "adds", "addi", "addis", "addiu", "daddiu", "addw") and len(ops) in (2, 3):
                src = st.get(ops[1] if len(ops) == 3 else dst)
                try:
                    k = int(ops[-1].lstrip("#"), 0) << (16 if m == "addis" else 0)
                except ValueError:
                    k = None
                if i.refs and (src is None or src[0] != "vptr"):
                    a = i.refs[-1]
                    v = ("ti", self.ti[a]) if a in self.ti else ("addr", a)
                elif k is not None and src and src[0] == "addr":
                    a = (src[1] + k) & ((1 << self.b.bits) - 1)
                    v = ("ti", self.ti[a]) if a in self.ti else ("addr", a)
                elif k is not None and src and src[0] == "vptr":
                    v = ("vptr", src[1], src[2], src[3] + k)
            elif m in ("lis", "lui") and len(ops) == 2 and not i.refs:
                try:                                    # (the high part of an address: `addi` adds the rest)
                    v = ("addr", (int(ops[1], 0) << (12 if self.b.arch.startswith("riscv") else 16))
                         & ((1 << self.b.bits) - 1))
                except ValueError:
                    v = None
            elif m == "or" and len(ops) == 3 and ops[1] == ops[2]:
                v = st.get(ops[1])                     # (PowerPC `mr.`: `or. r9, r3, r3`)
            st.pop(dst, None)
            if v is not None:
                st[dst] = v
        return st

    def call(self, i, ops, st: dict, dyncast: bool = False):
        ptr = self.ptr
        targets = None
        if i.target is None and ops:
            op = ops[0]
            inner = _inner(op)
            if inner is not None:
                base, disp = _base_disp(inner)
                bv = st.get(self.reg(base)) if base else None
                if bv and bv[0] == "vptr" and disp is not None:
                    targets = self.slot(bv[1], bv[2], (bv[3] + disp) // ptr)
            elif _is_reg(op):
                v = st.get(self.reg(op))
                if v and v[0] == "fn":
                    targets = v[1]
            if targets:
                self.sites[i.addr] = targets
        if i.target is not None:
            self._passed.setdefault(i.target, []).append(tuple(st.get(r) for r in self.argregs))
        this = st.get(self.this)
        ctor = self.ctors.get(i.target) if i.target is not None else None
        result = None
        if dyncast or i.target in self.dyncast:      # __dynamic_cast(obj, src type, dst type, hint)
            dst = st.get("x2" if self.a64 else self.argregs[2] if self.risc is not None
                         else "rdx" if self.x64 else None)
            if dst and dst[0] == "ti":
                result = ("obj", frozenset(self.derived.get(dst[1], {dst[1]})), dst[1])
        elif i.target is not None and i.target in self.returns:
            result = self.returns[i.target]
        for k in list(st):
            if isinstance(k, str) and k not in self.saved:
                del st[k]
        if ctor is not None and this is not None and this[0] == "ptr":
            new = ("obj", frozenset({ctor}), None)
            for k, v in list(st.items()):
                if v == this:
                    st[k] = new
        st[self.ret] = result if result is not None else self.fresh()


def _join(states: list[dict]) -> dict:
    """What every way into a block agrees on; objects that may be of different classes on
    different ways: of any of them."""
    out = {}
    for k, v in states[0].items():
        vs = [x.get(k) for x in states]
        if all(w == v for w in vs):
            out[k] = v
        elif all(w is not None and w[0] in ("addr", "addrs") for w in vs):
            out[k] = ("addrs", frozenset().union(*({w[1]} if w[0] == "addr" else w[1] for w in vs)))
        elif _merge_objs(vs) is not None:
            out[k] = _merge_objs(vs)
    return out


def _merge_objs(vs: list) -> tuple | None:
    """Objects (or null pointers -- no call goes through them) from several ways: an object of
    any of their classes; None when some way has something else."""
    if not all(v is not None and v[0] in ("obj", "null") for v in vs):
        return None
    objs = [v for v in vs if v[0] == "obj"]
    if not objs:
        return None
    statics = {v[2] for v in objs}
    return "obj", frozenset().union(*(v[1] for v in objs)), statics.pop() if len(statics) == 1 else None


def _a64_ops(text: str) -> list[str]:
    """Operands, a bracketed address kept whole: `x8, [x0, #8]` -> ["x8", "[x0, #8]"]."""
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _a64_mem(op: str) -> tuple[str | None, int | None]:
    """`[x0, #8]` -> ("x0", 8); `[sp]` -> ("sp", 0); pre/post-indexed and register offsets: None."""
    if not op.startswith("[") or not op.endswith("]"):
        return None, None
    parts = [p.strip() for p in op[1:-1].split(",")]
    if len(parts) == 1:
        return parts[0], 0
    if len(parts) == 2 and parts[1].startswith("#"):
        try:
            return parts[0], int(parts[1][1:], 0)
        except ValueError:
            return None, None
    return None, None


def _is_reg(op: str) -> bool:
    return op.isalnum() and not op[:1].isdigit()


def _inner(op: str) -> str | None:
    if not op.endswith("]") or "[" not in op:
        return None
    return op.split("[", 1)[1][:-1]


def _stack(inner: str) -> bool:
    base, disp = _base_disp(inner)
    return base in ("rbp", "rsp", "ebp", "esp") and disp is not None


def _base_disp(inner: str) -> tuple[str | None, int | None]:
    """`rax + 0x10` -> ("rax", 16); `rbp - 8` -> ("rbp", -8); anything with an index -> (None, None)."""
    parts = inner.split()
    if not parts or "*" in inner or "rip" in parts:
        return None, None
    base = parts[0] if _is_reg(parts[0]) else None
    if len(parts) == 1:
        return base, 0
    if len(parts) == 3 and parts[1] in "+-" and parts[2][:1].isdigit():
        try:
            v = int(parts[2], 0)
        except ValueError:
            return None, None
        return base, v if parts[1] == "+" else -v
    return None, None


# ARM, MIPS, RISC-V and PowerPC (System V / AAPCS / o32 / ELF ABIs): argument registers (the
# first is `this`), the result register, registers a call keeps, frame base registers, the
# word loads and stores by pointer size, zero registers
_RISC = {
    "arm": {"args": ("r0", "r1", "r2", "r3"), "ret": "r0",
            "saved": ("r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sb", "sl", "fp", "sp"),
            "frame": ("sp", "r7", "r11", "fp"), "loads": {4: ("ldr",)}, "stores": {4: ("str",)}, "zero": ()},
    "mips": {"args": ("$a0", "$a1", "$a2", "$a3"), "ret": "$v0",
             "saved": tuple(f"$s{n}" for n in range(8)) + ("$fp", "$sp", "$gp", "$s8"),
             "frame": ("$sp", "$fp", "$s8"), "loads": {4: ("lw",), 8: ("ld",)}, "stores": {4: ("sw",), 8: ("sd",)},
             "zero": ("$zero", "$0")},
    "riscv": {"args": tuple(f"a{n}" for n in range(8)), "ret": "a0",
              "saved": tuple(f"s{n}" for n in range(12)) + ("sp", "fp"),
              "frame": ("sp", "s0", "fp"), "loads": {4: ("lw", "lwsp"), 8: ("ld", "ldsp")},
              "stores": {4: ("sw", "swsp"), 8: ("sd", "sdsp")}, "zero": ("zero", "x0")},
    "ppc": {"args": tuple(f"r{n}" for n in range(3, 11)), "ret": "r3",
            "saved": tuple(f"r{n}" for n in range(14, 32)) + ("r1", "r2"),
            "frame": ("r1", "r31"), "loads": {4: ("lwz",), 8: ("ld",)}, "stores": {4: ("stw",), 8: ("std",)},
            "zero": ()},
}


def _risc_arch(arch: str) -> str | None:
    if arch == "arm":
        return "arm"
    for k in ("mips", "riscv", "ppc"):
        if arch.startswith(k):
            return k
    return None


def _risc_reg(op: str) -> bool:
    return bool(op) and (op.isalnum() or op[0] == "$" and op[1:].isalnum()) and not op[:1].isdigit()


def _risc_mem(op: str, r: dict) -> tuple[str | None, int | None]:
    """`[r3, #8]`, `[r0]` (ARM), `0x20(a5)`, `($v0)`, `-8(r31)` -> (base, displacement); an index
    register or a pre / post-indexed form -> (None, None)."""
    op = op.strip()
    if op.startswith("["):
        if op.endswith("!"):
            return None, None
        return _a64_mem(op)
    if op.endswith(")") and "(" in op:
        off, _, base = op[:-1].partition("(")
        try:
            return base.strip(), int(off.strip() or "0", 0)
        except ValueError:
            return None, None
    return None, None


def object_calls(an, classes: dict[str, CppClass]) -> dict[int, tuple[frozenset[int], bool]]:
    if (an.bin.arch not in ("x64", "x86", "arm64") and _risc_arch(an.bin.arch) is None) or not classes:
        return {}
    t = _Types(an, classes)
    if t.this is None:
        return {}
    return t.run()

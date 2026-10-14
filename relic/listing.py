"""Annotated disassembly listing shared by the CLI and the GUI."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

from .analysis import Analysis
from .analysis.functions import Function
from .disasm import CALL, JMP, Insn

_HEX = re.compile(r"0x[0-9a-fA-F]+")


@dataclass
class Line:
    kind: str  # func | label | insn | data | blank | xref
    addr: int
    text: str = ""
    raw: bytes = b""
    mnemonic: str = ""
    operands: str = ""
    comment: str = ""
    target: int | None = None  # navigable address for this line
    color: str | None = None   # background a plugin gave the line (`#rrggbb`)


def operands(an: Analysis, i: Insn) -> str:
    """Operand text with branch targets replaced by symbolic names."""
    op = i.op_str
    if i.target is not None and i.kind != "normal":
        name = an.label(i.target)
        op = _HEX.sub(lambda m: name if int(m.group(), 16) == i.target else m.group(), op)
    return op


def comment(an: Analysis, i: Insn) -> str:
    parts = []
    for a, (old, new) in getattr(an, "patches", {}).items():
        if a <= i.addr < a + len(new):
            parts.append(f"patched (was {old.hex(' ')})" if a == i.addr else "patched")
            break
    user = an.comments.get(i.addr)
    if user:
        parts.append(user)
    if i.kind == CALL and i.target is None and i.mem_target is not None:
        n = an.call_name(i)
        if n:
            parts.append(n)
    seen = set()
    for r in i.refs:
        if r in seen or r == i.target:
            continue
        seen.add(r)
        d = an.describe_ref(r)
        if d:
            parts.append(d)
        elif r != i.mem_target:
            parts.append(f"{r:#x}")
    return "; ".join(parts)


def decorate(an: Analysis, lines: list[Line], decorators=()) -> list[Line]:
    """Let plugin decorators add to instruction / data lines: each is called as `d(an, line)` and
    returns None, a comment to append, or a dict with `comment` and / or `color` (`#rrggbb`)."""
    if not decorators:
        return lines
    for ln in lines:
        if ln.kind not in ("insn", "data"):
            continue
        for d in decorators:
            r = d(an, ln)
            if not r:
                continue
            if isinstance(r, str):
                r = {"comment": r}
            text = r.get("comment")
            if text:
                ln.comment = f"{ln.comment}; {text}" if ln.comment else str(text)
            if r.get("color"):
                ln.color = str(r["color"])
    return lines


def function_lines(an: Analysis, f: Function, decorators=()) -> list[Line]:
    """The listing of a function; `decorators` are plugin hooks (see `decorate`)."""
    return decorate(an, _function_lines(an, f), decorators)


def _function_lines(an: Analysis, f: Function) -> list[Line]:
    lines: list[Line] = []
    name = an.name(f.addr) or f.name
    callers = sorted({x.frm for x in an.xrefs_to.get(f.addr, []) if x.kind in ("call", "jmp")})
    lines.append(Line("func", f.addr, f"{name}:"))
    for c in callers[:8]:
        lines.append(Line("xref", f.addr, f"; XREF from {an.location(c)}", target=c))
    if len(callers) > 8:
        lines.append(Line("xref", f.addr, f"; ... {len(callers) - 8} more xrefs"))
    if f.is_import:
        lines.append(Line("insn", f.addr, comment="imported function"))
        return lines
    labels = set(f.blocks) - {f.addr}
    pools = _pool_slots(an, f)
    prev_end = None
    prev_blk = None
    for a in sorted(f.blocks):
        blk = f.blocks[a]
        if prev_end is not None and prev_end < a:
            lines += _with_comments(an, _gap_lines(an, f, prev_end, a, prev_blk, pools))
        elif prev_end is not None and prev_end != a:
            lines.append(Line("blank", prev_end))
        if a in labels:
            lines.append(Line("label", a, f"{an.label(a)}:"))
        for i in blk.insns:
            lines.append(insn_line(an, i))
        prev_end = blk.end
        prev_blk = blk
    if prev_end is not None:
        tail = _tail_end(an, f, prev_end, pools)
        if tail > prev_end:
            lines += _with_comments(an, _gap_lines(an, f, prev_end, tail, prev_blk, pools))
    return lines


def _with_comments(an: Analysis, lines: list[Line]) -> list[Line]:
    """The user's comments on data lines (instruction lines already carry theirs)."""
    for ln in lines:
        user = an.comments.get(ln.addr) if ln.kind == "data" else None
        if user:
            ln.comment = f"{user}; {ln.comment}" if ln.comment else user
    return lines


# ------------------------------------------------------------ data inside functions
# Bytes between a function's blocks (and the literal pool after its last one) are not
# instructions: ARM literal pools, Thumb `tbb`/`tbh` offset tables, inline jump tables,
# x86 alignment padding. They are shown as data lines instead of being left out.

_GAP_MAX = 0x4000            # larger holes are not one function's data
_POOL_REACH = 0x1000         # pc-relative loads reach at most 4 KiB ahead (ARM ldr: 4095)


def _pool_slots(an: Analysis, f: Function) -> dict[int, tuple[int, Insn]]:
    """Literal pool slots the function loads pc-relative -> (size, loading insn):
    ARM / Thumb `ldr rX, [pc, #n]` (`vldr`, `ldrd`, ...), AArch64 `ldr x0, label`."""
    arch = an.bin.arch
    if arch not in ("arm", "arm64"):
        return {}
    out: dict[int, tuple[int, Insn]] = {}
    for b in f.blocks.values():
        for i in b.insns:
            m = i.mnemonic.split(".")[0]
            c = i.cs
            if c is None or not (m.startswith("ldr") or m.startswith("vldr")):
                continue
            try:
                ops = c.operands
            except Exception:
                continue
            if arch == "arm":
                if len(ops) < 2 or ops[-1].type != 3 or c.reg_name(ops[-1].mem.base) != "pc" or ops[-1].mem.index:
                    continue
                disp = ops[-1].mem.disp
                if getattr(ops[-1], "subtracted", False) and disp > 0:
                    disp = -disp
                pc = ((i.addr + 4) & ~3) if i.thumb else i.addr + 8
                slot = pc + disp
                reg = c.reg_name(ops[0].reg) or ""
                size = 8 if m in ("ldrd",) or reg.startswith("d") else 2 if m.startswith("ldrh") or \
                    m.startswith("ldrsh") else 1 if m.startswith("ldrb") or m.startswith("ldrsb") else 4
            else:
                if len(ops) != 2 or ops[1].type != 2:
                    continue
                slot = ops[1].imm
                reg = c.reg_name(ops[0].reg) or ""
                size = 16 if reg.startswith("q") else 8 if reg[:1] in ("x", "d") else 4
            out[slot] = (size, i)
    return out


def _tail_end(an: Analysis, f: Function, start: int, pools: dict) -> int:
    """End of the data right after the function's last block: its literal pool (from the slots
    it loads, or an ARM `$d` mapping symbol), stopping at the next function."""
    if an.bin.arch not in ("arm", "arm64"):
        return start
    nxt = start + _POOL_REACH
    starts = getattr(an, "_fstarts", None) or sorted(an.functions)
    k = bisect.bisect_right(starts, start - 1)
    if k < len(starts):
        nxt = min(nxt, starts[k])
    end = start
    for slot, (size, _) in pools.items():
        if start <= slot < nxt:
            end = max(end, slot + size)
    mapping = an.bin.arm_mapping
    if mapping and mapping.get(start) == "d":
        later = [a for a in mapping if start < a < nxt]
        end = max(end, min(later) if later else nxt)
    return min(end, nxt)


def _gap_lines(an: Analysis, f: Function, s: int, e: int, prev_blk, pools: dict) -> list[Line]:
    if e - s > _GAP_MAX or _other_function_in(an, f, s, e):
        return [Line("blank", s)]
    data = an.bin.read(s, e - s)
    if len(data) != e - s:
        return [Line("blank", s)]
    out = [Line("blank", s)]
    if an.bin.arch in ("x86", "x64"):
        if _is_padding(an, s, e, data):
            out.append(Line("data", s, raw=data, mnemonic="align", operands=str(_align_of(e)),
                            comment=f"{e - s} bytes of padding"))
            return out
        return out + _code_lines(an, s, e, f)       # e.g. after a call that does not return
    jt = _jump_table_at(an, f, s, prev_blk)
    if jt is not None:
        size, targets = jt
        out.append(Line("label", s, f"jumptable_{s:x}:  ; {len(targets)} cases"))
        for k, t in enumerate(targets):
            a = s + size * k
            if a + size > e:
                break
            name = {1: ".byte", 2: ".short"}.get(size, ".word")
            out.append(Line("data", a, raw=an.bin.read(a, size), mnemonic=name,
                            operands=f"{an.bin.read_int(a, size):#x}", comment=f"case {k} -> {an.label(t)}",
                            target=t))
        s += size * len(targets)
        if s >= e:
            return out
    # ARM mapping symbols (`$a` / `$t` code, `$d` data) say which parts are code nothing reaches
    mapping = an.bin.arm_mapping
    marks = sorted(a for a in mapping if s < a < e) if mapping else []
    for lo, hi in zip([s] + marks, marks + [e]):
        k = bisect.bisect_right(an.dis._map_addrs, lo) - 1 if mapping else -1
        kind = an.dis._map_kinds[k] if k >= 0 else "d"
        if kind in ("a", "t") and lo not in pools:
            out += _code_lines(an, lo, hi, f)
        else:
            out += _word_lines(an, f, lo, hi, pools)
    return out


def _other_function_in(an: Analysis, f: Function, s: int, e: int) -> bool:
    """Code of another function lives in the hole (e.g. `f`'s cold block is far away, or the
    hole holds a block of another function's own cold part)."""
    cache = getattr(an, "_block_spans", None)
    if cache is None or cache[0] is not an.functions:
        spans = sorted((b.addr, b.end, g.addr) for g in an.functions.values() if not g.is_import
                       for b in g.blocks.values())
        cache = (an.functions, [x[0] for x in spans], spans)
        an._block_spans = cache
    _, starts, spans = cache
    k = max(bisect.bisect_left(starts, s) - 1, 0)
    while k < len(spans) and spans[k][0] < e:
        lo, hi, owner = spans[k]
        if owner != f.addr and hi > s:
            return True
        k += 1
    starts = getattr(an, "_fstarts", None) or sorted(an.functions)
    k = bisect.bisect_left(starts, s)
    return k < len(starts) and starts[k] < e and starts[k] != f.addr


def _code_lines(an: Analysis, s: int, e: int, f: Function | None = None) -> list[Line]:
    """Code inside the function that no known edge reaches. With an unresolved indirect jump
    in the function it may well be a target of that jump."""
    unresolved = f is not None and any(
        b.last.kind == JMP and b.last.target is None and b.last.addr not in f.jump_tables and not b.succs
        for b in f.blocks.values() if b.insns)
    note = "no known path (unresolved indirect jump)" if unresolved else "not reached"
    out = []
    for i in an.dis.linear(s, 4096):
        if i.addr != s or i.end > e:
            break
        ln = insn_line(an, i)
        if not out:                              # once, on the first instruction of the run
            ln.comment = "; ".join(x for x in (note, ln.comment) if x)
        out.append(ln)
        s = i.end
    return out + (_byte_lines(an, s, e) if s < e else [])


def _is_padding(an: Analysis, s: int, e: int, data: bytes) -> bool:
    if all(b in (0x90, 0xCC, 0x00) for b in data):
        return True
    a = s
    for i in an.dis.linear(s, 64):
        if a >= e:
            break
        if i.addr != a or i.end > e or not (i.mnemonic.startswith("nop") or i.mnemonic == "int3" or
                                            i.mnemonic in ("xchg", "lea") and _self_op(i.op_str)):
            return False
        a = i.end
    return a >= e


def _self_op(op: str) -> bool:
    """`xchg ax, ax`, `lea esi, [esi]`: multi-byte nops of old assemblers."""
    parts = [p.strip().strip("[]").replace("+ 0", "").strip() for p in op.split(",")]
    return len(parts) == 2 and parts[0].split()[-1] == parts[1].split()[-1]


def _align_of(addr: int) -> int:
    n = 1
    while n < 64 and addr % (n * 2) == 0:
        n *= 2
    return n


def _jump_table_at(an: Analysis, f: Function, s: int, prev_blk) -> tuple[int, list[int]] | None:
    """The inline table a dispatch right before `s` reads: Thumb `tbb` / `tbh` (byte / halfword
    entries) and ARM `ldr pc, [pc, rI, lsl #2]` (words)."""
    if prev_blk is None or not prev_blk.insns:
        return None
    jmp = prev_blk.insns[-1]
    targets = f.jump_tables.get(jmp.addr)
    if not targets:
        return None
    m = jmp.mnemonic.split(".")[0]
    if m == "tbb":
        return 1, targets
    if m == "tbh":
        return 2, targets
    if m.startswith("ldr") and "pc" in jmp.op_str.split(",")[0]:
        start = ((jmp.addr + 4) & ~3) if jmp.thumb else jmp.addr + 8
        return (4, targets) if start == s else None
    return None


def _byte_lines(an: Analysis, s: int, e: int) -> list[Line]:
    out = []
    while s < e:
        n = min(8, e - s)
        raw = an.bin.read(s, n)
        out.append(Line("data", s, raw=raw, mnemonic=".byte", operands=", ".join(f"{b:#04x}" for b in raw)))
        s += n
    return out


def _word_lines(an: Analysis, f: Function, s: int, e: int, pools: dict) -> list[Line]:
    """Literal pool words: the value, what it points at, and -- for an ARM PIC pool slot added to
    pc by the code that loads it (`ldr r3, [pc, #n]; add r3, pc, r3`) -- the address it makes."""
    out = []
    bits = an.bin.bits
    while s < e:
        size = pools[s][0] if s in pools else 4
        if size not in (1, 2, 4, 8, 16) or s % min(size, 4) or s + size > e:
            size = 2 if s % 2 == 0 and s + 2 <= e else 1
        if size == 16:
            size = 8
        raw = an.bin.read(s, size)
        v = int.from_bytes(raw, "little" if an.bin.endian == "little" else "big")
        name = {1: ".byte", 2: ".short", 4: ".word", 8: ".quad"}[size]
        operand = f"{v:#x}"
        target = None
        notes = []
        code = v & ~1 if an.bin.arch == "arm" else v
        if size >= 4 and code in f.blocks:
            operand, target = an.label(code), code
        elif size * 8 >= min(bits, 32) and v and an.bin.is_mapped(v):
            d = an.describe_ref(v)
            target = v
            if d:
                notes.append(d)
        if size == 2 and an.bin.arch == "arm" and v == 0xBF00 or size == 4 and v == 0xE320F000:
            notes.append("nop (padding)")
        if s in pools:
            made = _pic_target(an, pools[s][1], v)
            if made is not None:
                d = an.describe_ref(made) or an.label(made)
                notes.append(f"pc + {v:#x} = {d}")
                target = made
            elif size == 4 and (got := _got_base(an)) is not None:
                imp = an.bin.imports_by_got.get((got + v) & 0xFFFFFFFF)
                if imp is not None:
                    notes.append(f"GOT + {v:#x} = [{imp.name}@got]")
            notes.append(f"literal <- {an.location(pools[s][1].addr)}")
        out.append(Line("data", s, raw=raw, mnemonic=name, operands=operand, comment="; ".join(notes),
                        target=target))
        s += size
    return out


def _got_base(an: Analysis) -> int | None:
    """`_GLOBAL_OFFSET_TABLE_`, which ARM PIC code adds GOT offsets from the literal pool to."""
    a = an.bin.name_to_addr.get("_GLOBAL_OFFSET_TABLE_")
    if a is None:
        sec = an.bin.section(".got")
        a = sec.addr if sec is not None else None
    return a


def _pic_target(an: Analysis, ldr: Insn, value: int) -> int | None:
    """`ldr rX, [pc, #n]` followed (within a few instructions) by `add rX, pc, rX`: the pool
    word is an offset from that `add`'s pc."""
    c = ldr.cs
    if c is None or an.bin.arch != "arm":
        return None
    try:
        dst = c.reg_name(c.operands[0].reg)
    except Exception:
        return None
    a = ldr.end
    for _ in range(6):
        i = an.dis.decode(a)
        if i is None:
            return None
        ops = [o.strip() for o in i.op_str.split(",")]
        if i.mnemonic.split(".")[0] == "add" and ops[0] == dst and "pc" in ops[1:] and \
                (dst in ops[1:] or len(ops) == 2):
            pc = ((i.addr + 4) & ~3) if i.thumb else i.addr + 8
            return (pc + value) & 0xFFFFFFFF
        if ops and ops[0] == dst or i.is_terminator:
            return None
        a = i.end
    return None


def insn_line(an: Analysis, i: Insn) -> Line:
    tgt = i.target if i.target is not None else (i.refs[0] if i.refs else None)
    return Line("insn", i.addr, raw=i.raw, mnemonic=i.mnemonic, operands=operands(an, i),
                comment=comment(an, i), target=tgt)


def render(lines: list[Line], show_bytes: bool = True) -> str:
    out = []
    for ln in lines:
        if ln.kind == "func":
            out.append("")
            out.append(f"{ln.addr:016x}  {ln.text}" if ln.addr >> 32 else f"{ln.addr:08x}  {ln.text}")
        elif ln.kind in ("xref", "label"):
            out.append(f"{'':10}{ln.text}")
        elif ln.kind == "blank":
            out.append("")
        else:
            addr = f"{ln.addr:016x}" if ln.addr >> 32 else f"{ln.addr:08x}"
            raw = ln.raw.hex(" ")
            raw = (raw if len(raw) <= 23 else raw[:20] + "..").ljust(24) if show_bytes else ""
            ins = f"{ln.mnemonic} {ln.operands}".strip().ljust(36)
            c = f"; {ln.comment}" if ln.comment else ""
            out.append(f"  {addr}  {raw}{ins}{c}".rstrip())
    return "\n".join(out)

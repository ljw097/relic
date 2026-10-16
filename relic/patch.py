"""Byte patches: change instructions or data, keep the changes in the project, write a patched file.

A patch replaces bytes of the file image (only bytes the file holds: not
.bss). `Analysis.patch()` records it -- the original bytes too, so it can
be reverted -- and re-analyses the binary; the project file keeps patches
and re-applies them when the binary is opened again. `export()` writes the
patched image next to the original.

Helpers build the bytes for the common edits:

- `nop_bytes`: the instruction at an address replaced with NOPs of the
  architecture (x86 `90`, A32 / Thumb / AArch64 / MIPS / RISC-V / PPC nops);
- `invert_bytes`: a conditional branch with its condition negated (x86
  `jcc`, A32 / Thumb `b<cc>`, `cbz` / `cbnz`, AArch64 `b.cc`, `cbz`, `tbz`,
  MIPS `beq` / `bne`, `blez` / `bgtz`, `bltz` / `bgez`);
- `assemble`: text assembled with keystone (`pip install keystone-engine`),
  when it is installed.
"""
from __future__ import annotations

import os
import shutil
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .analysis import Analysis
    from .loader.base import Binary


class PatchError(Exception):
    pass


def parse_hex(text: str) -> bytes:
    """`90 90`, `9090`, `0x90,0x90` -> bytes; a quoted string (`"/bin/sh\\0"`, escapes as in
    Python) -> its bytes, with no NUL added."""
    stripped = text.strip()
    if stripped[:1] in ("'", '"') or stripped[:2] in ("b'", 'b"'):
        import ast
        try:
            v = ast.literal_eval(stripped if stripped[0] == "b" else "b" + stripped)
        except (ValueError, SyntaxError) as e:
            raise PatchError(f"bad string {text!r}: {e}") from None
        if not isinstance(v, bytes):
            raise PatchError(f"bad string {text!r}")
        return v
    t = text.replace(",", " ").replace("0x", "").replace("\\x", " ")
    try:
        return bytes.fromhex(t.replace(" ", ""))
    except ValueError:
        raise PatchError(f"not hex bytes: {text!r}") from None


def write(b: "Binary", addr: int, data: bytes) -> bytes:
    """Replace the file bytes at `addr` (in place in `b.data`); returns the bytes that were there."""
    if not data:
        raise PatchError("nothing to write")
    off = b.addr_to_offset(addr)
    end = b.addr_to_offset(addr + len(data) - 1)
    if off is None or end is None or end != off + len(data) - 1:
        raise PatchError(f"{addr:#x}..{addr + len(data):#x} is not all in the file (bss, unmapped or "
                         "split over segments)")
    old = bytes(b.data[off:off + len(data)])
    b.data = b.data[:off] + bytes(data) + b.data[off + len(data):]
    return old


# ------------------------------------------------------------------ NOPs
def _nop_unit(b: "Binary", thumb: bool) -> bytes:
    e = b.endian
    if b.arch in ("x86", "x64"):
        return b"\x90"
    if b.arch == "arm":
        return (0xBF00).to_bytes(2, e) if thumb else (0xE320F000).to_bytes(4, e)
    if b.arch == "arm64":
        return (0xD503201F).to_bytes(4, e)
    if b.arch.startswith("mips"):
        return b"\0\0\0\0"
    if b.arch.startswith("riscv"):
        return (0x00000013).to_bytes(4, e)
    if b.arch.startswith("ppc"):
        return (0x60000000).to_bytes(4, e)
    raise PatchError(f"no NOP for {b.arch}")


def nop_bytes(an: "Analysis", addr: int) -> bytes:
    """NOPs covering the instruction at `addr`."""
    i = an.dis.decode(addr)
    if i is None:
        raise PatchError(f"no instruction at {addr:#x}")
    unit = _nop_unit(an.bin, i.thumb)
    if i.size % len(unit):
        raise PatchError(f"{i.size}-byte instruction cannot be filled with {len(unit)}-byte NOPs")
    if i.thumb and i.size == 4:                      # nop.w: two halfwords, F3AF 8000
        return (0xF3AF).to_bytes(2, an.bin.endian) + (0x8000).to_bytes(2, an.bin.endian)
    return unit * (i.size // len(unit))


# ------------------------------------------------------- branch inversion
_MIPS_FLIP = {0b000100: 0b000101, 0b000101: 0b000100,      # beq <-> bne
              0b000110: 0b000111, 0b000111: 0b000110,      # blez <-> bgtz
              0b010100: 0b010101, 0b010101: 0b010100,      # beql <-> bnel
              0b010110: 0b010111, 0b010111: 0b010110}      # blezl <-> bgtzl


def invert_bytes(an: "Analysis", addr: int) -> bytes:
    """The conditional branch at `addr` with the opposite condition (same length, same target)."""
    b = an.bin
    i = an.dis.decode(addr)
    if i is None or i.kind != "cjmp":
        raise PatchError(f"no conditional branch at {addr:#x}")
    raw = bytearray(i.raw)
    e = b.endian
    if b.arch in ("x86", "x64"):
        k = 0
        while k < len(raw) and raw[k] in (0x2E, 0x3E, 0xF2, 0xF3, 0x66, 0x67):   # hints, bnd
            k += 1
        if k < len(raw) and 0x70 <= raw[k] <= 0x7F:
            raw[k] ^= 1
        elif k + 1 < len(raw) and raw[k] == 0x0F and 0x80 <= raw[k + 1] <= 0x8F:
            raw[k + 1] ^= 1
        else:
            raise PatchError(f"{i.mnemonic} has no inverse (jcxz / loop)")
        return bytes(raw)
    if b.arch == "arm64":
        w = int.from_bytes(raw, e)
        if w >> 24 == 0x54:                              # b.cond
            if w & 0xF >= 0xE:
                raise PatchError("b.al / b.nv cannot be inverted")
            w ^= 1
        elif (w >> 25) & 0x3F in (0b011010, 0b011011):   # cbz / cbnz, tbz / tbnz: op is bit 24
            w ^= 1 << 24
        else:
            raise PatchError(f"cannot invert {i.mnemonic}")
        return w.to_bytes(4, e)
    if b.arch == "arm":
        if not i.thumb:
            w = int.from_bytes(raw, e)
            if w >> 28 >= 0xE:
                raise PatchError("unconditional")
            return (w ^ (1 << 28)).to_bytes(4, e)
        h = int.from_bytes(raw[:2], e)
        if len(raw) == 2:
            if h >> 12 == 0xD and (h >> 8) & 0xF < 0xE:      # b<cc>.n
                return (h ^ (1 << 8)).to_bytes(2, e)
            if h & 0xF500 == 0xB100:                         # cbz / cbnz: bit 11
                return (h ^ (1 << 11)).to_bytes(2, e)
        elif h >> 11 == 0b11110 and (h >> 6) & 0xF < 0xE:    # b<cc>.w: cond in bits 6-9
            return (h ^ (1 << 6)).to_bytes(2, e) + bytes(raw[2:])
        raise PatchError(f"cannot invert {i.mnemonic}")
    if b.arch.startswith("mips"):
        w = int.from_bytes(raw, e)
        op = w >> 26
        if op in _MIPS_FLIP:
            return ((w & 0x03FFFFFF) | (_MIPS_FLIP[op] << 26)).to_bytes(4, e)
        if op == 1 and (w >> 16) & 0x1F in (0, 1, 2, 3):      # bltz / bgez (and -l)
            return (w ^ (1 << 16)).to_bytes(4, e)
        raise PatchError(f"cannot invert {i.mnemonic}")
    raise PatchError(f"branch inversion is not supported on {b.arch}")


# ------------------------------------------------------------- assembling
def assemble(an: "Analysis", addr: int, text: str) -> bytes:
    """Machine code for `text` at `addr` (keystone; `;` separates instructions)."""
    try:
        import keystone as K
    except ImportError:
        raise PatchError("assembling needs keystone: pip install keystone-engine") from None
    b = an.bin
    big = K.KS_MODE_BIG_ENDIAN if b.endian == "big" else K.KS_MODE_LITTLE_ENDIAN
    if b.arch in ("x86", "x64"):
        args = (K.KS_ARCH_X86, K.KS_MODE_64 if b.arch == "x64" else K.KS_MODE_32)
    elif b.arch == "arm64":
        args = (K.KS_ARCH_ARM64, big)
    elif b.arch == "arm":
        i = an.dis.decode(addr)
        args = (K.KS_ARCH_ARM, (K.KS_MODE_THUMB if i is not None and i.thumb else K.KS_MODE_ARM) | big)
    elif b.arch.startswith("mips"):
        args = (K.KS_ARCH_MIPS, (K.KS_MODE_MIPS64 if b.bits == 64 else K.KS_MODE_MIPS32) | big)
    elif b.arch.startswith("ppc"):
        args = (K.KS_ARCH_PPC, (K.KS_MODE_PPC64 if b.bits == 64 else K.KS_MODE_PPC32) | big)
    else:
        raise PatchError(f"no assembler for {b.arch}")
    try:
        enc, _ = K.Ks(*args).asm(text, addr)
    except K.KsError as e:
        raise PatchError(f"cannot assemble {text!r}: {e}") from None
    if not enc:
        raise PatchError(f"{text!r} assembles to nothing")
    return bytes(enc)


def fit(an: "Analysis", addr: int, data: bytes) -> bytes:
    """Pad `data` with NOPs to the end of the last instruction it overwrites, so no partial
    instruction is left behind."""
    end, a = addr + len(data), addr
    while a < end:
        i = an.dis.decode(a)
        if i is None:
            return data
        a = i.end
    if a == end:
        return data
    unit = _nop_unit(an.bin, False)
    pad = a - end
    return data + unit * (pad // len(unit)) if pad % len(unit) == 0 else data


# ---------------------------------------------------------------- export
def export(b: "Binary", path: str) -> str:
    """Write the (patched) file image to `path`, keeping the original's permission bits."""
    with open(path, "wb") as fp:
        fp.write(bytes(b.data))
    try:
        mode = stat.S_IMODE(os.stat(b.path).st_mode)
        os.chmod(path, mode)
    except OSError:
        shutil.copymode(b.path, path) if os.path.exists(b.path) else None
    return path


__all__ = ["PatchError", "assemble", "export", "fit", "invert_bytes", "nop_bytes", "parse_hex", "write"]

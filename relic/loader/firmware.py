"""Firmware images in text formats: Intel HEX and Motorola S-record. Their data records place
bytes at addresses (one segment per contiguous run); the start-address record, when there is
one, is the entry point. The architecture is not in the file: the one asked for (default ARM,
the usual microcontroller core here)."""
from __future__ import annotations

from .base import Binary, Section, Segment, Symbol


def is_ihex(data: bytes) -> bool:
    head = data[:2048].lstrip()
    return head.startswith(b":") and all(_ihex_line(ln) for ln in head.splitlines()[:8] if ln.strip())


def _ihex_line(ln: bytes) -> bool:
    ln = ln.strip()
    return ln.startswith(b":") and len(ln) >= 11 and all(c in b"0123456789ABCDEFabcdef" for c in ln[1:])


def is_srec(data: bytes) -> bool:
    lines = [ln.strip() for ln in data[:2048].splitlines() if ln.strip()][:8]
    return bool(lines) and all(len(ln) >= 10 and ln[:1] == b"S" and ln[1:2] in b"0123456789" and
                               all(c in b"0123456789ABCDEFabcdef" for c in ln[2:]) for ln in lines)


def _parse_ihex(text: bytes) -> tuple[dict[int, int], int | None]:
    mem: dict[int, int] = {}
    upper, entry = 0, None
    for no, ln in enumerate(text.splitlines(), 1):
        ln = ln.strip()
        if not ln:
            continue
        if not _ihex_line(ln):
            raise ValueError(f"Intel HEX line {no}: not a record")
        rec = bytes.fromhex(ln[1:].decode())
        n, addr, kind, payload = rec[0], int.from_bytes(rec[1:3], "big"), rec[3], rec[4:4 + rec[0]]
        if (sum(rec) & 0xFF) != 0:
            raise ValueError(f"Intel HEX line {no}: bad checksum")
        if kind == 0:
            for k, byte in enumerate(payload[:n]):
                mem[upper + addr + k] = byte
        elif kind == 1:
            break
        elif kind == 2:
            upper = int.from_bytes(payload, "big") << 4
        elif kind == 4:
            upper = int.from_bytes(payload, "big") << 16
        elif kind in (3, 5):
            entry = int.from_bytes(payload, "big") if kind == 5 else \
                (int.from_bytes(payload[:2], "big") << 4) + int.from_bytes(payload[2:4], "big")
    return mem, entry


def _parse_srec(text: bytes) -> tuple[dict[int, int], int | None]:
    mem: dict[int, int] = {}
    entry = None
    for no, ln in enumerate(text.splitlines(), 1):
        ln = ln.strip()
        if not ln:
            continue
        kind = ln[1:2].decode()
        rec = bytes.fromhex(ln[2:].decode())
        if (sum(rec) & 0xFF) != 0xFF:
            raise ValueError(f"S-record line {no}: bad checksum")
        alen = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}.get(kind)
        if alen is None:
            continue
        addr = int.from_bytes(rec[1:1 + alen], "big")
        payload = rec[1 + alen:-1]
        if kind in "123":
            for k, byte in enumerate(payload):
                mem[addr + k] = byte
        elif kind in "789":
            entry = addr
    return mem, entry


def load_firmware(path: str, data: bytes, arch: str | None = None) -> Binary:
    fmt = "IHEX" if is_ihex(data) else "SREC"
    mem, entry = (_parse_ihex if fmt == "IHEX" else _parse_srec)(data)
    if not mem:
        raise ValueError(f"{fmt}: no data records")
    b = Binary(path, b"")
    b.format = fmt
    b.arch = arch or "arm"
    b.bits = 64 if b.arch in ("x64", "arm64", "riscv64", "mips64", "ppc64") else 32
    b.endian = "big" if b.arch in ("ppc",) else "little"
    image = bytearray()
    runs = []                                    # (address, length) of contiguous data
    for a in sorted(mem):
        if runs and a == runs[-1][0] + runs[-1][1]:
            runs[-1] = (runs[-1][0], runs[-1][1] + 1)
        else:
            runs.append((a, 1))
    for k, (a, n) in enumerate(runs):
        off = len(image)
        image += bytes(mem[a + i] for i in range(n))
        b.sections.append(Section(f".data{k}" if len(runs) > 1 else ".flash", a, n, off, True, True, True))
        b.segments.append(Segment(a, n, off, n, True, True, True))
    b.data = bytes(image)
    b.base = runs[0][0]
    if entry is None and b.arch == "arm" and len(image) >= 8:
        # a Cortex-M vector table: initial stack pointer, then the reset handler (Thumb)
        reset = int.from_bytes(image[4:8], "little")
        if reset & 1 and any(a <= (reset & ~1) < a + n for a, n in runs):
            entry = reset
    if b.arch == "arm" and entry is not None and entry & 1:
        entry &= ~1
        b.thumb_code.add(entry)
    b.entry = entry if entry is not None else runs[0][0]
    b.add_symbol(Symbol("start" if entry is None else "reset", b.entry, 0, "func", "synthetic"))
    b.info["records"] = f"{len(mem)} bytes in {len(runs)} run(s)"
    b._finalize()
    return b


__all__ = ["is_ihex", "is_srec", "load_firmware"]

"""A local debugging session: gdb (MI) underneath, Relic's view of the binary on top.

- the program runs on a pseudo-terminal, so its output and input go through
  `read_output()` / `send_input()` (a GUI console) instead of gdb's own tty;
- addresses translate between the static image Relic analysed and the running
  process: for a PIE the load base comes from the process mappings, and
  `slide` turns a static address into a live one (`to_live`) and back
  (`to_static`), so breakpoints, names and the decompiler line up;
- registers, memory, mappings and frames come back as plain Python values;
  `telescope()` follows pointer chains pwndbg-style.
"""
from __future__ import annotations

import os
import re
import termios
import threading
from dataclasses import dataclass, field

from .mi import GdbMI, MIError

# general-purpose registers shown first, per gdb architecture name prefix
_GPRS = {
    "i386:x86-64": ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
                    "r15", "rbp", "rsp", "rip", "eflags"],
    "i386": ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp", "eip", "eflags"],
    "aarch64": [f"x{k}" for k in range(31)] + ["sp", "pc", "cpsr"],
    "arm": [f"r{k}" for k in range(13)] + ["sp", "lr", "pc", "cpsr"],
}
_PC = {"i386:x86-64": "rip", "i386": "eip", "aarch64": "pc", "arm": "pc"}
_SP = {"i386:x86-64": "rsp", "i386": "esp", "aarch64": "sp", "arm": "sp"}


@dataclass
class Mapping:
    start: int
    end: int
    perms: str
    offset: int
    path: str

    @property
    def kind(self) -> str:
        p = self.path
        if p == "[stack]":
            return "stack"
        if p == "[heap]":
            return "heap"
        if "x" in self.perms:
            return "code"
        if p.startswith("["):
            return p.strip("[]")
        return "data" if p else "anon"

    def contains(self, a: int) -> bool:
        return self.start <= a < self.end


@dataclass
class Frame:
    level: int
    addr: int
    func: str


@dataclass
class TeleRow:
    """One stack / memory slot: its address, the chain of values it leads to, and a note."""
    addr: int
    chain: list[int] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)      # mapping kind of each pointer in the chain
    note: str = ""                                      # symbol / string / instruction at the end


class DebugError(Exception):
    pass


class Session:
    """Debug one program locally. Methods block until gdb answers (use a worker thread in a GUI)."""

    def __init__(self, path: str, args: list[str] | None = None, analysis=None, gdb: str | None = None,
                 on_stop=None, on_output=None):
        self.path = os.path.abspath(path)
        self.args = list(args or [])
        self.an = analysis
        self.on_stop = on_stop
        self.on_output = on_output
        self.mi = GdbMI(gdb, on_async=self._async)
        self.arch = ""
        self.word = 8
        self.slide = 0
        self.breakpoints: dict[int, int] = {}       # live address -> gdb breakpoint number
        self.prev_regs: dict[str, int] = {}
        self.regs: dict[str, int] = {}
        self._reg_names: list[str] = []
        self._maps: list[Mapping] | None = None
        self._out: list[bytes] = []
        self._out_lock = threading.Lock()
        self.master, slave = os.openpty()
        # what the program prints arrives as is (no echo of the input, no \n -> \r\n)
        attrs = termios.tcgetattr(slave)
        attrs[1] &= ~termios.ONLCR
        attrs[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        self.tty = os.ttyname(slave)
        self._slave = slave
        self._tty_reader = threading.Thread(target=self._read_tty, daemon=True)
        self._tty_reader.start()
        try:
            self.mi.command(f'-file-exec-and-symbols "{self.path}"')
        except MIError as e:
            self.close()
            raise DebugError(str(e)) from None
        self.mi.command(f"-inferior-tty-set {self.tty}")
        self.mi.console("set confirm off")
        self.mi.console("set pagination off")
        self.mi.console("set disassembly-flavor intel")
        if self.args:
            self.mi.command("-exec-arguments " + " ".join(_quote(a) for a in self.args))

    # ----------------------------------------------------------- program I/O
    def _read_tty(self):
        while True:
            try:
                data = os.read(self.master, 4096)
            except OSError:
                return
            if not data:
                return
            with self._out_lock:
                self._out.append(data)
            if self.on_output:
                self.on_output(data)

    def read_output(self) -> bytes:
        """Program output since the last call."""
        with self._out_lock:
            data = b"".join(self._out)
            self._out.clear()
        return data

    def send_input(self, data: bytes | str):
        if isinstance(data, str):
            data = data.encode()
        os.write(self.master, data)

    # ------------------------------------------------------------- execution
    def _async(self, r):
        if r.kind == "exec" and r.cls == "stopped" and self.on_stop:
            self.on_stop(r)

    @property
    def alive(self) -> bool:
        return not self.mi.exited and bool(self.regs or self.arch)

    def _run_and_wait(self, cmd: str, timeout: float) -> dict:
        self.mi.stopped.clear()
        self.mi.command(cmd)
        r = self.mi.wait_stopped(timeout)
        if r is None:
            raise DebugError("the program is still running (interrupt it)")
        return self._after_stop(r.results)

    def _after_stop(self, stop: dict) -> dict:
        self._maps = None
        reason = stop.get("reason", "")
        if reason.startswith("exited") or self.mi.exited:
            self.regs = {}
            return stop
        frame = stop.get("frame", {})
        if not self.arch:
            self.arch = frame.get("arch", "") or self._arch_from_gdb()
            self.word = 8 if self.arch in ("i386:x86-64", "aarch64") or "64" in self.arch else 4
            self._compute_slide()
        self.prev_regs = self.regs
        self.regs = self.read_registers()
        return stop

    def _arch_from_gdb(self) -> str:
        out = self.mi.console("show architecture")
        m = re.search(r'\(currently "?([\w:.-]+)"?\)', out) or re.search(r'is "?([\w:.-]+)"?', out)
        return m.group(1) if m else ""

    def start(self, stop_at: str = "entry", timeout: float = 30.0) -> dict:
        """Start the program, stopping at its first instruction (`entry`) or at `main`."""
        if stop_at == "main":
            return self._run_and_wait("-exec-run --start", timeout)
        return self._run_and_wait('-interpreter-exec console "starti"', timeout)

    def cont(self, timeout: float = 30.0) -> dict:
        return self._run_and_wait("-exec-continue", timeout)

    def step_into(self, timeout: float = 30.0) -> dict:
        return self._run_and_wait("-exec-step-instruction", timeout)

    def step_over(self, timeout: float = 30.0) -> dict:
        return self._run_and_wait("-exec-next-instruction", timeout)

    def step_out(self, timeout: float = 30.0) -> dict:
        return self._run_and_wait("-exec-finish", timeout)

    def run_to(self, live_addr: int, timeout: float = 30.0) -> dict:
        self.mi.command(f"-break-insert -t *{live_addr:#x}")
        return self.cont(timeout)

    def interrupt(self):
        self.mi.command("-exec-interrupt")

    def kill(self):
        try:
            self.mi.console("kill")
        except MIError:
            pass
        self.regs = {}

    def close(self):
        try:
            self.mi.close()
        finally:
            for fd in (self.master, self._slave):
                try:
                    os.close(fd)
                except OSError:
                    pass

    # ----------------------------------------------------------- breakpoints
    def add_breakpoint(self, live_addr: int) -> int:
        r = self.mi.command(f"-break-insert *{live_addr:#x}")
        n = int(r.results["bkpt"]["number"])
        self.breakpoints[live_addr] = n
        return n

    def remove_breakpoint(self, live_addr: int):
        n = self.breakpoints.pop(live_addr, None)
        if n is not None:
            self.mi.command(f"-break-delete {n}")

    def toggle_breakpoint(self, live_addr: int) -> bool:
        """Set or clear a breakpoint; returns whether one is set now."""
        if live_addr in self.breakpoints:
            self.remove_breakpoint(live_addr)
            return False
        self.add_breakpoint(live_addr)
        return True

    # -------------------------------------------------------------- state
    def read_registers(self) -> dict[str, int]:
        if not self._reg_names:
            r = self.mi.command("-data-list-register-names")
            self._reg_names = r.results.get("register-names", [])
        r = self.mi.command("-data-list-register-values x")
        out = {}
        for item in r.results.get("register-values", []):
            k = int(item["number"])
            if k < len(self._reg_names) and self._reg_names[k]:
                try:
                    out[self._reg_names[k]] = int(item["value"], 16)
                except (ValueError, TypeError):
                    pass                        # vector registers come back as structures
        return out

    def gprs(self) -> list[tuple[str, int, bool]]:
        """(name, value, changed since the previous stop) of the general-purpose registers."""
        names = _GPRS.get(self.arch) or [n for n in self._reg_names[:20] if n]
        return [(n, self.regs[n], n in self.prev_regs and self.prev_regs[n] != self.regs[n])
                for n in names if n in self.regs]

    @property
    def pc(self) -> int | None:
        return self.regs.get(_PC.get(self.arch, "pc"))

    @property
    def sp(self) -> int | None:
        return self.regs.get(_SP.get(self.arch, "sp"))

    def read_memory(self, addr: int, size: int) -> bytes | None:
        try:
            r = self.mi.command(f"-data-read-memory-bytes {addr:#x} {size}")
        except MIError:
            return None
        out = bytearray()
        for blk in r.results.get("memory", []):
            begin = int(blk["begin"], 16)
            if begin != addr + len(out):
                break
            out += bytes.fromhex(blk["contents"])
        return bytes(out) if out else None

    def read_word(self, addr: int) -> int | None:
        b = self.read_memory(addr, self.word)
        return int.from_bytes(b, "little") if b and len(b) == self.word else None

    def mappings(self) -> list[Mapping]:
        if self._maps is not None:
            return self._maps
        out = []
        try:
            text = self.mi.console("info proc mappings")
        except MIError:
            return []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4 or not parts[0].startswith("0x"):
                continue
            try:
                start, end = int(parts[0], 16), int(parts[1], 16)
                # gdb 12+: start end size offset perms objfile; older: start end size offset objfile
                if len(parts) >= 5 and re.fullmatch(r"[r-][w-][x-][ps-]", parts[4]):
                    perms, path = parts[4], " ".join(parts[5:])
                else:
                    perms, path = "", " ".join(parts[4:])
                out.append(Mapping(start, end, perms, int(parts[3], 16), path))
            except ValueError:
                continue
        self._maps = out
        return out

    def mapping_at(self, addr: int) -> Mapping | None:
        return next((m for m in self.mappings() if m.contains(addr)), None)

    def backtrace(self) -> list[Frame]:
        try:
            r = self.mi.command("-stack-list-frames 0 64")
        except MIError:
            return []
        out = []
        for item in r.results.get("stack", []):
            fr = item.get("frame", item)
            try:
                out.append(Frame(int(fr["level"]), int(fr["addr"], 16), fr.get("func", "??")))
            except (KeyError, ValueError):
                continue
        return out

    def disassemble(self, live_addr: int, count: int = 12) -> list[tuple[int, str]]:
        """(address, text) of `count` instructions from `live_addr` (gdb's own disassembler)."""
        try:
            r = self.mi.command(f"-data-disassemble -s {live_addr:#x} -e {live_addr + count * 16:#x} -- 0")
        except MIError:
            return []
        out = []
        for ins in r.results.get("asm_insns", [])[:count]:
            out.append((int(ins["address"], 16), ins.get("inst", "")))
        return out

    def evaluate(self, expr: str) -> str:
        r = self.mi.command(f'-data-evaluate-expression "{expr}"')
        return r.results.get("value", "")

    def address_of(self, expr: str) -> int | None:
        """A live address for what the user typed: `0x7ffd...` as is, a name Relic knows
        (`main`, `sub_401136+0x10`) through the slide, else gdb's value (`$rsp+8`, `&buf`)."""
        text = expr.strip()
        if not text:
            return None
        if re.fullmatch(r"(0x)?[0-9a-fA-F]+", text) and (text.startswith("0x") or not text.isalpha()):
            return int(text, 16)
        if self.an is not None and not text.startswith(("$", "&", "*", "(")):
            a = self.an.resolve(text)
            if a is not None:
                return self.to_live(a)
        try:
            v = self.evaluate(text)
        except MIError:
            return None
        m = re.search(r"0x[0-9a-fA-F]+", v)
        if m:
            return int(m.group(), 16)
        try:
            return int(v.split()[0], 0) & ((1 << (8 * self.word)) - 1)
        except (ValueError, IndexError):
            return None

    def execute(self, cli: str) -> str:
        """A raw gdb command (the console panel); returns its output."""
        return self.mi.console(cli)

    # ------------------------------------------------------ static <-> live
    def _compute_slide(self):
        """Load bias of the main executable: live = static + slide."""
        self.slide = 0
        if self.an is None:
            return
        b = self.an.bin
        if getattr(b, "elf_type", "") != "ET_DYN":
            return
        exe = os.path.realpath(self.path)
        maps = [m for m in self.mappings() if m.path and os.path.realpath(m.path) == exe]
        if not maps:
            return
        base_live = min(m.start - m.offset for m in maps)
        loads = [s.addr - s.offset for s in b.segments if getattr(s, "offset", None) is not None]
        base_static = min(loads) if loads else 0
        self.slide = base_live - base_static

    def to_live(self, static_addr: int) -> int:
        return static_addr + self.slide

    def to_static(self, live_addr: int) -> int | None:
        a = live_addr - self.slide
        return a if self.an is not None and self.an.bin.is_mapped(a) else None

    def symbolize(self, live_addr: int) -> str:
        """`func+0x12` for an address of the main executable (Relic's names), else gdb's symbol."""
        s = self.to_static(live_addr)
        if s is not None:
            m = self.mapping_at(live_addr)
            if m is None or os.path.realpath(m.path or "") == os.path.realpath(self.path):
                return self.an.location(s)
        try:
            out = self.mi.console(f"info symbol {live_addr:#x}").strip()
        except MIError:
            return ""
        if not out or out.startswith("No symbol"):
            return ""
        m = re.match(r"(\S+)(?: \+ (\d+))? in section", out)
        if not m:
            return ""
        return m.group(1) + (f"+{int(m.group(2)):#x}" if m.group(2) else "")

    # ---------------------------------------------------------- telescope
    def telescope(self, addr: int | None = None, count: int = 12, depth: int = 4) -> list[TeleRow]:
        """pwndbg's telescope: each word from `addr` (default: the stack pointer), followed
        through pointers into mapped memory, ending in a symbol, a string or a plain value."""
        if addr is None:
            addr = self.sp
        if addr is None:
            return []
        raw = self.read_memory(addr, count * self.word) or b""
        rows = []
        for k in range(len(raw) // self.word):
            a = addr + k * self.word
            v = int.from_bytes(raw[k * self.word:(k + 1) * self.word], "little")
            row = TeleRow(a, [v])
            seen = {a}
            while len(row.chain) <= depth:
                m = self.mapping_at(v)
                if m is None:
                    break
                row.kinds.append(m.kind)
                if "x" in m.perms:
                    row.note = self.symbolize(v)
                    break
                s = self._string_at(v)
                if s is not None:
                    row.note = repr(s)
                    break
                if v in seen:
                    break
                seen.add(v)
                nxt = self.read_word(v)
                if nxt is None:
                    break
                row.chain.append(nxt)
                v = nxt
            rows.append(row)
        return rows

    def _string_at(self, addr: int) -> str | None:
        b = self.read_memory(addr, 64)
        if not b:
            return None
        end = b.find(b"\0")
        s = b[: end if end >= 0 else len(b)]
        if len(s) >= 4 and all(32 <= c < 127 or c in (9, 10, 13) for c in s):
            return s.decode()
        return None


def _quote(a: str) -> str:
    return a if re.fullmatch(r"[\w./:=+-]+", a) else '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"'


__all__ = ["DebugError", "Frame", "Mapping", "Session", "TeleRow"]

"""pwndbg-style local debugging in the GUI: a controller and its context panels.

`DebugController` owns a `relic.debugger.Session` and a worker thread: every
gdb call runs there, and after each stop it gathers a `Snapshot` -- what
pwndbg's `context` prints: registers (changed ones marked), the code at pc,
the stack as a telescope, the backtrace -- and hands it to the GUI through a
signal. The program's own output arrives through `output`.

Panels: `BreakpointsPanel`, `RegistersPanel`, `StackPanel`, `BacktracePanel`, `CodePanel` (gdb's
disassembly at pc, for code outside the analysed binary too), `VmmapPanel`,
`MemoryPanel` (a hexdump at an address or expression) and `ConsolePanel` (program output, a
line to type the program's input, and a gdb command line).
"""
from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field, replace

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QFontMetrics, QTextCursor
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from ..debugger.session import describe_stop, watch_key
from .views import THEME, mono_font

# pwndbg's colours for where a pointer leads
_KIND_COLOR = {"stack": "call", "heap": "mnem", "code": "jump", "data": "ret", "anon": "fg", "vdso": "addr",
               "vvar": "addr"}


@dataclass
class Breakpoint:
    """A breakpoint or watchpoint, kept across runs: at an address of the analysed binary,
    on a gdb location outside it (`puts` in libc), or on memory (`notes`, `*(int *)($rbp-4)`)."""
    addr: int | None = None        # static, for a breakpoint in the analysed binary
    enabled: bool = True
    condition: str = ""
    hits: int = 0
    location: str = ""             # gdb location, for a breakpoint by name outside the binary
    watch: str = ""                # watched expression, for a watchpoint
    access: str = "write"          # watchpoint: write / read / access
    size: int | None = None        # watchpoint: bytes watched at an address (None: a word)

    @property
    def key(self):
        """The static address, the gdb location, or the watch key (`write:notes`)."""
        if self.addr is not None:
            return self.addr
        return self.location or watch_key(self.watch, self.access, self.size)

    @property
    def kind(self) -> str:
        return f"{self.access} watch" if self.watch else "break"

    def describe(self, an=None) -> str:
        if self.watch:
            return f"{self.access} {self.watch}" + (f" ({self.size} bytes)" if self.size else "")
        if self.addr is not None:
            return an.location(self.addr) if an is not None else f"{self.addr:#x}"
        return self.location


@dataclass
class Snapshot:
    running: bool = False
    exited: str = ""                     # "exited normally" / "exited with code N" / "killed"
    reason: str = ""
    stop: str = ""                       # why it stopped, for people: `watchpoint 3 notes: 0 -> 0x4052a0`
    pc: int | None = None                # live
    pc_static: int | None = None         # in the analysed image, when pc is there
    regs: list = field(default_factory=list)        # (name, value, changed, note)
    stack: list = field(default_factory=list)       # TeleRow
    frames: list = field(default_factory=list)      # (level, addr, symbol)
    code: list = field(default_factory=list)        # (addr, text, symbol)
    breakpoints: list = field(default_factory=list)  # Breakpoint
    maps: list = field(default_factory=list)        # Mapping
    heap: object = None                              # debugger.heap.Heap, None: no heap yet
    word: int = 8


class DebugController(QObject):
    """Runs a debug session off the GUI thread; one command at a time."""

    state = Signal(object)        # Snapshot after every stop (or exit)
    output = Signal(bytes)        # program output
    log = Signal(str)             # gdb command output, errors
    busy = Signal(bool)
    memory = Signal(object, bytes, str)  # (live address, bytes read, what it is) for the memory view

    def __init__(self, parent=None):
        super().__init__(parent)
        self.session = None
        self.an = None
        self.path = ""
        self.args: list[str] = []
        self.static_bps: dict[int, Breakpoint] = {}      # in the analysed binary, by static address
        self.other_bps: dict[str, Breakpoint] = {}       # by gdb location / watch key, in insertion order
        self.mem_addr: int | None = None   # the memory view's address (None: follow the stack pointer)
        self.last = Snapshot()
        self._jobs: queue.Queue = queue.Queue()
        self._worker = threading.Thread(target=self._loop, daemon=True)
        self._worker.start()

    # ----------------------------------------------------------- worker
    def _loop(self):
        while True:
            job = self._jobs.get()
            if job is None:
                self._jobs.task_done()
                return
            fn, snapshot = job
            self.busy.emit(True)
            try:
                fn()
                if snapshot:
                    self.last = self._snapshot()
                    self.state.emit(self.last)
                    if self.last.pc is not None and not self.last.exited:
                        self._emit_memory()
            except Exception as e:  # noqa: BLE001 - shown in the console, the GUI stays up
                self.log.emit(f"error: {e}\n")
                if snapshot and self.session is not None:
                    try:
                        self.last = self._snapshot()
                        self.state.emit(self.last)
                    except Exception:  # noqa: BLE001
                        pass
            finally:
                self._jobs.task_done()
                self.busy.emit(False)

    def _submit(self, fn, snapshot: bool = True):
        self._jobs.put((fn, snapshot))

    @property
    def idle(self) -> bool:
        """No command queued or running."""
        return not self._jobs.unfinished_tasks

    def shutdown(self, timeout: float = 5.0):
        self._submit(self._close, snapshot=False)
        self._jobs.put(None)
        self._worker.join(timeout)

    # -------------------------------------------------------- commands
    @property
    def active(self) -> bool:
        return self.session is not None and bool(self.last.pc is not None and not self.last.exited)

    def start(self, path: str, analysis=None, args: list[str] | None = None, stop_at: str = "entry"):
        def go():
            from ..debugger import Session
            self._close()
            self.path, self.an, self.args = path, analysis, list(args or [])
            run = path
            if analysis is not None and analysis.patches:
                # run what the listing shows: the patched image, written next to nothing else
                import os
                import tempfile

                from ..patch import export
                self._tmpdir = tempfile.mkdtemp(prefix="relic-dbg-")
                run = export(analysis.bin, os.path.join(self._tmpdir, os.path.basename(path)))
                n = len(analysis.patches)
                self.log.emit(f"[ debugging the patched image ({n} patch{'es' if n != 1 else ''}): {run} ]\n")
            self.session = Session(run, self.args, analysis, on_output=self.output.emit)
            self.mem_addr = None
            self.session.start(stop_at)
            for bp in sorted(self.static_bps.values(), key=lambda b: b.addr):
                bp.hits = 0
                self.session.add_breakpoint(self.session.to_live(bp.addr), bp.condition, bp.enabled)
            for bp in self.other_bps.values():
                bp.hits = 0
                try:
                    self._apply(bp)
                except Exception as e:  # noqa: BLE001 - e.g. `$rbp-4` before there is a frame
                    self.log.emit(f"{bp.describe()}: {e}\n")
        self._submit(go)

    def _close(self):
        if self.session is not None:
            try:
                self.session.close()
            finally:
                self.session = None
        tmp = getattr(self, "_tmpdir", None)
        if tmp:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
            self._tmpdir = None

    def _run(self, name: str, *args):
        def go():
            if self.session is None:
                raise RuntimeError("no program is being debugged (Debug > Start)")
            getattr(self.session, name)(*args)
        self._submit(go)

    def cont(self):
        self._run("cont", 3600)

    def step_into(self):
        self._run("step_into")

    def step_over(self):
        self._run("step_over")

    def step_out(self):
        self._run("step_out")

    def run_to(self, static_addr: int):
        def go():
            if self.session is None:
                raise RuntimeError("no program is being debugged (Debug > Start)")
            self.session.run_to(self.session.to_live(static_addr), 3600)
        self._submit(go)

    def interrupt(self):
        # not through the queue: the worker is blocked waiting for the stop this causes
        if self.session is not None:
            threading.Thread(target=self.session.interrupt, daemon=True).start()

    def stop(self):
        def go():
            if self.session is not None:
                self.session.kill()
            self._close()
        self._submit(go)

    def toggle_breakpoint(self, static_addr: int) -> bool:
        """Set or clear a breakpoint at an address of the analysed binary (before or while running)."""
        on = static_addr not in self.static_bps
        if on:
            self.static_bps[static_addr] = Breakpoint(static_addr)
        else:
            del self.static_bps[static_addr]

        def go():
            if self.session is not None and self.session.regs:
                live = self.session.to_live(static_addr)
                if on and live not in self.session.breakpoints:
                    self.session.add_breakpoint(live)
                elif not on:
                    self.session.remove_breakpoint(live)
        self._submit(go, snapshot=False)
        return on

    @property
    def breakpoint_list(self) -> list[Breakpoint]:
        """Breakpoints in the binary by address, then the others in the order they were added."""
        return sorted(self.static_bps.values(), key=lambda b: b.addr) + list(self.other_bps.values())

    def _find(self, key) -> Breakpoint | None:
        return self.static_bps.get(key) if isinstance(key, int) else self.other_bps.get(key)

    def _live_key(self, key):
        return self.session.to_live(key) if isinstance(key, int) else key

    def _apply(self, bp: Breakpoint):
        """Set `bp` in the running session (worker thread)."""
        s = self.session
        if bp.watch:
            s.add_watchpoint(bp.watch, bp.access, bp.size, bp.condition, bp.enabled)
        elif bp.addr is not None:
            s.add_breakpoint(s.to_live(bp.addr), bp.condition, bp.enabled)
        else:
            s.add_named_breakpoint(bp.location, bp.condition, bp.enabled)

    def breakpoint_at(self, text: str, analysis=None) -> Breakpoint | None:
        """A breakpoint on what the user typed: a function of the binary (`vuln`, `sub_401136`),
        `name@plt` or an address there stop in the binary; a library function (`puts`, an import
        of the binary) or anything else Relic cannot place is left to gdb (`libc.so.6:system`)."""
        text = text.strip()
        if not text:
            return None
        an = analysis if analysis is not None else self.an
        a = None
        if an is not None:
            imports = {i.name for i in an.bin.imports}
            try:
                if text.endswith("@plt"):
                    a = an.resolve(text[:-4])
                elif text not in imports:
                    a = an.resolve(text)
            except ValueError:                  # `name+junk`: gdb may still know it
                a = None
            if a is not None and not an.bin.is_mapped(a):
                a = None
        if a is not None:
            if a not in self.static_bps:
                self.toggle_breakpoint(a)
            return self.static_bps[a]
        bp = self.other_bps.get(text)
        if bp is not None:
            return bp
        bp = self.other_bps[text] = Breakpoint(location=text)
        self._add_live(bp)
        return bp

    def add_watchpoint(self, expr: str, access: str = "write", size: int | None = None) -> Breakpoint | None:
        """Watch memory: a name or address of the binary (`notes`, `0x404040`, `size` bytes) or a
        gdb expression (`*(int *)($rbp-4)`); kept across runs like breakpoints."""
        expr = expr.strip()
        if not expr:
            return None
        bp = Breakpoint(watch=expr, access=access, size=size)
        if bp.key in self.other_bps:
            return self.other_bps[bp.key]
        self.other_bps[bp.key] = bp
        self._add_live(bp)
        return bp

    def _add_live(self, bp: Breakpoint):
        def go():
            if self.session is not None and self.session.regs:
                try:
                    self._apply(bp)
                except Exception:
                    # gdb refused it (no such function, no free debug register): forget it
                    self.other_bps.pop(bp.key, None)
                    raise
        self._submit(go, snapshot=self.active)

    def remove_breakpoint(self, key):
        """Delete a breakpoint or watchpoint by its `key`."""
        if isinstance(key, int):
            if key in self.static_bps:
                self.toggle_breakpoint(key)
            return
        bp = self.other_bps.pop(key, None)
        if bp is None:
            return

        def go():
            s = self.session
            if s is not None and s.regs:
                if bp.watch:
                    s.remove_watchpoint(key)
                else:
                    s.remove_named_breakpoint(key)
        self._submit(go, snapshot=self.active)

    def set_breakpoint(self, key, enabled: bool | None = None, condition: str | None = None):
        """Enable / disable a breakpoint or watchpoint (by `key`: a static address, a gdb location
        or a watch key) or change its condition (`$rdi == 5`)."""
        bp = self._find(key)
        if bp is None:
            return
        if enabled is not None:
            bp.enabled = enabled
        if condition is not None:
            bp.condition = condition.strip()

        def go():
            s = self.session
            if s is not None and s.regs:
                live = self._live_key(key)
                if enabled is not None:
                    s.set_enabled(live, enabled)
                if condition is not None:
                    s.set_condition(live, bp.condition)
        self._submit(go, snapshot=False)

    def set_register(self, name: str, value: str):
        """Change a register to a number or gdb expression; the panels refresh."""
        def go():
            if self.session is None or not self.session.regs:
                raise RuntimeError("no stopped program to change")
            self.session.set_register(name, value)
        self._submit(go)

    def write_memory(self, where: str | int, data: str | bytes):
        """Write bytes (`41 42`, `"AAAA\\n"`, `0x401136` as a word) at a live address or an
        expression (`$rsp+8`, `notes`); the memory view moves there."""
        def go():
            from ..debugger import parse_bytes
            s = self.session
            if s is None or not s.regs:
                raise RuntimeError("no stopped program to change")
            a = s.address_of(where) if isinstance(where, str) else where
            if a is None:
                raise RuntimeError(f"cannot evaluate {where!r}")
            raw = data if isinstance(data, bytes) else parse_bytes(data, s.word)
            s.write_memory(a, raw)
            self.mem_addr = a
            self.log.emit(f"wrote {len(raw)} bytes at {a:#x}\n")
        self._submit(go)

    def send_input(self, text: str):
        if self.session is not None:
            self.session.send_input(text)

    def view_memory(self, where: str | int | None = None, size: int = 0x100):
        """Read memory for the memory view: at a live address, an expression (`$rsp+8`, `main`,
        `0x7ffd...`), or with None again at the last place (or the stack pointer)."""
        def go():
            s = self.session
            if s is None or not s.regs:
                raise RuntimeError("no stopped program to read memory from")
            if isinstance(where, str):
                a = s.address_of(where)
                if a is None:
                    raise RuntimeError(f"cannot evaluate {where!r}")
                self.mem_addr = a
            elif where is not None:
                self.mem_addr = where
            self._emit_memory(size)
        self._submit(go, snapshot=False)

    def _emit_memory(self, size: int = 0x100):
        s = self.session
        a = self.mem_addr if self.mem_addr is not None else s.sp
        if a is None:
            return
        data = s.read_memory(a, size) or b""
        m = s.mapping_at(a)
        what = s.symbolize(a) if m is not None and "x" in m.perms else (m.path or m.kind if m else "unmapped")
        self.memory.emit(a, data, what)

    def gdb(self, command: str):
        def go():
            if self.session is None:
                raise RuntimeError("no program is being debugged (Debug > Start)")
            self.log.emit(f"gdb> {command}\n{self.session.execute(command)}")
        self._submit(go)

    # -------------------------------------------------------- snapshot
    def _snapshot(self) -> Snapshot:
        s = self.session
        if s is not None and s.regs:
            hits = s.hits_by_number()
            for bp in self.breakpoint_list:
                n = s.number_of(self._live_key(bp.key))
                if n is not None:
                    bp.hits = hits.get(n, bp.hits)
        snap = Snapshot(breakpoints=[replace(b) for b in self.breakpoint_list])
        if s is None:
            snap.exited = "not running"
            return snap
        stop = s.mi.last_stop.results if s.mi.last_stop is not None else {}
        snap.reason = stop.get("reason", "")
        snap.stop = describe_stop(stop) if stop else ""
        if snap.reason.startswith("exited") or s.mi.exited or not s.regs:
            code = stop.get("exit-code")
            snap.exited = f"exited with code {int(code, 8)}" if code else "exited normally"
            if snap.reason.startswith("exited-signalled"):
                snap.exited = f"killed by {stop.get('signal-name', 'a signal')}"
            return snap
        snap.word = s.word
        snap.pc = s.pc
        snap.pc_static = s.to_static(snap.pc) if snap.pc is not None else None
        for name, value, changed in s.gprs():
            note = ""
            m = s.mapping_at(value)
            if m is not None:
                note = s.symbolize(value) if "x" in m.perms else (repr(s._string_at(value))
                                                                   if s._string_at(value) else m.kind)
            snap.regs.append((name, value, changed, note))
        snap.maps = list(s.mappings())
        snap.stack = s.telescope(count=16)
        snap.frames = [(f.level, f.addr, s.symbolize(f.addr)) for f in s.backtrace()]
        if snap.pc is not None:
            snap.code = [(a, t, s.symbolize(a)) for a, t in s.disassemble(snap.pc, 10)]
        try:
            snap.heap = s.heap()
        except Exception as e:  # noqa: BLE001 - a heap that cannot be walked leaves the panel empty
            self.log.emit(f"heap: {e}\n")
        return snap


# ------------------------------------------------------------------ panels
def _setup(t: QTableWidget, headers: list[str]):
    t.setColumnCount(len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.verticalHeader().setVisible(False)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setFont(mono_font())
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    t.verticalHeader().setDefaultSectionSize(QFontMetrics(t.font()).height() + 4)   # dense, like a terminal
    t.setWordWrap(False)
    t.setTextElideMode(Qt.TextElideMode.ElideNone)     # pointer chains scroll instead of ending in "..."


def _item(text: str, color: str | None = None, data=None) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    if color:
        it.setForeground(QColor(color))
    if data is not None:
        it.setData(Qt.ItemDataRole.UserRole, str(data))     # as text: Qt ints stop at 2**63
    return it


def item_value(it: QTableWidgetItem | None) -> int | None:
    """The address / value an item of a debugger panel stands for."""
    v = it.data(Qt.ItemDataRole.UserRole) if it is not None else None
    return int(v) if v is not None else None


def _hex(v: int, word: int) -> str:
    return f"{v:#0{word * 2 + 2}x}"


class RegistersPanel(QTableWidget):
    """General-purpose registers; the context menu (or `E`) edits the selected one."""

    edit_requested = Signal(str, object)   # register name, current value (64-bit: not Qt's int)

    def __init__(self, parent=None):
        super().__init__(parent)
        _setup(self, ["Reg", "Value", ""])
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)

    def selected_register(self) -> tuple[str, int] | None:
        row = self.currentRow()
        name, value = self.item(row, 0), item_value(self.item(row, 1))
        return (name.text(), value) if name is not None and value is not None else None

    def _menu(self, pos):
        from PySide6.QtWidgets import QMenu
        self.setCurrentCell(self.rowAt(pos.y()), 1)
        reg = self.selected_register()
        if reg is None:
            return
        menu = QMenu(self)
        menu.addAction(f"Set {reg[0]}...", lambda: self.edit_requested.emit(*reg))
        menu.exec(self.viewport().mapToGlobal(pos))

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_E and self.selected_register() is not None:
            self.edit_requested.emit(*self.selected_register())
            return
        super().keyPressEvent(e)

    def show_snapshot(self, snap: Snapshot):
        self.setRowCount(len(snap.regs))
        for k, (name, value, changed, note) in enumerate(snap.regs):
            col = THEME["jump"] if changed else None
            self.setItem(k, 0, _item(name, col))
            self.setItem(k, 1, _item(_hex(value, snap.word), col, value))
            self.setItem(k, 2, _item(note, THEME["comment"]))


class StackPanel(QTableWidget):
    """The telescope from the stack pointer: offset, address, the pointer chain."""

    def __init__(self, parent=None):
        super().__init__(parent)
        _setup(self, ["", "Address", "Value"])

    def show_snapshot(self, snap: Snapshot):
        rows = snap.stack
        self.setRowCount(len(rows))
        for k, r in enumerate(rows):
            text = " —▸ ".join(_hex(v, snap.word) for v in r.chain)
            if r.note:
                text += f" ◂— {r.note}"
            kind = r.kinds[0] if r.kinds else ""
            self.setItem(k, 0, _item(f"{k:02}:{k * snap.word:04x}", THEME["addr"]))
            self.setItem(k, 1, _item(_hex(r.addr, snap.word), THEME[_KIND_COLOR.get("stack", "fg")], r.addr))
            self.setItem(k, 2, _item(text, THEME.get(_KIND_COLOR.get(kind, "fg"), THEME["fg"]),
                                     r.chain[0] if r.chain else None))


class BacktracePanel(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        _setup(self, ["#", "Address", "Function"])

    def show_snapshot(self, snap: Snapshot):
        self.setRowCount(len(snap.frames))
        for k, (level, addr, sym) in enumerate(snap.frames):
            self.setItem(k, 0, _item(str(level), THEME["addr"]))
            self.setItem(k, 1, _item(_hex(addr, snap.word), None, addr))
            self.setItem(k, 2, _item(sym or "??", THEME["func"]))


class CodePanel(QPlainTextEdit):
    """gdb's disassembly at pc (works in libraries too, where the listing has nothing)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(mono_font())
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)

    def show_snapshot(self, snap: Snapshot):
        lines = []
        for a, text, sym in snap.code:
            mark = "►" if a == snap.pc else " "
            lines.append(f"{mark} {a:#x} {('<' + sym + '>') if sym else '':24} {text}")
        if snap.exited:
            lines = [f"[ {snap.exited} ]"]
        self.setPlainText("\n".join(lines))


class VmmapPanel(QTableWidget):
    """The process's memory map (pwndbg `vmmap`), coloured by kind; the main binary's rows bold."""

    def __init__(self, parent=None):
        super().__init__(parent)
        _setup(self, ["Start", "End", "Perm", "Size", "Offset", "File"])

    def show_snapshot(self, snap: Snapshot):
        self.setRowCount(len(snap.maps))
        for k, m in enumerate(snap.maps):
            col = THEME.get(_KIND_COLOR.get(m.kind, "fg"), THEME["fg"])
            cells = [_hex(m.start, snap.word), _hex(m.end, snap.word), m.perms, f"{m.end - m.start:#x}",
                     f"{m.offset:#x}", m.path]
            for c, text in enumerate(cells):
                self.setItem(k, c, _item(text, col, m.start))


_STATE_COLOR = {"used": "fg", "free": "ret", "tcache": "call", "top": "addr"}


class HeapPanel(QWidget):
    """The glibc heap (pwndbg `heap` / `tcachebins`): every chunk of `[heap]` with its state,
    and the tcache lists. Double-clicking a chunk or a list entry shows it in the memory view."""

    view = Signal(object)        # live address to show in the memory view (Qt ints are 32-bit)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.label = QLabel("no heap")
        self.chunks = QTableWidget()
        _setup(self.chunks, ["Chunk", "Size", "State", "Flags", "Data"])
        self.bins = QTableWidget()
        _setup(self.bins, ["tcache", "Count", "Entries"])
        for t in (self.chunks, self.bins):
            t.cellDoubleClicked.connect(lambda r, c, t=t: self._clicked(t, r, c))
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.label)
        row = QHBoxLayout()
        row.addWidget(self.chunks, 3)
        row.addWidget(self.bins, 2)
        lay.addLayout(row)

    def _clicked(self, table, r, c):
        it = table.item(r, 0)
        if table is self.bins:
            cell = table.item(r, 2)
            text = cell.text().split(" -> ")[0] if cell is not None else ""
            target = int(text, 16) if text.startswith("0x") else None
        else:
            target = int(it.data(Qt.ItemDataRole.UserRole)) if it is not None else None
        if target is not None:
            self.view.emit(target)

    def show_snapshot(self, snap: Snapshot):
        h = snap.heap
        if h is None:
            self.label.setText("no heap (nothing allocated yet)" if not snap.exited else "")
            self.chunks.setRowCount(0)
            self.bins.setRowCount(0)
            return
        w = snap.word
        free = sum(c.state in ("free", "tcache") for c in h.chunks)
        link = {True: ", safe-linking", False: "", None: ""}[h.safe_linking]
        self.label.setText(f"[heap] {h.start:#x}-{h.end:#x}: {len(h.chunks)} chunks, {free} free{link}"
                           + (f"  ({h.note})" if h.note else ""))
        self.chunks.setRowCount(len(h.chunks))
        for k, c in enumerate(h.chunks):
            col = THEME.get(_STATE_COLOR.get(c.state, "fg"), THEME["fg"])
            text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in c.data)
            cells = [_hex(c.addr, w), f"{c.size:#x}", c.state, c.flag_text(), f"{c.data.hex(' ')}  |{text}|"]
            for col_k, t in enumerate(cells):
                self.chunks.setItem(k, col_k, _item(t, col, c.user))
        self.bins.setRowCount(len(h.tcache))
        for k, b in enumerate(h.tcache):
            chain = " -> ".join(f"{p:#x}" for p in b.entries) + (f"  ({b.broken})" if b.broken else "")
            col = THEME["ret"] if b.broken else None
            for col_k, t in enumerate([f"{b.size:#x}", str(b.count), chain]):
                self.bins.setItem(k, col_k, _item(t, col))


def hexdump(addr: int, data: bytes, width: int = 16) -> str:
    """`addr  00 11 22 ...  |ascii|` lines."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexes = " ".join(f"{b:02x}" for b in chunk)
        half = width // 2 * 3
        if len(chunk) > width // 2:
            hexes = hexes[:half] + " " + hexes[half:]
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{addr + off:#014x}  {hexes:<{width * 3}}  |{text}|")
    return "\n".join(lines)


class MemoryPanel(QWidget):
    """A hexdump of live memory; type an address or expression (`$rsp`, `main`, `$rdi+8`)."""

    goto_expr = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.where = QLineEdit()
        self.where.setPlaceholderText("address / expression ($rsp, $rdi+8, main, 0x7ffd...), Enter to view")
        self.where.setFont(mono_font())
        self.label = QLabel()
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(mono_font())
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.where.returnPressed.connect(self._go)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(QLabel("at"))
        row.addWidget(self.where)
        lay.addLayout(row)
        lay.addWidget(self.label)
        lay.addWidget(self.text)
        self.addr: int | None = None

    def _go(self):
        t = self.where.text().strip()
        if t:
            self.goto_expr.emit(t)

    def show_memory(self, addr: int, data: bytes, what: str):
        self.addr = addr
        self.label.setText(f"{addr:#x}  {what}" + ("" if data else "  (cannot read)"))
        self.text.setPlainText(hexdump(addr, data))


class BreakpointsPanel(QTableWidget):
    """Breakpoints and watchpoints: a check box to enable each, its kind and location, a condition
    to edit, the hit count; `Delete` removes the selected ones."""

    changed = Signal(object, object, object)    # key (Breakpoint.key), enabled or None, condition or None
    removed = Signal(object)                    # key

    def __init__(self, analysis=None, parent=None):
        super().__init__(parent)
        _setup(self, ["On", "Type", "Address", "Location", "Condition", "Hits"])
        self.setEditTriggers(QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed)
        self.an = analysis
        self.keys: list = []                    # Breakpoint.key of each row
        self._filling = False
        self.itemChanged.connect(self._edited)

    def show_breakpoints(self, bps: list):
        self._filling = True
        try:
            self.keys = [b.key for b in bps]
            self.setRowCount(len(bps))
            for k, b in enumerate(bps):
                on = QTableWidgetItem()
                on.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
                on.setCheckState(Qt.CheckState.Checked if b.enabled else Qt.CheckState.Unchecked)
                self.setItem(k, 0, on)
                self.setItem(k, 1, _item(b.kind, THEME["mnem"] if b.watch else THEME["comment"]))
                self.setItem(k, 2, _item(f"{b.addr:#x}" if b.addr is not None else "", THEME["addr"], b.addr))
                self.setItem(k, 3, _item(b.describe(self.an), THEME["func"], b.addr))
                cond = _item(b.condition)
                cond.setFlags(cond.flags() | Qt.ItemFlag.ItemIsEditable)
                self.setItem(k, 4, cond)
                self.setItem(k, 5, _item(str(b.hits)))
        finally:
            self._filling = False

    def show_snapshot(self, snap: Snapshot):
        self.show_breakpoints(snap.breakpoints)

    def _edited(self, it: QTableWidgetItem):
        if self._filling or not 0 <= it.row() < len(self.keys):
            return
        key = self.keys[it.row()]
        if it.column() == 0:
            self.changed.emit(key, it.checkState() == Qt.CheckState.Checked, None)
        elif it.column() == 4:
            self.changed.emit(key, None, it.text())

    def keyPressEvent(self, e):
        editing = self.state() == QAbstractItemView.State.EditingState
        if e.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace) and not editing:
            for row in sorted({ix.row() for ix in self.selectedIndexes()}, reverse=True):
                if row < len(self.keys):
                    self.removed.emit(self.keys[row])
            return
        super().keyPressEvent(e)


class ConsolePanel(QWidget):
    """Program output, the program's stdin, and a gdb command line."""

    stdin_line = Signal(str)
    gdb_line = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(mono_font())
        self.out.setMaximumBlockCount(5000)
        self.stdin = QLineEdit()
        self.stdin.setPlaceholderText("input to the program (Enter sends the line + \\n)")
        self.stdin.setFont(mono_font())
        self.cmd = QLineEdit()
        self.cmd.setPlaceholderText("gdb command (x/8gx $rsp, info proc mappings, ...)")
        self.cmd.setFont(mono_font())
        self.stdin.returnPressed.connect(self._send_stdin)
        self.cmd.returnPressed.connect(self._send_cmd)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.out)
        row = QHBoxLayout()
        row.addWidget(QLabel("stdin"))
        row.addWidget(self.stdin)
        lay.addLayout(row)
        row = QHBoxLayout()
        row.addWidget(QLabel("gdb>"))
        row.addWidget(self.cmd)
        lay.addLayout(row)

    def append(self, text: str):
        cur = self.out.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.insertText(text)
        self.out.setTextCursor(cur)
        self.out.ensureCursorVisible()

    def _send_stdin(self):
        line = self.stdin.text()
        self.stdin.clear()
        self.stdin_line.emit(line + "\n")

    def _send_cmd(self):
        line = self.cmd.text().strip()
        self.cmd.clear()
        if line:
            self.gdb_line.emit(line)


__all__ = ["Breakpoint", "BreakpointsPanel", "BacktracePanel", "CodePanel", "ConsolePanel", "DebugController",
           "HeapPanel", "MemoryPanel", "RegistersPanel", "Snapshot", "StackPanel", "VmmapPanel", "hexdump",
           "item_value"]

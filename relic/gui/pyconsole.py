"""The GUI's Python console: an interpreter over the scripting namespace (`relic.scripting`)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QVBoxLayout, QWidget

from ..scripting import Console
from .views import mono_font

BANNER = ("Relic Python console: an, bin, here(), goto(x), name(a), rename(a, n), comment(a, t), func(),\n"
          "functions(), xrefs_to(a), disasm(a, n), decompile(f), search('48 8b ??'), patch(a, b'..'),\n"
          "nop(a), invert(a), assemble(a, 'ret'), revert(a), save()\n")


class _Input(QLineEdit):
    """A line with history (Up / Down)."""

    def __init__(self, panel: "PythonConsole"):
        super().__init__()
        self.panel = panel
        self.history: list[str] = []
        self.pos = 0

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down) and self.history:
            self.pos = max(0, self.pos - 1) if e.key() == Qt.Key.Key_Up else min(len(self.history), self.pos + 1)
            self.setText(self.history[self.pos] if self.pos < len(self.history) else "")
            return
        super().keyPressEvent(e)


class PythonConsole(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(mono_font())
        self.out.setMaximumBlockCount(10000)
        self.prompt = QLabel(">>>")
        self.prompt.setFont(mono_font())
        self.line = _Input(self)
        self.line.setFont(mono_font())
        self.line.setPlaceholderText("Python (an, here(), decompile(), ...): Enter runs, Up/Down history")
        self.line.returnPressed.connect(self._enter)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.out)
        row = QHBoxLayout()
        row.addWidget(self.prompt)
        row.addWidget(self.line)
        lay.addLayout(row)
        self.console: Console | None = None
        self.append(BANNER)

    def restyle(self):
        for w in (self.out, self.prompt, self.line):
            w.setFont(mono_font())

    def set_namespace(self, ns: dict):
        """Bind to an analysis: a fresh namespace, variables of an earlier session kept."""
        if self.console is None:
            self.console = Console(ns)
        else:
            self.console.interp.locals.update(ns)

    def append(self, text: str):
        cur = self.out.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        cur.insertText(text)
        self.out.setTextCursor(cur)
        self.out.ensureCursorVisible()

    def run(self, line: str) -> str:
        """Run a line as if typed; returns its output."""
        if self.console is None:
            self.append("(open a binary first)\n")
            return ""
        self.append(f"{self.console.prompt}{line}\n")
        out = self.console.push(line)
        self.append(out)
        self.prompt.setText(self.console.prompt.strip())
        return out

    def _enter(self):
        line = self.line.text()
        self.line.clear()
        if line.strip():
            self.line.history.append(line)
        self.line.pos = len(self.line.history)
        self.run(line)


__all__ = ["PythonConsole"]

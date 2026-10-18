"""Debug > Target: where the program runs -- here under gdb, under qemu-user (a program of
another architecture), under wine with Windows' gdbserver.exe (a Windows program), on a
gdbserver, or a process already running (attach) -- and how it starts (environment, working
directory, a file for its input)."""
from __future__ import annotations

from PySide6.QtWidgets import (QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLineEdit, QPlainTextEdit,
                               QSpinBox)

KINDS = [("auto", "Automatic (here, under QEMU for another architecture, under wine for Windows)"),
         ("local", "This machine (gdb)"), ("qemu", "QEMU user mode (gdb stub)"),
         ("wine", "Wine with Windows' gdbserver.exe"), ("remote", "Remote gdbserver (host:port)"),
         ("attach", "Attach to a running process")]


class TargetDialog(QDialog):
    def __init__(self, parent, target=None):
        super().__init__(parent)
        self.setWindowTitle("Debugger target")
        self.resize(520, 360)
        self.kind = QComboBox()
        for key, text in KINDS:
            self.kind.addItem(text, key)
        self.address = QLineEdit()
        self.address.setPlaceholderText("localhost:1234")
        self.pid = QSpinBox()
        self.pid.setRange(0, 1 << 30)
        self.env = QPlainTextEdit()
        self.env.setPlaceholderText("NAME=value, one per line")
        self.cwd = QLineEdit()
        self.stdin = QLineEdit()
        self.stdin.setPlaceholderText("a file to read the program's input from")
        self.sysroot = QLineEdit()
        self.sysroot.setPlaceholderText("where the target's libraries are (default: the cross toolchain's)")
        form = QFormLayout(self)
        for label, w in (("Run", self.kind), ("gdbserver address", self.address), ("Process ID", self.pid),
                         ("Environment", self.env), ("Working directory", self.cwd), ("Input file", self.stdin),
                         ("Sysroot", self.sysroot)):
            form.addRow(label, w)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        self.kind.currentIndexChanged.connect(self._enable)
        if target is not None:
            self.set_target(target)
        self._enable()

    def _enable(self):
        k = self.kind.currentData()
        self.address.setEnabled(k == "remote")
        self.pid.setEnabled(k == "attach")
        starts = k in ("auto", "local", "qemu", "wine")
        for w in (self.env, self.cwd, self.stdin):
            w.setEnabled(starts)
        self.sysroot.setEnabled(k in ("auto", "qemu", "remote"))

    def set_target(self, t):
        self.kind.setCurrentIndex(next(i for i, (key, _) in enumerate(KINDS) if key == (t.kind if t else "auto")))
        if t is None:
            return
        self.address.setText(t.address)
        self.pid.setValue(t.pid)
        self.env.setPlainText("\n".join(f"{k}={v}" for k, v in t.env.items()))
        self.cwd.setText(t.cwd)
        self.stdin.setText(t.stdin)
        self.sysroot.setText(t.sysroot)

    def target(self):
        """The target chosen (None: automatic -- decided by the binary's architecture), with
        its environment, directory, input file and sysroot."""
        from ..debugger import Target
        env = {}
        for line in self.env.toPlainText().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k.strip():
                    env[k.strip()] = v
        k = self.kind.currentData()
        t = Target("local" if k == "auto" else k, self.address.text().strip(), self.pid.value(), env,
                   self.cwd.text().strip(), self.stdin.text().strip(), self.sysroot.text().strip())
        if k == "auto":
            t.kind = "auto"
        return t

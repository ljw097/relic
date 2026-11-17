"""The compare window (File > Compare with older build): `relic diff` in the GUI. The functions
an earlier build has in common with this one, the ones that changed first, and the ones added
and removed; a function's diff (instructions, or pseudocode); double-click goes to it here."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton,
                               QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout)

from .views import mono_font

ROLE = Qt.ItemDataRole.UserRole


class _DiffColors(QSyntaxHighlighter):
    """Removed lines red, added lines green, hunk headers dimmed."""

    def highlightBlock(self, text: str):
        if text.startswith(("---", "+++")):
            return
        color = {"-": "#c0392b", "+": "#2e8b57", "@": "#7f8c8d"}.get(text[:1])
        if color:
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            self.setFormat(0, len(text), fmt)


class CompareDialog(QDialog):
    def __init__(self, win, diff):
        super().__init__(win)
        self.win, self.diff = win, diff
        self.setWindowTitle(f"Compare with {os.path.basename(diff.old.bin.path)}")
        self.resize(900, 640)
        s = diff.summary()
        self.summary = QLabel(f"{os.path.basename(diff.old.bin.path)} -> {os.path.basename(diff.new.bin.path)}: "
                              f"{len(diff.matches)} matched ({s['identical']} identical, {s['changed']} changed), "
                              f"{s['added']} added, {s['removed']} removed")
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Function", "Similar", "Old", "New", "Matched by"])
        self.tree.setColumnWidth(0, 300)
        self.tree.itemSelectionChanged.connect(self.show_diff)
        self.tree.itemDoubleClicked.connect(self.go)
        self.pseudo = QCheckBox("Pseudocode")
        self.pseudo.toggled.connect(self.show_diff)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(mono_font())
        self._colors = _DiffColors(self.text.document())
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.tree)
        split.addWidget(self.text)
        split.setSizes([300, 340])
        buttons = QHBoxLayout()
        buttons.addWidget(self.pseudo)
        buttons.addStretch(1)
        port = QPushButton("Port annotations")
        port.setToolTip("Names, comments and variable names of the older build onto the matching functions here")
        port.clicked.connect(self.port)
        buttons.addWidget(port)
        lay = QVBoxLayout(self)
        lay.addWidget(self.summary)
        lay.addWidget(split)
        lay.addLayout(buttons)
        self.fill()

    def name_of(self, m) -> str:
        """A matched function's name: a real one of either side (a stripped build's `sub_...`
        last), as named now -- after a port too."""
        from ..analysis.bindiff import real_name
        d = self.diff
        return real_name(d.new, m.new) or real_name(d.old, m.old) or d.new.name(m.new) or m.name

    def fill(self):
        d = self.diff
        self.tree.clear()
        same = [m for m in d.matches if m.identical]
        groups = (("Changed", d.changed(), True), ("Added", d.added, True), ("Removed", d.removed, True),
                  ("Identical", sorted(same, key=lambda m: m.new), False))
        self.groups = {}
        for title, rows, expand in groups:
            top = QTreeWidgetItem(self.tree, [f"{title} ({len(rows)})"])
            top.setFlags(top.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.groups[title] = top
            for r in rows:
                if isinstance(r, int):              # (added / removed: an address on one side)
                    an = d.new if title == "Added" else d.old
                    cols = [an.name(r) or f"sub_{r:x}", "", "" if title == "Added" else f"{r:x}",
                            f"{r:x}" if title == "Added" else "", f"{an.functions[r].size} bytes"]
                    data = ("new" if title == "Added" else "old", r)
                else:
                    cols = [self.name_of(r), f"{r.similarity:.1%}", f"{r.old:x}", f"{r.new:x}", r.how]
                    data = ("match", r)
                it = QTreeWidgetItem(top, cols)
                it.setData(0, ROLE, data)
            top.setExpanded(expand)
        first = self.groups["Changed"].child(0)
        if first is not None:
            self.tree.setCurrentItem(first)

    def current(self):
        it = self.tree.currentItem()
        return it.data(0, ROLE) if it is not None else None

    def show_diff(self):
        from ..analysis.bindiff import function_diff
        from ..decompiler.emit import decompile
        data = self.current()
        if data is None:
            self.text.setPlainText("")
            return
        kind, x = data
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            if kind == "match":
                lines = function_diff(self.diff, x, self.pseudo.isChecked())
                head = f"{self.name_of(x)}: {x.old:#x} -> {x.new:#x}, {x.similarity:.0%} alike (matched by {x.how})"
                self.text.setPlainText(head + "\n" + ("\n".join(lines) if lines else "(the same code)"))
                return
            an = self.diff.new if kind == "new" else self.diff.old
            f = an.functions[x]
            sign = "+" if kind == "new" else "-"
            if self.pseudo.isChecked():
                try:
                    body = decompile(an, f).text.splitlines()
                except Exception as e:  # noqa: BLE001 - shown instead of the pseudocode
                    body = [f"// not decompiled ({type(e).__name__}: {e})"]
            else:
                body = [f"{i.addr:x}  {i.mnemonic} {i.op_str}" for b in sorted(f.blocks) for i in f.blocks[b].insns]
            what = "only in the new build" if kind == "new" else "only in the old build"
            self.text.setPlainText(f"{an.name(x) or f'sub_{x:x}'} @ {x:#x}: {what}\n"
                                   + "\n".join(sign + ln for ln in body))
        finally:
            QApplication.restoreOverrideCursor()

    def go(self, item=None, _col=0):
        """Go to the function in this build (a removed one has no place here)."""
        data = item.data(0, ROLE) if item is not None else self.current()
        if data is None:
            return False
        kind, x = data
        addr = x.new if kind == "match" else x if kind == "new" else None
        return addr is not None and self.win.goto(addr)

    def port(self):
        got = self.win._ported(self.diff)
        if got is not None:
            self.fill()
        return got

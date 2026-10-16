"""The version history window (File > History): commit the annotations with a message, see
what changed between versions, put an older version back."""
from __future__ import annotations

from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QInputDialog, QPlainTextEdit, QPushButton,
                               QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout)
from PySide6.QtCore import Qt

from .views import mono_font


def diff_text(changes: list) -> str:
    from ..analysis.project import summary_of_diff
    lines = []
    for sec, key, old, new in changes:
        sign = "+" if old is None else "-" if new is None else "~"
        what = repr(new) if old is None else repr(old) if new is None else f"{old!r} -> {new!r}"
        lines.append(f"{sign} {sec:<10} {key}: {what}")
    lines.append(summary_of_diff(changes))
    return "\n".join(lines)


class HistoryDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("History")
        self.resize(760, 520)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Version", "Time", "Author", "Message", "Contents"])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.itemSelectionChanged.connect(self.show_diff)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(mono_font())
        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self.tree)
        split.addWidget(self.text)
        buttons = QHBoxLayout()
        for label, slot in (("Commit...", self.commit), ("Checkout", self.checkout)):
            b = QPushButton(label)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        buttons.addStretch(1)
        lay = QVBoxLayout(self)
        lay.addWidget(split)
        lay.addLayout(buttons)
        self.refresh()

    @property
    def an(self):
        return self.win.an

    def refresh(self):
        from ..analysis.project import summary
        self.tree.clear()
        if self.an is None:
            return
        for v in reversed(self.an.history):
            it = QTreeWidgetItem(self.tree, [str(v["id"]), v["time"], v["author"], v["message"], summary(v["notes"])])
            it.setData(0, Qt.ItemDataRole.UserRole, v["id"])
        self.show_diff()

    def selected(self) -> list[int]:
        return sorted(it.data(0, Qt.ItemDataRole.UserRole) for it in self.tree.selectedItems())

    def show_diff(self):
        """One version selected: what changed since it; two: from the older to the newer;
        none: since the latest version."""
        if self.an is None:
            return
        sel = self.selected()
        try:
            if len(sel) >= 2:
                head, changes = f"version {sel[0]} -> {sel[-1]}", self.an.diff_versions(sel[0], sel[-1])
            elif sel:
                head, changes = f"version {sel[0]} -> now", self.an.diff_versions(sel[0])
            else:
                head = f"version {self.an.history[-1]['id']} -> now" if self.an.history else "no versions yet -> now"
                changes = self.an.diff_versions()
        except KeyError as e:
            self.text.setPlainText(str(e))
            return
        self.text.setPlainText(head + "\n\n" + diff_text(changes))

    def commit(self, message: str | None = None):
        if self.an is None:
            return None
        if message is None:
            message, ok = QInputDialog.getText(self, "Commit", "What this version is:")
            if not ok:
                return None
        try:
            v = self.an.commit(message)
        except ValueError as e:
            self.win.statusBar().showMessage(str(e), 4000)
            return None
        self.win._mark_dirty()
        self.refresh()
        return v

    def checkout(self):
        sel = self.selected()
        if len(sel) != 1 or self.an is None:
            self.win.statusBar().showMessage("select one version to check out", 4000)
            return
        self.an.checkout(sel[0])
        self.win._after_edit()
        self.win.statusBar().showMessage(f"checked out version {sel[0]} (Ctrl+Z undoes it)", 6000)
        self.refresh()

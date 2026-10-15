"""The snapshots window (File > Snapshots): named copies of the annotations to go back to."""
from __future__ import annotations

from PySide6.QtWidgets import (QDialog, QHBoxLayout, QInputDialog, QMessageBox, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout)


class SnapshotsDialog(QDialog):
    """Take a snapshot of every name, comment, type, struct and bookmark; restore one (one undo
    step) or delete it. Snapshots are saved with the project."""

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Snapshots")
        self.resize(560, 320)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Taken", "Contents"])
        self.tree.setRootIsDecorated(False)
        self.tree.setColumnWidth(0, 160)
        self.tree.setColumnWidth(1, 150)
        self.tree.itemDoubleClicked.connect(lambda *_: self.restore())
        buttons = QHBoxLayout()
        for text, slot in (("Take...", self.take), ("Restore", self.restore), ("Delete", self.delete)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        buttons.addStretch(1)
        lay = QVBoxLayout(self)
        lay.addWidget(self.tree)
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
        for name, snap in self.an.snapshots.items():
            QTreeWidgetItem(self.tree, [name, snap["time"], summary(snap["notes"])])

    def selected(self) -> str | None:
        it = self.tree.currentItem()
        return it.text(0) if it is not None else None

    def take(self, name: str | None = None):
        if self.an is None:
            return
        if not name:
            name, ok = QInputDialog.getText(self, "Snapshot", "Name:", text=f"snapshot {len(self.an.snapshots) + 1}")
            if not ok or not name.strip():
                return
        if name.strip() in self.an.snapshots and QMessageBox.question(
                self, "Snapshot", f"Replace snapshot '{name.strip()}'?") != QMessageBox.StandardButton.Yes:
            return
        self.an.take_snapshot(name)
        self.win._mark_dirty()
        self.refresh()

    def restore(self):
        name = self.selected()
        if name is None or self.an is None:
            return
        self.an.restore_snapshot(name)            # (undoable: the current annotations are kept)
        self.win._after_edit()
        self.win.statusBar().showMessage(f"restored snapshot '{name}' (Ctrl+Z undoes it)", 6000)

    def delete(self):
        name = self.selected()
        if name is None or self.an is None:
            return
        if QMessageBox.question(self, "Snapshots", f"Delete snapshot '{name}'?") != QMessageBox.StandardButton.Yes:
            return
        self.an.delete_snapshot(name)
        self.win._mark_dirty()
        self.refresh()

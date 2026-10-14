"""The structures window: recovered structs, their fields, and editing them by hand."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                               QListWidget, QListWidgetItem, QMessageBox, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout)

from ..decompiler.vartypes import int_type
from .views import mono_font


class StructsDialog(QDialog):
    """Structs recovered so far (and those the project remembers): rename a struct, rename or
    retype a field in place, add a field (`int`, `char *`, `char[16]` at an offset), remove one.
    Every change goes through the main window, so the pseudocode follows."""

    COLS = ["Offset", "Name", "Type", "Size"]

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("Structures")
        self.resize(760, 420)
        self.list = QListWidget()
        self.list.setFont(mono_font())
        self.table = QTableWidget(0, len(self.COLS))
        self.table.setHorizontalHeaderLabels(self.COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(mono_font())
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.decl = QLabel()
        self.decl.setFont(mono_font())
        self.decl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        buttons = QHBoxLayout()
        for text, slot in (("Rename struct...", self.rename_struct), ("Add field...", self.add_field),
                           ("Remove field", self.remove_field), ("Refresh", self.refresh)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        right = QVBoxLayout()
        right.addWidget(self.table, 2)
        right.addWidget(self.decl, 1)
        right.addLayout(buttons)
        lay = QHBoxLayout(self)
        lay.addWidget(self.list, 1)
        lay.addLayout(right, 3)
        self.structs = []
        self._filling = False
        self.list.currentRowChanged.connect(self._show)
        self.table.itemChanged.connect(self._edited)
        self.refresh()

    # ------------------------------------------------------------- data
    @property
    def an(self):
        return self.win.an

    def shown(self, st) -> str:
        return self.an.struct_names.get(st.name, {}).get("name") or st.name

    def refresh(self):
        from ..decompiler.structs import known_structs
        cur = self.current()
        self.structs = known_structs(self.an, self.an.bin.bits) if self.an is not None else []
        self.list.clear()
        for st in self.structs:
            item = QListWidgetItem(f"{self.shown(st)}  ({st.size} bytes)")
            item.setData(Qt.ItemDataRole.UserRole, st.name)
            self.list.addItem(item)
        if not self.structs:
            self.decl.setText("No structs yet: decompile functions that use one (they are recovered\n"
                              "from fixed-offset accesses), or apply `struct NAME *` with Y.")
        names = [st.name for st in self.structs]
        self.list.setCurrentRow(names.index(cur.name) if cur is not None and cur.name in names else 0)

    def current(self):
        row = self.list.currentRow()
        return self.structs[row] if 0 <= row < len(self.structs) else None

    def _show(self, _row=None):
        st = self.current()
        self._filling = True
        try:
            self.table.setRowCount(0)
            if st is None:
                return
            d = self.an.struct_names.get(st.name, {})
            for off in sorted(st.fields):
                f = st.fields[off]
                name = d.get("fields", {}).get(f.name, f.name)
                t = d.get("types", {}).get(f.name) or f.ctype or int_type(f.bits)
                if f.array:
                    t += f"[{f.count if f.count is not None else ''}]"
                r = self.table.rowCount()
                self.table.insertRow(r)
                cells = [f"{off:#x}", name, t, str(f.end - f.offset)]
                for c, text in enumerate(cells):
                    it = QTableWidgetItem(text)
                    it.setData(Qt.ItemDataRole.UserRole, off)
                    if c not in (1, 2):
                        it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.table.setItem(r, c, it)
            self.decl.setText("\n".join(st.declaration(
                lambda s: self.shown(s),
                lambda f: d.get("fields", {}).get(f.name, f.name),
                lambda f: d.get("types", {}).get(f.name))))
        finally:
            self._filling = False

    # ------------------------------------------------------------- edits
    def _edited(self, it: QTableWidgetItem):
        if self._filling:
            return
        st = self.current()
        if st is None:
            return
        off = it.data(Qt.ItemDataRole.UserRole)
        f = st.fields.get(off)
        if f is None:
            return
        text = it.text().strip()
        ok = True
        if it.column() == 1:
            ok = self.win.rename_struct(st.name, f.name, "" if text == f.name else text)
        elif it.column() == 2:
            if "[" in text:                           # an array: its layout changes
                ok = self.edit(lambda: self.an.add_field(st.name, off, text))
            else:
                ok = self.win.set_field_type(st.name, f.name, text)
        if not ok:
            QMessageBox.warning(self, "Structures", self.win.statusBar().currentMessage() or "not changed")
        self.refresh()

    def edit(self, change) -> bool:
        try:
            change()
        except ValueError as e:
            self.win.statusBar().showMessage(str(e), 5000)
            return False
        self.win._after_edit()
        return True

    def rename_struct(self):
        st = self.current()
        if st is None:
            return
        text, ok = QInputDialog.getText(self, "Rename struct", f"Name for {st.name} (empty to reset):",
                                        text=self.shown(st))
        if ok:
            self.win.rename_struct(st.name, None, text.strip())
            self.refresh()

    def add_field(self):
        st = self.current()
        if st is None:
            return
        text, ok = QInputDialog.getText(self, "Add field", "offset type [name]  (0x18 char *name, 0x20 int[4]):")
        if not ok or not text.strip():
            return
        parts = text.split()
        try:
            off = int(parts[0], 0)
        except ValueError:
            QMessageBox.warning(self, "Structures", f"bad offset {parts[0]!r}")
            return
        rest = parts[1:]
        name = ""
        if len(rest) >= 2 and rest[-1].replace("_", "a").isalnum() and not rest[-1].endswith(("*", "]")):
            name = rest.pop()                          # `0x18 char * name`, `0x18 int count`
        if not self.edit(lambda: self.an.add_field(st.name, off, " ".join(rest), name)):
            QMessageBox.warning(self, "Structures", self.win.statusBar().currentMessage())
        self.refresh()

    def remove_field(self):
        st = self.current()
        rows = sorted({i.row() for i in self.table.selectedIndexes()})
        if st is None or not rows:
            return
        for r in rows:
            off = self.table.item(r, 0).data(Qt.ItemDataRole.UserRole)
            self.an.remove_field(st.name, off)
        self.win._after_edit()
        self.refresh()


__all__ = ["StructsDialog"]

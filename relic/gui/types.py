"""The types window: C declarations imported from headers (File > Import C header)."""
from __future__ import annotations

from PySide6.QtWidgets import (QDialog, QHBoxLayout, QMessageBox, QPushButton, QTreeWidget, QTreeWidgetItem,
                               QVBoxLayout)

from .views import mono_font


class TypesDialog(QDialog):
    """Imported enums (with their values), typedefs, structs and function prototypes; import
    another header or forget them all. Changes go through the main window (undo, pseudocode)."""

    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.setWindowTitle("C types")
        self.resize(640, 460)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Definition"])
        self.tree.setFont(mono_font())
        self.tree.setColumnWidth(0, 220)
        buttons = QHBoxLayout()
        for text, slot in (("Import header...", self.import_header), ("Load type library", self.load_library),
                           ("Remove all", self.clear),
                           ("Refresh", self.refresh)):
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
        self.tree.clear()
        an = self.an
        if an is None:
            return
        ut = an.user_types
        enums = QTreeWidgetItem(self.tree, ["enums", ""])
        for name, values in sorted(ut.get("enums", {}).items()):
            it = QTreeWidgetItem(enums, [f"enum {name}", f"{len(values)} values"])
            for k, v in values.items():
                QTreeWidgetItem(it, [k, str(v)])
        typedefs = QTreeWidgetItem(self.tree, ["typedefs", ""])
        for name, t in sorted(ut.get("typedefs", {}).items()):
            QTreeWidgetItem(typedefs, [name, t])
        structs = QTreeWidgetItem(self.tree, ["structs", ""])
        for name, d in sorted(an.struct_names.items()):
            if not d.get("imported"):
                continue
            it = QTreeWidgetItem(structs, [f"struct {name}", f"{len(d.get('layout', {}))} fields"])
            fields = d.get("fields", {})
            types = d.get("types", {})
            for off, entry in sorted(d.get("layout", {}).items(), key=lambda kv: int(kv[0], 16)):
                gen = f"f_{int(off, 16):x}"
                t = types.get(gen) or entry[1] or f"{entry[0]}-bit"
                QTreeWidgetItem(it, [fields.get(gen, gen), f"{off}: {t}"])
        protos = QTreeWidgetItem(self.tree, ["prototypes", ""])
        for name, p in sorted(ut.get("prototypes", {}).items()):
            params = ", ".join(p["params"]) + (", ..." if p.get("variadic") else "")
            QTreeWidgetItem(protos, [name, f"{p['ret']} {name}({params or 'void'})"])
        for top in (enums, typedefs, structs, protos):
            top.setText(1, f"{top.childCount()}")
            top.setExpanded(top.childCount() <= 20)

    def load_library(self):
        """The bundled type library for the binary: the C library's (struct stat, tm,
        sockaddr_in, ...), or for a PE the Windows API's (SYSTEM_INFO, STARTUPINFOA, ...)."""
        if self.an is None:
            return
        from ..decompiler.typelibs import default_library
        name = default_library(self.an.bin.format)
        got = self.an.load_type_library(name)
        self.win._after_edit()
        self.win.statusBar().showMessage(f"{name} types: {len(got['structs'])} structs", 5000)
        self.refresh()

    def import_header(self):
        self.win.header_dialog()
        self.refresh()

    def clear(self):
        if self.an is None:
            return
        if QMessageBox.question(self, "C types", "Forget every imported C declaration?") != \
                QMessageBox.StandardButton.Yes:
            return
        self.an.clear_imported_types()
        self.win._after_edit()
        self.refresh()

"""The library signatures window (File > Library signatures, Shift+F5): the signature sets
there are, which fit the binary, how many functions each named; apply sets, take a set's names
back, add a signature file or static library, build sets from the installed toolchains."""
from __future__ import annotations

import os

from PySide6.QtWidgets import (QAbstractItemView, QDialog, QFileDialog, QHBoxLayout, QLabel, QMessageBox,
                               QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout)

COLUMNS = ["File", "Library", "Version", "Arch", "Format", "Signatures", "For this binary", "Named"]


class SignaturesDialog(QDialog):
    def __init__(self, win):
        super().__init__(win)
        self.win = win
        self.extra: list[str] = []               # files added here (besides the signature directories)
        self.setWindowTitle("Library signatures")
        self.resize(860, 380)
        self.info = QLabel()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setColumnWidth(0, 230)
        self.tree.itemDoubleClicked.connect(lambda *_: self.apply_selected())
        buttons = QHBoxLayout()
        for text, slot in (("Apply", self.apply_selected), ("Remove names", self.remove_selected),
                           ("Add file...", self.add_file), ("Build from toolchains", self.build_system),
                           ("Refresh", self.refresh)):
            b = QPushButton(text)
            b.clicked.connect(slot)
            buttons.addWidget(b)
        buttons.addStretch(1)
        lay = QVBoxLayout(self)
        lay.addWidget(self.info)
        lay.addWidget(self.tree)
        lay.addLayout(buttons)
        self.refresh()

    @property
    def an(self):
        return self.win.an

    def databases(self) -> list:
        """Every signature set: those in the signature directories and those added here."""
        from ..analysis import libsigs
        paths = [os.path.join(d, f) for d in libsigs.sig_dirs() for f in sorted(os.listdir(d)) if f.endswith(".sig")]
        out, seen = [], set()
        for p in paths + self.extra:
            key = os.path.abspath(p)
            if key in seen:
                continue
            seen.add(key)
            try:
                out.append(libsigs.SigDB.load(p))
            except (OSError, ValueError, KeyError):
                continue
        return out

    def refresh(self):
        from ..analysis import libsigs
        self.tree.clear()
        self.dbs = self.databases()
        an = self.an
        fit = set()
        if an is not None:
            tc = an.toolchain
            self.info.setText(f"{os.path.basename(an.bin.path)}: {an.bin.arch} {an.bin.format}; {tc.describe()}; "
                              f"{len(an.lib_names)} functions named by library signatures")
            fit = {id(db) for db in libsigs.select([db for db in self.dbs if db.arch == an.bin.arch], tc,
                                                   an.bin.format)}
        counts: dict[str, int] = {}
        for src in (an.lib_sources.values() if an is not None else ()):
            counts[src] = counts.get(src, 0) + 1
        for db in self.dbs:
            it = QTreeWidgetItem(self.tree, [db.label, db.library or "-", db.version or "-", db.arch, db.format,
                                             str(len(db.sigs)), "yes" if id(db) in fit else "",
                                             str(counts.get(db.label, 0) or "")])
            it.setToolTip(0, db.path or db.source)

    def selected(self) -> list:
        rows = {self.tree.indexOfTopLevelItem(it) for it in self.tree.selectedItems()}
        return [self.dbs[r] for r in sorted(rows) if 0 <= r < len(self.dbs)]

    def apply_selected(self) -> int:
        """Name functions by the selected sets (those for another architecture are left out)."""
        if self.an is None:
            return 0
        dbs = [db for db in self.selected() if db.arch == self.an.bin.arch]
        n = self.win.apply_signature_dbs(dbs)
        self.refresh()
        return n

    def remove_selected(self) -> int:
        """Take back the names the selected sets gave."""
        if self.an is None:
            return 0
        n = sum(self.an.unapply_signatures(db.label) for db in self.selected())
        if n:
            self.win._after_edit()
            self.win._fill_functions()
        self.win.statusBar().showMessage(f"{n} library names taken back", 5000)
        self.refresh()
        return n

    def add_file(self, path: str | None = None):
        """A signature file, or a static library / object file (built into ~/.relic/sigs)."""
        from ..analysis import libsigs
        if not path:
            start = (libsigs.sig_dirs() or [os.path.expanduser("~")])[0]
            path, _ = QFileDialog.getOpenFileName(self, "Add signatures", start,
                                                  "Signatures or static libraries (*.sig *.a *.o *.obj);;All files (*)")
            if not path:
                return None
        try:
            if not path.endswith(".sig"):
                db = libsigs.build([path])
                out = os.path.join(os.path.expanduser("~"), ".relic", "sigs", libsigs.set_name(db))
                db.save(out)
                path = out
            else:
                libsigs.SigDB.load(path)
        except (OSError, ValueError, KeyError) as e:
            QMessageBox.warning(self, "Library signatures", f"{path}: {e}")
            return None
        self.extra.append(path)
        self.refresh()
        return path

    def build_system(self, out_dir: str | None = None) -> int:
        n = self.win.build_system_signatures(out_dir)
        if out_dir:
            self.extra += [os.path.join(out_dir, f) for f in sorted(os.listdir(out_dir)) if f.endswith(".sig")]
        self.refresh()
        return n

"""Main window: function list, central views, info tables and navigation."""
from __future__ import annotations

import os
import traceback

from PySide6.QtCore import QSortFilterProxyModel, Qt, QThread, Signal
from PySide6.QtGui import QAction, QColor, QKeySequence, QPalette, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QDockWidget, QFileDialog, QHeaderView,
                               QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox, QTableView,
                               QTabWidget, QVBoxLayout, QWidget)

from ..analysis import Analysis
from ..analysis.strings import escape
from .views import THEME, DisasmView, GraphView, HexView, PseudocodeView, mono_font

ADDR_ROLE = Qt.ItemDataRole.UserRole + 1


def apply_theme(app: QApplication):
    """Dark Fusion palette matching the view colours."""
    app.setStyle("Fusion")
    p = QPalette()
    bg, base, fg = QColor("#25262b"), QColor(THEME["bg"]), QColor(THEME["fg"])
    for role, c in ((QPalette.ColorRole.Window, bg), (QPalette.ColorRole.WindowText, fg),
                    (QPalette.ColorRole.Base, base), (QPalette.ColorRole.AlternateBase, bg),
                    (QPalette.ColorRole.Text, fg), (QPalette.ColorRole.Button, bg),
                    (QPalette.ColorRole.ButtonText, fg), (QPalette.ColorRole.ToolTipBase, base),
                    (QPalette.ColorRole.ToolTipText, fg), (QPalette.ColorRole.Highlight, QColor("#3b4261")),
                    (QPalette.ColorRole.HighlightedText, QColor("#ffffff")),
                    (QPalette.ColorRole.PlaceholderText, QColor(THEME["addr"]))):
        p.setColor(role, c)
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(THEME["addr"]))
    app.setPalette(p)


class AnalysisThread(QThread):
    """Loads and analyses a binary off the GUI thread."""

    done = Signal(object, object)  # Analysis, extra results
    failed = Signal(str)

    def __init__(self, path: str, arch: str | None, base: int, parent=None):
        super().__init__(parent)
        self.path, self.arch, self.base = path, arch, base

    def run(self):
        try:
            from ..analysis import analyze
            an = analyze(self.path, self.arch, self.base)
            extra = {"checksec": an.checksec()}
            self.done.emit(an, extra)
        except Exception as e:  # noqa: BLE001 - surfaced to the user
            self.failed.emit(f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}")


class VulnsThread(QThread):
    """Runs the pwnable heuristics after the window is up (they may decompile functions)."""

    done = Signal(object)

    def __init__(self, an: Analysis, parent=None):
        super().__init__(parent)
        self.an = an

    def run(self):
        try:
            self.done.emit(self.an.vulns())
        except Exception:  # noqa: BLE001 - an empty table beats a crashed GUI
            self.done.emit([])


class Table(QTableView):
    """Read-only sortable table; double-click emits the row's address."""

    activated_addr = Signal(int)

    def __init__(self, headers: list[str], parent=None):
        super().__init__(parent)
        self.model_ = QStandardItemModel(0, len(headers), self)
        self.model_.setHorizontalHeaderLabels(headers)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model_)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setSortRole(ADDR_ROLE + 1)
        self.setModel(self.proxy)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(20)
        self.horizontalHeader().setStretchLastSection(True)
        self.setFont(mono_font(9))
        self.doubleClicked.connect(self._activated)

    def clear_rows(self):
        self.model_.removeRows(0, self.model_.rowCount())

    def add_row(self, values: list, addr: int | None = None, color: str | None = None):
        items = []
        for v in values:
            it = QStandardItem(f"{v:#x}" if isinstance(v, int) and not isinstance(v, bool) else str(v))
            it.setData(v if isinstance(v, int) else str(v).lower(), ADDR_ROLE + 1)
            if addr is not None:
                it.setData(addr, ADDR_ROLE)
            if color:
                it.setForeground(QColor(color))
            items.append(it)
        self.model_.appendRow(items)

    def fit(self):
        self.resizeColumnsToContents()
        self.sortByColumn(-1, Qt.SortOrder.AscendingOrder)

    def _activated(self, idx):
        a = idx.data(ADDR_ROLE)
        if a is not None:
            self.activated_addr.emit(int(a))


class FilteredTable(QWidget):
    """Table with a filter box on top."""

    def __init__(self, headers: list[str], placeholder: str = "Filter", key_column: int = -1, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        self.filter = QLineEdit(self)
        self.filter.setPlaceholderText(placeholder)
        self.filter.setClearButtonEnabled(True)
        self.table = Table(headers, self)
        self.table.proxy.setFilterKeyColumn(key_column)
        self.filter.textChanged.connect(self.table.proxy.setFilterFixedString)
        lay.addWidget(self.filter)
        lay.addWidget(self.table)


_C_RESERVED = {"if", "else", "while", "do", "for", "switch", "case", "default", "break", "continue", "return",
               "goto", "sizeof", "int", "char", "short", "long", "void", "unsigned", "signed", "struct", "union",
               "enum", "typedef", "const", "static", "extern", "volatile", "float", "double"}


class MainWindow(QMainWindow):
    TAB_DISASM, TAB_GRAPH, TAB_DECOMP, TAB_HEX = range(4)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.an: Analysis | None = None
        self.thread: AnalysisThread | None = None
        self.vulns_thread: VulnsThread | None = None
        self.cur: int | None = None
        self.back: list[int] = []
        self.fwd: list[int] = []
        self.dirty = False
        self.setWindowTitle("Relic")

        self.disasm = DisasmView()
        self.graph = GraphView()
        self.decomp = PseudocodeView()
        self.hex = HexView()
        self.tabs = QTabWidget()
        self.tabs.addTab(self.disasm, "Disassembly")
        self.tabs.addTab(self.graph, "Graph")
        self.tabs.addTab(self.decomp, "Pseudocode")
        self.tabs.addTab(self.hex, "Hex")
        self.tabs.currentChanged.connect(self._tab_changed)
        self.setCentralWidget(self.tabs)
        for v in (self.disasm, self.graph, self.decomp):
            v.navigate.connect(self.goto)
            v.cursor_addr.connect(self._cursor_moved)

        self.funcs = FilteredTable(["Name", "Address", "Size"], "Filter functions", key_column=0)
        self.funcs.table.activated_addr.connect(self.goto)
        self._dock("Functions", self.funcs, Qt.DockWidgetArea.LeftDockWidgetArea)

        self.xrefs = Table(["From", "Type", "Location", "Instruction"])
        self.xrefs.activated_addr.connect(self.goto)
        self.xrefs_dock = self._dock("Xrefs", self.xrefs, Qt.DockWidgetArea.RightDockWidgetArea)

        self.strings = FilteredTable(["Address", "Section", "Encoding", "Value"], "Filter strings")
        self.imports = FilteredTable(["Address", "GOT / IAT", "Name", "Library"], "Filter imports")
        self.vulns = Table(["Severity", "Address", "Function", "Kind", "Message"])
        self.checksec = Table(["Property", "Value"])
        self.info = FilteredTable(["Name", "Address", "Size", "Offset", "Perm"], "Filter sections")
        self.strings.table.activated_addr.connect(self.goto_xref_or_addr)
        self.imports.table.activated_addr.connect(self.goto)
        self.vulns.activated_addr.connect(self.goto)
        self.info.table.activated_addr.connect(self.goto)
        bottom = Qt.DockWidgetArea.BottomDockWidgetArea
        docks = [self._dock(t, w, bottom) for t, w in (("Strings", self.strings), ("Imports", self.imports),
                                                       ("Vulns", self.vulns), ("Checksec", self.checksec),
                                                       ("Sections", self.info))]
        for d in docks[1:]:
            self.tabifyDockWidget(docks[0], d)
        docks[0].raise_()
        self.docks = docks

        self.status = QLabel()
        self.status.setFont(mono_font(9))
        self.statusBar().addPermanentWidget(self.status, 1)
        self._actions()
        self._update_actions()

    # ---------------------------------------------------------------- setup
    def _dock(self, title: str, w: QWidget, area) -> QDockWidget:
        d = QDockWidget(title, self)
        d.setObjectName(title)
        d.setWidget(w)
        self.addDockWidget(area, d)
        return d

    def _actions(self):
        def act(menu, text, shortcut, slot, needs_an=True):
            a = QAction(text, self)
            if shortcut:
                a.setShortcuts([QKeySequence(s) for s in (shortcut if isinstance(shortcut, tuple) else (shortcut,))])
            a.triggered.connect(slot)
            menu.addAction(a)
            if needs_an:
                self._an_actions.append(a)
            return a

        self._an_actions: list[QAction] = []
        mb = self.menuBar()
        m = mb.addMenu("&File")
        act(m, "&Open...", QKeySequence.StandardKey.Open, self.open_dialog, False)
        act(m, "&Save project", QKeySequence.StandardKey.Save, self.save_project)
        m.addSeparator()
        act(m, "&Quit", QKeySequence.StandardKey.Quit, self.close, False)
        m = mb.addMenu("&Navigate")
        act(m, "&Go to address...", "G", self.goto_dialog)
        self.back_act = act(m, "&Back", ("Esc", "Alt+Left"), self.go_back)
        self.fwd_act = act(m, "&Forward", ("Ctrl+Return", "Alt+Right"), self.go_forward)
        m.addSeparator()
        act(m, "Toggle &graph / listing", "Space", self.toggle_graph)
        act(m, "Toggle &pseudocode / listing", ("Tab", "F5"), self.toggle_decompile)
        act(m, "&Hex view", "Ctrl+H", lambda: self.tabs.setCurrentIndex(self.TAB_HEX))
        act(m, "&Functions", "Ctrl+F", self._focus_functions)
        m = mb.addMenu("&Edit")
        act(m, "&Rename...", "N", self.rename_dialog)
        act(m, "&Comment...", ";", self.comment_dialog)
        act(m, "&Xrefs to...", "X", self.show_xrefs_here)
        m = mb.addMenu("&View")
        for d in [self.findChild(QDockWidget, "Functions"), self.xrefs_dock, *self.docks]:
            m.addAction(d.toggleViewAction())
        for a in self.actions():
            a.setShortcutContext(Qt.ShortcutContext.WindowShortcut)

    def _update_actions(self):
        for a in self._an_actions:
            a.setEnabled(self.an is not None)
        self.back_act.setEnabled(self.an is not None and bool(self.back))
        self.fwd_act.setEnabled(self.an is not None and bool(self.fwd))

    # --------------------------------------------------------------- loading
    def open_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open binary")
        if path:
            self.open_file(path)

    def open_file(self, path: str, arch: str | None = None, base: int = 0):
        if not self._confirm_discard():
            return
        if self.thread is not None and self.thread.isRunning():
            self.statusBar().showMessage("analysis already running", 3000)
            return
        self.statusBar().showMessage(f"analysing {path} ...")
        self.setWindowTitle(f"Relic - {os.path.basename(path)} (analysing)")
        self.thread = AnalysisThread(path, arch, base, self)
        self.thread.done.connect(self.set_analysis)
        self.thread.failed.connect(self._failed)
        self.thread.start()

    def wait(self, ms: int = 60000) -> bool:
        """Block until a background analysis (and the vulns scan after it) finishes."""
        ok = True
        if self.thread is not None:
            ok = self.thread.wait(ms)
            QApplication.processEvents()
        if self.vulns_thread is not None:
            ok = self.vulns_thread.wait(ms) and ok
            QApplication.processEvents()
        return ok

    def _failed(self, msg: str):
        self.setWindowTitle("Relic")
        self.statusBar().showMessage("analysis failed", 5000)
        QMessageBox.critical(self, "Relic", msg.split("\n\n", 1)[0])

    def set_analysis(self, an: Analysis, extra: dict | None = None):
        extra = extra or {}
        self.an = an
        self.back.clear()
        self.fwd.clear()
        self.cur = None
        self.dirty = False
        self.disasm.func = self.graph.func = None
        self.setWindowTitle(f"Relic - {os.path.basename(an.bin.path)}  [{an.bin.describe()}]")
        self._fill_functions()
        self._fill_tables(extra.get("checksec") or an.checksec())
        if "vulns" in extra:
            self._fill_vulns(extra["vulns"])
        else:
            self._fill_vulns(None)
            self.vulns_thread = VulnsThread(an, self)
            self.vulns_thread.done.connect(self._fill_vulns)
            self.vulns_thread.start()
        self.statusBar().showMessage(f"{len(an.functions)} functions, {len(an.strings)} strings", 5000)
        main = an.function_by_name("main")
        start = main.addr if main else an.bin.entry
        self._update_actions()
        self.goto(start, record=False)

    def _fill_functions(self):
        t = self.funcs.table
        t.setSortingEnabled(False)
        t.clear_rows()
        an = self.an
        for f in sorted(an.functions.values(), key=lambda f: f.addr):
            color = THEME["addr"] if f.is_import else (THEME["jump"] if f.noreturn else None)
            t.add_row([an.name(f.addr) or f.name, f.addr, f.size], f.addr, color)
        t.setSortingEnabled(True)
        t.fit()

    def _fill_vulns(self, vulns):
        """Fill the Vulns table; None shows that the scan is still running."""
        self.vulns.setSortingEnabled(False)
        self.vulns.clear_rows()
        if vulns is None:
            self.vulns.add_row(["...", "", "", "", "scanning (call arguments are being decompiled)"])
            return
        sev_color = {"high": THEME["jump"], "medium": THEME["label"], "low": THEME["call"]}
        for v in vulns:
            self.vulns.add_row([v.severity, v.addr, v.func, v.kind, v.message], v.addr, sev_color.get(v.severity))
        self.vulns.setSortingEnabled(True)
        self.vulns.fit()

    def _fill_tables(self, checksec: dict):
        an, b = self.an, self.an.bin
        t = self.strings.table
        t.setSortingEnabled(False)
        t.clear_rows()
        for s in an.strings:
            t.add_row([s.addr, s.section, s.encoding, escape(s.value, 200)], s.addr)
        t.setSortingEnabled(True)
        t.fit()

        t = self.imports.table
        t.setSortingEnabled(False)
        t.clear_rows()
        for i in sorted(b.imports, key=lambda i: (i.library, i.name)):
            t.add_row([i.addr, i.got, i.name, i.library], i.addr or i.got or None)
        for e in sorted(b.exports, key=lambda e: e.addr):
            t.add_row([e.addr, 0, e.name, "(export)"], e.addr, THEME["func"])
        t.setSortingEnabled(True)
        t.fit()

        self.checksec.clear_rows()
        for k, v in checksec.items():
            self.checksec.add_row([k, v])
        self.checksec.fit()

        t = self.info.table
        t.setSortingEnabled(False)
        t.clear_rows()
        for s in b.sections:
            t.add_row([s.name, s.addr, s.size, s.offset, s.perms], s.addr if s.addr else None)
        t.setSortingEnabled(True)
        t.fit()

    # ------------------------------------------------------------ navigation
    def goto(self, addr: int, record: bool = True) -> bool:
        an = self.an
        if an is None:
            return False
        if not an.bin.is_mapped(addr) and an.function_at(addr) is None:
            self.statusBar().showMessage(f"{addr:#x} is not mapped", 3000)
            return False
        if record and self.cur is not None and self.cur != addr:
            self.back.append(self.cur)
            del self.back[:-256]
            self.fwd.clear()
        self._show(addr)
        return True

    def _show(self, addr: int):
        an = self.an
        self.cur = addr
        f = an.function_at(addr)
        if f is not None:
            self.disasm.show_function(an, f, addr)
            self.graph.show_function(an, f, addr)
            if self.tabs.currentIndex() == self.TAB_DECOMP:   # decompiled on demand only
                self.decomp.show_function(an, f, addr)
            if self.tabs.currentIndex() == self.TAB_HEX:
                self.tabs.setCurrentIndex(self.TAB_DISASM)
        else:
            self.tabs.setCurrentIndex(self.TAB_HEX)
        self.hex.show_addr(an, addr)
        self._show_status(addr)
        self._update_actions()
        if self.xrefs_dock.isVisible():
            self._fill_xrefs(self._xref_subject(addr))

    def go_back(self):
        if self.back:
            if self.cur is not None:
                self.fwd.append(self.cur)
            self._show(self.back.pop())

    def go_forward(self):
        if self.fwd:
            if self.cur is not None:
                self.back.append(self.cur)
            self._show(self.fwd.pop())

    def goto_xref_or_addr(self, addr: int):
        """Strings: jump to the first code reference if there is one, else the data."""
        refs = self.an.xrefs_to.get(addr) if self.an else None
        self._fill_xrefs(addr)
        self.xrefs_dock.show()
        self.goto(refs[0].frm if refs else addr)

    def goto_dialog(self):
        text, ok = QInputDialog.getText(self, "Go to", "Address or symbol (main, 0x401000, main+0x10):")
        if ok and text.strip():
            self.goto_text(text)

    def goto_text(self, text: str) -> bool:
        a = self.an.resolve(text) if self.an else None
        if a is None:
            self.statusBar().showMessage(f"cannot resolve '{text}'", 3000)
            return False
        return self.goto(a)

    def toggle_graph(self):
        self.tabs.setCurrentIndex(self.TAB_GRAPH if self.tabs.currentIndex() != self.TAB_GRAPH else self.TAB_DISASM)

    def toggle_decompile(self):
        self.tabs.setCurrentIndex(self.TAB_DECOMP if self.tabs.currentIndex() != self.TAB_DECOMP
                                  else self.TAB_DISASM)

    def _tab_changed(self, idx: int):
        if self.an is None or self.cur is None:
            return
        if idx == self.TAB_DECOMP:
            f = self.an.function_at(self.cur)
            if f is not None:
                self.decomp.show_function(self.an, f, self.cur)
            self.decomp.setFocus()
        elif idx == self.TAB_DISASM:
            self.disasm.goto(self.cur)
            self.disasm.setFocus()
        elif idx == self.TAB_GRAPH:
            self.graph.goto(self.cur)
            self.graph.setFocus()

    def _focus_functions(self):
        self.findChild(QDockWidget, "Functions").show()
        self.funcs.filter.setFocus()
        self.funcs.filter.selectAll()

    def _cursor_moved(self, addr: int):
        self.cur = addr
        self._show_status(addr)

    def _show_status(self, addr: int):
        an = self.an
        sec = an.bin.section_at(addr)
        off = an.bin.addr_to_offset(addr)
        parts = [f"{addr:#x}", an.location(addr)]
        if sec is not None:
            parts.append(sec.name)
        if off is not None:
            parts.append(f"file {off:#x}")
        self.status.setText("   ".join(parts))

    # ---------------------------------------------------------------- edits
    def _subject(self) -> int | None:
        """Address an edit applies to: function/label header, or the line's address."""
        if self.an is None:
            return None
        if self.tabs.currentIndex() == self.TAB_DISASM:
            ln = self.disasm.current_line()
            if ln is not None:
                return ln.addr
        if self.tabs.currentIndex() == self.TAB_DECOMP:
            a = self.decomp.current_addr()
            if a is not None:
                return a
        return self.cur

    def _rename_subject(self) -> int | None:
        if self.tabs.currentIndex() == self.TAB_DECOMP:
            a = self.decomp.symbol_under_cursor()
            if a is not None:
                return a
        if self.tabs.currentIndex() == self.TAB_DISASM:
            ln = self.disasm.current_line()
            if ln is not None:
                if ln.kind in ("func", "label"):
                    return ln.addr
                if ln.target is not None and self.an.bin.is_mapped(ln.target):
                    return ln.target
        a = self.cur
        if a is None:
            return None
        f = self.an.function_at(a)
        return f.addr if f is not None else a

    def rename_dialog(self):
        if self.tabs.currentIndex() == self.TAB_DECOMP:
            var = self.decomp.variable_under_cursor()
            if var is not None:
                shown, gen = var
                text, ok = QInputDialog.getText(self, "Rename variable",
                                                f"Name for {shown} (empty to reset to {gen}):", text=shown)
                if ok:
                    self.rename_variable(gen, text.strip())
                return
        a = self._rename_subject()
        if a is None:
            return
        cur = self.an.name(a) or ""
        text, ok = QInputDialog.getText(self, "Rename", f"Name for {a:#x} (empty to reset):", text=cur)
        if ok:
            self.rename(a, text.strip())

    def rename_variable(self, generated: str, name: str) -> bool:
        """Rename a local / parameter of the function shown in the pseudocode."""
        import keyword
        import re
        func = self.decomp.func
        if func is None or self.an is None:
            return False
        taken = set(self.decomp.result.variables) if self.decomp.result is not None else set()
        current = next((k for k, v in (self.decomp.result.variables.items() if self.decomp.result else ())
                        if v == generated), generated)
        if name and (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or keyword.iskeyword(name)
                     or name in _C_RESERVED or (name in taken and name != current)):
            self.statusBar().showMessage(f"'{name}' is not a free C identifier here", 3000)
            return False
        self.an.rename_var(func.addr, generated, name)
        self._after_edit()
        return True

    def rename(self, addr: int, name: str):
        if name and any(c.isspace() for c in name):
            self.statusBar().showMessage("names cannot contain spaces", 3000)
            return
        self.an.rename(addr, name)
        self._after_edit()
        if addr in self.an.functions:
            self._fill_functions()

    def comment_dialog(self):
        a = self._subject()
        if a is None:
            return
        text, ok = QInputDialog.getText(self, "Comment", f"Comment at {a:#x}:", text=self.an.comments.get(a, ""))
        if ok:
            self.comment(a, text.strip())

    def comment(self, addr: int, text: str):
        self.an.comment(addr, text)
        self._after_edit()

    def _after_edit(self):
        self.dirty = True
        self.setWindowTitle(self.windowTitle().rstrip(" *") + " *")
        keep = self.cur
        self.disasm.reload()
        self.graph.reload()
        self.decomp.invalidate(reload=self.tabs.currentIndex() == self.TAB_DECOMP)
        if keep is not None:
            self.disasm.goto(keep)
            self.graph.goto(keep)

    def save_project(self) -> bool:
        if self.an is None:
            return False
        try:
            self.an.save_project()
        except OSError as e:
            QMessageBox.warning(self, "Relic", f"cannot save project: {e}")
            return False
        self.dirty = False
        self.setWindowTitle(self.windowTitle().rstrip(" *"))
        self.statusBar().showMessage(f"saved {self.an.project_path}", 3000)
        return True

    def _confirm_discard(self) -> bool:
        if not self.dirty or self.an is None:
            return True
        r = QMessageBox.question(self, "Relic", "Save renames and comments to the project file?",
                                 QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard
                                 | QMessageBox.StandardButton.Cancel)
        if r == QMessageBox.StandardButton.Save:
            return self.save_project()
        return r == QMessageBox.StandardButton.Discard

    def closeEvent(self, e):
        if not self._confirm_discard():
            e.ignore()
            return
        if self.thread is not None:
            self.thread.wait()
        if self.vulns_thread is not None:
            self.vulns_thread.wait()
        self.decomp.shutdown()
        super().closeEvent(e)

    # ---------------------------------------------------------------- xrefs
    def _xref_subject(self, addr: int) -> int:
        f = self.an.function_at(addr)
        if f is not None and addr not in self.an.xrefs_to and not self.an.xrefs_from.get(addr):
            return f.addr
        return addr

    def show_xrefs_here(self):
        if self.an is None:
            return
        a = None
        if self.tabs.currentIndex() == self.TAB_DISASM:
            ln = self.disasm.current_line()
            if ln is not None:
                a = ln.addr if ln.kind in ("func", "label") else (ln.target if ln.target is not None else ln.addr)
        if a is None:
            a = self.cur
        if a is None:
            return
        self._fill_xrefs(a)
        self.xrefs_dock.show()
        self.xrefs_dock.raise_()
        if self.xrefs.model_.rowCount() == 1:
            self.goto(int(self.xrefs.model_.item(0, 0).data(ADDR_ROLE)))

    def _fill_xrefs(self, addr: int):
        an = self.an
        self.xrefs_dock.setWindowTitle(f"Xrefs to {an.label(addr)}")
        t = self.xrefs
        t.setSortingEnabled(False)
        t.clear_rows()
        for x in sorted(an.xrefs_to.get(addr, []), key=lambda x: x.frm):
            i = an.dis.decode(x.frm)
            t.add_row([x.frm, x.kind, an.location(x.frm), f"{i.mnemonic} {i.op_str}" if i else ""], x.frm)
        t.setSortingEnabled(True)
        t.fit()

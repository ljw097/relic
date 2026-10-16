"""Main window: function list, central views, info tables and navigation."""
from __future__ import annotations

import os
import traceback

from PySide6.QtCore import QSettings, QSortFilterProxyModel, Qt, QThread, Signal
from PySide6.QtGui import QAction, QColor, QKeySequence, QPalette, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox, QDockWidget,
                               QFileDialog, QFormLayout, QInputDialog, QLabel, QLineEdit, QMainWindow, QMessageBox,
                               QProgressBar, QTableView, QTabWidget, QToolButton, QVBoxLayout, QWidget)

from ..analysis import Analysis
from ..analysis.strings import escape
from ..progress import Cancelled, Progress
from .debugger import (BacktracePanel, BreakpointsPanel, CodePanel, ConsolePanel, DebugController, HeapPanel,
                       MemoryPanel, RegistersPanel, StackPanel, VmmapPanel, item_value)
from .views import (DEFAULT_FONT_SIZE, THEME, DisasmView, GraphView, HexView, PseudocodeView, current_theme,
                    font_size, mono_font, set_font_size, set_theme)

ADDR_ROLE = Qt.ItemDataRole.UserRole + 1


def apply_theme(app: QApplication):
    """Fusion palette matching the view colours of the current theme."""
    app.setStyle("Fusion")
    p = QPalette()
    bg, base, fg = QColor(THEME["window"]), QColor(THEME["bg"]), QColor(THEME["fg"])
    for role, c in ((QPalette.ColorRole.Window, bg), (QPalette.ColorRole.WindowText, fg),
                    (QPalette.ColorRole.Base, base), (QPalette.ColorRole.AlternateBase, bg),
                    (QPalette.ColorRole.Text, fg), (QPalette.ColorRole.Button, bg),
                    (QPalette.ColorRole.ButtonText, fg), (QPalette.ColorRole.ToolTipBase, base),
                    (QPalette.ColorRole.ToolTipText, fg), (QPalette.ColorRole.Highlight, QColor(THEME["selection"])),
                    (QPalette.ColorRole.HighlightedText, QColor(THEME["fg"])),
                    (QPalette.ColorRole.PlaceholderText, QColor(THEME["addr"]))):
        p.setColor(role, c)
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(THEME["addr"]))
    app.setPalette(p)


class WorkThread(QThread):
    """Background work that reports progress and stops at its next checkpoint when cancelled.

    Exactly one of `done`, `failed` or `cancelled` is emitted when the work ends.
    """

    failed = Signal(str)
    cancelled = Signal()
    progress = Signal(str, int, int)  # stage, done, total (0: unknown)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.what = ""
        self.token = Progress(self._report)

    def _report(self, stage: str, done: int, total: int):
        self.progress.emit(stage, done, total)

    def cancel(self):
        self.token.cancel()

    def run(self):
        handle = self.token.activate()
        try:
            self.work()
        except Cancelled:
            self.cancelled.emit()
        except Exception as e:  # noqa: BLE001 - surfaced to the user
            self.failed.emit(f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}")
        finally:
            Progress.deactivate(handle)
            self.token.callback = None      # refers back to this thread: no cycle once done

    def work(self):
        raise NotImplementedError


class AnalysisThread(WorkThread):
    """Loads and analyses a binary off the GUI thread."""

    done = Signal(object, object)  # Analysis, extra results

    def __init__(self, path: str, arch: str | None, base: int, parent=None):
        super().__init__(parent)
        self.path, self.arch, self.base = path, arch, base

    def work(self):
        from ..analysis import analyze
        an = analyze(self.path, self.arch, self.base)
        extra = {"checksec": an.checksec()}
        self.done.emit(an, extra)


class VulnsThread(WorkThread):
    """Runs the pwnable heuristics after the window is up (they may decompile functions).

    A failure is reported through `failed`, never as an empty result: "no findings" and
    "the scan broke" must not look the same.
    """

    done = Signal(object)

    def __init__(self, an: Analysis, parent=None):
        super().__init__(parent)
        self.an = an

    def work(self):
        self.done.emit(self.an.vulns())


class ExportThread(WorkThread):
    """Writes the whole binary's pseudocode to a C file (relic.decompiler.export)."""

    done = Signal(object, str)          # result, path

    def __init__(self, an: Analysis, path: str, parent=None):
        super().__init__(parent)
        self.an, self.path = an, path

    def work(self):
        from ..decompiler.export import export_c
        tmp = self.path + ".part"
        try:
            with open(tmp, "w") as fp:
                res = export_c(self.an, fp)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)              # (a cancelled export leaves no half-written file)
            raise
        os.replace(tmp, self.path)
        self.done.emit(res, self.path)


class SearchThread(WorkThread):
    """Runs one search (relic.analysis.search) off the GUI thread."""

    done = Signal(object, str)          # hits, description

    def __init__(self, an: Analysis, kind: str, query, parent=None):
        super().__init__(parent)
        self.an, self.kind, self.query = an, kind, query

    def work(self):
        from ..analysis import search
        fn = {"bytes": search.find_bytes, "text": search.find_text, "imm": search.find_imm,
              "insn": search.find_insn}[self.kind]
        self.done.emit(fn(self.an, self.query), f"{self.kind} {self.query!r}" if self.kind != "imm"
                       else f"immediate {self.query:#x}")


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


class WatchDialog(QDialog):
    """Expression to watch, write / read / access, and how many bytes."""

    SIZES = [("word", None), ("1 byte", 1), ("2 bytes", 2), ("4 bytes", 4), ("8 bytes", 8)]

    def __init__(self, parent=None, expr: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Add watchpoint")
        self.expr = QLineEdit(expr)
        self.expr.setPlaceholderText("notes, notes+8, 0x404040, *(int *)($rbp-4)")
        self.access = QComboBox()
        self.access.addItems(["write", "read", "access"])
        self.size = QComboBox()
        self.size.addItems([t for t, _ in self.SIZES])
        form = QFormLayout(self)
        form.addRow("Expression", self.expr)
        form.addRow("Stop on", self.access)
        form.addRow("Size", self.size)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def values(self) -> tuple[str, str, int | None]:
        return self.expr.text().strip(), self.access.currentText(), self.SIZES[self.size.currentIndex()][1]


class MainWindow(QMainWindow):
    TAB_DISASM, TAB_GRAPH, TAB_DECOMP, TAB_HEX = range(4)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._load_appearance()
        self.an: Analysis | None = None
        self._last_vulns = None
        self._last_checksec: dict | None = None
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
        from .navband import NavBand
        self.navband = NavBand()
        self.navband.navigate.connect(self.goto)
        central = QWidget()
        lay = QVBoxLayout(central)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.navband)
        lay.addWidget(self.tabs)
        self.setCentralWidget(central)
        for v in (self.disasm, self.graph, self.decomp):
            v.navigate.connect(self.goto)
            v.cursor_addr.connect(self._cursor_moved)

        self.funcs = FilteredTable(["Name", "Address", "Size"], "Filter functions", key_column=0)
        self.funcs.table.activated_addr.connect(self.goto)
        self._dock("Functions", self.funcs, Qt.DockWidgetArea.LeftDockWidgetArea)

        self.xrefs = Table(["From", "Type", "Location", "Instruction"])
        self.xrefs.activated_addr.connect(self.goto)
        self.xrefs_dock = self._dock("Xrefs", self.xrefs, Qt.DockWidgetArea.RightDockWidgetArea)
        self.search_results = Table(["Address", "Location", "Match"])
        self.search_results.activated_addr.connect(self.goto)
        self.search_dock = self._dock("Search", self.search_results, Qt.DockWidgetArea.RightDockWidgetArea)
        self.bookmarks = Table(["Address", "Location", "Description"])
        self.bookmarks.activated_addr.connect(self.goto)
        self.bookmarks.setContextMenuPolicy(Qt.ContextMenuPolicy.ActionsContextMenu)
        rm = QAction("Remove bookmark", self.bookmarks)
        rm.setShortcut(QKeySequence(QKeySequence.StandardKey.Delete))
        rm.setShortcutContext(Qt.ShortcutContext.WidgetShortcut)
        rm.triggered.connect(self.remove_selected_bookmarks)
        self.bookmarks.addAction(rm)
        self.bookmarks_dock = self._dock("Bookmarks", self.bookmarks, Qt.DockWidgetArea.RightDockWidgetArea)
        self.tabifyDockWidget(self.xrefs_dock, self.search_dock)
        self.tabifyDockWidget(self.xrefs_dock, self.bookmarks_dock)
        self.xrefs_dock.raise_()
        self.search_thread: SearchThread | None = None


        self.strings = FilteredTable(["Address", "Section", "Encoding", "Value"], "Filter strings")
        self.imports = FilteredTable(["Address", "GOT / IAT", "Name", "Library"], "Filter imports")
        self.vulns = Table(["Severity", "Address", "Function", "Kind", "Message"])
        self.checksec = Table(["Property", "Value"])
        self.info = FilteredTable(["Name", "Address", "Size", "Offset", "Perm"], "Filter sections")
        self.names = FilteredTable(["Address", "Name", "Kind"], "Filter names")
        self.names.table.activated_addr.connect(self.goto)
        self.strings.table.activated_addr.connect(self.goto_xref_or_addr)
        self.imports.table.activated_addr.connect(self.goto)
        self.vulns.activated_addr.connect(self.goto)
        self.info.table.activated_addr.connect(self.goto)
        bottom = Qt.DockWidgetArea.BottomDockWidgetArea
        from .pyconsole import PythonConsole
        self.pyconsole = PythonConsole()
        docks = [self._dock(t, w, bottom) for t, w in (("Strings", self.strings), ("Imports", self.imports),
                                                       ("Vulns", self.vulns), ("Checksec", self.checksec),
                                                       ("Sections", self.info), ("Names", self.names),
                                                       ("Python", self.pyconsole))]
        for d in docks[1:]:
            self.tabifyDockWidget(docks[0], d)
        docks[0].raise_()
        self.docks = docks

        # local debugging (pwndbg-style context panels; shown once a session starts)
        self.dbg = DebugController(self)
        self.dbg_args: list[str] = []
        self.dbg_regs = RegistersPanel()
        self.dbg_stack = StackPanel()
        self.dbg_bt = BacktracePanel()
        self.dbg_code = CodePanel()
        self.dbg_console = ConsolePanel()
        self.dbg_mem = MemoryPanel()
        self.dbg_vmmap = VmmapPanel()
        self.dbg_heap = HeapPanel()
        self.dbg_bps = BreakpointsPanel()
        right, bottom = Qt.DockWidgetArea.RightDockWidgetArea, Qt.DockWidgetArea.BottomDockWidgetArea
        self.dbg_docks = [self._dock("Registers", self.dbg_regs, right), self._dock("Stack", self.dbg_stack, right),
                          self._dock("Console", self.dbg_console, bottom), self._dock("Code", self.dbg_code, bottom),
                          self._dock("Backtrace", self.dbg_bt, bottom), self._dock("Memory", self.dbg_mem, bottom),
                          self._dock("Vmmap", self.dbg_vmmap, bottom), self._dock("Heap", self.dbg_heap, bottom),
                          self._dock("Breakpoints", self.dbg_bps, bottom)]
        # registers, then the stack, below the xrefs / search tabs; console, code and backtrace
        # with the bottom tabs (strings, imports, ...)
        self.splitDockWidget(self.xrefs_dock, self.dbg_docks[0], Qt.Orientation.Vertical)
        self.splitDockWidget(self.dbg_docks[0], self.dbg_docks[1], Qt.Orientation.Vertical)
        for d in self.dbg_docks[2:]:
            self.tabifyDockWidget(self.docks[-1], d)
        for d in self.dbg_docks:
            d.hide()
        self.dbg.state.connect(self._debug_state)
        self.dbg.output.connect(self._debug_output)
        self.dbg.log.connect(self.dbg_console.append)
        self.dbg.busy.connect(self._debug_busy)
        self.dbg_console.stdin_line.connect(self.dbg.send_input)
        self.dbg_console.gdb_line.connect(self.dbg.gdb)
        self.dbg_bt.cellDoubleClicked.connect(self._debug_frame_clicked)
        self.dbg.memory.connect(self.dbg_mem.show_memory)
        self.dbg_mem.goto_expr.connect(self.dbg.view_memory)
        self.dbg_heap.view.connect(self._debug_view_heap)
        self.dbg_bps.changed.connect(self._debug_breakpoint_edited)
        self.dbg_bps.removed.connect(self._debug_breakpoint_removed)
        self.dbg_regs.edit_requested.connect(self.debug_set_register_dialog)
        self.dbg_bps.cellDoubleClicked.connect(self._debug_breakpoint_clicked)
        for t in (self.dbg_regs, self.dbg_stack, self.dbg_vmmap):
            t.cellDoubleClicked.connect(lambda r, c, t=t: self._debug_follow(t, r, c))

        self.status = QLabel()
        self.status.setFont(mono_font(9))
        self.statusBar().addPermanentWidget(self.status, 1)
        # background work: what runs, how far it got, and a way to stop it
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(220)
        self.progress.setTextVisible(True)
        self.cancel_button = QToolButton()
        self.cancel_button.setText("Cancel")
        self.cancel_button.setToolTip("Stop the running analysis / vulnerability scan (Ctrl+.)")
        self.cancel_button.clicked.connect(self.cancel_work)
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().addPermanentWidget(self.cancel_button)
        self.progress.hide()
        self.cancel_button.hide()
        self._closing = False
        self.plugin_hooks: dict[str, list] = {"analysis": [], "cursor": [], "edit": [], "debug": []}
        self._actions()
        self._update_actions()
        self._load_plugins()
        self._restore_layout()

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
        self.recent_menu = m.addMenu("Open &Recent")
        self._fill_recent_menu()
        act(m, "&Save project", QKeySequence.StandardKey.Save, self.save_project)
        act(m, "Apply library &signatures...", None, self.signatures_dialog)
        act(m, "Import C &header...", None, self.header_dialog)
        act(m, "&Run script...", "Alt+F7", self.script_dialog)
        self.recent_scripts_menu = m.addMenu("Recent scrip&ts")
        self._fill_recent_scripts()
        act(m, "&Export pseudocode...", None, self.export_dialog)
        m.addSeparator()
        act(m, "Sna&pshots...", None, self.show_snapshots)
        act(m, "&History...", None, self.show_history)
        act(m, "&Merge project...", None, self.merge_dialog)
        lm = m.addMenu("&Lumina")
        act(lm, "&Pull function names", None, self.lumina_pull)
        act(lm, "Pu&sh function names", None, self.lumina_push)
        act(lm, "&Choose store...", None, self.lumina_store_dialog, False)
        m.addSeparator()
        act(m, "&Cancel background work", "Ctrl+.", self.cancel_work, False)
        m.addSeparator()
        act(m, "&Quit", QKeySequence.StandardKey.Quit, self.close, False)
        m = mb.addMenu("&Navigate")
        act(m, "&Go to address...", "G", self.goto_dialog)
        self.back_act = act(m, "&Back", ("Esc", "Alt+Left"), self.go_back)
        self.fwd_act = act(m, "&Forward", ("Ctrl+Return", "Alt+Right"), self.go_forward)
        m.addSeparator()
        act(m, "&Mark position...", "Alt+M", self.bookmark_dialog)
        act(m, "B&ookmarks", "Ctrl+M", self.show_bookmarks)
        m.addSeparator()
        act(m, "Toggle &graph / listing", "Space", self.toggle_graph)
        act(m, "Toggle &pseudocode / listing", ("Tab", "F5"), self.toggle_decompile)
        act(m, "&Hex view", "Ctrl+H", lambda: self.tabs.setCurrentIndex(self.TAB_HEX))
        act(m, "&Functions", "Ctrl+F", self._focus_functions)
        m = mb.addMenu("&Edit")
        act(m, "&Rename...", "N", self.rename_dialog)
        act(m, "&Comment...", ";", self.comment_dialog)
        act(m, "Re&peatable comment...", ":", self.repeatable_comment_dialog)
        act(m, "Set t&ype...", "Y", self.set_type_dialog)
        act(m, "&Xrefs to...", "X", self.show_xrefs_here)
        d = m.addMenu("Code / &data")
        act(d, "&Undefine", "U", self.undefine_here)
        act(d, "&Code", "C", lambda: self.define_here("code"))
        act(d, "&Data (byte / word / dword / qword)", "D", self.data_here)
        act(d, "&String", "A", lambda: self.define_here("string"))
        act(d, "&Array...", "*", self.array_dialog)
        d.addSeparator()
        act(d, "Create &function", "P", self.create_function_here)
        act(d, "D&elete function", "Ctrl+Delete", self.delete_function_here)
        n = m.addMenu("&Number")
        act(n, "&Hex / decimal", "H", lambda: self.number_format("hex"))
        act(n, "&Character", "R", lambda: self.number_format("char"))
        act(n, "&Binary", "B", lambda: self.number_format("bin"))
        act(n, "&Offset (address)", "O", lambda: self.number_format("offset"))
        act(n, "&Reset", None, lambda: self.number_format(""))
        m.addSeparator()
        act(m, "&Patch bytes...", "Ctrl+Alt+P", self.patch_bytes_dialog)
        act(m, "&Assemble...", "Ctrl+Alt+A", self.assemble_dialog)
        act(m, "&NOP instruction", "Ctrl+Alt+N", lambda: self.patch_with("nop"))
        act(m, "In&vert branch", "Ctrl+Alt+J", lambda: self.patch_with("invert"))
        act(m, "Re&vert patch", None, self.revert_patch_here)
        act(m, "&Undo", "Ctrl+Z", self.undo)
        act(m, "Redo", ("Ctrl+Shift+Z", "Ctrl+Y"), self.redo)
        act(m, "&Export patched file...", None, self.export_patched_dialog)
        m = mb.addMenu("&Search")
        act(m, "Sequence of &bytes...", "Alt+B", lambda: self.search_dialog("bytes"))
        act(m, "&Text...", "Alt+T", lambda: self.search_dialog("text"))
        act(m, "&Immediate value...", "Alt+I", lambda: self.search_dialog("imm"))
        act(m, "I&nstruction (regex)...", "Ctrl+Alt+I", lambda: self.search_dialog("insn"))
        m = mb.addMenu("&Debug")
        act(m, "&Start / Continue", "F9", self.debug_start_or_continue)
        act(m, "Start at &main", "Shift+F9", lambda: self.debug_start("main"))
        act(m, "Step &into", "F7", self.dbg.step_into)
        act(m, "Step &over", "F8", self.dbg.step_over)
        act(m, "Step o&ut", "Ctrl+F7", self.dbg.step_out)
        act(m, "&Run to cursor", "F4", self.debug_run_to_cursor)
        act(m, "Toggle &breakpoint", "F2", self.debug_toggle_breakpoint)
        act(m, "Breakpoint at &function...", "Ctrl+Alt+B", self.debug_breakpoint_dialog)
        act(m, "Add &watchpoint...", "Ctrl+Alt+W", self.debug_watchpoint_dialog)
        act(m, "Set re&gister...", None, lambda: self.debug_set_register_dialog())
        act(m, "&Write memory...", None, self.debug_write_memory_dialog)
        act(m, "&Pause", "Ctrl+Alt+Pause", self.dbg.interrupt, False)
        act(m, "S&top", "Ctrl+F2", self.dbg.stop, False)
        m.addSeparator()
        act(m, "Program &arguments...", None, self.debug_arguments_dialog)
        self.plugins_menu = mb.addMenu("&Plugins")
        m = mb.addMenu("&View")
        act(m, "&Python console", "Ctrl+Shift+P", self.show_python_console, False)
        act(m, "&Structures...", "Ctrl+Shift+S", self.show_structs)
        act(m, "C &types...", None, self.show_types)
        act(m, "Call &graph...", "Ctrl+Shift+G", self.show_call_graph)
        self.light_act = act(m, "&Light theme", "Ctrl+Shift+L",
                             lambda on: self.set_appearance(theme="light" if on else "dark"), False)
        self.light_act.setCheckable(True)
        self.light_act.setChecked(current_theme() == "light")
        act(m, "Zoom &in", ("Ctrl+=", "Ctrl++"), lambda: self.set_appearance(size=font_size() + 1), False)
        act(m, "Zoom &out", "Ctrl+-", lambda: self.set_appearance(size=font_size() - 1), False)
        act(m, "&Reset zoom", "Ctrl+0", lambda: self.set_appearance(size=DEFAULT_FONT_SIZE), False)
        m.addSeparator()
        for d in [self.findChild(QDockWidget, "Functions"), self.xrefs_dock, *self.docks]:
            m.addAction(d.toggleViewAction())
        for a in self.actions():
            a.setShortcutContext(Qt.ShortcutContext.WindowShortcut)

    # ------------------------------------------------------------ appearance
    def _load_appearance(self):
        st = self.settings()
        theme = st.value("theme", "dark")
        set_theme(theme if theme in ("dark", "light") else "dark")
        try:
            set_font_size(int(st.value("font_size", DEFAULT_FONT_SIZE)))
        except (TypeError, ValueError):
            set_font_size(DEFAULT_FONT_SIZE)
        app = QApplication.instance()
        if app is not None:
            apply_theme(app)

    def set_appearance(self, theme: str | None = None, size: int | None = None):
        """Switch the colour theme and / or the code font size, and remember them."""
        st = self.settings()
        if theme is not None:
            set_theme(theme)
            st.setValue("theme", theme)
            app = QApplication.instance()
            if app is not None:
                apply_theme(app)
            self.light_act.setChecked(theme == "light")
        if size is not None:
            st.setValue("font_size", set_font_size(size))
        st.sync()
        for v in (self.disasm, self.graph, self.decomp, self.hex, self.pyconsole):
            v.restyle()
        if theme is not None and self.an is not None:
            # table rows carry theme colours (imports, noreturn functions, severities)
            self._fill_functions()
            if self._last_checksec is not None:
                self._fill_tables(self._last_checksec)
            if self._last_vulns is not None:
                self._fill_vulns(self._last_vulns)
        self.statusBar().showMessage(f"{current_theme()} theme, {font_size()} pt", 3000)

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

    # ----------------------------------------------------------- settings
    MAX_RECENT = 10

    @staticmethod
    def settings() -> QSettings:
        """Per-user settings; RELIC_SETTINGS points them at an ini file (tests, portable use)."""
        path = os.environ.get("RELIC_SETTINGS")
        return QSettings(path, QSettings.Format.IniFormat) if path else QSettings("relic", "relic")

    def recent_files(self) -> list[dict]:
        import json
        try:
            items = json.loads(self.settings().value("recent", "[]") or "[]")
        except (TypeError, ValueError):
            return []
        return [r for r in items if isinstance(r, dict) and isinstance(r.get("path"), str)]

    def _remember(self, path: str, arch: str | None, base: int):
        import json
        path = os.path.abspath(path)
        items = [r for r in self.recent_files() if r["path"] != path]
        items.insert(0, {"path": path, "arch": arch, "base": base})
        self.settings().setValue("recent", json.dumps(items[:self.MAX_RECENT]))
        self._fill_recent_menu()

    def _fill_recent_menu(self):
        self.recent_menu.clear()
        items = self.recent_files()
        for r in items:
            label = r["path"] + (f"  [{r['arch']} @ {r.get('base', 0):#x}]" if r.get("arch") else "")
            a = self.recent_menu.addAction(label)
            a.triggered.connect(lambda _=False, r=r: self.open_file(r["path"], r.get("arch"), r.get("base") or 0))
        self.recent_menu.setEnabled(bool(items))

    def _restore_layout(self):
        st = self.settings()
        geo, state = st.value("geometry"), st.value("windowState")
        if geo is not None:
            self.restoreGeometry(geo)
        if state is not None:
            self.restoreState(state)

    def _save_layout(self):
        st = self.settings()
        st.setValue("geometry", self.saveGeometry())
        st.setValue("windowState", self.saveState())
        st.sync()

    def open_file(self, path: str, arch: str | None = None, base: int = 0):
        if not self._confirm_discard():
            return
        if self.thread is not None and self.thread.isRunning():
            self.statusBar().showMessage("analysis already running", 3000)
            return
        self.statusBar().showMessage(f"analysing {path} ...")
        self.setWindowTitle(f"Relic - {os.path.basename(path)} (analysing)")
        self.thread = AnalysisThread(path, arch, base, self)
        self.thread.done.connect(self._analysis_done)
        self.thread.failed.connect(self._failed)
        self.thread.cancelled.connect(self._analysis_cancelled)
        self._track(self.thread, "analysing")
        self.thread.start()

    # ------------------------------------------------------- background work
    # thread signals go to bound methods (per-thread data lives on the thread, found through
    # `sender()`), not to lambdas capturing the window: no window <-> thread reference cycles
    def _analysis_done(self, an: Analysis, extra: dict):
        t = self.sender()
        if isinstance(t, AnalysisThread):
            self._remember(t.path, t.arch, t.base)
        self.set_analysis(an, extra)

    def _track(self, thread: WorkThread, what: str):
        """Show `thread`'s progress in the status bar until it ends."""
        thread.what = what
        thread.progress.connect(self._thread_progress)
        thread.finished.connect(self._work_finished)
        self.progress.setRange(0, 0)
        self.progress.setFormat(what)
        self.progress.show()
        self.cancel_button.setEnabled(True)
        self.cancel_button.show()

    def _thread_progress(self, stage: str, done: int, total: int):
        t = self.sender()
        self._on_progress(getattr(t, "what", "working"), stage, done, total)

    def _on_progress(self, what: str, stage: str, done: int, total: int):
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(min(done, total))
            self.progress.setFormat(f"{what}: {stage} %v/%m")
        else:
            self.progress.setRange(0, 0)             # unknown amount: busy indicator
            self.progress.setFormat(f"{what}: {stage} {done}" if done else f"{what}: {stage}")

    def running_work(self) -> list[WorkThread]:
        return [t for t in (self.thread, self.vulns_thread, getattr(self, "search_thread", None),
                            getattr(self, "export_thread", None))
                if t is not None and t.isRunning()]

    def _work_finished(self):
        if self.running_work():
            return
        self.progress.hide()
        self.cancel_button.hide()
        if self._closing:
            self.close()                             # a close deferred until the work stopped

    def cancel_work(self):
        """Ask the running analysis / scan to stop; it does so at its next checkpoint."""
        running = self.running_work()
        for t in running:
            t.cancel()
        if running:
            self.cancel_button.setEnabled(False)
            self.progress.setFormat("cancelling ...")
            self.statusBar().showMessage("cancelling ...", 3000)

    def _analysis_cancelled(self):
        self.setWindowTitle(f"Relic - {os.path.basename(self.an.bin.path)}" if self.an else "Relic")
        self.statusBar().showMessage("analysis cancelled", 5000)

    def wait(self, ms: int = 60000) -> bool:
        """Block until a background analysis (and the vulns scan after it) finishes."""
        ok = True
        if self.thread is not None:
            ok = self.thread.wait(ms)
            QApplication.processEvents()
        if self.vulns_thread is not None:
            ok = self.vulns_thread.wait(ms) and ok
            QApplication.processEvents()
        if getattr(self, "search_thread", None) is not None:
            ok = self.search_thread.wait(ms) and ok
            QApplication.processEvents()
        return ok

    def _failed(self, msg: str):
        self.setWindowTitle("Relic")
        self.statusBar().showMessage("analysis failed", 5000)
        QMessageBox.critical(self, "Relic", msg.split("\n\n", 1)[0])

    def set_analysis(self, an: Analysis, extra: dict | None = None):
        extra = extra or {}
        self.an = an
        from ..scripting import namespace
        self.pyconsole.set_namespace(namespace(an, self))
        self.back.clear()
        self.fwd.clear()
        self.cur = None
        self.dirty = False
        self.disasm.func = self.graph.func = None
        self.setWindowTitle(f"Relic - {os.path.basename(an.bin.path)}  [{an.bin.describe()}]")
        self._fill_functions()
        self._fill_bookmarks()
        self._fill_tables(extra.get("checksec") or an.checksec())
        if "vulns" in extra:
            self._fill_vulns(extra["vulns"])
        else:
            self._fill_vulns(None)
            self.vulns_thread = VulnsThread(an, self)
            self.vulns_thread.done.connect(self._fill_vulns)
            self.vulns_thread.failed.connect(self._vulns_failed)
            self.vulns_thread.cancelled.connect(self._vulns_cancelled)
            self._track(self.vulns_thread, "vulns scan")
            self.vulns_thread.start()
        self.statusBar().showMessage(f"{len(an.functions)} functions, {len(an.strings)} strings", 5000)
        main = an.function_by_name("main")
        start = main.addr if main else an.bin.entry
        self._update_actions()
        self._run_hooks("analysis")
        self.goto(start, record=False)

    def _fill_functions(self):
        t = self.funcs.table
        t.setSortingEnabled(False)
        t.clear_rows()
        an = self.an
        for f in sorted(an.functions.values(), key=lambda f: f.addr):
            color = THEME["addr"] if f.is_import else (THEME["jump"] if f.noreturn else
                                                       THEME["comment"] if f.library else None)
            t.add_row([an.name(f.addr) or f.name, f.addr, f.size], f.addr, color)
        t.setSortingEnabled(True)
        t.fit()

    def _fill_vulns(self, vulns):
        """Fill the Vulns table; None shows that the scan is still running."""
        self._last_vulns = vulns
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

    def _vulns_stopped(self, message: str, color: str | None = None):
        """The scan ended without a result: say so in the table instead of showing no findings."""
        self.vulns.setSortingEnabled(False)
        self.vulns.clear_rows()
        self.vulns.add_row(["error" if color else "-", "", "", "", message], None, color)
        self.vulns.fit()

    def _vulns_cancelled(self):
        self._vulns_stopped("scan cancelled")

    def _vulns_failed(self, msg: str):
        head = msg.split("\n\n", 1)[0]
        self._vulns_stopped(f"vulnerability scan failed: {head}", THEME["jump"])
        self.vulns.setToolTip(msg)
        self.statusBar().showMessage(f"vulnerability scan failed: {head}", 8000)

    def _fill_tables(self, checksec: dict):
        self._last_checksec = checksec
        self.navband.set_analysis(self.an)
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

        self._fill_names()

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
        self.navband.set_current(addr)
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
        elif self.tabs.currentIndex() != self.TAB_HEX and self.disasm.show_region(an, addr):
            self.tabs.setCurrentIndex(self.TAB_DISASM)        # data / unexplored code: listed
        else:
            self.tabs.setCurrentIndex(self.TAB_HEX)
        self.hex.show_addr(an, addr)
        self._show_status(addr)
        self._update_actions()
        if self.xrefs_dock.isVisible():
            self._fill_xrefs(self._xref_subject(addr))
        self._notify_cursor(addr)

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

    # ---------------------------------------------------------------- search
    _SEARCH_PROMPTS = {
        "bytes": ("Search bytes", "Hex bytes, ?? for any byte (48 8b ?? 05):"),
        "text": ("Search text", "Text (ASCII / UTF-8 and UTF-16LE, case-insensitive):"),
        "imm": ("Search immediate", "Value used as an immediate or displacement (0x186a0, 100000, -1):"),
        "insn": ("Search instructions", "Regular expression over the listing text (call.*system):"),
    }

    def search_dialog(self, kind: str):
        if self.an is None:
            return
        title, label = self._SEARCH_PROMPTS[kind]
        text, ok = QInputDialog.getText(self, title, label)
        if ok and text.strip():
            self.search(kind, text.strip())

    def search(self, kind: str, text: str) -> bool:
        """Start a search; the hits fill the Search panel when it finishes."""
        if self.an is None:
            return False
        if self.search_thread is not None and self.search_thread.isRunning():
            self.statusBar().showMessage("a search is already running", 3000)
            return False
        query = text
        if kind == "imm":
            try:
                query = int(text, 0)
            except ValueError:
                self.statusBar().showMessage(f"'{text}' is not a number", 3000)
                return False
        self.search_thread = SearchThread(self.an, kind, query, self)
        self.search_thread.done.connect(self._search_done)
        self.search_thread.failed.connect(self._search_failed)
        self._track(self.search_thread, "searching")
        self.search_thread.start()
        return True

    def _search_failed(self, msg: str):
        self.statusBar().showMessage(f"search failed: {msg.split(chr(10))[0]}", 6000)

    def _search_done(self, hits, what: str):
        t = self.search_results
        t.setSortingEnabled(False)
        t.clear_rows()
        for h in hits:
            t.add_row([h.addr, self.an.location(h.addr), h.text], h.addr)
        t.setSortingEnabled(True)
        t.fit()
        self.search_dock.show()
        self.search_dock.raise_()
        self.statusBar().showMessage(f"{len(hits)} hit(s) for {what}", 5000)

    # --------------------------------------------------------------- debugging
    def debug_start(self, stop_at: str = "entry"):
        """Run the analysed binary locally under gdb, stopped at its entry point (or `main`)."""
        if self.an is None:
            return
        regs, stack = self.dbg_docks[:2]
        first = not regs.isVisible() and not stack.isVisible()
        for d in self.dbg_docks:
            d.show()
        if first and not regs.isFloating() and (self.tabifiedDockWidgets(regs) or self.tabifiedDockWidgets(stack)):
            # docks hidden next to a tabbed one come back as tabs: lay registers and the stack
            # out again, one above the other in a column of their own on the right
            for d in (regs, stack):
                self.removeDockWidget(d)
            self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, regs, Qt.Orientation.Vertical)
            self.splitDockWidget(regs, stack, Qt.Orientation.Vertical)
            regs.show()
            stack.show()
        self.resizeDocks([regs], [max(regs.width(), 520)], Qt.Orientation.Horizontal)
        if first:
            h = self.height()
            self.resizeDocks([self.xrefs_dock, regs, stack], [h // 6, h // 3, h // 3], Qt.Orientation.Vertical)
        self.dbg_docks[2].raise_()        # console
        self.dbg_console.append(f"$ {self.an.bin.path} {' '.join(self.dbg_args)}\n")
        self.dbg.start(self.an.bin.path, self.an, self.dbg_args, stop_at)

    def debug_start_or_continue(self):
        if self.dbg.session is None or self.dbg.last.exited:
            self.debug_start()
        else:
            self.dbg.cont()

    def debug_toggle_breakpoint(self):
        if self.cur is None:
            return
        on = self.dbg.toggle_breakpoint(self.cur)
        self._debug_breakpoints_changed()
        self.statusBar().showMessage(f"breakpoint {'set' if on else 'cleared'} at {self.an.location(self.cur)}", 3000)

    def _debug_breakpoints_changed(self):
        self._debug_marks(self.dbg.last.pc_static)
        self.dbg_bps.an = self.an
        self.dbg_bps.show_breakpoints(self.dbg.breakpoint_list)

    def _debug_marks(self, pc_static: int | None):
        """pc and enabled breakpoints in the listing and the pseudocode."""
        bps = [a for a, b in self.dbg.static_bps.items() if b.enabled]
        self.disasm.set_debug_marks(pc_static, bps)
        self.decomp.set_debug_marks(pc_static, bps)

    def _debug_breakpoint_edited(self, key, enabled, condition):
        self.dbg.set_breakpoint(key, enabled, condition)
        self._debug_breakpoints_changed()

    def _debug_breakpoint_removed(self, key):
        self.dbg.remove_breakpoint(key)
        self._debug_breakpoints_changed()

    def _debug_breakpoint_clicked(self, row: int, col: int):
        if col in (2, 3):
            a = item_value(self.dbg_bps.item(row, 2))
            if a is not None:
                self.goto(a)

    def debug_breakpoint_dialog(self):
        """Break on a function by name: one of the binary (`vuln`), `puts@plt`, or a library
        function (`puts` stops inside libc)."""
        if self.an is None:
            return
        cur = self.an.name(self.cur) if self.cur is not None else ""
        text, ok = QInputDialog.getText(self, "Breakpoint at function",
                                        "Function (vuln, puts, puts@plt, libc.so.6:system, 0x401136):",
                                        text=cur or "")
        if ok and text.strip():
            self.debug_break_at(text)

    def debug_break_at(self, text: str):
        bp = self.dbg.breakpoint_at(text, self.an)
        self._debug_breakpoints_changed()
        if bp is not None:
            self.dbg_docks[7].show()
            self.statusBar().showMessage(f"breakpoint on {bp.describe(self.an)}", 3000)

    def debug_watchpoint_dialog(self):
        """Watch memory: a global of the binary (`notes`), an address, or a gdb expression."""
        if self.an is None:
            return
        dlg = WatchDialog(self, self._debug_watch_default())
        if dlg.exec():
            self.debug_watch(*dlg.values())

    def _debug_watch_default(self) -> str:
        """The data the cursor's instruction refers to, else the memory view's address."""
        if self.cur is not None:
            refs = [x.to for x in self.an.xrefs_from.get(self.cur, ()) if x.kind == "data"]
            refs = [a for a in refs if self.an.string_at(a) is None] or refs
            if refs:
                return self.an.label(refs[0])
        return f"{self.dbg_mem.addr:#x}" if self.dbg_mem.addr is not None else ""

    def debug_set_register_dialog(self, name: str = "", value: int | None = None):
        """Change a register: `rax = 0x41`, or `$rsp+8` (any gdb expression)."""
        if not self.dbg.active:
            return
        if not name:
            name, ok = QInputDialog.getItem(self, "Set register", "Register:",
                                            [n for n, *_ in self.dbg.last.regs], 0, False)
            if not ok:
                return
            value = next((v for n, v, *_ in self.dbg.last.regs if n == name), None)
        text, ok = QInputDialog.getText(self, "Set register", f"New value of {name} (number or gdb expression):",
                                        text=f"{value:#x}" if value is not None else "")
        if ok and text.strip():
            self.dbg.set_register(name, text)

    def debug_write_memory_dialog(self):
        """Write bytes at an address: hex (`41 42 ff`), a string (`"AAAA\\n"`) or a word (`0x401136`)."""
        if not self.dbg.active:
            return
        where, ok = QInputDialog.getText(self, "Write memory", "Address or expression ($rsp+8, notes, 0x7ffd...):",
                                         text=f"{self.dbg_mem.addr:#x}" if self.dbg_mem.addr is not None else "$rsp")
        if not ok or not where.strip():
            return
        data, ok = QInputDialog.getText(self, "Write memory",
                                        'Bytes: hex (41 42 ff), "string\\n", or a word (0x401136):')
        if ok and data.strip():
            self.dbg.write_memory(where, data)
            self.dbg_docks[5].show()
            self.dbg_docks[5].raise_()

    def debug_watch(self, expr: str, access: str = "write", size: int | None = None):
        bp = self.dbg.add_watchpoint(expr, access, size)
        self._debug_breakpoints_changed()
        if bp is not None:
            self.dbg_docks[7].show()
            self.statusBar().showMessage(f"watching {bp.describe()}", 3000)

    def debug_run_to_cursor(self):
        if self.cur is not None:
            self.dbg.run_to(self.cur)

    def _debug_view_heap(self, addr: int):
        """A heap chunk (or tcache entry) double-clicked: its memory, in the memory view."""
        self.dbg.view_memory(addr)
        next(d for d in self.dbg_docks if d.widget() is self.dbg_mem).raise_()

    def debug_arguments_dialog(self):
        text, ok = QInputDialog.getText(self, "Program arguments", "Arguments (space-separated):",
                                        text=" ".join(self.dbg_args))
        if ok:
            import shlex
            try:
                self.dbg_args = shlex.split(text)
            except ValueError as e:
                self.statusBar().showMessage(f"arguments: {e}", 4000)

    def _debug_state(self, snap):
        self.dbg_bps.an = self.an
        for panel in (self.dbg_regs, self.dbg_stack, self.dbg_bt, self.dbg_code, self.dbg_vmmap, self.dbg_heap,
                      self.dbg_bps):
            panel.show_snapshot(snap)
        if snap.exited:
            self._debug_marks(None)
            self.dbg_console.append(f"[ {snap.exited} ]\n")
            self.statusBar().showMessage(f"program {snap.exited}", 5000)
            return
        if snap.pc_static is not None:
            self.goto(snap.pc_static, record=False)
        self._debug_marks(snap.pc_static)
        self._run_hooks("debug", snap)
        where = self.an.location(snap.pc_static) if snap.pc_static is not None else f"{snap.pc:#x}"
        self.statusBar().showMessage(f"stopped at {where}" + (f" ({snap.stop})" if snap.stop else ""), 5000)
        if snap.reason.endswith(("watchpoint-trigger", "watchpoint-scope")):
            self.dbg_console.append(f"[ {snap.stop} at {where} ]\n")

    def _debug_output(self, data: bytes):
        self.dbg_console.append(data.decode("utf-8", "replace"))

    def _debug_busy(self, busy: bool):
        if busy:
            self.statusBar().showMessage("running ...")

    def _debug_frame_clicked(self, row: int, _col: int):
        live = item_value(self.dbg_bt.item(row, 1))
        s = self.dbg.session
        if live is not None and s is not None:
            a = s.to_static(live)
            if a is not None:
                self.goto(a)

    def _debug_follow(self, table, row: int, col: int):
        """Double-click on a register, stack slot or mapping: code of the analysed binary opens
        in the listing, anything else in the memory view."""
        live = item_value(table.item(row, col))
        if live is None:
            live = item_value(table.item(row, 1))
        s = self.dbg.session
        if live is None or s is None:
            return
        a = s.to_static(live)
        if table is not self.dbg_vmmap and a is not None and self.an.function_at(a) is not None:
            self.goto(a)
            return
        self.dbg.view_memory(live)
        self.dbg_docks[5].show()
        self.dbg_docks[5].raise_()

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
        self.navband.set_current(addr)
        self._show_status(addr)
        self._notify_cursor(addr)

    def _notify_cursor(self, addr: int):
        """Plugins' cursor hooks, once per address the cursor arrives at."""
        if addr != getattr(self, "_hooked_addr", None):
            self._hooked_addr = addr
            self._run_hooks("cursor", addr)

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

    # ------------------------------------------------------- code and data
    def _item_addr(self) -> int | None:
        a = self.disasm.current_addr() if self.tabs.currentIndex() == self.TAB_DISASM else self.cur
        return a if a is not None else self.cur

    def define_here(self, kind: str, **kw):
        a = self._item_addr()
        if a is None or self.an is None:
            return
        try:
            self.an.define_data(a, kind, **kw)
        except ValueError as e:
            self.statusBar().showMessage(str(e), 4000)
            return
        self._after_edit()
        self.goto(a, record=False)

    def data_here(self):
        """D: a byte, then a word, dword, qword, and round again."""
        from ..datalist import CYCLE
        a = self._item_addr()
        if a is None:
            return
        cur = (self.an.data_defs.get(a) or [""])[0]
        self.define_here(CYCLE[(CYCLE.index(cur) + 1) % len(CYCLE)] if cur in CYCLE else "byte")

    def array_dialog(self):
        from ..datalist import SIZES
        a = self._item_addr()
        if a is None:
            return
        cur = (self.an.data_defs.get(a) or ["byte"])[0]
        n, ok = QInputDialog.getInt(self, "Array", f"Number of {cur if cur in SIZES else 'byte'} elements:",
                                    16, 1, 1 << 20)
        if ok:
            self.define_here("array", count=n, element=cur if cur in SIZES else "byte")

    def undefine_here(self):
        a = self._item_addr()
        if a is None:
            return
        self.an.undefine(a)
        self._after_edit()
        self.goto(a, record=False)

    def create_function_here(self):
        a = self._item_addr()
        if a is None:
            return
        try:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            try:
                self.an.create_function(a)
            finally:
                QApplication.restoreOverrideCursor()
        except ValueError as e:
            self.statusBar().showMessage(str(e), 4000)
            return
        self._after_patch(a)
        self.statusBar().showMessage(f"function at {a:#x}", 4000)

    def delete_function_here(self):
        f = self.an.function_at(self.cur) if self.an is not None and self.cur is not None else None
        if f is None or f.is_import:
            self.statusBar().showMessage("no function here", 3000)
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            self.an.delete_function(f.addr)
        finally:
            QApplication.restoreOverrideCursor()
        self._after_patch(f.addr)
        self.statusBar().showMessage(f"removed the function at {f.addr:#x}", 4000)

    def number_format(self, fmt: str):
        """Show the number under the cursor another way (IDA's H / R / B / O): an operand of the
        listing's instruction, or a constant of the pseudocode. Again on the same format: back to
        the default (H toggles hex and decimal)."""
        if self.an is None:
            return
        if self.tabs.currentIndex() == self.TAB_DECOMP:
            self._pseudocode_number(fmt)
            return
        ln = self.disasm.current_line()
        if ln is None or ln.kind != "insn" or not ln.operands:
            self.statusBar().showMessage("put the cursor on an instruction operand", 4000)
            return
        from ..numfmt import numbers_in, operand_at, split_operands
        start = self.disasm.columns["mnem"] + len(ln.mnemonic) + 1
        pos = self.disasm.textCursor().positionInBlock() - start
        spans = split_operands(ln.operands)
        if 0 <= pos <= len(ln.operands):
            k = operand_at(ln.operands, pos)
        else:                                      # not on the operands: the first with a number
            k = next((j for j, (a, b) in enumerate(spans) if numbers_in(ln.operands[a:b])), 0)
        text = ln.operands[spans[k][0]:spans[k][1]]
        cur = self.an.op_formats.get(ln.addr, {}).get(str(k))
        if fmt == "hex":
            fmt = "dec" if cur == "hex" or (cur is None and "0x" in text) else "hex"
        elif fmt and cur == fmt:
            fmt = ""
        if fmt and not numbers_in(text):
            self.statusBar().showMessage(f"operand {k + 1} has no number", 4000)
            return
        self.an.set_operand_format(ln.addr, k, fmt)
        self._after_edit()

    def _pseudocode_number(self, fmt: str):
        import re

        from PySide6.QtGui import QTextCursor
        cur = self.decomp.textCursor()
        cur.select(QTextCursor.SelectionType.WordUnderCursor)
        word, line = cur.selectedText(), cur.block().text()
        col = cur.selectionStart() - cur.block().position()
        before = line[col - 1:col] if col > 0 else ""
        value = None
        if before == "'" and word:                 # a character constant: 'ABCD'
            value = int.from_bytes(word.encode("latin-1", "replace"), "big")
        elif re.fullmatch(r"0[xX][0-9a-fA-F]+|0b[01]+|\d+", word):
            value = int(word, 0) if not word.isdigit() else int(word)
            if before == "-":
                value = -value
        func = self.decomp.func.addr if self.decomp.func is not None else None
        if value is None or func is None:
            self.statusBar().showMessage("put the cursor on a number", 4000)
            return
        if fmt == "offset":
            self.statusBar().showMessage("an offset is shown in the listing (O on the instruction)", 4000)
            return
        current = self.an.num_formats.get(func, {}).get(str(value))
        if fmt == "hex":
            fmt = "dec" if current == "hex" or (current is None and word.lower().startswith("0x")) else "hex"
        elif fmt and current == fmt:
            fmt = ""
        self.an.set_number_format(func, value, fmt)
        self._after_edit()

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
            st = self.decomp.struct_under_cursor()
            if st is not None:
                shown, struct, fld = st
                what = f"field {shown} of struct {struct}" if fld else f"struct {shown}"
                text, ok = QInputDialog.getText(self, "Rename", f"Name for {what} (empty to reset):", text=shown)
                if ok:
                    self.rename_struct(struct, fld, text.strip())
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

    def set_type_dialog(self):
        """Pseudocode: a C type for the variable / parameter or struct field under the cursor
        (`char *`, `unsigned int`, `struct note *`); empty resets to the recovered one."""
        if self.tabs.currentIndex() != self.TAB_DECOMP or self.decomp.result is None:
            self.statusBar().showMessage("set type: put the cursor on a variable or field in the pseudocode", 4000)
            return
        var = self.decomp.variable_under_cursor()
        if var is not None:
            shown, gen = var
            cur = self.decomp.result.types.get(gen, "")
            text, ok = QInputDialog.getText(self, "Set type", f"Type of {shown} (empty: as recovered):", text=cur)
            if ok:
                self.set_var_type(gen, text)
            return
        func = self.decomp.func
        if func is not None and self.decomp.textCursor().blockNumber() == self._signature_row() and \
                self.decomp.word_under_cursor() == (self.an.name(func.addr) or func.name):
            cur = self.an.var_types.get(func.addr, {}).get("@return", "")
            text, ok = QInputDialog.getText(self, "Set type", f"Return type of {self.an.name(func.addr)} "
                                            "(empty: as recovered):", text=cur)
            if ok:
                try:
                    self.an.set_return_type(func.addr, text)
                except ValueError as e:
                    self.statusBar().showMessage(f"set type: {e}", 5000)
                    return
                self._after_edit()
            return
        st = self.decomp.struct_under_cursor()
        if st is not None and st[2] is not None:
            shown, struct, fld = st
            cur = self.an.struct_names.get(struct, {}).get("types", {}).get(fld, "")
            text, ok = QInputDialog.getText(self, "Set type", f"Type of field {shown} (empty: as recovered):",
                                            text=cur)
            if ok:
                self.set_field_type(struct, fld, text)

    def _signature_row(self) -> int:
        """The pseudocode row of the function's signature (after the struct declarations)."""
        lines = self.decomp.toPlainText().split("\n")
        name = self.an.name(self.decomp.func.addr) or ""
        return next((k for k, ln in enumerate(lines) if ln and not ln.startswith((" ", "}", "struct", "union", "//"))
                     and f"{name}(" in ln), -1)

    def set_var_type(self, generated: str, ctype: str) -> bool:
        func = self.decomp.func
        if func is None or self.an is None:
            return False
        try:
            self.an.set_var_type(func.addr, generated, ctype)
        except ValueError as e:
            self.statusBar().showMessage(f"set type: {e}", 5000)
            return False
        self._after_edit()
        return True

    def set_field_type(self, struct: str, field: str, ctype: str) -> bool:
        try:
            self.an.set_field_type(struct, field, ctype)
        except ValueError as e:
            self.statusBar().showMessage(f"set type: {e}", 5000)
            return False
        self._after_edit()
        return True

    def rename_struct(self, struct: str, field: str | None, name: str) -> bool:
        """Name a recovered struct (field None) or one of its fields, by generated names."""
        import keyword
        import re
        if name and (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or keyword.iskeyword(name)):
            self.statusBar().showMessage(f"'{name}' is not a C identifier", 3000)
            return False
        if field is None:
            self.an.rename_struct(struct, name)
        else:
            self.an.rename_field(struct, field, name)
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

    def repeatable_comment_dialog(self):
        """A comment shown here and wherever this address is referred to (calls, jumps, data
        references)."""
        a = self._subject()
        if a is None:
            return
        text, ok = QInputDialog.getText(self, "Repeatable comment", f"Repeatable comment at {a:#x}:",
                                        text=self.an.rcomments.get(a, ""))
        if ok:
            self.an.repeatable_comment(a, text.strip())
            self._after_edit()

    def _fill_names(self):
        t = self.names.table
        t.setSortingEnabled(False)
        t.clear_rows()
        colors = {"function": THEME["func"], "library": THEME["func"], "import": THEME["call"], "data": None,
                  "label": None}
        for a, name, kind in self.an.names():
            t.add_row([a, name, kind], a, colors.get(kind))
        t.setSortingEnabled(True)
        t.fit()

    def export_dialog(self):
        """Write the pseudocode of every function to a C file, in the background."""
        if getattr(self, "export_thread", None) is not None and self.export_thread.isRunning():
            self.statusBar().showMessage("an export is already running", 3000)
            return
        start = self.an.bin.path + ".c"
        path, _ = QFileDialog.getSaveFileName(self, "Export pseudocode", start, "C files (*.c);;All files (*)")
        if path:
            self.export_pseudocode(path)

    def export_pseudocode(self, path: str) -> "ExportThread":
        t = ExportThread(self.an, path, self)
        t.done.connect(self._exported)
        t.failed.connect(lambda msg: QMessageBox.warning(self, "Export pseudocode", msg.split("\n\n")[0]))
        t.cancelled.connect(lambda: self.statusBar().showMessage("export cancelled", 4000))
        self.export_thread = t
        self._track(t, "export")
        t.start()
        return t

    def _exported(self, res: dict, path: str):
        more = f", {len(res['failed'])} not decompiled" if res["failed"] else ""
        self.statusBar().showMessage(f"{os.path.basename(path)}: {res['functions']} functions{more}", 8000)

    def show_types(self):
        """The imported C types window."""
        from .types import TypesDialog
        if getattr(self, "types_dialog", None) is None:
            self.types_dialog = TypesDialog(self)
        else:
            self.types_dialog.refresh()
        self.types_dialog.show()
        self.types_dialog.raise_()
        return self.types_dialog

    def show_snapshots(self):
        """The snapshots window."""
        from .snapshots import SnapshotsDialog
        if getattr(self, "snapshots_dialog", None) is None:
            self.snapshots_dialog = SnapshotsDialog(self)
        else:
            self.snapshots_dialog.refresh()
        self.snapshots_dialog.show()
        self.snapshots_dialog.raise_()
        return self.snapshots_dialog

    # ------------------------------------------------------------- scripts
    def script_dialog(self):
        start = (self._recent_scripts() or [os.path.dirname(self.an.bin.path) if self.an else ""])[0]
        path, _ = QFileDialog.getOpenFileName(self, "Run script", os.path.dirname(start) or start,
                                              "Python scripts (*.py);;All files (*)")
        if path:
            self.run_script_file(path)

    def _recent_scripts(self) -> list[str]:
        v = self.settings().value("scripts/recent", []) or []
        return [v] if isinstance(v, str) else list(v)

    def _fill_recent_scripts(self):
        menu = self.recent_scripts_menu
        menu.clear()
        for p in self._recent_scripts():
            menu.addAction(os.path.basename(p), lambda p=p: self.run_script_file(p)).setToolTip(p)
        menu.setEnabled(bool(self._recent_scripts()))

    def run_script_file(self, path: str) -> bool:
        """Run a Python script with the scripting namespace (IDA's Alt+F7); its output and any
        error go to the Python console."""
        import contextlib
        import io
        import traceback

        from ..scripting import namespace, run_script
        if self.an is None:
            self.statusBar().showMessage("open a binary first", 3000)
            return False
        recent = [path] + [p for p in self._recent_scripts() if p != path]
        self.settings().setValue("scripts/recent", recent[:10])
        self._fill_recent_scripts()
        out = io.StringIO()
        ok = True
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                run_script(path, namespace(self.an, self))
            except SystemExit:
                pass
            except Exception:  # noqa: BLE001 - a script error is shown, the GUI stays up
                ok = False
                traceback.print_exc()
        self.pyconsole.append(f"[script {os.path.basename(path)}]\n{out.getvalue()}")
        self.statusBar().showMessage(f"{os.path.basename(path)}: {'done' if ok else 'failed (see the Python console)'}",
                                     5000)
        self._after_edit()
        return ok

    # ------------------------------------------------------------- lumina
    def lumina_store(self) -> str:
        from ..analysis.lumina import default_store
        return str(self.settings().value("lumina/store", "") or default_store())

    def lumina_store_dialog(self):
        text, ok = QInputDialog.getText(self, "Lumina store", "JSON file or http://host:port of a "
                                        "`relic lumina serve`:", text=self.lumina_store())
        if ok and text.strip():
            self.settings().setValue("lumina/store", text.strip())

    def lumina_pull(self) -> dict | None:
        """Names, comments and variable names of the functions the store knows (one undo step)."""
        if self.an is None:
            return None
        try:
            got = self.an.lumina_pull(self.lumina_store())
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Lumina", f"{self.lumina_store()}: {e}")
            return None
        self.statusBar().showMessage(f"lumina: {len(got['applied'])} function(s) named from "
                                     f"{got['matched']} match(es)", 6000)
        if got["applied"]:
            self._after_edit()
            self._fill_functions()
        return got

    def lumina_push(self) -> dict | None:
        if self.an is None:
            return None
        try:
            got = self.an.lumina_push(self.lumina_store())
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Lumina", f"{self.lumina_store()}: {e}")
            return None
        self.statusBar().showMessage(f"lumina: pushed {got['pushed']} function(s)", 6000)
        return got

    def show_history(self):
        """The version history window."""
        from .history import HistoryDialog
        if getattr(self, "history_dialog", None) is None:
            self.history_dialog = HistoryDialog(self)
        else:
            self.history_dialog.refresh()
        self.history_dialog.show()
        self.history_dialog.raise_()
        return self.history_dialog

    def merge_dialog(self):
        """Pick another analyst's project file of this binary and merge its annotations."""
        path, _ = QFileDialog.getOpenFileName(self, "Merge project", os.path.dirname(self.an.bin.path),
                                              "Relic projects (*.relic.json *.json);;All files (*)")
        if path:
            self.merge_project(path)

    def merge_project(self, path: str, theirs: bool = False) -> dict | None:
        """Merge `path` into the annotations (one undo step); where both differ, ours is kept
        unless `theirs`. Asks before merging a project made for another binary."""
        from ..analysis.project import ProjectMismatch
        name = os.path.basename(path)
        try:
            try:
                got = self.an.merge_project(path, theirs)
            except ProjectMismatch as e:
                if QMessageBox.question(self, "Merge project", f"{name}: {e}. Merge anyway?") != \
                        QMessageBox.StandardButton.Yes:
                    return None
                got = self.an.merge_project(path, theirs, force=True)
        except (OSError, ValueError) as e:
            QMessageBox.warning(self, "Merge project", f"{name}: {e}")
            return None
        added = ", ".join(f"{n} {k}" for k, n in got["added"].items()) or "nothing new"
        msg = f"{name}: added {added}"
        if got["conflicts"]:
            msg += f"; {len(got['conflicts'])} conflicting (kept {got['kept']})"
            lines = []
            for section, key, ours, other in got["conflicts"][:30]:
                where = f"{key:#x}" if isinstance(key, int) else \
                    (f"{key[0]:#x} {key[1]}" if isinstance(key, tuple) else str(key))
                lines.append(f"{section} {where}: ours {_short(ours)}, theirs {_short(other)}")
            more = len(got["conflicts"]) - len(lines)
            QMessageBox.information(self, "Merge project", msg + ":\n\n" + "\n".join(lines)
                                    + (f"\n... and {more} more" if more > 0 else ""))
        self.statusBar().showMessage(msg, 8000)
        if got["added"] or got["conflicts"] and theirs:
            self._after_edit()
        return got

    def header_dialog(self):
        """Pick C headers: their structs, enums, typedefs and prototypes go into the project."""
        paths, _ = QFileDialog.getOpenFileNames(self, "Import C header", os.path.dirname(self.an.bin.path),
                                                "C headers (*.h *.hpp *.c);;All files (*)")
        for p in paths:
            self.import_header(p)

    def import_header(self, path: str) -> dict | None:
        from ..decompiler.cheader import HeaderError
        try:
            with open(path) as fp:
                got = self.an.import_header(fp.read())
        except (OSError, HeaderError) as e:
            QMessageBox.warning(self, "Import C header", f"{os.path.basename(path)}: {e}")
            return None
        parts = [f"{len(got[k])} {k}" for k in ("structs", "enums", "typedefs", "functions", "imports") if got[k]]
        self.statusBar().showMessage(f"{os.path.basename(path)}: {', '.join(parts) or 'nothing new'}", 6000)
        self._after_edit()
        return got

    def signatures_dialog(self):
        """Pick signature files (or static libraries, built into ~/.relic/sigs) and name the
        functions without a symbol that match."""
        from ..analysis import libsigs
        start = (libsigs.sig_dirs() or [os.path.expanduser("~")])[0]
        paths, _ = QFileDialog.getOpenFileNames(self, "Library signatures", start,
                                                "Signatures or static libraries (*.sig *.a *.o);;All files (*)")
        if paths:
            self.apply_signatures(paths)

    def apply_signatures(self, paths: list[str]) -> int:
        """Name functions by these signature files / static libraries; how many were named."""
        from ..analysis import libsigs
        dbs = []
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            for p in paths:
                try:
                    if p.endswith(".sig"):
                        db = libsigs.SigDB.load(p)
                    else:                        # a library: build its signatures once, keep them
                        db = libsigs.build([p])
                        out = os.path.join(os.path.expanduser("~"), ".relic", "sigs",
                                           f"{os.path.splitext(os.path.basename(p))[0]}-{db.arch}.sig")
                        db.save(out)
                except (OSError, ValueError) as e:
                    QMessageBox.warning(self, "Library signatures", f"{p}: {e}")
                    continue
                if db.arch == self.an.bin.arch:
                    dbs.append(db)
            named = libsigs.apply(self.an, dbs)
        finally:
            QApplication.restoreOverrideCursor()
        self.an.lib_names.update(named)
        if not dbs:
            self.statusBar().showMessage(f"no signatures for {self.an.bin.arch}", 5000)
        else:
            self.statusBar().showMessage(f"{len(named)} functions named by library signatures", 5000)
        if named:
            self._after_edit()
            self._fill_functions()
        return len(named)

    # ------------------------------------------------------------- undo / bookmarks
    def undo(self) -> bool:
        """Undo the last edit -- rename, comment, type, struct edit, bookmark or patch (Ctrl+Z)."""
        return self._undo_redo(self.an.undo if self.an is not None else None, "undid", "undo")

    def redo(self) -> bool:
        return self._undo_redo(self.an.redo if self.an is not None else None, "redid", "redo")

    def _undo_redo(self, step, done: str, what: str) -> bool:
        if step is None:
            return False
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        funcs = self.an.functions
        try:
            r = step()                            # a patch step analyses again
        finally:
            QApplication.restoreOverrideCursor()
        if r is not None and r[0] != "patch" and self.an.functions is not funcs:
            self._after_patch(r[1] if r[1] is not None else self.cur)    # (a function made / removed)
            self.statusBar().showMessage(f"{done} the function edit", 4000)
            return True
        if r is None:
            self.statusBar().showMessage(f"nothing to {what}", 3000)
            return False
        kind, addr = r
        if kind == "patch":
            self._after_patch(addr)
            self.statusBar().showMessage(f"{done} the patch edit at {addr:#x}", 4000)
        else:
            self._after_edit()
            self._fill_functions()
            self._fill_bookmarks()
            if getattr(self, "structs_dialog", None) is not None and self.structs_dialog.isVisible():
                self.structs_dialog.refresh()
            if addr is not None and self.an.bin.is_mapped(addr) and addr != self.cur:
                self.goto(addr)
            self.statusBar().showMessage(f"{done} the edit" + (f" at {addr:#x}" if addr is not None else ""), 4000)
        self._fill_bookmarks()
        return True

    def bookmark_dialog(self):
        """Bookmark the cursor position (Alt+M); an empty description removes the bookmark."""
        a = self._subject()
        if a is None:
            return
        cur = self.an.bookmarks.get(a) or self.an.location(a)
        text, ok = QInputDialog.getText(self, "Mark position", f"Bookmark at {a:#x} (empty to remove):", text=cur)
        if ok:
            self.set_bookmark(a, text)

    def set_bookmark(self, addr: int, text: str | None):
        self.an.bookmark(addr, text)
        self._fill_bookmarks()
        self._mark_dirty()
        if text:
            self.statusBar().showMessage(f"bookmarked {addr:#x}", 3000)

    def show_bookmarks(self):
        self.bookmarks_dock.show()
        self.bookmarks_dock.raise_()
        self.bookmarks.setFocus()

    def remove_selected_bookmarks(self):
        rows = {i.row() for i in self.bookmarks.selectionModel().selectedRows()}
        addrs = [int(self.bookmarks.proxy.index(r, 0).data(ADDR_ROLE)) for r in rows]
        for a in addrs:
            self.an.bookmark(a, None)
        if addrs:
            self._fill_bookmarks()
            self._mark_dirty()

    def _fill_bookmarks(self):
        t = self.bookmarks
        t.setSortingEnabled(False)
        t.clear_rows()
        if self.an is not None:
            for a, text in sorted(self.an.bookmarks.items()):
                t.add_row([a, self.an.location(a), text], a)
        t.setSortingEnabled(True)
        t.fit()

    def _mark_dirty(self):
        self.dirty = True
        self.setWindowTitle(self.windowTitle().rstrip(" *") + " *")

    def _after_edit(self):
        self.dirty = True
        self.setWindowTitle(self.windowTitle().rstrip(" *") + " *")
        self._fill_names()
        self._run_hooks("edit")
        keep = self.cur
        self.disasm.reload()
        self.graph.reload()
        self.decomp.invalidate(reload=self.tabs.currentIndex() == self.TAB_DECOMP)
        if keep is not None:
            self.disasm.goto(keep)
            self.graph.goto(keep)

    # ------------------------------------------------------------- scripting
    def show_call_graph(self):
        """The callers and callees of the function at the cursor."""
        from .callgraph import CallGraphDialog
        f = self.an.function_at(self.cur) if self.cur is not None else None
        if f is None:
            self.statusBar().showMessage("no function here", 3000)
            return None
        self.call_graph_dialog = CallGraphDialog(self, f.addr)
        self.call_graph_dialog.show()
        return self.call_graph_dialog

    def show_structs(self):
        """The structures window (one per main window, refreshed when shown)."""
        from .structs import StructsDialog
        if getattr(self, "structs_dialog", None) is None:
            self.structs_dialog = StructsDialog(self)
        else:
            self.structs_dialog.refresh()
        self.structs_dialog.show()
        self.structs_dialog.raise_()
        return self.structs_dialog

    def show_python_console(self):
        d = self.findChild(QDockWidget, "Python")
        d.show()
        d.raise_()
        self.pyconsole.line.setFocus()

    def _load_plugins(self):
        from ..scripting import load_plugins
        self.plugin_names, failed = load_plugins(self)
        if not self.plugin_names and not failed:
            self.plugins_menu.addAction("(no plugins: RELIC_PLUGINS or ~/.relic/plugins)").setEnabled(False)
        for name, err in failed:
            self.report_plugin_error(name, err)

    def add_plugin_action(self, text: str, slot, shortcut: str | None = None) -> QAction:
        a = QAction(text, self)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
            a.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        a.triggered.connect(slot)
        self.plugins_menu.addAction(a)
        return a

    def add_line_decorator(self, fn):
        self.disasm.decorators.append(fn)
        if self.an is not None:
            self.disasm.reload()

    def _run_hooks(self, kind: str, *args):
        if not self.plugin_hooks[kind] or self.an is None:
            return
        from ..scripting import namespace
        ns = namespace(self.an, self)
        for fn in list(self.plugin_hooks[kind]):
            fn(ns, *args)

    def report_plugin_error(self, plugin: str, error: str):
        self.pyconsole.append(f"[plugin {plugin}] {error}\n")
        self.statusBar().showMessage(f"plugin {plugin} failed (see the Python console)", 6000)

    # ------------------------------------------------------------------ patching
    def _patch_target(self) -> int | None:
        """The instruction under the cursor (listing / graph), or the cursor address."""
        return self.cur if self.an is not None else None

    def patch(self, addr: int, data: bytes) -> bool:
        """Write bytes at `addr`, re-analyse, refresh the views (the cursor stays)."""
        from ..patch import PatchError
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            old = self.an.patch(addr, data)
        except PatchError as e:
            QApplication.restoreOverrideCursor()
            self.statusBar().showMessage(f"patch: {e}", 6000)
            return False
        QApplication.restoreOverrideCursor()
        self._after_patch(addr)
        self.statusBar().showMessage(f"patched {addr:#x}: {old.hex(' ')} -> {data.hex(' ')}", 6000)
        return True

    def patch_with(self, how: str) -> bool:
        """NOP the instruction at the cursor, or invert its conditional branch."""
        from ..patch import PatchError, invert_bytes, nop_bytes
        a = self._patch_target()
        if a is None:
            return False
        try:
            data = nop_bytes(self.an, a) if how == "nop" else invert_bytes(self.an, a)
        except PatchError as e:
            self.statusBar().showMessage(f"patch: {e}", 6000)
            return False
        return self.patch(a, data)

    def patch_bytes_dialog(self):
        from ..patch import PatchError, parse_hex
        a = self._patch_target()
        if a is None:
            return
        i = self.an.dis.decode(a)
        text, ok = QInputDialog.getText(self, "Patch bytes", f"Bytes at {a:#x} (hex):",
                                        text=i.raw.hex(" ") if i is not None else "")
        if ok and text.strip():
            try:
                self.patch(a, parse_hex(text))
            except PatchError as e:
                self.statusBar().showMessage(f"patch: {e}", 6000)

    def assemble_dialog(self):
        from ..patch import PatchError, assemble, fit
        a = self._patch_target()
        if a is None:
            return
        i = self.an.dis.decode(a)
        text, ok = QInputDialog.getText(self, "Assemble", f"Instructions at {a:#x} (`;` between them):",
                                        text=f"{i.mnemonic} {i.op_str}".strip() if i is not None else "")
        if ok and text.strip():
            try:
                self.patch(a, fit(self.an, a, assemble(self.an, a, text)))
            except PatchError as e:
                self.statusBar().showMessage(f"assemble: {e}", 6000)

    def revert_patch_here(self) -> bool:
        a = self._patch_target()
        if a is None:
            return False
        start = next((p for p, (_, new) in self.an.patches.items() if p <= a < p + len(new)), None)
        if start is None:
            self.statusBar().showMessage("no patch here", 3000)
            return False
        self.an.revert(start)
        self._after_patch(a)
        self.statusBar().showMessage(f"reverted the patch at {start:#x}", 4000)
        return True

    def undo_patch(self) -> bool:
        """Undo the last patch or revert (Ctrl+Z); the cursor goes to it."""
        if self.an is None:
            return False
        addr = self.an.undo_patch()
        if addr is None:
            self.statusBar().showMessage("nothing to undo", 3000)
            return False
        self._after_patch(addr)
        self.statusBar().showMessage(f"undid the patch edit at {addr:#x}", 4000)
        return True

    def redo_patch(self) -> bool:
        if self.an is None:
            return False
        addr = self.an.redo_patch()
        if addr is None:
            self.statusBar().showMessage("nothing to redo", 3000)
            return False
        self._after_patch(addr)
        self.statusBar().showMessage(f"redid the patch edit at {addr:#x}", 4000)
        return True

    def export_patched_dialog(self):
        from ..patch import export
        if self.an is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export patched file", self.an.bin.path + ".patched")
        if path:
            try:
                export(self.an.bin, path)
            except OSError as e:
                QMessageBox.warning(self, "Relic", f"cannot write {path}: {e}")
                return
            self.statusBar().showMessage(f"wrote {path} ({len(self.an.patches)} patches)", 5000)

    def _after_patch(self, keep: int | None):
        """The analysis was redone in place: functions, blocks and xrefs are new objects."""
        self.disasm.func = self.graph.func = None
        self.decomp.func = None
        self.decomp.invalidate(reload=False)
        self._fill_functions()
        self._fill_tables(self._last_checksec)
        self.dirty = True
        self.setWindowTitle(self.windowTitle().rstrip(" *") + " *")
        if keep is not None:
            self.goto(keep, record=False)
        self._run_hooks("analysis")

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
        r = QMessageBox.question(self, "Relic", "Save renames, comments and patches to the project file?",
                                 QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard
                                 | QMessageBox.StandardButton.Cancel)
        if r == QMessageBox.StandardButton.Save:
            return self.save_project()
        return r == QMessageBox.StandardButton.Discard

    CLOSE_WAIT_MS = 2000

    def closeEvent(self, e):
        if not self._closing and not self._confirm_discard():
            e.ignore()
            return
        # running work is cancelled, not waited for: it stops at its next checkpoint, which is
        # normally within milliseconds; if it takes longer the window goes away now and the
        # close completes when the thread ends (a QThread must not be destroyed while running)
        running = self.running_work()
        for t in running:
            t.cancel()
        for t in running:
            t.wait(self.CLOSE_WAIT_MS)
        if self.running_work():
            self._closing = True
            self.hide()
            e.ignore()
            return
        self.decomp.shutdown()
        self.dbg.shutdown()
        self._save_layout()
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


def _short(v) -> str:
    text = repr(v)
    return text if len(text) <= 60 else text[:57] + "..."

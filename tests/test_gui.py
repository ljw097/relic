"""GUI smoke tests (offscreen Qt platform)."""
import os
import shutil

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# keep the tests away from the user's real settings (recent files, window layout)
os.environ["RELIC_SETTINGS"] = os.path.join(__import__("tempfile").mkdtemp(), "relic-test.ini")
pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)  # also missing libEGL etc.

from PySide6.QtCore import QEvent, Qt  # noqa: E402
from PySide6.QtGui import QKeyEvent  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from relic.gui.main_window import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def win(app, vuln64, tmp_path):
    path = tmp_path / "vuln64"
    shutil.copy(vuln64, path)  # project file is written next to the binary
    w = MainWindow()
    w.open_file(str(path))
    assert w.wait()
    assert w.an is not None
    yield w
    w.dirty = False
    w.close()


def _rows(table):
    m = table.model_
    return [[m.item(r, c).text() for c in range(m.columnCount())] for r in range(m.rowCount())]


def test_opens_at_main_and_fills_tables(win):
    an = win.an
    assert win.cur == an.function_by_name("main").addr
    assert "main:" in win.disasm.toPlainText()
    names = [r[0] for r in _rows(win.funcs.table)]
    assert "vuln" in names and "classify" in names
    assert any("gets()" in r[4] for r in _rows(win.vulns))
    assert any(r[2] == "gets" for r in _rows(win.imports.table))
    assert any("hello %s" in r[3] for r in _rows(win.strings.table))
    assert _rows(win.checksec)


def test_navigation_history(win):
    start = win.cur
    assert win.goto_text("vuln")
    vuln = win.an.function_by_name("vuln").addr
    assert win.cur == vuln and "call gets" in win.disasm.toPlainText()
    assert vuln in win.graph.nodes
    win.go_back()
    assert win.cur == start
    win.go_forward()
    assert win.cur == vuln
    assert not win.goto_text("no_such_symbol")


def test_data_address_opens_hex(win):
    s = next(s for s in win.an.strings if "hello" in s.value)
    assert win.goto(s.addr)
    assert win.tabs.currentIndex() == win.TAB_HEX
    assert f"{s.addr & ~0xF:016x}" in win.hex.toPlainText()


def test_rename_comment_save(win):
    vuln = win.an.function_by_name("vuln").addr
    win.goto(vuln)
    win.rename(vuln, "overflow_me")
    win.comment(vuln, "gets() here")
    text = win.disasm.toPlainText()
    assert "overflow_me:" in text and "; gets() here" in text
    assert "overflow_me" in [r[0] for r in _rows(win.funcs.table)]
    assert win.dirty and win.save_project() and not win.dirty
    assert os.path.exists(win.an.project_path)


def test_xrefs_panel(win):
    win.goto_text("menu")
    win._fill_xrefs(win.an.function_by_name("menu").addr)
    rows = _rows(win.xrefs)
    assert rows and any(r[2].startswith("main") for r in rows)


def test_pseudocode_tab_follows_navigation(win):
    vuln = win.an.function_by_name("vuln").addr
    win.goto(vuln)
    win.toggle_decompile()
    assert win.tabs.currentIndex() == win.TAB_DECOMP
    assert win.decomp.wait_idle()
    text = win.decomp.toPlainText()
    assert text.startswith("void vuln(void)") and "gets(buf_48);" in text
    # navigating while the tab is shown re-decompiles the new function
    win.goto_text("checksum")
    assert win.decomp.wait_idle()
    assert win.decomp.toPlainText().startswith("int checksum(char *a1)")
    win.toggle_decompile()
    assert win.tabs.currentIndex() == win.TAB_DISASM


def test_pseudocode_cursor_syncs_with_listing(win):
    vuln = win.an.function_by_name("vuln")
    win.goto(vuln.addr)
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    # put the pseudocode cursor on the gets() line: the window's current address follows
    row = next(k for k, ln in enumerate(win.decomp.result.lines) if "gets(" in ln.text)
    from PySide6.QtGui import QTextCursor
    win.decomp.setTextCursor(QTextCursor(win.decomp.document().findBlockByNumber(row)))
    gets_addr = win.decomp.result.lines[row].addr
    assert win.cur == gets_addr
    win.tabs.setCurrentIndex(win.TAB_DISASM)
    assert win.disasm.current_line().mnemonic == "call" and win.disasm.current_addr() == gets_addr
    # and back: a listing address maps to the pseudocode line it produced
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    assert win.decomp.textCursor().blockNumber() == row


def test_pseudocode_shows_renames(win):
    win.goto_text("vuln")
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    win.rename(win.an.function_by_name("checksum").addr, "hash_name")
    assert win.decomp.wait_idle()
    assert "hash_name(buf_48)" in win.decomp.toPlainText()


def test_pseudocode_rename_subject_is_word_under_cursor(win):
    win.goto_text("vuln")
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    doc = win.decomp.document()
    row = next(k for k, ln in enumerate(win.decomp.result.lines) if "checksum(" in ln.text)
    col = doc.findBlockByNumber(row).text().index("checksum") + 2
    from PySide6.QtGui import QTextCursor
    cur = QTextCursor(doc.findBlockByNumber(row))
    cur.movePosition(QTextCursor.MoveOperation.Right, n=col)
    win.decomp.setTextCursor(cur)
    assert win._rename_subject() == win.an.function_by_name("checksum").addr
    # a local variable is not a symbol: fall back to the current function
    row = next(k for k, ln in enumerate(win.decomp.result.lines) if "char buf_48" in ln.text)
    cur = QTextCursor(doc.findBlockByNumber(row))
    cur.movePosition(QTextCursor.MoveOperation.Right, n=10)
    win.decomp.setTextCursor(cur)
    assert win._rename_subject() == win.an.function_by_name("vuln").addr


def test_pseudocode_decompiles_in_background(win):
    """The GUI thread only shows a placeholder; the result replaces it when the job is done."""
    win.goto_text("main")
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.busy() or win.decomp.toPlainText().startswith("int main(")
    first = win.decomp.toPlainText()
    assert first.startswith("// decompiling main") or first.startswith("int main(")
    assert win.decomp.wait_idle()
    assert win.decomp.toPlainText().startswith("int main(")


def test_pseudocode_stale_result_is_not_shown(win):
    """Switching function while a job runs shows the newer function, not the old result."""
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    win.goto_text("add_note")
    win.goto_text("classify")          # requested while add_note may still be decompiling
    assert win.decomp.wait_idle()
    assert win.decomp.toPlainText().startswith("int classify(")


def _cursor_on(view, needle, offset=1):
    from PySide6.QtGui import QTextCursor
    doc = view.document()
    row = next(k for k, ln in enumerate(view.result.lines) if needle in ln.text)
    cur = QTextCursor(doc.findBlockByNumber(row))
    cur.movePosition(QTextCursor.MoveOperation.Right, n=doc.findBlockByNumber(row).text().index(needle) + offset)
    view.setTextCursor(cur)


def test_rename_variable_in_pseudocode(win):
    win.goto_text("checksum")
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    _cursor_on(win.decomp, "var_c = 0")
    assert win.decomp.variable_under_cursor() == ("var_c", "var_c")
    assert win.rename_variable("var_c", "hash")
    assert win.decomp.wait_idle()
    text = win.decomp.toPlainText()
    assert "int hash;" in text and "hash ^= 0x1337;" in text and "var_c" not in text
    # the parameter, then an invalid / clashing name is refused
    assert win.rename_variable("a1", "s")
    assert win.decomp.wait_idle()
    assert win.decomp.toPlainText().startswith("int checksum(char *s)")
    assert not win.rename_variable("var_10", "hash")       # taken
    assert not win.rename_variable("var_10", "while")      # keyword
    assert not win.rename_variable("var_10", "2x")         # not an identifier
    # persisted in the project file and restored on load
    assert win.save_project()
    from relic.analysis import Analysis
    from relic.loader import load
    an2 = Analysis(load(win.an.bin.path)).run()
    f = an2.function_by_name("checksum")
    assert an2.var_names[f.addr] == {"var_c": "hash", "a1": "s"}
    # empty name resets
    assert win.rename_variable("var_c", "")
    assert win.decomp.wait_idle()
    assert "var_c" in win.decomp.toPlainText()


def test_comment_shows_in_pseudocode(win):
    win.goto_text("vuln")
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    row = next(k for k, ln in enumerate(win.decomp.result.lines) if "gets(" in ln.text)
    win.comment(win.decomp.result.lines[row].addr, "overflow here")
    assert win.decomp.wait_idle()
    assert "gets(buf_48);  // overflow here" in win.decomp.toPlainText()


def test_word_under_cursor_is_highlighted_with_register_aliases(win):
    from PySide6.QtGui import QTextCursor
    win.goto_text("checksum")
    view = win.disasm
    doc = view.document()
    row = next(k for k in range(doc.blockCount()) if " eax" in doc.findBlockByNumber(k).text())
    text = doc.findBlockByNumber(row).text()
    cur = QTextCursor(doc.findBlockByNumber(row))
    cur.movePosition(QTextCursor.MoveOperation.Right, n=text.index(" eax") + 2)
    view.setTextCursor(cur)
    words = {s.cursor.selectedText() for s in view.extraSelections()[1:]}
    assert "eax" in words and ("rax" in words or "al" in words or len(words) == 1)
    assert len(view.extraSelections()) > 2           # several occurrences, plus the line band
    # pseudocode: a variable
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    assert win.decomp.wait_idle()
    _cursor_on(win.decomp, "var_c = 0")
    assert {s.cursor.selectedText() for s in win.decomp.extraSelections()[1:]} == {"var_c"}
    assert len(win.decomp.extraSelections()) >= 4



def test_recent_files_and_layout_are_remembered(app, win):
    path = os.path.abspath(win.an.bin.path)
    assert win.recent_files()[0]["path"] == path
    labels = [a.text() for a in win.recent_menu.actions()]
    assert labels and labels[0].startswith(path)
    # the dock layout survives a restart
    xr = win.xrefs_dock
    xr.hide()
    win.dirty = False
    win.close()
    w2 = MainWindow()
    try:
        assert w2.recent_files()[0]["path"] == path
        assert w2.xrefs_dock.isHidden()
    finally:
        w2.close()


def _slow_analyze(path, arch=None, base=0):
    """An analysis that only ends when cancelled (checks in like the real one)."""
    import time

    from relic.progress import checkpoint, report
    k = 0
    while True:
        report("functions", k)
        checkpoint()
        time.sleep(0.01)
        k += 1


def _spin(app, cond, ms=5000):
    import time
    end = time.monotonic() + ms / 1000
    while not cond() and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)
    return cond()


def test_vulns_scan_failure_is_not_shown_as_no_findings(app, vuln64, tmp_path, monkeypatch):
    from relic.analysis import Analysis

    def boom(self):
        raise RuntimeError("scanner exploded")
    monkeypatch.setattr(Analysis, "vulns", boom)
    path = tmp_path / "vuln64"
    shutil.copy(vuln64, path)
    w = MainWindow()
    w.open_file(str(path))
    assert w.wait()
    rows = _rows(w.vulns)
    assert len(rows) == 1 and rows[0][0] == "error" and "scan failed: RuntimeError: scanner exploded" in rows[0][4]
    w.close()


def test_analysis_progress_and_cancel(app, vuln64, tmp_path, monkeypatch):
    import relic.analysis
    monkeypatch.setattr(relic.analysis, "analyze", _slow_analyze)
    w = MainWindow()
    w.open_file(str(vuln64))
    assert _spin(app, lambda: "functions" in w.progress.format())    # progress reaches the status bar
    assert w.progress.isVisibleTo(w) and w.cancel_button.isVisibleTo(w)
    w.cancel_work()
    assert w.wait(5000)
    assert _spin(app, lambda: not w.progress.isVisibleTo(w))
    assert w.an is None and w.windowTitle() == "Relic"
    w.close()


def test_close_does_not_wait_for_a_long_analysis(app, vuln64, monkeypatch):
    import time

    import relic.analysis
    monkeypatch.setattr(relic.analysis, "analyze", _slow_analyze)
    w = MainWindow()
    w.show()
    w.open_file(str(vuln64))
    assert _spin(app, lambda: w.running_work() != [])
    t = time.monotonic()
    w.close()
    assert time.monotonic() - t < 1.5                  # cancelled, not waited for
    assert not w.running_work() and not w.isVisible()


def test_decompilation_is_cancellable(vuln64):
    from relic.analysis import analyze
    from relic.decompiler.emit import decompile
    from relic.progress import Cancelled, Progress
    an = analyze(vuln64)
    token = Progress()
    token.cancel()
    handle = token.activate()
    try:
        with pytest.raises(Cancelled):
            decompile(an, an.function_by_name("main"))
    finally:
        Progress.deactivate(handle)
    assert decompile(an, an.function_by_name("main")).text      # no token: unaffected


def test_close_completes_after_slow_checkpoint(app, vuln64, monkeypatch):
    """Work that takes a while to reach its next checkpoint: the window hides at once and the
    close finishes when the thread has stopped (never destroying a running QThread)."""
    import time

    import relic.analysis
    from relic.progress import checkpoint

    def sluggish(path, arch=None, base=0):
        while True:
            time.sleep(0.4)
            checkpoint()
    monkeypatch.setattr(relic.analysis, "analyze", sluggish)
    monkeypatch.setattr(MainWindow, "CLOSE_WAIT_MS", 50)
    w = MainWindow()
    w.show()
    w.open_file(str(vuln64))
    assert _spin(app, lambda: w.running_work() != [])
    w.close()
    assert not w.isVisible() and w._closing
    assert _spin(app, lambda: not w.running_work())
    app.processEvents()
    assert not w.isVisible()


def test_theme_and_font_size_switch_and_persist(app, win):
    from relic.gui import views
    try:
        win.set_appearance(theme="light")
        assert views.current_theme() == "light" and views.THEME["bg"] == views.THEMES["light"]["bg"]
        for v in (win.disasm, win.decomp, win.hex):
            assert views.THEMES["light"]["bg"] in v.styleSheet()
        assert win.light_act.isChecked()
        assert app.palette().color(app.palette().ColorRole.Base).name() == views.THEMES["light"]["bg"]
        size = views.font_size()
        win.set_appearance(size=size + 3)
        assert win.disasm.font().pointSize() == size + 3 and win.decomp.font().pointSize() == size + 3
        win.set_appearance(size=1000)
        assert views.font_size() == views.FONT_SIZES[1]
        # a new window starts with the remembered appearance
        w2 = MainWindow()
        assert views.current_theme() == "light" and w2.disasm.font().pointSize() == views.FONT_SIZES[1]
        w2.close()
    finally:
        win.set_appearance(theme="dark", size=views.DEFAULT_FONT_SIZE)
    assert views.THEME["bg"] == views.THEMES["dark"]["bg"] and views.font_size() == views.DEFAULT_FONT_SIZE


def test_graph_keeps_its_selection_across_a_restyle(win):
    from relic.gui import views
    win.goto(win.an.function_by_name("vuln").addr)
    win.tabs.setCurrentIndex(win.TAB_GRAPH)
    win.graph.show_function(win.an, win.an.function_by_name("vuln"))
    sel = [a for a, n in win.graph.nodes.items() if n.selected]
    try:
        win.set_appearance(theme="light")
        assert [a for a, n in win.graph.nodes.items() if n.selected] == sel
        assert win.graph.backgroundBrush().color().name() == views.THEMES["light"]["bg"]
    finally:
        win.set_appearance(theme="dark")


def test_search_panel(app, win):
    assert win.search("insn", r"call\s+gets")
    assert win.wait()
    rows = _rows(win.search_results)
    assert rows and "vuln+0x" in rows[0][1] and "call gets" in rows[0][2]
    assert not win.search("imm", "not-a-number")
    assert win.search("bytes", "e8 ?? ?? ?? ??") and win.wait()
    assert len(_rows(win.search_results)) > 5


def _debug_wait(app, win, cond, ms=20000):
    return _spin(app, lambda: win.dbg.idle and cond(), ms)


def test_debugger_panels_breakpoints_and_console(app, win):
    from test_debugger import _can_debug
    if not _can_debug():
        pytest.skip("gdb with ptrace permission is needed")
    an = win.an
    win.dbg_args = ["5"]
    vuln = an.function_by_name("vuln").addr
    win.goto(vuln)
    win.debug_toggle_breakpoint()                       # before starting: applied at start
    assert vuln in win.dbg.static_bps
    win.debug_start()
    assert _debug_wait(app, win, lambda: win.dbg_regs.rowCount() > 0)
    assert all(d.isVisibleTo(win) for d in win.dbg_docks)
    assert win.dbg_docks[1] not in win.tabifiedDockWidgets(win.dbg_docks[0])    # stack beside registers
    win.debug_start_or_continue()                       # F9: continue to the breakpoint
    assert _debug_wait(app, win, lambda: win.disasm.debug_pc == vuln)
    assert win.cur == vuln
    assert win.dbg_bps.rowCount() == 1 and win.dbg_bps.item(0, 3).text() == "vuln"
    assert win.dbg_bps.item(0, 5).text() == "1"
    assert win.dbg_regs.rowCount() >= 16 and win.dbg_regs.item(0, 0).text() == "rax"
    assert win.dbg_stack.rowCount() == 16 and "main+" in win.dbg_stack.item(0, 2).text()
    assert win.dbg_bt.item(0, 2).text() == "vuln"
    assert "►" in win.dbg_code.toPlainText()
    # memory view follows the stack pointer; vmmap lists the binary, stack and libc
    rsp = next(int(win.dbg_regs.item(k, 1).text(), 16) for k in range(win.dbg_regs.rowCount())
               if win.dbg_regs.item(k, 0).text() == "rsp")
    assert _debug_wait(app, win, lambda: win.dbg_mem.addr == rsp)
    assert win.dbg_mem.text.toPlainText().startswith(f"{rsp:#014x}")
    paths = [win.dbg_vmmap.item(k, 5).text() for k in range(win.dbg_vmmap.rowCount())]
    assert "[stack]" in paths and any(p.endswith("vuln64") for p in paths)
    win.dbg_mem.where.setText("$rsp+0x10")
    win.dbg_mem._go()
    assert _debug_wait(app, win, lambda: win.dbg_mem.addr == rsp + 0x10)
    row = next(k for k in range(win.dbg_regs.rowCount()) if win.dbg_regs.item(k, 0).text() == "rip")
    win.goto(an.function_by_name("main").addr)
    win._debug_follow(win.dbg_regs, row, 1)             # code of the binary: the listing
    assert win.cur == vuln
    win._debug_follow(win.dbg_vmmap, paths.index("[stack]"), 0)    # a mapping: the memory view
    assert _debug_wait(app, win, lambda: win.dbg_mem.label.text().endswith("[stack]"))
    win.dbg.step_over()
    assert _debug_wait(app, win, lambda: win.disasm.debug_pc not in (None, vuln))
    win.dbg_console.stdin.setText("relic")
    win.dbg_console._send_stdin()
    win.dbg_console.cmd.setText("info registers rip")
    win.dbg_console._send_cmd()
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: "exited" in win.dbg_console.out.toPlainText())
    text = win.dbg_console.out.toPlainText()
    assert "hello relic" in text and "gdb> info registers rip" in text and "exited" in text
    win.dbg.stop()
    assert _debug_wait(app, win, lambda: win.dbg.session is None)
    # breakpoints panel: disable and add a condition (kept for the next run)
    win.dbg_bps.item(0, 0).setCheckState(Qt.CheckState.Unchecked)
    win.dbg_bps.item(0, 4).setText("$rdi == 1")
    bp = win.dbg.static_bps[vuln]
    assert not bp.enabled and bp.condition == "$rdi == 1"
    assert vuln not in win.disasm.debug_bps


def test_debugger_watchpoints_and_library_breakpoints(app, win):
    from test_debugger import _can_debug
    if not _can_debug():
        pytest.skip("gdb with ptrace permission is needed")
    from relic.gui.main_window import WatchDialog
    an = win.an
    notes = an.resolve("notes")
    # the watch dialog offers the global the cursor's instruction refers to
    add_note = an.function_by_name("add_note")
    win.goto(next(x.frm for x in an.xrefs_to[notes] if an.function_at(x.frm) is add_note))
    assert win._debug_watch_default() == "notes"
    dlg = WatchDialog(win, "notes")
    dlg.access.setCurrentText("read")
    dlg.size.setCurrentIndex(3)
    assert dlg.values() == ("notes", "read", 4)
    # set before the program runs: applied at start, a library function stops inside libc
    win.debug_break_at("puts")
    win.debug_break_at("add_note")
    win.debug_watch("notes", "write")
    assert [win.dbg_bps.item(k, 1).text() for k in range(3)] == ["break", "break", "write watch"]
    assert win.dbg_bps.item(0, 3).text() == "add_note" and win.dbg_bps.item(1, 3).text() == "puts"
    assert add_note.addr in win.dbg.static_bps
    win.debug_start()
    assert _debug_wait(app, win, lambda: win.dbg_regs.rowCount() > 0)
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: "puts" in win.dbg_bt.item(0, 2).text())
    assert win.dbg.last.pc_static is None                   # in libc, not at the PLT stub
    win.dbg_bps.selectRow(1)                       # Delete on the puts row
    win.dbg_bps.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Delete, Qt.KeyboardModifier.NoModifier))
    assert win.dbg_bps.rowCount() == 2 and "puts" not in win.dbg.other_bps
    win.dbg.send_input("1\n8\nAAAA\n4\n")
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: win.disasm.debug_pc == add_note.addr)
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: "[ watchpoint " in win.dbg_console.out.toPlainText())
    assert an.function_at(win.cur) is add_note
    assert win.dbg.last.stop.startswith("watchpoint ") and ": 0 -> " in win.dbg.last.stop
    assert win.dbg.last.reason == "watchpoint-trigger"
    assert win.dbg_bps.item(1, 5).text() == "1"
    win.dbg_bps.item(1, 0).setCheckState(Qt.CheckState.Unchecked)
    assert not win.dbg.other_bps["write:notes"].enabled
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: "exited" in win.dbg_console.out.toPlainText())
    win.dbg.stop()
    assert _debug_wait(app, win, lambda: win.dbg.session is None)


def test_debugger_pseudocode_marks_and_editing(app, win):
    from test_debugger import _can_debug
    if not _can_debug():
        pytest.skip("gdb with ptrace permission is needed")
    an = win.an
    win.dbg_args = ["5"]
    classify = an.function_by_name("classify").addr
    win.goto(classify)
    win.debug_toggle_breakpoint()
    win.toggle_decompile()
    assert win.decomp.wait_idle()
    pc_row, bp_rows = win.decomp.debug_rows()
    assert pc_row is None and bp_rows == [0]                 # the signature line stands for the entry
    win.debug_start()
    assert _debug_wait(app, win, lambda: win.dbg_regs.rowCount() > 0)
    win.dbg.send_input("x\n")
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: win.decomp.debug_pc == classify)
    assert win.decomp.wait_idle() and win.decomp.func.addr == classify
    assert win.decomp.debug_rows() == (0, [0])
    from PySide6.QtGui import QColor
    from relic.gui.views import THEME
    marks = [s.cursor.blockNumber() for s in win.decomp.extraSelections()
             if s.format.background().color() == QColor(THEME["pc_line"])]
    assert marks == [0]

    def reg(name):
        return next(int(win.dbg_regs.item(k, 1).text(), 16) for k in range(win.dbg_regs.rowCount())
                    if win.dbg_regs.item(k, 0).text() == name)
    assert reg("rdi") == 5
    win.dbg.set_register("rdi", "0")                          # classify(0) returns 10
    assert _debug_wait(app, win, lambda: reg("rdi") == 0)
    win.dbg.write_memory("$rsp-0x40", '"relic"')
    assert _debug_wait(app, win, lambda: "|relic" in win.dbg_mem.text.toPlainText())
    assert "wrote 5 bytes" in win.dbg_console.out.toPlainText()
    win.debug_start_or_continue()
    assert _debug_wait(app, win, lambda: "exited with code 10" in win.dbg_console.out.toPlainText())
    win.dbg.stop()
    assert _debug_wait(app, win, lambda: win.dbg.session is None)


def test_patching_inverts_nops_reverts_and_exports(app, win, tmp_path):
    an = win.an
    main = an.function_by_name("main")
    cj = next(i for b in sorted(main.blocks.values(), key=lambda b: b.addr) for i in b.insns if i.kind == "cjmp")
    before = cj.mnemonic
    win.goto(cj.addr)
    assert win.patch_with("invert")
    assert win.an is an and an.dis.decode(cj.addr).mnemonic != before and cj.addr in an.patches
    assert win.cur == cj.addr and "*" in win.windowTitle()
    assert "patched (was " in win.disasm.toPlainText()
    assert not win.patch_with("invert") or an.dis.decode(cj.addr).mnemonic == before   # twice: back
    win.goto(an.function_by_name("vuln").addr)
    gets_call = next(i for b in an.function_at(win.cur).blocks.values() for i in b.insns
                     if i.kind == "call" and an.call_name(i) == "gets")
    win.goto(gets_call.addr)
    assert win.patch_with("nop")
    assert all(an.dis.decode(a).mnemonic == "nop" for a in range(gets_call.addr, gets_call.end))
    win.toggle_decompile()
    assert win.decomp.wait_idle() and "gets(" not in win.decomp.toPlainText()
    win.toggle_decompile()
    out = tmp_path / "patched"
    from relic.patch import export
    export(an.bin, str(out))
    assert out.read_bytes() != open(an.bin.path, "rb").read() and os.access(out, os.X_OK)
    assert win.revert_patch_here() and gets_call.addr not in an.patches
    assert an.dis.decode(gets_call.addr).kind == "call"
    win.save_project()
    import json
    saved = json.load(open(an.project_path))["patches"]
    assert list(saved) == list({f"{a:#x}" for a in an.patches})


def test_python_console_and_plugins(app, vuln64, tmp_path, monkeypatch):
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / "mark.py").write_text(
        "def register(api):\n"
        "    def run(ns):\n"
        "        ns['comment'](ns['here'](), 'seen by a plugin')\n"
        "    api.add_action('Mark here', run, 'Ctrl+Alt+M')\n")
    (plugins / "broken.py").write_text("raise RuntimeError('boom')\n")
    monkeypatch.setenv("RELIC_PLUGINS", str(plugins))
    path = tmp_path / "vuln64"
    shutil.copy(vuln64, path)
    w = MainWindow()
    try:
        w.open_file(str(path))
        assert w.wait()
        assert w.plugin_names == ["mark"]
        assert "[plugin broken]" in w.pyconsole.out.toPlainText() and "boom" in w.pyconsole.out.toPlainText()
        act = next(a for a in w.plugins_menu.actions() if a.text() == "Mark here")
        act.trigger()
        assert w.an.comments.get(w.cur) == "seen by a plugin" and "seen by a plugin" in w.disasm.toPlainText()
        w.show_python_console()
        out = w.pyconsole.run("hex(here()) == hex(an.function_by_name('main').addr)")
        assert out.strip() == "True"
        w.pyconsole.run("goto('vuln')")
        assert w.cur == w.an.function_by_name("vuln").addr
        w.pyconsole.line.setText("rename(here(), 'pwnme')")
        w.pyconsole._enter()
        assert w.an.name(w.cur) == "pwnme" and w.pyconsole.line.history == ["rename(here(), 'pwnme')"]
    finally:
        w.dirty = False
        w.close()

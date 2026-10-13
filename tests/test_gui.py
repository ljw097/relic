"""GUI smoke tests (offscreen Qt platform)."""
import os
import shutil

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# keep the tests away from the user's real settings (recent files, window layout)
os.environ["RELIC_SETTINGS"] = os.path.join(__import__("tempfile").mkdtemp(), "relic-test.ini")
pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)  # also missing libEGL etc.

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

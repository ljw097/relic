"""GUI smoke tests (offscreen Qt platform)."""
import os
import shutil

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
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
    text = win.decomp.toPlainText()
    assert text.startswith("void vuln(void)") and "gets(buf_48);" in text
    # navigating while the tab is shown re-decompiles the new function
    win.goto_text("checksum")
    assert win.decomp.toPlainText().startswith("int checksum(char *a1)")
    win.toggle_decompile()
    assert win.tabs.currentIndex() == win.TAB_DISASM


def test_pseudocode_cursor_syncs_with_listing(win):
    vuln = win.an.function_by_name("vuln")
    win.goto(vuln.addr)
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
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
    assert win.decomp.textCursor().blockNumber() == row


def test_pseudocode_shows_renames(win):
    win.goto_text("vuln")
    win.tabs.setCurrentIndex(win.TAB_DECOMP)
    win.rename(win.an.function_by_name("checksum").addr, "hash_name")
    assert "hash_name(buf_48)" in win.decomp.toPlainText()

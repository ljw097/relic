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

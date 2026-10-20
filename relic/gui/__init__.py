"""PySide6 front end. `run(path)` opens the main window."""
from __future__ import annotations

import sys


def run(path: str | None = None, arch: str | None = None, base: int = 0) -> int:
    # (Qt imported here: the Qt-free modules, `layout`, import without PySide6's libraries)
    from PySide6.QtWidgets import QApplication

    from .main_window import MainWindow, apply_theme

    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("Relic")
    apply_theme(app)
    win = MainWindow()
    win.resize(1400, 900)
    win.show()
    if path:
        win.open_file(path, arch, base)
    else:
        win.statusBar().showMessage("Open a binary: File > Open (Ctrl+O), File > Open Recent, or drop it on the window")
    return app.exec()


__all__ = ["run"]

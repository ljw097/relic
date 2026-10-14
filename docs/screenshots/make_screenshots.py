"""Regenerate the README screenshots: `python docs/screenshots/make_screenshots.py [out_dir]`.

Runs the GUI offscreen on tests/bins/vuln64.out (build it by running the test suite once) and
needs gdb for the debugger shots. The binary is copied to a temporary directory so the program
path in the console stays short and no project file lands next to the test binary.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else HERE)
WORK = tempfile.mkdtemp(prefix="relic-shots-")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["RELIC_SETTINGS"] = os.path.join(WORK, "relic.ini")      # default layout, no saved state
sys.path.insert(0, ROOT)

from PySide6.QtWidgets import QApplication, QDockWidget  # noqa: E402

app = QApplication([])

from relic.gui.main_window import MainWindow  # noqa: E402

AFTER_GETS = 0x401633          # `lea rax, [rbp - 0x40]` right after `call gets` in vuln()


def pump(cond, timeout=30.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


def settle(n=30):
    for _ in range(n):
        app.processEvents()
        time.sleep(0.01)


def main():
    shutil.copy(os.path.join(ROOT, "tests", "bins", "vuln64.out"), os.path.join(WORK, "vuln64"))
    os.chdir(WORK)
    os.makedirs(OUT, exist_ok=True)
    w = MainWindow()
    w.resize(1600, 960)
    w.show()
    w.open_file("./vuln64")
    assert w.wait()
    w.set_appearance("dark", 10)
    an = w.an
    func = lambda name: an.function_by_name(name).addr  # noqa: E731

    def shot(name):
        settle()
        w.grab().save(os.path.join(OUT, name))
        print("saved", name)

    w.goto(func("vuln"))
    w.tabs.setCurrentIndex(w.TAB_DISASM)
    shot("listing.png")
    w.goto(func("main"))
    w.tabs.setCurrentIndex(w.TAB_GRAPH)
    shot("graph.png")
    w.goto(func("classify"))
    w.tabs.setCurrentIndex(w.TAB_DECOMP)
    pump(lambda: "switch" in w.decomp.toPlainText())
    shot("pseudocode.png")
    w.tabs.setCurrentIndex(w.TAB_DISASM)
    w.goto(func("show_note"))
    w.findChild(QDockWidget, "Vulns").raise_()
    pump(lambda: w.wait(100))
    shot("vulns.png")

    w.set_appearance("light", 10)
    w.tabs.setCurrentIndex(w.TAB_DECOMP)
    w.goto(func("vuln"))
    pump(lambda: "gets" in w.decomp.toPlainText())
    shot("light.png")
    w.set_appearance("dark", 10)
    w.tabs.setCurrentIndex(w.TAB_DISASM)
    w.xrefs_dock.raise_()

    # the README walkthrough: break in vuln(), run to just after gets(), feed it a line
    w.dbg_args = ["5"]
    w.goto(func("vuln"))
    w.debug_toggle_breakpoint()
    w.debug_start()
    pump(lambda: w.dbg_regs.rowCount() > 0 and w.dbg.idle)
    w.debug_start_or_continue()
    pump(lambda: w.disasm.debug_pc == func("vuln") and w.dbg.idle)
    w.goto(AFTER_GETS)
    w.debug_run_to_cursor()
    settle(20)
    w.dbg.send_input("AAAAAAAABBBBBBBB\n")
    pump(lambda: w.disasm.debug_pc == AFTER_GETS and w.dbg.idle)
    settle(50)
    w.dbg_docks[2].raise_()            # console
    shot("debugger.png")
    w.dbg_docks[5].raise_()            # memory
    w.dbg.view_memory("$rbp-0x40")
    pump(lambda: w.dbg.idle)
    w.dbg_docks[1].raise_()            # stack
    shot("debugger-memory.png")
    w.dbg.stop()
    pump(lambda: w.dbg.idle)
    w.dirty = False
    w.dbg.shutdown()
    w.close()
    shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()

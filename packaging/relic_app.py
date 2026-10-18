"""Entry point of the stand-alone executables (PyInstaller): with no arguments the GUI opens
empty -- a file is opened from it later -- and every `relic` command works as usual."""
import multiprocessing
import sys

from relic.__main__ import main


def _console():
    """Windows GUI build (no console of its own): run from a terminal with a command, print to
    that terminal."""
    if sys.platform != "win32" or sys.stdout is not None or len(sys.argv) < 2:
        return
    import ctypes
    if ctypes.windll.kernel32.AttachConsole(-1):          # ATTACH_PARENT_PROCESS
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        sys.stderr = sys.stdout
    else:
        import io
        sys.stdout = sys.stderr = io.StringIO()              # (double-clicked with arguments)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    _console()
    sys.exit(main())

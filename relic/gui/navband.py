"""The navigation band (IDA's): the whole loaded image as one strip coloured by what each part
is, with the current position marked; click or drag to go there."""
from __future__ import annotations

import bisect

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QWidget

from .views import THEME

COLORS = {"code": "mnem", "library": "edge_true", "import": "call", "data": "addr", "unexplored": "label"}


class NavBand(QWidget):
    navigate = Signal(object)          # address (Qt ints are 32-bit)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(14)
        self.regions: list[tuple[int, int, str]] = []
        self._offsets: list[int] = []      # running size before each region (sections side by side)
        self.total = 0
        self.cur: int | None = None
        self.setToolTip("navigation band: function code, library code, imports, data, unexplored code")

    def set_analysis(self, an):
        from ..analysis.navband import band_regions
        self.regions = band_regions(an) if an is not None else []
        self._offsets, t = [], 0
        for s, e, _ in self.regions:
            self._offsets.append(t)
            t += e - s
        self.total = t
        self.update()

    def set_current(self, addr: int | None):
        self.cur = addr
        self.update()

    def x_of(self, addr: int) -> float | None:
        starts = [r[0] for r in self.regions]
        k = bisect.bisect_right(starts, addr) - 1
        if k < 0 or not self.total or addr >= self.regions[k][1]:
            return None
        return (self._offsets[k] + addr - self.regions[k][0]) / self.total * self.width()

    def addr_at(self, x: float) -> int | None:
        if not self.total:
            return None
        pos = max(0, min(int(x / max(self.width(), 1) * self.total), self.total - 1))
        k = bisect.bisect_right(self._offsets, pos) - 1
        s, e, _ = self.regions[k]
        return min(s + pos - self._offsets[k], e - 1)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(THEME["window"]))
        if not self.total:
            return
        w, h = self.width(), self.height()
        for (s, e, kind), off in zip(self.regions, self._offsets):
            x0 = off / self.total * w
            x1 = (off + e - s) / self.total * w
            p.fillRect(int(x0), 2, max(int(x1) - int(x0), 1), h - 4, QColor(THEME[COLORS[kind]]))
        if self.cur is not None:
            x = self.x_of(self.cur)
            if x is not None:
                p.fillRect(int(x) - 1, 0, 3, h, QColor(THEME["jump"]))

    def mousePressEvent(self, e):
        self._go(e)

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.MouseButton.LeftButton:
            self._go(e)

    def _go(self, e):
        a = self.addr_at(e.position().x())
        if a is not None:
            self.navigate.emit(a)

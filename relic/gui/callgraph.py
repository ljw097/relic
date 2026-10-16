"""The call graph window (View > Call graph): callers left, callees right; double-click a
function to go there, or to centre the graph on it with Shift."""
from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QBrush, QColor, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (QDialog, QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsView, QHBoxLayout, QLabel,
                               QSpinBox, QVBoxLayout)

from .views import THEME, mono_font

COL_W, ROW_H, PAD = 240, 34, 8


class CallGraphDialog(QDialog):
    def __init__(self, win, addr: int):
        super().__init__(win)
        self.win = win
        self.addr = addr
        self.resize(900, 560)
        self.depth = QSpinBox()
        self.depth.setRange(1, 4)
        self.depth.setValue(1)
        self.depth.valueChanged.connect(lambda _: self.draw())
        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.mouseDoubleClickEvent = self._double_click
        self.note = QLabel()
        top = QHBoxLayout()
        top.addWidget(QLabel("levels"))
        top.addWidget(self.depth)
        top.addWidget(self.note, 1)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.view)
        self.nodes: dict[int, tuple[float, float, float, float]] = {}     # function -> rect
        self.draw()

    def draw(self):
        from ..analysis.callgraph import call_graph
        an = self.win.an
        self.scene.clear()
        self.scene.setBackgroundBrush(QColor(THEME["bg"]))
        self.nodes = {}
        levels, edges, more = call_graph(an, self.addr, self.depth.value())
        self.setWindowTitle(f"Call graph: {an.name(self.addr) or hex(self.addr)}")
        cols: dict[int, list[int]] = {}
        for a, lv in levels.items():
            cols.setdefault(lv, []).append(a)
        font = mono_font()
        for lv, items in cols.items():
            items.sort(key=lambda a: an.name(a) or "")
            x = lv * COL_W
            y0 = -len(items) * ROW_H / 2
            for k, a in enumerate(items):
                name = an.name(a) or an.functions[a].name
                t = QGraphicsSimpleTextItem(name + ("  …" if a in more else ""))
                t.setFont(font)
                f = an.functions[a]
                color = THEME["call"] if f.is_import else THEME["func"] if lv == 0 else THEME["fg"]
                t.setBrush(QBrush(QColor(color)))
                w = min(t.boundingRect().width(), COL_W - 40) + 2 * PAD
                y = y0 + k * ROW_H
                rect = self.scene.addRect(x - w / 2, y, w, ROW_H - 10, QPen(QColor(THEME["node_border"])),
                                          QBrush(QColor(THEME["current"] if lv == 0 else THEME["node"])))
                rect.setZValue(1)
                t.setPos(x - w / 2 + PAD, y + 3)
                t.setZValue(2)
                self.scene.addItem(t)
                self.nodes[a] = (x - w / 2, y, w, ROW_H - 10)
        pen = QPen(QColor(THEME["edge"]))
        for a, b in edges:
            if a not in self.nodes or b not in self.nodes:
                continue
            ax, ay, aw, ah = self.nodes[a]
            bx, by, bw, bh = self.nodes[b]
            p0, p1 = QPointF(ax + aw, ay + ah / 2), QPointF(bx, by + bh / 2)
            if levels[b] <= levels[a]:                        # backwards (recursion, a cycle)
                p0, p1 = QPointF(ax, ay + ah / 2), QPointF(bx + bw, by + bh / 2)
            path = QPainterPath(p0)
            mid = (p0.x() + p1.x()) / 2
            path.cubicTo(QPointF(mid, p0.y()), QPointF(mid, p1.y()), p1)
            self.scene.addPath(path, pen).setZValue(0)
        n_callers = sum(1 for lv in levels.values() if lv < 0)
        n_callees = sum(1 for lv in levels.values() if lv > 0)
        self.note.setText(f"{n_callers} callers, {n_callees} callees"
                          + (" (some levels cut short: …)" if more else "")
                          + "   double-click: go there, Shift+double-click: centre on it")
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))

    def function_at(self, x: float, y: float) -> int | None:
        return next((a for a, (rx, ry, rw, rh) in self.nodes.items()
                     if rx <= x <= rx + rw and ry <= y <= ry + rh), None)

    def _double_click(self, e):
        p = self.view.mapToScene(e.position().toPoint())
        a = self.function_at(p.x(), p.y())
        if a is None:
            return
        if e.modifiers() & Qt.KeyboardModifier.ShiftModifier:
            self.addr = a
            self.draw()
        else:
            self.win.goto(a)

"""Central views: linear disassembly, control-flow graph and hex dump."""
from __future__ import annotations

from PySide6.QtCore import QCoreApplication, QPointF, QRectF, Qt, QThread, Signal
from PySide6.QtGui import (QBrush, QColor, QFont, QFontDatabase, QPainter, QPainterPath, QPen,
                           QSyntaxHighlighter, QTextCharFormat, QTextCursor)
from PySide6.QtWidgets import (QGraphicsItem, QGraphicsPathItem, QGraphicsScene, QGraphicsSimpleTextItem,
                               QGraphicsView, QPlainTextEdit, QTextEdit)

from ..analysis import Analysis
from ..analysis.functions import Function
from ..listing import Line, function_lines, render
from ..progress import Cancelled, Progress

THEMES = {
    "dark": {
        "bg": "#1e1f22", "fg": "#d4d4d4", "addr": "#6c7086", "bytes": "#585b70", "mnem": "#89b4fa",
        "call": "#f9e2af", "jump": "#f38ba8", "ret": "#cba6f7", "comment": "#7fb77e", "label": "#fab387",
        "func": "#a6e3a1", "current": "#2d2f36", "node": "#26272b", "node_border": "#45475a",
        "edge_true": "#7fb77e", "edge_false": "#f38ba8", "edge": "#89b4fa", "word": "#3e4452",
        "window": "#25262b", "selection": "#3b4261", "pc_line": "#24402c", "bp_line": "#4a252b",
    },
    "light": {
        "bg": "#fbfbfa", "fg": "#24292f", "addr": "#8c959f", "bytes": "#a0a7b0", "mnem": "#0550ae",
        "call": "#8a5a00", "jump": "#cf222e", "ret": "#8250df", "comment": "#1a7f37", "label": "#bc4c00",
        "func": "#116329", "current": "#eef2f7", "node": "#ffffff", "node_border": "#c4cbd4",
        "edge_true": "#1a7f37", "edge_false": "#cf222e", "edge": "#0969da", "word": "#dbe7f5",
        "window": "#eff1f3", "selection": "#b6d4fe", "pc_line": "#d3f2d0", "bp_line": "#f9d4d8",
    },
}
# the active colours: one dict changed in place, so every module sees the switch
THEME: dict[str, str] = dict(THEMES["dark"])
_STATE = {"theme": "dark", "font_size": 10}
FONT_SIZES = (6, 28)
DEFAULT_FONT_SIZE = 10


def set_theme(name: str) -> None:
    """Switch the colour theme (views pick it up in `restyle`)."""
    if name not in THEMES:
        raise ValueError(f"unknown theme {name!r}")
    THEME.clear()
    THEME.update(THEMES[name])
    _STATE["theme"] = name


def current_theme() -> str:
    return _STATE["theme"]


def set_font_size(size: int) -> int:
    """Point size of the code views (clamped); returns the size in effect."""
    _STATE["font_size"] = max(FONT_SIZES[0], min(FONT_SIZES[1], int(size)))
    return _STATE["font_size"]


def font_size() -> int:
    return _STATE["font_size"]


def mono_font(size: int | None = None) -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSize(size if size is not None else _STATE["font_size"])
    return f


def _code_style() -> str:
    return (f"QPlainTextEdit {{ background: {THEME['bg']}; color: {THEME['fg']}; "
            f"selection-background-color: {THEME['selection']}; }}")


def _fmt(color: str, bold: bool = False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    return f


_WORD_LIMIT = 2000          # occurrences highlighted at most (huge functions)


def _word_under_cursor(edit: QPlainTextEdit) -> str:
    cur = edit.textCursor()
    cur.select(QTextCursor.SelectionType.WordUnderCursor)
    return cur.selectedText()


def _same_words(word: str) -> list[str]:
    """`word` and the names of the same thing: a register's other widths (rax, eax, ax, al)."""
    from ..analysis.vulns import canon
    base = canon(word)
    if base == word and not word.startswith("r"):
        return [word]
    from ..analysis.vulns import _ALIAS
    return sorted({base, *(k for k, v in _ALIAS.items() if v == base)} | {word})


def _row_and_word_selections(edit: QPlainTextEdit, row: int) -> list:
    """The current-line band plus every occurrence of the word under the cursor."""
    import re
    sel = QTextEdit.ExtraSelection()
    sel.format.setBackground(QColor(THEME["current"]))
    sel.format.setProperty(QTextCharFormat.Property.FullWidthSelection, True)
    sel.cursor = QTextCursor(edit.document().findBlockByNumber(row))
    out = [sel]
    word = _word_under_cursor(edit)
    if len(word) < 2 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", word):
        return out
    rx = re.compile(r"(?<![A-Za-z0-9_.])(" + "|".join(map(re.escape, _same_words(word))) + r")(?![A-Za-z0-9_])")
    fmt = QTextCharFormat()
    fmt.setBackground(QColor(THEME["word"]))
    block = edit.document().firstBlock()
    while block.isValid() and len(out) < _WORD_LIMIT:
        for m in rx.finditer(block.text()):
            ws = QTextEdit.ExtraSelection()
            ws.format = fmt
            c = QTextCursor(block)
            c.setPosition(block.position() + m.start())
            c.setPosition(block.position() + m.end(), QTextCursor.MoveMode.KeepAnchor)
            ws.cursor = c
            out.append(ws)
        block = block.next()
    return out


class ListingHighlighter(QSyntaxHighlighter):
    """Colours a listing produced by `listing.render` using its fixed columns."""

    def __init__(self, doc, view: "DisasmView"):
        super().__init__(doc)
        self.view = view
        self.refresh(rehighlight=False)

    def refresh(self, rehighlight: bool = True):
        """Rebuild the formats from the current theme."""
        self.f = {k: _fmt(v, k in ("func", "label")) for k, v in THEME.items()}
        if rehighlight:
            self.rehighlight()

    def highlightBlock(self, text: str):
        n = self.currentBlock().blockNumber()
        ln = self.view.line_at(n)
        if ln is None:
            return
        if ln.kind == "func":
            self.setFormat(0, len(text), self.f["func"])
            return
        if ln.kind == "label":
            self.setFormat(0, len(text), self.f["label"])
            return
        if ln.kind == "xref":
            self.setFormat(0, len(text), self.f["comment"])
            return
        if ln.kind not in ("insn", "data"):
            return
        c = self.view.columns
        self.setFormat(0, c["bytes"], self.f["addr"])
        self.setFormat(c["bytes"], c["mnem"] - c["bytes"], self.f["bytes"])
        m = ln.mnemonic
        key = "mnem"
        if ln.kind == "data":
            key = "label"
        elif m.startswith("call") or m in ("bl", "blx", "jal", "jalr"):
            key = "call"
        elif m.startswith("j") or m.startswith("b") and m not in ("bswap", "bt", "bts", "btr", "btc", "bsf", "bsr"):
            key = "jump"
        elif m.startswith("ret") or m == "leave":
            key = "ret"
        self.setFormat(c["mnem"], len(m), self.f[key])
        k = text.find("; ", c["mnem"])
        if k >= 0:
            self.setFormat(k, len(text) - k, self.f["comment"])


class DisasmView(QPlainTextEdit):
    """Read-only linear listing of one function; double-click follows references."""

    navigate = Signal(object)       # an address (Qt's int is 32-bit: PE64 images sit above 2**32)
    cursor_addr = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(mono_font())
        self.setStyleSheet(_code_style())
        self.an: Analysis | None = None
        self.func: Function | None = None
        self.region: tuple[int, int] | None = None     # (start, end) when showing memory outside functions
        self.lines: list[Line] = []
        self.row_of: dict[int, int] = {}
        self.columns = {"bytes": 20, "mnem": 44}
        self.debug_pc: int | None = None          # while debugging: the stopped-at instruction
        self.debug_bps: set[int] = set()
        self.decorators: list = []                # plugin line decorators (listing.decorate)
        self.show_bytes = True
        self.highlighter = ListingHighlighter(self.document(), self)
        self.cursorPositionChanged.connect(self._moved)

    def restyle(self):
        """Apply the current theme and font size."""
        self.setFont(mono_font())
        self.setStyleSheet(_code_style())
        self.highlighter.refresh()
        self._moved()

    def line_at(self, row: int) -> Line | None:
        return self.lines[row] if 0 <= row < len(self.lines) else None

    def show_function(self, an: Analysis, f: Function, addr: int | None = None):
        self.an = an
        self.region = None
        if f is not self.func or not self.lines:
            self.func = f
            self.reload()
        self.goto(addr if addr is not None else f.addr)

    def show_region(self, an: Analysis, addr: int) -> bool:
        """Memory outside functions (data, unexplored code) around `addr` (datalist)."""
        from ..datalist import window
        w = window(an, addr)
        if w is None:
            return False
        self.an = an
        if self.func is not None or getattr(self, "region", None) != w or not self.lines:
            self.func = None
            self.region = w
            self.reload()
        if not self.goto(addr):                  # inside an item: its first line
            starts = sorted(self.row_of)
            import bisect
            k = bisect.bisect_right(starts, addr) - 1
            if k >= 0:
                self.goto(starts[k])
        return True

    def reload(self):
        if self.an is None:
            return
        if self.func is None:
            if getattr(self, "region", None) is None:
                return
            from ..datalist import region_lines
            from ..listing import decorate
            lines = decorate(self.an, region_lines(self.an, *self.region), self.decorators)
        else:
            lines = function_lines(self.an, self.func, self.decorators)
        text = render(lines, self.show_bytes)
        if text.startswith("\n"):  # render() puts a blank line before the function header
            text = text[1:]
        self.lines = lines
        self.row_of = {}
        for k, ln in enumerate(lines):
            if ln.kind in ("insn", "data") or (ln.kind == "func" and ln.addr not in self.row_of):
                self.row_of.setdefault(ln.addr, k)
        addr_w = 16 if any(ln.addr >> 32 for ln in lines) else 8
        self.columns = {"bytes": 2 + addr_w + 2, "mnem": 2 + addr_w + 2 + (24 if self.show_bytes else 0)}
        sb = self.verticalScrollBar().value()
        self.setPlainText(text)
        self.verticalScrollBar().setValue(sb)

    def goto(self, addr: int) -> bool:
        row = self.row_of.get(addr)
        if row is None:
            return False
        cur = QTextCursor(self.document().findBlockByNumber(row))
        self.setTextCursor(cur)
        self.centerCursor()
        self._highlight_row(row)
        return True

    def current_line(self) -> Line | None:
        return self.line_at(self.textCursor().blockNumber())

    def current_addr(self) -> int | None:
        ln = self.current_line()
        return ln.addr if ln else None

    def _highlight_row(self, row: int):
        sel = _row_and_word_selections(self, row)
        # the cursor band first, then the debugger's marks over it, then the word highlights
        self.setExtraSelections(sel[:1] + self._debug_selections() + sel[1:])

    def set_debug_marks(self, pc: int | None, breakpoints=()):
        """Mark the stopped-at instruction and the breakpoints (static addresses) while debugging."""
        self.debug_pc = pc
        self.debug_bps = set(breakpoints)
        self._highlight_row(self.textCursor().blockNumber())

    def _debug_selections(self) -> list:
        # plugin colours first: the debugger's marks show over them
        marks = [(k, ln.color) for k, ln in enumerate(self.lines) if ln.color]
        marks += [(self.row_of.get(a), "bp_line") for a in getattr(self, "debug_bps", ())]
        if getattr(self, "debug_pc", None) is not None:
            marks.append((self.row_of.get(self.debug_pc), "pc_line"))
        return _line_marks(self, marks)

    def _moved(self):
        row = self.textCursor().blockNumber()
        self._highlight_row(row)
        ln = self.line_at(row)
        if ln is not None:
            self.cursor_addr.emit(ln.addr)

    def mouseDoubleClickEvent(self, e):
        super().mouseDoubleClickEvent(e)
        ln = self.current_line()
        if ln is None:
            return
        word = self.textCursor().selectedText()
        if self.an is not None and word:
            a = self.an.resolve(word)
            if a is not None and (self.an.bin.is_mapped(a)) and not word.isdigit():
                self.navigate.emit(a)
                return
        if ln.target is not None:
            self.navigate.emit(ln.target)


# --------------------------------------------------------------------- graph
class _Node(QGraphicsItem):
    PAD = 6

    def __init__(self, view: "GraphView", addr: int, lines: list[str], font: QFont):
        super().__init__()
        self.view, self.addr, self.lines = view, addr, lines
        self.text = QGraphicsSimpleTextItem("\n".join(lines), self)
        self.text.setFont(font)
        self.text.setBrush(QBrush(QColor(THEME["fg"])))
        self.text.setPos(self.PAD, self.PAD)
        r = self.text.boundingRect()
        self.w, self.h = r.width() + 2 * self.PAD, r.height() + 2 * self.PAD
        self.line_h = r.height() / max(len(lines), 1)
        self.selected = False
        self.setAcceptHoverEvents(True)

    def boundingRect(self) -> QRectF:
        return QRectF(0, 0, self.w, self.h)

    def paint(self, p: QPainter, opt, widget=None):
        p.setBrush(QColor(THEME["current"] if self.selected else THEME["node"]))
        p.setPen(QPen(QColor(THEME["label"] if self.selected else THEME["node_border"]), 1.5))
        p.drawRoundedRect(self.boundingRect(), 4, 4)

    def mouseDoubleClickEvent(self, e):
        row = int((e.pos().y() - self.PAD) // self.line_h)
        self.view.node_activated(self, row)


class GraphView(QGraphicsView):
    """Layered control-flow graph of the current function."""

    navigate = Signal(object)       # an address (Qt's int is 32-bit: PE64 images sit above 2**32)
    cursor_addr = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setBackgroundBrush(QColor(THEME["bg"]))
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.font = mono_font(max(font_size() - 1, FONT_SIZES[0]))
        self.nodes: dict[int, _Node] = {}
        self.an: Analysis | None = None
        self.func: Function | None = None
        self.graph_layout = None
        # collapsed groups per function: head block -> the blocks folded into it
        self.collapsed: dict[int, dict[int, frozenset]] = {}
        self.rep: dict[int, int] = {}          # block -> the node showing it

    # ------------------------------------------------------------- collapsing
    def groups(self) -> dict[int, frozenset]:
        return self.collapsed.setdefault(self.func.addr, {}) if self.func is not None else {}

    def selected_block(self) -> int | None:
        return next((a for a, n in self.nodes.items() if n.selected), None)

    def loop_of(self, addr: int) -> frozenset | None:
        """The innermost natural loop containing block `addr` (header first in iteration: the set's
        header is the one block every other reaches the latch through), or None."""
        f = self.func
        if f is None:
            return None
        from .layout import _back_edges
        succs = {a: list(b.succs) for a, b in f.blocks.items()}
        back = _back_edges(set(f.blocks), succs, f.addr)
        best = None
        for latch, head in back:
            body, work = {head}, [latch]
            while work:
                b = work.pop()
                if b in body:
                    continue
                body.add(b)
                work += [p for p in f.blocks[b].preds if p in f.blocks]
            if addr in body and (best is None or len(body) < len(best[1])):
                best = (head, body)
        return frozenset(best[1]) if best else None

    def collapse(self, addr: int | None = None, loop: bool = False) -> bool:
        """Fold the selected block (or the innermost loop around it) into one node."""
        if self.func is None:
            return False
        a = addr if addr is not None else self.selected_block()
        if a is None:
            return False
        a = self.rep.get(a, a)
        members = self.loop_of(a) if loop else frozenset({a})
        if not members:
            return False
        head = self._loop_head(members) if loop else a
        g = self.groups()
        for h in [h for h, ms in g.items() if ms & members]:
            members |= g.pop(h)                  # a loop around collapsed blocks swallows them
        g[head] = frozenset(members)
        self.reload()
        self.goto(head)
        return True

    def _loop_head(self, members: frozenset) -> int:
        """The block of a loop entered from outside it (its header)."""
        f = self.func
        entries = [m for m in members if m == f.addr or any(p not in members for p in f.blocks[m].preds)]
        return min(entries) if entries else min(members)

    def expand(self, addr: int | None = None) -> bool:
        a = addr if addr is not None else self.selected_block()
        if a is None:
            return False
        head = self.rep.get(a, a)
        if self.groups().pop(head, None) is None:
            return False
        self.reload()
        self.goto(head)
        return True

    def expand_all(self):
        self.groups().clear()
        self.reload()

    def keyPressEvent(self, e):
        k = e.key()
        if k == Qt.Key.Key_Minus and not e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.collapse()
        elif k == Qt.Key.Key_L:
            self.collapse(loop=True)
        elif k in (Qt.Key.Key_Plus, Qt.Key.Key_Equal) and not e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.expand()
        else:
            super().keyPressEvent(e)

    def restyle(self):
        """Apply the current theme and font size (the graph is drawn again)."""
        self.font = mono_font(max(font_size() - 1, FONT_SIZES[0]))
        self.setBackgroundBrush(QColor(THEME["bg"]))
        selected = next((a for a, n in self.nodes.items() if n.selected), None)
        self.reload()
        if selected is not None:
            self.goto(selected)

    def wheelEvent(self, e):
        if e.modifiers() & Qt.KeyboardModifier.ControlModifier:
            k = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
            self.scale(k, k)
        else:
            super().wheelEvent(e)

    def show_function(self, an: Analysis, f: Function, addr: int | None = None):
        if f is not self.func or self.an is not an:
            self.an, self.func = an, f
            self.reload()
        self.goto(addr if addr is not None else f.addr)

    def reload(self):
        from ..listing import insn_line
        sc = self.scene()
        sc.clear()
        self.nodes = {}
        an, f = self.an, self.func
        self.rep = {}
        if an is None or f is None or not f.blocks:
            return
        groups = {h: ms for h, ms in self.groups().items() if h in f.blocks}
        for h, ms in groups.items():
            for m in ms:
                self.rep[m] = h
        for a, blk in f.blocks.items():
            if a in self.rep and self.rep[a] != a:
                continue                          # shown by its group's node
            if a in groups:
                ms = groups[a]
                n_ins = sum(len(f.blocks[m].insns) for m in ms if m in f.blocks)
                what = f"{len(ms)} blocks (loop)" if len(ms) > 1 else "block"
                rows = [f"{an.label(a)}:" if a != f.addr else f"{an.name(a)}:",
                        f"  [+] {what}, {n_ins} instructions collapsed"]
                node = _Node(self, a, rows, self.font)
                node.collapsed = True
                sc.addItem(node)
                self.nodes[a] = node
                continue
            rows = [f"{an.label(a)}:"] if a != f.addr else [f"{an.name(a)}:"]
            for i in blk.insns:
                ln = insn_line(an, i)
                c = f"  ; {ln.comment}" if ln.comment else ""
                rows.append(f"{i.addr:x}  {ln.mnemonic} {ln.operands}{c}")
            node = _Node(self, a, rows, self.font)
            sc.addItem(node)
            self.nodes[a] = node
        self._layout(f)

    def _layout(self, f: Function):
        """Sugiyama-style layered layout (see `layout.py`): loops point back up, long edges are
        routed between the blocks they pass, crossings are reduced."""
        from .layout import layered_layout
        sizes = {a: (n.w, n.h) for a, n in self.nodes.items()}
        rep = lambda b: self.rep.get(b, b)         # noqa: E731 - a block's node
        out: dict[int, list[int]] = {}
        for a, blk in f.blocks.items():
            for s in blk.succs:
                ra, rs = rep(a), rep(s)
                if s in f.blocks and rs in self.nodes and ra != rs and rs not in out.setdefault(ra, []):
                    out[ra].append(rs)
        edges = [(a, s) for a, ss in out.items() for s in ss]
        lay = layered_layout(sizes, edges, rep(f.addr))
        self.graph_layout = lay
        for a, (x, y) in lay.pos.items():
            self.nodes[a].setPos(x, y)
        # edge bundling: three or more forward edges into one block meet at a junction above it,
        # three or more out of one block (a switch) leave it through a shared trunk
        fan_in: dict[int, int] = {}
        for a2, s2 in edges:
            if (a2, s2) not in lay.back:
                fan_in[s2] = fan_in.get(s2, 0) + 1
        self.bundled_in = {s for s, n in fan_in.items() if n >= self.BUNDLE}
        self.bundled_out = set()
        for a in self.nodes:
            blk = f.blocks[a]
            src = self.nodes[a]
            succs = out.get(a, [])
            fwd = [s for s in succs if (a, s) not in lay.back]
            trunk = len(fwd) >= self.BUNDLE
            if trunk:
                self.bundled_out.add(a)
            # out-ports spread along the block's bottom, in the order of where the edges go
            def heads(s, a=a):
                r = lay.routes.get((a, s))
                return r[0][0] if r else self.nodes[s].pos().x() + self.nodes[s].w / 2
            ports = sorted(succs, key=heads)
            for k, s in enumerate(ports):
                color = THEME["edge"]
                if blk.last.kind == "cjmp" and not getattr(src, "collapsed", False):
                    color = THEME["edge_true"] if s == blk.last.target else THEME["edge_false"]
                frac = (k + 1) / (len(ports) + 1)
                if trunk and (a, s) not in lay.back:
                    frac = 0.5                         # the shared trunk leaves from the middle
                route = lay.routes.get((a, s), [])
                if (a, s) not in lay.back:
                    # drop straight to the bottom of the layer before bending, so the edge never
                    # cuts through a taller block next to its source
                    bottom = lay.row_bottom.get(lay.layer[a])
                    if bottom is not None and bottom > src.pos().y() + src.h + 1:
                        route = [(src.pos().x() + src.w * frac, bottom), *route]
                self._edge(src, self.nodes[s], color, (a, s) in lay.back, route, frac,
                           trunk=trunk and (a, s) not in lay.back,
                           junction=s in self.bundled_in and (a, s) not in lay.back)
        self.setSceneRect(self.scene().itemsBoundingRect().adjusted(-60, -60, 60, 60))

    BUNDLE = 3            # edges sharing an end, from which on they are bundled
    JUNCTION = 16         # how far from the block the bundle splits / merges

    def _edge(self, a: _Node, b: _Node, color: str, back: bool, route=(), frac: float = 0.5,
              trunk: bool = False, junction: bool = False):
        p1 = a.pos() + QPointF(a.w * frac, a.h)
        p2 = b.pos() + QPointF(b.w / 2, 0)
        path = QPainterPath(p1)
        pts = [QPointF(x, y) for x, y in route]
        if trunk:                                  # down the shared trunk, then apart
            pts.insert(0, QPointF(p1.x(), p1.y() + self.JUNCTION))
        if junction:                               # together into the shared end above the block
            pts.append(QPointF(p2.x(), p2.y() - self.JUNCTION))
        if back:
            # leave below the block, climb along the route (or beside both blocks), enter from above
            side = pts[0].x() if pts else max(a.pos().x() + a.w, b.pos().x() + b.w) + 25
            top = pts[-1].x() if pts else side
            path.lineTo(p1.x(), p1.y() + 12)
            path.lineTo(side, p1.y() + 12)
            for p in pts:
                path.lineTo(p)
            path.lineTo(top, p2.y() - 12)
            path.lineTo(p2.x(), p2.y() - 12)
            path.lineTo(p2)
        else:
            chain = [p1, *pts, p2]
            for q0, q1 in zip(chain, chain[1:]):
                if q0.x() == q1.x():
                    path.lineTo(q1)
                else:
                    mid = (q0.y() + q1.y()) / 2
                    path.cubicTo(QPointF(q0.x(), mid), QPointF(q1.x(), mid), q1)
        item = QGraphicsPathItem(path)
        item.setPen(QPen(QColor(color), 1.4))
        item.setZValue(-1)
        self.scene().addItem(item)
        head = QPainterPath(p2)
        head.lineTo(p2.x() - 4, p2.y() - 7)
        head.lineTo(p2.x() + 4, p2.y() - 7)
        head.closeSubpath()
        hi = QGraphicsPathItem(head)
        hi.setBrush(QColor(color))
        hi.setPen(QPen(QColor(color)))
        self.scene().addItem(hi)

    def goto(self, addr: int) -> bool:
        if self.func is None:
            return False
        blk = self.func.block_at(addr) if addr not in self.nodes else self.func.blocks[addr]
        if blk is None:
            return False
        a = self.rep.get(blk.addr, blk.addr)
        if a not in self.nodes:
            return False
        blk = self.func.blocks[a]
        for n in self.nodes.values():
            if n.selected:
                n.selected = False
                n.update()
        node = self.nodes[blk.addr]
        node.selected = True
        node.update()
        self.centerOn(node.pos() + QPointF(node.w / 2, min(node.h / 2, 150)))
        return True

    def node_activated(self, node: _Node, row: int):
        if getattr(node, "collapsed", False):
            self.expand(node.addr)                    # double-click opens a collapsed node
            return
        blk = self.func.blocks[node.addr]
        k = row - 1
        if 0 <= k < len(blk.insns):
            i = blk.insns[k]
            self.cursor_addr.emit(i.addr)
            tgt = i.target if i.target is not None else (i.refs[0] if i.refs else None)
            if tgt is not None:
                self.navigate.emit(tgt)


# ----------------------------------------------------------------------- hex
class HexView(QPlainTextEdit):
    WINDOW = 0x2000

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(mono_font())
        self.setStyleSheet(_code_style())
        self.base = 0

    def restyle(self):
        self.setFont(mono_font())
        self.setStyleSheet(_code_style())

    def show_addr(self, an: Analysis, addr: int):
        b = an.bin
        seg = b.segment_at(addr)
        if seg is None:
            self.setPlainText(f"{addr:#x}: unmapped")
            return
        start = max(seg.addr, (addr & ~0xF) - self.WINDOW // 2)
        end = min(seg.addr + seg.memsz, start + self.WINDOW)
        data = b.read(start, end - start)
        rows = []
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hx = " ".join(f"{c:02x}" for c in chunk)
            hx = hx[:23] + " " + hx[23:] if len(chunk) > 8 else hx
            asc = "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in chunk)
            rows.append(f"{start + off:016x}  {hx:<48}  {asc}")
        self.base = start
        self.setPlainText("\n".join(rows))
        row = (addr - start) // 16
        cur = QTextCursor(self.document().findBlockByNumber(row))
        self.setTextCursor(cur)
        self.centerCursor()


# ---------------------------------------------------------------- pseudocode
_C_KEYWORDS = ("if", "else", "while", "do", "for", "switch", "case", "default", "break", "continue", "return",
               "goto", "sizeof")
_C_TYPES = ("void", "char", "short", "int", "long", "unsigned", "signed", "bool", "int8_t", "int16_t", "int32_t",
            "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t", "__int128")


class PseudocodeHighlighter(QSyntaxHighlighter):
    """C colouring: keywords, types, literals, comments, called functions."""

    def __init__(self, doc):
        super().__init__(doc)
        self.refresh(rehighlight=False)

    def refresh(self, rehighlight: bool = True):
        import re
        self.rules = [
            (re.compile(r"\b(" + "|".join(_C_TYPES) + r")\b"), _fmt(THEME["ret"])),
            (re.compile(r"\b(" + "|".join(_C_KEYWORDS) + r")\b"), _fmt(THEME["jump"])),
            (re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?=\()"), _fmt(THEME["call"])),
            (re.compile(r"\b(0x[0-9a-fA-F]+|\d+)\b"), _fmt(THEME["mnem"])),
            (re.compile(r"\bloc_[0-9a-f]+\b"), _fmt(THEME["label"])),
            (re.compile(r'"(?:[^"\\]|\\.)*"'), _fmt(THEME["label"])),
            (re.compile(r"//.*$"), _fmt(THEME["comment"])),
        ]
        if rehighlight:
            self.rehighlight()

    def highlightBlock(self, text: str):
        for rx, f in self.rules:
            for m in rx.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), f)


CANCELLED_TEXT = "// decompilation cancelled"


def _decompile_text(an: Analysis, f: Function):
    """Decompiled result for `f`, or an explanatory comment string on failure."""
    try:
        from ..decompiler.emit import decompile
        return decompile(an, f)
    except Cancelled:
        return CANCELLED_TEXT
    except NotImplementedError as e:
        return f"// {e}"
    except Exception as e:  # noqa: BLE001 - never take the GUI down with a decompiler bug
        return f"// decompilation failed: {type(e).__name__}: {e}"


class DecompileJob(QThread):
    """Decompiles one function off the GUI thread."""

    finished_result = Signal(int, object, object)   # generation, function address, Decompiled | str

    def __init__(self, gen: int, an: Analysis, f: Function, parent=None):
        super().__init__(parent)
        self.gen, self.an, self.f = gen, an, f
        self.token = Progress()

    def cancel(self):
        self.token.cancel()

    def run(self):
        handle = self.token.activate()
        try:
            self.finished_result.emit(self.gen, self.f.addr, _decompile_text(self.an, self.f))
        finally:
            Progress.deactivate(handle)


def _line_marks(view: QPlainTextEdit, marks) -> list:
    """Full-width background bands for (row, THEME key) pairs; rows that are None are skipped."""
    out = []
    for row, key in marks:
        if row is None:
            continue
        sel = QTextEdit.ExtraSelection()
        sel.format.setBackground(QColor(THEME.get(key, key)))     # a theme key, or a colour itself
        sel.format.setProperty(QTextCharFormat.Property.FullWidthSelection, True)
        sel.cursor = QTextCursor(view.document().findBlockByNumber(row))
        out.append(sel)
    return out


class PseudocodeView(QPlainTextEdit):
    """Decompiled C of one function, synchronised with the listing by instruction address.

    Decompilation runs on demand (when the view is shown) in a background
    thread, one function at a time, and is cached per function until
    `invalidate` is called (after a rename, say). While it runs the view shows
    a placeholder; a result that arrives for a function no longer shown, or
    from before an invalidation, is not displayed.
    """

    navigate = Signal(object)       # an address (Qt's int is 32-bit: PE64 images sit above 2**32)
    cursor_addr = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(mono_font())
        self.setStyleSheet(_code_style())
        self.highlighter = PseudocodeHighlighter(self.document())
        self.an: Analysis | None = None
        self.func: Function | None = None
        self.result = None                      # emit.Decompiled of the shown function
        self.cache: dict[int, object] = {}
        self.pending: int | None = None         # address to show once decompiled
        self.gen = 0                            # bumped by invalidate(): older results are stale
        self.job: DecompileJob | None = None
        self.queued: Function | None = None     # requested while a job was running
        self.debug_pc: int | None = None        # while debugging: the stopped-at instruction (static)
        self.debug_bps: set[int] = set()
        self._syncing = False
        self.cursorPositionChanged.connect(self._moved)

    def restyle(self):
        """Apply the current theme and font size."""
        self.setFont(mono_font())
        self.setStyleSheet(_code_style())
        self.highlighter.refresh()
        self._moved()

    def show_function(self, an: Analysis, f: Function, addr: int | None = None):
        if an is not self.an:
            self.cache.clear()
        self.an = an
        target = addr if addr is not None else f.addr
        if f is not self.func or f.addr not in self.cache:
            self.func = f
            self.pending = target
            self.reload()
        if self.result is not None and self.result.addr == f.addr:
            self.goto(target)
        else:
            self.pending = target

    def invalidate(self, reload: bool = True):
        """Forget cached output (names changed); re-render now if `reload`, else when next shown."""
        keep = self.current_addr_or_func()
        self.cache.clear()
        self.result = None
        self.gen += 1
        if reload and self.func is not None and self.an is not None:
            self.pending = keep
            self.reload()

    def word_under_cursor(self) -> str:
        cur = self.textCursor()
        cur.select(QTextCursor.SelectionType.WordUnderCursor)
        return cur.selectedText()

    def struct_under_cursor(self) -> tuple[str, str, str | None] | None:
        """(shown name, generated struct, generated field or None) for a struct or field name
        under the cursor; a field shared by several structs resolves to the first shown."""
        word = self.word_under_cursor()
        if self.result is None or not word:
            return None
        if word in self.result.structs:
            return word, self.result.structs[word], None
        pairs = self.result.fields.get(word)
        if pairs:
            return word, pairs[0][0], pairs[0][1]
        return None

    def variable_under_cursor(self) -> tuple[str, str] | None:
        """(shown name, generated name) of the local / parameter under the cursor."""
        word = self.word_under_cursor()
        if self.result is None or word not in self.result.variables:
            return None
        return word, self.result.variables[word]

    def symbol_under_cursor(self) -> int | None:
        """Address of the function / global named by the word under the cursor."""
        cur = self.textCursor()
        cur.select(QTextCursor.SelectionType.WordUnderCursor)
        word = cur.selectedText()
        import re
        # local names (v1, a2, var_c, buf_48) and numbers are not symbols ("a1" would parse as hex)
        if self.an is None or not word or re.fullmatch(r"[va]\d+|(var|buf|arg)_[0-9a-f]+|\d.*", word):
            return None
        a = self.an.resolve(word)
        return a if a is not None and self.an.name(a) else None

    def current_addr_or_func(self) -> int | None:
        a = self.current_addr()
        return a if a is not None else (self.func.addr if self.func is not None else None)

    def reload(self):
        if self.an is None or self.func is None:
            return
        f = self.func
        res = self.cache.get(f.addr)
        if res is None:
            self.result = None
            self._set_text(f"// decompiling {self.an.name(f.addr) or f.name} ...")
            self._request(f)
            return
        self._display(res)

    def _set_text(self, text: str):
        self._syncing = True
        self.setPlainText(text)
        self._syncing = False

    def _display(self, res):
        self.result = res if not isinstance(res, str) else None
        self._set_text(res if isinstance(res, str) else res.text)
        if self.result is not None and self.pending is not None:
            self.goto(self.pending)

    def _request(self, f: Function):
        if self.job is not None and self.job.isRunning():
            self.queued = f        # only the latest request matters
            if self.job.f is not f:
                # the user moved on: stop the old one at its next checkpoint instead of making
                # the new function wait for it (work it finished stays cached in the analysis)
                self.job.cancel()
            return
        self.job = DecompileJob(self.gen, self.an, f, self)
        self.job.finished_result.connect(self._finished)
        self.job.start()

    def _finished(self, gen: int, addr: int, res):
        job, self.job = self.job, None
        if job is not None:
            job.wait()
            job.deleteLater()
        cancelled = isinstance(res, str) and res == CANCELLED_TEXT
        if gen == self.gen and not cancelled:
            self.cache[addr] = res
        if self.func is not None and self.func.addr == addr and gen == self.gen and not cancelled:
            self._display(res)
        nxt, self.queued = self.queued, None
        if self.func is not None and self.func.addr not in self.cache:
            nxt = self.func        # still waiting for the shown function (e.g. renamed meanwhile)
        if nxt is not None and nxt.addr not in self.cache:
            self._request(nxt)

    def shutdown(self):
        """Stop a running job before the view goes away (a QThread must not outlive it): it is
        cancelled at its next checkpoint, between optimisation rounds or structuring steps."""
        self.queued = None
        if self.job is not None:
            self.job.cancel()
            self.job.wait()
            self.job = None

    def busy(self) -> bool:
        return self.job is not None or self.queued is not None

    def wait_idle(self, ms: int = 60000) -> bool:
        """Block until pending decompilation finished and is shown (for scripts and tests)."""
        import time
        end = time.monotonic() + ms / 1000
        while self.busy():
            if self.job is not None:
                self.job.wait(50)
            QCoreApplication.processEvents()
            if time.monotonic() > end:
                return False
        QCoreApplication.processEvents()
        return True

    def line_for(self, addr: int) -> int | None:
        """The line for `addr`: exact, else the closest line from an earlier instruction."""
        if self.result is None:
            return None
        best, best_addr = None, -1
        for k, ln in enumerate(self.result.lines):
            if ln.addr is None:
                continue
            if ln.addr == addr:
                return k
            if best_addr < ln.addr <= addr:
                best, best_addr = k, ln.addr
        return best

    def goto(self, addr: int) -> bool:
        row = self.line_for(addr)
        if row is None:
            return False
        self._syncing = True
        self.setTextCursor(QTextCursor(self.document().findBlockByNumber(row)))
        self._syncing = False
        self.centerCursor()
        self._highlight_row(row)
        return True

    def current_addr(self) -> int | None:
        if self.result is None:
            return None
        row = self.textCursor().blockNumber()
        lines = self.result.lines
        return lines[row].addr if 0 <= row < len(lines) else None

    def _highlight_row(self, row: int):
        sel = _row_and_word_selections(self, row)
        self.setExtraSelections(sel[:1] + self._debug_selections() + sel[1:])

    def set_debug_marks(self, pc: int | None, breakpoints=()):
        """Mark the statement being executed and the lines with breakpoints (static addresses)."""
        self.debug_pc = pc
        self.debug_bps = set(breakpoints)
        self._highlight_row(self.textCursor().blockNumber())

    def debug_rows(self) -> tuple[int | None, list[int]]:
        """(row of the statement at pc, rows of breakpoints) in the shown function. pc maps to the
        statement whose first instruction is the closest at or before it; a breakpoint needs
        a statement starting at its address, or the function's entry."""
        if self.result is None or self.an is None or self.func is None:
            return None, []
        pc_row = None
        if self.debug_pc is not None and self.an.function_at(self.debug_pc) is self.func:
            pc_row = self.line_for(self.debug_pc)
        exact = {}
        for k, ln in enumerate(self.result.lines):
            if ln.addr is not None:
                exact.setdefault(ln.addr, k)
        bp_rows = sorted({exact.get(a, 0 if a == self.func.addr else None) for a in self.debug_bps} - {None})
        return pc_row, bp_rows

    def _debug_selections(self) -> list:
        pc_row, bp_rows = self.debug_rows()
        return _line_marks(self, [(r, "bp_line") for r in bp_rows] + [(pc_row, "pc_line")])

    def _moved(self):
        self._highlight_row(self.textCursor().blockNumber())
        if self._syncing:
            return
        a = self.current_addr()
        if a is not None:
            self.cursor_addr.emit(a)

    def mouseDoubleClickEvent(self, e):
        super().mouseDoubleClickEvent(e)
        word = self.textCursor().selectedText()
        if self.an is None or not word or word.isdigit():
            return
        if word.startswith("loc_"):
            try:
                self.goto(int(word[4:], 16))
            except ValueError:
                pass
            return
        a = self.an.resolve(word)
        if a is not None and self.an.bin.is_mapped(a):
            self.navigate.emit(a)

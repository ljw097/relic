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

THEME = {
    "bg": "#1e1f22", "fg": "#d4d4d4", "addr": "#6c7086", "bytes": "#585b70", "mnem": "#89b4fa",
    "call": "#f9e2af", "jump": "#f38ba8", "ret": "#cba6f7", "comment": "#7fb77e", "label": "#fab387",
    "func": "#a6e3a1", "current": "#2d2f36", "node": "#26272b", "node_border": "#45475a",
    "edge_true": "#7fb77e", "edge_false": "#f38ba8", "edge": "#89b4fa", "word": "#3e4452",
}


def mono_font(size: int = 10) -> QFont:
    f = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
    f.setPointSize(size)
    return f


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
        self.f = {k: _fmt(v, k in ("func", "label")) for k, v in THEME.items()}

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
        if ln.kind != "insn":
            return
        c = self.view.columns
        self.setFormat(0, c["bytes"], self.f["addr"])
        self.setFormat(c["bytes"], c["mnem"] - c["bytes"], self.f["bytes"])
        m = ln.mnemonic
        key = "mnem"
        if m.startswith("call") or m in ("bl", "blx", "jal", "jalr"):
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

    navigate = Signal(int)
    cursor_addr = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(mono_font())
        self.setStyleSheet(f"QPlainTextEdit {{ background: {THEME['bg']}; color: {THEME['fg']}; }}")
        self.an: Analysis | None = None
        self.func: Function | None = None
        self.lines: list[Line] = []
        self.row_of: dict[int, int] = {}
        self.columns = {"bytes": 20, "mnem": 44}
        self.show_bytes = True
        self.highlighter = ListingHighlighter(self.document(), self)
        self.cursorPositionChanged.connect(self._moved)

    def line_at(self, row: int) -> Line | None:
        return self.lines[row] if 0 <= row < len(self.lines) else None

    def show_function(self, an: Analysis, f: Function, addr: int | None = None):
        self.an = an
        if f is not self.func or not self.lines:
            self.func = f
            self.reload()
        self.goto(addr if addr is not None else f.addr)

    def reload(self):
        if self.an is None or self.func is None:
            return
        lines = function_lines(self.an, self.func)
        text = render(lines, self.show_bytes)
        if text.startswith("\n"):  # render() puts a blank line before the function header
            text = text[1:]
        self.lines = lines
        self.row_of = {}
        for k, ln in enumerate(lines):
            if ln.kind == "insn" or (ln.kind == "func" and ln.addr not in self.row_of):
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
        self.setExtraSelections(_row_and_word_selections(self, row))

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

    navigate = Signal(int)
    cursor_addr = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setBackgroundBrush(QColor(THEME["bg"]))
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.font = mono_font(9)
        self.nodes: dict[int, _Node] = {}
        self.an: Analysis | None = None
        self.func: Function | None = None

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
        if an is None or f is None or not f.blocks:
            return
        for a, blk in f.blocks.items():
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
        # longest-path layering over a DFS spanning tree (back edges ignored)
        order, seen, back = [], set(), set()
        stack = [(f.addr, iter(f.blocks[f.addr].succs))]
        seen.add(f.addr)
        on_stack = {f.addr}
        while stack:
            a, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                on_stack.discard(a)
                order.append(a)
                continue
            if nxt in on_stack:
                back.add((a, nxt))
            elif nxt not in seen and nxt in f.blocks:
                seen.add(nxt)
                on_stack.add(nxt)
                stack.append((nxt, iter(f.blocks[nxt].succs)))
        order.reverse()
        order += [a for a in sorted(f.blocks) if a not in seen]
        layer = {a: 0 for a in order}
        for a in order:
            for s in f.blocks[a].succs:
                if (a, s) not in back and s in layer:
                    layer[s] = max(layer[s], layer[a] + 1)
        rows: dict[int, list[int]] = {}
        for a in order:
            rows.setdefault(layer[a], []).append(a)
        y = 0.0
        gap_x, gap_y = 40.0, 50.0
        for lv in sorted(rows):
            members = rows[lv]
            width = sum(self.nodes[a].w for a in members) + gap_x * (len(members) - 1)
            x = -width / 2
            h = 0.0
            for a in members:
                n = self.nodes[a]
                n.setPos(x, y)
                x += n.w + gap_x
                h = max(h, n.h)
            y += h + gap_y
        for a, blk in f.blocks.items():
            src = self.nodes[a]
            for s in blk.succs:
                if s not in self.nodes:
                    continue
                color = THEME["edge"]
                if blk.last.kind == "cjmp":
                    color = THEME["edge_true"] if s == blk.last.target else THEME["edge_false"]
                self._edge(src, self.nodes[s], color, (a, s) in back)
        self.setSceneRect(self.scene().itemsBoundingRect().adjusted(-60, -60, 60, 60))

    def _edge(self, a: _Node, b: _Node, color: str, back: bool):
        p1 = a.pos() + QPointF(a.w / 2, a.h)
        p2 = b.pos() + QPointF(b.w / 2, 0)
        path = QPainterPath(p1)
        if back:
            side = max(a.pos().x() + a.w, b.pos().x() + b.w) + 25
            path.lineTo(p1.x(), p1.y() + 12)
            path.lineTo(side, p1.y() + 12)
            path.lineTo(side, p2.y() - 12)
            path.lineTo(p2.x(), p2.y() - 12)
            path.lineTo(p2)
        else:
            mid = (p1.y() + p2.y()) / 2
            path.cubicTo(QPointF(p1.x(), mid), QPointF(p2.x(), mid), p2)
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
        if blk is None or blk.addr not in self.nodes:
            return False
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
        self.setStyleSheet(f"QPlainTextEdit {{ background: {THEME['bg']}; color: {THEME['fg']}; }}")
        self.base = 0

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

    def highlightBlock(self, text: str):
        for rx, f in self.rules:
            for m in rx.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), f)


def _decompile_text(an: Analysis, f: Function):
    """Decompiled result for `f`, or an explanatory comment string on failure."""
    try:
        from ..decompiler.emit import decompile
        return decompile(an, f)
    except NotImplementedError as e:
        return f"// {e}"
    except Exception as e:  # noqa: BLE001 - never take the GUI down with a decompiler bug
        return f"// decompilation failed: {type(e).__name__}: {e}"


class DecompileJob(QThread):
    """Decompiles one function off the GUI thread."""

    finished_result = Signal(int, int, object)   # generation, function address, Decompiled | str

    def __init__(self, gen: int, an: Analysis, f: Function, parent=None):
        super().__init__(parent)
        self.gen, self.an, self.f = gen, an, f

    def run(self):
        self.finished_result.emit(self.gen, self.f.addr, _decompile_text(self.an, self.f))


class PseudocodeView(QPlainTextEdit):
    """Decompiled C of one function, synchronised with the listing by instruction address.

    Decompilation runs on demand (when the view is shown) in a background
    thread, one function at a time, and is cached per function until
    `invalidate` is called (after a rename, say). While it runs the view shows
    a placeholder; a result that arrives for a function no longer shown, or
    from before an invalidation, is not displayed.
    """

    navigate = Signal(int)
    cursor_addr = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setFont(mono_font())
        self.setStyleSheet(f"QPlainTextEdit {{ background: {THEME['bg']}; color: {THEME['fg']}; }}")
        self.highlighter = PseudocodeHighlighter(self.document())
        self.an: Analysis | None = None
        self.func: Function | None = None
        self.result = None                      # emit.Decompiled of the shown function
        self.cache: dict[int, object] = {}
        self.pending: int | None = None         # address to show once decompiled
        self.gen = 0                            # bumped by invalidate(): older results are stale
        self.job: DecompileJob | None = None
        self.queued: Function | None = None     # requested while a job was running
        self._syncing = False
        self.cursorPositionChanged.connect(self._moved)

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
        if self.an is None or not word or re.fullmatch(r"[va]\d+|(var|buf)_[0-9a-f]+|\d.*", word):
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
            return
        self.job = DecompileJob(self.gen, self.an, f, self)
        self.job.finished_result.connect(self._finished)
        self.job.start()

    def _finished(self, gen: int, addr: int, res):
        job, self.job = self.job, None
        if job is not None:
            job.wait()
            job.deleteLater()
        if gen == self.gen:
            self.cache[addr] = res
        if self.func is not None and self.func.addr == addr and gen == self.gen:
            self._display(res)
        nxt, self.queued = self.queued, None
        if self.func is not None and self.func.addr not in self.cache:
            nxt = self.func        # still waiting for the shown function (e.g. renamed meanwhile)
        if nxt is not None and nxt.addr not in self.cache:
            self._request(nxt)

    def shutdown(self):
        """Wait for a running job before the view goes away (a QThread must not outlive it)."""
        self.queued = None
        if self.job is not None:
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
        self.setExtraSelections(_row_and_word_selections(self, row))

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

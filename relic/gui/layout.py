"""Layered (Sugiyama-style) layout for control-flow graphs, independent of Qt.

1. Cycle removal: a DFS from the entry marks back edges (loops); they are
   laid out reversed, so every edge points down.
2. Layering: longest path from the sources, so a block sits below all of
   its (forward) predecessors.
3. Long edges get a dummy node in every layer they cross; their route runs
   through those points instead of through the blocks in between.
4. Crossing reduction: barycenter ordering, sweeping down and up, keeping
   the ordering with the fewest crossings seen.
5. Coordinates: every node wants to sit at the mean centre of its neighbours
   in the adjacent layer; the closest placement that keeps the layer's order
   and the minimum gaps is an isotonic regression (pool adjacent violators).
   Alternating sweeps settle straight runs of blocks into vertical columns.
"""
from __future__ import annotations

from dataclasses import dataclass, field

Node = int
Edge = tuple[int, int]


@dataclass
class Layout:
    pos: dict[Node, tuple[float, float]] = field(default_factory=dict)   # top-left corner
    layer: dict[Node, int] = field(default_factory=dict)
    order: list[list[Node]] = field(default_factory=list)                # real nodes per layer, left to right
    back: set[Edge] = field(default_factory=set)
    routes: dict[Edge, list[tuple[float, float]]] = field(default_factory=dict)  # dummy points, in edge direction
    row_bottom: dict[int, float] = field(default_factory=dict)          # layer -> y below its tallest block
    crossings: int = 0


class _Dummy:
    __slots__ = ("edge", "k", "top", "bottom")

    def __init__(self, edge: Edge, k: int):
        self.edge, self.k = edge, k
        self.top = self.bottom = 0.0

    def __repr__(self):
        return f"d{self.edge}#{self.k}"


def _back_edges(nodes, succs, entry) -> set[Edge]:
    back: set[Edge] = set()
    seen: set = set()
    roots = ([entry] if entry in nodes else []) + sorted(nodes)
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        on_stack = {root}
        stack = [(root, iter(succs.get(root, ())))]
        while stack:
            a, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                on_stack.discard(a)
                continue
            if nxt not in nodes:
                continue
            if nxt in on_stack:
                back.add((a, nxt))
            elif nxt not in seen:
                seen.add(nxt)
                on_stack.add(nxt)
                stack.append((nxt, iter(succs.get(nxt, ()))))
    return back


def _layers(nodes, dag: list[Edge], entry) -> dict[Node, int]:
    preds: dict = {n: [] for n in nodes}
    outs: dict = {n: [] for n in nodes}
    for a, b in dag:
        preds[b].append(a)
        outs[a].append(b)
    indeg = {n: len(preds[n]) for n in nodes}
    ready = sorted((n for n in nodes if indeg[n] == 0), key=lambda n: (n != entry, n))
    layer = {n: 0 for n in nodes}
    while ready:
        a = ready.pop(0)
        for b in outs[a]:
            layer[b] = max(layer[b], layer[a] + 1)
            indeg[b] -= 1
            if indeg[b] == 0:
                ready.append(b)
    return layer


def _count(upper: list, lower: list, down: dict) -> int:
    """Crossings between two adjacent layers (`down`: node -> neighbours in the lower layer)."""
    idx = {n: k for k, n in enumerate(lower)}
    ends = [idx[m] for n in upper for m in sorted(down.get(n, ()), key=idx.__getitem__)]
    # inversions of the lower endpoints, read in upper order
    c = 0
    for i in range(len(ends)):
        for j in range(i + 1, len(ends)):
            if ends[i] > ends[j]:
                c += 1
    return c


def _total(rows, down) -> int:
    return sum(_count(rows[i], rows[i + 1], down) for i in range(len(rows) - 1))


def _isotonic(want: list[float], gaps: list[float]) -> list[float]:
    """Positions closest (least squares) to `want` with x[i+1] - x[i] >= gaps[i]."""
    off = [0.0]
    for g in gaps:
        off.append(off[-1] + g)
    y = [w - o for w, o in zip(want, off)]
    blocks: list[list[float]] = []          # [sum, count]
    for v in y:
        blocks.append([v, 1])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]:
            s, c = blocks.pop()
            blocks[-1][0] += s
            blocks[-1][1] += c
    out = []
    for s, c in blocks:
        out += [s / c] * c
    return [v + o for v, o in zip(out, off)]


def layered_layout(sizes: dict[Node, tuple[float, float]], edges: list[Edge], entry: Node | None = None,
                   gap_x: float = 40.0, gap_y: float = 50.0, dummy_w: float = 12.0,
                   sweeps: int = 12) -> Layout:
    nodes = set(sizes)
    edges = [(a, b) for a, b in dict.fromkeys(edges) if a in nodes and b in nodes]
    succs: dict = {}
    for a, b in edges:
        succs.setdefault(a, []).append(b)
    back = _back_edges(nodes, succs, entry)
    # self loops stay out of the layering; other back edges are reversed
    dag = [((b, a) if (a, b) in back else (a, b)) for a, b in edges if a != b]
    layer = _layers(nodes, dag, entry)

    # dummy chains for edges spanning several layers
    down: dict = {}
    up: dict = {}
    rows: dict[int, list] = {}
    for n in sorted(nodes, key=lambda n: (n != entry, n)):
        rows.setdefault(layer[n], []).append(n)
    chains: dict[Edge, list[_Dummy]] = {}
    for (a, b), orig in zip(dag, [e for e in edges if e[0] != e[1]]):
        prev = a
        chain = []
        for k, lv in enumerate(range(layer[a] + 1, layer[b])):
            d = _Dummy(orig, k)
            rows.setdefault(lv, []).append(d)
            chain.append(d)
            down.setdefault(prev, []).append(d)
            up.setdefault(d, []).append(prev)
            prev = d
        down.setdefault(prev, []).append(b)
        up.setdefault(b, []).append(prev)
        chains[orig] = chain
    nrows = [rows.get(lv, []) for lv in range(max(rows) + 1)] if rows else []

    # crossing reduction: barycenter sweeps, keep the best ordering
    def sweep(order, downward: bool):
        rng = range(1, len(order)) if downward else range(len(order) - 2, -1, -1)
        for i in rng:
            ref = order[i - 1] if downward else order[i + 1]
            pos = {n: k for k, n in enumerate(ref)}
            nbrs = up if downward else down
            cur = {n: k for k, n in enumerate(order[i])}

            def bary(n):
                ps = [pos[m] for m in nbrs.get(n, ()) if m in pos]
                return sum(ps) / len(ps) if ps else cur[n]
            order[i] = sorted(order[i], key=lambda n: (bary(n), cur[n]))

    best = [list(r) for r in nrows]
    best_c = _total(best, down)
    cur = [list(r) for r in nrows]
    for k in range(sweeps):
        if best_c == 0:
            break
        sweep(cur, downward=k % 2 == 0)
        c = _total(cur, down)
        if c < best_c:
            best, best_c = [list(r) for r in cur], c

    # coordinates
    def width(n):
        return dummy_w if isinstance(n, _Dummy) else sizes[n][0]

    center: dict = {}
    for row in best:
        x = 0.0
        for n in row:
            center[n] = x + width(n) / 2
            x += width(n) + gap_x
    for k in range(8):
        downward = k % 2 == 0
        rng = range(1, len(best)) if downward else range(len(best) - 2, -1, -1)
        for i in rng:
            row = best[i]
            nbrs = up if downward else down
            want = []
            for n in row:
                ps = [center[m] for m in nbrs.get(n, ())]
                want.append(sum(ps) / len(ps) if ps else center[n])
            gaps = [(width(row[j]) + width(row[j + 1])) / 2 + (gap_x if not (isinstance(row[j], _Dummy) and
                    isinstance(row[j + 1], _Dummy)) else gap_x / 3) for j in range(len(row) - 1)]
            for n, x in zip(row, _isotonic(want, gaps)):
                center[n] = x
    if best:
        shift = -min(center[n] - width(n) / 2 for row in best for n in row)
        for n in center:
            center[n] += shift

    out = Layout(layer=layer, back=back, crossings=best_c)
    y = 0.0
    row_y: list[float] = []
    for row in best:
        h = max((sizes[n][1] for n in row if not isinstance(n, _Dummy)), default=0.0)
        row_y.append(y)
        out.row_bottom[len(row_y) - 1] = y + h
        for n in row:
            if not isinstance(n, _Dummy):
                out.pos[n] = (center[n] - sizes[n][0] / 2, y)
        y += h + gap_y
    for row, ry in zip(best, row_y):
        h = max((sizes[n][1] for n in row if not isinstance(n, _Dummy)), default=0.0)
        for n in row:
            if isinstance(n, _Dummy):
                n.top, n.bottom = ry, ry + h
    for e, chain in chains.items():
        # through each crossed layer vertically, so the edge passes beside its blocks
        pts = [p for d in chain for p in ((center[d], d.top), (center[d], d.bottom))]
        out.routes[e] = pts[::-1] if e in back else pts
    out.order = [[n for n in row if not isinstance(n, _Dummy)] for row in best]
    return out


__all__ = ["Layout", "layered_layout"]

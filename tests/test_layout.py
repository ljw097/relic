"""Layered CFG layout: back edges, layering, long-edge routes, crossing reduction, placement."""
from relic.gui.layout import _isotonic, layered_layout


def _sizes(*nodes, w=100.0, h=40.0):
    return {n: (w, h) for n in nodes}


def _overlaps(lay, sizes, gap=0.0):
    for row in lay.order:
        xs = sorted((lay.pos[n][0], lay.pos[n][0] + sizes[n][0]) for n in row)
        for (_a0, a1), (b0, _b1) in zip(xs, xs[1:]):
            if b0 < a1 + gap - 1e-6:
                return True
    return False


def test_loop_back_edge_points_up_everything_else_down():
    edges = [(1, 2), (2, 3), (3, 2), (3, 4)]          # while loop 2 <-> 3
    lay = layered_layout(_sizes(1, 2, 3, 4), edges, 1)
    assert lay.back == {(3, 2)}
    for a, b in edges:
        if (a, b) not in lay.back:
            assert lay.layer[a] < lay.layer[b]


def test_long_edge_is_routed_beside_the_blocks_it_passes():
    # 1 -> 2 -> 3 -> 4 and a shortcut 1 -> 4 across two layers
    sizes = _sizes(1, 2, 3, 4)
    lay = layered_layout(sizes, [(1, 2), (2, 3), (3, 4), (1, 4)], 1)
    route = lay.routes[(1, 4)]
    assert len(route) == 4                              # top and bottom of the two crossed layers
    for x, y in route:
        for n in (2, 3):
            nx, ny = lay.pos[n]
            assert not (nx <= x <= nx + sizes[n][0] and ny <= y <= ny + sizes[n][1])


def test_crossings_are_removed_where_possible():
    # two diamonds whose naive (address) order crosses: 1 -> {2, 3}, 2 -> 5, 3 -> 4
    edges = [(1, 2), (1, 3), (2, 5), (3, 4), (4, 6), (5, 6)]
    lay = layered_layout(_sizes(1, 2, 3, 4, 5, 6), edges, 1)
    assert lay.crossings == 0


def test_no_overlaps_and_straight_chains():
    sizes = {1: (300.0, 40.0), 2: (80.0, 40.0), 3: (120.0, 60.0), 4: (300.0, 40.0), 5: (60.0, 20.0)}
    lay = layered_layout(sizes, [(1, 2), (1, 3), (2, 4), (3, 4), (4, 5)], 1, gap_x=40)
    assert not _overlaps(lay, sizes, gap=40)
    # a block with a single predecessor and successor chain sits centred under it
    c4 = lay.pos[4][0] + sizes[4][0] / 2
    c5 = lay.pos[5][0] + sizes[5][0] / 2
    assert abs(c4 - c5) < 1e-6


def test_unreachable_blocks_and_self_loops_are_laid_out():
    lay = layered_layout(_sizes(1, 2, 9), [(1, 2), (2, 2)], 1)
    assert set(lay.pos) == {1, 2, 9} and (2, 2) in lay.back


def test_deterministic():
    edges = [(1, 2), (1, 3), (2, 4), (3, 4), (4, 1), (2, 5), (5, 4)]
    a = layered_layout(_sizes(1, 2, 3, 4, 5), edges, 1)
    b = layered_layout(_sizes(1, 2, 3, 4, 5), list(edges), 1)
    assert a.pos == b.pos and a.routes == b.routes


def test_isotonic_keeps_order_and_gaps():
    xs = _isotonic([0.0, 0.0, 0.0], [10.0, 10.0])
    assert xs == [-10.0, 0.0, 10.0]                    # spread evenly around the wanted spot
    assert _isotonic([0.0, 100.0], [10.0]) == [0.0, 100.0]


def test_real_cfg_reduces_crossings(flow_O2):
    from relic.analysis import analyze
    an = analyze(flow_O2)
    for f in an.functions.values():
        if f.is_import or len(f.blocks) < 4:
            continue
        sizes = {a: (120.0, 20.0 + 14 * len(b.insns)) for a, b in f.blocks.items()}
        edges = [(a, s) for a, b in f.blocks.items() for s in b.succs if s in f.blocks]
        base = layered_layout(sizes, edges, f.addr, sweeps=0)
        lay = layered_layout(sizes, edges, f.addr)
        assert lay.crossings <= base.crossings, f.name
        assert not _overlaps(lay, sizes), f.name


def test_crossing_count_matches_pairwise_count():
    import random

    from relic.gui.layout import _count
    rnd = random.Random(7)
    for _ in range(300):
        upper = list(range(rnd.randint(0, 12)))
        lower = list(range(100, 100 + rnd.randint(1, 12)))
        rnd.shuffle(lower)
        down = {u: rnd.sample(lower, rnd.randint(0, len(lower))) for u in upper}
        idx = {n: k for k, n in enumerate(lower)}
        ends = [idx[m] for n in upper for m in sorted(down[n], key=idx.__getitem__)]
        pairs = sum(ends[i] > ends[j] for i in range(len(ends)) for j in range(i + 1, len(ends)))
        assert _count(upper, lower, down) == pairs

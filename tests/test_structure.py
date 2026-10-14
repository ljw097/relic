"""Decompiler stage 4: control-flow structuring."""
import pytest

from relic.analysis import analyze
from relic.decompiler import decompile_ir
from relic.decompiler.ssa import reachable_order
from relic.decompiler.structure import Block, Seq, Structurer, to_pseudocode


def _pseudo(an, name):
    return to_pseudocode(decompile_ir(an, an.function_by_name(name)), an)


def _block_addrs(node, out):
    if isinstance(node, Seq):
        for it in node.items:
            _block_addrs(it, out)
    elif isinstance(node, Block):
        out.append(node.addr)
    else:
        for v in getattr(node, "__dict__", {}).values():
            if isinstance(v, (Seq, Block)):
                _block_addrs(v, out)
            elif isinstance(v, list):
                for x in v:
                    if hasattr(x, "__dict__") or isinstance(x, (Seq, Block)):
                        _block_addrs(x, out)
                    elif isinstance(x, tuple):
                        for y in x:
                            if hasattr(y, "__dict__"):
                                _block_addrs(y, out)


@pytest.mark.parametrize("variant", ["vuln64", "vuln64_pie"])
def test_every_block_emitted_once(request, variant):
    """Structuring visits every reachable block exactly once; gotos target visited blocks."""
    an = analyze(request.getfixturevalue(variant))
    for f in an.functions.values():
        if f.is_import:
            continue
        fn = decompile_ir(an, f)
        st = Structurer(fn)
        st.run()
        assert st.emitted == set(reachable_order(fn)), f"{f.name}: blocks not all emitted"
        assert st.gotos <= st.emitted


def test_checksum_is_a_loop_with_if(vuln64):
    code = _pseudo(analyze(vuln64), "checksum")
    assert "while (" in code and "if (" in code
    assert "phi(" not in code                 # SSA bookkeeping suppressed
    assert "goto" not in code                  # fully structured
    assert "0x1337" in code                    # the h ^= 0x1337 body survived


def test_classify_is_a_switch(vuln64):
    code = _pseudo(analyze(vuln64), "classify")
    assert "switch (" in code and "case 0:" in code and "default:" in code


def test_main_has_infinite_menu_loop(vuln64):
    code = _pseudo(analyze(vuln64), "main")
    assert "while (1) {" in code
    assert "menu" in code


def test_vuln_is_straight_line(vuln64):
    code = _pseudo(analyze(vuln64), "vuln")
    assert "while" not in code and "goto" not in code
    assert "; gets" in code and "; checksum" in code


def test_condition_negation_reads_naturally(vuln64):
    # the `h > 100000` test should not print as `!(... <=s ...)`
    code = _pseudo(analyze(vuln64), "checksum")
    assert "!(" not in code


def test_menu_loop_breaks_out(vuln64):
    """The `else break` leaving main's menu loop is explicit, not a fall-through."""
    from relic.decompiler.outssa import out_of_ssa
    an = analyze(vuln64)
    code = to_pseudocode(out_of_ssa(decompile_ir(an, an.function_by_name("main"))), an)
    assert "break;" in code and "goto" not in code


def test_pie_classify_switch_has_default(vuln64_pie):
    code = _pseudo(analyze(vuln64_pie), "classify")
    assert "default:" in code and "case 5:" in code and "goto" not in code


# ------------------------------------------------- structured tree vs. CFG, by execution
def _cfg(edges: dict, entry: int):
    """An IRFunction from {block: [successors]}: two successors branch on a variable `c<addr>`,
    one jumps, none returns; a tuple of successors is a jump table indexed by `s<addr>`."""
    from relic.decompiler.ir import (Assign, BinOp, Branch, Const, IndirectJump, IRBlock, IRFunction, Jump, Load,
                                     Return, Var)
    fn = IRFunction(entry, "f")
    for a, outs in edges.items():
        if isinstance(outs, tuple):
            idx = BinOp("*", Var(f"s{a:x}", 0, 64), Const(8, 64), 64)
            last = IndirectJump(a, Load(BinOp("+", Const(0x9000, 64), idx, 64), 64),
                                list(dict.fromkeys(outs)), list(outs))
            outs = list(dict.fromkeys(outs))
        elif len(outs) == 2:
            last = Branch(a, Var(f"c{a:x}", 0, 1), outs[0], outs[1])
        elif outs:
            last = Jump(a, outs[0])
        else:
            last = Return(a)
        # a statement in every block: none may be dropped as empty
        fn.blocks[a] = IRBlock(a, [Assign(a, Var(f"m{a:x}", 0, 32), Const(1, 32)), last], list(outs))
    for a, outs in edges.items():
        for s in dict.fromkeys(outs):
            fn.blocks[s].preds.append(a)
    return fn


def _choice(a, v, tables):
    """What block `a` does with the oracle's value `v`: a branch's side, a table's index."""
    return int(v * len(tables[a])) if a in tables else v < 0.5


def _tables(fn):
    from relic.decompiler.ir import IndirectJump
    return {a: b.stmts[-1].table for a, b in fn.blocks.items() if isinstance(b.stmts[-1], IndirectJump)}


def _run_cfg(fn, oracle, limit=60):
    trace, seen, a = [], {}, fn.addr
    tables = _tables(fn)
    while len(trace) < limit:
        trace.append(a)
        seen[a] = seen.get(a, 0) + 1
        outs = fn.blocks[a].succs
        if not outs:
            break
        if a in tables:
            a = tables[a][_choice(a, oracle(a, seen[a]), tables)]
        else:
            a = outs[0] if len(outs) == 1 or _choice(a, oracle(a, seen[a]), tables) else outs[1]
    return trace


def _compile_tree(tree):
    """A structured tree as jump code: ("visit", block), ("test", cond, else_index),
    ("jmp", index or ("label", block)), ("ret",). Labels: every non-copy block and loop header
    (where a `goto` lands, as the renderer prints them)."""
    from relic.decompiler.structure import If, Jump1, Loop, Ret, Switch
    code, labels = [], {}

    def emit(node, brk, cont):
        if node is None:
            return
        if isinstance(node, Seq):
            for it in node.items:
                emit(it, brk, cont)
        elif isinstance(node, Block):
            if not node.copy:
                labels.setdefault(node.addr, len(code))
            code.append(("visit", node.addr))
        elif isinstance(node, If):
            k = len(code)
            code.append(None)
            emit(node.then, brk, cont)
            if node.els is not None:
                j = len(code)
                code.append(None)
                code[k] = ("test", node.cond, len(code))
                emit(node.els, brk, cont)
                code[j] = ("jmp", len(code))
            else:
                code[k] = ("test", node.cond, len(code))
        elif isinstance(node, Loop):
            top = len(code)
            if node.header is not None:
                labels.setdefault(node.header, top)
            exits: list[int] = []
            if node.kind == "while":
                code.append(("visit", node.header))      # the test is the header block running
                exits.append(len(code))
                code.append(None)
                emit(node.body, exits, top)
                code.append(("jmp", top))
            elif node.kind == "dowhile":
                tests: list[int] = []
                emit(node.body, exits, tests)
                t = len(code)
                code.append(("test", node.cond, len(code) + 2))
                code.append(("jmp", top))
                for k in tests:
                    code[k] = ("jmp", t)
            else:
                emit(node.body, exits, top)
                code.append(("jmp", top))
            end = len(code)
            for k in exits:
                code[k] = ("test", node.cond, end) if code[k] is None else ("jmp", end)
        elif isinstance(node, Jump1):
            if node.kind == "goto":
                code.append(("jmp", ("label", node.addr)))
            elif node.kind == "break":
                brk.append(len(code))
                code.append(("jmp", None))
            elif isinstance(cont, list):                  # do-while: to the test, patched later
                cont.append(len(code))
                code.append(("jmp", None))
            else:
                code.append(("jmp", cont))
        elif isinstance(node, Ret):
            code.append(("ret", node.stmt.addr))
        elif isinstance(node, Switch):
            k = len(code)
            code.append(None)
            exits, starts, default = [], {}, None
            for case in node.cases:                     # case bodies in order: fall-through
                for v in case.values:
                    starts[v] = len(code)
                if case.default:
                    default = len(code)
                emit(case.body, exits, cont)
            end = len(code)
            for j in exits:
                code[j] = ("jmp", end)
            code[k] = ("switch", node.expr, starts, end if default is None else default)
        else:
            raise AssertionError(f"node {node}")
    emit(tree, None, None)
    return code, labels


def _run_tree(tree, oracle, limit=60, tables=None):
    """Execute a structured tree: the blocks it passes through, in order."""
    from relic.decompiler.ir import BinOp, Const, UnOp, Var
    code, labels = _compile_tree(tree)
    trace, seen, val = [], {}, {}
    tables = tables or {}

    def ev(c):
        if isinstance(c, Var):
            a = int(c.name[1:], 16)
            return _choice(a, val[a], tables)
        if isinstance(c, Const):
            return bool(c.value)
        if isinstance(c, UnOp) and c.op == "!":
            return not ev(c.a)
        if isinstance(c, BinOp) and c.op in ("&&", "||"):
            return (ev(c.a) and ev(c.b)) if c.op == "&&" else (ev(c.a) or ev(c.b))
        if isinstance(c, BinOp) and c.op in ("==", "!="):
            return (ev(c.a) == ev(c.b)) == (c.op == "==")
        raise AssertionError(f"condition {c}")

    pc = 0
    while pc < len(code) and len(trace) < limit:
        op = code[pc]
        pc += 1
        if op[0] == "visit":
            a = op[1]
            trace.append(a)
            seen[a] = seen.get(a, 0) + 1
            val[a] = oracle(a, seen[a])
        elif op[0] == "test":
            if not ev(op[1]):
                pc = op[2]
        elif op[0] == "switch":
            pc = op[2].get(ev(op[1]), op[3])
        elif op[0] == "jmp":
            pc = labels[op[1][1]] if isinstance(op[1], tuple) else op[1]
        elif op[0] == "ret":
            if not trace or trace[-1] != op[1]:
                trace.append(op[1])          # a return-only block, emitted as its `return` alone
            break
    return trace


def _oracles(seed_count=200):
    import random
    for seed in range(seed_count):
        rnd = random.Random(seed)
        table = {}
        yield lambda a, k, table=table, rnd=rnd: table.setdefault((a, k), rnd.random())


def test_loop_with_join_bypassed_by_one_side_runs_like_the_cfg():
    """A do-while whose body branches meet at the latch, one side passing a block (0x1667) the
    other skips: the latch test must follow every path (coreutils `true`'s c_strcasecmp loop,
    which once fell through into the other side's code)."""
    edges = {0x1656: [0x1682],
             0x1682: [0x165a, 0x169e],
             0x165a: [0x1675, 0x1667],
             0x169e: [0x1667, 0x166a],
             0x1667: [0x166a],
             0x166a: [0x15e7, 0x1675],
             0x1675: [0x15e7, 0x1682],
             0x15e7: []}
    fn = _cfg(edges, 0x1656)
    st = Structurer(fn)
    tree = st.run()
    assert not st.gotos
    for oracle in _oracles():
        assert _run_tree(tree, oracle, tables=_tables(fn)) == _run_cfg(fn, oracle)


_FOUND = [   # CFGs that once structured into code doing something else (one bug each)
    # a duplicated tail ending at the loop's follow, which is also the region's stop: `break`
    {0x100: [0x140, 0x110], 0x110: [0x130, 0x140], 0x130: [0x110, 0x150], 0x140: [0x150], 0x150: [0x160],
     0x160: []},
    # one side jumps straight to the region's stop while the post-dominator lies beyond it
    {0x100: [0x120, 0x170], 0x120: [0x130, 0x150], 0x130: [0x170, 0x160], 0x150: [0x180, 0x160],
     0x160: [0x170], 0x170: [], 0x180: []},
    # an inner loop leaving to the outer loop's follow: `break` out of the outer one too
    {0x100: [0x140, 0x120], 0x110: [0x110, 0x150], 0x120: [0x100, 0x150], 0x140: [0x110, 0x160],
     0x150: [0x160], 0x160: []},
    # a jump from an inner loop to the outer loop's header (no `continue 2` in C: goto)
    {0x100: [0x150], 0x110: [0x120], 0x120: [0x140, 0x150], 0x140: [0x160, 0x170], 0x150: [0x170],
     0x160: [0x140, 0x170], 0x170: [0x110, 0x190], 0x190: []},
]


@pytest.mark.parametrize("edges", _FOUND)
def test_found_cfgs_run_like_the_cfg(edges):
    fn = _cfg(edges, min(edges))
    tree = Structurer(fn).run()
    for oracle in _oracles(60):
        assert _run_tree(tree, oracle, tables=_tables(fn)) == _run_cfg(fn, oracle)


def _random_cfg(rnd, n, switches=False):
    addrs = [0x100 + 0x10 * i for i in range(n)]
    edges = {}
    for i, a in enumerate(addrs[:-1]):
        r, later = rnd.random(), addrs[i + 1:]
        if r < 0.15 and i:
            edges[a] = []
        elif r < 0.45:
            edges[a] = [rnd.choice(later)]
        elif r < 0.55 and switches and len(later) >= 3:
            edges[a] = tuple(rnd.choice(later) for _ in range(rnd.randint(3, 6)))
        else:
            t = rnd.choice(later if rnd.random() < 0.8 or not i else addrs[:i + 1])
            f = rnd.choice(later)
            edges[a] = [t] if t == f else [t, f]
    edges[addrs[-1]] = []
    seen, work = {addrs[0]}, [addrs[0]]
    while work:
        for s in set(edges[work.pop()]):
            if s not in seen:
                seen.add(s)
                work.append(s)
    return {a: edges[a] for a in addrs if a in seen}


def test_random_cfgs_run_like_the_cfg():
    """Structured output executes the same blocks in the same order as the CFG, whatever the
    branches decide (gotos included), for random graphs with loops, shared tails and exits."""
    import random
    for seed in range(300):
        rnd = random.Random(seed)
        edges = _random_cfg(rnd, rnd.randint(3, 14), switches=seed % 2 == 1)
        fn = _cfg(edges, min(edges))
        tree = Structurer(fn).run()
        for oracle in _oracles(15):
            assert _run_tree(tree, oracle, tables=_tables(fn)) == _run_cfg(fn, oracle), (seed, edges)

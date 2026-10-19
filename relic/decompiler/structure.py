"""Stage 4: control-flow structuring.

Turns the IR control-flow graph into a tree of structured constructs --
`if`/`else`, `while`/`do`/`while(1)` loops with `break`/`continue`, and
`switch` from a jump table -- falling back to labels and `goto` for edges
that do not fit a structured pattern. The result is rendered as indented
pseudocode by `to_pseudocode`.

Structuring works on the CFG only (block successors), so it is independent
of whether the IR is in SSA form. It is deliberately conservative: when a
region is not provably reducible it emits a `goto` rather than guessing, so
the printed control flow always matches the graph.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..progress import checkpoint
from .ir import (BinOp, Branch, IndirectJump, IRFunction, Jump, Reg, Return, Stmt, UnOp, fmt, fmt_stmt, walk)

EXIT = -1
SMALL_TAIL = 3   # statements a block may have and still be duplicated instead of reached by goto
DUP_BLOCKS = 6   # a tail region of at most this many blocks ...
DUP_STMTS = 12   # ... and statements is copied rather than reached by goto


# ------------------------------------------------------------------- AST nodes
@dataclass
class Seq:
    items: list = field(default_factory=list)
    end: int | None = field(default=None, compare=False)   # the stop flow reached at its end, if any


@dataclass
class Block:
    addr: int
    stmts: list[Stmt]
    copy: bool = False   # a duplicated small block (printed without its label)


@dataclass
class If:
    addr: int
    cond: object
    then: object
    els: object = None


@dataclass
class Loop:
    kind: str          # while | dowhile | inf
    cond: object       # None for `inf`
    body: object
    header: int | None = None   # header block (a `goto` may target it: the label goes before `while`)


@dataclass
class Case:
    addr: int          # first block of the case body
    values: list       # case labels (empty when the index could not be recovered)
    default: bool
    body: object


@dataclass
class Switch:
    addr: int
    expr: object       # the switch index (or the raw table address when unrecognised)
    cases: list        # list of Case


@dataclass
class Jump1:           # break | continue | goto
    kind: str
    addr: int = 0      # goto target


@dataclass
class Ret:
    stmt: Return


# --------------------------------------------------------------- graph helpers
def _rpo(entry, succ):
    seen, post, stack = {entry}, [], [(entry, iter(succ(entry)))]
    while stack:
        a, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            post.append(a)
        elif nxt not in seen:
            seen.add(nxt)
            stack.append((nxt, iter(succ(nxt))))
    post.reverse()
    return post


def _domtree(entry, succ, pred):
    rpo = _rpo(entry, succ)
    idx = {a: i for i, a in enumerate(rpo)}
    idom = {entry: entry}

    def inter(a, b):
        while a != b:
            while idx[a] > idx[b]:
                a = idom[a]
            while idx[b] > idx[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for a in rpo[1:]:
            ps = [p for p in pred(a) if p in idom]
            if not ps:
                continue
            new = ps[0]
            for p in ps[1:]:
                new = inter(p, new)
            if idom.get(a) != new:
                idom[a] = new
                changed = True
    return idom


def _negate(c):
    """Logical negation, inverting comparisons rather than wrapping in `!`."""
    if isinstance(c, UnOp) and c.op == "!":
        return c.a
    if isinstance(c, BinOp):
        if c.op[0] == "f":
            from .fp import is_fcmp, negate_fcmp
            if is_fcmp(c):
                return negate_fcmp(c)
        if c.op == "==":
            return BinOp("!=", c.a, c.b, 1)
        if c.op == "!=":
            return BinOp("==", c.a, c.b, 1)
        swap = {"<u": "<=u", "<=u": "<u", "<s": "<=s", "<=s": "<s"}
        if c.op in swap:
            return BinOp(swap[c.op], c.b, c.a, 1)
        if c.op in ("&&", "||") and c.bits == 1:      # De Morgan
            return BinOp("||" if c.op == "&&" else "&&", _negate(c.a), _negate(c.b), 1)
    return UnOp("!", c, 1)


def _terminator(blk):
    last = blk.stmts[-1] if blk.stmts else None
    if isinstance(last, (Branch, Jump, IndirectJump, Return)):
        return blk.stmts[:-1], last
    return blk.stmts, None


# ------------------------------------------------------------------- structurer
def _switch_index(expr):
    """(index expression, bias) of a jump-table address `table[idx - bias]`, if recognisable."""
    from .ir import Cast, Const, Load

    def strip(e):
        while isinstance(e, Cast) and e.kind in ("zext", "sext"):
            e = e.a
        return e
    # `base + (table[idx] << 2)` (AArch64, Thumb tbh): the index is inside the loaded entry
    for x in walk(expr):
        if isinstance(x, Load) and x is not expr:
            idx, bias = _switch_index(x.addr) if any(isinstance(n, BinOp) and n.op in ("*", "<<")
                                                     for n in walk(x.addr)) else (None, 0)
            if idx is None and isinstance(x.addr, BinOp) and x.addr.op == "+":
                a, b = x.addr.a, x.addr.b
                if isinstance(a, Const) != isinstance(b, Const):
                    idx = strip(b if isinstance(a, Const) else a)
            if idx is not None:
                return idx, bias
            break
    for x in walk(expr):
        if isinstance(x, BinOp) and isinstance(x.b, Const) and (
                (x.op == "*" and x.b.value in (1, 2, 4, 8)) or (x.op == "<<" and x.b.value in (0, 1, 2, 3))):
            idx = x.a
            while isinstance(idx, Cast) and idx.kind in ("zext", "sext"):
                idx = idx.a
            bias = 0
            if isinstance(idx, BinOp) and idx.op in ("+", "-") and isinstance(idx.b, Const):
                bias = -idx.b.signed if idx.op == "+" else idx.b.signed
                idx = idx.a
            return idx, bias
    # byte table (Thumb `tbb`): `table[idx]` with the scale folded away
    from .ir import Load
    for x in walk(expr):
        if isinstance(x, Load) and x.bits == 8 and isinstance(x.addr, BinOp) and x.addr.op == "+":
            a, b = x.addr.a, x.addr.b
            if isinstance(a, Const) and not isinstance(b, Const):
                return b, 0
            if isinstance(b, Const) and not isinstance(a, Const):
                return a, 0
    return None, 0


def _small_return(blk) -> bool:
    """A block that only returns a constant / variable: cheap to duplicate instead of a goto."""
    from .ir import Const, Var
    return len(blk.stmts) == 1 and isinstance(blk.stmts[0], Return) and \
        (blk.stmts[0].value is None or isinstance(blk.stmts[0].value, (Const, Var, Reg)))


class _Ctx:
    """One level of the break/continue context: a loop or a switch."""
    __slots__ = ("kind", "header", "follow", "body", "latch", "latch_cond")

    def __init__(self, kind, header, follow, body=frozenset()):
        self.kind, self.header, self.follow, self.body = kind, header, follow, body
        self.latch = self.latch_cond = None


class Structurer:
    def __init__(self, fn: IRFunction):
        self.fn = fn
        self.hidden: set[int] = set()       # statements not to print (ids): see _switch_index_via
        self.blocks = fn.blocks
        self.succ = {a: [s for s in b.succs if s in fn.blocks] for a, b in self.blocks.items()}
        self.pred = {a: [p for p in b.preds if p in fn.blocks] for a, b in self.blocks.items()}
        self.idom = _domtree(fn.addr, lambda a: self.succ.get(a, []), lambda a: self.pred.get(a, []))
        self.ipdom = self._post_idom()
        self.loops = self._find_loops()        # header -> dict(body, follow, kind, latches)
        self.emitted: set[int] = set()
        self.gotos: set[int] = set()
        self.rpo_index = {a: k for k, a in enumerate(_rpo(fn.addr, lambda a: self.succ.get(a, [])))}
        self._dup_depth = 0

    # -- dominance -----------------------------------------------------------
    def _dominates(self, a, b):
        while True:
            if a == b:
                return True
            nb = self.idom.get(b)
            if nb is None or nb == b:
                return False
            b = nb

    def _post_idom(self):
        terminals = [a for a in self.blocks if not self.succ[a]]
        fs = {a: list(self.succ[a]) for a in self.blocks}
        for t in terminals:
            fs[t] = fs.get(t, []) + [EXIT]
        fs[EXIT] = []
        rs: dict[int, list[int]] = {a: [] for a in fs}
        for a, outs in fs.items():
            for b in outs:
                rs[b].append(a)
        return _domtree(EXIT, lambda a: rs.get(a, []), lambda a: fs.get(a, []))

    def _postdom(self, a):
        p = self.ipdom.get(a)
        return None if p in (None, EXIT, a) else p

    # -- loops ---------------------------------------------------------------
    def _find_loops(self):
        loops = {}
        for u in self.blocks:
            if u not in self.idom:
                continue
            for h in self.succ[u]:
                if self._dominates(h, u):             # back edge u -> h
                    loops.setdefault(h, []).append(u)
        out = {}
        for h, latches in loops.items():
            body = {h}
            stack = list(latches)
            while stack:
                n = stack.pop()
                if n not in body:
                    body.add(n)
                    stack += [p for p in self.pred[n] if p != h and p in self.idom]
            exits = [s for n in sorted(body) for s in self.succ[n] if s not in body]
            follow = None
            latch = latches[0] if len(latches) == 1 else None
            lterm = _terminator(self.blocks[latch])[1] if latch is not None else None
            hbody, hterm = _terminator(self.blocks[h])
            if len(self.succ[h]) == 2 and any(s not in body for s in self.succ[h]) and not hbody \
                    and isinstance(hterm, Branch):
                # pre-tested loop: the header is nothing but the test that exits
                # (statements before the test would run once more than `while (c) {...}` says)
                kind, follow = "while", next(s for s in self.succ[h] if s not in body)
            elif latch is not None and isinstance(lterm, Branch) and \
                    any(s not in body for s in self.succ[latch]):
                # post-tested loop: the single latch tests and either repeats or leaves
                kind, follow = "dowhile", next(s for s in self.succ[latch] if s not in body)
            else:
                kind = "inf"   # endless: rendered while(1) with explicit break/continue
                # leave to the exit most body blocks agree on (the first in layout order)
                follow = exits[0] if exits else None
            meet = self._exits_meet(body, exits)
            if meet is not None and meet != follow:
                # the loop's exits each run a few statements and then meet: leaving it is
                # `{ ...; break; }` at each exit, and the code after the loop starts where they meet
                kind, follow = "inf", meet
            out[h] = {"body": frozenset(body), "follow": follow, "kind": kind, "latch": latch}
        return out

    def _exits_meet(self, body, exits):
        """The block several exits of a loop all lead to, each through at most one small block
        of its own (returns aside), or None."""
        targets = set()
        for e in dict.fromkeys(exits):
            blk = self.blocks.get(e)
            if blk is None:
                return None
            if _small_return(blk):
                continue
            stmts, term = _terminator(blk)
            nxt = self.succ.get(e, [])
            if len(self.pred.get(e, [])) == 1 and len(nxt) == 1 and nxt[0] not in body and \
                    not isinstance(term, (Branch, IndirectJump, Return)) and len(stmts) <= DUP_STMTS:
                targets.add(nxt[0])
            else:
                targets.add(e)
        if len(targets) != 1 or len(set(exits)) < 2:
            return None
        m = targets.pop()
        return m if m in self.blocks else None

    # -- code generation -----------------------------------------------------
    def run(self):
        tree = self._region(self.fn.addr, None, [])
        # safety net: anything structuring could not reach in-line is emitted under a
        # label so no code is ever silently dropped (guards against irreducible CFGs)
        kept = set()
        for a in _rpo(self.fn.addr, lambda x: self.succ.get(x, [])):
            if a not in self.emitted:
                self.gotos.add(a)
                kept.add(a)
                tree.items.append(self._region(a, None, []))
        _drop_fallthrough_gotos(tree, None)
        self.gotos = kept | _goto_targets(tree)
        return tree

    def _revisit(self, n, stops, ctx) -> Seq:
        """Flow reaches `n`, which was already emitted elsewhere: duplicate it when it is a
        small tail (a return, or a few statements leading straight to where this region goes
        anyway), otherwise jump to it with a `goto`."""
        blk = self.blocks[n]
        if _small_return(blk):
            return Seq([Ret(blk.stmts[0])])
        body, term = _terminator(blk)
        if len(body) <= SMALL_TAIL and not isinstance(term, (Branch, IndirectJump)):
            if isinstance(term, Return):
                return Seq([Block(n, body, copy=True), Ret(term)])
            nxt = self.succ[n][0] if len(self.succ[n]) == 1 else None
            if nxt is not None:
                # a break / continue first: the loop's follow may also be this region's stop,
                # and falling out of the region would run the loop's test instead
                edge = self._edge(nxt, ctx)
                if edge is not None:
                    return Seq([Block(n, body, copy=True), edge])
                if nxt in (stops if isinstance(stops, (set, frozenset)) else {stops}):
                    return Seq([Block(n, body, copy=True)], end=nxt)
                if _small_return(self.blocks[nxt]):
                    return Seq([Block(n, body, copy=True), Ret(self.blocks[nxt].stmts[0])])
        region = self._dup_region(n, stops, ctx)
        if region is not None:
            return self._duplicate(n, region, stops, ctx)
        return Seq([self._goto(n)])

    def _dup_region(self, n, stops, ctx):
        """The blocks to copy so that reaching `n` again needs no goto, or None if too costly.

        The region must be small (DUP_BLOCKS blocks, DUP_STMTS statements), acyclic,
        free of loop headers and switches, and every way out of it must be one
        this region handles anyway: the stop the current region ends at, a
        break / continue of the enclosing construct, or a `return`.
        """
        if self._dup_depth >= 2:
            return None
        stop_set = stops if isinstance(stops, (set, frozenset)) else {stops}
        region, work, total = set(), [n], 0
        while work:
            a = work.pop()
            if a in region:
                continue
            blk = self.blocks.get(a)
            if blk is None or a in self.loops or a == self.fn.addr:
                return None
            body, term = _terminator(blk)
            if isinstance(term, IndirectJump):
                return None
            region.add(a)
            total += len(body)
            if len(region) > DUP_BLOCKS or total > DUP_STMTS:
                return None
            for s in self.succ.get(a, ()):
                if s in stop_set or self._edge_kind(s, ctx) is not None:
                    continue
                if self._dominates(s, a):        # a back edge: a loop, not a tail
                    return None
                if _small_return(self.blocks[s]):
                    continue
                work.append(s)
        return region

    def _edge_kind(self, target, ctx):
        """Like `_edge`, but without side effects (no goto bookkeeping)."""
        if not ctx or target is None:
            return None
        top = ctx[-1]
        if top.kind == "switch" and target == top.follow:
            return "break"
        loop = next((c for c in reversed(ctx) if c.kind == "loop"), None)
        if loop is None:
            return None
        if target == loop.header and loop.latch_cond is None:
            return "continue"
        if target == loop.follow and top is loop:
            return "break"
        if target == loop.follow or self._outer_exit(target, ctx, loop):
            return "goto"
        return None

    def _duplicate(self, n, region, stops, ctx) -> Seq:
        """Structure a copy of `region` (already emitted elsewhere) at this point."""
        saved = set(self.emitted)
        self.emitted -= region
        self._dup_depth += 1
        try:
            seq = self._region(n, stops, ctx)
        finally:
            self._dup_depth -= 1
            self.emitted = saved
        return seq

    def _goto(self, n):
        blk = self.blocks.get(n)
        if blk is not None and _small_return(blk):
            return Ret(blk.stmts[0])                # (going to a bare `return x`: just return)
        self.gotos.add(n)
        return Jump1("goto", n)

    def _region(self, n, stop, ctx, loop_body: bool = False):
        """Structure from `n` until a block in `stop`. `loop_body`: this is a do-while's body
        itself, whose end is where its latch's test runs."""
        checkpoint()
        seq = Seq()
        stops = stop if isinstance(stop, (set, frozenset)) else {stop}
        while n is not None and n not in stops and n != EXIT:
            if n not in self.blocks:            # outside the function: nothing to structure
                seq.items.append(Jump1("goto", n))
                break
            if n in self.emitted:
                edge = self._edge(n, ctx)
                if edge is not None:
                    seq.items.append(edge)
                else:
                    again = self._revisit(n, stops, ctx)
                    seq.items.extend(again.items)
                    n = again.end           # a copied tail that runs to the stop ends there too
                break
            # a loop header we are not already inside -> emit the whole loop
            if n in self.loops and not any(c.kind == "loop" and c.header == n for c in ctx):
                node, follow = self._loop(n, ctx)
                seq.items.append(node)
                n = follow
                # leaving it may leave (or restart) an enclosing loop too
                edge = self._edge(n, ctx)
                if edge is not None:
                    seq.items.append(edge)
                    break
                continue
            self.emitted.add(n)
            blk = self.blocks[n]
            body, term = _terminator(blk)
            seq.items.append(Block(n, body, copy=self._dup_depth > 0))
            inner = next((c for c in reversed(ctx) if c.kind == "loop"), None)
            if inner is not None and inner.latch_cond is not None and n == inner.latch:
                # do-while latch: its test is the loop condition. Reached inside a branch (not
                # at the end of the body), go to that test: `continue` in a do-while does
                if not loop_body:
                    seq.items.append(Jump1("continue"))
                break
            if isinstance(term, Return):
                seq.items.append(Ret(term))
                n = None
            elif isinstance(term, IndirectJump) and not term.targets:
                seq.items.append(Block(n, [term], copy=True))   # unresolved: `goto *expr`
                n = None
            elif isinstance(term, IndirectJump):
                node, n = self._switch(n, term, None, ctx, self._postdom(n))
                seq.items.append(node)
            elif isinstance(term, Branch):
                node, n = self._if(n, term, stops, ctx)
                seq.items.append(node)
            else:  # Jump or fall-through
                nxt = self.succ[n][0] if self.succ[n] else None
                edge = self._edge(nxt, ctx)
                if edge is not None:
                    seq.items.append(edge)
                    n = None
                else:
                    n = nxt
        if n is not None and n in stops:
            seq.end = n
        return seq

    def _edge(self, target, ctx):
        """break / continue (or goto) if `target` leaves or restarts an enclosing construct."""
        if not ctx or target is None:
            return None
        top = ctx[-1]
        if top.kind == "switch" and target == top.follow:
            return Jump1("break")
        loop = next((c for c in reversed(ctx) if c.kind == "loop"), None)
        if loop is None:
            return None
        if target == loop.header and loop.latch_cond is None:
            return Jump1("continue")
        if target == loop.follow:
            return Jump1("break") if top is loop else self._goto(target)
        if self._outer_exit(target, ctx, loop):
            return self._goto(target)
        return None

    def _outer_exit(self, target, ctx, inner) -> bool:
        """`target` restarts or leaves a loop around the innermost one: C has no `continue 2`,
        it is a `goto`."""
        return any(c.kind == "loop" and c is not inner and target in (c.header, c.follow) for c in ctx)

    def _loop(self, h, ctx):
        info = self.loops[h]
        follow = info["follow"]
        c = _Ctx("loop", h, follow, info["body"])
        c.latch, c.latch_cond = info["latch"], None
        blk = self.blocks[h]
        body_stmts, term = _terminator(blk)
        if info["kind"] == "while" and isinstance(term, Branch):
            # the header is the loop test; the body is the side that stays in the loop
            self.emitted.add(h)
            stay = term.true if term.false == follow else term.false
            cond = term.cond if term.false == follow else _negate(term.cond)
            inner = Seq()
            if body_stmts:
                # statements before the test run on every iteration; keep them visible
                # inside the loop (rendered as a comment-free prefix of the body)
                inner.items.append(Block(h, body_stmts))
            inner.items.append(self._region(stay, h, ctx + [c]))
            return Loop("while", cond, inner, h), follow
        if info["kind"] == "dowhile":
            lterm = _terminator(self.blocks[c.latch])[1]
            cond = lterm.cond if lterm.true == h else _negate(lterm.cond)
            c.latch_cond = cond
            body = self._region(h, follow, ctx + [c], loop_body=True)
            return Loop("dowhile", cond, body, h), follow
        # endless: structure the whole body starting at the header
        return Loop("inf", None, self._region(h, follow, ctx + [c]), h), follow

    def _if(self, n, term: Branch, stops, ctx):
        follow = self._postdom(n)
        loop = next((c for c in reversed(ctx) if c.kind == "loop"), None)
        if loop is not None and follow is not None and follow not in loop.body:
            follow = None   # the join lies outside the loop: each side leaves on its own
        sw = ctx[-1] if ctx and ctx[-1].kind == "switch" else None
        if sw is not None and follow is not None and follow == sw.follow:
            follow = None
        cond, t, f = term.cond, term.true, term.false
        if follow is None:
            follow = self._join(n, t, f, loop, sw, stops)
        stop_set = stops if isinstance(stops, (set, frozenset)) else {stops}
        # sides that leave this region by reaching its stop (not by a break / continue of their own)
        leave = [x for x in dict.fromkeys((t, f)) if x in stop_set and self._edge_kind(x, ctx) is None]
        if (follow is None or follow not in stop_set) and len(leave) == 1:
            # the post-dominator lies beyond the stop (or there is none): the stop is where the
            # `if` ends, or the leaving side would fall into the code that follows instead
            follow = leave[0]

        # bounds check guarding a jump table -> switch with a default
        for tgt, other, _c in ((f, t, cond), (t, f, _negate(cond))):
            sb = self.blocks.get(tgt)
            if sb is not None and tgt not in self.emitted and self.pred.get(tgt) == [n] and \
                    len(sb.stmts) == 1 and isinstance(sb.stmts[0], IndirectJump) and sb.stmts[0].targets:
                self.emitted.add(tgt)
                return self._switch(tgt, sb.stmts[0], other, ctx, follow)

        def branch(target):
            if target == follow:
                return None
            edge = self._edge(target, ctx)
            if edge is not None:
                return edge
            if target in stops:
                return None
            inner_stops = {follow} if follow is not None else stops
            if target in self.emitted:
                return self._revisit(target, inner_stops, ctx)
            return self._region(target, inner_stops, ctx)

        then = branch(t)
        els = branch(f)
        if follow is None:
            # no join, but a side that runs to this region's stop continues there (its other
            # side leaves on its own): flow after the `if` is that stop. Sides running to two
            # different stops: one continues, the other says where it goes
            ran = [x for x in (then, els) if isinstance(x, Seq) and x.end is not None]
            ends = list(dict.fromkeys(x.end for x in ran))
            if len(ends) > 1:
                keep = next((e for e in ends if self._edge_kind(e, ctx) is None), ends[0])
                for x in ran:
                    if x.end != keep:
                        x.items.append(self._edge(x.end, ctx) or self._goto(x.end))
                        x.end = None
                ends = [keep]
            if ends:
                follow = ends[0]
        if then is None and els is not None:      # keep the taken side non-empty
            cond, then, els = _negate(cond), els, None
        return If(n, cond, then, els), follow

    def _join(self, n, t, f, loop, sw, stops):
        """Where the two sides of the branch at `n` meet when there is no post-dominator.

        With a `return` (or a loop exit) on one side, no block post-dominates the
        branch, but the sides may still meet: the first block (in reverse
        post-order) that `n` dominates and both sides reach, without leaving the
        enclosing loop, is the join. Sides that never get there end in their
        own return / break / goto.
        """
        stop_set = stops if isinstance(stops, (set, frozenset)) else {stops}
        limit = loop.body if loop is not None else None

        def reach(start, avoid=None):
            if start == avoid:
                return set()
            seen = {start}
            work = [start]
            while work:
                a = work.pop()
                for s in self.succ.get(a, ()):
                    if s in seen or s == n or (limit is not None and s not in limit) or s in stop_set or s == avoid:
                        continue
                    if self._dominates(s, a):        # back edge: not part of this acyclic region
                        continue
                    if loop is not None and s == loop.header:
                        continue
                    if sw is not None and s == sw.follow:
                        continue
                    seen.add(s)
                    work.append(s)
            return seen

        both = reach(t) & reach(f)
        cands = [m for m in both if m not in self.emitted and self._dominates(n, m) and m in self.rpo_index]

        def joins(m) -> bool:
            # neither side gets past `m` without going through it: code after the `if` (from m
            # on) is then reached only through m, never also from inside a branch
            after = reach(m)
            return not (reach(t, m) & after) and not (reach(f, m) & after)
        cands = [m for m in sorted(cands, key=self.rpo_index.__getitem__) if joins(m)]
        return cands[0] if cands else None

    def _switch_index_via(self, term: IndirectJump, n: int | None = None):
        """The index of a jump through a variable holding the computed target (`v2 = base +
        table[v1]; goto *v2`): from its single definition, which is dropped when nothing else
        reads it (the switch shows the index instead)."""
        from .ir import StackVar, Var
        if not isinstance(term.expr, (Var, StackVar)):
            return None, 0
        from .ir import Assign
        defs, uses = _var_defs_and_uses(self.fn)
        hit = defs.get(term.expr)
        if hit is None and n is not None:
            # defined more than once (two switches through the same variable): the definition in
            # the jump's own block
            blk = self.blocks.get(n)
            d = next((x for x in reversed(blk.stmts) if isinstance(x, Assign) and x.dst == term.expr), None) \
                if blk is not None else None
            if d is not None:
                idx, bias = _switch_index(d.src)
                return (idx, bias) if idx is not None and term.expr not in set(walk(idx)) else (None, 0)
        if hit is None:
            return None, 0
        b, d = hit
        idx, bias = _switch_index(d.src)
        if idx is not None and uses.get(term.expr, 0) == 1 and term.expr not in set(walk(idx)):
            self.hidden.add(id(d))          # (the emitter leaves it out)
        return idx, bias

    def _switch(self, n, term: IndirectJump, default, ctx, follow):
        """Switch on `term`'s jump table; `follow` is where every case ends up (or None)."""
        loop = next((c for c in reversed(ctx) if c.kind == "loop"), None)
        if loop is not None and follow is not None and follow not in loop.body:
            follow = None
        c = _Ctx("switch", n, follow)
        inner = ctx + [c]
        idx, bias = _switch_index(term.expr)
        if idx is None:
            idx, bias = self._switch_index_via(term, n)
        values: dict[int, list[int]] = {}
        for k, t in enumerate(term.table or term.targets):
            values.setdefault(t, []).append(k + bias)
        targets = [t for t in dict.fromkeys(term.targets) if t in self.blocks]
        if default is not None and default not in targets:
            targets.append(default)
        # case order: by smallest label, default last -- unless a case falls through into
        # another, in which case code layout order is the one that keeps the fall-through
        layout = sorted(targets)
        targets.sort(key=lambda t: (t == default and not values.get(t), min(values.get(t, [1 << 62]))))
        if any(self.succ.get(t) and len(self.succ[t]) == 1 and self.succ[t][0] in values for t in targets):
            targets = layout
        cases = []
        for i, t in enumerate(targets):
            labels = values.get(t, []) if idx is not None else []
            is_default = t == default
            stops = {follow} | set(targets[i + 1:i + 2])
            if t == follow:
                body = Seq([Jump1("break")])
            elif t in self.emitted:
                body = Seq([self._edge(t, inner) or (Ret(self.blocks[t].stmts[0]) if _small_return(self.blocks[t])
                                                      else self._goto(t))])
            else:
                body = self._region(t, stops, inner)
                if not _ends(body):
                    nxt = targets[i + 1] if i + 1 < len(targets) else None
                    # fell off the end: into the next case (fall-through) or out of the switch
                    if not (nxt is not None and body.end == nxt):
                        body.items.append(Jump1("break"))
            cases.append(Case(t, labels, is_default, body))
        return Switch(n, idx if idx is not None else term.expr, cases), follow


def _first_addr(node):
    """The block control enters `node` at, if it is a labelled one."""
    while isinstance(node, Seq):
        if not node.items:
            return None
        node = node.items[0]
    if isinstance(node, Block):
        return None if node.copy else node.addr
    if isinstance(node, Loop):
        return node.header
    return None


def _tail_goto(node, target) -> bool:
    """Whether every way through the end of `node` is a `goto target` (the plain last one)."""
    node = _last(node)
    return isinstance(node, Jump1) and node.kind == "goto" and node.addr == target


def _strip_tail_goto(node, target) -> None:
    """Remove `goto target` wherever it is the last thing done in `node` (inside `if`s, not loops)."""
    while isinstance(node, Seq) and node.items:
        last = node.items[-1]
        if isinstance(last, Jump1) and last.kind == "goto" and last.addr == target:
            node.items.pop()
            return
        if isinstance(last, If):
            for side in (last.then, last.els):
                if side is not None:
                    _strip_tail_goto(side, target)
            return
        node = last if isinstance(last, Seq) else None


def _drop_fallthrough_gotos(node, follow) -> None:
    """A `goto L` at the end of an `if` branch whose `if` is followed by L anyway: dropped."""
    if isinstance(node, Seq):
        k = 0
        while k < len(node.items):
            it = node.items[k]
            # `if (c) { T; goto L; } else { L: E }` is `if (c) { T } L: E`
            for side, other, neg in (("then", "els", False), ("els", "then", True)):
                if not isinstance(it, If) or it.els is None:
                    break
                first = _first_addr(getattr(it, other))
                if first is not None and _tail_goto(getattr(it, side), first):
                    _strip_tail_goto(getattr(it, side), first)
                    body = getattr(it, other)
                    keep = getattr(it, side)
                    node.items[k] = If(it.addr, _negate(it.cond) if neg else it.cond, keep, None)
                    node.items.insert(k + 1, body)
                    it = node.items[k]
                    break
            k += 1
        for k, it in enumerate(node.items):
            nxt = _first_addr(Seq(node.items[k + 1:])) if k + 1 < len(node.items) else follow
            if isinstance(it, If):
                if nxt is not None:
                    _strip_tail_goto(Seq([it]), nxt)
                _drop_fallthrough_gotos(it.then, nxt)
                _drop_fallthrough_gotos(it.els, nxt)
            elif isinstance(it, Seq):
                _drop_fallthrough_gotos(it, nxt)
            elif isinstance(it, Loop):
                _drop_fallthrough_gotos(it.body, None)
            elif isinstance(it, Switch):
                for c in it.cases:
                    _drop_fallthrough_gotos(c.body, None)
    elif isinstance(node, If):
        _drop_fallthrough_gotos(node.then, follow)
        _drop_fallthrough_gotos(node.els, follow)


def _goto_targets(node) -> set[int]:
    out = set()
    if isinstance(node, Seq):
        for it in node.items:
            out |= _goto_targets(it)
    elif isinstance(node, Jump1) and node.kind == "goto":
        out.add(node.addr)
    elif isinstance(node, If):
        out |= _goto_targets(node.then) | _goto_targets(node.els)
    elif isinstance(node, Loop):
        out |= _goto_targets(node.body)
    elif isinstance(node, Switch):
        for c in node.cases:
            out |= _goto_targets(c.body)
    return out


def _ends(node) -> bool:
    """Control never runs off the end of `node` (it returns or jumps on every way)."""
    node = _last(node)
    if isinstance(node, If):
        return node.els is not None and _ends(node.then) and _ends(node.els)
    return isinstance(node, (Ret, Jump1))


def _last(node):
    """The last item of a sequence, looking into nested sequences."""
    while isinstance(node, Seq):
        if not node.items:
            return None
        node = node.items[-1]
    return node


def _var_defs_and_uses(fn: IRFunction):
    from .ir import Assign, StackVar, Var, stmt_defs, stmt_exprs
    defs: dict = {}
    uses: dict = {}
    for b in fn.blocks.values():
        for s in b.stmts:
            for d in stmt_defs(s):
                if isinstance(d, (Var, StackVar)):
                    defs.setdefault(d, []).append((b, s))
            for top in stmt_exprs(s):
                for x in walk(top):
                    if isinstance(x, (Var, StackVar)):
                        uses[x] = uses.get(x, 0) + 1
    return {v: d[0] for v, d in defs.items() if len(d) == 1 and isinstance(d[0][1], Assign)}, uses


def _iter_blocks(node):
    if isinstance(node, Seq):
        for it in node.items:
            yield from _iter_blocks(it)
    elif isinstance(node, Block):
        yield node


# ------------------------------------------------------------------- rendering
def structure(fn: IRFunction) -> Seq:
    return Structurer(fn).run()


def to_pseudocode(fn: IRFunction, an=None) -> str:
    st = Structurer(fn)
    tree = st.run()
    out = [f"{fn.name}()"]
    out.append("{")
    _render(tree, 1, out, st.gotos)
    out.append("}")
    return "\n".join(out)


def _ind(n):
    return "    " * n


def _is_phi(s):
    from .ir import Assign, Phi
    return isinstance(s, Assign) and isinstance(s.src, Phi)


def _trim_continue(body):
    """Drop a redundant `continue` at the very end of a loop body."""
    node = body
    while isinstance(node, Seq) and node.items:
        last = node.items[-1]
        if isinstance(last, Jump1) and last.kind == "continue":
            node.items.pop()
            return
        node = last if isinstance(last, Seq) else None
        if node is None:
            return


def _render(node, depth, out, gotos):
    if isinstance(node, Seq):
        for it in node.items:
            _render(it, depth, out, gotos)
    elif isinstance(node, Block):
        if node.addr in gotos and not node.copy:
            out.append(f"{_ind(depth - 1)}  loc_{node.addr:x}:")
        for s in node.stmts:
            if _is_phi(s):
                continue  # SSA bookkeeping, not a real statement (removed at out-of-SSA)
            out.append(f"{_ind(depth)}{fmt_stmt(s)};")
    elif isinstance(node, Ret):
        v = node.stmt.value
        out.append(f"{_ind(depth)}return{(' ' + fmt(v)) if v is not None else ''};")
    elif isinstance(node, Jump1):
        if node.kind == "goto":
            out.append(f"{_ind(depth)}goto loc_{node.addr:x};")
        else:
            out.append(f"{_ind(depth)}{node.kind};")
    elif isinstance(node, If):
        out.append(f"{_ind(depth)}if ({fmt(node.cond)}) {{")
        _render(node.then if node.then is not None else Seq(), depth + 1, out, gotos)
        if node.els is not None:
            out.append(f"{_ind(depth)}}} else {{")
            _render(node.els, depth + 1, out, gotos)
        out.append(f"{_ind(depth)}}}")
    elif isinstance(node, Loop):
        if node.kind == "while":
            out.append(f"{_ind(depth)}while ({fmt(node.cond)}) {{")
        elif node.kind == "dowhile":
            out.append(f"{_ind(depth)}do {{")
        else:
            out.append(f"{_ind(depth)}while (1) {{")
        _trim_continue(node.body)
        _render(node.body, depth + 1, out, gotos)
        out.append(f"{_ind(depth)}}} while ({fmt(node.cond)});" if node.kind == "dowhile" else f"{_ind(depth)}}}")
    elif isinstance(node, Switch):
        out.append(f"{_ind(depth)}switch ({fmt(node.expr)}) {{")
        for case in node.cases:
            for label in case_labels(case):
                out.append(f"{_ind(depth)}{label}:")
            _render(case.body, depth + 1, out, gotos)
        out.append(f"{_ind(depth)}}}")


def case_labels(case: Case, fmt_value=str) -> list[str]:
    labels = [f"case {fmt_value(v)}" for v in case.values]
    if case.default:
        labels.append("default")
    if not labels:
        labels.append(f"case loc_{case.addr:x}")
    return labels


__all__ = ["Structurer", "structure", "to_pseudocode", "case_labels"]

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

from .ir import (BinOp, Branch, CallStmt, IndirectJump, IRFunction, Jump, Return, Stmt, UnOp, fmt, fmt_stmt)

EXIT = -1


# ------------------------------------------------------------------- AST nodes
@dataclass
class Seq:
    items: list = field(default_factory=list)


@dataclass
class Block:
    addr: int
    stmts: list[Stmt]


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


@dataclass
class Switch:
    addr: int
    expr: object
    cases: list        # list of (target_addr, node)


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
        if c.op == "==":
            return BinOp("!=", c.a, c.b, 1)
        if c.op == "!=":
            return BinOp("==", c.a, c.b, 1)
        swap = {"<u": "<=u", "<=u": "<u", "<s": "<=s", "<=s": "<s"}
        if c.op in swap:
            return BinOp(swap[c.op], c.b, c.a, 1)
    return UnOp("!", c, 1)


def _terminator(blk):
    last = blk.stmts[-1] if blk.stmts else None
    if isinstance(last, (Branch, Jump, IndirectJump, Return)):
        return blk.stmts[:-1], last
    return blk.stmts, None


# ------------------------------------------------------------------- structurer
class Structurer:
    def __init__(self, fn: IRFunction):
        self.fn = fn
        self.blocks = fn.blocks
        self.succ = {a: list(b.succs) for a, b in self.blocks.items()}
        self.pred = {a: list(b.preds) for a, b in self.blocks.items()}
        self.idom = _domtree(fn.addr, lambda a: self.succ.get(a, []), lambda a: self.pred.get(a, []))
        self.ipdom = self._post_idom()
        self.loops = self._find_loops()        # header -> dict(body, follow, kind)
        self.loop_of = {}                       # node -> header it most tightly belongs to
        for h, info in self.loops.items():
            for n in info["body"]:
                self.loop_of.setdefault(n, h)
        self.emitted: set[int] = set()
        self.gotos: set[int] = set()

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
                    stack += [p for p in self.pred[n] if p != h]
            exits = [s for n in body for s in self.succ[n] if s not in body]
            follow = exits[0] if exits else None
            # pre-tested loop: the header itself is the conditional that exits
            if len(self.succ[h]) == 2 and any(s not in body for s in self.succ[h]):
                kind, follow = "while", next(s for s in self.succ[h] if s not in body)
            else:
                kind = "inf"   # post-tested / endless: rendered while(1) with explicit break/continue
            out[h] = {"body": body, "follow": follow, "kind": kind, "latches": set(latches)}
        return out

    # -- code generation -----------------------------------------------------
    def run(self):
        tree = self._region(self.fn.addr, None, [])
        # safety net: anything structuring could not reach in-line is emitted under a
        # label so no code is ever silently dropped (guards against irreducible CFGs)
        for a in _rpo(self.fn.addr, lambda x: self.succ.get(x, [])):
            if a not in self.emitted:
                self.gotos.add(a)
                tree.items.append(self._region(a, None, []))
        return tree

    def _region(self, n, stop, loopstack):
        seq = Seq()
        while n is not None and n != stop and n != EXIT:
            if n in self.emitted:
                seq.items.append(Jump1("goto", n))
                self.gotos.add(n)
                break
            # a loop header we are not already inside -> emit the whole loop
            if n in self.loops and (not loopstack or loopstack[-1][0] != n):
                node, follow = self._loop(n, loopstack)
                seq.items.append(node)
                n = follow
                continue
            self.emitted.add(n)
            blk = self.blocks[n]
            body, term = _terminator(blk)
            if body:
                seq.items.append(Block(n, body))
            if isinstance(term, Return):
                seq.items.append(Ret(term))
                n = None
            elif isinstance(term, IndirectJump):
                seq.items.append(self._switch(n, term, loopstack))
                n = None
            elif isinstance(term, Branch):
                node, n = self._if(n, term, stop, loopstack)
                seq.items.append(node)
            else:  # Jump or fall-through
                nxt = self.succ[n][0] if self.succ[n] else None
                edge = self._loop_edge(nxt, loopstack)
                if edge is not None:
                    seq.items.append(edge)
                    n = None
                else:
                    n = nxt
        return seq

    def _loop_edge(self, target, loopstack):
        """break / continue if `target` leaves or restarts the innermost loop."""
        if not loopstack or target is None:
            return None
        header, follow = loopstack[-1]
        if target == header:
            return Jump1("continue")
        if target == follow:
            return Jump1("break")
        return None

    def _loop(self, h, loopstack):
        info = self.loops[h]
        follow = info["follow"]
        ls = loopstack + [(h, follow)]
        blk = self.blocks[h]
        body_stmts, term = _terminator(blk)
        if info["kind"] == "while" and isinstance(term, Branch):
            # the header is the loop test; the body is the side that stays in the loop
            self.emitted.add(h)
            stay = term.true if term.false == follow else term.false
            cond = term.cond if term.false == follow else _negate(term.cond)
            inner = Seq()
            if body_stmts:
                inner.items.append(Block(h, body_stmts))
            inner.items.append(self._region(stay, h, ls))
            return Loop("while", cond, inner), follow
        # endless / post-tested: structure the whole body starting at the header
        # (ls has (h, follow) on top, so _region treats h as an ordinary block, not a new loop)
        return Loop("inf", None, self._region(h, follow, ls)), follow

    def _if(self, n, term: Branch, stop, loopstack):
        follow = self._postdom(n)
        cond, t, f = term.cond, term.true, term.false

        def branch(target):
            if target == follow or target == stop:
                return None
            edge = self._loop_edge(target, loopstack)
            if edge is not None:
                return edge
            if target in self.emitted:
                self.gotos.add(target)
                return Jump1("goto", target)
            return self._region(target, follow, loopstack)

        then = branch(t)
        els = branch(f)
        if then is None and els is not None:      # keep the taken side non-empty
            cond, then, els = _negate(cond), els, None
        return If(n, cond, then, els), follow

    def _switch(self, n, term: IndirectJump, loopstack):
        follow = self._postdom(n)
        cases = []
        for t in dict.fromkeys(term.targets):
            if t == follow:
                cases.append((t, None))
            elif t in self.emitted:
                self.gotos.add(t)
                cases.append((t, Jump1("goto", t)))
            else:
                cases.append((t, self._region(t, follow, loopstack)))
        return Switch(n, term.expr, cases)


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
        if node.addr in gotos:
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
        out.append(f"{_ind(depth)}}}")
    elif isinstance(node, Switch):
        out.append(f"{_ind(depth)}switch ({fmt(node.expr)}) {{")
        for target, body in node.cases:
            out.append(f"{_ind(depth)}case loc_{target:x}:")
            if body is not None:
                _render(body, depth + 1, out, gotos)
        out.append(f"{_ind(depth)}}}")


__all__ = ["Structurer", "structure", "to_pseudocode"]

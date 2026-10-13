"""Leave SSA form: replace phi nodes by copies and coalesce variables.

Each phi `d = phi(p1: v1, p2: v2, ...)` gets a fresh temporary `t`: every
predecessor `pi` assigns `t = vi` just before its terminator and the phi
becomes `d = t`. Because `t` is fresh and only read at the top of the phi's
block, this is correct on critical edges and for parallel (swap) phis
without any edge splitting.

The copies are then removed again by coalescing: variables connected by a
copy are merged into one when their live ranges do not interfere (Chaitin
style, with the usual copy exception). What remains is a conventional IR
whose `Var`s are program variables rather than SSA values -- the input the
structurer and the C emitter want.

Merged variables are renamed `Var(name, 0, bits)`. A class that contains a
register's entry value (`rdi_0`) is named after the register, so the IR
interpreter still binds it to the register's value on entry; the other
classes are named `v1`, `v2`, ... in order of first definition.
"""
from __future__ import annotations

import copy

from .ir import (TERMINATORS, Assign, Expr, IRFunction, Phi, Var, map_stmt, stmt_defs, stmt_exprs, transform,
                 walk)


def _vars(e: Expr):
    return (x for x in walk(e) if isinstance(x, Var))


def _uses(s) -> set[Var]:
    return {v for top in stmt_exprs(s) for v in _vars(top)}


class _UF:
    def __init__(self):
        self.parent: dict[Var, Var] = {}

    def find(self, v: Var) -> Var:
        p = self.parent.setdefault(v, v)
        if p != v:
            p = self.parent[v] = self.find(p)
        return p

    def union(self, a: Var, b: Var) -> Var:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra
        return ra


def _prune_dead(fn: IRFunction):
    """Drop phis and call results that no real statement ever reads.

    Plain dead-code elimination counts a phi's sources as uses, so a web of
    phis that only feed each other (registers a loop's calls clobber) stays
    alive. Here liveness starts from the non-phi statements and flows back
    through phis only.
    """
    phis: dict[Var, Assign] = {}
    useful: set[Var] = set()
    for s in fn.stmts():
        if isinstance(s, Assign) and isinstance(s.src, Phi):
            phis[s.dst] = s
        else:
            useful |= _uses(s)
    work = [v for v in useful if v in phis]
    while work:
        for v in _vars(phis[work.pop()].src):
            if v not in useful:
                useful.add(v)
                if v in phis:
                    work.append(v)
    for b in fn.blocks.values():
        kept = []
        for s in b.stmts:
            if isinstance(s, Assign) and isinstance(s.src, Phi) and s.dst not in useful:
                continue
            if hasattr(s, "defs") and not isinstance(s, Assign):
                s.defs = [(r, v) for r, v in s.defs if not isinstance(v, Var) or v in useful]
            kept.append(s)
        b.stmts = kept


def _insert_copies(fn: IRFunction) -> list[Assign]:
    """Replace phis by copies through fresh temporaries; return the new copy statements."""
    copies: list[Assign] = []
    counter = 0
    for b in fn.blocks.values():
        phis = [s for s in b.stmts if isinstance(s, Assign) and isinstance(s.src, Phi)]
        for ph in phis:
            counter += 1
            tmp = Var(f"phi.{counter}", 1, ph.dst.bits)
            for pred, val in dict(ph.src.sources).items():
                pb = fn.blocks.get(pred)
                if pb is None:
                    continue
                cp = Assign(pb.stmts[-1].addr if pb.stmts else pred, tmp, val)
                if pb.stmts and isinstance(pb.stmts[-1], TERMINATORS):
                    pb.stmts.insert(len(pb.stmts) - 1, cp)
                else:
                    pb.stmts.append(cp)
                copies.append(cp)
            ph.src = tmp
            copies.append(ph)
    return copies


def _interference(fn: IRFunction) -> dict[Var, set[Var]]:
    """Variables simultaneously live at some definition point."""
    succs = {a: [s for s in b.succs if s in fn.blocks] for a, b in fn.blocks.items()}
    gen: dict[int, set[Var]] = {}
    kill: dict[int, set[Var]] = {}
    for a, b in fn.blocks.items():
        g, k = set(), set()
        for s in b.stmts:
            g |= _uses(s) - k
            k |= {d for d in stmt_defs(s) if isinstance(d, Var)}
        gen[a], kill[a] = g, k
    live_in = {a: set() for a in fn.blocks}
    changed = True
    while changed:
        changed = False
        for a in fn.blocks:
            out = set().union(*(live_in[s] for s in succs[a])) if succs[a] else set()
            new = gen[a] | (out - kill[a])
            if new != live_in[a]:
                live_in[a] = new
                changed = True

    graph: dict[Var, set[Var]] = {}

    def edge(x: Var, y: Var):
        if x != y:
            graph.setdefault(x, set()).add(y)
            graph.setdefault(y, set()).add(x)

    for a, b in fn.blocks.items():
        live = set().union(*(live_in[s] for s in succs[a])) if succs[a] else set()
        for s in reversed(b.stmts):
            defs = [d for d in stmt_defs(s) if isinstance(d, Var)]
            skip = s.src if isinstance(s, Assign) and isinstance(s.src, Var) else None
            for d in defs:
                graph.setdefault(d, set())
                for v in live:
                    if v != skip:
                        edge(d, v)
                for d2 in defs:
                    edge(d, d2)
            live -= set(defs)
            live |= _uses(s)
        # values live on entry to the function (entry registers) all coexist
        if a == fn.addr:
            for x in live:
                graph.setdefault(x, set())
                for y in live:
                    edge(x, y)
    return graph


def out_of_ssa(fn: IRFunction) -> IRFunction:
    """Return a copy of SSA `fn` with phis removed and variables coalesced."""
    fn = copy.deepcopy(fn)
    _prune_dead(fn)
    copies = _insert_copies(fn)
    graph = _interference(fn)
    uf = _UF()
    members: dict[Var, set[Var]] = {}
    nbrs: dict[Var, set[Var]] = {}

    def cls(v: Var) -> Var:
        r = uf.find(v)
        if r not in members:
            members[r] = {r}
            nbrs[r] = set(graph.get(r, ()))
        return r

    def entry(r: Var) -> str | None:
        names = {m.name for m in members[r] if m.version == 0}
        return names.pop() if len(names) == 1 else ("" if names else None)

    def try_merge(a: Var, b: Var):
        if not (isinstance(a, Var) and isinstance(b, Var)):
            return
        ra, rb = cls(a), cls(b)
        if ra == rb or a.bits != b.bits:
            return
        if nbrs[ra] & members[rb] or nbrs[rb] & members[ra]:
            return
        ea, eb = entry(ra), entry(rb)
        if ea is not None and eb is not None:
            return  # never merge two different entry registers
        r = uf.union(ra, rb)
        other = rb if r == ra else ra
        members[r] |= members.pop(other)
        nbrs[r] |= nbrs.pop(other)

    # phi copies first (they are what out-of-SSA introduced), then copies already in the IR
    for cp in copies:
        try_merge(cp.dst, cp.src)
    for s in list(fn.stmts()):
        if isinstance(s, Assign) and isinstance(s.dst, Var) and isinstance(s.src, Var):
            try_merge(s.dst, s.src)

    # name the classes
    names: dict[Var, Var] = {}
    counter = 0
    order: list[Var] = []
    for s in fn.stmts():
        for top in stmt_exprs(s):
            order += _vars(top)
        order += [d for d in stmt_defs(s) if isinstance(d, Var)]
    for v in order:
        r = cls(v)
        if r in names:
            continue
        e = entry(r)
        if e:
            names[r] = Var(e, 0, r.bits)
        else:
            counter += 1
            names[r] = Var(f"v{counter}", 0, r.bits)

    def rn(e: Expr) -> Expr:
        return transform(e, lambda x: names[cls(x)] if isinstance(x, Var) else x)

    for b in fn.blocks.values():
        kept = []
        for s in b.stmts:
            map_stmt(s, rn)
            if isinstance(s, Assign) and isinstance(s.dst, Var):
                s.dst = names[cls(s.dst)]
                if s.src == s.dst:
                    continue  # coalesced copy
            elif hasattr(s, "defs"):
                s.defs = [(r, names[cls(v)] if isinstance(v, Var) else v) for r, v in s.defs]
            kept.append(s)
        b.stmts = kept
    return fn


__all__ = ["out_of_ssa"]

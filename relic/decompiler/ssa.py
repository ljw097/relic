"""SSA construction over registers.

Memory stays as it is (Load / Store); only registers become versioned
`Var`s. Version 0 of a register is its value on entry to the function.
Calls get explicit uses (argument registers) and defs (clobbered registers)
from the calling convention so later passes see their register effects.
"""
from __future__ import annotations

import copy

from .arch import ArchInfo
from .ir import (Assign, CallStmt, Effect, Expr, IRFunction, Phi, Reg, Return, Stmt, Unknown, Var, map_stmt,
                 stmt_defs, transform, walk)


# ------------------------------------------------------------------ dominators
def reachable_order(fn: IRFunction) -> list[int]:
    """Blocks reachable from the entry, in reverse post-order."""
    seen, post = {fn.addr}, []
    stack = [(fn.addr, iter(fn.blocks[fn.addr].succs))]
    while stack:
        a, it = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            post.append(a)
        elif nxt in fn.blocks and nxt not in seen:
            seen.add(nxt)
            stack.append((nxt, iter(fn.blocks[nxt].succs)))
    post.reverse()
    return post


def dominators(fn: IRFunction, rpo: list[int]) -> dict[int, int]:
    """Immediate dominators (Cooper, Harvey & Kennedy). The entry maps to itself."""
    index = {a: k for k, a in enumerate(rpo)}
    idom = {fn.addr: fn.addr}

    def intersect(a, b):
        while a != b:
            while index[a] > index[b]:
                a = idom[a]
            while index[b] > index[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for a in rpo[1:]:
            preds = [p for p in fn.blocks[a].preds if p in idom]
            if not preds:
                continue
            new = preds[0]
            for p in preds[1:]:
                new = intersect(p, new)
            if idom.get(a) != new:
                idom[a] = new
                changed = True
    return idom


def frontiers(fn: IRFunction, idom: dict[int, int]) -> dict[int, set[int]]:
    df: dict[int, set[int]] = {a: set() for a in idom}
    for a in idom:
        preds = [p for p in fn.blocks[a].preds if p in idom]
        if len(preds) < 2:
            continue
        for p in preds:
            r = p
            while r != idom[a]:
                df[r].add(a)
                r = idom[r]
    return df


def dom_children(idom: dict[int, int]) -> dict[int, list[int]]:
    kids: dict[int, list[int]] = {a: [] for a in idom}
    for a, d in idom.items():
        if a != d:
            kids[d].append(a)
    for v in kids.values():
        v.sort()
    return kids


# ------------------------------------------------------------- construction
def _prepare(fn: IRFunction, arch: ArchInfo) -> IRFunction:
    """Copy of `fn` with unreachable blocks dropped, preds rebuilt and call effects explicit."""
    fn = copy.deepcopy(fn)
    rpo = reachable_order(fn)
    live = set(rpo)
    fn.blocks = {a: fn.blocks[a] for a in sorted(live)}
    for b in fn.blocks.values():
        b.succs = [s for s in b.succs if s in live]
        b.preds = []
    for b in fn.blocks.values():
        for s in b.succs:
            if b.addr not in fn.blocks[s].preds:
                fn.blocks[s].preds.append(b.addr)

    widths: dict[str, int] = {}
    for s in fn.stmts():
        for e in stmt_defs(s):
            widths[e.name] = e.bits
        for top in _exprs(s):
            for x in walk(top):
                if isinstance(x, Reg):
                    widths[x.name] = x.bits
    for name in (arch.sp, arch.ret, *arch.call_reads, *arch.call_clobbers):
        widths.setdefault(name, 1 if len(name) == 2 and name.endswith("f") else
                          (128 if name.startswith("xmm") else arch.bits))

    def reg(n):
        return Reg(n, widths[n])

    for s in fn.stmts():
        if isinstance(s, CallStmt) and not s.uses and not s.defs:
            s.uses = [(r, reg(r)) for r in arch.call_reads if not r.startswith("xmm") or r in _seen(fn)]
            s.defs = [(r, reg(r)) for r in arch.call_clobbers if not r.startswith("xmm") or r in _seen(fn)]
        elif isinstance(s, Return) and s.value is None:
            s.value = reg(arch.ret)
    return fn


def _seen(fn: IRFunction) -> set[str]:
    cache = getattr(fn, "_seen_regs", None)
    if cache is None:
        cache = set()
        for s in fn.stmts():
            for e in stmt_defs(s):
                cache.add(e.name)
            for top in _exprs(s):
                cache.update(x.name for x in walk(top) if isinstance(x, Reg))
        fn._seen_regs = cache
    return cache


def _exprs(s: Stmt) -> list[Expr]:
    from .ir import stmt_exprs
    return stmt_exprs(s)


def to_ssa(fn: IRFunction, arch: ArchInfo) -> IRFunction:
    """Return an SSA copy of `fn` (the input is left untouched)."""
    fn = _prepare(fn, arch)
    rpo = reachable_order(fn)
    idom = dominators(fn, rpo)
    df = frontiers(fn, idom)
    kids = dom_children(idom)

    # 1. phi placement at iterated dominance frontiers
    defsites: dict[str, set[int]] = {}
    width: dict[str, int] = {}
    for b in fn.blocks.values():
        for s in b.stmts:
            for d in stmt_defs(s):
                defsites.setdefault(d.name, set()).add(b.addr)
                width[d.name] = d.bits
    phis: dict[int, dict[str, Assign]] = {a: {} for a in fn.blocks}
    for name, sites in defsites.items():
        work = list(sites)
        while work:
            a = work.pop()
            for f in df.get(a, ()):
                if name not in phis[f]:
                    phis[f][name] = Assign(f, Reg(name, width[name]), Phi((), width[name]))
                    if f not in sites:
                        work.append(f)
    phi_args: dict[tuple[int, str], dict[int, Expr]] = {}
    for a, ps in phis.items():
        if ps:
            fn.blocks[a].stmts[:0] = [ps[n] for n in sorted(ps)]

    # 2. renaming along the dominator tree
    counter: dict[str, int] = {}
    stacks: dict[str, list[int]] = {}

    def cur(r: Reg) -> Var:
        st = stacks.get(r.name)
        return Var(r.name, st[-1] if st else 0, r.bits)

    def fresh(r: Reg) -> Var:
        v = counter.get(r.name, 0) + 1
        counter[r.name] = v
        stacks.setdefault(r.name, []).append(v)
        return Var(r.name, v, r.bits)

    def rename_uses(e: Expr) -> Expr:
        return transform(e, lambda x: cur(x) if isinstance(x, Reg) else x)

    def visit(a: int):
        pushed: list[str] = []
        blk = fn.blocks[a]
        for s in blk.stmts:
            is_phi = isinstance(s, Assign) and isinstance(s.src, Phi)
            if not is_phi:
                map_stmt(s, rename_uses)
            if isinstance(s, Assign):
                s.dst = fresh(s.dst)
                pushed.append(s.dst.name)
            elif isinstance(s, (CallStmt, Effect, Unknown)):
                new = []
                for r, d in s.defs:
                    v = fresh(d)
                    pushed.append(v.name)
                    new.append((r, v))
                s.defs = new
        for succ in blk.succs:
            for name, ph in phis[succ].items():
                phi_args.setdefault((succ, name), {})[a] = cur(Reg(name, width[name]))
        for k in kids[a]:
            yield k
        yield ("pop", pushed)

    # iterative DFS over the dominator tree
    stack = [visit(fn.addr)]
    while stack:
        item = next(stack[-1], None)
        if item is None:
            stack.pop()
        elif isinstance(item, tuple):
            for n in item[1]:
                stacks[n].pop()
        else:
            stack.append(visit(item))

    for a, ps in phis.items():
        for name, ph in ps.items():
            args = phi_args.get((a, name), {})
            srcs = tuple((p, args[p]) for p in fn.blocks[a].preds if p in args)
            ph.src = Phi(srcs, ph.src.bits)
    return fn

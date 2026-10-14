"""The C the emitter prints for a structured function runs like the CFG.

Random control-flow graphs (tests/test_structure.py) go through the structurer and
`CWriter.node` -- every tree rewrite the emitter makes (else-if chains, `&&` merging, loop
body tidying, early-exit flattening) included. Statements print as `T(addr)` (record the
block), branch conditions as `C(addr)` and jump-table indexes as `S(addr, n)`, both answered
by an oracle hashed from (block, visit count, seed). All functions are compiled into one
program with gcc and run; each trace must match the CFG walked with the same oracle.
"""
import os
import random
import shutil
import subprocess
from types import SimpleNamespace

import pytest
from test_structure import _cfg, _random_cfg, _tables

from relic.decompiler.chains import switchify
from relic.decompiler.emit import CWriter
from relic.decompiler.ir import BinOp, Const, UnOp, Var
from relic.decompiler.structure import Structurer

LIMIT = 60
SEEDS = 12
M32 = 0xFFFFFFFF


def _hash(a: int, k: int, seed: int) -> int:
    h = (a * 0x9E3779B1 + k * 0x85EBCA77 + seed * 0xC2B2AE3D) & M32
    h ^= h >> 15
    h = (h * 0x2C1B3C6D) & M32
    h ^= h >> 12
    return h


def _run_cfg(fn, seed):
    tables = _tables(fn)
    trace, seen, a = [], {}, fn.addr
    while len(trace) < LIMIT:
        trace.append(a)
        seen[a] = seen.get(a, 0) + 1
        outs = fn.blocks[a].succs
        if not outs:
            break
        h = _hash(a, seen[a], seed)
        if a in tables:
            a = tables[a][h % len(tables[a])]
        else:
            a = outs[0] if len(outs) == 1 or h & 1 else outs[1]
    return trace


def _c_function(k: int, fn) -> str:
    tables = _tables(fn)
    st = Structurer(fn)
    tree = switchify(st.run(), frozenset(st.gotos))
    w = object.__new__(CWriter)
    w.p = SimpleNamespace(gotos=st.gotos, fn=fn)
    lines: list[str] = []
    w.emit = lambda text, addr, depth: lines.append("    " * (depth + 1) + text)
    w.stmt = lambda s: f"T(0x{s.addr:x});"
    w._term_addr = lambda a: a

    def expr(e, prec=0):
        if isinstance(e, Var) and e.name[0] == "c":
            return f"C(0x{e.name[1:]})"
        if isinstance(e, Var) and e.name[0] == "s":
            a = int(e.name[1:], 16)
            return f"S(0x{a:x}, {len(tables[a])})"
        if isinstance(e, Const):
            return str(e.value)
        if isinstance(e, UnOp) and e.op == "!":
            return f"!({expr(e.a)})"
        if isinstance(e, BinOp) and e.op in ("&&", "||", "==", "!="):
            return f"({expr(e.a)} {e.op} {expr(e.b)})"
        raise AssertionError(f"condition {e}")
    w.expr = expr
    w.node(tree, 0)
    return f"static void f{k}(void)\n{{\n" + "\n".join(lines) + "\n}\n"


_PRELUDE = r"""
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#define LIMIT %d
static jmp_buf full;
static int trace[LIMIT], ntrace, seen[4096];
static unsigned seed, val[4096];
static unsigned hash(unsigned a, unsigned k, unsigned s)
{
    unsigned h = a * 0x9E3779B1u + k * 0x85EBCA77u + s * 0xC2B2AE3Du;
    h ^= h >> 15; h *= 0x2C1B3C6Du; h ^= h >> 12;
    return h;
}
#define T(a) do { if (ntrace >= LIMIT) longjmp(full, 1); trace[ntrace++] = (a); \
                  seen[a] += 1; val[a] = hash((a), seen[a], seed); } while (0)
#define C(a) (val[a] & 1)
#define S(a, n) (val[a] %% (n))
static void run(void (*f)(void), int k, unsigned s)
{
    ntrace = 0; seed = s; memset(seen, 0, sizeof seen);
    if (!setjmp(full))
        f();
    printf("%%d %%u", k, s);
    for (int i = 0; i < ntrace; i++)
        printf(" %%d", trace[i]);
    printf("\n");
}
""" % LIMIT


@pytest.mark.skipif(shutil.which("gcc") is None, reason="needs gcc")
def test_emitted_c_runs_like_the_cfg(tmp_path):
    fns = []
    for seed in range(250):
        rnd = random.Random(1000 + seed)
        edges = _random_cfg(rnd, rnd.randint(3, 14), switches=seed % 2 == 1)
        fns.append(_cfg(edges, min(edges)))
    src = _PRELUDE + "".join(_c_function(k, fn) for k, fn in enumerate(fns))
    src += "int main(void)\n{\n" + "".join(
        f"    for (unsigned s = 0; s < {SEEDS}; s++) run(f{k}, {k}, s);\n" for k in range(len(fns))) + \
        "    return 0;\n}\n"
    c = tmp_path / "flows.c"
    c.write_text(src)
    exe = str(tmp_path / "flows")
    r = subprocess.run(["gcc", "-O0", "-w", "-o", exe, str(c)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[:3000]
    out = subprocess.run([exe], capture_output=True, text=True, check=True).stdout.splitlines()
    got = {}
    for line in out:
        k, s, *rest = line.split()
        got[int(k), int(s)] = [int(x) for x in rest]
    bad = [(k, s) for k, fn in enumerate(fns) for s in range(SEEDS) if got[k, s] != _run_cfg(fn, s)]
    if bad:
        k, s = bad[0]
        fn = fns[k]
        edges = {hex(a): [hex(x) for x in b.succs] for a, b in fn.blocks.items()}
        pytest.fail(f"{len(bad)} runs differ; first: f{k} seed {s}\n{edges}\n"
                    f"C:   {[hex(x) for x in got[k, s]]}\nCFG: {[hex(x) for x in _run_cfg(fn, s)]}\n"
                    + _c_function(k, fn))
    assert os.path.exists(exe)

"""Compare relic's decompiler with angr's on the same functions of stripped binaries: how many
each decompiles, how fast, how much of the output is valid C, and gotos per function.

    python tools/compare_decompilers.py CORPUS_DIR NAME... [--angr-python PY] [--limit N]
                                       [--timeout SECONDS] [--json OUT.json]

The functions are the ground truth of tools/compare_tools.py (the unstripped build's function
symbols in .text) that both tools found in the stripped copy, up to --limit per binary. "Valid
C": the function's pseudocode alone passes `gcc -fsyntax-only` after a prelude of the integer
types both tools use; errors about undeclared identifiers (globals and functions neither tool
declares) and implicit declarations are not counted -- only what makes it not C.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from compare_tools import text_range, truth  # noqa: E402

RELIC = r'''
import json, sys, time
sys.path.insert(0, sys.argv[2])
from relic.analysis import analyze
from relic.decompiler.emit import decompile
an = analyze(sys.argv[1])
for a in json.loads(sys.argv[3]):
    f = an.functions.get(a)
    t = time.perf_counter()
    try:
        text = decompile(an, f).text if f is not None else None
        err = None if text else "not a function"
    except Exception as e:
        text, err = None, f"{type(e).__name__}: {e}"[:160]
    print(json.dumps({"addr": a, "text": text, "error": err, "seconds": time.perf_counter() - t}), flush=True)
'''

ANGR = r'''
import json, logging, sys, time
logging.disable(logging.CRITICAL)
import angr
p = angr.Project(sys.argv[1], auto_load_libs=False, load_debug_info=False)
cfg = p.analyses.CFGFast(normalize=True)
obj = p.loader.main_object
bias = obj.mapped_base - obj.linked_base
for a in json.loads(sys.argv[3]):
    t = time.perf_counter()
    try:
        f = cfg.kb.functions.get(a + bias)
        if f is None:
            raise KeyError("not a function")
        d = p.analyses.Decompiler(f, cfg=cfg.model)
        text = d.codegen.text if d.codegen is not None else None
        err = None if text else "no output"
    except Exception as e:
        text, err = None, f"{type(e).__name__}: {e}"[:160]
    print(json.dumps({"addr": a, "text": text, "error": err, "seconds": time.perf_counter() - t}), flush=True)
'''

PRELUDE = """#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef unsigned char uchar; typedef unsigned short ushort; typedef unsigned int uint;
typedef unsigned long ulong; typedef long long longlong; typedef unsigned long long ulonglong;
typedef __int128 int128_t; typedef unsigned __int128 uint128_t;
"""
_NOT_C = re.compile(r"error: (?!.*(undeclared|implicit declaration|unknown type name|storage size|"
                    r"invalid use of undefined type|dereferencing pointer to incomplete type|"
                    r"has no member named|incomplete type))")


def run(code: str, python: str, path: str, addrs: list[int], timeout: int) -> dict:
    out = {}
    try:
        r = subprocess.run([python, "-c", code, path, os.path.dirname(HERE), json.dumps(addrs)],
                           capture_output=True, text=True, timeout=timeout)
        lines = r.stdout.splitlines()
    except subprocess.TimeoutExpired as e:
        lines = (e.stdout or b"").decode(errors="replace").splitlines() if isinstance(e.stdout, bytes) else \
            (e.stdout or "").splitlines()
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        out[d["addr"]] = d
    return out


def valid_c(text: str) -> bool:
    """The pseudocode is C apart from what it refers to without declaring it."""
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fp:
        fp.write(PRELUDE + text + "\n")
        name = fp.name
    try:
        r = subprocess.run(["gcc", "-fsyntax-only", "-w", "-fpermissive", "-std=gnu11", name], capture_output=True,
                           text=True)
        return not any(_NOT_C.search(line) for line in r.stderr.splitlines())
    finally:
        os.unlink(name)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("names", nargs="+")
    ap.add_argument("--angr-python", default=sys.executable)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--tools", default="relic,angr")
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    tools = args.tools.split(",")
    results = {}
    for name in args.names:
        full = os.path.join(args.corpus, name)
        lo, hi = text_range(full)
        funcs = sorted(truth(full))
        if args.limit:
            funcs = funcs[:args.limit]
        res = {}
        if "relic" in tools:
            res["relic"] = run(RELIC, sys.executable, full + ".stripped", funcs, args.timeout)
        if "angr" in tools:
            res["angr"] = run(ANGR, args.angr_python, full + ".stripped", funcs, args.timeout)
        both = [a for a in funcs if all(a in res[t] for t in res)]
        row = {"functions": len(both)}
        for tool, got in res.items():
            done = [got[a] for a in both if got[a]["text"]]
            row[tool] = {"decompiled": len(done), "failed": len(both) - len(done),
                         "seconds_total": round(sum(got[a]["seconds"] for a in both), 2),
                         "valid_c": sum(1 for d in done if valid_c(d["text"])),
                         "gotos": sum(len(re.findall(r"\bgoto\b", d["text"])) for d in done),
                         "lines": sum(d["text"].count("\n") + 1 for d in done)}
            print(f"{name:20} {tool:6} {json.dumps(row[tool])}", flush=True)
        results[name] = row
    if args.json:
        with open(args.json, "w") as fp:
            json.dump(results, fp, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

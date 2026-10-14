"""Decompiler benchmark: analysis time, full decompilation time, slowest functions, output quality.

    python tools/bench.py /usr/bin/grep [--limit 30] [--profile] [--json out.json]

Every function is decompiled with a time cap (default 30 s, SIGALRM); one that hits it is
reported as a timeout instead of stalling the run. Quality counters: `goto`s, unresolved
indirect jumps and opaque `__asm`-style statements in the pseudocode, so a speed change that
makes the output worse shows up next to the timings.
"""
from __future__ import annotations

import argparse
import cProfile
import json
import os
import pstats
import re
import signal
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from relic.analysis import analyze  # noqa: E402
from relic.decompiler.emit import decompile  # noqa: E402


class Timeout(Exception):
    pass


def _alarm(_sig, _frame):
    raise Timeout()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--cap", type=float, default=30.0, help="seconds per function")
    ap.add_argument("--limit", type=int, default=0, help="only the first N functions")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--profile", action="store_true", help="print the hottest code (cProfile)")
    ap.add_argument("--json", help="write the numbers here")
    args = ap.parse_args(argv)

    t = time.perf_counter()
    an = analyze(args.binary)
    t_an = time.perf_counter() - t
    funcs = sorted((f for f in an.functions.values() if not f.is_import), key=lambda f: f.addr)
    if args.limit:
        funcs = funcs[:args.limit]
    signal.signal(signal.SIGALRM, _alarm)
    prof = cProfile.Profile() if args.profile else None
    rows, timeouts, errors = [], [], []
    gotos = unresolved = asm = 0
    t = time.perf_counter()
    for f in funcs:
        name = an.name(f.addr) or f.name
        t0 = time.perf_counter()
        signal.setitimer(signal.ITIMER_REAL, args.cap)
        try:
            if prof:
                prof.enable()
            text = decompile(an, f).text
        except Timeout:
            timeouts.append(name)
            text = ""
        except Exception as e:  # noqa: BLE001 - counted, the run goes on
            errors.append(f"{name}: {type(e).__name__}: {e}")
            text = ""
        finally:
            if prof:
                prof.disable()
            signal.setitimer(signal.ITIMER_REAL, 0)
        dt = time.perf_counter() - t0
        rows.append((dt, name, len(f.blocks)))
        gotos += len(re.findall(r"\bgoto loc_", text))
        unresolved += text.count("unresolved")
        asm += text.count("__asm")
    t_dec = time.perf_counter() - t
    rows.sort(reverse=True)
    print(f"{args.binary}: {len(an.functions)} functions, analysis {t_an:.1f}s")
    print(f"decompiled {len(funcs)} in {t_dec:.1f}s  (timeouts {len(timeouts)}, errors {len(errors)})")
    print(f"quality: goto {gotos}, unresolved jumps {unresolved}, __asm {asm}")
    for dt, name, nb in rows[:args.top]:
        print(f"  {dt:7.2f}s  {nb:4} blocks  {name}")
    for e in errors[:10]:
        print("  error:", e)
    if prof:
        pstats.Stats(prof).sort_stats("tottime").print_stats(20)
    if args.json:
        with open(args.json, "w") as fp:
            json.dump({"binary": args.binary, "analysis": t_an, "decompile": t_dec, "functions": len(funcs),
                       "timeouts": timeouts, "errors": errors, "goto": gotos, "unresolved": unresolved,
                       "asm": asm, "slowest": rows[:args.top]}, fp, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Compare relic with other open-source binary analysis tools on function detection: how many of
a stripped binary's functions each finds (recall), how many of what it reports are real
functions (precision), and how long it takes.

    python tools/compare_tools.py CORPUS_DIR [--angr-python PY] [--tools relic,angr,r2,lief,ghidra]
                                  [--ghidra GHIDRA_DIR] [--timeout SECONDS] [--json OUT.json]

CORPUS_DIR holds pairs `NAME` (with symbols) and `NAME.stripped`. The ground truth is the
unstripped build's function symbols inside `.text`, read with binutils'
readelf -- none of the compared tools -- and every tool analyses the stripped copy. Only
addresses inside `.text` are scored (PLT stubs and `.init` / `.fini` are not functions of the
program's own code). Each tool runs in a process of its own (angr and LIEF from the Python given
by --angr-python), with a time limit; reported addresses are brought back to link-time
addresses where a tool loads the binary elsewhere (angr and radare2 relocate PIE executables).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# each worker prints {"funcs": [addresses], "base": load bias to subtract or 0}
WORKERS = {
    "relic": '''
import json, sys
sys.path.insert(0, sys.argv[2])
from relic.analysis import analyze
an = analyze(sys.argv[1])
print(json.dumps({"funcs": [a for a, f in an.functions.items() if not f.is_import], "base": 0}))
''',
    "angr": '''
import json, logging, sys
logging.disable(logging.CRITICAL)
import angr
p = angr.Project(sys.argv[1], auto_load_libs=False, load_debug_info=False)
cfg = p.analyses.CFGFast()
obj = p.loader.main_object
funcs = [f.addr for f in cfg.kb.functions.values()
         if not f.is_plt and not f.is_simprocedure and not f.is_syscall and not f.is_alignment
         and obj.contains_addr(f.addr)]
print(json.dumps({"funcs": funcs, "base": obj.mapped_base - obj.linked_base}))
''',
    "lief": '''
import json, sys
import lief
b = lief.parse(sys.argv[1])
print(json.dumps({"funcs": sorted({f.address for f in b.functions}), "base": 0}))
''',
}


GHIDRA_SCRIPT = r'''
// The functions Ghidra's auto-analysis found (not external or thunks) as JSON, to args[0]; "base"
// is its load address of the entry point minus the link-time one (args[1]).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.*;

public class RelicListFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long base = currentProgram.getSymbolTable().getSymbols("entry").next().getAddress().getOffset()
            - Long.parseLong(a[1]);
        StringBuilder b = new StringBuilder("{\"base\": " + base + ", \"funcs\": [");
        boolean first = true;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal() || f.isThunk()) continue;
            b.append(first ? "" : ", ").append(f.getEntryPoint().getOffset());
            first = false;
        }
        try (PrintWriter out = new PrintWriter(new FileWriter(a[0]))) {
            out.println(b.append("]}"));
        }
    }
}
'''


def run_ghidra(ghidra: str, path: str, entry: int, timeout: int) -> dict:
    """Ghidra headless: import with auto-analysis, then RelicListFunctions.java."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "RelicListFunctions.java"), "w") as fp:
            fp.write(GHIDRA_SCRIPT)
        result = os.path.join(tmp, "out.json")
        os.makedirs(os.path.join(tmp, "proj"))
        subprocess.run([os.path.join(ghidra, "support", "analyzeHeadless"), os.path.join(tmp, "proj"), "p",
                        "-import", path, "-scriptPath", tmp, "-postScript", "RelicListFunctions.java", result,
                        str(entry), "-deleteProject"], capture_output=True, text=True, timeout=timeout)
        with open(result) as fp:
            return json.load(fp)


def entry_of(path: str) -> int:
    out = subprocess.run(["readelf", "-hW", path], capture_output=True, text=True).stdout
    return int(re.search(r"Entry point address:\s+0x([0-9a-f]+)", out).group(1), 16)


def text_range(path: str) -> tuple[int, int]:
    out = subprocess.run(["readelf", "-SW", path], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.search(r"\]\s+\.text\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", line)
        if m:
            start = int(m.group(1), 16)
            return start, start + int(m.group(2), 16)
    raise ValueError(f"{path}: no .text")


def thumb(path: str) -> bool:
    """32-bit ARM: bit 0 of a function address is the Thumb bit, not part of it."""
    out = subprocess.run(["readelf", "-hW", path], capture_output=True, text=True).stdout
    return bool(re.search(r"Machine:\s+ARM$", out, re.M))


def truth(path: str) -> set[int]:
    """Function starts: FUNC symbols in .text (readelf)."""
    lo, hi = text_range(path)
    keep = ~1 if thumb(path) else ~0
    out = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True, check=True).stdout
    starts = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 8 and p[3] == "FUNC" and p[6] != "UND":
            a = int(p[1], 16)
            if lo <= a < hi:          # (crt helpers like frame_dummy have size 0: functions too)
                starts.add(a & keep)
    return starts


def run_worker(tool: str, path: str, python: str, timeout: int, ghidra: str | None = None) -> dict:
    t = time.monotonic()
    try:
        if tool == "ghidra":
            got = run_ghidra(ghidra, path, entry_of(path), timeout)
        elif tool == "r2":
            r = subprocess.run(["r2", "-q", "-e", "scr.color=0", "-c", "aaa; aflj", path], capture_output=True,
                               text=True, timeout=timeout)
            data = json.loads(r.stdout.strip().splitlines()[-1] or "[]")
            got = {"funcs": [f["offset"] for f in data], "base": 0}
        else:
            r = subprocess.run([python, "-c", WORKERS[tool], path, os.path.dirname(HERE)], capture_output=True,
                               text=True, timeout=timeout)
            if r.returncode != 0:
                return {"error": r.stderr.strip().splitlines()[-1][:200] if r.stderr.strip() else "failed",
                        "seconds": round(time.monotonic() - t, 2)}
            got = json.loads(r.stdout.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"error": f"timeout ({timeout} s)", "seconds": timeout}
    except (ValueError, IndexError, KeyError, OSError) as e:
        return {"error": f"bad output: {e}", "seconds": round(time.monotonic() - t, 2)}
    got["seconds"] = round(time.monotonic() - t, 2)
    return got


def score(found: set[int], true: set[int]) -> dict:
    hit = len(found & true)
    p = hit / len(found) if found else 0.0
    r = hit / len(true) if true else 0.0
    return {"found": len(found), "correct": hit, "precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--angr-python", default=sys.executable, help="a Python with angr and lief installed")
    ap.add_argument("--tools", default="relic,angr,r2,lief", help="also: ghidra (with --ghidra)")
    ap.add_argument("--ghidra", help="Ghidra's install directory (holds support/analyzeHeadless)")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    tools = args.tools.split(",")
    results = {}
    names = sorted(n for n in os.listdir(args.corpus) if not n.endswith(".stripped")
                   and os.path.exists(os.path.join(args.corpus, n + ".stripped")))
    for name in names:
        full = os.path.join(args.corpus, name)
        stripped = full + ".stripped"
        true = truth(full)
        lo, hi = text_range(full)
        row = {"functions": len(true)}
        for tool in tools:
            py = sys.executable if tool == "relic" else args.angr_python
            got = run_worker(tool, stripped, py, args.timeout, args.ghidra)
            if "error" in got:
                row[tool] = {"error": got["error"], "seconds": got["seconds"]}
            else:
                base = got.get("base", 0)
                keep = ~1 if thumb(full) else ~0
                found = {(a - base) & keep for a in got["funcs"]}
                if tool == "r2" and found.isdisjoint(true) and true:
                    # (radare2 maps a PIE executable elsewhere: bring it back by the entry point)
                    found = _r2_rebase(stripped, full, found, lo, hi)
                found = {a for a in found if lo <= a < hi}
                row[tool] = {**score(found, true), "seconds": got["seconds"]}
            print(f"{name:22} {tool:6} {json.dumps(row[tool])}", flush=True)
        results[name] = row
    if args.json:
        with open(args.json, "w") as fp:
            json.dump(results, fp, indent=1)
    return 0


def _r2_rebase(stripped: str, full: str, found: set[int], lo: int, hi: int) -> set[int]:
    r = subprocess.run(["r2", "-q", "-c", "iej", stripped], capture_output=True, text=True)
    try:
        r2_entry = json.loads(r.stdout)[0]["vaddr"]
    except (ValueError, IndexError, KeyError):
        return found
    out = subprocess.run(["readelf", "-hW", full], capture_output=True, text=True).stdout
    entry = int(re.search(r"Entry point address:\s+0x([0-9a-f]+)", out).group(1), 16)
    return {a - (r2_entry - entry) for a in found}


if __name__ == "__main__":
    sys.exit(main())

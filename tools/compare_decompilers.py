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
import time

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
# the built-in types and calling-convention words each tool's own output uses
TOOL_PRELUDE = {
    "ghidra": """typedef unsigned char undefined; typedef unsigned char undefined1; typedef unsigned short undefined2;
typedef unsigned int undefined3; typedef unsigned int undefined4; typedef unsigned long undefined5;
typedef unsigned long undefined6; typedef unsigned long undefined7; typedef unsigned long undefined8;
typedef unsigned __int128 undefined16; typedef unsigned char byte; typedef signed char sbyte;
typedef unsigned short word; typedef short sword; typedef unsigned int dword; typedef int sdword;
typedef unsigned long qword; typedef long sqword; typedef long double float10; typedef void code;
#define processEntry
#define __cdecl
#define __stdcall
#define __fastcall
#define __thiscall
""",
    "retdec": "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n",   # (what its output includes)
}
_NOT_C = re.compile(r"error: (?!.*(undeclared|implicit declaration|unknown type name|storage size|"
                    r"invalid use of undefined type|dereferencing pointer to incomplete type|"
                    r"has no member named|incomplete type))")


def run_r2(path: str, addrs: list[int], timeout: int) -> dict:
    """radare2's own pseudocode (`pdc`) for each function, after `aaa`. One process for all of
    them: each function's time is the whole run's split evenly."""
    mark = "=RELICFN="
    cmds = "aaa;" + "".join(f"s {a};af;?e {mark}{a};pdc;" for a in addrs)
    t = time.perf_counter()
    try:
        r = subprocess.run(["r2", "-q", "-e", "scr.color=0", "-e", "scr.interactive=false", "-c", cmds, path],
                           capture_output=True, text=True, timeout=timeout)
        text = r.stdout
    except subprocess.TimeoutExpired:
        return {}
    each = (time.perf_counter() - t) / max(len(addrs), 1)
    out = {}
    for part in text.split(mark)[1:]:
        head, _, body = part.partition("\n")
        body = body.strip()
        out[int(head)] = {"addr": int(head), "text": body or None, "error": None if body else "no output",
                          "seconds": each}
    return out


GHIDRA_SCRIPT = r'''
// Decompile the functions at the link-time addresses listed in args[0]; one JSON line each to args[1].
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class RelicDecompileList extends GhidraScript {
    private static String q(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        List<String> lines = Files.readAllLines(Paths.get(a[0]));
        long delta = currentProgram.getSymbolTable().getSymbols("entry").next().getAddress().getOffset()
            - Long.parseLong(lines.get(0).trim());
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new FileWriter(a[1]))) {
            for (String line : lines.subList(1, lines.size())) {
                long addr = Long.parseLong(line.trim());
                Address ad = toAddr(addr + delta);
                long t = System.nanoTime();
                String text = null, err = null;
                Function f = getFunctionAt(ad);
                if (f == null) f = createFunction(ad, null);
                if (f == null) err = "not a function";
                else {
                    DecompileResults r = d.decompileFunction(f, 120, monitor);
                    if (r != null && r.decompileCompleted()) text = r.getDecompiledFunction().getC();
                    else err = r == null ? "failed" : String.valueOf(r.getErrorMessage());
                }
                double sec = (System.nanoTime() - t) / 1e9;
                out.println("{\"addr\": " + addr + ", \"text\": " + (text == null ? "null" : q(text))
                    + ", \"error\": " + (err == null ? "null" : q(err)) + ", \"seconds\": " + sec + "}");
                out.flush();
            }
        }
    }
}
'''


def run_ghidra(ghidra: str, path: str, entry: int, addrs: list[int], timeout: int) -> dict:
    """Ghidra's decompiler (headless: import, auto-analysis, then RelicDecompileList.java)."""
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "RelicDecompileList.java"), "w") as fp:
            fp.write(GHIDRA_SCRIPT)
        with open(os.path.join(tmp, "addrs.txt"), "w") as fp:
            fp.write("\n".join(map(str, [entry, *addrs])) + "\n")
        result = os.path.join(tmp, "out.jsonl")
        os.makedirs(os.path.join(tmp, "proj"))
        try:
            subprocess.run([os.path.join(ghidra, "support", "analyzeHeadless"), os.path.join(tmp, "proj"), "p",
                            "-import", path, "-scriptPath", tmp, "-postScript", "RelicDecompileList.java",
                            os.path.join(tmp, "addrs.txt"), result, "-deleteProject"],
                           capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        if os.path.exists(result):
            for line in open(result):
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                out[d["addr"]] = d
    return out


def run_retdec(retdec: str, path: str, ranges: dict[int, int], timeout: int) -> dict:
    """RetDec on the whole list in one run (`--select-ranges`), its output split per function
    (from its `// Address range: 0x1440 - ...` comment to the `}` in column 0); each function's
    time is the run's split evenly."""
    with tempfile.TemporaryDirectory() as tmp:
        out_c = os.path.join(tmp, "out.c")
        sel = ",".join(f"0x{a:x}-0x{a + max(size, 1) - 1:x}" for a, size in ranges.items())
        t = time.perf_counter()
        try:
            subprocess.run([retdec, path, "-o", out_c, "--select-ranges", sel, "--cleanup"], capture_output=True,
                           text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {}
        each = (time.perf_counter() - t) / max(len(ranges), 1)
        text = open(out_c, errors="replace").read() if os.path.exists(out_c) else ""
    found = {}
    for m in re.finditer(r"^// Address range: 0x([0-9a-f]+) - 0x[0-9a-f]+\n(.*?^\})", text, re.S | re.M):
        found[int(m.group(1), 16)] = m.group(2)
    return {a: {"addr": a, "text": found.get(a), "error": None if a in found else "not in output", "seconds": each}
            for a in ranges}


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


def entry(path: str) -> int:
    out = subprocess.run(["readelf", "-hW", path], capture_output=True, text=True).stdout
    return int(re.search(r"Entry point address:\s+0x([0-9a-f]+)", out).group(1), 16)


def sizes_of(path: str) -> dict[int, int]:
    """Function sizes from the unstripped build's symbols (RetDec decompiles address ranges)."""
    out = subprocess.run(["readelf", "-sW", path], capture_output=True, text=True).stdout
    sizes = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 8 and p[3] == "FUNC" and p[6] != "UND":
            sizes[int(p[1], 16)] = max(sizes.get(int(p[1], 16), 0), int(p[2], 0))
    return sizes


def valid_c(text: str, tool: str = "") -> bool:
    """The pseudocode is C apart from what it refers to without declaring it."""
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fp:
        fp.write(PRELUDE + TOOL_PRELUDE.get(tool, "") + text + "\n")
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
    ap.add_argument("--tools", default="relic,angr", help="relic, angr, r2, ghidra, retdec")
    ap.add_argument("--ghidra", help="Ghidra's install directory (holds support/analyzeHeadless)")
    ap.add_argument("--retdec", help="the retdec-decompiler program")
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
        if "r2" in tools:
            res["r2"] = run_r2(full + ".stripped", funcs, args.timeout)
        if "ghidra" in tools:
            res["ghidra"] = run_ghidra(args.ghidra, full + ".stripped", entry(full), funcs, args.timeout)
        if "retdec" in tools:
            sizes = sizes_of(full)
            res["retdec"] = run_retdec(args.retdec, full + ".stripped", {a: sizes.get(a, 1) for a in funcs},
                                       args.timeout)
        both = [a for a in funcs if all(a in res[t] for t in res)]
        row = {"functions": len(both)}
        for tool, got in res.items():
            done = [got[a] for a in both if got[a]["text"]]
            row[tool] = {"decompiled": len(done), "failed": len(both) - len(done),
                         "seconds_total": round(sum(got[a]["seconds"] for a in both), 2),
                         "valid_c": sum(1 for d in done if valid_c(d["text"], tool)),
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

"""Compare relic's file loader with LIEF: for each file, the entry point, the sections (name,
address, size) and the imported function names each reports, how often they agree, and how
long parsing takes.

    python tools/compare_formats.py FILE... [--lief-python PY] [--json OUT.json]

Both run in processes of their own over the whole list (`relic.loader.load`, `lief.parse`),
timing each file. Sections: the ones mapped in memory (ELF: SHF_ALLOC, `.bss` too). Imports:
every imported symbol, functions and data (`stderr`), weak ones too (`__gmon_start__`), compared
without symbol versions (`printf@GLIBC_2.2.5`).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

RELIC = r'''
import json, sys, time
sys.path.insert(0, sys.argv[1])
from relic.loader import load
for path in sys.argv[2:]:
    t = time.perf_counter()
    try:
        b = load(path)
        out = {"entry": b.entry, "sections": sorted([s.name, s.addr, s.size] for s in b.sections
                                                    if s.addr and s.size and not s.name.startswith("LOAD")),
               "imports": sorted({i.name.split("@")[0] for i in b.imports if i.name}), "format": b.format}
    except Exception as e:
        out = {"error": f"{type(e).__name__}: {e}"[:200]}
    out["seconds"] = time.perf_counter() - t
    print(json.dumps({path: out}), flush=True)
'''

LIEF = r'''
import json, sys, time
import lief
lief.logging.disable()
for path in sys.argv[2:]:
    t = time.perf_counter()
    try:
        b = lief.parse(path)
        if b is None:
            raise ValueError("not parsed")
        fmt = b.format.name if hasattr(b, "format") else type(b).__module__
        if isinstance(b, lief.ELF.Binary):
            secs = [[s.name, s.virtual_address, s.size] for s in b.sections
                    if s.virtual_address and s.size and lief.ELF.Section.FLAGS.ALLOC in s.flags_list]
        elif isinstance(b, lief.PE.Binary):
            base = b.optional_header.imagebase
            secs = [[s.name, base + s.virtual_address, s.virtual_size or s.size] for s in b.sections]
        else:
            secs = [[s.name, s.virtual_address, s.size] for s in b.sections if s.size]
        entry = b.entrypoint
        syms = b.imported_symbols if hasattr(b, "imported_symbols") else b.imported_functions
        imports = sorted({f.name.split("@")[0] for f in syms if f.name})
        out = {"entry": entry, "sections": sorted(secs), "imports": imports, "format": fmt}
    except Exception as e:
        out = {"error": f"{type(e).__name__}: {e}"[:200]}
    out["seconds"] = time.perf_counter() - t
    print(json.dumps({path: out}), flush=True)
'''


def elf_imports(path: str) -> set[str] | None:
    """An ELF file's imports per binutils: the undefined symbols of its dynamic symbol table (no
    version); None for other formats."""
    with open(path, "rb") as fp:
        if fp.read(4) != b"\x7fELF":
            return None
    out = subprocess.run(["readelf", "--dyn-syms", "-W", path], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 8 and p[6] == "UND" and p[7]:
            names.add(p[7].split("@")[0])
    return names


def run(code: str, python: str, files: list[str]) -> dict:
    r = subprocess.run([python, "-c", code, os.path.dirname(HERE), *files], capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        try:
            out.update(json.loads(line))
        except ValueError:
            continue
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--lief-python", default=sys.executable)
    ap.add_argument("--json")
    args = ap.parse_args(argv)
    a = run(RELIC, sys.executable, args.files)
    b = run(LIEF, args.lief_python, args.files)
    rows = {}
    for f in args.files:
        x, y = a.get(f, {"error": "no output"}), b.get(f, {"error": "no output"})
        row = {"relic_s": round(x.get("seconds", 0), 4), "lief_s": round(y.get("seconds", 0), 4)}
        if "error" in x or "error" in y:
            row["relic_error"], row["lief_error"] = x.get("error"), y.get("error")
        else:
            sx = {(n, ad) for n, ad, _ in x["sections"]}
            sy = {(n, ad) for n, ad, _ in y["sections"]}
            row.update(entry=x["entry"] == y["entry"], sections=sx == sy,
                       sections_only_relic=sorted(n for n, _ in sx - sy),
                       sections_only_lief=sorted(n for n, _ in sy - sx),
                       imports=set(x["imports"]) == set(y["imports"]),
                       imports_only_relic=sorted(set(x["imports"]) - set(y["imports"]))[:10],
                       imports_only_lief=sorted(set(y["imports"]) - set(x["imports"]))[:10],
                       n_imports=(len(x["imports"]), len(y["imports"])))
        true = elf_imports(f)
        if true is not None:
            for tool, got in (("relic", x), ("lief", y)):
                if "imports" in got:
                    found = set(got["imports"])
                    row[f"{tool}_imports_missed"] = sorted(true - found)[:10]
                    row[f"{tool}_imports_extra"] = sorted(found - true)[:10]
                    row[f"{tool}_imports_pr"] = (len(found & true), len(found), len(true))
        rows[f] = row
    for tool in ("relic", "lief"):
        prs = [r[f"{tool}_imports_pr"] for r in rows.values() if f"{tool}_imports_pr" in r]
        hit, found, true = (sum(x[k] for x in prs) for k in range(3))
        print(f"{tool} ELF imports vs readelf: precision {hit / found:.4f}, recall {hit / true:.4f}, "
              f"files with every import {sum(1 for x in prs if x[0] == x[2])} of {len(prs)}")
    ok = [r for r in rows.values() if "entry" in r]
    summary = {"files": len(rows), "both_parsed": len(ok),
               "relic_failed": sum(1 for r in rows.values() if r.get("relic_error")),
               "lief_failed": sum(1 for r in rows.values() if r.get("lief_error")),
               "entry_agree": sum(r["entry"] for r in ok), "sections_agree": sum(r["sections"] for r in ok),
               "imports_agree": sum(r["imports"] for r in ok),
               "relic_seconds": round(sum(r["relic_s"] for r in rows.values()), 3),
               "lief_seconds": round(sum(r["lief_s"] for r in rows.values()), 3)}
    print(json.dumps(summary, indent=1))
    if args.json:
        with open(args.json, "w") as fp:
            json.dump({"summary": summary, "files": rows}, fp, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())

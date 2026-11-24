"""Draw the charts of docs/benchmarks.md (SVG, no dependencies) from the JSON the compare_*
scripts write.

    python tools/bench_charts.py --detect detect.json [more.json ...] --decomp decomp.json [more.json ...]
                                 --out docs/benchmarks

Files of each kind are merged per binary, so the tools can come from separate runs.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
import os
from html import escape

# one colour per tool, always the same one (validated categorical palette, fixed order)
# (bars in the order the series dict gives; each chart's order is checked for colour-blind separation)
COLORS = {"Relic": "#2a78d6", "angr": "#eb6834", "radare2": "#1baf7a", "LIEF": "#eda100", "Ghidra": "#6250d6",
          "RetDec": "#008300"}
NAMES = {"relic": "Relic", "angr": "angr", "r2": "radare2", "lief": "LIEF", "ghidra": "Ghidra", "retdec": "RetDec"}
SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
FONT = "font-family=\"-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif\""


def bars(title: str, subtitle: str, groups: list[str], series: dict[str, list[float | None]], fmt, vmax: float,
         note: str = "") -> str:
    """Grouped horizontal bars: one group per row label, one bar per tool, the value at its end."""
    w, right = 760, 70
    left = max(150, 7 * max(len(g) for g in groups) + 24)   # (room for the longest row label)
    bar, gap, group_gap = 14, 2, 18
    tools = [t for t in series if any(v is not None for v in series[t])]
    top = 92
    group_h = len(tools) * (bar + gap) - gap
    h = top + len(groups) * (group_h + group_gap) + (40 if note else 24)
    plot_w = w - left - right
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" {FONT}>',
           f'<rect width="{w}" height="{h}" rx="8" fill="{SURFACE}"/>',
           f'<text x="20" y="30" font-size="17" font-weight="600" fill="{INK}">{escape(title)}</text>',
           f'<text x="20" y="50" font-size="12.5" fill="{INK2}">{escape(subtitle)}</text>']
    x = 20                                         # legend, one row, in tool order
    for t in tools:
        out.append(f'<rect x="{x}" y="64" width="12" height="12" rx="3" fill="{COLORS[t]}"/>')
        out.append(f'<text x="{x + 17}" y="74.5" font-size="12.5" fill="{INK}">{escape(t)}</text>')
        x += 17 + 8 * len(t) + 22
    for k in range(5):                             # recessive grid
        gx = left + plot_w * k / 4
        out.append(f'<line x1="{gx:.1f}" y1="{top - 6}" x2="{gx:.1f}" y2="{h - (34 if note else 18)}" '
                   f'stroke="{GRID}" stroke-width="1"/>')
    y = top
    for gi, g in enumerate(groups):
        out.append(f'<text x="{left - 10}" y="{y + group_h / 2 + 4:.1f}" font-size="12.5" text-anchor="end" '
                   f'fill="{INK}">{escape(g)}</text>')
        for t in tools:
            v = series[t][gi]
            if v is not None:
                bw = max(plot_w * min(v, vmax) / vmax, 2)
                out.append(f'<rect x="{left}" y="{y}" width="{bw:.1f}" height="{bar}" rx="3" fill="{COLORS[t]}">'
                           f'<title>{escape(t)}, {escape(g)}: {escape(fmt(v))}</title></rect>')
                out.append(f'<text x="{left + bw + 5:.1f}" y="{y + bar - 3}" font-size="11" fill="{INK2}">'
                           f'{escape(fmt(v))}</text>')
            y += bar + gap
        y += group_gap - gap
    if note:
        out.append(f'<text x="20" y="{h - 14}" font-size="11.5" fill="{INK2}">{escape(note)}</text>')
    out.append("</svg>")
    return "\n".join(out) + "\n"


def detection(detect: dict) -> tuple[str, str]:
    builds = {"-O0": "O0", "-O2": "O2", "-O2, no .eh_frame": "O2noeh", "AArch64 -O2": "a64"}
    rows = {b: [] for b in builds}
    for name, r in detect.items():
        key = "AArch64 -O2" if "a64" in name else next(b for b, s in builds.items() if name.endswith("-" + s))
        rows[key].append(r)
    f1, secs = {}, {}
    tools = [t for t in ("relic", "angr", "r2", "lief", "ghidra") if any(t in r for r in detect.values())]
    for tool in tools:
        t = NAMES[tool]
        f1[t], secs[t] = [], []
        for b in builds:
            ok = [r[tool] for r in rows[b] if "found" in r.get(tool, {})]
            found, corr = sum(x["found"] for x in ok), sum(x["correct"] for x in ok)
            true = sum(r["functions"] for r in rows[b] if "found" in r.get(tool, {}))
            p, rc = (corr / found if found else 0), corr / true
            f1[t].append(2 * p * rc / (p + rc) if p + rc else None if not ok else 0)
            secs[t].append(sum(x["seconds"] for x in ok))
    n = sum(r["functions"] for r in detect.values())
    a = bars("Function detection (F1)", f"{len(detect)} stripped binaries, {n:,} functions; higher is better",
             list(builds), f1, lambda v: f"{v:.3f}", 1.0,
             "LIEF only reads .eh_frame (the unwind table): a ceiling while it's there, nothing without it.")
    b = bars("Function detection time", "whole analysis, summed over each build's binaries; lower is better",
             list(builds), {t: v for t, v in secs.items() if t != "LIEF"}, lambda v: f"{v:.1f} s",
             max(max(v) for t, v in secs.items() if t != "LIEF"))
    return a, b


def decompiler(decomp: dict) -> tuple[str, str]:
    groups = [("brotli-O2", "brotli -O2"), ("zstd-O2", "zstd -O2"), ("lua-O2", "lua -O2"),
              ("lua-a64-O2", "lua AArch64 -O2")]
    tools = [t for t in ("relic", "angr", "ghidra", "retdec", "r2") if any(t in decomp.get(g, {}) for g, _ in groups)]
    valid = {NAMES[t]: [100 * decomp[g][t]["valid_c"] / decomp[g]["functions"] if t in decomp.get(g, {}) else None
                        for g, _ in groups] for t in tools}
    ms = {NAMES[t]: [1000 * decomp[g][t]["seconds_total"] / max(decomp[g][t]["decompiled"], 1)
                     if t in decomp.get(g, {}) else None for g, _ in groups]
          for t in tools if t not in ("r2", "retdec")}
    a = bars("Decompiler output that is valid C", "share of functions whose pseudocode passes gcc -fsyntax-only; "
             "higher is better", [n for _, n in groups], valid, lambda v: f"{v:.0f}%", 100,
             "radare2's pdc prints pseudo-assembly, not C.")
    b = bars("Decompiler time per function", "average, not counting the analysis before it; lower is better",
             [n for _, n in groups], ms, lambda v: f"{v:,.0f} ms", max(v for x in ms.values() for v in x if v),
             "RetDec and radare2 aren't shown: they decompile in one run with their analysis, not per function.")
    return a, b


def quality(q: dict, decomp: dict) -> str:
    """One group per metric, one bar per tool: totals over every binary scored."""
    tools = [t for t in ("relic", "angr", "ghidra", "retdec", "r2") if any(t in b["summary"] for b in q.values())]
    agg = {t: Counter() for t in tools}
    for name, b in q.items():
        for t in tools:
            s = b["summary"].get(t)
            if s is None:
                continue
            a = agg[t]
            a["eq_pass"] += s["equiv_passed"]
            a["eq_test"] += s["equiv_tested"]
            for k in ("cfg", "dfg"):
                if s[f"{k}_common"] is not None:
                    a[f"{k}_sum"] += s[f"{k}_common"] * s["common"]
                    a[f"{k}_n"] += s["common"]
            for k in ("type_slots", "type_kind", "type_exact"):
                a[k] += s[k]
            row = decomp.get(name, {}).get(t)
            if row:
                a["valid"] += row["valid_c"]
                a["given"] += decomp[name]["functions"]

    def pct(x, y):
        return 100 * x / y if y else None
    metrics = [("Syntax validity", lambda a: pct(a["valid"], a["given"])),
               ("Behavioural equivalence", lambda a: pct(a["eq_pass"], a["eq_test"])),
               ("Control-flow similarity", lambda a: pct(a["cfg_sum"], a["cfg_n"])),
               ("Data-flow similarity", lambda a: pct(a["dfg_sum"], a["dfg_n"])),
               ("Types: kind and size", lambda a: pct(a["type_kind"], a["type_slots"])),
               ("Types: exact", lambda a: pct(a["type_exact"], a["type_slots"]))]
    series = {NAMES[t]: [f(agg[t]) for _, f in metrics] for t in tools}
    return bars("Decompiler output quality", "totals over every binary scored; higher is better",
                [m for m, _ in metrics], series, lambda v: f"{v:.0f}%", 100,
                "Similarities: graph-kernel similarity to the source's CFG / SSA def-use graph, as %.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--detect", nargs="+", required=True)
    ap.add_argument("--decomp", nargs="+", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--quality", help="tools/decomp_quality.py --json output")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    decomp: dict = {}
    for path in args.decomp:
        for name, row in json.load(open(path)).items():
            merged = decomp.setdefault(name, {})
            merged.update({k: v for k, v in row.items() if k != "functions"})
            merged["functions"] = min(merged.get("functions", row["functions"]), row["functions"])
    detect: dict = {}
    for path in args.detect:
        for name, row in json.load(open(path)).items():
            detect.setdefault(name, {}).update(row)
    charts = dict(zip(("detection-f1", "detection-time"), detection(detect)))
    charts.update(zip(("decompiler-valid-c", "decompiler-time"), decompiler(decomp)))
    if args.quality:
        charts["decompiler-quality"] = quality(json.load(open(args.quality)), decomp)
    for name, svg in charts.items():
        with open(os.path.join(args.out, f"{name}.svg"), "w") as fp:
            fp.write(svg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

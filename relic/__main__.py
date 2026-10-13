"""Command line entry point.

    relic [FILE]                  open the GUI
    relic info FILE               headers, sections, libraries
    relic checksec FILE           exploit mitigations
    relic funcs FILE              discovered functions
    relic disasm FILE [WHERE]     disassemble a function / address (default: main or entry)
    relic cfg FILE WHERE          control-flow graph as Graphviz dot
    relic strings FILE            strings in data sections
    relic imports FILE            imported / exported symbols
    relic xrefs FILE WHERE        cross references to an address or symbol
    relic vulns FILE              pwnable heuristics (dangerous calls, format strings, ...)
    relic ir FILE [WHERE]         decompiler IR of a function (debugging aid)
    relic opt FILE [WHERE]        optimised SSA IR, with strings/xrefs resolved
    relic decompile FILE [WHERE]  structured C-like pseudocode of a function
"""
from __future__ import annotations

import argparse
import sys

from . import __version__

COMMANDS = ("info", "checksec", "funcs", "disasm", "cfg", "strings", "imports", "xrefs", "vulns", "ir", "opt",
            "decompile", "gui")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="relic", description="Relic - decompiler & disassembler for RE and pwnable")
    p.add_argument("--version", action="version", version=f"relic {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, help_, where=False, where_required=False):
        s = sub.add_parser(name, help=help_)
        s.add_argument("file")
        if where:
            s.add_argument("where", nargs=None if where_required else "?", help="address, symbol or symbol+off")
        s.add_argument("--arch", help="architecture for raw blobs (x86, x64, arm, arm64, mips, ...)")
        s.add_argument("--base", type=lambda v: int(v, 0), default=0, help="load address for raw blobs")
        return s

    add("info", "file headers, sections and libraries")
    add("checksec", "exploit mitigations")
    s = add("funcs", "list functions")
    s.add_argument("-a", "--all", action="store_true", help="include imported stubs")
    s = add("disasm", "disassemble a function or address", where=True)
    s.add_argument("-n", "--count", type=int, help="linear sweep of N instructions instead of a function")
    s.add_argument("--no-bytes", action="store_true")
    add("cfg", "control-flow graph (Graphviz dot)", where=True, where_required=True)
    s = add("strings", "strings in data sections")
    s.add_argument("-m", "--min", type=int, default=4)
    s.add_argument("-g", "--grep", help="only strings containing this substring (case-insensitive)")
    add("imports", "imported and exported symbols")
    add("xrefs", "cross references to an address/symbol", where=True, where_required=True)
    add("vulns", "pwnable heuristics")
    add("ir", "decompiler IR of a function", where=True)
    s = add("opt", "optimised SSA IR with strings/xrefs resolved", where=True)
    s.add_argument("--no-opt", action="store_true", help="show SSA before the optimisation passes")
    s.add_argument("--xrefs", action="store_true", help="also list the function's constant references")
    add("decompile", "structured C-like pseudocode", where=True)
    g = sub.add_parser("gui", help="open the GUI")
    g.add_argument("file", nargs="?")
    g.add_argument("--arch", help="architecture for raw blobs (x86, x64, arm, arm64, mips, ...)")
    g.add_argument("--base", type=lambda v: int(v, 0), default=0, help="load address for raw blobs")
    return p


def _analyze(args):
    from .analysis import Analysis
    from .loader import load
    return Analysis(load(args.file, args.arch, args.base)).run()


def _where(an, text, default=None) -> int:
    if text is None:
        f = an.function_by_name("main")
        return f.addr if f else (default if default is not None else an.bin.entry)
    a = an.resolve(text)
    if a is None:
        sys.exit(f"relic: cannot resolve '{text}'")
    return a


def cmd_info(args):
    from .loader import load
    b = load(args.file, args.arch, args.base)
    print(f"File:      {b.path}")
    print(f"Format:    {b.describe()}")
    print(f"Entry:     {b.entry:#x}")
    if b.interp:
        print(f"Interp:    {b.interp}")
    for k, v in b.info.items():
        print(f"{k + ':':10} {v}")
    if b.libraries:
        print(f"Libraries: {', '.join(b.libraries)}")
    print("\nSections:")
    print(f"  {'name':20} {'addr':>18} {'size':>10} {'offset':>10}  perm")
    for s in b.sections:
        print(f"  {s.name:20} {s.addr:#18x} {s.size:#10x} {s.offset:#10x}  {s.perms}")


def cmd_checksec(args):
    an = _analyze(args)
    for k, v in an.checksec().items():
        print(f"{k + ':':10} {v}")


def cmd_funcs(args):
    an = _analyze(args)
    print(f"{'address':>18}  {'size':>6} {'blocks':>6} {'calls':>5}  name")
    for f in sorted(an.functions.values(), key=lambda f: f.addr):
        if f.is_import and not args.all:
            continue
        flags = " [import]" if f.is_import else (" [noreturn]" if f.noreturn else "")
        print(f"{f.addr:#18x}  {f.size:6} {len(f.blocks):6} {len(f.calls):5}  {an.name(f.addr)}{flags}")


def cmd_disasm(args):
    from .listing import function_lines, insn_line, render
    an = _analyze(args)
    a = _where(an, args.where)
    if args.count:
        lines = [insn_line(an, i) for i in an.dis.linear(a, args.count)]
    else:
        f = an.function_at(a)
        if f is None:
            lines = [insn_line(an, i) for i in an.dis.linear(a, 32)]
        else:
            lines = function_lines(an, f)
    print(render(lines, not args.no_bytes).lstrip("\n"))


def cmd_cfg(args):
    an = _analyze(args)
    f = an.function_at(_where(an, args.where))
    if f is None:
        sys.exit("relic: no function there")
    from .listing import insn_line
    print(f'digraph "{an.name(f.addr)}" {{')
    print('  node [shape=box fontname="monospace" fontsize=10];')
    for a, blk in sorted(f.blocks.items()):
        body = "\\l".join(f"{i.addr:x}: {insn_line(an, i).mnemonic} {insn_line(an, i).operands}".replace('"', '\\"')
                          for i in blk.insns) + "\\l"
        print(f'  b{a:x} [label="{body}"];')
        for s in blk.succs:
            color = ""
            if blk.last.kind == "cjmp":
                color = ' [color=green]' if s == blk.last.target else ' [color=red]'
            print(f"  b{a:x} -> b{s:x}{color};")
    print("}")


def cmd_strings(args):
    from .analysis.strings import escape, find_strings
    from .loader import load
    b = load(args.file, args.arch, args.base)
    needle = args.grep.lower() if args.grep else None
    for s in find_strings(b, args.min):
        if needle is not None and needle not in s.value.lower():
            continue
        enc = "" if s.encoding == "ascii" else f" ({s.encoding})"
        print(f"{s.addr:#x}  {s.section:12} \"{escape(s.value, 200)}\"{enc}")


def cmd_imports(args):
    from .loader import load
    b = load(args.file, args.arch, args.base)
    print("Imports:")
    for i in sorted(b.imports, key=lambda i: (i.library, i.name)):
        stub = f"{i.addr:#x}" if i.addr else "-"
        lib = f"  ({i.library})" if i.library else ""
        print(f"  {stub:>18}  got={i.got:#x}  {i.name}{lib}")
    if b.exports:
        print("Exports:")
        for e in sorted(b.exports, key=lambda e: e.addr):
            print(f"  {e.addr:#18x}  {e.name}")


def cmd_xrefs(args):
    an = _analyze(args)
    a = _where(an, args.where)
    refs = an.xrefs_to.get(a, [])
    if not refs:
        print(f"no xrefs to {an.label(a)}")
    for x in sorted(refs, key=lambda x: x.frm):
        i = an.dis.decode(x.frm)
        text = f"{i.mnemonic} {i.op_str}" if i else ""
        print(f"{x.frm:#x}  {x.kind:5} {an.location(x.frm):28} {text}")


def cmd_vulns(args):
    an = _analyze(args)
    found = an.vulns()
    if not found:
        print("nothing suspicious found")
    for v in found:
        print(f"[{v.severity:6}] {v.addr:#x} {v.func:20} {v.kind:15} {v.message}")


def cmd_ir(args):
    from .decompiler import lift
    an = _analyze(args)
    f = an.function_at(_where(an, args.where))
    if f is None:
        sys.exit("relic: no function there")
    if f.is_import:
        sys.exit(f"relic: {an.name(f.addr)} is an imported function")
    try:
        print(lift(an, f))
    except NotImplementedError as e:
        sys.exit(f"relic: {e}")


def cmd_opt(args):
    from .decompiler import decompile_ir
    from .decompiler.refs import format_ir, ir_xrefs
    an = _analyze(args)
    f = an.function_at(_where(an, args.where))
    if f is None:
        sys.exit("relic: no function there")
    if f.is_import:
        sys.exit(f"relic: {an.name(f.addr)} is an imported function")
    try:
        fn = decompile_ir(an, f, optimize=not args.no_opt)
    except NotImplementedError as e:
        sys.exit(f"relic: {e}")
    print(format_ir(fn, an))
    if not args.no_opt:
        from .decompiler.arch import arch_for
        from .decompiler.stack import analyze_frame
        try:
            frame = analyze_frame(fn, arch_for(an.bin))
        except NotImplementedError:
            frame = None
        slots = [s for _, s in sorted(frame.slots.items())] if frame else []
        locals_ = [s for s in slots if s.kind != "retaddr"]
        if locals_:
            print(f"\n; frame: {len(locals_)} slots"
                  + (f", {len(frame.buffers())} buffer(s)" if frame.buffers() else ""))
            for s in locals_:
                desc = f"char[{s.size:#x}]" if s.kind == "buffer" else f"{s.width} bytes"
                flags = " taken" if s.taken and s.kind != "buffer" else ""
                print(f";   [rsp{s.offset:+#x}]  {s.name():12} {desc}{flags}")
    if args.xrefs:
        refs = ir_xrefs(fn, an)
        print("\n; references:" if refs else "\n; no constant references")
        for r in refs:
            print(f";   {r.frm:#x}  {r.kind:6} -> {an.label(r.to)}")


def cmd_decompile(args):
    from .decompiler import decompile_ir
    from .decompiler.structure import to_pseudocode
    an = _analyze(args)
    f = an.function_at(_where(an, args.where))
    if f is None:
        sys.exit("relic: no function there")
    if f.is_import:
        sys.exit(f"relic: {an.name(f.addr)} is an imported function")
    try:
        fn = decompile_ir(an, f)
    except NotImplementedError as e:
        sys.exit(f"relic: {e}")
    print(to_pseudocode(fn, an))


def cmd_gui(args):
    try:
        from .gui import run
    except ImportError as e:
        sys.exit(f"relic: GUI unavailable ({e}). Install PySide6.")
    return run(args.file, args.arch, args.base)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and not argv[0].startswith("-")):
        argv.insert(0, "gui")
    args = _parser().parse_args(argv)
    try:
        return globals()[f"cmd_{args.cmd}"](args) or 0
    except FileNotFoundError as e:
        sys.exit(f"relic: {e.filename}: no such file")
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())

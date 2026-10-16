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
    relic search FILE --bytes P   byte pattern (`48 8b ?? 05`), --text, --imm or --insn REGEX
    relic sigs build LIB.a... -o OUT.sig   library signatures (name functions of static binaries)
    relic sigs list               the signature files analyses use

Commands that analyse a FILE take `--sigs OUT.sig` (repeatable) to name library functions
with those signature files instead of the ones in ~/.relic/sigs / $RELIC_SIGS, `--no-sigs`
to use none.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__

COMMANDS = ("info", "checksec", "funcs", "disasm", "cfg", "strings", "imports", "xrefs", "vulns", "ir", "opt",
            "decompile", "search", "patch", "script", "sigs", "types", "project", "lumina", "gui")


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
        s.add_argument("--sigs", action="append", metavar="FILE.sig",
                       help="library signature file to name functions with (repeatable)")
        s.add_argument("--no-sigs", action="store_true", help="name no functions by library signatures")
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
    s = add("decompile", "C-like pseudocode", where=True)
    s.add_argument("-a", "--all", action="store_true", help="every function in the binary")
    s.add_argument("--addrs", action="store_true", help="prefix each line with its instruction address")
    s.add_argument("-o", "--output", metavar="FILE.c",
                   help="write the pseudocode to a C file (with -a: struct declarations once, then every function)")
    s.add_argument("--header", action="append", metavar="FILE.h",
                   help="C declarations to use (structs, enums, typedefs, prototypes; repeatable, not saved)")
    s = add("types", "import C headers into the project (structs, enums, typedefs, prototypes), or list them")
    s.add_argument("headers", nargs="*", metavar="FILE.h", help="headers to import (none: list what is imported)")
    s.add_argument("--no-save", action="store_true", help="check the headers without saving the project")
    s.add_argument("--lib", action="append", metavar="NAME", help="import a bundled type library (libc, win32)")
    s = add("project", "snapshots of the annotations; merge another analyst's project file")
    s.add_argument("action", choices=("snapshots", "snapshot", "restore", "delete", "merge", "commit", "log", "diff",
                                      "checkout"),
                   help="snapshots: list; snapshot/restore/delete NAME; merge OTHER.relic.json; commit -m MSG; log; "
                        "diff [A [B]] (versions, default: latest -> now); checkout N")
    s.add_argument("arg", nargs="?", metavar="NAME|FILE|N")
    s.add_argument("arg2", nargs="?", metavar="N")
    s.add_argument("-m", "--message", help="commit: what this version is")
    s.add_argument("--author", help="commit: who (default: the login name)")
    s.add_argument("--theirs", action="store_true", help="merge: where both differ, take the other file's value")
    s.add_argument("--force", action="store_true", help="merge: even if the project is for another binary")
    s = add("search", "search bytes, text, immediates or instructions")
    how = s.add_mutually_exclusive_group(required=True)
    how.add_argument("--bytes", metavar="PATTERN", help="hex bytes, `??` for any byte: '48 8b ?? 05'")
    how.add_argument("--text", help="a string (ASCII / UTF-8 and UTF-16LE, case-insensitive)")
    how.add_argument("--imm", metavar="VALUE", type=lambda v: int(v, 0),
                     help="instructions using this immediate or displacement")
    how.add_argument("--insn", metavar="REGEX", help="instructions whose text matches: 'call.*system'")
    s.add_argument("--case", action="store_true", help="case-sensitive --text")
    s = add("patch", "patch bytes / NOP / invert a branch / assemble, write a patched copy", where=True)
    how = s.add_mutually_exclusive_group()
    how.add_argument("--bytes", metavar="HEX", help="bytes to write: '90 90', or a quoted string: '\"/bin/sh\\0\"'")
    how.add_argument("--nop", action="store_true", help="replace the instruction with NOPs")
    how.add_argument("--invert", action="store_true", help="negate the conditional branch")
    how.add_argument("--asm", metavar="TEXT", help="assemble (keystone): 'xor eax, eax; ret'")
    how.add_argument("--revert", action="store_true", help="drop the project's patch at this address")
    how.add_argument("--list", action="store_true", help="list the project's patches")
    s.add_argument("-o", "--output", help="patched file to write (default: FILE.patched)")
    s.add_argument("--no-save", action="store_true", help="do not record the patch in the project file")
    s = add("script", "run a Python script against the analysis (an, decompile(), rename(), ...)")
    s.add_argument("script", help="Python file; the scripting API is in its globals (see relic.scripting)")
    s.add_argument("args", nargs=argparse.REMAINDER, help="arguments for the script (sys.argv[1:]); "
                   "relic's own options go before the script")
    s.add_argument("--save", action="store_true", help="save the project file afterwards")
    s = sub.add_parser("lumina", help="share function names / comments / types through a store (push, pull, serve)")
    s.add_argument("action", choices=("push", "pull", "serve"))
    s.add_argument("target", help="the binary (push / pull), or the store file to serve")
    s.add_argument("--store", help="JSON file or http:// server (default: ~/.relic/lumina.json, $RELIC_LUMINA)")
    s.add_argument("--overwrite", action="store_true", help="pull: replace names the project already has")
    s.add_argument("--host", default="127.0.0.1", help="serve: address to listen on (default: localhost only)")
    s.add_argument("--port", type=int, default=8765, help="serve: port")
    s.add_argument("--no-save", action="store_true", help="pull: do not save the project")
    s = sub.add_parser("sigs", help="library signatures: build from static libraries, list")
    s.add_argument("action", choices=("build", "list"))
    s.add_argument("libs", nargs="*", help="static libraries (.a) / object files to build from")
    s.add_argument("-o", "--output", help="signature file to write (build; with --system: the directory)")
    s.add_argument("--system", action="store_true",
                   help="build: a set for every static library of the installed toolchains (glibc, libm, "
                        "libstdc++, libgcc; native and cross) into ~/.relic/sigs")
    g = sub.add_parser("gui", help="open the GUI")
    g.add_argument("file", nargs="?")
    g.add_argument("--arch", help="architecture for raw blobs (x86, x64, arm, arm64, mips, ...)")
    g.add_argument("--base", type=lambda v: int(v, 0), default=0, help="load address for raw blobs")
    return p


def _analyze(args):
    from .analysis import Analysis
    from .loader import load
    try:
        b = load(args.file, args.arch, args.base)
    except (OSError, ValueError) as e:
        sys.exit(f"relic: {args.file}: {e}")
    an = Analysis(b)
    an.sig_paths = [] if getattr(args, "no_sigs", False) else getattr(args, "sigs", None)
    return an.run()


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
    try:
        b = load(args.file, args.arch, args.base)
    except (OSError, ValueError) as e:
        sys.exit(f"relic: {args.file}: {e}")
    print(f"File:      {b.path}")
    print(f"Format:    {b.describe()}")
    print(f"Entry:     {b.entry:#x}")
    if b.interp:
        print(f"Interp:    {b.interp}")
    for k, v in b.info.items():
        print(f"{k + ':':10} {v}")
    if b.libraries:
        print(f"Libraries: {', '.join(b.libraries)}")
    from .analysis.ident import identify
    tc = identify(b)
    print(f"Compiler:  {tc.compiler or 'unknown'}")
    print(f"C library: {tc.libc or 'unknown'}{f' ({tc.linking})' if tc.linking else ''}")
    if tc.languages:
        print(f"Languages: {', '.join(tc.languages)}")
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
        if f.library:
            flags += " [lib]"
        print(f"{f.addr:#18x}  {f.size:6} {len(f.blocks):6} {len(f.calls):5}  {an.name(f.addr)}{flags}")


def cmd_sigs(args):
    from .analysis import libsigs
    if args.action == "build" and args.system:
        out = args.output or os.path.join(os.path.expanduser("~"), ".relic", "sigs")
        done = libsigs.build_system(out, lambda text: print(f"building {text}", flush=True))
        for path, db in done:
            print(f"{path}: {len(db.sigs)} signatures ({db.arch})")
        if not done:
            sys.exit("relic: no static libraries of an installed toolchain found")
        return 0
    if args.action == "build":
        if not args.libs or not args.output:
            sys.exit("relic: sigs build LIB.a... -o OUT.sig  (or: sigs build --system)")
        db = libsigs.build(args.libs)
        db.save(args.output)
        print(f"{args.output}: {len(db.sigs)} signatures ({db.arch}) from {db.source}")
        return 0
    dirs = libsigs.sig_dirs()
    if not dirs:
        print("no signature directories (~/.relic/sigs, $RELIC_SIGS)")
    for d in dirs:
        for f in sorted(os.listdir(d)):
            if f.endswith(".sig"):
                db = libsigs.SigDB.load(os.path.join(d, f))
                what = " ".join(x for x in (db.library, db.version) if x) or db.source
                print(f"{os.path.join(d, f)}: {what} ({db.arch}), {len(db.sigs)} signatures from {db.source}")
    return 0


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


def _import_headers(an, paths):
    from .decompiler.cheader import HeaderError
    for path in paths or ():
        with open(path) as fp:
            text = fp.read()
        try:
            got = an.import_header(text)
        except HeaderError as e:
            sys.exit(f"relic: {path}: {e}")
        yield path, got


def cmd_types(args):
    an = _analyze(args)
    if args.lib:
        for lib in args.lib:
            try:
                got = an.load_type_library(lib)
            except KeyError as e:
                sys.exit(f"relic: {e.args[0]}")
            print(f"{lib}: {len(got['structs'])} structs ({', '.join(got['structs'])})")
        if not args.headers:
            if not args.no_save:
                an.save_project()
                print(f"saved {an.project_path}")
            return
    if args.headers:
        for path, got in _import_headers(an, args.headers):
            parts = [f"{len(got[k])} {k}" for k in ("structs", "enums", "typedefs", "functions", "imports") if got[k]]
            print(f"{path}: {', '.join(parts) or 'nothing new'}")
            for k in ("structs", "enums", "typedefs", "functions", "imports"):
                if got[k]:
                    print(f"  {k}: {', '.join(got[k])}")
        if not args.no_save:
            an.save_project()
            print(f"saved {an.project_path}")
        return
    ut = an.user_types
    structs = sorted(n for n, d in an.struct_names.items() if d.get("imported"))
    if not (structs or ut.get("enums") or ut.get("typedefs")):
        print("no C declarations imported (relic types FILE header.h)")
        return
    for n in structs:
        print(f"struct {n}  ({len(an.struct_names[n].get('layout', {}))} fields)")
    for n, vals in sorted(ut.get("enums", {}).items()):
        print(f"enum {n} {{ {', '.join(f'{k} = {v}' for k, v in vals.items())} }}")
    for n, t in sorted(ut.get("typedefs", {}).items()):
        print(f"typedef {t} {n}")
    for a, types in sorted(an.var_types.items()):
        if "@return" in types:
            params = ", ".join(f"{t} {v}" for v, t in sorted(types.items()) if v != "@return")
            print(f"{types['@return']} {an.name(a)}({params})")


def cmd_decompile(args):
    from .decompiler.emit import decompile
    an = _analyze(args)
    list(_import_headers(an, args.header))
    if args.all and args.output:
        from .decompiler.export import export_c
        with open(args.output, "w") as fp:
            res = export_c(an, fp)
        print(f"{args.output}: {res['functions']} functions, {res['structs']} structs"
              + (f", {len(res['failed'])} not decompiled" if res["failed"] else ""))
        return
    if args.all:
        funcs = [f for f in sorted(an.functions.values(), key=lambda f: f.addr) if not f.is_import]
    else:
        f = an.function_at(_where(an, args.where))
        if f is None:
            sys.exit("relic: no function there")
        if f.is_import:
            sys.exit(f"relic: {an.name(f.addr)} is an imported function")
        funcs = [f]
    for k, f in enumerate(funcs):
        try:
            d = decompile(an, f)
        except NotImplementedError as e:
            sys.exit(f"relic: {e}")
        if k:
            print()
        if args.output:
            with open(args.output, "a" if k else "w") as fp:
                fp.write(d.text + "\n\n")
            continue
        if args.addrs:
            for ln in d.lines:
                tag = f"{ln.addr:8x}" if ln.addr is not None else " " * 8
                print(f"{tag}  {'    ' * ln.depth}{ln.text}".rstrip())
        else:
            print(d.text)


def cmd_project(args):
    from .analysis.project import ProjectMismatch, summary
    an = _analyze(args)
    if args.action in ("commit", "log", "diff", "checkout"):
        return _project_history(an, args)
    if args.action == "snapshots":
        for name, snap in an.snapshots.items():
            print(f"{name:24} {snap['time']}  {summary(snap['notes'])}")
        if not an.snapshots:
            print("no snapshots")
        return
    if not args.arg:
        sys.exit(f"relic: project {args.action} needs a {'file' if args.action == 'merge' else 'name'}")
    if args.action == "snapshot":
        snap = an.take_snapshot(args.arg)
        print(f"snapshot '{args.arg}': {summary(snap['notes'])}")
    elif args.action == "restore":
        if args.arg not in an.snapshots:
            sys.exit(f"relic: no snapshot '{args.arg}'")
        an.restore_snapshot(args.arg)
        print(f"restored '{args.arg}'")
    elif args.action == "delete":
        if not an.delete_snapshot(args.arg):
            sys.exit(f"relic: no snapshot '{args.arg}'")
        print(f"deleted '{args.arg}'")
    else:
        try:
            got = an.merge_project(args.arg, theirs=args.theirs, force=args.force)
        except (ProjectMismatch, ValueError) as e:
            sys.exit(f"relic: {e}")
        added = ", ".join(f"{n} {k}" for k, n in got["added"].items()) or "nothing"
        print(f"added {added}")
        for section, key, ours, theirs in got["conflicts"]:
            key = f"{key:#x}" if isinstance(key, int) else (f"{key[0]:#x} {key[1]}" if isinstance(key, tuple) else key)
            print(f"conflict {section} {key}: ours {ours!r}, theirs {theirs!r} (kept {got['kept']})")
    an.save_project()


def _project_history(an, args):
    from .analysis.project import summary, summary_of_diff
    if args.action == "log":
        for v in reversed(an.history):
            print(f"{v['id']:>4}  {v['time']}  {v['author']:<12} {v['message']}  ({summary(v['notes'])})")
        if not an.history:
            print("no versions")
        return
    if args.action == "commit":
        if not args.message:
            sys.exit("relic: project commit needs -m MESSAGE")
        v = an.commit(args.message, args.author)
        print(f"version {v['id']}: {v['message']} ({summary(v['notes'])})")
    elif args.action == "diff":
        try:
            a = int(args.arg) if args.arg else None
            b = int(args.arg2) if args.arg2 else None
            changes = an.diff_versions(a, b)
        except (KeyError, ValueError) as e:
            sys.exit(f"relic: {e}")
        for sec, key, old, new in changes:
            sign = "+" if old is None else "-" if new is None else "~"
            print(f"{sign} {sec:<10} {key}: " + (repr(new) if old is None else repr(old) if new is None
                                                  else f"{old!r} -> {new!r}"))
        print(summary_of_diff(changes))
        return
    else:
        try:
            an.checkout(int(args.arg))
        except (KeyError, TypeError, ValueError) as e:
            sys.exit(f"relic: no such version ({e})")
        print(f"checked out version {args.arg}")
    an.save_project()


def cmd_lumina(args):
    from .analysis import Analysis
    from .loader import load
    if args.action == "serve":
        from .analysis.lumina import serve
        print(f"serving {args.target} on http://{args.host}:{args.port}", flush=True)
        try:
            serve(args.target, args.host, args.port)
        except KeyboardInterrupt:
            pass
        return
    an = Analysis(load(args.target)).run()
    try:
        if args.action == "push":
            got = an.lumina_push(args.store)
            print(f"pushed {got['pushed']} function(s)" + (f" ({got['skipped']} too short)" if got["skipped"] else ""))
            return
        got = an.lumina_pull(args.store, args.overwrite)
    except (OSError, ValueError) as e:
        sys.exit(f"relic: {e}")
    for a, name in got["applied"]:
        print(f"{a:#x}  {name}")
    print(f"{len(got['applied'])} function(s) from {got['matched']} match(es)")
    if got["applied"] and not args.no_save:
        an.save_project()


def cmd_search(args):
    from .analysis.search import PatternError, find_bytes, find_imm, find_insn, find_text
    an = _analyze(args)
    try:
        if args.bytes is not None:
            hits = find_bytes(an, args.bytes)
        elif args.text is not None:
            hits = find_text(an, args.text, case=args.case)
        elif args.imm is not None:
            hits = find_imm(an, args.imm)
        else:
            hits = find_insn(an, args.insn)
    except PatternError as e:
        sys.exit(f"relic: {e}")
    if not hits:
        print("not found")
    for h in hits:
        print(f"{h.addr:#x}  {an.location(h.addr):28} {h.text}")


def cmd_patch(args):
    from . import patch as P
    an = _analyze(args)
    if args.list:
        for a, (old, new) in sorted(an.patches.items()):
            print(f"{a:#x}  {an.location(a):28} {old.hex(' ')} -> {new.hex(' ')}")
        if not an.patches:
            print("no patches")
        return
    if args.where is None:
        sys.exit("relic: patch needs an address")
    addr = _where(an, args.where)
    try:
        if args.revert:
            if not an.revert(addr):
                sys.exit(f"relic: no patch at {addr:#x}")
        else:
            if args.nop:
                data = P.nop_bytes(an, addr)
            elif args.invert:
                data = P.invert_bytes(an, addr)
            elif args.asm is not None:
                data = P.fit(an, addr, P.assemble(an, addr, args.asm))
            elif args.bytes is not None:
                data = P.parse_hex(args.bytes)
            else:
                sys.exit("relic: one of --bytes / --nop / --invert / --asm / --revert / --list")
            old = an.patch(addr, data)
            print(f"{addr:#x}  {old.hex(' ')} -> {data.hex(' ')}")
            for ln in _disasm_lines(an, addr, len(data)):
                print("   ", ln)
    except P.PatchError as e:
        sys.exit(f"relic: {e}")
    if not args.no_save:
        an.save_project()
    out = P.export(an.bin, args.output or args.file + ".patched")
    print(f"wrote {out} ({len(an.patches)} patch{'es' if len(an.patches) != 1 else ''})")


def _disasm_lines(an, addr: int, size: int) -> list[str]:
    out, a = [], addr
    while a < addr + size:
        i = an.dis.decode(a)
        if i is None:
            break
        out.append(f"{i.addr:#x}  {i.mnemonic} {i.op_str}".rstrip())
        a = i.end
    return out


def cmd_script(args):
    from .scripting import namespace, run_script
    an = _analyze(args)
    run_script(args.script, namespace(an), args.args)
    if args.save:
        an.save_project()


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
    if args.cmd != "gui":
        from .scripting import load_plugins
        _, failed = load_plugins(None)           # plugins' loaders / processors / decompile hooks
        for name, err in failed:
            print(f"relic: plugin {name} failed to load:\n{err}", file=sys.stderr)
    try:
        return globals()[f"cmd_{args.cmd}"](args) or 0
    except FileNotFoundError as e:
        sys.exit(f"relic: {e.filename}: no such file")
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())

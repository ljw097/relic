# Relic

**English** | [한국어](README.ko.md)

A disassembler and decompiler I'm building for reverse engineering and pwn challenges.
The GUI is PySide6 and disassembly comes from capstone; the analysis, decompiler and debugger on top of that are written from scratch.

I'll admit the goal is ambitious: as good as IDA Pro + Hex-Rays, and better where I can manage it.
There's a long way to go, but opening an x86-64 or ARM binary, browsing functions, naming things, reading pseudocode
and measuring an overflow offset in the debugger all work fine today. The current release is [0.1.0 beta](https://github.com/ljw097/relic/releases/tag/v0.1.0).

![The Relic debugger stopped in vuln() right after gets(): the AAAA… input shows up in the registers and the stack telescope](docs/screenshots/debugger.png)

## Installing

Grab the wheel from the release page:

```sh
python3 -m venv .venv
.venv/bin/pip install https://github.com/ljw097/relic/releases/download/v0.1.0/relic_re-0.1.0-py3-none-any.whl
.venv/bin/relic ./chall
```

Or run it from source:

```sh
git clone https://github.com/ljw097/relic && cd relic
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

You need Python 3.10+ on Linux. The debugger needs `gdb` (`sudo apt install gdb`); to debug ARM, MIPS and other
foreign binaries, install `gdb-multiarch` and `qemu-user` as well.
`Ctrl+Alt+A` (patch by assembling) needs keystone, which is a separate extra: `pip install 'relic-re[asm]'`.

## What it does

| | |
|---|---|
| ![Listing](docs/screenshots/listing.png) | ![Graph](docs/screenshots/graph.png) |
| The listing. String references show up as comments, call targets by name | The CFG graph. Taken / not-taken edges are green / red, loops route around the side |
| ![Pseudocode](docs/screenshots/pseudocode.png) | ![Vulns](docs/screenshots/vulns.png) |
| Pseudocode. A jump table comes back as a `switch` | The Vulns tab: format strings, `gets()`, ret2win candidates |

(All screenshots are of [`tests/src/vuln.c`](tests/src/vuln.c).)

Roughly, here's what works:

- **Files it opens**: ELF (executables, shared libraries, `.o` files, core dumps), PE, COFF objects, members of `.a`
  archives, Intel HEX / S-record, and plain raw dumps. For raw firmware it will also guess the load address (`--base auto`).
- **Architectures**: x86, x86-64, ARM/Thumb, AArch64, MIPS32 (both byte orders), MIPS64, RISC-V (RV64GC), and
  PowerPC (32-bit and 64-bit little-endian) go all the way to pseudocode.
- **Analysis**: functions, CFGs, xrefs, strings, jump tables, finding `main` in stripped binaries, and working out
  which compiler and libc built the binary.
- **Library function names**: in statically linked, stripped binaries it finds libc and other library functions by
  FLIRT-style byte signatures and names them. It can build the signature files from the static libraries of the
  toolchains you have installed (`relic sigs build --system`).
- **Decompiler**: recovers structs from memory access patterns, and you can assign types yourself (`Y`). Floating point, libc and Windows API
  prototypes, and C header import are in. There are tests that recompile the output and check it behaves like the original.
- **GUI**: most of what your hands know from IDA is there (names, comments, xrefs, search, bookmarks, byte patching, undo),
  and the shortcuts match IDA's wherever I could make them.
- **Debugger**: gdb (via GDB/MI) underneath, with a pwndbg feel on top. Local, gdbserver, qemu-user and attaching to a running process
  all work, and you get registers, a stack telescope, vmmap and glibc heap chunks.
- **Scripting**: a Python console inside the GUI, `relic script`, and plugins.
- **For pwn**: checksec, dangerous calls, non-constant format strings, width-less `scanf("%s")`, ret2win candidates.
  IDA doesn't do these, so I added them.

### Where it stands against IDA

These numbers are eyeballed. Read them as "the share of what IDA does in that area that Relic does about as well."
The total is a weighted average, with weights from how much each area matters to me when I'm actually reversing. Right now it's **about 78%**.

| Area (weight) | Progress | Notes |
|---|---|---|
| File formats (8) | 70% | No Mach-O |
| Processors (8) | 80% | IDA handles 60+ CPU families, so this is the furthest behind |
| Auto-analysis (14) | 55% | Still misses some functions and indirect jumps in big binaries |
| Library identification (8) | 100% | On the stripped static C test binaries, 83–94% of the functions that had symbols get named, with no wrong names |
| Type system (10) | 85% | No by-value struct arguments or returns |
| Decompiler (20) | 52% | Too many gotos left, no x87 floating point or SIMD |
| Interactive UI (12) | 100% | |
| Scripting & extensions (8) | 100% | |
| Debugger (7) | 100% | Windows (PE) programs run under wine with Windows' own gdbserver.exe |
| Projects & collaboration (5) | 100% | Snapshots, version history, merging, Lumina-style name sharing |

What "100%" means for each area, and what's left, is written down in [TODO.md](TODO.md).
The log of finished work is in [docs/history.md](docs/history.md). (Both are in Korean.)

## CLI

Most things work without the GUI. The ones I use all the time:

```sh
relic info      ./chall              # headers, sections, libraries, compiler
relic checksec  ./chall              # NX, PIE, canary, RELRO
relic funcs     ./chall              # function list
relic disasm    ./chall main
relic decompile ./chall main
relic vulns     ./chall              # likely bugs
relic strings   ./chall -g bin/sh    # filter by substring, case-insensitive
relic xrefs     ./chall menu         # what references this address
```

Less frequent, but handy to know about:

```sh
relic decompile ./chall -a -o chall.c            # the whole binary as one C file
relic decompile ./chall main --header chall.h    # using struct declarations you wrote
relic cfg       ./chall classify | dot -Tsvg > cfg.svg
relic search    ./chall --bytes '48 8b ?? 05'    # --text, --imm 0x186a0, --insn 'call.*system'
relic patch     ./chall main+0x2f --invert       # flip the branch, write ./chall.patched
relic script    ./chall rename_all.py
relic sigs build /usr/lib/x86_64-linux-gnu/libc.a -o ~/.relic/sigs/glibc-x64.sig
relic project   ./chall commit -m "named the parser"
relic disasm    sc.bin --arch x64 --base 0x1000 -n 30   # a raw blob such as shellcode
```

Addresses can be written as `0x401000`, `401000`, `main` or `main+0x10`.
`relic <command> -h` lists the options.

### Examples

Build `tests/src/vuln.c` with `-no-pie -fno-stack-protector` and run:

```
$ relic vulns vuln64.out
[high  ] 0x4014d0 show_note            format-string   printf() called with a non-constant format string
[high  ] 0x40162e vuln                 dangerous-call  gets() never checks bounds: stack/heap overflow
[info  ] 0x401296 win                  win-function    win runs system("/bin/sh") - ret2win target?
```

Build the same source with `-fstack-protector-strong -pie -O1` and decompile:

```
$ relic decompile vuln64_pie.out vuln
void vuln(void)
{
    char buf_58[72];  // ret-0x58
    // stack canary at ret-0x10 (check hidden)

    puts("name?");
    gets(buf_58);
    __printf_chk(1, "hello %s (%d)\n", buf_58, checksum(buf_58));
}
```

The number in a local's name is how far below the return address slot it starts. `buf_58` starts 0x58 bytes below it,
so 0x58 bytes of filler from the start of the buffer reach the return address. This build has a canary, though: it sits at
`ret-0x10`, right above the 72-byte (0x58 − 0x10) buffer, so a straight overwrite fails the canary check before `vuln` returns.
You'd need to leak the canary and write it back, or a build without one. For pwn, this offset is the bit I find most useful.

Structs are recovered from how memory is accessed. Below is the struct the elements of the global array `notes` point to; every function that uses the array shares the same definition:

```
$ relic decompile vuln64.out add_note
struct s_notes {  // recovered, 12 bytes
    char *f_0;
    int f_8;
};
...
        notes[var_1c] = malloc(16);
        notes[var_1c]->f_0 = malloc(var_20);
        notes[var_1c]->f_8 = var_20;
```

Rename it in the GUI with `N` (say, `struct note { char *data; int size; }`) and every other function picks up the new names.

## GUI

```sh
relic ./chall          # same as relic gui ./chall
```

The first time you open something:

1. Analysis runs in the background and jumps to `main` when it's done. It finds `main` even in stripped binaries.
2. Double-click a function in the list on the left to go there; double-clicking a `call` target follows it. `Esc` goes back.
3. `Space` is the graph, `Tab` is pseudocode, `Ctrl+H` is hex. The cursor follows you between views.
4. Name things with `N` and comment with `;` as you read, then `Ctrl+S`. It saves to `<binary>.relic.json` next to the binary.
   Only your edits (names, comments, types, patches) are saved; the analysis itself is redone each time you open the file.
5. For pwn, take a quick look at the Vulns and Checksec tabs at the bottom first.

### Shortcuts

If you've used IDA, these will feel familiar.

| Key | Action |
|---|---|
| `G` | Go to address / symbol |
| `Esc` / `Ctrl+Enter` | Back / forward |
| `Space` | Listing ↔ graph |
| `Tab`, `F5` | Listing ↔ pseudocode |
| `Ctrl+H` | Hex |
| `N` | Rename (in pseudocode: variables, structs and fields too) |
| `;` | Comment |
| `Y` | Set type (`char *`, `struct note *` …) |
| `X` | Xrefs |
| `U` / `C` / `D` / `A` / `P` | Undefine / code / data / string / create function |
| `H` / `R` / `B` | Show a number as hex↔decimal / char / binary |
| `Alt+B` / `Alt+T` / `Alt+I` | Search bytes / text / immediate |
| `Ctrl+Z` / `Ctrl+Shift+Z` | Undo / redo |
| `Alt+M` / `Ctrl+M` | Add bookmark / list bookmarks |
| `Ctrl+Shift+S` | Structs window |
| `Ctrl+Shift+P` | Python console |
| `Shift+F5` | Signatures window |
| `Ctrl+Alt+N` / `Ctrl+Alt+J` / `Ctrl+Alt+A` | NOP out / flip branch / patch by assembling |
| `F9` / `F7` / `F8` / `F4` / `F2` | Debugger run·continue / step into / step over / run to cursor / breakpoint |
| `Ctrl+Shift+L` | Light / dark theme |
| `Ctrl+=` / `Ctrl+-` | Bigger / smaller font |
| `Ctrl+.` | Cancel a running analysis or search |

### Debugger

The Debug menu (`F9`) runs the open binary under gdb. Connecting to a remote gdbserver, running a foreign-architecture binary
under qemu-user, or attaching to a process that's already running are all picked in Debug ▸ Debugger target. The program's input and output go through the Console panel.
Windows executables open under wine on Linux, debugged through Windows' own `gdbserver.exe` (`sudo apt install wine gdb-mingw-w64-target`).

The panels will feel familiar if you've used pwndbg. Registers highlights what changed since the last stop and shows where pointers lead;
Stack is a telescope; there are also Backtrace, Vmmap, Memory, Breakpoints, Threads and Modules panels.
Double-click a value to follow it: code opens in the listing, anything else in Memory. If you've patched the binary, the debugger runs a temporary patched copy.

#### Try it: measuring the overflow offset in `vuln()`

This is how the screenshot at the top was taken. `tests/bins/vuln64.out` appears after you run the tests once
(it is built with `-no-pie -fno-stack-protector`, so there's no canary).

1. Open it with `relic tests/bins/vuln64.out` and put `5` in Debug ▸ Program arguments. With an argument, `main` calls `vuln()`.
2. Go to `vuln` and set a breakpoint with `F2`.
3. Press `F9` twice: it stops at the entry point first, then in `vuln`.
4. Put the cursor on the line right after `call gets` and press `F4`. When it waits for input, type `AAAAAAAABBBBBBBB` on the Console's stdin line.
5. The Stack panel shows `0x4141414141414141`, and a few lines below it the return address `main+0x3c`.
6. Type `$rbp-0x40` into the Memory tab to dump from the start of the buffer. The buffer starts at `rbp-0x40` and the return
   address sits right above the saved `rbp` (8 bytes), so the offset is 0x40 + 8 = 0x48, matching the pseudocode's `char buf_48[64]; // ret-0x48`.

The Console's `gdb>` line takes ordinary gdb commands like `x/8gx $rsp`.
Inside Docker, gdb needs the ptrace capability (`--cap-add=SYS_PTRACE`) to work properly.

## Scripting

The GUI's Python console (`Ctrl+Shift+P`), plugins and `relic script` all share the same functions:
`here()`, `goto()`, `rename()`, `comment()`, `functions()`, `xrefs_to()`, `decompile()`, `search()`, `patch()` and so on.
The full list is in [docs/scripting.md](docs/scripting.md).

A plugin is just a Python file with a `register(api)` function, placed in `~/.relic/plugins/` (or a directory listed in `RELIC_PLUGINS`):

```python
# ~/.relic/plugins/mark_gets.py
def register(api):
    def run(ns):
        for f in ns["functions"]():
            if "gets(" in ns["decompile"](f):
                ns["comment"](f.addr, "calls gets")
    api.add_action("Mark gets() callers", run, "Ctrl+Alt+G")     # shows up in the Plugins menu

    def deco(an, line):                                           # add comments and colors to listing lines
        if line.mnemonic == "call" and "gets" in line.operands:
            return {"comment": "unbounded read", "color": "#5a1e1e"}
    api.add_line_decorator(deco)
```

If a plugin throws, the GUI keeps going and the error is printed in the Python console.

You can also use it as a library:

```python
from relic.analysis import analyze

an = analyze("./chall")
print(an.checksec())
for v in an.vulns():
    print(v.severity, hex(v.addr), v.message)
```

## Code layout

```
relic/
  loader/      ELF / PE / COFF / core dumps / firmware → a common Binary model
  disasm.py    capstone wrapper
  analysis/    functions & CFGs, xrefs, strings, signatures, compiler identification, checksec, vulns, project files
  decompiler/  lifters → SSA & optimization → structuring → C output (design notes in docs/decompiler-plan.md)
  debugger/    the gdb/MI session
  gui/         PySide6 windows and views
  scripting.py the API shared by the console, plugins and relic script
  __main__.py  CLI
```

## Tests

```sh
.venv/bin/pytest -q
.venv/bin/ruff check .
```

The tests build their samples on the spot with gcc and cross compilers. They go as far as recompiling the decompiler's
output and checking it produces the same values as the original. Tests whose compiler is missing are skipped, and the GUI tests run with `QT_QPA_PLATFORM=offscreen`.

If you hit a bug or some odd-looking pseudocode, I'd be grateful for an issue with the binary attached.

## License

MIT

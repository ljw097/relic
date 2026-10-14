"""GDB/MI: run `gdb --interpreter=mi3` and talk to it in records.

A command goes out as `<token><command>`; gdb answers with a result record
carrying the same token (`<token>^done,...` / `^error,msg="..."` / `^running`)
and, at any time, out-of-band records: async (`*stopped,...`, `=library-
loaded,...`) and stream output (`~"console"`, `@"target"`, `&"log"`).

`parse_record` turns one line into a `Record`; `GdbMI` owns the process, a
reader thread, and a blocking `command()` that returns the matching result
(console output produced on the way is collected into it). Async records go
to a callback, and the last `*stopped` is kept so callers can wait for it.
"""
from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
from dataclasses import dataclass, field


class MIError(Exception):
    """gdb answered `^error`, or did not answer in time."""


@dataclass
class Record:
    kind: str                      # result ^ | exec * | status + | notify = | console ~ | target @ | log & | prompt
    cls: str = ""                  # done, running, error, stopped, ... (or the stream text)
    results: dict = field(default_factory=dict)
    token: int | None = None
    text: str = ""                 # stream records


# ------------------------------------------------------------------- parsing
_ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "e": "\x1b", "a": "\a", "b": "\b",
        "f": "\f", "v": "\v"}


def _cstring(s: str, i: int) -> tuple[str, int]:
    """Parse a C string starting at s[i] == '"'; returns (value, index after the closing quote)."""
    assert s[i] == '"'
    i += 1
    out = []
    raw = bytearray()

    def flush():
        if raw:
            out.append(raw.decode("utf-8", "replace"))
            raw.clear()
    while i < len(s):
        c = s[i]
        if c == '"':
            flush()
            return "".join(out), i + 1
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n in "01234567":                      # octal byte (gdb escapes non-ASCII this way)
                j = i + 1
                while j < len(s) and j < i + 4 and s[j] in "01234567":
                    j += 1
                raw.append(int(s[i + 1:j], 8) & 0xFF)
                i = j
                continue
            flush()
            out.append(_ESC.get(n, n))
            i += 2
            continue
        flush()
        out.append(c)
        i += 1
    flush()
    return "".join(out), i


def _value(s: str, i: int):
    c = s[i]
    if c == '"':
        return _cstring(s, i)
    if c == "{":
        return _tuple(s, i + 1, "}")
    if c == "[":
        i += 1
        if s[i] == "]":
            return [], i + 1
        # a list of values or of name=value results
        items = []
        while True:
            if s[i] in '"{[':
                v, i = _value(s, i)
                items.append(v)
            else:
                k, v, i = _result(s, i)
                items.append({k: v})
            if s[i] == ",":
                i += 1
                continue
            if s[i] == "]":
                return items, i + 1
            raise ValueError(f"bad list at {i}: {s[i:i + 20]!r}")
    raise ValueError(f"bad value at {i}: {s[i:i + 20]!r}")


def _result(s: str, i: int):
    eq = s.index("=", i)
    k = s[i:eq]
    v, i = _value(s, eq + 1)
    return k, v, i


def _tuple(s: str, i: int, end: str):
    out: dict = {}
    if s[i] == end:
        return out, i + 1
    while True:
        k, v, i = _result(s, i)
        out[k] = v
        if i >= len(s) or s[i] == end:
            return out, i + 1
        if s[i] != ",":
            raise ValueError(f"bad tuple at {i}: {s[i:i + 20]!r}")
        i += 1


def parse_record(line: str) -> Record:
    line = line.rstrip("\r\n")
    if line.strip() == "(gdb)":
        return Record("prompt")
    i = 0
    while i < len(line) and line[i].isdigit():
        i += 1
    token = int(line[:i]) if i else None
    if i >= len(line):
        return Record("console", text=line)
    marker = line[i]
    kinds = {"^": "result", "*": "exec", "+": "status", "=": "notify", "~": "console", "@": "target",
             "&": "log"}
    if marker not in kinds:
        return Record("target", text=line + "\n")         # inferior output without a tty
    kind = kinds[marker]
    rest = line[i + 1:]
    if kind in ("console", "target", "log"):
        text, _ = _cstring(rest, 0) if rest.startswith('"') else (rest, 0)
        return Record(kind, token=token, text=text)
    comma = rest.find(",")
    cls = rest if comma < 0 else rest[:comma]
    results = {} if comma < 0 else _tuple(rest + "\x00", comma + 1, "\x00")[0]
    return Record(kind, cls, results, token)


# ------------------------------------------------------------------ process
def find_gdb() -> str | None:
    return shutil.which("gdb-multiarch") or shutil.which("gdb")


class GdbMI:
    """One gdb process in MI mode."""

    def __init__(self, gdb: str | None = None, on_async=None, on_stream=None):
        exe = gdb or find_gdb()
        if exe is None:
            raise FileNotFoundError("gdb not found (install gdb or gdb-multiarch)")
        env = dict(os.environ, TERM="dumb", LC_ALL="C.UTF-8")
        self.proc = subprocess.Popen([exe, "--interpreter=mi3", "-q", "-nx"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                                     text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.on_async = on_async
        self.on_stream = on_stream
        self._token = 0
        self._lock = threading.Lock()
        self._waiting: dict[int, queue.Queue] = {}
        self._console: dict[int, list[str]] = {}
        self._current: int | None = None          # token whose console output is being collected
        self.stopped = threading.Event()
        self.last_stop: Record | None = None
        self.exited = False
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    # reader thread
    def _read(self):
        for line in self.proc.stdout:
            try:
                r = parse_record(line)
            except (ValueError, IndexError):
                r = Record("log", text=line)
            if r.kind == "prompt":
                continue
            if r.kind == "result":
                q = self._waiting.get(r.token) if r.token is not None else None
                if q is not None:
                    q.put(r)
                continue
            if r.kind in ("console", "log"):
                tok = self._current
                if tok is not None and tok in self._console:
                    self._console[tok].append(r.text)
            if r.kind == "exec":
                if r.cls == "stopped":
                    self.last_stop = r
                    if r.results.get("reason", "").startswith("exited"):
                        self.exited = True
                    self.stopped.set()
                elif r.cls == "running":
                    self.stopped.clear()
            if r.kind in ("exec", "notify", "status") and self.on_async:
                self.on_async(r)
            elif r.kind in ("console", "target", "log") and self.on_stream:
                self.on_stream(r)
        self.exited = True
        self.stopped.set()
        for q in list(self._waiting.values()):
            q.put(Record("result", "error", {"msg": "gdb exited"}))

    def command(self, cmd: str, timeout: float = 30.0) -> Record:
        """Send one MI command and wait for its result record (raises MIError on ^error)."""
        with self._lock:
            self._token += 1
            tok = self._token
            q: queue.Queue = queue.Queue()
            self._waiting[tok] = q
            self._console[tok] = []
            self._current = tok
            try:
                self.proc.stdin.write(f"{tok}{cmd}\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError):
                raise MIError("gdb is not running") from None
            try:
                r = q.get(timeout=timeout)
            except queue.Empty:
                raise MIError(f"gdb did not answer {cmd!r}") from None
            finally:
                self._waiting.pop(tok, None)
                self._current = None
            r.text = "".join(self._console.pop(tok, []))
        if r.cls == "error":
            raise MIError(r.results.get("msg", "error"))
        return r

    def console(self, cmd: str, timeout: float = 30.0) -> str:
        """Run a CLI command through MI and return its console output."""
        quoted = cmd.replace("\\", "\\\\").replace('"', '\\"')
        return self.command(f'-interpreter-exec console "{quoted}"', timeout).text

    def wait_stopped(self, timeout: float = 30.0) -> Record | None:
        if not self.stopped.wait(timeout):
            return None
        return self.last_stop

    def close(self):
        if self.proc.poll() is None:
            try:
                self.proc.stdin.write("-gdb-exit\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=3)
            except (BrokenPipeError, ValueError, subprocess.TimeoutExpired, OSError):
                self.proc.kill()
                self.proc.wait()


__all__ = ["GdbMI", "MIError", "Record", "find_gdb", "parse_record"]

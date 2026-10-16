"""Shared function metadata (IDA's Lumina): names, comments, variable names and types, pushed
to a store under a fingerprint of the function's code and pulled into any binary that has the
same function -- another build, a stripped copy, a colleague's analysis.

The fingerprint is position independent: each instruction's mnemonic and operands, with
addresses (anything mapped), branch targets (the block they go to) and pc / rip-relative
displacements replaced by placeholders. A store is a JSON file (`~/.relic/lumina.json` by
default) or a server (`relic lumina serve`, an `http://` store), so a team can share one.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import Analysis
    from .functions import Function

MIN_INSNS = 6                 # shorter functions look alike: neither pushed nor pulled
_NUM = re.compile(r"(?<![\w.])(-?)(0x[0-9a-fA-F]+|\d+)(?![\w.])")
_PCREL = re.compile(r"\b(rip|eip|pc)\b")


def default_store() -> str:
    return os.environ.get("RELIC_LUMINA") or os.path.join(os.path.expanduser("~"), ".relic", "lumina.json")


def fingerprint(an: "Analysis", f: "Function") -> str | None:
    """A hash of the function's code that is the same wherever it is linked; None for imported
    stubs and functions too short to tell apart."""
    if f.is_import or not f.blocks:
        return None
    blocks = sorted(f.blocks)
    index = {a: k for k, a in enumerate(blocks)}
    parts, n = [an.bin.arch], 0
    for a in blocks:
        parts.append(f"B{index[a]}")
        for i in f.blocks[a].insns:
            n += 1
            ops = i.op_str
            if i.target is not None:
                tgt = f"L{index[i.target]}" if i.target in index else "F"
                ops = _NUM.sub(lambda m, t=i.target, s=tgt: s if int(m.group(2), 0) == t else m.group(0), ops)
            pcrel = bool(_PCREL.search(ops))

            def norm(m, pcrel=pcrel):
                v = int(m.group(2), 0)
                if v >= 0x1000 and an.bin.is_mapped(v):
                    return "A"
                if pcrel and v >= 0x100:
                    return "D"
                return m.group(0)
            parts.append(f"{i.mnemonic} {_NUM.sub(norm, ops)}")
    if n < MIN_INSNS:
        return None
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:32]


def metadata(an: "Analysis", f: "Function") -> dict | None:
    """What the user said about `f`: its name, comments (by offset from its start), repeatable
    comment, variable names and types, return type. None when nothing."""
    out: dict = {}
    # the user's name, else the binary's own (a symbol: not `sub_...`, not a signature's guess)
    name = an.renames.get(f.addr) or (f.name if not f.name.startswith("sub_") and not f.library else None)
    if name:
        out["name"] = name
    end = f.end
    comments = {f"{a - f.addr:#x}": t for a, t in an.comments.items() if f.addr <= a < end and f.block_at(a)}
    if comments:
        out["comments"] = comments
    if f.addr in an.rcomments:
        out["rcomment"] = an.rcomments[f.addr]
    for key, attr in (("var_names", "var_names"), ("var_types", "var_types")):
        v = getattr(an, attr).get(f.addr)
        if v:
            out[key] = dict(v)
    return out or None


# ------------------------------------------------------------------ stores
class Store:
    """A JSON file of {fingerprint: entry}, or a server's URL."""

    def __init__(self, where: str | None = None):
        self.where = where or default_store()

    @property
    def remote(self) -> bool:
        return self.where.startswith(("http://", "https://"))

    def _load(self) -> dict:
        try:
            with open(self.where) as fp:
                data = json.load(fp)
        except FileNotFoundError:
            return {}
        if not isinstance(data, dict) or not isinstance(data.get("functions", {}), dict):
            raise ValueError(f"{self.where}: not a lumina store")
        return data.get("functions", {})

    def _save(self, funcs: dict):
        os.makedirs(os.path.dirname(os.path.abspath(self.where)), exist_ok=True)
        tmp = self.where + ".tmp"
        with open(tmp, "w") as fp:
            json.dump({"version": 1, "functions": funcs}, fp, indent=1, sort_keys=True)
        os.replace(tmp, self.where)

    def _http(self, path: str, body: dict) -> dict:
        import urllib.request
        req = urllib.request.Request(self.where.rstrip("/") + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def get(self, keys: list[str]) -> dict:
        """The entries stored under these fingerprints."""
        if self.remote:
            return self._http("/get", {"keys": keys}).get("functions", {})
        funcs = self._load()
        return {k: funcs[k] for k in keys if k in funcs}

    def put(self, entries: dict) -> int:
        """Store entries (a newer entry replaces an older one); how many were new or changed."""
        if self.remote:
            return int(self._http("/put", {"functions": entries}).get("stored", 0))
        funcs = self._load()
        n = 0
        for k, e in entries.items():
            old = funcs.get(k)
            if old is None or {x: y for x, y in old.items() if x not in ("time", "binary")} != \
                    {x: y for x, y in e.items() if x not in ("time", "binary")}:
                funcs[k] = e
                n += 1
        if n:
            self._save(funcs)
        return n


def push(an: "Analysis", store: Store, funcs: list | None = None) -> dict:
    """Send what the user said about functions (every annotated one by default) to the store.
    {"pushed": n stored, "skipped": n too short to fingerprint}."""
    entries, skipped = {}, 0
    for f in funcs if funcs is not None else an.functions.values():
        meta = metadata(an, f)
        if meta is None:
            continue
        fp = fingerprint(an, f)
        if fp is None:
            skipped += 1
            continue
        meta["binary"] = os.path.basename(an.bin.path)
        meta["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        entries[fp] = meta
    return {"pushed": store.put(entries) if entries else 0, "skipped": skipped}


def pull(an: "Analysis", store: Store, overwrite: bool = False) -> dict:
    """Apply the store's metadata to the functions that match it (not to ones the user already
    named, unless `overwrite`). {"applied": [(address, name)], "matched": n}."""
    by_fp = {}
    for f in an.functions.values():
        fp = fingerprint(an, f)
        if fp is not None:
            by_fp.setdefault(fp, []).append(f)
    found = store.get(sorted(by_fp))
    applied = []
    for fp, e in found.items():
        for f in by_fp.get(fp, ()):
            if f.addr in an.renames and not overwrite:
                continue
            if e.get("name"):
                an.renames[f.addr] = e["name"]
            for off, text in (e.get("comments") or {}).items():
                a = f.addr + int(off, 16)
                if f.block_at(a) and (overwrite or a not in an.comments):
                    an.comments[a] = text
            if e.get("rcomment"):
                an.rcomments[f.addr] = e["rcomment"]
            for key, attr in (("var_names", "var_names"), ("var_types", "var_types")):
                if e.get(key):
                    cur = getattr(an, attr).setdefault(f.addr, {})
                    for k, v in e[key].items():
                        if overwrite or k not in cur:
                            cur[k] = v
            applied.append((f.addr, e.get("name") or an.name(f.addr) or f.name))
    return {"applied": sorted(applied), "matched": len(found)}


# ------------------------------------------------------------------ server
def serve(path: str, host: str = "127.0.0.1", port: int = 8765, ready=None):
    """A store for a team: POST /get {"keys": [...]}, POST /put {"functions": {...}}, backed by
    the JSON file `path`. Listens on localhost unless told otherwise."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    store = Store(path)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 64 << 20:
                    raise ValueError("request too large")
                body = json.loads(self.rfile.read(n).decode() or "{}")
                with lock:
                    if self.path == "/get":
                        keys = [k for k in body.get("keys", []) if isinstance(k, str)]
                        out = {"functions": store.get(keys)}
                    elif self.path == "/put":
                        funcs = body.get("functions", {})
                        if not isinstance(funcs, dict):
                            raise ValueError("functions must be an object")
                        out = {"stored": store.put({k: v for k, v in funcs.items()
                                                    if isinstance(k, str) and isinstance(v, dict)})}
                    else:
                        self.send_error(404)
                        return
                data = json.dumps(out).encode()
                self.send_response(200)
            except (ValueError, json.JSONDecodeError) as e:
                data = json.dumps({"error": str(e)}).encode()
                self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer((host, port), Handler)
    if ready is not None:
        ready(server)
    try:
        server.serve_forever()
    finally:
        server.server_close()


__all__ = ["Store", "default_store", "fingerprint", "metadata", "pull", "push", "serve"]

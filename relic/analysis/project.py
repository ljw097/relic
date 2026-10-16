"""The user's annotations as JSON (the project file's sections), snapshots of them, and merging
another project file into this one.

A snapshot is a named copy of every annotation (names, comments, variable names and types,
structs, bookmarks, imported C types) kept in the project file; restoring it is one undo step.
Merging takes another analyst's project file of the same binary: what only it has is added, and
where both have a different value, ours is kept (or theirs, `theirs=True`) and the conflict is
reported. Byte patches are neither snapshotted nor merged: they change the code itself.
"""
from __future__ import annotations

import copy
import hashlib
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import Analysis

# project-file section -> Analysis attribute, for the {address: value} sections
FLAT = {"renames": "renames", "comments": "comments", "bookmarks": "bookmarks", "repeatable": "rcomments",
        "data": "data_defs", "function_edits": "func_edits"}
# {function address: {generated name: value}}
NESTED = {"variables": "var_names", "types": "var_types", "operands": "op_formats", "numbers": "num_formats"}


def sha256(an: "Analysis") -> str:
    """Of the file on disk (patches change only the loaded copy): which binary a project is for."""
    if an._sha256 is None:
        h = hashlib.sha256()
        with open(an.bin.path, "rb") as fp:
            for chunk in iter(lambda: fp.read(1 << 20), b""):
                h.update(chunk)
        an._sha256 = h.hexdigest()
    return an._sha256


def notes_to_json(an: "Analysis") -> dict:
    data = {k: {f"{a:#x}": v for a, v in sorted(getattr(an, attr).items())} for k, attr in FLAT.items()}
    for k, attr in NESTED.items():
        data[k] = {f"{a:#x}": dict(sorted(v.items())) for a, v in sorted(getattr(an, attr).items())}
    data["structs"] = dict(sorted(an.struct_names.items()))
    if an.user_types:
        data["c_types"] = an.user_types
    return copy.deepcopy(data)


def notes_from_json(an: "Analysis", data: dict):
    for k, attr in FLAT.items():
        setattr(an, attr, {int(a, 16): v for a, v in data.get(k, {}).items()})
    for k, attr in NESTED.items():
        setattr(an, attr, {int(a, 16): dict(v) for a, v in data.get(k, {}).items()})
    an.struct_names = {k: copy.deepcopy(v) for k, v in data.get("structs", {}).items()}
    an.user_types = copy.deepcopy(dict(data.get("c_types", {})))


# ------------------------------------------------------------------ snapshots
def take(an: "Analysis", name: str) -> dict:
    name = name.strip()
    if not name:
        raise ValueError("a snapshot needs a name")
    snap = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "notes": notes_to_json(an)}
    an.snapshots[name] = snap
    return snap


def summary(notes: dict) -> str:
    """`12 names, 3 comments, 2 structs` for a snapshot's annotations."""
    parts = []
    for key, word in (("renames", "name"), ("comments", "comment"), ("bookmarks", "bookmark"),
                      ("structs", "struct")):
        n = len(notes.get(key, {}))
        if n:
            parts.append(f"{n} {word}{'s' if n != 1 else ''}")
    n = sum(len(v) for v in notes.get("variables", {}).values()) + sum(len(v) for v in notes.get("types", {}).values())
    if n:
        parts.append(f"{n} variable edit{'s' if n != 1 else ''}")
    return ", ".join(parts) or "no annotations"


# ---------------------------------------------------------------------- merge
class ProjectMismatch(ValueError):
    """The other project file belongs to a different binary."""


def merge(an: "Analysis", data: dict, theirs: bool = False, force: bool = False) -> dict:
    """Merge the annotations of another project file (its parsed JSON) into `an`. Returns
    {"added": {section: n}, "conflicts": [(section, key, ours, theirs)], "kept": "ours"|"theirs"}."""
    other = data.get("sha256")
    if other and not force and other != sha256(an):
        raise ProjectMismatch(f"the project is for another file ({data.get('binary') or 'unknown'}, "
                              f"sha256 {other[:12]}...)")
    added: dict[str, int] = {}
    conflicts: list[tuple] = []

    def put(section: str, mine: dict, key, value, label=None):
        if key not in mine:
            mine[key] = copy.deepcopy(value)
            added[section] = added.get(section, 0) + 1
        elif mine[key] != value:
            conflicts.append((section, label if label is not None else key, copy.deepcopy(mine[key]),
                              copy.deepcopy(value)))
            if theirs:
                mine[key] = copy.deepcopy(value)

    for k, attr in FLAT.items():
        mine = getattr(an, attr)
        for a, v in data.get(k, {}).items():
            put(k, mine, int(a, 16), v)
    for k, attr in NESTED.items():
        mine = getattr(an, attr)
        for a, inner in data.get(k, {}).items():
            fn = mine.setdefault(int(a, 16), {})
            for gen, v in inner.items():
                put(k, fn, gen, v, (int(a, 16), gen))
            if not fn:
                del mine[int(a, 16)]
    for name, entry in data.get("structs", {}).items():
        put("structs", an.struct_names, name, entry)
    ct = data.get("c_types", {})
    if ct:
        ut = an.user_types
        heads = ut.setdefault("headers", [])
        for h in ct.get("headers", []):
            if h not in heads:
                heads.append(h)
                added["headers"] = added.get("headers", 0) + 1
        if not heads:
            del ut["headers"]
        if ct.get("bare"):
            ut["bare"] = sorted(set(ut.get("bare", [])) | set(ct["bare"]))
        for section in ("enums", "typedefs", "prototypes", "formats"):
            if ct.get(section):
                mine = ut.setdefault(section, {})
                for name, v in ct[section].items():
                    put(section, mine, name, v)
    return {"added": added, "conflicts": conflicts, "kept": "theirs" if theirs else "ours"}


__all__ = ["ProjectMismatch", "merge", "notes_from_json", "notes_to_json", "sha256", "summary", "take"]

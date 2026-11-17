"""Release versions follow Semantic Versioning 2.0.0 (https://semver.org): checked by the Release
workflow before anything is built.

    python tools/semver_check.py VERSION [--prerelease] [--tags-from FILE]

VERSION must be MAJOR.MINOR.PATCH with an optional pre-release (`1.5.0-rc.1`; build metadata is
not used for releases), marked a pre-release exactly when it has one, and newer than every
release tag (`v1.4.0`) in FILE (`git ls-remote --tags` output, `-` for stdin). Exit status 1 and
the reason on stderr otherwise.
"""
from __future__ import annotations

import argparse
import re
import sys

_SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                     r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?")


def parse(v: str) -> tuple[int, int, int, tuple] | None:
    """(major, minor, patch, pre-release identifiers) of a release version, or None."""
    m = _SEMVER.fullmatch(v)
    if m is None:
        return None
    pre = tuple(int(x) if x.isdigit() else x for x in m.group(4).split(".")) if m.group(4) else ()
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def key(v: tuple) -> tuple:
    """Sort key with SemVer's precedence: a pre-release sorts before its release; identifiers
    compare numerically when numeric, numeric ones before alphanumeric ones."""
    major, minor, patch, pre = v
    ids = tuple((0, x, "") if isinstance(x, int) else (1, 0, x) for x in pre)
    return major, minor, patch, 0 if pre else 1, ids


def tags_versions(text: str) -> list[str]:
    """The versions of `v*` release tags in `git ls-remote --tags` output (peeled `^{}` lines once)."""
    out = []
    for line in text.splitlines():
        ref = line.split()[-1] if line.split() else ""
        m = re.fullmatch(r"refs/tags/v(.+?)(\^\{\})?", ref)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def check(version: str, prerelease: bool, existing: list[str]) -> str | None:
    """Why `version` cannot be released, or None."""
    v = parse(version)
    if v is None:
        return f"{version!r} is not a semantic version (MAJOR.MINOR.PATCH, optionally -PRERELEASE)"
    if bool(v[3]) != prerelease:
        return (f"{version} has a pre-release part: mark the release a pre-release" if v[3] else
                f"{version} is marked a pre-release but has no pre-release part (say {version}-rc.1)")
    older = [parse(t) for t in existing]
    newest = max((t for t in older if t is not None), key=key, default=None)
    if newest is not None and key(v) <= key(newest):
        shown = f"{newest[0]}.{newest[1]}.{newest[2]}" + ("-" + ".".join(map(str, newest[3])) if newest[3] else "")
        return f"{version} is not newer than the latest release, {shown}"
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--prerelease", action="store_true")
    ap.add_argument("--tags-from", help="`git ls-remote --tags` output (`-`: stdin)")
    args = ap.parse_args(argv)
    existing = []
    if args.tags_from:
        text = sys.stdin.read() if args.tags_from == "-" else open(args.tags_from).read()
        existing = tags_versions(text)
    why = check(args.version, args.prerelease, existing)
    if why:
        print(f"version check: {why}", file=sys.stderr)
        return 1
    print(f"version check: {args.version} is fine")
    return 0


if __name__ == "__main__":
    sys.exit(main())

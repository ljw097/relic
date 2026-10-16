"""What built a binary: the compiler (and its version), the C library, how it was linked and
the languages in it -- read from what toolchains leave behind: the ELF `.comment` section,
the GNU version requirements of the dynamic symbols, the PE Rich header MSVC's linker writes,
runtime strings (MinGW, glibc), Go's build info and Rust's panic paths.

`identify(binary)` returns a `Toolchain`; `relic info` prints it, and the library signatures
use the C library it names to choose a signature set (`libsigs.available`).
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..loader.base import Binary


@dataclass
class Toolchain:
    compiler: str | None = None          # "GCC 13.3.0", "clang 18.1.3", "MSVC 2022 (19.38)", ...
    libc: str | None = None              # "glibc", "glibc 2.38", "musl", "msvcrt", "ucrt", ...
    linking: str | None = None           # "static" / "dynamic"
    languages: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)   # where each conclusion came from

    @property
    def libc_family(self) -> str | None:
        return self.libc.split()[0] if self.libc else None

    @property
    def libc_version(self) -> str | None:
        parts = (self.libc or "").split()
        return parts[1] if len(parts) > 1 else None

    def describe(self) -> str:
        parts = [p for p in (self.compiler, self.libc and f"{self.libc} ({self.linking or '?'})") if p]
        if self.languages:
            parts.append("/".join(self.languages))
        return ", ".join(parts) or "unknown"

    def to_json(self) -> dict:
        return {"compiler": self.compiler, "libc": self.libc, "linking": self.linking,
                "languages": list(self.languages), "evidence": list(self.evidence)}


def _section(b: "Binary", name: str) -> bytes:
    s = next((s for s in b.sections if s.name == name), None)
    if s is None or not s.size or s.offset is None:
        return b""
    return b.data[s.offset:s.offset + s.size]


def _ver_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))


# ---------------------------------------------------------------- compilers
_GCC = re.compile(rb"GCC: \(([^)]*)\) ([0-9][\w.\-~+]*)")
_CLANG = re.compile(rb"clang version ([0-9][\w.\-]*)")
_RUSTC = re.compile(rb"rustc version ([0-9][\w.\-]*)")
_GO = re.compile(rb"\bgo(1\.\d+(?:\.\d+)?)\b")


def _compiler_from_comment(text: bytes, tc: Toolchain, where: str) -> None:
    """The newest of each compiler named in `.comment`-style strings (crt objects of the C
    library carry their own, older `GCC:` lines)."""
    found = []
    clang = sorted({m.group(1).decode() for m in _CLANG.finditer(text)}, key=_ver_key)
    if clang:
        found.append(f"clang {clang[-1]}")
    gcc = sorted({m.group(2).decode() for m in _GCC.finditer(text)}, key=_ver_key)
    if gcc and not clang:                 # (clang-built code links GCC's crt objects)
        mingw = any(b"win32" in m.group(0) or b"posix" in m.group(0) or b"MinGW" in m.group(1)
                    for m in _GCC.finditer(text))
        found.append(("MinGW GCC " if mingw else "GCC ") + gcc[-1])
    if found:
        tc.compiler = found[0]
        tc.evidence.append(f"{where}: {found[0]}")


# MSVC: the Rich header's product ids (the tool that built each object) -> Visual Studio
_MSVC_PRODUCTS = [(0x005D, 0x006D, "2005"), (0x0078, 0x0092, "2008"), (0x0093, 0x00AF, "2010"),
                  (0x00B0, 0x00C6, "2012"), (0x00C7, 0x00DC, "2013"), (0x00DD, 0x0110, None)]
# Visual Studio 2015 and later share product ids: their build number tells them apart
_MSVC_BUILDS = [(23026, "2015"), (25017, "2017"), (27508, "2019"), (30133, "2022")]


def rich_header(data: bytes) -> list[tuple[int, int, int]] | None:
    """(product id, build, count) of each Rich header entry of a PE file, or None."""
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    end = data.find(b"Rich", 0x80, min(pe_off, len(data)))
    if end < 0 or end + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, end + 4)[0]
    start = None
    for off in range(end - 4, 0x7C, -4):
        if struct.unpack_from("<I", data, off)[0] ^ key == 0x536E6144:      # "DanS"
            start = off
            break
    if start is None:
        return None
    out = []
    for off in range(start + 16, end, 8):
        comp, count = (x ^ key for x in struct.unpack_from("<II", data, off))
        out.append((comp >> 16, comp & 0xFFFF, count))
    return out


def _msvc(entries: list[tuple[int, int, int]]) -> str | None:
    best = None
    for prod, build, _count in entries:
        for lo, hi, vs in _MSVC_PRODUCTS:
            if lo <= prod <= hi:
                if vs is None:
                    vs = next((v for b, v in reversed(_MSVC_BUILDS) if build >= b), "2015")
                if best is None or (build, vs) > (best[0], best[1]):
                    best = (build, vs)
    return f"MSVC (Visual Studio {best[1]}, build {best[0]})" if best else None


# --------------------------------------------------------------------- main
def identify(b: "Binary") -> Toolchain:
    if getattr(b, "elf_type", None) == "ET_CORE":
        return _core(b)
    tc = Toolchain()
    data = b.data
    if b.format == "ELF":
        _elf(b, tc)
    elif b.format == "PE":
        _pe(b, tc)
    # languages and runtimes anything may carry
    if _section(b, ".go.buildinfo") or b"\xff Go buildinf:" in data or _section(b, ".gopclntab"):
        go = sorted({m.group(1).decode() for m in _GO.finditer(data)}, key=_ver_key)
        tc.languages.append("Go")
        tc.evidence.append("Go build info" + (f": go{go[-1]}" if go else ""))
        if tc.compiler is None:
            tc.compiler = f"Go {go[-1]}" if go else "Go"
    if b"/rustc/" in data or b"rust_panic" in data or b"RUST_BACKTRACE" in data:
        tc.languages.append("Rust")
        tc.evidence.append("Rust runtime strings (rust_panic, /rustc/ paths)")
        comment = _elf_comment(b) if b.format == "ELF" else b""
        rust = sorted({m.group(1).decode() for m in _RUSTC.finditer(comment)}, key=_ver_key)
        if rust:
            tc.compiler = f"rustc {rust[-1]}"
    cxx = [lib for lib in b.libraries if lib.startswith(("libstdc++", "libc++", "msvcp", "libstdc++-"))]
    if cxx or b"St9exception" in data or b"basic_string::_M_" in data or b"__gxx_personality_v0" in data:
        tc.languages.append("C++")
        tc.evidence.append(f"C++ runtime: {cxx[0]}" if cxx else "C++ runtime (libstdc++ type names / messages)")
    if not tc.languages and tc.libc:
        tc.languages.append("C")
    return tc


def _core(b: "Binary") -> Toolchain:
    """A core dump's memory holds every library the process mapped: what built it is what built
    its executable (the first mapped file), when that file is still on disk."""
    import os

    from ..loader import load
    files = getattr(b, "core_files", None) or []
    exe = files[0][3] if files else None
    if exe and os.path.isfile(exe):
        try:
            tc = identify(load(exe))
        except Exception:  # noqa: BLE001 - unreadable executable: nothing known
            tc = Toolchain()
        else:
            tc.evidence.insert(0, f"core dump of {exe}")
            return tc
    return Toolchain(evidence=["core dump (executable not on disk)"])


def _elf_file(b: "Binary"):
    import io

    from elftools.elf.elffile import ELFFile
    try:
        return ELFFile(io.BytesIO(b.data))
    except Exception:  # noqa: BLE001 - not parseable: nothing to read
        return None


def _elf_comment(b: "Binary") -> bytes:
    """`.comment` (not loaded: it is not part of the image)."""
    elf = _elf_file(b)
    sec = elf.get_section_by_name(".comment") if elf is not None else None
    return sec.data() if sec is not None else b""


def _elf(b: "Binary", tc: Toolchain) -> None:
    comment = _elf_comment(b)
    if comment:
        _compiler_from_comment(comment, tc, ".comment")
    dynamic = bool(b.interp or b.libraries)
    tc.linking = "dynamic" if dynamic else "static"
    if dynamic:
        interp = b.interp or ""
        if "musl" in interp or any(lib.startswith("libc.musl") for lib in b.libraries):
            tc.libc = "musl"
            tc.evidence.append(f"interpreter {interp}")
        elif "libc.so.6" in b.libraries or "ld-linux" in interp:
            need = _glibc_needed(b)
            tc.libc = f"glibc {need}" if need else "glibc"
            tc.evidence.append(f"libc.so.6, needs GLIBC_{need}" if need else "libc.so.6")
        elif any(lib.startswith("libc.so") for lib in b.libraries) and "android" in interp + str(b.os):
            tc.libc = "bionic"
        elif "/system/bin/linker" in interp:
            tc.libc = "bionic"
            tc.evidence.append(f"interpreter {interp}")
        elif "uClibc" in interp or any("uClibc" in lib for lib in b.libraries):
            tc.libc = "uClibc"
    else:
        data = b.data
        if b"GLIBC_TUNABLES" in data or b"glibc: malloc" in data or b"Fatal glibc error" in data:
            tc.libc = "glibc"
            tc.evidence.append("glibc strings (GLIBC_TUNABLES, malloc messages)")
        elif b"musl libc" in data or b"/lib/ld-musl-" in data:
            tc.libc = "musl"
            tc.evidence.append("musl strings")
        elif b"uClibc" in data:
            tc.libc = "uClibc"


def _glibc_needed(b: "Binary") -> str | None:
    """The newest GLIBC_x.y version the dynamic symbols require."""
    try:
        from elftools.elf.gnuversions import GNUVerNeedSection
        elf = _elf_file(b)
        vers = []
        for sec in elf.iter_sections():
            if isinstance(sec, GNUVerNeedSection):
                for _need, auxes in sec.iter_versions():
                    vers += [a.name[6:] for a in auxes if a.name.startswith("GLIBC_2")]
    except Exception:  # noqa: BLE001 - a malformed section: no version
        return None
    return max(vers, key=_ver_key) if vers else None


def _pe(b: "Binary", tc: Toolchain) -> None:
    data = b.data
    rich = rich_header(data)
    msvc = _msvc(rich) if rich else None
    if msvc:
        tc.compiler = msvc
        tc.evidence.append("Rich header")
    if tc.compiler is None and (b"GCC: (" in data or b"Mingw-w64 runtime failure" in data):
        _compiler_from_comment(data, tc, "embedded GCC strings")
        if tc.compiler is None:
            tc.compiler = "MinGW GCC"
        if not tc.compiler.startswith("MinGW"):
            tc.compiler = "MinGW " + tc.compiler
        if b"Mingw-w64 runtime failure" in data:
            tc.evidence.append("MinGW-w64 runtime strings")
    if tc.compiler is None:
        clang = sorted({m.group(1).decode() for m in _CLANG.finditer(data)}, key=_ver_key)
        if clang:
            tc.compiler = f"clang {clang[-1]}"
    libs = [lib.lower() for lib in b.libraries]
    if any(lib.startswith("api-ms-win-crt") or lib == "ucrtbase.dll" for lib in libs):
        tc.libc = "ucrt"
    elif "msvcrt.dll" in libs:
        tc.libc = "msvcrt"
    elif any(re.match(r"msvcr\d+", lib) for lib in libs):
        tc.libc = next(lib for lib in libs if re.match(r"msvcr\d+", lib)).removesuffix(".dll")
    if tc.libc:
        tc.evidence.append(f"imports {tc.libc}")
    tc.linking = "dynamic" if tc.libc else "static"


__all__ = ["Toolchain", "identify", "rich_header"]

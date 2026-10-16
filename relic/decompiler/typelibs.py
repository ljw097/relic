"""Type libraries (IDA's .til): declarations of the C library's structs, imported into a
project on demand (`Analysis.load_type_library`) and laid out for the binary's ABI like any
header. With them, `stat(path, &st)` and `localtime()` results read as `st.st_size`,
`tm->tm_year`."""
from __future__ import annotations

_COMMON = """
struct timeval { long tv_sec; long tv_usec; };
struct timespec { long tv_sec; long tv_nsec; };
struct tm {
    int tm_sec; int tm_min; int tm_hour; int tm_mday; int tm_mon; int tm_year; int tm_wday; int tm_yday;
    int tm_isdst; long tm_gmtoff; const char *tm_zone;
};
struct in_addr { unsigned int s_addr; };
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_in {
    unsigned short sin_family; unsigned short sin_port; struct in_addr sin_addr; unsigned char sin_zero[8];
};
struct sockaddr_un { unsigned short sun_family; char sun_path[108]; };
struct iovec { void *iov_base; unsigned long iov_len; };
struct pollfd { int fd; short events; short revents; };
struct hostent { char *h_name; char **h_aliases; int h_addrtype; int h_length; char **h_addr_list; };
struct dirent {
    unsigned long d_ino; long d_off; unsigned short d_reclen; unsigned char d_type; char d_name[256];
};
"""

# struct stat: the kernel's layout for the architecture (glibc's 64-bit `stat`)
_STAT = {
    "x64": """
struct stat {
    unsigned long st_dev; unsigned long st_ino; unsigned long st_nlink; unsigned int st_mode;
    unsigned int st_uid; unsigned int st_gid; int __pad0; unsigned long st_rdev; long st_size;
    long st_blksize; long st_blocks; struct timespec st_atim; struct timespec st_mtim;
    struct timespec st_ctim; long __unused[3];
};
""",
    # asm-generic (AArch64, RISC-V 64, LoongArch)
    "generic64": """
struct stat {
    unsigned long st_dev; unsigned long st_ino; unsigned int st_mode; unsigned int st_nlink;
    unsigned int st_uid; unsigned int st_gid; unsigned long st_rdev; unsigned long __pad1; long st_size;
    int st_blksize; int __pad2; long st_blocks; struct timespec st_atim; struct timespec st_mtim;
    struct timespec st_ctim; unsigned int __unused[2];
};
""",
}

LIBRARIES = ("libc",)


def library_text(name: str, arch: str) -> str:
    """The declarations of type library `name` for a binary of `arch`."""
    if name != "libc":
        raise KeyError(f"no type library {name!r} (known: {', '.join(LIBRARIES)})")
    stat = _STAT["x64"] if arch == "x64" else _STAT["generic64"] if arch in ("arm64", "riscv64") else ""
    return _COMMON + stat


__all__ = ["LIBRARIES", "library_text"]

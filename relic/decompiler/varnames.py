"""Readable names for the decompiler's variables (`v3`, `a1`, `var_c` -> `fd`, `path`, `i`).

Suggestions, from what the code does with a variable, strongest first:

- a loop counter (`for (v = 0; v < n; v++)`, an integer): `i`, then `j`, `k`, ...
- the result of a known call: `fd = open(...)`, `fp = fopen(...)`, `len = strlen(...)`,
  `home = getenv("HOME")`, `config = get_config()` (an internal function's own name);
- its type: `struct stat st`, `FILE *fp`, `struct tm *tm`;
- an argument of a known function: what that parameter is called (`read(fd, buf, count)`).

The user's names always win; a suggestion is never a name already in use (another variable,
a function, a libc function, a C keyword) -- the next free `name2`, `name3` is taken instead.
Generated names stay the keys everything is stored under (renames, types, the project), so a
suggestion changes only what is shown.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from . import ir
from .ir import Assign, CallStmt, Const, StackVar, Var

if TYPE_CHECKING:
    from .emit import CWriter

# a call's result, by callee (sigs.base_name)
RESULTS = {
    **dict.fromkeys(("malloc", "calloc", "realloc", "reallocarray", "aligned_alloc", "valloc", "memalign",
                     "_Znwm", "_Znam", "_Znwj", "_Znaj", "operator new", "operator new[]"), "buf"),
    **dict.fromkeys(("strdup", "strndup", "xstrdup"), "copy"),
    **dict.fromkeys(("fopen", "fopen64", "fdopen", "freopen", "tmpfile", "popen"), "fp"),
    **dict.fromkeys(("open", "open64", "openat", "creat", "dup", "dup2", "dup3", "memfd_create"), "fd"),
    "socket": "sock", "accept": "conn", "accept4": "conn",
    **dict.fromkeys(("strlen", "strnlen", "wcslen"), "len"),
    **dict.fromkeys(("read", "pread", "pread64", "recv", "recvfrom", "recvmsg", "fread", "getline",
                     "readlink"), "nread"),
    **dict.fromkeys(("write", "pwrite", "send", "sendto", "sendmsg", "fwrite"), "nwritten"),
    **dict.fromkeys(("atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull"), "num"),
    **dict.fromkeys(("atof", "strtod", "strtof"), "value"),
    **dict.fromkeys(("fork", "vfork", "getpid", "getppid", "waitpid", "wait"), "pid"),
    **dict.fromkeys(("getuid", "geteuid"), "uid"), **dict.fromkeys(("getgid", "getegid"), "gid"),
    "time": "now", "clock": "ticks", "opendir": "dir", "fdopendir": "dir", "readdir": "ent", "readdir64": "ent",
    **dict.fromkeys(("mmap", "mmap64"), "map"),
    **dict.fromkeys(("strchr", "strrchr", "strstr", "strcasestr", "memchr", "memrchr", "strpbrk", "memmem"),
                    "found"),
    **dict.fromkeys(("fgets", "gets", "fgets_unlocked"), "line"),
    **dict.fromkeys(("strtok", "strtok_r", "strsep"), "tok"),
    **dict.fromkeys(("localtime", "gmtime", "localtime_r", "gmtime_r"), "tm"),
    **dict.fromkeys(("getpwnam", "getpwuid"), "pw"), **dict.fromkeys(("getgrnam", "getgrgid"), "gr"),
    **dict.fromkeys(("gethostbyname", "gethostbyaddr"), "host"),
    **dict.fromkeys(("strcmp", "strncmp", "strcasecmp", "strncasecmp", "memcmp", "bcmp"), "cmp"),
    **dict.fromkeys(("fgetc", "getc", "getchar", "getc_unlocked", "fgetc_unlocked"), "ch"),
    **dict.fromkeys(("rand", "random", "lrand48"), "rnd"),
    **dict.fromkeys(("signal", "sigaction"), "old_handler"),
    "dlopen": "handle", "dlsym": "sym", "pthread_self": "thread", "sysconf": "limit", "getopt": "opt",
    "getopt_long": "opt", "ftell": "pos", "lseek": "pos", "fileno": "fd", "inet_addr": "addr",
    "htons": "port", "ntohs": "port", "strerror": "msg", "ctime": "when", "ttyname": "tty",
}

# parameter names of common functions (more come from relic/decompiler/libc_h.py)
PARAMS = {
    "read": ("fd", "buf", "count"), "write": ("fd", "buf", "count"), "pread": ("fd", "buf", "count", "offset"),
    "pwrite": ("fd", "buf", "count", "offset"), "close": ("fd",), "lseek": ("fd", "offset", "whence"),
    "open": ("path", "flags", "mode"), "openat": ("dirfd", "path", "flags", "mode"), "creat": ("path", "mode"),
    "fopen": ("path", "mode"), "freopen": ("path", "mode", "fp"), "fdopen": ("fd", "mode"),
    "fclose": ("fp",), "fflush": ("fp",), "fgets": ("line", "size", "fp"), "fputs": ("str", "fp"),
    "fread": ("buf", "size", "count", "fp"), "fwrite": ("buf", "size", "count", "fp"),
    "fprintf": ("fp", "fmt"), "fscanf": ("fp", "fmt"), "fseek": ("fp", "offset", "whence"), "ftell": ("fp",),
    "fgetc": ("fp",), "fputc": ("ch", "fp"), "putc": ("ch", "fp"), "getc": ("fp",), "feof": ("fp",),
    "fileno": ("fp",), "setvbuf": ("fp", "buf", "mode", "size"), "puts": ("str",), "putchar": ("ch",),
    "printf": ("fmt",), "sprintf": ("buf", "fmt"), "snprintf": ("buf", "size", "fmt"), "scanf": ("fmt",),
    "sscanf": ("str", "fmt"), "vprintf": ("fmt", "ap"), "vfprintf": ("fp", "fmt", "ap"), "perror": ("msg",),
    "malloc": ("size",), "calloc": ("count", "size"), "realloc": ("ptr", "size"), "free": ("ptr",),
    "memcpy": ("dst", "src", "size"), "memmove": ("dst", "src", "size"), "memset": ("dst", "ch", "size"),
    "memcmp": ("buf1", "buf2", "size"), "memchr": ("buf", "ch", "size"),
    "strcpy": ("dst", "src"), "strncpy": ("dst", "src", "size"), "strcat": ("dst", "src"),
    "strncat": ("dst", "src", "size"), "strlen": ("str",), "strnlen": ("str", "maxlen"),
    "strcmp": ("str1", "str2"), "strncmp": ("str1", "str2", "size"), "strchr": ("str", "ch"),
    "strrchr": ("str", "ch"), "strstr": ("haystack", "needle"), "strdup": ("str",),
    "strndup": ("str", "size"), "strtok": ("str", "delim"), "atoi": ("str",), "atol": ("str",),
    "strtol": ("str", "end", "base"), "strtoul": ("str", "end", "base"), "getenv": ("name",),
    "setenv": ("name", "value", "overwrite"), "system": ("command",), "popen": ("command", "mode"),
    "execve": ("path", "argv", "envp"), "execv": ("path", "argv"), "execvp": ("file", "argv"),
    "execl": ("path", "arg"), "execlp": ("file", "arg"), "exit": ("status",), "_exit": ("status",),
    "socket": ("domain", "type", "protocol"), "bind": ("sock", "addr", "addrlen"),
    "connect": ("sock", "addr", "addrlen"), "listen": ("sock", "backlog"), "accept": ("sock", "addr", "addrlen"),
    "send": ("sock", "buf", "len", "flags"), "recv": ("sock", "buf", "len", "flags"),
    "sendto": ("sock", "buf", "len", "flags", "dst_addr", "addrlen"),
    "recvfrom": ("sock", "buf", "len", "flags", "src_addr", "addrlen"),
    "setsockopt": ("sock", "level", "optname", "optval", "optlen"), "shutdown": ("sock", "how"),
    "mmap": ("addr", "length", "prot", "flags", "fd", "offset"), "munmap": ("addr", "length"),
    "mprotect": ("addr", "length", "prot"), "stat": ("path", "st"), "lstat": ("path", "st"),
    "fstat": ("fd", "st"), "access": ("path", "mode"), "unlink": ("path",), "chdir": ("path",),
    "mkdir": ("path", "mode"), "rmdir": ("path",), "rename": ("oldpath", "newpath"),
    "chmod": ("path", "mode"), "opendir": ("path",), "readdir": ("dir",), "closedir": ("dir",),
    "kill": ("pid", "sig"), "waitpid": ("pid", "status", "options"), "sleep": ("seconds",),
    "usleep": ("usec",), "alarm": ("seconds",), "signal": ("signum", "handler"), "srand": ("seed",),
    "time": ("tloc",), "localtime": ("timep",), "strftime": ("buf", "size", "fmt", "tm"),
    "qsort": ("base", "count", "size", "compar"), "dlopen": ("filename", "flags"), "dlsym": ("handle", "symbol"),
    "pthread_create": ("thread", "attr", "start_routine", "arg"), "pthread_join": ("thread", "retval"),
    "pthread_mutex_lock": ("mutex",), "pthread_mutex_unlock": ("mutex",), "ioctl": ("fd", "request"),
    "dup2": ("oldfd", "newfd"), "pipe": ("pipefd",), "select": ("nfds", "readfds", "writefds", "exceptfds",
                                                                "timeout"),
    "poll": ("fds", "nfds", "timeout"), "inet_ntoa": ("in",), "inet_pton": ("af", "src", "dst"),
    "gethostbyname": ("name",), "getaddrinfo": ("node", "service", "hints", "res"),
}

# names too generic to say anything (a prototype's `s`, `p`), or what they say better
_RENAME_PARAM = {"s": "str", "c": "ch", "p": None, "x": None, "a": None, "b": None, "n": "n", "f": None,
                 "ptr": "ptr", "arg": None, "fmt": None, "format": None, "tloc": None, "in": None,
                 "status": None, "flags": None, "mode": None, "type": None, "how": None, "options": None,
                 "whence": None, "level": None, "optname": None, "base": None, "end": None, "delim": None,
                 "ap": None, "protocol": None, "domain": None, "request": None, "prot": None, "sig": None,
                 "overwrite": None, "seed": "seed", "retval": None, "attr": None, "hints": None}

# a struct type -> a name for a variable of it
_TYPES = {"stat": "st", "stat64": "st", "tm": "tm", "sockaddr_in": "addr", "sockaddr_in6": "addr",
          "sockaddr": "addr", "sockaddr_un": "addr", "sockaddr_storage": "addr", "timeval": "tv",
          "timespec": "ts", "pollfd": "pfd", "termios": "tio", "passwd": "pw", "group": "gr", "dirent": "ent",
          "dirent64": "ent", "hostent": "host", "addrinfo": "ai", "sigaction": "sa", "utsname": "uts",
          "rlimit": "rl", "rusage": "ru", "winsize": "ws", "iovec": "iov", "msghdr": "msg"}
_PTR_TYPES = {"FILE": "fp", "DIR": "dir"}

KEYWORDS = frozenset(("auto break case char const continue default do double else enum extern float for goto "
                      "if inline int long register restrict return short signed sizeof static struct switch "
                      "typedef union unsigned void volatile while bool true false main argc argv envp NULL "
                      "self _cmd this").split())

# internal function names saying what they return: `get_config` -> `config`
_VERB = re.compile(r"^(?:get|create|new|alloc|make|read|load|open|find|lookup|parse|build|init|fetch|copy|count|"
                   r"compute|calc|calculate|"
                   r"dup|clone)_?(?=[A-Za-z])", re.I)
_LOOP_NAMES = ("i", "j", "k", "l", "m")


def suggest(w: "CWriter") -> dict[str, str]:
    """Generated variable name -> suggested name, for the function `w` is writing."""
    from .sigs import base_name, lookup
    an = w.an
    fn = w.p.fn
    gen = lambda raw: w.names.get(raw, raw)
    params = set(w.p.params)
    votes: dict[str, list[tuple[int, str]]] = {}     # generated name -> (strength, suggestion)

    def vote(raw: str, strength: int, name: str | None):
        name = _clean(name)
        if name:
            votes.setdefault(gen(raw), []).append((strength, name))

    def var(e) -> str | None:
        e = _strip(e)
        return e.name if isinstance(e, (Var, StackVar)) else None

    # loop counters
    for depth, raw in _loop_counters(w):
        t = w.types.get(raw)
        if t is None or not t.ptr:
            vote(raw, 50 - depth, _LOOP_NAMES[min(depth, len(_LOOP_NAMES) - 1)])
    # call results and arguments
    for s in fn.stmts():
        call = None
        dst = None
        if isinstance(s, CallStmt):
            call = s.call
            reg = _result_reg(w, s)
            dst = next((v.name for r, v in s.defs if r == reg and isinstance(v, Var)), None)
        elif isinstance(s, Assign) and isinstance(_strip(s.src), ir.Call):
            call, dst = _strip(s.src), var(s.dst)
        if call is not None and dst is not None:
            vote(dst, 40, _result_name(an, w._callee_name(call), call))
        for top in ir.stmt_exprs(s):
            for c in ir.walk(top):
                if not isinstance(c, ir.Call):
                    continue
                name = base_name(w._callee_name(c) or "")
                names = PARAMS.get(name) or _header_params(name)
                if not names:
                    continue
                for k, a in enumerate(c.args):
                    if k >= len(names):
                        break
                    raw = var(a)
                    pname = _param_name(names[k])
                    weak = -5 if pname in _GENERIC else 0     # (`str`, `buf`: anything is one)
                    if raw is not None:
                        vote(raw, 20 + weak, pname)
                    elif isinstance(_strip(a), ir.StackAddr):        # a buffer on the stack: `stat(path, &st)`
                        vote(_strip(a).name, 25 + weak, pname)
    # counters, running totals, the value returned
    assigns: dict[str, list] = {}
    other_reads: dict[str, int] = {}
    returned: set[str] = set()
    for s in fn.stmts():
        if isinstance(s, Assign) and isinstance(s.dst, (Var, StackVar)):
            assigns.setdefault(s.dst.name, []).append(s.src)
        if isinstance(s, ir.Return) and s.value is not None and var(s.value) is not None:
            returned.add(var(s.value))
            continue
        for top in ir.stmt_exprs(s):
            for x in ir.walk(top):
                if isinstance(x, (Var, StackVar)):
                    other_reads[x.name] = other_reads.get(x.name, 0) + 1
    for raw, srcs in assigns.items():
        if raw in params:
            continue
        zero = [e for e in srcs if isinstance(_strip(e), Const) and _strip(e).value == 0]
        steps = [e for e in srcs if _steps(e, raw)]
        if zero and steps and len(zero) + len(steps) == len(srcs):
            if all(isinstance(_strip(e).b, Const) and _strip(e).b.value == 1 for e in steps):
                vote(raw, 35, "count")
            elif all(_strip(e).op == "+" and not isinstance(_strip(e).b, Const) for e in steps):
                vote(raw, 32, "total")
        # (only handed to `return`, never read otherwise: what the function returns)
        if raw in returned and not other_reads.get(raw):
            vote(raw, 10, "result")
    # types
    for raw, t in w.types.items():
        base = t.base[7:] if t.base.startswith("struct ") else t.base
        if t.ptr == 1 and base in _PTR_TYPES:
            vote(raw, 30, _PTR_TYPES[base])
        elif t.ptr <= 1 and t.base.startswith("struct ") and base in _TYPES:
            vote(raw, 30, _TYPES[base])

    # one name per variable, never one already in use
    taken = set(KEYWORDS) | set(w.names.values()) | set(w.user.values()) | set(params)
    taken |= {f.name for f in an.functions.values()} | set(an.renames.values()) | set(an.bin.name_to_addr)
    out: dict[str, str] = {}
    order = sorted(votes, key=lambda g: -max(s for s, _ in votes[g]))
    for g in order:
        if g in w.user:
            continue
        best = max(votes[g], key=lambda v: (v[0], sum(1 for x in votes[g] if x[1] == v[1])))[1]
        name = best
        k = 2
        while name in taken or lookup(name, an) is not None:
            name = f"{best}{k}"
            k += 1
        taken.add(name)
        out[g] = name
    return out


def _clean(name: str | None) -> str | None:
    if not name:
        return None
    name = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    if not name or name[0].isdigit() or len(name) > 24:
        return None
    return name


def _strip(e):
    while isinstance(e, ir.Cast):
        e = e.a
    return e


def _result_reg(w: "CWriter", s: CallStmt) -> str:
    from .fpabi import callee_ret, fp_ret_reg, is_fp_arch
    arch = w.p.arch
    return fp_ret_reg(arch) if is_fp_arch(arch) and callee_ret(w.an, s) else arch.ret


def _result_name(an, callee: str | None, call: ir.Call) -> str | None:
    from .sigs import base_name
    name = base_name(callee or "")
    if name == "getenv" and call.args and isinstance(_strip(call.args[0]), Const):
        text = an.bin.read_cstring(_strip(call.args[0]).value, 32)
        if text and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,20}", text):
            return text.lower()                     # getenv("HOME") -> home
    if name in RESULTS:
        return RESULTS[name]
    for pre in ("j_", "x"):                         # a thunk of / a dying wrapper around one (autoname.py)
        if name.startswith(pre) and name[len(pre):] in RESULTS:
            return RESULTS[name[len(pre):]]
    t = call.target
    if isinstance(t, Const) and t.value in an.functions and not an.functions[t.value].is_import and \
            name and not name.startswith(("sub_", "j_", "x")):
        m = _VERB.match(name)
        if m and len(name) - m.end() >= 3:          # get_config -> config, readHeader -> header
            rest = name[m.end():]
            return re.sub(r"(?<!^)(?=[A-Z])", "_", rest).lower()
    return None


def _param_name(name: str) -> str | None:
    if name in _RENAME_PARAM:
        return _RENAME_PARAM[name]
    return name if len(name) >= 2 else None


_HEADER: dict | None = None


def _header_params(name: str) -> tuple[str, ...] | None:
    """Parameter names a prototype in relic/decompiler/libc_h.py gives."""
    global _HEADER
    if _HEADER is None:
        from .libc_h import LIBC_H
        _HEADER = {}
        for m in re.finditer(r"[\w\s\*]*?\b(\w+)\s*\(([^)]*)\)\s*;", LIBC_H):
            names = []
            for p in m.group(2).split(","):
                p = p.strip()
                pm = re.search(r"(\w+)\s*(\[\])?$", p)
                names.append(pm.group(1) if pm and p not in ("void", "...") and " " in p.replace("*", " * ")
                             else "")
            _HEADER[m.group(1)] = tuple(names)
    return _HEADER.get(name)


def _loop_counters(w: "CWriter") -> list[tuple[int, str]]:
    """(nesting depth, variable) of each `for` loop's counter, in the order the loops are written:
    a loop the writer turns into `for (v = K; ...; v += 1)`."""
    from .emit import _flatten, _for_parts, _tidy
    from .structure import If, Loop, Seq, Switch
    out: list[tuple[int, str]] = []

    def walk(n, depth):
        if n is None:
            return
        if isinstance(n, Seq):
            items = _tidy(_flatten(n))
            k = 0
            while k < len(items):
                it, nxt = items[k], items[k + 1] if k + 1 < len(items) else None
                parts = _for_parts(it, nxt, w.p.gotos) if isinstance(nxt, Loop) else None
                if parts is not None:
                    _prev, init, step, body = parts
                    raw = init.dst.name if isinstance(init, Assign) and isinstance(init.dst, (Var, StackVar)) \
                        else None
                    if raw is not None and _counts(step, raw):
                        out.append((depth, raw))
                    walk(body, depth + 1)
                    k += 2
                    continue
                walk(it, depth)
                k += 1
        elif isinstance(n, If):
            walk(n.then, depth)
            walk(n.els, depth)
        elif isinstance(n, Loop):
            walk(n.body, depth)                 # (only `for` loops count: i, j, k by their nesting)
        elif isinstance(n, Switch):
            for c in n.cases:
                walk(c.body, depth)
    walk(w.p.tree, 0)
    return out


_GENERIC = frozenset(("str", "buf", "ptr", "n", "size", "len", "count", "dst", "src", "name", "value"))


def _steps(e, raw: str) -> bool:
    """`raw + x` / `x + raw` / `raw - K`: raw updated from itself."""
    e = _strip(e)
    if not isinstance(e, ir.BinOp) or e.op not in ("+", "-"):
        return False
    a, b = _strip(e.a), _strip(e.b)
    if isinstance(b, (Var, StackVar)) and b.name == raw and e.op == "+":
        a, b = b, a
    return isinstance(a, (Var, StackVar)) and a.name == raw and not (isinstance(b, (Var, StackVar)) and b.name == raw)


def _counts(step, raw: str) -> bool:
    """`v = v + K` / `v = v - K` with a small constant: a counter, not a pointer walk or a hash."""
    if not isinstance(step, Assign) or not isinstance(step.dst, (Var, StackVar)) or step.dst.name != raw:
        return False
    e = _strip(step.src)
    return isinstance(e, ir.BinOp) and e.op in ("+", "-") and isinstance(_strip(e.a), (Var, StackVar)) and \
        _strip(e.a).name == raw and isinstance(e.b, Const) and 0 < e.b.value <= 8


__all__ = ["suggest"]

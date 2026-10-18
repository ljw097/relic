"""Where the program runs (debugger.Target): under qemu-user's gdb stub (ARM, AArch64, MIPS,
RISC-V programs on this machine), on a gdbserver, attached to a running process, and locally
with an environment, a working directory and an input file."""
import os
import shutil
import subprocess
import time

import pytest

from relic.analysis import analyze
from relic.debugger import DebugError, Session, Target, describe_stop, find_gdb, qemu_for
from relic.debugger.session import _arch_key, _free_port
from relic.loader import load

HERE = os.path.dirname(__file__)
SRC = os.path.join(HERE, "src", "dbg_target.c")
# arch -> (cross compiler, qemu, gdb's register names expected first)
CROSS = {"arm64": ("aarch64-linux-gnu-gcc", "qemu-aarch64", ["x0", "x1"]),
         "arm": ("arm-linux-gnueabihf-gcc", "qemu-arm", ["r0", "r1"]),
         "mips": ("mipsel-linux-gnu-gcc", "qemu-mipsel", ["zero", "at"]),
         "mipsbe": ("mips-linux-gnu-gcc", "qemu-mips", ["zero", "at"]),
         "mips64": ("mips64el-linux-gnuabi64-gcc", "qemu-mips64el", ["zero", "at"]),
         "riscv64": ("riscv64-linux-gnu-gcc", "qemu-riscv64", ["ra", "sp"])}


def _multiarch() -> bool:
    """Whether the gdb found knows other architectures (gdb-multiarch)."""
    gdb = find_gdb()
    if gdb is None:
        return False
    r = subprocess.run([gdb, "-q", "-nx", "-batch", "-ex", "set architecture aarch64"], capture_output=True, text=True)
    return "target architecture is set to" in (r.stdout + r.stderr)


def _build(tmp_path, cc, name, *flags):
    if shutil.which(cc) is None:
        pytest.skip(f"needs {cc}")
    out = str(tmp_path / name)
    subprocess.run([cc, "-O0", *flags, "-o", out, SRC], check=True)
    return out


def _session_run(s, an, stdin_line=b"line1\n"):
    """Start at main, stop at work(), run to the end: what each step said."""
    st = s.start("main", 90)
    first = s.symbolize(s.pc)
    s.add_breakpoint(s.to_live(an.function_by_name("work").addr))
    if stdin_line is not None:
        s.send_input(stdin_line)
    hit = describe_stop(s.cont(90)), s.symbolize(s.pc), [n for n, _, _ in s.gprs()][:2], \
        [f.func for f in s.backtrace()][:2]
    end = describe_stop(s.cont(90))
    time.sleep(0.3)
    return describe_stop(st), first, hit, end, s.read_output()


@pytest.mark.parametrize("arch", sorted(CROSS))
def test_qemu_target(arch, tmp_path):
    """A program of another architecture runs under qemu-user; gdb drives it through the stub:
    main, a breakpoint, its registers and frames, its input / output and environment."""
    cc, qemu, regs = CROSS[arch]
    if shutil.which(qemu) is None or not _multiarch():
        pytest.skip(f"needs {qemu} and a gdb for {arch} (gdb-multiarch)")
    path = _build(tmp_path, cc, f"t_{arch}")
    an = analyze(path)
    assert an.bin.arch == arch.removesuffix("be") and Target.for_binary(an.bin).kind == "qemu" and qemu_for(an.bin)
    s = Session(path, ["a", "b"], an, target=Target("qemu", env={"RELIC_T": "env-ok"}))
    try:
        start, first, hit, end, out = _session_run(s, an)
    finally:
        s.close()
    assert first.startswith("main"), first
    assert hit[1].startswith("work") and hit[2] == regs and hit[3] == ["work", "main"], hit
    assert end == "exited normally" and out == b"hello env-ok\ngot line1\nr=12\n", (end, out)
    assert s.qemu.poll() is not None                              # (qemu went with the session)


def test_remote_gdbserver(tmp_path):
    if shutil.which("gdbserver") is None or find_gdb() is None:
        pytest.skip("needs gdbserver and gdb")
    path = _build(tmp_path, "gcc", "t_x64")
    an = analyze(path)
    port = _free_port()
    srv = subprocess.Popen(["gdbserver", f"127.0.0.1:{port}", path, "x"], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    s = Session(path, [], an, target=Target("remote", address=f"127.0.0.1:{port}"))
    try:
        st = s.start("main", 60)
        assert s.symbolize(s.pc).startswith("main"), describe_stop(st)
        assert s.slide and s.mappings()                          # (a PIE: where gdbserver loaded it)
        s.add_breakpoint(s.to_live(an.function_by_name("work").addr))
        srv.stdin.write(b"abc\n")
        srv.stdin.flush()
        s.cont(60)
        assert s.symbolize(s.pc).startswith("work")
        assert describe_stop(s.cont(60)) == "exited normally"
    finally:
        s.close()
        srv.kill()
    with pytest.raises(DebugError):                               # (nothing listens there)
        bad = Session(path, [], an, target=Target("remote", address=f"127.0.0.1:{_free_port()}"))
        try:
            bad.start("entry", 3)
        finally:
            bad.close()


def test_attach_and_detach(tmp_path):
    if find_gdb() is None:
        pytest.skip("needs gdb")
    path = _build(tmp_path, "gcc", "t_x64")
    an = analyze(path)
    p = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    time.sleep(0.5)                                              # (it waits for input in fgets)
    s = Session(path, [], an, target=Target("attach", pid=p.pid))
    try:
        try:
            s.start("entry", 30)
        except DebugError as e:
            pytest.skip(f"cannot attach here (ptrace scope?): {e}")
        assert s.slide                                           # (from the process's mappings)
        s.add_breakpoint(s.to_live(an.function_by_name("work").addr))
        p.stdin.write(b"zzz\n")
        p.stdin.flush()
        s.cont(30)
        assert s.symbolize(s.pc).startswith("work")
        s.detach()                                               # (it runs on without gdb)
        assert p.communicate(timeout=20)[0] == b"hello -\ngot zzz\nr=8\n"
    finally:
        s.close()
        p.kill()


def test_local_environment_directory_and_input_file(tmp_path):
    if find_gdb() is None:
        pytest.skip("needs gdb")
    path = _build(tmp_path, "gcc", "t_x64")
    an = analyze(path)
    (tmp_path / "in.txt").write_text("from a file\n")
    work = tmp_path / "wd"
    work.mkdir()
    s = Session(path, ["a b"], an, target=Target(env={"RELIC_T": "set here"}, cwd=str(work),
                                                 stdin=str(tmp_path / "in.txt")))
    try:
        s.start("main", 60)
        cwd = s.execute("info proc cwd")
        s.add_breakpoint(s.to_live(an.function_by_name("work").addr))
        s.cont(60)
        assert s.symbolize(s.pc).startswith("work")
        assert describe_stop(s.cont(60)) == "exited normally"
        time.sleep(0.3)
        out = s.read_output()
    finally:
        s.close()
    assert str(work) in cwd, cwd
    assert out == b"hello set here\ngot from a file\nr=10\n", out          # ("a b": one argument)


def test_architecture_tables():
    assert _arch_key("riscv:rv64") == "riscv" and _arch_key("armv7") == "arm" and _arch_key("mips:isa32r2") == "mips"
    assert _arch_key("i386:x86-64") == "i386:x86-64" and _arch_key("aarch64") == "aarch64"
    b = load("/bin/true")
    assert Target.for_binary(b).kind == "local"


@pytest.fixture(scope="module")
def threads_bin(tmp_path_factory):
    if find_gdb() is None or shutil.which("gcc") is None:
        pytest.skip("needs gdb and gcc")
    out = str(tmp_path_factory.mktemp("threads") / "th")
    subprocess.run(["gcc", "-O0", "-pthread", "-o", out, os.path.join(HERE, "src", "dbg_threads.c")], check=True)
    return out


def test_threads_modules_signals_and_trace(threads_bin):
    """Threads (look at another one's frames), the shared libraries, a signal's handling, and an
    instruction trace through a loop."""
    an = analyze(threads_bin)
    s = Session(threads_bin, [], an)
    try:
        s.start("main", 30)
        libs = [os.path.basename(m.path) for m in s.modules()]
        assert any(n.startswith("libc.so") for n in libs) and all(m.start < m.end for m in s.modules())
        assert s.signal("USR1") == {"stop": True, "print": True, "pass": True}
        s.add_breakpoint(s.to_live(an.function_by_name("spin").addr))
        s.cont(30)
        th = s.threads()
        assert len(th) == 3 and sum(t.current for t in th) == 1
        cur = next(t for t in th if t.current)
        assert s.symbolize(cur.addr).startswith("spin")
        other = next(t for t in th if not t.current)
        s.select_thread(other.id)
        assert "usleep" in [f.func for f in s.backtrace()] and not s.symbolize(s.pc).startswith("spin")
        s.select_thread(cur.id)
        pcs = s.trace(60)
        assert len(pcs) == 61 and all(s.symbolize(a).startswith("spin") for a in pcs)
        assert len(set(pcs)) < len(pcs)                           # (the loop: instructions again)
        assert describe_stop(s.cont(30)) == "signal SIGUSR1 (User defined signal 1)"
        assert s.set_signal("SIGUSR1", stop=False, pass_=True) == {"stop": False, "print": False, "pass": True}
        assert describe_stop(s.cont(30)) == "exited normally"
        time.sleep(0.2)
        assert s.read_output() == b"spin 135\ncaught 10\ndone\n"
    finally:
        s.close()
    s = Session(threads_bin, [], an)
    try:
        s.stop_on_library_load(True)
        s.start("entry", 30)
        assert describe_stop(s.cont(30)).startswith("library event")
    finally:
        s.close()

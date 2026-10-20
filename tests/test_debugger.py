"""Local debugging through gdb/MI (relic.debugger): parsing, sessions, PIE slide, telescope, I/O."""
import os
import shutil
import subprocess
import time

import pytest

from relic.analysis import analyze
from relic.debugger.mi import parse_record


def _can_debug() -> bool:
    gdb = shutil.which("gdb")
    if gdb is None:
        return False
    r = subprocess.run([gdb, "-q", "-nx", "-batch", "-ex", "starti", "-ex", "kill", "/bin/true"],
                       capture_output=True, text=True, timeout=30)
    return "process" in (r.stdout + r.stderr) and "ptrace" not in (r.stdout + r.stderr).lower()


needs_gdb = pytest.mark.skipif(not _can_debug(), reason="gdb with ptrace permission is needed")


def test_mi_parser():
    r = parse_record('12^done,bkpt={number="1",addr="0x0000000000401667",thread-groups=["i1"]}')
    assert r.token == 12 and r.kind == "result" and r.cls == "done"
    assert r.results["bkpt"]["addr"] == "0x0000000000401667" and r.results["bkpt"]["thread-groups"] == ["i1"]
    r = parse_record('*stopped,reason="breakpoint-hit",frame={addr="0x1",func="main",args=[]},thread-id="1"')
    assert r.kind == "exec" and r.cls == "stopped" and r.results["frame"]["func"] == "main"
    r = parse_record('~"Breakpoint 1, \\"x\\"\\n"')
    assert r.kind == "console" and r.text == 'Breakpoint 1, "x"\n'
    r = parse_record('^done,register-values=[{number="0",value="0x1c"},{number="1",value="0x0"}]')
    assert [v["value"] for v in r.results["register-values"]] == ["0x1c", "0x0"]
    r = parse_record('^done,stack=[frame={level="0",addr="0x10"},frame={level="1",addr="0x20"}]')
    assert [f["frame"]["level"] for f in r.results["stack"]] == ["0", "1"]
    assert parse_record("(gdb) ").kind == "prompt"
    assert parse_record('~"caf\\303\\251\\n"').text == "café\n"


@needs_gdb
@pytest.mark.parametrize("fixture", ["vuln64", "vuln64_pie", "vuln32_pie"])
def test_session_breakpoint_registers_telescope_io(request, fixture):
    from relic.debugger import Session
    path = request.getfixturevalue(fixture)
    an = analyze(path)
    s = Session(path, args=["5"], analysis=an)
    try:
        s.start("entry")
        if fixture.endswith("pie"):
            assert s.slide and s.slide % 0x1000 == 0             # loaded somewhere else than 0
        vuln = an.function_by_name("vuln").addr
        s.add_breakpoint(s.to_live(vuln))
        st = s.cont()
        assert st.get("reason") == "breakpoint-hit"
        assert s.to_static(s.pc) == vuln and s.symbolize(s.pc) == "vuln"
        names = [n for n, _, _ in s.gprs()]
        assert ("rip" in names or "eip" in names) and len(names) >= 9
        rows = s.telescope(count=4)
        assert rows and rows[0].addr == s.sp
        assert rows[0].note.startswith("main+")                    # the return address into main
        assert [s.symbolize(f.addr) for f in s.backtrace()][:2][0] == "vuln"
        assert any(m.kind == "stack" for m in s.mappings())
        s.step_over()
        assert s.to_static(s.pc) != vuln and any(changed for _, _, changed in s.gprs())
        s.send_input("relic\n")
        st = s.cont(timeout=20)
        assert st.get("reason", "").startswith("exited")
        time.sleep(0.2)
        out = s.read_output()
        assert b"name?\n" in out and b"hello relic" in out              # no echo, no \r\n
    finally:
        s.close()


@needs_gdb
def test_breakpoint_toggle_and_raw_command(vuln64):
    from relic.debugger import Session
    an = analyze(vuln64)
    s = Session(vuln64, analysis=an)
    try:
        s.start("main")
        assert s.symbolize(s.pc).startswith("main")
        a = an.function_by_name("menu").addr
        assert s.toggle_breakpoint(a) is True and a in s.breakpoints
        assert s.toggle_breakpoint(a) is False and not s.breakpoints
        assert "rip" in s.execute("info registers rip")
        assert s.address_of("$rsp") == s.sp
        assert s.address_of("$rsp+8") == s.sp + 8
        assert s.address_of(f"{s.sp:#x}") == s.sp
        assert s.address_of("menu") == s.to_live(a)
        assert s.address_of("no_such_thing_here") is None
        s.kill()
    finally:
        s.close()
    assert not os.path.exists(f"/proc/{s.mi.proc.pid}/status") or s.mi.proc.poll() is not None



@needs_gdb
def test_breakpoint_condition_enable_hits(vuln64):
    from relic.debugger import Session
    an = analyze(vuln64)
    s = Session(vuln64, args=["5"], analysis=an)
    try:
        s.start("entry")
        vuln = s.to_live(an.function_by_name("vuln").addr)
        classify = s.to_live(an.function_by_name("classify").addr)
        s.add_breakpoint(vuln, enabled=False)
        s.add_breakpoint(classify, condition="$rdi == 4")
        s.set_breakpoint_condition(classify, "$rdi == 5")         # classify(atoi("5"))
        s.send_input("x\n")
        st = s.cont(timeout=20)
        assert st.get("reason") == "breakpoint-hit" and s.pc == classify
        assert s.breakpoint_hits() == {vuln: 0, classify: 1}
        s.set_breakpoint_enabled(vuln, True)
        assert s.cont(timeout=20).get("reason", "").startswith("exited")
    finally:
        s.close()

def test_hexdump():
    from relic.gui.debugger import hexdump
    out = hexdump(0x1000, b"hello, world!\x00\x01\xff" + b"A" * 4)
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("0x000000001000  68 65 6c 6c 6f 2c 20 77  6f 72")
    assert lines[0].endswith("|hello, world!...|")
    assert lines[1].startswith("0x000000001010  41 41 41 41") and lines[1].endswith("|AAAA|")


@needs_gdb
@pytest.mark.parametrize("fixture", ["vuln64", "vuln64_pie"])
def test_watchpoints_and_named_breakpoints(request, fixture):
    from relic.debugger import Session, describe_stop, watch_key
    path = request.getfixturevalue(fixture)
    an = analyze(path)
    s = Session(path, analysis=an)
    try:
        s.start("entry")
        notes = an.resolve("notes")
        assert s.watch_expression("notes") == f"*(long long *){s.to_live(notes):#x}"
        assert s.watch_expression("notes+8", 4) == f"*(int *){s.to_live(notes) + 8:#x}"
        assert s.watch_expression("*(int *)($rbp-4)") == "*(int *)($rbp-4)"
        # a library function by name stops in libc itself, not at the PLT stub
        s.add_named_breakpoint("puts")
        st = s.cont(timeout=20)
        assert st.get("reason") == "breakpoint-hit" and describe_stop(st) == f"breakpoint {s.named['puts']}"
        assert s.to_static(s.pc) is None and "puts" in s.symbolize(s.pc)
        s.remove_named_breakpoint("puts")
        # add_note: the while loop reads notes[0], then notes[0] = malloc(...) writes it
        s.add_watchpoint("notes", "read")
        s.add_watchpoint("notes", "write")
        s.send_input("1\n8\nAAAA\n4\n")
        st = s.cont(timeout=20)
        assert st.get("reason") == "read-watchpoint-trigger"
        assert s.symbolize(s.pc).startswith("add_note+")
        s.remove_watchpoint(watch_key("notes", "read"))
        st = s.cont(timeout=20)
        assert st.get("reason") == "watchpoint-trigger" and s.symbolize(s.pc).startswith("add_note+")
        text = describe_stop(st)
        assert text.startswith("watchpoint ") and ": 0 -> " in text
        new = int(st["value"]["new"])
        assert s.read_word(s.to_live(notes)) == new and s.mapping_at(new).kind == "heap"
        assert s.hits_by_number()[s.watchpoints[watch_key("notes")]] == 1
        s.set_enabled(watch_key("notes"), False)
        assert s.cont(timeout=20).get("reason", "").startswith("exited")
    finally:
        s.close()


def test_parse_bytes():
    from relic.debugger import DebugError, parse_bytes
    assert parse_bytes("41 42 ff") == parse_bytes("4142ff") == b"AB\xff"
    assert parse_bytes('"AA\\n"') == b"AA\n" and parse_bytes("b'\\x00a'") == b"\x00a"
    assert parse_bytes("0x401136") == bytes.fromhex("3611400000000000")
    assert parse_bytes("-1", 4) == b"\xff" * 4
    with pytest.raises(DebugError):
        parse_bytes("zz")


@needs_gdb
def test_set_register_and_write_memory(vuln64):
    from relic.debugger import Session
    an = analyze(vuln64)
    s = Session(vuln64, args=["5"], analysis=an)
    try:
        s.start("entry")
        s.add_breakpoint(s.to_live(an.function_by_name("classify").addr))
        s.send_input("x\n")
        s.cont(timeout=20)
        assert s.regs["rdi"] == 5
        s.write_memory(s.sp - 0x40, b"relic\0")
        assert s.read_memory(s.sp - 0x40, 6) == b"relic\0" and s._string_at(s.sp - 0x40) == "relic"
        s.set_register("rdi", "$rdi - 5")          # classify(0) returns 10, classify(5) 63
        assert s.regs["rdi"] == 0
        s.set_register("$rax", -1)
        assert s.regs["rax"] == (1 << 64) - 1
        st = s.cont(timeout=20)
        assert st.get("reason") == "exited" and int(st["exit-code"], 8) == 10
    finally:
        s.close()


def test_child_env_undoes_the_bundles_library_path(monkeypatch):
    """The stand-alone executables point LD_LIBRARY_PATH at their bundled libraries; gdb and
    the other programs Relic starts get the original value back (or none)."""
    import sys

    from relic.sysenv import child_env
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIxyz")
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    assert child_env()["LD_LIBRARY_PATH"] == "/tmp/_MEIxyz"        # (run from source: as it is)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert "LD_LIBRARY_PATH" not in child_env({"TERM": "dumb"})
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/opt/lib")
    env = child_env()
    assert env["LD_LIBRARY_PATH"] == "/opt/lib" and "LD_LIBRARY_PATH_ORIG" not in env


@pytest.mark.skipif(shutil.which("gdb") is None or not os.path.exists("/proc"), reason="needs gdb on Linux")
def test_gdb_starts_from_a_bundle_with_its_own_libstdcxx(monkeypatch, tmp_path):
    """The 1.0.0 Linux executable: its older libstdc++ on LD_LIBRARY_PATH made the system gdb
    die at once ("gdb exited"). A broken library there stands in for it."""
    import sys

    from relic.debugger.mi import GdbMI, MIError
    (tmp_path / "libstdc++.so.6").write_bytes(b"not a library")
    monkeypatch.setenv("LD_LIBRARY_PATH", str(tmp_path))
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    g = GdbMI()                                      # from source: the path is kept, gdb cannot start
    try:
        with pytest.raises(MIError, match="gdb exited: .*libstdc"):  # (and says why)
            g.command("-gdb-version", timeout=20)
    finally:
        g.close()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    g = GdbMI()
    try:
        assert "GNU gdb" in g.command("-gdb-version", timeout=20).text
    finally:
        g.close()


@pytest.mark.skipif(shutil.which("gdb") is None or shutil.which("gcc") is None, reason="needs gdb and gcc")
@pytest.mark.parametrize("pie", [True, False])
def test_start_at_main_of_a_stripped_program(tmp_path, pie):
    """gdb knows no `main` in a stripped program (`-exec-run --start` ran it to the end): the
    analysis' main is where it stops."""
    from relic.debugger import Session
    out = str(tmp_path / "hello")
    subprocess.run(["gcc", "-O2", "-s", "-pie" if pie else "-no-pie", "-o", out,
                    os.path.join(os.path.dirname(__file__), "src", "hello.c")], check=True)
    an = analyze(out)
    s = Session(out, analysis=an)
    try:
        st = s.start("main")
        assert st.get("reason") == "breakpoint-hit", st
        assert s.to_static(s.pc) == an.function_by_name("main").addr
    finally:
        s.close()


def test_program_arguments_reach_the_program_as_typed():
    """gdb starts the program through a shell: `$`, backticks and quotes must not be expanded
    (`%7$p` is a format-string payload, not `%7` and a variable)."""
    from relic.debugger.session import _quote
    args = ["%7$p", "a$HOME", "`echo pwn`", "$(id)", "it's", "back\\slash", "two words", "", 'say "hi"', "plain"]
    r = subprocess.run(["sh", "-c", "printf '[%s]\\n' " + " ".join(_quote(a) for a in args)],
                       capture_output=True, text=True, check=True)
    assert r.stdout.splitlines() == [f"[{a}]" for a in args]

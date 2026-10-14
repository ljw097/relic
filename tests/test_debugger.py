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

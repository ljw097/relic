from relic.__main__ import main


def run(capsys, *argv):
    assert main(list(argv)) == 0
    return capsys.readouterr().out


def test_disasm_names_calls(capsys, vuln64):
    out = run(capsys, "disasm", vuln64, "vuln")
    assert "vuln:" in out
    assert "call gets" in out and "call checksum" in out
    assert '"hello %s (%d)\\n"' in out


def test_funcs_and_vulns(capsys, vuln64):
    out = run(capsys, "funcs", vuln64)
    assert "classify" in out and "puts" not in out
    out = run(capsys, "vulns", vuln64)
    assert "format-string" in out and "gets()" in out


def test_checksec_and_xrefs(capsys, vuln64):
    assert "No canary found" in run(capsys, "checksec", vuln64)
    assert "main" in run(capsys, "xrefs", vuln64, "menu")


def test_cfg_dot(capsys, vuln64):
    out = run(capsys, "cfg", vuln64, "classify")
    assert out.startswith('digraph "classify"') and out.count("->") >= 8


def test_ir(capsys, vuln64):
    out = run(capsys, "ir", vuln64, "classify")
    assert out.startswith("function classify @") and "goto *rax" in out and "__asm" not in out


def test_opt(capsys, vuln64):
    out = run(capsys, "opt", vuln64, "menu", "--xrefs")
    assert out.startswith("function menu @")
    assert "zf_" not in out and "pf_" not in out      # flags cleaned up
    assert '"1. add"' in out                           # strings resolved inline
    assert "call   -> puts" in out                     # xref listing


def test_strings_grep(capsys, vuln64):
    out = run(capsys, "strings", vuln64, "-g", "bin/sh")
    assert '"/bin/sh"' in out
    assert "hello" not in out

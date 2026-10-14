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


def test_opt_frame(capsys, vuln64):
    out = run(capsys, "opt", vuln64, "vuln")
    assert "; gets" in out                              # resolved callee
    assert "; frame:" in out and "buf_48" in out        # stack layout with buffer
    assert "char[0x40]" in out                          # overflow-to-saved distance


def test_decompile(capsys, vuln64):
    out = run(capsys, "decompile", vuln64, "main")
    assert out.startswith("int main(int argc, ")
    assert "while (1) {" in out                         # structured menu loop
    assert "if (" in out and "menu()" in out


def test_decompile_addrs_and_all(capsys, vuln64):
    out = run(capsys, "decompile", vuln64, "vuln", "--addrs")
    line = next(ln for ln in out.splitlines() if "gets(" in ln)
    assert int(line.split()[0], 16)                    # address column
    out = run(capsys, "decompile", vuln64, "-a")
    assert "void vuln(void)" in out and "int checksum(" in out


def test_strings_grep(capsys, vuln64):
    out = run(capsys, "strings", vuln64, "-g", "bin/sh")
    assert '"/bin/sh"' in out
    assert "hello" not in out

"""C header import: declarations parsed and laid out like the compiler does, then used by the
decompiler (struct fields, enumerator names, parameter and return types)."""
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

from relic.analysis import analyze
from relic.decompiler.cheader import HeaderError, Model, parse
from relic.decompiler.emit import decompile

HERE = os.path.dirname(__file__)
TYPES_H = os.path.join(HERE, "src", "types.h")

LAYOUT_H = r"""
/* a bit of everything a header declares */
#include <stdint.h>
#define IGNORED(x) x \
    continued
typedef unsigned int u32;
enum color { RED, GREEN = 5, BLUE, ALPHA = 1 << 4, MASK = ALPHA | GREEN, NEG = -2 };
struct hdr { uint16_t len; unsigned char kind; } __attribute__((aligned(2)));
struct node {
    struct node *next;          // list
    const char *volatile name;
    int vals[4];
    struct hdr h;
    enum color c;
    double d;
    char tag;
    long l;
    union { int i; double f; char b[12]; } u;
    void (*cb)(int, struct node *);
    u32 flags;
    unsigned long long big;
    short pair[2][3];
    char tail[];
};
typedef struct { short x, y; } pt_t;
struct shapes { pt_t pts[sizeof(int) - 1]; long long ll; char c; };
union any { char c; long long ll; double d; };
int process(struct node *n, enum color c, double scale, const char *msg, ...);
static inline int helper(int x) { return x + 1; }
extern struct node *head;
"""

FIELDS = {"node": ["next", "name", "vals", "h", "c", "d", "tag", "l", "u", "cb", "flags", "big", "pair", "tail"],
          "shapes": ["pts", "ll", "c"]}


def _offsets(cc: list[str], run: list[str], tmp_path) -> dict[str, int] | None:
    (tmp_path / "t.h").write_text(LAYOUT_H)
    lines = [f'printf("{s}.{f} %zu\\n", offsetof(struct {s}, {f}));' for s, fs in FIELDS.items() for f in fs]
    lines += [f'printf("size {s} %zu\\n", sizeof(struct {s}));' for s in ("node", "shapes", "hdr")]
    lines.append('printf("size any %zu\\n", sizeof(union any));')
    (tmp_path / "chk.c").write_text('#include <stdio.h>\n#include <stddef.h>\n#include "t.h"\nint main(void) {\n'
                                    + "\n".join(lines) + "\n}\n")
    exe = tmp_path / "chk"
    if subprocess.run([*cc, "-o", str(exe), str(tmp_path / "chk.c")], capture_output=True).returncode:
        return None
    out = subprocess.run([*run, str(exe)], capture_output=True, text=True).stdout
    return {k: int(v) for k, v in (ln.rsplit(" ", 1) for ln in out.splitlines())}


@pytest.mark.parametrize("abi", ["x64", "x86", "arm", "a64"])
def test_layout_matches_the_compiler(abi, tmp_path):
    cc, run, model = {"x64": (["gcc"], [], Model()), "x86": (["gcc", "-m32"], [], Model(4, 4, 4, 4, 12)),
                      "arm": (["arm-linux-gnueabihf-gcc", "-static"], ["qemu-arm"], Model(4, 4, 4, 8, 8)),
                      "a64": (["aarch64-linux-gnu-gcc", "-static"], ["qemu-aarch64"], Model())}[abi]
    if shutil.which(cc[0]) is None or run and shutil.which(run[0]) is None:
        pytest.skip(f"no {cc[0]}")
    want = _offsets(cc, run, tmp_path)
    if want is None:
        pytest.skip(f"{' '.join(cc)} cannot build the probe")
    h = parse(LAYOUT_H, model)
    got = {}
    for s in FIELDS:
        agg = h.aggregates[f"struct {s}"]
        for m in agg.members:
            got[f"{s}.{m.name}"] = m.offset
        got[f"size {s}"] = agg.size
    got["size hdr"] = h.aggregates["struct hdr"].size
    got["size any"] = h.aggregates["union any"].size
    assert got == want


def test_enums_typedefs_and_prototypes():
    h = parse(LAYOUT_H)
    assert h.enums["color"] == {"RED": 0, "GREEN": 5, "BLUE": 6, "ALPHA": 16, "MASK": 21, "NEG": -2}
    assert h.typedefs["u32"].spell() == "unsigned int"
    assert h.typedefs["pt_t"].spell() == "struct pt_t"            # the anonymous struct takes the name
    assert h.bare == {"pt_t"}
    p = h.prototypes["process"]
    assert [t.spell() for _, t in p.params] == ["struct node *", "enum color", "double", "char *"]
    assert p.variadic and p.ret.spell() == "int"
    assert "helper" in h.prototypes                                # (its body is skipped)
    assert h.aggregates["struct node"].members[9].type.func       # the function pointer


@pytest.mark.parametrize("text,msg", [
    ("struct s {\n  int a : 3;\n};", "line 2: bit-field 'a'"),
    ("struct s { mystery_t x; };", "line 1"),
    ("enum e { A = UNDEFINED_MACRO };", "not a known constant"),
    ("struct s { int a; ", "end of input"),
    ("struct s { struct t inner; };", "struct t is used by value before it is defined"),
])
def test_errors_name_the_line(text, msg):
    with pytest.raises(HeaderError, match=re.escape(msg)):
        parse(text)


@pytest.fixture(params=["types_O0", "types_O2"])
def typed(request, tmp_path):
    src = request.getfixturevalue(request.param)
    path = tmp_path / os.path.basename(src)
    shutil.copy(src, path)                       # (the project file goes next to it)
    an = analyze(str(path))
    with open(TYPES_H) as fp:
        got = an.import_header(fp.read())
    return request.param, an, got


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


def test_import_summary(typed):
    _, an, got = typed
    assert got == {"structs": ["header", "job"], "enums": ["options_t", "state"], "typedefs": ["job_t", "options_t"],
                   "functions": ["add_option", "count_running", "run_job", "state_name"]}
    assert an.enum("state") == {"IDLE": 0, "RUNNING": 1, "STOPPED": 5, "FAILED": 6}
    assert an.resolve_type("job_t *") == "struct job *"


def test_enumerators_fields_and_signatures(typed):
    name, an, _ = typed
    code = _c(an, "state_name")
    assert code.startswith("char *state_name(enum state a1)"), code
    for e in ("IDLE", "RUNNING", "STOPPED", "FAILED"):
        assert e in code, code
    assert '"running"' in code and "4202" not in code
    code = _c(an, "run_job")
    assert "int run_job(struct job *a1, enum state a2, options_t a3)" in code, code
    assert "->state != FAILED" in code or "->state == FAILED" in code
    assert "& OPT_DRY)" in code and "& OPT_VERBOSE)" in code
    assert "->hdr.len" in code and "->name" in code and "->prio[" in code
    # the header's own declarations, nested struct first
    assert code.index("struct header {") < code.index("struct job {") < code.index("int run_job(")
    assert "    struct header hdr;" in code and "    enum state state;" in code and "hdr.len;" not in code
    code = _c(an, "count_running")
    assert "->state == RUNNING" in code and "->next" in code and "f_" not in code, code
    code = _c(an, "main")
    assert "run_job(" in code and ", RUNNING, " in code and ", STOPPED, " in code
    assert "add_option(" in code and ", OPT_FORCE)" in code, code


_HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "%(header)s"
#define __printf_chk(flag, ...) printf(__VA_ARGS__)
%(defines)s
#define main ref_main
#include "%(src)s"
#undef main
%(undefs)s

%(code)s

int main(int argc, char **argv)
{
    int re = argc > 1;
    job_t j[3];
    memset(j, 0, sizeof j);
    j[0].name = "a"; j[1].name = "b"; j[2].name = "c";
    j[0].next = &j[1]; j[1].next = &j[2];
    j[0].prio[0] = 3; j[0].prio[2] = 4; j[1].state = RUNNING; j[2].state = FAILED;
    for (int s = 0; s < 8; s++)
        printf("%%s\n", re ? p_state_name((enum state)s) : state_name((enum state)s));
    for (int o = 0; o < 16; o++) {
        job_t *t = &j[o %% 3];
        enum state to = (enum state)(o %% 7);
        int r = re ? p_run_job(t, to, (options_t)o) : run_job(t, to, (options_t)o);
        if (re)
            p_add_option(&j[1], (options_t)(1 << (o %% 4)));
        else
            add_option(&j[1], (options_t)(1 << (o %% 4)));
        int n = re ? p_count_running(j) : count_running(j);
        printf("%%d %%d %%u %%u %%d\n", r, n, j[1].opts, j[0].hdr.len, j[0].state);
    }
    return 0;
}
"""
FUNCS = ("state_name", "add_option", "run_job", "count_running")


def test_recompiled_pseudocode_behaves_like_the_original(typed, tmp_path):
    """The pseudocode, compiled against the header it was decompiled with, does what the original
    does (output of both, run on the same jobs)."""
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler")
    name, an, _ = typed
    bodies = []
    for f in FUNCS:
        text = _c(an, f)
        text = text[text.index(f"{f}(") - 40:] if "};" in text else text
        start = next(k for k, ln in enumerate(text.splitlines()) if f"{f}(" in ln and not ln.startswith(" "))
        lines = text.splitlines()[start:]
        lines[0] = re.sub(rf"\b{f}\(", f"p_{f}(", lines[0])
        bodies.append("\n".join(lines))
    code = "\n\n".join(bodies)
    for f in FUNCS:
        code = re.sub(rf"\b{f}\(", f"p_{f}(", code)
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"header": TYPES_H, "src": os.path.join(HERE, "src", "types.c"), "code": code,
                               "defines": "", "undefs": ""})
    exe = tmp_path / "re"
    r = subprocess.run([cc, "-w", "-fwrapv", "-o", str(exe), str(src)], capture_output=True, text=True)
    assert r.returncode == 0, f"{name}: does not compile:\n{r.stderr[:3000]}\n{code}"
    ref = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30).stdout
    out = subprocess.run([str(exe), "re"], capture_output=True, text=True, timeout=30).stdout
    assert ref and out == ref, f"{name}:\n{code}"


def test_project_round_trip_and_undo(typed):
    name, an, _ = typed
    an.save_project()
    with open(an.project_path) as fp:
        data = json.load(fp)
    assert data["c_types"]["enums"]["state"]["FAILED"] == 6 and data["structs"]["job"]["imported"]
    again = analyze(an.bin.path)                 # loads the project
    assert again.enum("options_t") == an.enum("options_t")
    assert "->state == RUNNING" in _c(again, "count_running")
    # one undo takes the whole import back
    an.undo()
    assert an.enum("state") is None and "job" not in an.struct_names
    assert "RUNNING" not in _c(an, "count_running")
    an.redo()
    assert "->state == RUNNING" in _c(an, "count_running")


def test_user_edits_override_the_header(typed):
    _, an, _ = typed
    an.rename_field("job", "f_8", "label")
    code = _c(an, "run_job")
    assert "->label" in code and "struct job {  // recovered" in code     # edited: the layout view
    f = an.function_by_name("state_name")
    an.set_return_type(f.addr, "const char *")
    assert _c(an, "state_name").startswith("char *state_name(")
    an.set_return_type(f.addr, "")
    an.set_var_type(f.addr, "a1", "int")
    assert _c(an, "state_name").startswith(("int64_t state_name(int a1)", "int state_name(int a1)",
                                             "char *state_name(int a1)"))


def test_second_header_builds_on_the_first(typed):
    _, an, _ = typed
    got = an.import_header("typedef job_t *job_ptr;\nstruct queue { job_ptr head; enum state mode; };")
    assert got["structs"] == ["queue"] and got["typedefs"] == ["job_ptr"]
    assert an.resolve_type("job_ptr") == "struct job *"
    assert an.struct_names["queue"]["types"]["f_0"] == "struct job *"
    with pytest.raises(HeaderError):
        an.import_header("struct broken {")
    assert "queue" in an.struct_names                              # a failed import changes nothing


def test_cli(types_O0, tmp_path):
    from relic.__main__ import main
    path = tmp_path / "types_O0.out"
    shutil.copy(types_O0, path)
    r = subprocess.run([sys.executable, "-m", "relic", "decompile", str(path), "count_running", "--header", TYPES_H],
                       capture_output=True, text=True, cwd=os.path.dirname(HERE))
    assert "->state == RUNNING" in r.stdout, r.stderr
    assert not os.path.exists(str(path) + ".relic.json")           # --header is not saved
    assert main(["types", str(path), TYPES_H]) in (0, None)
    assert os.path.exists(str(path) + ".relic.json")
    r = subprocess.run([sys.executable, "-m", "relic", "types", str(path)], capture_output=True, text=True,
                       cwd=os.path.dirname(HERE))
    assert "enum state { IDLE = 0, RUNNING = 1, STOPPED = 5, FAILED = 6 }" in r.stdout
    assert "struct job" in r.stdout and "char * state_name(enum state a1)" in r.stdout

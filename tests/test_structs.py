"""Struct recovery: fields from fixed-offset accesses, shared through globals, renamed, recompiled."""
import os
import re
import shutil
import subprocess

import pytest

from relic.analysis import analyze
from relic.decompiler.emit import decompile

HERE = os.path.dirname(__file__)
FUNCS = ["item_score", "item_add", "name_len", "pool_total", "pool_first", "item_weight", "make_item",
         "list_sum", "list_put", "list_initial", "chain_sum"]      # callees first


def _c(an, name):
    return decompile(an, an.function_by_name(name)).text


def test_notes_struct_shared_by_every_function(vuln64):
    an = analyze(vuln64)
    for name in ("add_note", "show_note", "del_note"):
        text = _c(an, name)
        assert "struct s_notes {" in text and "char *f_0;" in text, text
        assert "->f_0" in text and "*(int64_t *)" not in text, text
    assert "->f_8 = " in _c(an, "add_note")


@pytest.mark.parametrize("variant", ["vuln64_pie", "vuln_arm", "vuln_thumb", "vuln_a64", "vuln_mips_pie"])
def test_notes_struct_other_builds(request, variant):
    an = analyze(request.getfixturevalue(variant))
    text = _c(an, "add_note")
    off = 8 if an.bin.bits == 64 else 4
    assert "struct s_notes {" in text and "char *f_0;" in text and f"->f_{off:x} = " in text, text
    assert "->f_0" in _c(an, "show_note")


def test_rename_struct_and_fields_persist(vuln64, tmp_path):
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    an = analyze(str(path))
    an.rename_struct("s_notes", "note")
    an.rename_field("s_notes", "f_0", "data")
    an.rename_field("s_notes", "f_8", "size")
    an.rename(an.resolve("notes"), "note_table")            # the struct keeps its identity
    d = decompile(an, an.function_by_name("add_note"))
    assert "struct note {" in d.text and "note_table[var_1c]->size = var_20;" in d.text
    assert d.structs == {"note": "s_notes"} and d.fields["data"] == [("s_notes", "f_0")]
    an.save_project()
    again = analyze(str(path))
    assert "struct note {  // recovered, 12 bytes\n    char *data;\n    int size;\n};" in _c(again, "show_note")
    again.rename_field("s_notes", "f_8", "")
    assert "int f_8;" in _c(again, "add_note")


@pytest.mark.parametrize("variant", ["structs_O0", "structs_O2"])
def test_struct_parameters_and_nested_fields(request, variant):
    an = analyze(request.getfixturevalue(variant))
    text = _c(an, "item_score")
    # pool_first passes pool[0]: the parameter is the pool's struct, with item_score's fields in it
    assert "int item_score(struct s_pool *a1)" in text, text
    assert text.startswith("struct s_pool {  // recovered, 24 bytes"), text
    assert "->f_8" in text and "->f_c" in text and "->f_10" in text, text
    text = _c(an, "chain_sum")
    assert "->f_10" in text and "->f_8" in text, text            # next, it
    assert "->f_8" in _c(an, "item_add") and "->f_10" in _c(an, "item_add")


_HARNESS = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* reference: the original source, functions renamed ref_*; the decompiled code sees the
   same `pool` storage with its recovered element type */
%(defines)s
#define main ref_main
#define pool ref_pool
#include "%(src)s"
#undef main
#undef pool
%(undefs)s
#define pool (*(struct s_pool *(*)[4])&ref_pool)

/* decompiled */
%(code)s

int main(void) {
    int bad = 0;
    struct item it[3] = {{"alpha", 5, 3, 1000}, {"", -7, 2, -99}, {0, 40000, -1, 1LL << 40}};
    struct node n3 = {9, 0, 0}, n2 = {-4, &it[1], &n3}, n1 = {7, &it[0], &n2};
    for (int k = 0; k < 3; k++) {
        if (item_score((void *)&it[k]) != ref_item_score(&it[k])) { printf("item_score %%d\n", k); bad++; }
        if (name_len((void *)&it[k]) != ref_name_len(&it[k])) { printf("name_len %%d\n", k); bad++; }
        struct item a = it[k], b = it[k];
        item_add((void *)&a, 11); ref_item_add(&b, 11);
        if (memcmp(&a, &b, sizeof a)) { printf("item_add %%d\n", k); bad++; }
        ref_pool[k] = &it[k];
        if (pool_total() != ref_pool_total()) { printf("pool_total %%d\n", k); bad++; }
        if (pool_first() != ref_pool_first()) { printf("pool_first %%d\n", k); bad++; }
        if (item_weight((void *)&it[k]) != ref_item_weight(&it[k])) { printf("item_weight %%d\n", k); bad++; }
    }
    if (chain_sum((void *)&n1) != ref_chain_sum(&n1)) { printf("chain_sum\n"); bad++; }
    struct list la = {3, -2, {4, -9, 100, 7, 7, 7, 7, 7}, "hello, struct"}, lb = la;
    for (int i = -1; i < 9; i++) {
        list_put((void *)&la, i, i * 11 - 3); ref_list_put(&lb, i, i * 11 - 3);
        if (memcmp(&la, &lb, sizeof la)) { printf("list_put %%d\n", i); bad++; }
        if (list_sum((void *)&la) != ref_list_sum(&la)) { printf("list_sum %%d\n", i); bad++; }
        for (int k = 0; k < 20; k += 3)
            if (list_initial((void *)&la, k) != ref_list_initial(&la, k)) { printf("list_initial %%d\n", k); bad++; }
    }
    int ns[] = {-5, 0, 3, 7, 1234, 70000};
    for (int k = 0; k < 6; k++)
        if (make_item(ns[k]) != ref_make_item(ns[k])) { printf("make_item %%d\n", ns[k]); bad++; }
    if (!bad) puts("ok");
    return bad != 0;
}
"""


@pytest.mark.parametrize("variant", ["structs_O0", "structs_O2"])
def test_recovered_layout_recompiles_and_matches(request, variant, tmp_path):
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    an = analyze(request.getfixturevalue(variant))
    seen, parts = set(), []
    for fn in FUNCS:
        text = _c(an, fn)
        # a struct shared by several functions is declared above each: keep the first
        for block in re.findall(r"^struct \w+ \{.*?^\};\n", text, re.M | re.S):
            text = text.replace(block, "" if block in seen else block)
            seen.add(block)
        parts.append(text)
    code = "\n\n".join(parts)
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"code": code, "src": os.path.join(HERE, "src", "structs.c"),
                               "defines": "\n".join(f"#define {f} ref_{f}" for f in FUNCS),
                               "undefs": "\n".join(f"#undef {f}" for f in FUNCS)})
    exe = tmp_path / "re"
    r = subprocess.run([cc, "-w", "-fwrapv", "-Wno-error=incompatible-pointer-types", "-Wno-error=int-conversion",
                        "-o", str(exe), str(src)], capture_output=True, text=True)
    assert r.returncode == 0, f"{variant}: does not compile:\n{r.stderr[:3000]}\n{code}"
    r = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
    assert r.stdout.strip().endswith("ok"), f"{variant}:\n{r.stdout}\n{code}"


@pytest.mark.parametrize("variant", ["structs_O0", "structs_O2"])
def test_nested_and_self_referential_structs(request, variant):
    an = analyze(request.getfixturevalue(variant))
    text = _c(an, "chain_sum")
    node = re.search(r"struct (s_chain_sum_\d+) \{", text).group(1)
    item = re.search(r"struct (s_chain_sum_\d+_8) \{", text).group(1)
    assert f"    struct {item} *f_8;\n    struct {node} *f_10;" in text, text       # it, next
    assert text.index(f"struct {item} {{") < text.index(f"struct {node} {{")        # declared first
    assert f"int chain_sum(struct {node} *a1)" in text
    assert re.search(r"->f_8->f_8|v\d+->f_8;", text), text                          # n->it->count


def test_user_types_for_variables_and_fields(structs_O2, tmp_path):
    path = tmp_path / "s"
    shutil.copy(structs_O2, path)
    an = analyze(str(path))
    score = decompile(an, an.function_by_name("item_score"))
    item = next(iter(score.structs.values()))
    an.rename_struct(item, "item")
    an.rename_field(item, "f_8", "count")
    # the struct recovered in item_score, applied to the parameter of other functions
    for fn in ("name_len", "item_add"):
        an.set_var_type(an.function_by_name(fn).addr, "a1", "struct item *")
        text = _c(an, fn)
        assert f"{fn}(struct item *a1" in text and "struct item {" in text, text
    assert "char *f_0;" in _c(an, "name_len") and "->count" in _c(an, "item_add")
    # scalar types, a bad type, an unknown struct
    an.set_var_type(an.function_by_name("item_add").addr, "a2", "unsigned int")
    assert "struct item *a1, unsigned int a2)" in _c(an, "item_add")
    with pytest.raises(ValueError):
        an.set_var_type(an.function_by_name("item_add").addr, "a2", "int[")
    an.set_var_type(an.function_by_name("chain_sum").addr, "a1", "struct node *")
    text = _c(an, "chain_sum")
    assert "// a1: no struct node to apply" in text and "struct node *a1" not in text
    # a field typed as a pointer to a named struct: the nested access goes through it
    node = next(g for s, g in decompile(an, an.function_by_name("chain_sum")).structs.items()
                if not s.endswith("_8"))
    an.rename_struct(node, "node")
    an.set_field_type(node, "f_8", "struct item *")
    text = _c(an, "chain_sum")
    assert "    struct item *f_8;" in text and "->count" in text, text
    an.save_project()
    again = analyze(str(path))
    assert "->count" in _c(again, "chain_sum") and "unsigned int a2)" in _c(again, "item_add")
    again.set_var_type(again.function_by_name("item_add").addr, "a2", "")
    assert "unsigned int a2" not in _c(again, "item_add")


def test_applied_types_still_recompile(structs_O2, tmp_path):
    """Structs applied by the user change only how the code reads, not what it computes."""
    an = analyze(structs_O2)
    item = next(iter(decompile(an, an.function_by_name("item_score")).structs.values()))
    an.rename_struct(item, "item_r")          # (the reference source has its own `struct item`)
    for fn in ("name_len", "item_add"):
        an.set_var_type(an.function_by_name(fn).addr, "a1", "struct item_r *")
    cc = shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler")
    for fn in FUNCS:                         # a struct applied to several functions grows with each
        _c(an, fn)
    seen, parts = set(), []
    for fn in FUNCS:
        text = _c(an, fn)
        for block in re.findall(r"^struct \w+ \{.*?^\};\n", text, re.M | re.S):
            name = block.split()[1]
            text = text.replace(block, "" if name in seen else block)
            seen.add(name)
        parts.append(text)
    src = tmp_path / "re.c"
    src.write_text(_HARNESS % {"code": "\n\n".join(parts), "src": os.path.join(HERE, "src", "structs.c"),
                               "defines": "\n".join(f"#define {f} ref_{f}" for f in FUNCS),
                               "undefs": "\n".join(f"#undef {f}" for f in FUNCS)})
    r = subprocess.run([cc, "-w", "-fwrapv", "-Wno-error=incompatible-pointer-types", "-Wno-error=int-conversion",
                        "-o", str(tmp_path / "re"), str(src)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[:3000]
    assert subprocess.run([str(tmp_path / "re")], capture_output=True, text=True).stdout.strip().endswith("ok")


@pytest.mark.parametrize("variant", ["structs_O0", "structs_O2"])
def test_local_struct_passed_to_a_callee(request, variant):
    """make_item mallocs an item and hands it to item_weight: one struct for both, with the
    fields item_weight reads (kind, total) known on the caller's side too."""
    an = analyze(request.getfixturevalue(variant))
    callee = _c(an, "item_weight")
    caller = _c(an, "make_item")
    name = re.search(r"struct (s_make_item_\d+) \{", caller).group(1)
    assert f"int item_weight(struct {name} *a1)" in callee, callee
    decl = re.search(r"^struct %s \{.*?^\};" % name, caller, re.M | re.S).group(0)
    assert "short f_c;" in decl and "int64_t f_10;" in decl and decl in callee


@pytest.mark.parametrize("variant", ["structs_O0", "structs_O2"])
def test_array_fields(request, variant):
    an = analyze(request.getfixturevalue(variant))
    text = _c(an, "list_put")
    assert re.search(r"void list_put\(struct s_list_put_\d+ \*a1, int a2, int a3\)", text), text
    assert "    int f_8[];" in text and re.search(r"->f_8\[\w+\] = ", text) and "->f_0 = " in text, text
    text = _c(an, "list_initial")
    assert "    char f_28[];" in text and re.search(r"->f_28\[\w+ & 15\]", text), text
    if variant.endswith("O0"):                  # (-O2 walks a pointer through vals instead)
        assert re.search(r"->f_8\[var_\w+\]", _c(an, "list_sum"))


def test_hand_edited_fields_persist(vuln64, tmp_path):
    path = tmp_path / "v"
    shutil.copy(vuln64, path)
    an = analyze(str(path))
    _c(an, "add_note")
    an.add_field("s_notes", 0x10, "char[8]", "tag")
    an.add_field("s_notes", 0xc, "unsigned int")
    an.remove_field("s_notes", 0)
    with pytest.raises(ValueError):
        an.add_field("s_notes", 0x20, "struct nope")          # no size known
    text = _c(an, "add_note")
    assert "    unsigned int f_c;\n    char tag[8];" in text and "*(int64_t *)notes[" in text, text
    an.save_project()
    again = analyze(str(path))
    text = _c(again, "show_note")
    assert "    char tag[8];" in text and "char *f_0" not in text, text
    again.add_field("s_notes", 0, "char *")                  # back
    assert "->f_0" in _c(again, "show_note")


def test_cancel_during_struct_recovery_caches_nothing(vuln64, monkeypatch):
    """A decompilation cancelled while it scans other functions for a struct (the GUI moved on)
    must not leave "no struct" behind: decompiled again, the struct is there."""
    from relic.decompiler import pipeline
    from relic.progress import Cancelled
    an = analyze(vuln64)
    real = pipeline.prepare
    target = an.function_by_name("add_note")

    def prepare(an_, f):
        if f is not target:                    # the other functions the struct is looked up in
            raise Cancelled()
        return real(an_, f)
    monkeypatch.setattr(pipeline, "prepare", prepare)
    with pytest.raises(Cancelled):
        decompile(an, target)
    monkeypatch.setattr(pipeline, "prepare", real)
    assert all(v is not None for v in an.__dict__.get("_structs", {}).values())
    text = _c(an, "add_note")
    assert "struct s_notes {" in text and "->f_8 = " in text, text

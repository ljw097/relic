"""Shared function metadata (relic.analysis.lumina): fingerprints, push / pull, the server."""
import json
import os
import shutil
import subprocess
import sys
import threading


from relic.analysis import analyze
from relic.analysis.lumina import Store, fingerprint, serve

HERE = os.path.dirname(__file__)


def test_fingerprint_is_position_independent(vuln64, vuln64_pie, vuln64_stripped):
    a, b, c = analyze(vuln64), analyze(vuln64_pie), analyze(vuln64_stripped)
    fa = fingerprint(a, a.function_by_name("add_note"))
    assert fa and fa == fingerprint(c, c.functions[a.function_by_name("add_note").addr])   # stripped copy
    assert fingerprint(a, a.function_by_name("vuln")) != fa
    assert fingerprint(b, b.function_by_name("add_note")) is not None                       # (PIE: its own)
    assert all(fingerprint(a, f) is None for f in a.functions.values() if f.is_import)


def test_push_pull_names_a_stripped_copy(vuln64, vuln64_stripped, tmp_path):
    store = str(tmp_path / "store.json")
    src = analyze(vuln64)
    src.comment(src.function_by_name("vuln").addr + 4, "overflow here")
    src.rename_var(src.function_by_name("vuln").addr, "buf_48", "line")
    got = src.lumina_push(store)
    assert got["pushed"] >= 10
    with open(store) as fp:
        assert json.load(fp)["version"] == 1
    assert src.lumina_push(store)["pushed"] == 0                    # nothing new the second time
    path = tmp_path / "stripped"
    shutil.copy(vuln64_stripped, path)
    an = analyze(str(path))
    vuln = src.function_by_name("vuln").addr
    got = an.lumina_pull(store)
    names = dict(got["applied"])
    assert names[vuln] == "vuln" and "add_note" in names.values() and "main" in names.values()
    assert an.comments[vuln + 4] == "overflow here" and an.var_names[vuln]["buf_48"] == "line"
    an.undo()                                                       # one undo step
    assert vuln not in an.renames and vuln + 4 not in an.comments
    an.rename(vuln, "mine")
    an.lumina_pull(store)
    assert an.renames[vuln] == "mine"                               # the user's name stays
    an.lumina_pull(store, overwrite=True)
    assert an.renames[vuln] == "vuln"


def test_server_store(vuln64, vuln64_stripped, tmp_path):
    ready = threading.Event()
    box = {}

    def started(server):
        box["server"] = server
        ready.set()
    t = threading.Thread(target=serve, args=(str(tmp_path / "team.json"), "127.0.0.1", 0, started), daemon=True)
    t.start()
    assert ready.wait(10)
    url = f"http://127.0.0.1:{box['server'].server_address[1]}"
    try:
        assert analyze(vuln64).lumina_push(url)["pushed"] >= 10
        got = analyze(vuln64_stripped).lumina_pull(url)
        assert "vuln" in dict(got["applied"]).values()
        assert Store(url).get(["nope"]) == {}
    finally:
        box["server"].shutdown()


def test_cli(vuln64, vuln64_stripped, tmp_path):
    store = str(tmp_path / "s.json")
    path = tmp_path / "stripped"
    shutil.copy(vuln64_stripped, path)

    def relic(*args):
        r = subprocess.run([sys.executable, "-m", "relic", "lumina", *args, "--store", store],
                           capture_output=True, text=True, cwd=os.path.dirname(HERE))
        return r.returncode, r.stdout + r.stderr
    code, out = relic("push", vuln64)
    assert code == 0 and "pushed" in out
    code, out = relic("pull", str(path))
    assert code == 0 and " vuln\n" in out and "function(s) from" in out
    assert os.path.exists(str(path) + ".relic.json")
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    r = subprocess.run([sys.executable, "-m", "relic", "lumina", "pull", str(path), "--store", str(bad)],
                       capture_output=True, text=True, cwd=os.path.dirname(HERE))
    assert r.returncode != 0 and "not a lumina store" in r.stderr

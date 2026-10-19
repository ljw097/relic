"""C++ classes from Itanium RTTI (tests/src/classes.cpp, g++ -O2), with symbols and stripped:
bases, vtables (one per base of a class with several), virtual method names, and virtual calls
through `this` resolved over the class hierarchy."""
import os
import shutil
import subprocess

import pytest

from relic.__main__ import main
from relic.analysis import analyze

HERE = os.path.dirname(__file__)


@pytest.fixture(scope="module", params=["plain", "stripped"])
def classes(request, tmp_path_factory):
    cxx = shutil.which("g++")
    if cxx is None:
        pytest.skip("needs g++")
    out = str(tmp_path_factory.mktemp("rtti") / "classes")
    subprocess.run([cxx, "-O2", "-o", out, os.path.join(HERE, "src", "classes.cpp")], check=True)
    if request.param == "stripped":
        subprocess.run(["strip", out], check=True)
    return request.param, out


def test_class_hierarchy(classes):
    _, path = classes
    an = analyze(path)
    cl = an.classes
    assert {"Animal", "Dog", "Bird", "Named", "Parrot"} <= set(cl)
    assert cl["Dog"].bases == ["Animal"] and cl["Parrot"].bases == ["Bird", "Named"]
    assert [vt.offset for vt in cl["Parrot"].vtables] == [0, -8]      # (Named's part of a Parrot)
    assert len(cl["Dog"].vtables[0].slots) == 5                       # 2 destructors, sound, legs, speak
    dog, bird, parrot = (cl[n].vtables[0].slots for n in ("Dog", "Bird", "Parrot"))
    assert dog[4] == bird[4] == parrot[4]                             # speak(): Animal's, inherited
    assert parrot[3] == bird[3] != dog[3]                             # legs(): Bird's override
    assert an.name(cl["Dog"].vtables[0].addr - 16) in ("vtable for Dog", "_ZTV3Dog")


def test_stripped_names(classes):
    kind, path = classes
    an = analyze(path)
    cl = an.classes
    if kind != "stripped":
        return
    assert an.functions[cl["Dog"].vtables[0].slots[2]].name == "Dog::vfunc2"
    assert an.functions[cl["Dog"].vtables[0].slots[4]].name == "Animal::vfunc4"      # (shared: the base's)
    assert an.functions[cl["Parrot"].vtables[0].slots[3]].name == "Bird::vfunc3"
    assert an.functions[cl["Parrot"].vtables[1].slots[0]].name.startswith("Parrot::thunk8_vfunc")


def test_virtual_call_through_this(classes):
    """`speak()` calls `sound()` (slot 2) on `this`: an Animal, so any of the classes' sound()."""
    _, path = classes
    an = analyze(path)
    speak = an.functions[an.classes["Dog"].vtables[0].slots[4]]
    sites = [(a, t) for a, (t, _) in an.icalls.items() if speak.block_at(a) is not None]
    assert len(sites) == 1
    want = {an.classes[n].vtables[0].slots[2] for n in ("Dog", "Bird", "Parrot")}
    assert sites[0][1] == want
    assert all(any(x.frm == sites[0][0] for x in an.xrefs_to[t]) for t in want)


def test_cli(classes, capsys):
    _, path = classes
    main(["classes", path, "--no-sigs"])
    out = capsys.readouterr().out
    assert "class Parrot : Bird, Named" in out and "pure virtual" not in out.split("class Dog")[1].split("class")[0]

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


@pytest.fixture(scope="module", params=["plain", "stripped", "O0-stripped"])
def classes(request, tmp_path_factory):
    cxx = shutil.which("g++")
    if cxx is None:
        pytest.skip("needs g++")
    out = str(tmp_path_factory.mktemp("rtti") / "classes")
    opt = "-O0" if request.param.startswith("O0") else "-O2"
    subprocess.run([cxx, opt, "-o", out, os.path.join(HERE, "src", "classes.cpp")], check=True)
    if request.param.endswith("stripped"):
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
    assert cl["Parrot"].offsets == {"Bird": 0, "Named": 8}
    dog, bird, parrot = (cl[n].vtables[0].slots for n in ("Dog", "Bird", "Parrot"))
    assert dog[4] == bird[4] == parrot[4]                             # speak(): Animal's, inherited
    assert parrot[3] == bird[3] != dog[3]                             # legs(): Bird's override
    assert an.name(cl["Dog"].vtables[0].addr - 16) in ("vtable for Dog", "_ZTV3Dog")


def test_stripped_names(classes):
    kind, path = classes
    an = analyze(path)
    cl = an.classes
    if kind != "stripped":
        return       # (-O0: no identical code folded, so the inherited methods are told apart less)
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
    assert len(sites) == 1, sites
    want = {an.classes[n].vtables[0].slots[2] for n in ("Dog", "Bird", "Parrot")}
    assert sites[0][1] == want
    assert all(any(x.frm == sites[0][0] for x in an.xrefs_to[t]) for t in want)


def test_cli(classes, capsys):
    _, path = classes
    main(["classes", path, "--no-sigs"])
    out = capsys.readouterr().out
    assert "class Parrot : Bird, Named" in out and "pure virtual" not in out.split("class Dog")[1].split("class")[0]


@pytest.fixture(scope="module", params=["x86_64", "i686"])
def msvc(request, tmp_path_factory):
    """tests/src/classes_msvc.cpp built for MSVC's C++ ABI (PE, MSVC RTTI) by clang and lld-link."""
    clang, link = shutil.which("clang"), shutil.which("lld-link")
    if clang is None or link is None:
        pytest.skip("needs clang and lld-link")
    d = tmp_path_factory.mktemp("msvc")
    target = f"--target={request.param}-pc-windows-msvc"
    subprocess.run([clang, "-x", "c++", target, "-O2", "-fno-exceptions", "-c", "-o", str(d / "cls.obj"),
                    os.path.join(HERE, "src", "classes_msvc.cpp")], check=True)
    subprocess.run([clang, target, '-DSYM="??_7type_info@@6B@"', "-c", "-o", str(d / "ti.obj"),
                    os.path.join(HERE, "src", "msvc_typeinfo.c")], check=True)
    out = str(d / "cls.exe")
    subprocess.run([link, f"/out:{out}", "/entry:mainCRTStartup", "/subsystem:console", "/nodefaultlib",
                    str(d / "cls.obj"), str(d / "ti.obj")], check=True)
    return request.param, out


def test_msvc_classes(msvc):
    arch, path = msvc
    an = analyze(path)
    cl = an.classes
    ptr = 8 if arch == "x86_64" else 4
    assert {"Dog", "Bird", "Parrot"} <= set(cl)
    assert cl["Dog"].bases == ["Animal"] and cl["Parrot"].bases == ["Bird", "Named"]
    assert [vt.offset for vt in cl["Parrot"].vtables] == [0, -ptr]
    dog, bird, parrot = (cl[n].vtables[0].slots for n in ("Dog", "Bird", "Parrot"))
    assert dog[3] == bird[3] == parrot[3] and parrot[2] == bird[2] != dog[2]
    assert an.functions[dog[1]].name == "Dog::vfunc1"
    assert an.name(cl["Dog"].vtables[0].addr - ptr) == "vtable for Dog"      # (from its locator pointer)
    # speak() calls sound() (slot 1) through `this` (rcx / ecx)
    speak = an.functions[dog[3]]
    sites = [t for a, (t, _) in an.icalls.items() if speak.block_at(a) is not None]
    assert sites == [frozenset(cl[n].vtables[0].slots[1] for n in ("Dog", "Bird", "Parrot"))]
    # the entry point: make()'s object (constructed in place) -- speak(), legs(), the destructor
    entry = an.functions[an.bin.entry]
    calls = sorted((t for a, (t, _) in an.icalls.items() if entry.block_at(a) is not None), key=len)
    assert frozenset({dog[3]}) in calls and frozenset({dog[2], bird[2]}) in calls


def test_virtual_calls_on_objects(classes):
    """main: `make()` returns a Dog, a Bird or a Parrot (what it constructs, through constructors
    at -O0, vtables stored in place at -O2) -- its speak() and destructor calls; the result of
    `dynamic_cast<const Named *>` -- Named's name() in a Parrot: the thunk of its second vtable."""
    _, path = classes
    an = analyze(path)
    cl = an.classes
    main = an.function_by_name("main")
    got = sorted((t for a, (t, _) in an.icalls.items() if main.block_at(a) is not None), key=len)
    slots = {n: cl[n].vtables[0].slots for n in ("Dog", "Bird", "Parrot")}
    speak = frozenset({slots["Dog"][4]})
    deleting = frozenset(slots[n][1] for n in slots)            # (the deleting destructors)
    name = cl["Parrot"].vtables[1].slots[0]
    assert speak in got and deleting in got
    own = {v.slots[0] for v in cl["Named"].vtables[:1]}         # (Named's own, when it has a vtable: -O0)
    assert any(name in t and t <= {name} | own for t in got)


def test_virtual_calls_on_arguments(classes):
    """show(const Animal *a), only ever called with make()'s object: a->sound(), a->legs()."""
    _, path = classes
    an = analyze(path)
    slots = {n: an.classes[n].vtables[0].slots for n in ("Dog", "Bird", "Parrot")}
    main = an.function_by_name("main")
    speak = an.functions[slots["Dog"][4]]
    rest = {}
    for a, (t, _) in an.icalls.items():
        f = an.function_at(a)
        if f is not main and f is not speak:
            rest.setdefault(f.addr, set()).add(t)
    sound = frozenset(slots[n][2] for n in slots)
    legs = frozenset(slots[n][3] for n in slots)
    assert any(ts == {sound, legs} for ts in rest.values()), rest


@pytest.fixture(scope="module", params=["O0", "O2"])
def a64(request, tmp_path_factory):
    """tests/src/classes.cpp for AArch64, stripped: by aarch64-linux-gnu-g++, or by clang against
    the cross C++ runtime library."""
    d = tmp_path_factory.mktemp("a64")
    out = str(d / "classes")
    src = os.path.join(HERE, "src", "classes.cpp")
    gxx = shutil.which("aarch64-linux-gnu-g++")
    gcc, clang = shutil.which("aarch64-linux-gnu-gcc"), shutil.which("clang++")
    lib = "/usr/aarch64-linux-gnu/lib/libstdc++.so.6"
    if gxx:
        subprocess.run([gxx, f"-{request.param}", "-o", out, src], check=True)
    elif gcc and clang and os.path.exists(lib):
        subprocess.run([clang, "--target=aarch64-linux-gnu", f"-{request.param}", "-c", "-o", out + ".o", src],
                       check=True)
        subprocess.run([gcc, "-o", out, out + ".o", lib], check=True)
    else:
        pytest.skip("needs an AArch64 C++ compiler")
    subprocess.run([shutil.which("aarch64-linux-gnu-strip") or "strip", out], check=True)
    return out


def test_a64_virtual_calls(a64):
    """AArch64: the same classes, and main's calls -- make()'s object (constructors at -O0, vtables
    stored in place, two at once by `stp`, at -O2), the dynamic_cast result -- and show()'s."""
    an = analyze(a64)
    cl = an.classes
    assert cl["Parrot"].bases == ["Bird", "Named"] and [v.offset for v in cl["Parrot"].vtables] == [0, -8]
    slots = {n: cl[n].vtables[0].slots for n in ("Dog", "Bird", "Parrot")}
    main = an.function_by_name("main")
    got = [t for a, (t, _) in an.icalls.items() if main.block_at(a) is not None]
    assert frozenset({slots["Dog"][4]}) in got and frozenset(slots[n][1] for n in slots) in got
    assert any(cl["Parrot"].vtables[1].slots[0] in t for t in got)
    sound = frozenset(slots[n][2] for n in slots)
    assert sum(t == sound for _, (t, _) in an.icalls.items()) >= 2          # (show() and speak())

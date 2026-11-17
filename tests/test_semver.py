"""tools/semver_check.py: release versions follow Semantic Versioning (the Release workflow)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from semver_check import check, key, parse, tags_versions  # noqa: E402

TAGS = """abc\trefs/tags/v1.3.0
def\trefs/tags/v1.4.0
def\trefs/tags/v1.4.0^{}
012\trefs/tags/v0.3.0
345\trefs/tags/not-a-release
"""


def test_parse():
    assert parse("1.5.0") == (1, 5, 0, ())
    assert parse("2.0.0-rc.1") == (2, 0, 0, ("rc", 1))
    for bad in ("1.5", "1.5.0.1", "v1.5.0", "01.5.0", "1.5.0-", "1.5.0-01", "1.5.0+build"):
        assert parse(bad) is None, bad


def test_precedence():
    # semver.org's example: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta < 1.0.0-beta
    #   < 1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
             "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0"]
    assert sorted(order, key=lambda v: key(parse(v))) == order


def test_check():
    tags = tags_versions(TAGS)
    assert tags == ["1.3.0", "1.4.0", "0.3.0"]
    assert check("1.5.0", False, tags) is None
    assert check("1.4.1", False, tags) is None and check("2.0.0", False, tags) is None
    assert "not newer" in check("1.4.0", False, tags)
    assert "not newer" in check("1.3.9", False, tags)
    assert "not a semantic version" in check("1.5", False, tags)
    assert "pre-release" in check("1.5.0-rc.1", False, tags)
    assert check("1.5.0-rc.1", True, tags) is None
    assert "no pre-release part" in check("1.5.0", True, tags)
    assert check("0.1.0", False, []) is None

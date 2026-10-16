"""Write docs/scripting.md from the scripting API's docstrings: python tools/gen_scripting_docs.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from relic.scripting import reference  # noqa: E402

out = os.path.join(os.path.dirname(__file__), "..", "docs", "scripting.md")
with open(out, "w") as fp:
    fp.write(reference())
print(f"wrote {os.path.normpath(out)}")

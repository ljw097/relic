"""Decompiler (work in progress). See docs/decompiler-plan.md.

Stage 1: `lift(an, func)` turns a function's CFG into IR (`relic.decompiler.ir`).
"""
from __future__ import annotations

from .ir import IRFunction
from .lift import lift_function as lift

__all__ = ["IRFunction", "lift"]

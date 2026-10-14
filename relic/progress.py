"""Cooperative cancellation and progress reporting for long-running work.

Analysis, the vulns scan and decompilation run in background threads in the
GUI. Python threads cannot be stopped from outside, so the work itself checks
in at safe points: `checkpoint()` raises `Cancelled` once the token of the
current thread was cancelled, and `report()` forwards progress to whoever
listens. A thread installs its token with `Progress.activate()`; code running
without one (the CLI, tests) pays one context-variable lookup per checkpoint.
"""
from __future__ import annotations

import threading
import time
from contextvars import ContextVar
from typing import Callable

ProgressCallback = Callable[[str, int, int], None]   # stage, done, total (0: unknown)


class Cancelled(Exception):
    """The work was cancelled at a checkpoint."""


class Progress:
    """Cancellation flag plus a throttled progress callback for one piece of work."""

    def __init__(self, callback: ProgressCallback | None = None, interval: float = 0.1):
        self._cancel = threading.Event()
        self.callback = callback
        self.interval = interval
        self._last = 0.0

    def cancel(self):
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check(self):
        if self._cancel.is_set():
            raise Cancelled()

    def report(self, stage: str, done: int = 0, total: int = 0, force: bool = False):
        self.check()
        if self.callback is None:
            return
        now = time.monotonic()
        if force or now - self._last >= self.interval or (total and done >= total):
            self._last = now
            self.callback(stage, done, total)

    def activate(self):
        """Make this the token of the calling thread (returns a reset handle for `deactivate`)."""
        return _current.set(self)

    @staticmethod
    def deactivate(handle):
        _current.reset(handle)


_current: ContextVar[Progress | None] = ContextVar("relic_progress", default=None)


def current() -> Progress | None:
    return _current.get()


def checkpoint():
    """Raise `Cancelled` if the current thread's work was cancelled."""
    p = _current.get()
    if p is not None and p._cancel.is_set():
        raise Cancelled()


def report(stage: str, done: int = 0, total: int = 0, force: bool = False):
    """Report progress to the current thread's listener (and check for cancellation)."""
    p = _current.get()
    if p is not None:
        p.report(stage, done, total, force)


__all__ = ["Cancelled", "Progress", "checkpoint", "current", "report"]

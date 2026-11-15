"""One sandbox run at a time across Kratos (E.7b §3.7, §6 `test_sandbox_global_lock`).

`agent/self_test.py::run_sandbox_test` assumes serial use (its `capture_output` buffering and
the single Incus host). The evo-loop and an E.7b reproduction both drive it, and two E.7b
reproductions could run at once, so both take THIS lock: an advisory `flock` on one fixed file,
outside any data dir (self_test has none), so it serialises evo-loop and review alike.

`hold()` blocks until the lock is free (a waiting reproduction shows "waiting for the sandbox").
`try_hold()` returns immediately with whether it got the lock, for a caller that wants to say so.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:                     # pragma: no cover - non-POSIX; evo-loop is POSIX-only anyway
    fcntl = None                        # type: ignore[assignment]


def lock_path() -> Path:
    """A per-user fixed path (not under a data dir -- self_test has none)."""
    return Path(tempfile.gettempdir()) / f"kratos-sandbox-{os.getuid() if hasattr(os, 'getuid') else 'user'}.lock"


@contextlib.contextmanager
def hold(*, blocking: bool = True) -> Iterator[bool]:
    """Hold the global sandbox lock for the duration of the block. Yields True when held.
    With `blocking=False`, yields immediately with whether it was acquired (and does not hold
    it if it wasn't)."""
    if fcntl is None:
        yield True
        return
    path = lock_path()
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if blocking else (fcntl.LOCK_EX | fcntl.LOCK_NB))
            acquired = True
        except (BlockingIOError, OSError):
            if blocking:
                raise
            acquired = False
        yield acquired
    finally:
        if acquired:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def is_busy() -> bool:
    """True when another holder has the lock right now (a non-blocking probe, for 'waiting for
    the sandbox' messaging). Never holds the lock."""
    with hold(blocking=False) as got:
        return not got

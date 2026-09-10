"""Cross-process, per-target run lock (design doc A6 §6 concurrency).

Only ONE Kratos run may investigate a given target at a time. Without this, a
background SCHEDULED run and a concurrent INTERACTIVE investigation on the same
host would collide: interleaved writes into the shared ``data_dir`` (two runs'
scan/log files, which ``correlate_findings``' latest-file discovery could then
mix), and two simultaneous SSH sessions to the target (log confusion / rate
limits). Self-ban is already avoided because Kratos's host is in the target's
fail2ban ``ignoreip``, but the data interleaving is a real correctness risk.

Mechanism: an ``flock`` (advisory, POSIX) on a per-target lockfile under
``data_dir/locks/`` — the same primitive the kept-tools persistence lock uses, so
it works ACROSS processes (a systemd-invoked ``kratos scheduled-run`` vs. the
interactive TUI process). NON-BLOCKING by design: the caller decides what to do
when the target is busy — a scheduled run defers (skips + notifies, never blocks
a timer); an interactive run tells the human to try again in a moment. Keyed by
target, so a self-host (127.0.0.1) run and a monitored-target run never block
each other.

Linux-only (fcntl), consistent with the rest of the scheduling feature (systemd
user timers). A caller on a platform without fcntl would fail at import — that is
acceptable: scheduling is a Linux-host capability.
"""
from __future__ import annotations

import fcntl
import re
import time
from pathlib import Path
from typing import Callable, IO, Optional

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _locks_dir(data_dir: Path) -> Path:
    return Path(data_dir) / "locks"


def target_lock_path(data_dir: Path, target: Optional[str]) -> Path:
    slug = _SLUG_RE.sub("_", (target or "default").strip()) or "default"
    return _locks_dir(data_dir) / f"target-{slug}.lock"


def try_acquire_target(data_dir: Path, target: Optional[str]) -> Optional[IO]:
    """Try to take the per-target lock WITHOUT blocking. Returns an open,
    flock-held file handle on success (pass it to ``release_target`` when the run
    finishes), or ``None`` if another process currently holds it. The lock is
    released automatically if this process dies (flock is tied to the open file
    description), so a crashed run never wedges the target permanently."""
    path = target_lock_path(data_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    f = open(path, "w")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    return f


def acquire_target_blocking(
    data_dir: Path,
    target: Optional[str],
    *,
    timeout: float,
    poll: float = 0.5,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Optional[IO]:
    """Try to take the lock, WAITING up to ``timeout`` seconds for a busy target
    to free (re-checking every ``poll`` s). Returns a held handle as soon as it's
    free, or ``None`` on timeout or if ``should_stop()`` becomes true (e.g. the
    user cancelled). Bounded on purpose: the caller (an interactive run) waits out
    a quick collision but never freezes indefinitely on a long one. Each attempt
    is non-blocking, so this never wedges even if the holder never releases."""
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        handle = try_acquire_target(data_dir, target)
        if handle is not None:
            return handle
        if should_stop is not None and should_stop():
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(poll, remaining))


def release_target(handle: Optional[IO]) -> None:
    """Release a lock taken by ``try_acquire_target`` (no-op on ``None``)."""
    if handle is None:
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()

"""Who has the data open (docs/phaseD/D.8 §3.9).

Every long-running Kratos process that uses a data folder -- the TUI, `kratos serve`,
`kratos mcp-serve`, the agent listener (`kratos subagent-serve`, the always-on service)
and `kratos scheduled-run` -- holds a SHARED lock on ``<data>/locks/in-use.lock`` for its
lifetime (`hold`). A restore takes the same lock EXCLUSIVELY (`exclusive`), so it refuses
while any of them runs, and none of them can start while a restore runs. The kernel drops
a lock when its process dies, so a crashed process never blocks a restore.

A second lock, ``locks/backup.lock``, keeps two backups (or a backup and a restore) of
the same data from running at once.
"""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path

from kratos.paths import ensure_private_dir

IN_USE = "in-use.lock"
BACKUP = "backup.lock"
_held: list[int] = []


class InUseError(RuntimeError):
    pass


def _open(data_dir: Path, name: str) -> int:
    d = ensure_private_dir(Path(data_dir) / "locks")
    return os.open(d / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)


def hold(data_dir: Path | str, what: str) -> None:
    """Mark this process as using `data_dir` until it exits. Refuses while a restore runs."""
    fd = _open(Path(data_dir), IN_USE)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError as e:
        os.close(fd)
        if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
            raise InUseError(f"a backup restore is running on {data_dir}; start {what} again when it has finished") \
                from None
        raise
    _held.append(fd)


def exclusive(data_dir: Path | str) -> int | None:
    """The in-use lock, exclusively (a restore), or None when something holds it."""
    fd = _open(Path(data_dir), IN_USE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def backup_lock(data_dir: Path | str) -> int | None:
    fd = _open(Path(data_dir), BACKUP)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def release(fd: int | None) -> None:
    if fd is None:
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

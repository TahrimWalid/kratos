"""At most a few SSH sessions to one machine at a time, across every Kratos process.

Collection (kratos.collect) runs its checks in parallel, and several of them open more
than one SSH session. sshd starts refusing new connections when more than
`MaxStartups` (default 10:30:100 -- from 10 on) are still authenticating at once, and
some fail2ban setups count those refusals: the phase A audit saw 10 logins to the
lab target in the same second from one cold collection, and an investigation and a
schedule running together double that.

Each session holds one of `max_sessions()` lock files for its machine (`flock`, so a
crashed process frees its slot by itself); a session that finds them all taken waits,
until its own time limit or until its check is cancelled. The lock folder is private
(0700, owned by this user, never followed through a symlink); if it can't be used,
the cap is skipped with a warning -- a read never fails because of it.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import logging
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Iterator

from kratos.utils import cancel as _cancel

logger = logging.getLogger(__name__)

DEFAULT_MAX_SESSIONS = 4
_POLL_SECONDS = 0.05


class Busy(Exception):
    """Every slot for the machine stayed taken for the whole wait."""


def max_sessions() -> int:
    """KRATOS_SSH_MAX_SESSIONS (1..10), else DEFAULT_MAX_SESSIONS."""
    try:
        n = int(os.environ.get("KRATOS_SSH_MAX_SESSIONS", DEFAULT_MAX_SESSIONS))
    except ValueError:
        return DEFAULT_MAX_SESSIONS
    return min(10, max(1, n))


def _folder(name: str = "ssh-slots") -> Path | None:
    """A private folder for this user's SSH runtime files, or None when it isn't safe."""
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    folder = Path(base) / f"kratos-{os.getuid()}" / name
    try:
        for p in (folder.parent, folder):
            try:
                os.mkdir(p, 0o700)
            except FileExistsError:
                pass
            st = os.lstat(p)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                logger.warning("ssh slots: %s is not a private folder of this user; no session cap", p)
                return None
    except OSError as e:
        logger.warning("ssh slots: %s unusable (%s); no session cap", folder, e)
        return None
    return folder


CONTROL_PERSIST_SECONDS = 60


def mux_options() -> list[str]:
    """ssh options that reuse one authenticated connection per machine for every session
    (ControlMaster, as Ansible does): one handshake instead of one per read, so a burst of
    checks never piles up unauthenticated connections against sshd's MaxStartups. The
    socket lives in the private folder, named by %C (a hash, short enough for a socket
    path). [] when that folder can't be used -- each session then connects on its own.
    KRATOS_SSH_MUX=off turns it off."""
    if os.environ.get("KRATOS_SSH_MUX", "on").lower() in ("0", "off", "no", "false"):
        return []
    folder = _folder("ssh-mux")
    if folder is None:
        return []
    # ServerAlive: a master whose network went away dies within ~30 s instead of making
    # every later session hang on it until its own timeout.
    return ["-o", "ControlMaster=auto", "-o", f"ControlPath={folder}/%C",
            "-o", f"ControlPersist={CONTROL_PERSIST_SECONDS}",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2"]


def _try_take(folder: Path, host_key: str, n: int) -> int | None:
    for i in range(n):
        try:
            fd = os.open(folder / f"{host_key}.{i}", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError:
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            continue
        return fd
    return None


@contextlib.contextmanager
def slot(host: str, *, wait_seconds: float) -> Iterator[None]:
    """Hold one SSH session slot for `host` while the block runs. Raises Busy after
    `wait_seconds` without a free slot, and cancel.Cancelled if the caller's check is
    cancelled while waiting."""
    folder = _folder()
    if folder is None:
        yield
        return
    host_key = hashlib.sha256(str(host).encode("utf-8", "replace")).hexdigest()[:16]
    deadline = time.monotonic() + max(0.0, wait_seconds)
    fd = _try_take(folder, host_key, max_sessions())
    while fd is None:
        scope = _cancel.current()
        if scope is not None and scope.cancelled:
            raise _cancel.Cancelled("cancelled while waiting for an SSH session slot")
        if time.monotonic() >= deadline:
            raise Busy(f"{max_sessions()} SSH sessions to this machine were busy for {wait_seconds:.0f}s")
        time.sleep(_POLL_SECONDS)
        fd = _try_take(folder, host_key, max_sessions())
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

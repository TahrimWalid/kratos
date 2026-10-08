"""Owner-only SQLite files.

`kratos.db` holds every paired machine's pairing token -- the secret the
signing key for that machine's execution channel is derived from -- plus
investigation transcripts. SQLite creates a new database with the process
umask (usually 0644), so on a shared host any local user could read the
tokens (review v2 F-5).

Every store opens its database through `connect_private`: a missing database
file is created 0600 before SQLite sees it, and an existing one (and its
-wal/-shm/-journal companions) is tightened to 0600. SQLite gives the
-wal/-shm/-journal files it creates the same permissions as the database
file, so once the database is private they are too.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

from kratos.paths import ensure_private_dir

logger = logging.getLogger(__name__)

PRIVATE_MODE = 0o600
COMPANION_SUFFIXES = ("-wal", "-shm", "-journal")
_warned: set[str] = set()


def _tighten(path: Path) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode) or not (st.st_mode & 0o077):
        return
    try:
        os.chmod(path, PRIVATE_MODE)
    except OSError as e:  # e.g. owned by another user: say so once, keep working
        if str(path) not in _warned:
            _warned.add(str(path))
            logger.warning("%s is readable by other users and could not be restricted to owner-only (%s); "
                           "it holds pairing tokens -- fix its permissions (chmod 600)", path, e.strerror or e)


def prepare_private_db(db_path: Path, *, create: bool = True) -> None:
    """Make `db_path` (and its SQLite companions) owner-only. With `create`,
    a missing database file is created empty and 0600 first, and a missing
    folder is created owner-only."""
    db_path = Path(db_path)
    if create:
        ensure_private_dir(db_path.parent)
        try:
            os.close(os.open(db_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, PRIVATE_MODE))
        except FileExistsError:
            pass
    _tighten(db_path)
    for suffix in COMPANION_SUFFIXES:
        _tighten(db_path.with_name(db_path.name + suffix))


def connect_private(db_path: Path | str, *, create: bool = True, **kwargs: Any) -> sqlite3.Connection:
    """`sqlite3.connect` for a database that should be owner-only (a plain
    path; for a read-only `file:` URI call `prepare_private_db(..., create=False)`
    and connect yourself)."""
    prepare_private_db(Path(db_path), create=create)
    return sqlite3.connect(db_path, **kwargs)

"""Per-component schema versions in `kratos.db`.

Each component (the event store, the settings store, ...) owns its tables and
migrates itself when opened: read its version from `schema_versions`, apply the
numbered steps it hasn't applied yet, record the new version -- all in one
`BEGIN IMMEDIATE` transaction, so two processes opening the same database at
once can't both apply a step, and a failing step leaves nothing half-done.

Steps must be idempotent (`CREATE TABLE IF NOT EXISTS`, ...): a database
created before `schema_versions` existed may already hold some of the tables.
"""
from __future__ import annotations

import sqlite3
from typing import Callable, Sequence

from kratos.utils.timeutil import utc_now_iso

Step = Callable[[sqlite3.Connection], None]

_CREATE_VERSIONS = """
CREATE TABLE IF NOT EXISTS schema_versions (
    component TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    updated_at TEXT
)
"""


def schema_version(conn: sqlite3.Connection, component: str) -> int:
    """The component's applied version (0 when it has never been migrated)."""
    conn.execute(_CREATE_VERSIONS)
    row = conn.execute("SELECT version FROM schema_versions WHERE component = ?", (component,)).fetchone()
    return int(row[0]) if row else 0


def migrate(conn: sqlite3.Connection, component: str, steps: Sequence[Step]) -> int:
    """Bring `component` up to `len(steps)`: step N (1-based) moves version N-1 to N.
    Returns the version now applied. A database at a NEWER version than this code
    knows (written by a later Kratos) is left alone rather than downgraded."""
    if conn.in_transaction:
        raise RuntimeError("migrate() needs a connection with no open transaction")
    conn.execute("BEGIN IMMEDIATE")
    try:
        current = schema_version(conn, component)
        for number, step in enumerate(steps, start=1):
            if number > current:
                step(conn)
        target = max(current, len(steps))
        if target != current:
            conn.execute(
                "INSERT INTO schema_versions (component, version, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(component) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at",
                (component, target, utc_now_iso()),
            )
        conn.execute("COMMIT")
        return target
    except BaseException:
        conn.execute("ROLLBACK")
        raise

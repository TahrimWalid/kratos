"""Where users, scopes and the audit trail live -- kratos.db (docs/phaseD/D.7 §3.1, §3.10).

- `users`: one row per Kratos user (id, name, role, disabled, created by/at). The OS account
  that owns the data folder is the **owner** (`user_id = 'owner'`, always admin, never
  disabled); its row is made on first use, so an existing single-owner install keeps
  working with no action from anyone.
- `user_scopes`: the machines and groups (`@web`) each user may see.
- `user_gateway_ids`: a shared Open WebUI's user ids mapped to Kratos users (made by the
  owner; an unmapped id is refused).
- `audit_log`: one row per allowed or refused action. Append-only: a trigger refuses
  UPDATE, and DELETE unless a prune (people-only, itself recorded) has opened a permit.
"""
from __future__ import annotations

import getpass
import sqlite3
import time
from pathlib import Path
from typing import Iterator
import contextlib

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "authz"
OWNER_ID = "owner"


def _owner_name() -> str:
    try:
        name = getpass.getuser()
    except Exception:  # noqa: BLE001 -- containers without a login name
        name = ""
    return (str(name or "").strip() or "owner")[:40]


_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log "
    "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log "
    "WHEN NOT EXISTS (SELECT 1 FROM audit_log_prune_permit) "
    "BEGIN SELECT RAISE(ABORT, 'audit_log rows can only be removed by kratos audit prune'); END",
)


def _guard(conn: sqlite3.Connection) -> None:
    for sql in _TRIGGERS:
        conn.execute(sql)


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          user_id TEXT PRIMARY KEY,            -- 'owner' or 'u_<hex>'
          name TEXT NOT NULL,                  -- shown everywhere; unique, case-insensitive
          role TEXT NOT NULL,                  -- viewer | investigator | admin
          created_at REAL NOT NULL,
          created_by TEXT NOT NULL,
          disabled_at REAL,                    -- set = refused everywhere
          disabled_by TEXT,
          note TEXT
        )
        """
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_name ON users(lower(name))")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_scopes (
          user_id TEXT NOT NULL,
          kind TEXT NOT NULL,                  -- machine | group
          value TEXT NOT NULL,                 -- a machine's name/address (lower case) or a group name
          added_at REAL NOT NULL,
          added_by TEXT NOT NULL,
          PRIMARY KEY (user_id, kind, value)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_gateway_ids (
          provider TEXT NOT NULL,              -- 'openwebui'
          external_id TEXT NOT NULL,           -- the gateway's own user id (the JWT 'sub')
          email TEXT,                          -- shown to the owner only, never trusted
          user_id TEXT NOT NULL,
          added_at REAL NOT NULL,
          added_by TEXT NOT NULL,
          PRIMARY KEY (provider, external_id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY,
          at REAL NOT NULL,
          user_id TEXT,                        -- NULL when no user could be resolved
          user_name TEXT,
          interface TEXT NOT NULL,             -- tui | cli | mcp | serve | schedule
          credential TEXT,                     -- token id, or gateway token + forwarded user
          action TEXT NOT NULL,
          machine TEXT,
          object TEXT,                         -- session, finding key, run id, channel, export, ...
          result TEXT NOT NULL CHECK (result IN ('allowed', 'refused')),
          reason TEXT,
          run_id TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS audit_log_at ON audit_log(at)")
    conn.execute("CREATE INDEX IF NOT EXISTS audit_log_user_at ON audit_log(user_id, at)")
    conn.execute("CREATE TABLE IF NOT EXISTS audit_log_prune_permit (opened_at REAL NOT NULL)")
    _guard(conn)
    conn.execute("INSERT OR IGNORE INTO users (user_id, name, role, created_at, created_by) VALUES (?, ?, 'admin', ?, ?)",
                 (OWNER_ID, _owner_name(), time.time(), "install"))


STEPS = (_step_1,)


def db_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


def connect(data_dir: Path | str) -> sqlite3.Connection:
    path = db_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
        # Someone with write access to the file can drop a trigger; every open puts the
        # append-only guards back (a no-op when they exist).
        _guard(conn)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path | str) -> Iterator[sqlite3.Connection]:
    conn = connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()

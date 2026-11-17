"""What `kratos connect` keeps -- `connect_apps` in kratos.db (docs/phaseE/E.5b §5.1).

One row per connection a person made with `kratos connect <app>`: which app, the token it
made (its id only, never the token), the machines and doors it carries, the secret file
written for the app (relative to the data folder), the chat server's port at the time,
when and by whom. Replacing or undoing a connection marks the row (`replaced_at`) -- the
row is kept as history; at most one live row per app (a partial unique index).
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "connect"


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS connect_apps (
          id INTEGER PRIMARY KEY,
          app TEXT NOT NULL,                  -- openwebui | ag-ui | other
          token_id TEXT NOT NULL,             -- serve_tokens.token_id (never the token)
          machines TEXT NOT NULL,             -- JSON list
          doors TEXT NOT NULL,                -- JSON list
          secret_file TEXT NOT NULL,          -- relative to the data folder (connect/<app>.env|.headers)
          serve_port INTEGER NOT NULL,        -- the chat server's port the app was pointed at
          app_port INTEGER,                   -- Open WebUI's own port (new installs)
          mode TEXT NOT NULL DEFAULT '',      -- openwebui: "new" (Kratos's own Open WebUI) | "existing"
          app_url TEXT,                       -- openwebui: the address the person opens
          created_at REAL NOT NULL,
          created_by TEXT NOT NULL,
          replaced_at REAL,
          replaced_why TEXT
        )
        """
    )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS connect_apps_live ON connect_apps(app) WHERE replaced_at IS NULL")


STEPS = (_step_1,)


def connect(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


def _row(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    d["machines"] = json.loads(d["machines"] or "[]")
    d["doors"] = json.loads(d["doors"] or "[]")
    return d


def live(data_dir: Path, app: str | None = None) -> list[dict[str, Any]]:
    conn = connect(data_dir)
    try:
        if app:
            rows = conn.execute("SELECT * FROM connect_apps WHERE replaced_at IS NULL AND app = ?", (app,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM connect_apps WHERE replaced_at IS NULL ORDER BY app").fetchall()
    finally:
        conn.close()
    return [_row(r) for r in rows]


def record(data_dir: Path, *, app: str, token_id: str, machines: list[str], doors: list[str], secret_file: str,
           serve_port: int, app_port: int | None, created_by: str, replaces: int | None = None,
           mode: str = "", app_url: str | None = None, now: float | None = None) -> int:
    """Insert the new live row (and close the one it replaces) in one transaction. Raises
    sqlite3.IntegrityError when another run made a live row for the app meanwhile."""
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if replaces is not None:
                conn.execute("UPDATE connect_apps SET replaced_at = ?, replaced_why = 'replaced' WHERE id = ? "
                             "AND replaced_at IS NULL", (now, replaces))
            cur = conn.execute(
                "INSERT INTO connect_apps (app, token_id, machines, doors, secret_file, serve_port, app_port, "
                "mode, app_url, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (app, token_id, json.dumps(machines), json.dumps(doors), secret_file, int(serve_port),
                 app_port, mode, app_url, now, created_by))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        return int(cur.lastrowid)
    finally:
        conn.close()


def close(data_dir: Path, row_id: int, why: str, now: float | None = None) -> None:
    conn = connect(data_dir)
    try:
        conn.execute("UPDATE connect_apps SET replaced_at = ?, replaced_why = ? WHERE id = ? AND replaced_at IS NULL",
                     (time.time() if now is None else now, why, int(row_id)))
    finally:
        conn.close()

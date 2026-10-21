"""What the chat server keeps -- in kratos.db (docs/phaseB/B.3 §3.5, §3.13, §3.14).

- `serve_tokens`: one row per client token. Only an scrypt hash of the secret part is
  stored (with its salt and the scrypt parameters), never the token. A token names the
  machines it may investigate (`targets`, empty = the default machine only) and the doors
  it may use (`doors`: "openai", "mcp"). Revoking sets `revoked_at`; nothing is deleted.
- `serve_sessions`: which Kratos session holds a client's chat (token + client chat key).
- `serve_audit`: one row per request -- who (token id, client address, the user name the
  client forwarded, for the record only), what (door, endpoint, model/target, run id), how
  it ended (status, duration, bytes out). Never the message text: that is in the
  session's transcript. Append-only; nothing pruned automatically.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "serve"
AUDIT_STATUSES = ("ok", "refused", "stopped", "error", "budget", "unauthorized", "task")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS serve_tokens (
          token_id TEXT PRIMARY KEY,           -- the public part of krt_<id>_<secret>
          name TEXT NOT NULL,
          secret_hash TEXT NOT NULL,           -- hex scrypt(secret, salt)
          salt TEXT NOT NULL,                  -- hex
          kdf TEXT NOT NULL,                   -- JSON {"name": "scrypt", "n": .., "r": .., "p": .., "dklen": ..}
          targets TEXT NOT NULL,               -- JSON list; [] = the default machine only
          doors TEXT NOT NULL,                 -- JSON list of "openai" / "mcp"
          created_at REAL NOT NULL,
          created_by TEXT NOT NULL,
          revoked_at REAL,
          last_used_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS serve_sessions (
          token_id TEXT NOT NULL,
          client_chat_key TEXT NOT NULL,       -- the client's chat id, or a hash of (token, model, first message)
          session_id TEXT NOT NULL,            -- the Kratos session (sessions table)
          target TEXT NOT NULL,
          created REAL NOT NULL,
          PRIMARY KEY (token_id, client_chat_key, target)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS serve_audit (
          id INTEGER PRIMARY KEY,
          at REAL NOT NULL,
          token_id TEXT,                       -- NULL when no valid token was given
          door TEXT NOT NULL,                  -- openai | mcp
          endpoint TEXT NOT NULL,
          model TEXT,
          target TEXT,
          client_addr TEXT,
          client_user TEXT,                    -- what the client forwarded (record only, never trusted)
          run_id TEXT,
          status TEXT NOT NULL,
          metered INTEGER NOT NULL DEFAULT 0,  -- 1 when this request used the model (the hourly limit counts these)
          duration REAL NOT NULL DEFAULT 0,
          bytes_out INTEGER NOT NULL DEFAULT 0,
          detail TEXT                          -- a short plain reason for a refusal / error
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS serve_audit_token_at ON serve_audit(token_id, at)")
    conn.execute("CREATE INDEX IF NOT EXISTS serve_audit_at ON serve_audit(at)")
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS serve_audit_append_only BEFORE UPDATE ON serve_audit "
        "BEGIN SELECT RAISE(ABORT, 'serve_audit is append-only'); END"
    )


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


# --------------------------------------------------------------------------- tokens
def insert_token(data_dir: Path, row: dict[str, Any]) -> None:
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO serve_tokens (token_id, name, secret_hash, salt, kdf, targets, doors, created_at, "
            "created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["token_id"], row["name"], row["secret_hash"], row["salt"], json.dumps(row["kdf"]),
             json.dumps(row["targets"]), json.dumps(row["doors"]), row["created_at"], row["created_by"]),
        )
        conn.execute("COMMIT")
    finally:
        conn.close()


def _token_dict(r: sqlite3.Row) -> dict[str, Any]:
    return {"token_id": r["token_id"], "name": r["name"], "secret_hash": r["secret_hash"], "salt": r["salt"],
            "kdf": json.loads(r["kdf"]), "targets": json.loads(r["targets"]), "doors": json.loads(r["doors"]),
            "created_at": float(r["created_at"]), "created_by": r["created_by"],
            "revoked_at": r["revoked_at"], "last_used_at": r["last_used_at"]}


def get_token(data_dir: Path, token_id: str) -> dict[str, Any] | None:
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT * FROM serve_tokens WHERE token_id = ?", (token_id,)).fetchone()
    finally:
        conn.close()
    return _token_dict(r) if r is not None else None


def list_tokens(data_dir: Path) -> list[dict[str, Any]]:
    conn = connect(data_dir)
    try:
        rows = conn.execute("SELECT * FROM serve_tokens ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return [_token_dict(r) for r in rows]


def name_in_use(data_dir: Path, name: str) -> bool:
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT 1 FROM serve_tokens WHERE name = ? AND revoked_at IS NULL", (name,)).fetchone()
    finally:
        conn.close()
    return r is not None


def revoke_token(data_dir: Path, token_id: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute("UPDATE serve_tokens SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL",
                           (now, token_id))
        conn.execute("COMMIT")
        return cur.rowcount > 0
    finally:
        conn.close()


def touch_token(data_dir: Path, token_id: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute("UPDATE serve_tokens SET last_used_at = ? WHERE token_id = ?", (now, token_id))
    finally:
        conn.close()


# --------------------------------------------------------------------------- sessions
def session_for(data_dir: Path, token_id: str, chat_key: str, target: str) -> str | None:
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT session_id FROM serve_sessions WHERE token_id = ? AND client_chat_key = ? "
                         "AND target = ?", (token_id, chat_key, target)).fetchone()
    finally:
        conn.close()
    return r["session_id"] if r is not None else None


def remember_session(data_dir: Path, token_id: str, chat_key: str, target: str, session_id: str,
                     now: float | None = None) -> str:
    """Record the client chat -> Kratos session pairing; if another request for the same
    chat won the race, return ITS session (so one chat never splits into two)."""
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT OR IGNORE INTO serve_sessions (token_id, client_chat_key, session_id, target, created) "
                     "VALUES (?, ?, ?, ?, ?)", (token_id, chat_key, session_id, target, now))
        r = conn.execute("SELECT session_id FROM serve_sessions WHERE token_id = ? AND client_chat_key = ? "
                         "AND target = ?", (token_id, chat_key, target)).fetchone()
        conn.execute("COMMIT")
        return r["session_id"]
    finally:
        conn.close()


def sessions_with_prefix(data_dir: Path, token_id: str, prefix: str) -> list[dict[str, Any]]:
    """This token's client-chat rows whose key starts with `prefix`, newest first."""
    conn = connect(data_dir)
    try:
        rows = conn.execute("SELECT * FROM serve_sessions WHERE token_id = ? AND substr(client_chat_key, 1, ?) = ? "
                            "ORDER BY created DESC", (token_id, len(prefix), prefix)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def sessions_of_token(data_dir: Path, token_id: str) -> list[str]:
    conn = connect(data_dir)
    try:
        rows = conn.execute("SELECT session_id FROM serve_sessions WHERE token_id = ?", (token_id,)).fetchall()
    finally:
        conn.close()
    return [r["session_id"] for r in rows]


# --------------------------------------------------------------------------- audit
def audit(data_dir: Path, *, door: str, endpoint: str, status: str, token_id: str | None = None,
          model: str | None = None, target: str | None = None, client_addr: str | None = None,
          client_user: str | None = None, run_id: str | None = None, metered: bool = False,
          duration: float = 0.0, bytes_out: int = 0, detail: str | None = None,
          now: float | None = None) -> None:
    if status not in AUDIT_STATUSES:
        raise ValueError(f"unknown audit status {status!r}")
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute(
            "INSERT INTO serve_audit (at, token_id, door, endpoint, model, target, client_addr, client_user, "
            "run_id, status, metered, duration, bytes_out, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now, token_id, door, endpoint[:120], (model or None) and str(model)[:200], target, client_addr,
             (client_user or None) and str(client_user)[:200], run_id, status, 1 if metered else 0,
             float(duration), int(bytes_out), (detail or None) and str(detail)[:300]),
        )
    finally:
        conn.close()


def metered_requests_since(data_dir: Path, token_id: str, since: float) -> int:
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT COUNT(*) AS n FROM serve_audit WHERE token_id = ? AND metered = 1 AND at >= ?",
                         (token_id, since)).fetchone()
    finally:
        conn.close()
    return int(r["n"])


def recent_audit(data_dir: Path, limit: int = 50) -> list[dict[str, Any]]:
    conn = connect(data_dir)
    try:
        rows = conn.execute("SELECT * FROM serve_audit ORDER BY at DESC, id DESC LIMIT ?", (int(limit),)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]

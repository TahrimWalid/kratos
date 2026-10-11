"""What the tamper checks remember between runs, in kratos.db (0.3).

- `log_file_state`: one row per tracked log file per machine -- the inode,
  size, mtime and hash of the first 4 KiB seen at the last check, and the same
  facts for its first rotation (rename and copytruncate rotations are told
  apart from truncation/replacement by comparing with these). Rows whose
  `path` starts with "@" hold other remembered state as JSON in `extra`
  (e.g. "@auditd": whether auditd was running with rules last time).
- `seal_verifications`: one row per journal file verification (append-only):
  its name, sha256, whether it was archived and sealed, and the result.

Nothing is deleted automatically (owner decision 5). Targets are stored as
target_key(); times as epoch seconds (UTC).
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

COMPONENT = "logsources"
RESULTS = ("pass", "fail", "unsealed", "error", "skipped_unchanged")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS log_file_state (
          target TEXT NOT NULL,
          path TEXT NOT NULL,
          inode INTEGER, size INTEGER, mtime REAL, head_hash TEXT, status TEXT,
          rot_path TEXT, rot_inode INTEGER, rot_size INTEGER, rot_mtime REAL,
          extra TEXT,
          checked_at REAL NOT NULL,
          PRIMARY KEY (target, path)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seal_verifications (
          id INTEGER PRIMARY KEY,
          target TEXT NOT NULL,
          file_name TEXT NOT NULL,
          sha256 TEXT,
          size INTEGER,
          archived INTEGER NOT NULL,
          sealed INTEGER,
          result TEXT NOT NULL,
          detail TEXT,
          verified_at REAL NOT NULL,
          run_id TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS seal_verifications_file ON seal_verifications(target, file_name, verified_at)")
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS seal_verifications_append_only BEFORE UPDATE ON seal_verifications "
        "BEGIN SELECT RAISE(ABORT, 'seal_verifications is append-only'); END"
    )


STEPS = (_step_1,)


def _connect(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path) -> Iterator[sqlite3.Connection]:
    conn = _connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


_FILE_COLS = ("path", "inode", "size", "mtime", "head_hash", "status", "rot_path", "rot_inode", "rot_size",
              "rot_mtime", "checked_at")


def file_states(data_dir: Path, target: str) -> dict[str, dict[str, Any]]:
    """{path: previous state} for one machine (paths starting with "@" excluded)."""
    with opened(data_dir) as conn:
        rows = conn.execute(f"SELECT {', '.join(_FILE_COLS)} FROM log_file_state WHERE target = ? "
                            "AND path NOT LIKE '@%'", (target_key(target),)).fetchall()
    return {r[0]: dict(zip(_FILE_COLS, r)) for r in rows}


def save_file_states(data_dir: Path, target: str, states: list[dict[str, Any]], checked_at: float | None = None) -> None:
    """Replace the remembered state of these files (one transaction)."""
    when = time.time() if checked_at is None else checked_at
    tk = target_key(target)
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for s in states:
                conn.execute(
                    "INSERT INTO log_file_state (target, path, inode, size, mtime, head_hash, status, rot_path, "
                    "rot_inode, rot_size, rot_mtime, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(target, path) DO UPDATE SET inode = excluded.inode, size = excluded.size, "
                    "mtime = excluded.mtime, head_hash = excluded.head_hash, status = excluded.status, "
                    "rot_path = excluded.rot_path, rot_inode = excluded.rot_inode, rot_size = excluded.rot_size, "
                    "rot_mtime = excluded.rot_mtime, checked_at = excluded.checked_at",
                    (tk, s["path"], s.get("inode"), s.get("size"), s.get("mtime"), s.get("head_hash"), s.get("status"),
                     s.get("rot_path"), s.get("rot_inode"), s.get("rot_size"), s.get("rot_mtime"), when))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def get_extra(data_dir: Path, target: str, key: str) -> dict[str, Any] | None:
    with opened(data_dir) as conn:
        row = conn.execute("SELECT extra, checked_at FROM log_file_state WHERE target = ? AND path = ?",
                           (target_key(target), "@" + key)).fetchone()
    if not row or not row[0]:
        return None
    try:
        data = json.loads(row[0])
    except ValueError:
        return None
    return {**data, "_checked_at": row[1]} if isinstance(data, dict) else None


def put_extra(data_dir: Path, target: str, key: str, value: dict[str, Any]) -> None:
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO log_file_state (target, path, extra, checked_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(target, path) DO UPDATE SET extra = excluded.extra, checked_at = excluded.checked_at",
                (target_key(target), "@" + key, json.dumps(value, sort_keys=True), time.time()))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def add_verification(data_dir: Path, target: str, *, file_name: str, sha256: str | None, size: int | None,
                     archived: bool, sealed: bool | None, result: str, detail: str = "",
                     run_id: str | None = None) -> None:
    if result not in RESULTS:
        raise ValueError(f"unknown result {result!r}")
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("INSERT INTO seal_verifications (target, file_name, sha256, size, archived, sealed, result, "
                         "detail, verified_at, run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (target_key(target), file_name, sha256, size, int(bool(archived)),
                          None if sealed is None else int(bool(sealed)), result, detail[:2000], time.time(), run_id))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


_VER_COLS = ("file_name", "sha256", "size", "archived", "sealed", "result", "detail", "verified_at", "run_id")


def verified_archives(data_dir: Path, target: str) -> dict[str, dict[str, Any]]:
    """The last PASSING verification of each archived file: {name: row}."""
    with opened(data_dir) as conn:
        rows = conn.execute(
            f"SELECT {', '.join(_VER_COLS)} FROM seal_verifications WHERE target = ? AND archived = 1 "
            "AND result = 'pass' ORDER BY verified_at", (target_key(target),)).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        out[r[0]] = dict(zip(_VER_COLS, r))
    return out


def verifications(data_dir: Path, target: str, limit: int = 200) -> list[dict[str, Any]]:
    with opened(data_dir) as conn:
        rows = conn.execute(f"SELECT {', '.join(_VER_COLS)} FROM seal_verifications WHERE target = ? "
                            "ORDER BY verified_at DESC, id DESC LIMIT ?", (target_key(target), int(limit))).fetchall()
    return [dict(zip(_VER_COLS, r)) for r in rows]

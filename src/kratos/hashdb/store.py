"""`hash_reputation`: the reputation Kratos last decided for each (machine, SHA-256).

One row per distinct file content seen on a machine (target_key, sha256), replaced when
it is looked up again. A person's online lookup of one hash (kratos.hashdb.lookup) is
cached under target_key '' with source "online" and its date. Listed in the data
inventory (category `hash_reputation`, backed up); nothing deletes rows on its own.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store, write_transaction

COMPONENT = "hash_reputation"
ONLINE = ""                       # the target_key of a person's online lookups


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hash_reputation (
          target_key TEXT NOT NULL,       -- the machine ('' for a person's online lookup)
          sha256 TEXT NOT NULL,
          sha1 TEXT,                      -- only for the known-good lookup, never an identity
          verdict TEXT NOT NULL,          -- known_bad | package_modified | package | known_good | unknown | not_checked
          sources TEXT NOT NULL,          -- JSON [{source, detail, date}]
          checked_at REAL NOT NULL,       -- epoch UTC
          path_seen TEXT,                 -- the path it was last seen at on this machine
          note TEXT NOT NULL DEFAULT '',
          PRIMARY KEY (target_key, sha256)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS hash_reputation_sha256 ON hash_reputation(sha256)")


STEPS = (_step_1,)


def connect(data_dir: Path | str) -> sqlite3.Connection:
    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


def put_many(data_dir: Path | str, target_key: str, rows: list[dict[str, Any]], *, at: float | None = None) -> int:
    """rows: [{sha256, sha1, verdict, sources, path, note}] (rows without a sha256 are skipped)."""
    at = time.time() if at is None else at
    vals = [(target_key, str(r["sha256"]).lower(), r.get("sha1"), r["verdict"], json.dumps(r.get("sources") or []),
             at, r.get("path"), str(r.get("note") or "")[:500]) for r in rows if r.get("sha256")]
    if not vals:
        return 0
    conn = connect(data_dir)
    try:
        with write_transaction(conn):
            conn.executemany(
                "INSERT INTO hash_reputation (target_key, sha256, sha1, verdict, sources, checked_at, path_seen, note) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(target_key, sha256) DO UPDATE SET sha1=excluded.sha1, "
                "verdict=excluded.verdict, sources=excluded.sources, checked_at=excluded.checked_at, "
                "path_seen=excluded.path_seen, note=excluded.note", vals)
    finally:
        conn.close()
    return len(vals)


def lookup(data_dir: Path | str, sha256: str) -> list[dict[str, Any]]:
    """Every row for one hash: each machine it was seen on, and a cached online lookup."""
    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return []
    conn = connect(data_dir)
    try:
        rows = conn.execute("SELECT target_key, sha256, sha1, verdict, sources, checked_at, path_seen, note "
                            "FROM hash_reputation WHERE sha256 = ? ORDER BY checked_at DESC",
                            (str(sha256).lower(),)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        try:
            sources = json.loads(r[4] or "[]")
        except ValueError:
            sources = []
        out.append({"target_key": r[0], "sha256": r[1], "sha1": r[2], "verdict": r[3], "sources": sources,
                    "checked_at": r[5], "path": r[6], "note": r[7]})
    return out

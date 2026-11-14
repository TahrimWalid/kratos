"""Code-root tables in kratos.db (E.7a §5.1).

- ``code_roots``        one row per (machine, folder): candidate | confirmed | ignored, why it was
                        offered (JSON reasons), which listeners serve it, who decided and when, the
                        last time a person accepted its current state (a deploy without git).
- ``code_root_events``  append-only trail: offered, confirmed, ignored, added, accepted_state,
                        gone, back -- with the actor. A trigger refuses UPDATE and DELETE.
- ``code_files``        per confirmed root, the latest inventory (`kind` = current) and the
                        accepted baseline (`kind` = baseline): path relative to the root, size,
                        mode, SHA-256, git blob id, git status. The current rows are REPLACED by
                        every complete read (a snapshot, not history); baseline rows are replaced
                        only when a person accepts a state (or on the root's first read).
- ``code_deps``         per confirmed root, the dependencies its lockfiles and installed metadata
                        name (ecosystem, package, version, where); replaced per read.

Keyed by ``target_key``. File CONTENTS are never stored here or anywhere: only hashes,
paths and findings. Inventoried (B.5) with backup class `include`.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store, write_transaction

COMPONENT = "code"
TABLES = ("code_roots", "code_root_events", "code_files", "code_deps")
STATUSES = ("candidate", "confirmed", "ignored", "stale")
EVENT_KINDS = ("offered", "confirmed", "ignored", "unignored", "added", "accepted_state", "gone", "back",
               "no_longer_offered")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS code_roots (
          id INTEGER PRIMARY KEY,
          target_key TEXT NOT NULL,
          path TEXT NOT NULL,
          status TEXT NOT NULL,                 -- candidate | confirmed | ignored | stale (no longer offered)
          why TEXT NOT NULL DEFAULT '[]',       -- JSON [{kind, detail}] -- Kratos's words
          serving TEXT NOT NULL DEFAULT '[]',   -- JSON [{pid, exe, address, port, via}]
          source TEXT NOT NULL,                 -- discovered | person
          first_seen REAL NOT NULL,
          last_offered REAL,                    -- the last discovery that offered it
          decided_by TEXT,
          decided_at REAL,
          accepted_at REAL,                     -- the last time a person accepted its state
          gone_since REAL,                      -- the folder was not there at the last read
          UNIQUE (target_key, path)
        )
        """)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS code_root_events (
          id INTEGER PRIMARY KEY,
          root_id INTEGER NOT NULL,
          target_key TEXT NOT NULL,
          path TEXT NOT NULL,
          at REAL NOT NULL,
          kind TEXT NOT NULL,
          actor TEXT,
          interface TEXT,
          user_id TEXT,
          detail TEXT NOT NULL DEFAULT ''
        )
        """)
    conn.execute("CREATE INDEX IF NOT EXISTS code_root_events_root ON code_root_events(root_id, at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS code_files (
          root_id INTEGER NOT NULL,
          kind TEXT NOT NULL,                   -- current | baseline
          relpath TEXT NOT NULL,
          size INTEGER,
          mode TEXT,
          sha256 TEXT,
          blob TEXT,
          git_status TEXT,                      -- tracked | modified | untracked | ignored | staged | ... | -
          mtime INTEGER,
          read_at REAL NOT NULL,
          PRIMARY KEY (root_id, kind, relpath)
        )
        """)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS code_deps (
          root_id INTEGER NOT NULL,
          ecosystem TEXT NOT NULL,
          package TEXT NOT NULL,
          version TEXT NOT NULL,
          source_file TEXT NOT NULL,
          installed INTEGER NOT NULL DEFAULT 0,
          read_at REAL NOT NULL,
          PRIMARY KEY (root_id, ecosystem, package, version, source_file)
        )
        """)


def _step_2(conn: sqlite3.Connection) -> None:
    for verb in ("UPDATE", "DELETE"):
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS code_root_events_no_{verb.lower()} BEFORE {verb} ON "
                     f"code_root_events BEGIN SELECT RAISE(ABORT, 'code_root_events is append-only'); END")


STEPS = (_step_1, _step_2)


def connect(data_dir: Path | str) -> sqlite3.Connection:
    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, COMPONENT, STEPS)
        _step_2(conn)                      # the append-only guard is re-made on every open
    except BaseException:
        conn.close()
        raise
    conn.row_factory = sqlite3.Row
    return conn


_tx = write_transaction        # one transaction per multi-row write (see its docstring)


def _root(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for k in ("why", "serving"):
        try:
            d[k] = json.loads(d.get(k) or "[]")
        except ValueError:
            d[k] = []
    return d


def roots(data_dir: Path | str, target_key: str, *, status: str | None = None) -> list[dict[str, Any]]:
    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return []
    conn = connect(data_dir)
    try:
        q = "SELECT * FROM code_roots WHERE target_key = ?"
        args: list[Any] = [target_key]
        if status:
            q += " AND status = ?"
            args.append(status)
        return [_root(r) for r in conn.execute(q + " ORDER BY path", args)]
    finally:
        conn.close()


def all_roots(data_dir: Path | str, *, status: str | None = None) -> list[dict[str, Any]]:
    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return []
    conn = connect(data_dir)
    try:
        q, args = "SELECT * FROM code_roots", []
        if status:
            q += " WHERE status = ?"
            args.append(status)
        return [_root(r) for r in conn.execute(q + " ORDER BY target_key, path", args)]
    finally:
        conn.close()


def get_root(data_dir: Path | str, root_id: int) -> dict[str, Any] | None:
    conn = connect(data_dir)
    try:
        row = conn.execute("SELECT * FROM code_roots WHERE id = ?", (int(root_id),)).fetchone()
        return _root(row) if row else None
    finally:
        conn.close()


def event(conn: sqlite3.Connection, root: dict[str, Any], kind: str, *, actor: Any = None, detail: str = "",
          at: float | None = None) -> None:
    if kind not in EVENT_KINDS:
        raise ValueError(kind)
    conn.execute("INSERT INTO code_root_events (root_id, target_key, path, at, kind, actor, interface, user_id, "
                 "detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (root["id"], root["target_key"], root["path"], time.time() if at is None else at, kind,
                  getattr(actor, "user", None), getattr(actor, "interface", None), getattr(actor, "user_id", None),
                  str(detail)[:500]))


def offer(data_dir: Path | str, target_key: str, candidates: Iterable[dict[str, Any]], *,
          now: float | None = None) -> list[dict[str, Any]]:
    """Record what discovery offered: new folders become candidates (an `offered` event);
    known ones keep their status (a person's ignore stays) and get their reasons refreshed."""
    now = time.time() if now is None else now
    candidates = list(candidates)
    offered = {c["path"] for c in candidates}
    conn = connect(data_dir)
    try:
        with _tx(conn):
            # a candidate discovery no longer offers stops asking for a decision (never read either way)
            for row in conn.execute("SELECT * FROM code_roots WHERE target_key = ? AND status = 'candidate'",
                                    (target_key,)).fetchall():
                if row["path"] not in offered:
                    conn.execute("UPDATE code_roots SET status = 'stale' WHERE id = ?", (row["id"],))
                    event(conn, dict(row), "no_longer_offered", at=now)
            for c in candidates:
                row = conn.execute("SELECT * FROM code_roots WHERE target_key = ? AND path = ?",
                                   (target_key, c["path"])).fetchone()
                why = json.dumps(c.get("why") or [])
                serving = json.dumps(c.get("serving") or [])
                if row is None:
                    cur = conn.execute(
                        "INSERT INTO code_roots (target_key, path, status, why, serving, source, first_seen, "
                        "last_offered) VALUES (?, ?, 'candidate', ?, ?, 'discovered', ?, ?)",
                        (target_key, c["path"], why, serving, now, now))
                    event(conn, {"id": cur.lastrowid, "target_key": target_key, "path": c["path"]}, "offered",
                          at=now, detail="; ".join(str(w.get("detail")) for w in c.get("why") or [])[:400])
                else:
                    status = "candidate" if row["status"] == "stale" else row["status"]
                    conn.execute("UPDATE code_roots SET why = ?, serving = ?, last_offered = ?, status = ? WHERE id = ?",
                                 (why, serving, now, status, row["id"]))
                    if row["status"] == "stale":
                        event(conn, dict(row), "offered", at=now, detail="offered again")
        return roots(data_dir, target_key)
    finally:
        conn.close()


def decide(data_dir: Path | str, target_key: str, path: str, status: str, *, actor: Any, source: str,
           kind: str, detail: str = "", now: float | None = None) -> dict[str, Any]:
    """Set a root's status (the caller checked the person); inserts it when it is new."""
    if status not in STATUSES:
        raise ValueError(status)
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        with _tx(conn):
            row = conn.execute("SELECT * FROM code_roots WHERE target_key = ? AND path = ?",
                               (target_key, path)).fetchone()
            who = getattr(actor, "user", None)
            if row is None:
                cur = conn.execute(
                    "INSERT INTO code_roots (target_key, path, status, why, source, first_seen, decided_by, "
                    "decided_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (target_key, path, status, json.dumps([{"kind": "person", "detail": "added by a person"}]),
                     source, now, who, now))
                rid = cur.lastrowid
            else:
                rid = row["id"]
                conn.execute("UPDATE code_roots SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
                             (status, who, now, rid))
            event(conn, {"id": rid, "target_key": target_key, "path": path}, kind, actor=actor, detail=detail,
                  at=now)
            return _root(conn.execute("SELECT * FROM code_roots WHERE id = ?", (rid,)).fetchone())
    finally:
        conn.close()


def mark_gone(data_dir: Path | str, root: dict[str, Any], gone: bool, *, now: float | None = None) -> None:
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        with _tx(conn):
            if gone and root.get("gone_since") is None:
                conn.execute("UPDATE code_roots SET gone_since = ? WHERE id = ?", (now, root["id"]))
                event(conn, root, "gone", at=now)
            elif not gone and root.get("gone_since") is not None:
                conn.execute("UPDATE code_roots SET gone_since = NULL WHERE id = ?", (root["id"],))
                event(conn, root, "back", at=now)
    finally:
        conn.close()


def events(data_dir: Path | str, root_id: int) -> list[dict[str, Any]]:
    conn = connect(data_dir)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM code_root_events WHERE root_id = ? ORDER BY at, id",
                                              (int(root_id),))]
    finally:
        conn.close()


# --------------------------------------------------------------------------- files and deps
def replace_files(data_dir: Path | str, root_id: int, kind: str, rows: list[dict[str, Any]], *,
                  at: float | None = None) -> None:
    """Replace one root's `kind` rows (current: every complete read; baseline: the first read
    or a person's accept). The replaced rows are a snapshot, not history (E.7a §5.1)."""
    if kind not in ("current", "baseline"):
        raise ValueError(kind)
    at = time.time() if at is None else at
    conn = connect(data_dir)
    try:
        with _tx(conn):
            # snapshot replaced by the newer read of the same root (spec: "replaced per read")
            conn.execute("DELETE FROM code_files WHERE root_id = ? AND kind = ?", (int(root_id), kind))
            conn.executemany(
                "INSERT INTO code_files (root_id, kind, relpath, size, mode, sha256, blob, git_status, mtime, read_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [(int(root_id), kind, r["relpath"], r.get("size"), r.get("mode"), r.get("sha256"), r.get("blob"),
                  r.get("git_status") or "-", r.get("mtime"), at) for r in rows])
    finally:
        conn.close()


def files(data_dir: Path | str, root_id: int, kind: str = "current") -> dict[str, dict[str, Any]]:
    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return {}
    conn = connect(data_dir)
    try:
        return {r["relpath"]: dict(r) for r in conn.execute(
            "SELECT * FROM code_files WHERE root_id = ? AND kind = ?", (int(root_id), kind))}
    finally:
        conn.close()


def has_baseline(data_dir: Path | str, root_id: int) -> bool:
    conn = connect(data_dir)
    try:
        return conn.execute("SELECT 1 FROM code_files WHERE root_id = ? AND kind = 'baseline' LIMIT 1",
                            (int(root_id),)).fetchone() is not None
    finally:
        conn.close()


def set_accepted(data_dir: Path | str, root: dict[str, Any], *, actor: Any, now: float | None = None,
                 detail: str = "") -> None:
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.execute("UPDATE code_roots SET accepted_at = ? WHERE id = ?", (now, root["id"]))
            event(conn, root, "accepted_state", actor=actor, at=now, detail=detail)
    finally:
        conn.close()


def replace_deps(data_dir: Path | str, root_id: int, rows: list[dict[str, Any]], *, at: float | None = None) -> None:
    at = time.time() if at is None else at
    conn = connect(data_dir)
    try:
        with _tx(conn):
            # snapshot replaced by the newer read of the same root (spec: "replaced per read")
            conn.execute("DELETE FROM code_deps WHERE root_id = ?", (int(root_id),))
            conn.executemany(
                "INSERT OR IGNORE INTO code_deps (root_id, ecosystem, package, version, source_file, installed, "
                "read_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(int(root_id), r["ecosystem"], r["package"], r["version"], r["source_file"],
                  1 if r.get("installed") else 0, at) for r in rows])
    finally:
        conn.close()


def deps(data_dir: Path | str, root_id: int) -> list[dict[str, Any]]:
    conn = connect(data_dir)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM code_deps WHERE root_id = ? ORDER BY ecosystem, "
                                              "package, version", (int(root_id),))]
    finally:
        conn.close()


def ecosystems_seen(data_dir: Path | str) -> list[str]:
    """Every language ecosystem a CONFIRMED root's dependencies name (for vulndb-update)."""
    db = Path(data_dir) / "kratos.db"
    if not db.exists():
        return []
    conn = connect(data_dir)
    try:
        return [r[0] for r in conn.execute(
            "SELECT DISTINCT d.ecosystem FROM code_deps d JOIN code_roots r ON r.id = d.root_id "
            "WHERE r.status = 'confirmed' ORDER BY 1")]
    finally:
        conn.close()

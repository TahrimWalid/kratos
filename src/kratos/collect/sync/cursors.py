"""Where each synced log source left off, and which time spans the event store holds
COMPLETELY. Both live in `kratos.db` on this host; nothing is written on a monitored
machine.

`sync_cursors`: one row per (machine, source, kind). kind `journal` -> `position` is the
journal cursor; kind `file:<n>` -> `position` is a byte offset into catalog file n, and
`inode` says which file that offset belongs to.

`sync_coverage`: spans [start_ts, end_ts] (UTC epoch). `complete=1` means every matching
line in the span is in the store; `complete=0` is a recorded gap (a vacuumed journal, a
truncated or lost file). Adjacent complete spans are merged, so a gap keeps the spans on
either side apart -- `covered()` is true only for a window with no hole in it.
"""
from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "collect_sync"
MERGE_SLACK_SECONDS = 1.0       # spans closer than this are one span


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_cursors (
            target TEXT NOT NULL,            -- target_key
            source TEXT NOT NULL,            -- catalog sync source (auth, cron, ...)
            kind TEXT NOT NULL,              -- journal | file:<n>
            position TEXT,                   -- journal cursor, or a byte offset
            seqnum_id TEXT,                  -- the cursor's s= part (journal)
            inode INTEGER,                   -- the file the offset belongs to (files)
            updated_at REAL,
            last_ts REAL,                    -- time of the last line handled (UTC epoch)
            behind INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (target, source, kind)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_coverage (
            id INTEGER PRIMARY KEY,
            target TEXT NOT NULL,
            source TEXT NOT NULL,
            start_ts REAL NOT NULL,
            end_ts REAL NOT NULL,
            complete INTEGER NOT NULL,       -- 1: every line in the span is stored; 0: a recorded gap
            recorded_at REAL NOT NULL,
            note TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS sync_coverage_ts ON sync_coverage(target, source, start_ts)")


_STEPS = (_step_1,)


def connect(data_dir: Path) -> sqlite3.Connection:
    db_path = Path(data_dir) / "kratos.db"
    conn = connect_store(db_path)
    try:
        migrate_once(conn, db_path, COMPONENT, _STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@dataclass
class Cursor:
    target: str
    source: str
    kind: str
    position: str | None
    seqnum_id: str | None
    inode: int | None
    updated_at: float | None
    last_ts: float | None
    behind: bool

    @property
    def offset(self) -> int:
        try:
            return int(self.position or 0)
        except ValueError:
            return 0


def get_cursor(data_dir: Path, target: str, source: str, kind: str) -> Cursor | None:
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT * FROM sync_cursors WHERE target = ? AND source = ? AND kind = ?",
                         (target, source, kind)).fetchone()
    finally:
        conn.close()
    if r is None:
        return None
    return Cursor(r["target"], r["source"], r["kind"], r["position"], r["seqnum_id"], r["inode"], r["updated_at"],
                  r["last_ts"], bool(r["behind"]))


def cursors(data_dir: Path, target: str | None = None) -> list[Cursor]:
    conn = connect(data_dir)
    try:
        rows = (conn.execute("SELECT * FROM sync_cursors ORDER BY target, source, kind").fetchall() if target is None
                else conn.execute("SELECT * FROM sync_cursors WHERE target = ? ORDER BY source, kind",
                                  (target,)).fetchall())
    finally:
        conn.close()
    return [Cursor(r["target"], r["source"], r["kind"], r["position"], r["seqnum_id"], r["inode"], r["updated_at"],
                   r["last_ts"], bool(r["behind"])) for r in rows]


def put_cursor(data_dir: Path, target: str, source: str, kind: str, *, position: str | None,
               seqnum_id: str | None = None, inode: int | None = None, last_ts: float | None = None,
               behind: bool = False) -> None:
    conn = connect(data_dir)
    try:
        conn.execute(
            "INSERT INTO sync_cursors (target, source, kind, position, seqnum_id, inode, updated_at, last_ts, behind) "
            "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(target, source, kind) DO UPDATE SET position=excluded.position, "
            "seqnum_id=excluded.seqnum_id, inode=excluded.inode, updated_at=excluded.updated_at, "
            "last_ts=excluded.last_ts, behind=excluded.behind",
            (target, source, kind, position, seqnum_id, inode, time.time(), last_ts, 1 if behind else 0))
    finally:
        conn.close()


def delete_cursors(data_dir: Path, target: str, source: str) -> None:
    conn = connect(data_dir)
    try:
        conn.execute("DELETE FROM sync_cursors WHERE target = ? AND source = ?", (target, source))
    finally:
        conn.close()


def add_span(data_dir: Path, target: str, source: str, start: float, end: float, *, complete: bool,
             note: str = "") -> None:
    """Record a span. A complete span is merged with every complete span it touches or
    overlaps; an incomplete one (a gap) is stored as its own row."""
    if end < start:
        start, end = end, start
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if complete:
                rows = conn.execute(
                    "SELECT id, start_ts, end_ts FROM sync_coverage WHERE target = ? AND source = ? AND complete = 1 "
                    "AND end_ts >= ? AND start_ts <= ?", (target, source, start - MERGE_SLACK_SECONDS,
                                                          end + MERGE_SLACK_SECONDS)).fetchall()
                for r in rows:
                    start, end = min(start, r["start_ts"]), max(end, r["end_ts"])
                if rows:
                    conn.execute(f"DELETE FROM sync_coverage WHERE id IN ({','.join('?' * len(rows))})",
                                 [r["id"] for r in rows])
            conn.execute("INSERT INTO sync_coverage (target, source, start_ts, end_ts, complete, recorded_at, note) "
                         "VALUES (?,?,?,?,?,?,?)", (target, source, start, end, 1 if complete else 0, time.time(), note))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


@dataclass
class Span:
    start: float
    end: float
    complete: bool
    note: str = ""


def spans(data_dir: Path, target: str, source: str | None = None) -> list[tuple[str, Span]]:
    conn = connect(data_dir)
    try:
        if source is None:
            rows = conn.execute("SELECT * FROM sync_coverage WHERE target = ? ORDER BY source, start_ts",
                                (target,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM sync_coverage WHERE target = ? AND source = ? ORDER BY start_ts",
                                (target, source)).fetchall()
    finally:
        conn.close()
    return [(r["source"], Span(r["start_ts"], r["end_ts"], bool(r["complete"]), r["note"] or "")) for r in rows]


def covered(data_dir: Path, target: str, source: str, start: float, end: float) -> bool:
    """True when the store holds every matching line of `source` on `target` between
    `start` and `end`: complete spans cover the whole window with no hole."""
    if end < start:
        start, end = end, start
    conn = connect(data_dir)
    try:
        rows = conn.execute(
            "SELECT start_ts, end_ts FROM sync_coverage WHERE target = ? AND source = ? AND complete = 1 "
            "AND end_ts >= ? AND start_ts <= ? ORDER BY start_ts",
            (target, source, start - MERGE_SLACK_SECONDS, end + MERGE_SLACK_SECONDS)).fetchall()
    finally:
        conn.close()
    reach = start
    for r in rows:
        if r["start_ts"] > reach + MERGE_SLACK_SECONDS:
            return False
        reach = max(reach, r["end_ts"])
        if reach >= end - MERGE_SLACK_SECONDS:
            return True
    return reach >= end - MERGE_SLACK_SECONDS


def held(data_dir: Path, target: str, source: str, start: float, end: float) -> tuple[float, float | None]:
    """(seconds of [start, end] the store holds `source` completely, the earliest such moment or
    None) -- complete spans merged, holes not counted. Never more than end - start."""
    if end < start:
        start, end = end, start
    conn = connect(data_dir)
    try:
        rows = conn.execute(
            "SELECT start_ts, end_ts FROM sync_coverage WHERE target = ? AND source = ? AND complete = 1 "
            "AND end_ts >= ? AND start_ts <= ? ORDER BY start_ts", (target, source, start, end)).fetchall()
    finally:
        conn.close()
    total, reach, first = 0.0, start, None
    for r in rows:
        lo, hi = max(start, float(r["start_ts"]), reach), min(end, float(r["end_ts"]))
        if hi > lo:
            total += hi - lo
            first = lo if first is None else first
            reach = hi
    return total, first

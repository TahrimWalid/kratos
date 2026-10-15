"""`collect_state`: the last result of each check on each machine, and who is running it.

One row per (machine, check), in `kratos.db` on THIS host -- nothing is written on a
monitored machine. Three jobs:

* freshness: a result younger than its limit is reused instead of re-run;
* claims: two processes (the TUI and a schedule, say) must not run the same check on
  the same machine at once -- a claim is taken inside `BEGIN IMMEDIATE`; a claim older
  than twice the budget is a dead process's and is taken over;
* history: the last runs of each check (start, end, status, who) so "no duplicate runs"
  can be checked after the fact.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "collect"
HISTORY_KEEP = 20
USABLE = ("ok", "partial")          # statuses whose result can be reused while fresh


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS collect_state (
            target TEXT NOT NULL,            -- target_key
            check_name TEXT NOT NULL,
            started_at REAL,                 -- epoch UTC of the last finished run's start
            finished_at REAL,                -- ... and end
            status TEXT,                     -- ok | partial | failed | skipped | not_supported
            summary TEXT,
            gaps TEXT,                       -- JSON list of plain-words coverage gaps
            finding_ids TEXT,                -- JSON list
            detail TEXT,
            running_since REAL,              -- epoch UTC of a live claim, NULL when nobody is running it
            running_by TEXT,                 -- "<pid>:<token>" of the claim holder
            history TEXT,                    -- JSON list, newest last: {started, finished, status, by}
            PRIMARY KEY (target, check_name)
        )
        """
    )


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
class Row:
    target: str
    check_name: str
    started_at: float | None = None
    finished_at: float | None = None
    status: str | None = None
    summary: str = ""
    gaps: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)
    detail: str = ""
    running_since: float | None = None
    running_by: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def age(self, now: float) -> float | None:
        return None if self.finished_at is None else max(0.0, now - self.finished_at)

    def fresh(self, ttl_seconds: float, now: float) -> bool:
        return (self.status in USABLE and self.finished_at is not None
                and self.finished_at + ttl_seconds > now)


def _loads(text: Any, default: Any) -> Any:
    try:
        value = json.loads(text) if text else default
    except (TypeError, ValueError):
        return default
    return value if isinstance(value, type(default)) else default


def _row(r: sqlite3.Row) -> Row:
    return Row(
        target=r["target"], check_name=r["check_name"], started_at=r["started_at"], finished_at=r["finished_at"],
        status=r["status"], summary=r["summary"] or "", gaps=_loads(r["gaps"], []),
        finding_ids=_loads(r["finding_ids"], []), detail=r["detail"] or "",
        running_since=r["running_since"], running_by=r["running_by"], history=_loads(r["history"], []),
    )


def get(data_dir: Path, target: str, check_name: str) -> Row | None:
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT * FROM collect_state WHERE target = ? AND check_name = ?",
                         (target, check_name)).fetchone()
        return _row(r) if r else None
    finally:
        conn.close()


def all_rows(data_dir: Path, target: str | None = None) -> list[Row]:
    conn = connect(data_dir)
    try:
        if target is None:
            rows = conn.execute("SELECT * FROM collect_state ORDER BY target, check_name").fetchall()
        else:
            rows = conn.execute("SELECT * FROM collect_state WHERE target = ? ORDER BY check_name",
                                (target,)).fetchall()
        return [_row(r) for r in rows]
    finally:
        conn.close()


def new_owner() -> str:
    return f"{os.getpid()}:{uuid.uuid4().hex[:8]}"


@dataclass
class Claim:
    kind: str                 # "fresh" | "claimed" | "busy"
    row: Row | None = None    # the stored row (fresh: the result to reuse; busy: the holder's claim)


def claim(data_dir: Path, target: str, check_name: str, *, ttl_seconds: float, stale_claim_seconds: float,
          owner: str, force: bool = False, now: float | None = None) -> Claim:
    """Decide what to do about one check, atomically:

    * `fresh`   -- a usable result younger than its limit exists (never with `force`);
    * `busy`    -- someone else holds a live claim: wait for their result;
    * `claimed` -- the caller now holds the claim and must `finish()` (or `release()`) it.
    """
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            r = conn.execute("SELECT * FROM collect_state WHERE target = ? AND check_name = ?",
                             (target, check_name)).fetchone()
            row = _row(r) if r else None
            live = (row is not None and row.running_since is not None
                    and now - row.running_since < stale_claim_seconds and row.running_by != owner)
            if live:
                conn.execute("COMMIT")
                return Claim("busy", row)
            if row is not None and not force and row.fresh(ttl_seconds, now):
                conn.execute("COMMIT")
                return Claim("fresh", row)
            if row is None:
                conn.execute("INSERT INTO collect_state (target, check_name, running_since, running_by) "
                             "VALUES (?, ?, ?, ?)", (target, check_name, now, owner))
            else:
                conn.execute("UPDATE collect_state SET running_since = ?, running_by = ? "
                             "WHERE target = ? AND check_name = ?", (now, owner, target, check_name))
            conn.execute("COMMIT")
            return Claim("claimed", row)
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def finish(data_dir: Path, target: str, check_name: str, *, owner: str, started_at: float, finished_at: float,
           status: str, summary: str, gaps: list[str], finding_ids: list[str] | None = None,
           detail: str = "") -> None:
    """Record a finished run and drop the claim. A result that is not usable
    (failed / skipped / not_supported) keeps the PREVIOUS good result's text out of
    the way: the row shows the latest outcome, so the digest says what happened now."""
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            r = conn.execute("SELECT history FROM collect_state WHERE target = ? AND check_name = ?",
                             (target, check_name)).fetchone()
            history = _loads(r["history"] if r else None, [])
            history.append({"started": round(started_at, 3), "finished": round(finished_at, 3),
                            "status": status, "by": owner})
            history = history[-HISTORY_KEEP:]
            conn.execute(
                "INSERT INTO collect_state (target, check_name, started_at, finished_at, status, summary, gaps, "
                "finding_ids, detail, running_since, running_by, history) VALUES (?,?,?,?,?,?,?,?,?,NULL,NULL,?) "
                "ON CONFLICT(target, check_name) DO UPDATE SET started_at=excluded.started_at, "
                "finished_at=excluded.finished_at, status=excluded.status, summary=excluded.summary, "
                "gaps=excluded.gaps, finding_ids=excluded.finding_ids, detail=excluded.detail, "
                "running_since=NULL, running_by=NULL, history=excluded.history",
                (target, check_name, started_at, finished_at, status, summary, json.dumps(gaps),
                 json.dumps(finding_ids or []), detail[:500], json.dumps(history)),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


def release(data_dir: Path, target: str, check_name: str, *, owner: str) -> None:
    """Drop a claim without recording a result (the run never started)."""
    conn = connect(data_dir)
    try:
        conn.execute("UPDATE collect_state SET running_since = NULL, running_by = NULL "
                     "WHERE target = ? AND check_name = ? AND running_by = ?", (target, check_name, owner))
    finally:
        conn.close()


def set_finding_ids(data_dir: Path, target: str, check_name: str, finding_ids: list[str]) -> None:
    conn = connect(data_dir)
    try:
        conn.execute("UPDATE collect_state SET finding_ids = ? WHERE target = ? AND check_name = ?",
                     (json.dumps(finding_ids), target, check_name))
    finally:
        conn.close()


def expire(data_dir: Path, check_name: str) -> int:
    """Make every machine's result of `check_name` stale, so the next collection
    runs it again (e.g. after new vulnerability data arrives). Keeps the result
    text; only its age changes. Returns how many rows were touched."""
    if not (Path(data_dir) / "kratos.db").exists():
        return 0
    conn = connect(data_dir)
    try:
        cur = conn.execute("UPDATE collect_state SET finished_at = 0 WHERE check_name = ? AND finished_at IS NOT NULL",
                           (check_name,))
        return cur.rowcount
    finally:
        conn.close()

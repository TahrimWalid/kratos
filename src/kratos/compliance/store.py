"""Compliance tables in kratos.db (E.2 §5.1).

- ``compliance_runs``       one row per compliance evaluation of a machine (when, how read, the
                            ComplianceAsCode product and level, the mapping version);
- ``compliance_results``    one row per framework control per run (status, the check ids and
                            their evidence as JSON, the read times) -- never edited;
- ``control_owners``        who owns a control, for a machine / a group / all machines, with a
                            due date and a note -- a person's decision;
- ``control_na``            "not applicable" decisions: reason, expiry, the person;
- ``compliance_profiles``   the CIS level per machine (Level 1 Server unless a person says 2);
- ``control_owner_events``  append-only trail of every owner / N/A / level change, with the
                            actor (a trigger refuses UPDATE and DELETE).

Results are keyed by ``target_key`` (re-pairing a machine keeps them); owners and N/A by
framework + control + scope. Inventoried (B.5) with backup class `include`; nothing here
deletes rows on its own.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "compliance"
TABLES = ("compliance_runs", "compliance_results", "control_owners", "control_na", "compliance_profiles",
          "control_owner_events")


def _step_1(conn: sqlite3.Connection) -> None:
    # One statement per execute(): executescript() would COMMIT inside the migration's transaction.
    for sql in _SCHEMA:
        conn.execute(sql)


_SCHEMA: tuple[str, ...] = (
    """
CREATE TABLE IF NOT EXISTS compliance_runs (
          run_id TEXT PRIMARY KEY,
          target_key TEXT NOT NULL,
          at REAL NOT NULL,                 -- epoch UTC of the evaluation
          via TEXT NOT NULL DEFAULT '',     -- ssh | subagent (the hardening read used)
          read_at REAL,                     -- when that hardening read was taken
          product TEXT,                     -- ComplianceAsCode product, NULL = no CIS mapping
          product_note TEXT NOT NULL DEFAULT '',
          level TEXT NOT NULL,
          mapping_version TEXT NOT NULL,    -- the ComplianceAsCode commit the CIS rows came from
          counts TEXT NOT NULL,             -- JSON {framework: {status: n}}
          complete INTEGER NOT NULL DEFAULT 0,
          results_run TEXT NOT NULL         -- the run whose compliance_results rows hold these results
                                            -- (itself, or an earlier run with exactly the same results)
        )
    """,
    """
CREATE INDEX IF NOT EXISTS compliance_runs_target ON compliance_runs(target_key, at)
    """,
    """
CREATE TABLE IF NOT EXISTS compliance_results (
          run_id TEXT NOT NULL,
          target_key TEXT NOT NULL,
          framework TEXT NOT NULL,          -- cis | iso27001 | nis2
          control_id TEXT NOT NULL,
          status TEXT NOT NULL,             -- pass | fail | partial | not_checked | needs_person | not_applicable
          reason TEXT NOT NULL DEFAULT '',
          checks TEXT NOT NULL DEFAULT '[]',   -- JSON: the check ids that gave evidence
          read_times TEXT NOT NULL DEFAULT '{}',
          PRIMARY KEY (run_id, framework, control_id)
        )
    """,
    """
CREATE INDEX IF NOT EXISTS compliance_results_target ON compliance_results(target_key, framework)
    """,
    """
CREATE TABLE IF NOT EXISTS control_owners (
          framework TEXT NOT NULL,
          control_id TEXT NOT NULL,
          scope TEXT NOT NULL,              -- 'machine:<target_key>' | 'group:<name>' | 'all'
          owner_user_id TEXT,               -- a Kratos user, or NULL with a free name
          owner_name TEXT NOT NULL,
          due TEXT,                         -- YYYY-MM-DD or NULL
          note TEXT NOT NULL DEFAULT '',
          set_by TEXT NOT NULL,
          set_at REAL NOT NULL,
          PRIMARY KEY (framework, control_id, scope)
        )
    """,
    """
CREATE TABLE IF NOT EXISTS control_na (
          framework TEXT NOT NULL,
          control_id TEXT NOT NULL,
          scope TEXT NOT NULL,
          reason TEXT NOT NULL,
          expires_at REAL NOT NULL,
          set_by TEXT NOT NULL,
          set_at REAL NOT NULL,
          PRIMARY KEY (framework, control_id, scope)
        )
    """,
    """
CREATE TABLE IF NOT EXISTS compliance_profiles (
          target_key TEXT PRIMARY KEY,
          cis_level TEXT NOT NULL,
          set_by TEXT NOT NULL,
          set_at REAL NOT NULL
        )
    """,
    """
CREATE TABLE IF NOT EXISTS control_owner_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          at REAL NOT NULL,
          kind TEXT NOT NULL,               -- owner_set | owner_clear | na_set | na_clear | na_expired | level_set
          framework TEXT NOT NULL DEFAULT '',
          control_id TEXT NOT NULL DEFAULT '',
          scope TEXT NOT NULL DEFAULT '',
          detail TEXT NOT NULL DEFAULT '{}',
          actor TEXT NOT NULL,
          interface TEXT NOT NULL DEFAULT ''
        )
    """,
    "CREATE TRIGGER IF NOT EXISTS control_owner_events_no_update BEFORE UPDATE ON control_owner_events "
    "BEGIN SELECT RAISE(ABORT, 'control_owner_events is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS control_owner_events_no_delete BEFORE DELETE ON control_owner_events "
    "BEGIN SELECT RAISE(ABORT, 'control_owner_events is append-only'); END",
)


STEPS = (_step_1,)


def connect(data_dir: Path | str) -> sqlite3.Connection:
    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    for sql in _SCHEMA[-2:]:             # the append-only guards, re-made on every open (D.7's lesson)
        conn.execute(sql)
    conn.commit()
    conn.row_factory = sqlite3.Row
    return conn


@contextlib.contextmanager
def opened(data_dir: Path | str) -> Iterator[sqlite3.Connection]:
    conn = connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


def save_run(data_dir: Path | str, target_key: str, *, at: float, via: str, read_at: float | None,
             product: str | None, product_note: str, level: str, mapping_version: str,
             counts: dict[str, Any], complete: bool, rows: list[dict[str, Any]]) -> str:
    """One run row; result rows only when they differ from the machine's last stored results
    (nothing is ever deleted, so identical rows twice a day would only grow the database)."""
    run_id = uuid.uuid4().hex[:16]
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            prev = conn.execute("SELECT results_run FROM compliance_runs WHERE target_key = ? ORDER BY at DESC "
                                "LIMIT 1", (target_key,)).fetchone()
            same = False
            if prev is not None:
                old = {(r["framework"], r["control_id"]): (r["status"], r["reason"], r["checks"]) for r in conn.execute(
                    "SELECT framework, control_id, status, reason, checks FROM compliance_results WHERE run_id = ?",
                    (prev["results_run"],))}
                new = {(r["framework"], r["control"]): (r["status"], str(r.get("reason") or "")[:600],
                                                        json.dumps(r.get("checks") or [])) for r in rows}
                same = old == new
            holder = prev["results_run"] if same else run_id
            conn.execute("INSERT INTO compliance_runs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (run_id, target_key, at, via, read_at, product, product_note, level, mapping_version,
                          json.dumps(counts, sort_keys=True), int(bool(complete)), holder))
            if same:
                conn.execute("COMMIT")
                return run_id
            conn.executemany(
                "INSERT INTO compliance_results VALUES (?,?,?,?,?,?,?,?)",
                [(run_id, target_key, r["framework"], r["control"], r["status"], str(r.get("reason") or "")[:600],
                  json.dumps(r.get("checks") or []), json.dumps(r.get("read_times") or {}, sort_keys=True))
                 for r in rows])
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return run_id


def results_of(data_dir: Path | str, run_id: str) -> list[dict[str, Any]]:
    """A run's control results (stored with it, or with the earlier run it was identical to)."""
    with opened(data_dir) as conn:
        r = conn.execute("SELECT results_run FROM compliance_runs WHERE run_id = ?", (run_id,)).fetchone()
        if r is None:
            return []
        return [dict(x) for x in conn.execute("SELECT * FROM compliance_results WHERE run_id = ?", (r[0],))]


def latest_run(data_dir: Path | str, target_key: str) -> dict[str, Any] | None:
    with opened(data_dir) as conn:
        r = conn.execute("SELECT * FROM compliance_runs WHERE target_key = ? ORDER BY at DESC LIMIT 1",
                         (target_key,)).fetchone()
    return dict(r) if r else None


def runs(data_dir: Path | str, target_key: str, limit: int = 20) -> list[dict[str, Any]]:
    with opened(data_dir) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM compliance_runs WHERE target_key = ? ORDER BY at DESC "
                                              "LIMIT ?", (target_key, int(limit)))]


def add_event(conn: sqlite3.Connection, *, kind: str, framework: str = "", control_id: str = "", scope: str = "",
              detail: dict[str, Any] | None = None, actor: str, interface: str = "", at: float | None = None) -> None:
    conn.execute("INSERT INTO control_owner_events (at, kind, framework, control_id, scope, detail, actor, interface) "
                 "VALUES (?,?,?,?,?,?,?,?)", (time.time() if at is None else at, kind, framework, control_id, scope,
                                              json.dumps(detail or {}, sort_keys=True), actor[:120], interface))


def events(data_dir: Path | str, limit: int = 100) -> list[dict[str, Any]]:
    with opened(data_dir) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM control_owner_events ORDER BY id DESC LIMIT ?",
                                              (int(limit),))]


def counts_all(data_dir: Path | str) -> dict[str, int]:
    with opened(data_dir) as conn:
        return {t: int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]) for t in TABLES}

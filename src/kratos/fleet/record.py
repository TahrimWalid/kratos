"""Fleet runs on record (D.2 §5.2): kratos.db -> ``fleet_runs`` (one row per question or
group audit: who asked, over which group, the window, the estimate, the cost, the code
summary) and ``fleet_run_machines`` (one row per machine in it: outcome, why, how it was
reached, coverage, finding counts, the run-record span of its collection).

Append-only in spirit: a run's row is written when it starts and completed once; nothing
here deletes. The model's text is not stored here (the run record and the session
transcript hold it); these rows are what ``/fleet`` and an audit read.
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

COMPONENT = "fleet_runs"


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fleet_runs (
          run_id TEXT PRIMARY KEY,
          kind TEXT NOT NULL,                  -- question | audit
          question TEXT NOT NULL,
          group_ref TEXT NOT NULL,             -- '@web', '@all', or the machines asked about
          window TEXT,                         -- JSON: the resolved period(s)
          actor TEXT NOT NULL, interface TEXT NOT NULL, source TEXT NOT NULL,
          estimate TEXT,                       -- JSON: machines, reads, tokens, cost
          status TEXT NOT NULL,                -- running | final_answer | fallback | refused_by_budget | ...
          summary TEXT,
          machines INTEGER NOT NULL DEFAULT 0,
          outside_scope INTEGER NOT NULL DEFAULT 0,
          tokens INTEGER, cost_usd REAL,
          extra_reads TEXT,                    -- JSON list
          trace_id TEXT,
          started_at REAL NOT NULL, finished_at REAL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS fleet_runs_started ON fleet_runs(started_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS fleet_run_machines (
          run_id TEXT NOT NULL,
          machine TEXT NOT NULL,               -- target_key form
          outcome TEXT NOT NULL,               -- ok | partial | unreachable | busy | timeout | failed | stopped
          reason TEXT,
          transport TEXT,
          coverage TEXT,                       -- JSON list of what was not read
          findings TEXT,                       -- JSON {severity: count} of open findings
          act INTEGER NOT NULL DEFAULT 0,
          passed INTEGER,                      -- 1: its answer passed every check; NULL: Kratos wrote it
          trace_span_id TEXT,
          elapsed_s REAL,
          PRIMARY KEY (run_id, machine)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS fleet_run_machines_machine ON fleet_run_machines(machine, run_id)")


STEPS = (_step_1,)


def _db(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


@contextlib.contextmanager
def opened(data_dir: Path | str) -> Iterator[sqlite3.Connection]:
    path = _db(data_dir)
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
        yield conn
    finally:
        conn.close()


def start(data_dir: Path | str, *, run_id: str, kind: str, question: str, group_ref: str, window: Any,
          actor: Any, source: str, estimate: dict[str, Any], machines: int, outside_scope: int,
          trace_id: str | None) -> None:
    with opened(data_dir) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO fleet_runs (run_id, kind, question, group_ref, window, actor, interface, source, "
            "estimate, status, machines, outside_scope, trace_id, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)",
            (run_id, kind, question[:2000], group_ref[:500], json.dumps(window, default=str),
             str(getattr(actor, "user", actor))[:120], str(getattr(actor, "interface", "")), source,
             json.dumps(estimate, default=str), int(machines), int(outside_scope), trace_id, time.time()))


def finish(data_dir: Path | str, run_id: str, *, status: str, summary: str, results: list[Any],
           passed: dict[str, bool | None], tokens: int | None, cost_usd: float | None,
           extra_reads: list[dict[str, Any]]) -> None:
    from kratos.fleet.digest import _open

    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("UPDATE fleet_runs SET status = ?, summary = ?, tokens = ?, cost_usd = ?, extra_reads = ?, "
                         "finished_at = ? WHERE run_id = ?",
                         (status, summary[:2000], tokens, cost_usd, json.dumps(extra_reads, default=str)[:20000],
                          time.time(), run_id))
            for r in results:
                found = _open(r.findings)
                by: dict[str, int] = {}
                for f in found:
                    sev = str(f.get("severity") or "info").lower()
                    by[sev] = by.get(sev, 0) + 1
                act = sum(1 for f in found if str((f.get("ssvc") or {}).get("outcome") or "") == "act")
                p = passed.get(r.machine)
                conn.execute(
                    "INSERT OR REPLACE INTO fleet_run_machines (run_id, machine, outcome, reason, transport, coverage, "
                    "findings, act, passed, trace_span_id, elapsed_s) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, r.machine, r.outcome, (r.reason or "")[:500], r.transport,
                     json.dumps([g[:300] for g in r.gaps[:20]]), json.dumps(by), act,
                     None if p is None else int(bool(p)), r.span_id, round(r.elapsed, 2)))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def recent(data_dir: Path | str, limit: int = 20) -> list[dict[str, Any]]:
    if not _db(data_dir).exists():
        return []
    with opened(data_dir) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM fleet_runs ORDER BY started_at DESC LIMIT ?",
                                              (int(limit),))]


def machines_of(data_dir: Path | str, run_id: str) -> list[dict[str, Any]]:
    if not _db(data_dir).exists():
        return []
    with opened(data_dir) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM fleet_run_machines WHERE run_id = ? ORDER BY machine",
                                              (run_id,))]


def last_per_machine(data_dir: Path | str) -> dict[str, dict[str, Any]]:
    """Each machine's row from the newest fleet run that covered it (for /fleet)."""
    if not _db(data_dir).exists():
        return {}
    with opened(data_dir) as conn:
        rows = conn.execute(
            "SELECT m.*, r.started_at FROM fleet_run_machines m JOIN fleet_runs r ON r.run_id = m.run_id "
            "ORDER BY r.started_at").fetchall()
    return {r["machine"]: dict(r) for r in rows}

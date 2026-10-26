"""`hunt_runs`: one row per hunt -- who, when, what was hunted, over which machines and
window, the coverage in one line and the hit counts (C.3 §3.7).

The indicator a person typed is personal data (it may name an account or an address):
it is listed in the data inventory (kratos.datainv, category `hunts`) and the person
removes old rows with `kratos data prune --category hunts`. Nothing deletes them on
its own.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "hunt_runs"
SOURCES = ("tui", "cli", "chat", "mcp", "auto")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS hunt_runs (
          id INTEGER PRIMARY KEY,
          at REAL NOT NULL,                  -- epoch UTC, when the hunt started
          finished_at REAL,
          source TEXT NOT NULL,              -- tui | cli | chat | mcp | auto
          actor TEXT NOT NULL,               -- who: "user via interface", a token id, or "kratos (threat intel)"
          indicators TEXT NOT NULL,          -- JSON: [{kind, value}] -- what was typed (personal data)
          window_start REAL,                 -- NULL: everything Kratos holds
          window_end REAL,
          machines TEXT NOT NULL,            -- JSON: the machines searched
          coverage TEXT,                     -- the coverage statement, in one line
          hits INTEGER NOT NULL DEFAULT 0,   -- matching records, all machines
          hit_machines INTEGER NOT NULL DEFAULT 0,
          summary TEXT,                      -- JSON: per indicator, per machine: count, first, last
          run_id TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS hunt_runs_at ON hunt_runs(at)")


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


def record(data_dir: Path | str, *, at: float, source: str, actor: str, indicators: list[dict[str, str]],
           window: tuple[float | None, float | None], machines: list[str], coverage: str, hits: int,
           hit_machines: int, summary: dict[str, Any], run_id: str | None) -> int:
    if source not in SOURCES:
        raise ValueError(f"unknown hunt source {source!r}")
    conn = connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "INSERT INTO hunt_runs (at, finished_at, source, actor, indicators, window_start, window_end, machines, "
            "coverage, hits, hit_machines, summary, run_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (at, time.time(), source, str(actor or "?")[:200], json.dumps(indicators), window[0], window[1],
             json.dumps(machines), coverage[:2000], int(hits), int(hit_machines),
             json.dumps(summary, sort_keys=True, default=str)[:20000], run_id))
        conn.execute("COMMIT")
        return int(cur.lastrowid)
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def recent(data_dir: Path | str, limit: int = 20, *, source: str | None = None) -> list[dict[str, Any]]:
    conn = connect(data_dir)
    try:
        if source is None:
            rows = conn.execute("SELECT * FROM hunt_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM hunt_runs WHERE source = ? ORDER BY id DESC LIMIT ?",
                                (source, limit)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("indicators", "machines", "summary"):
            try:
                d[k] = json.loads(d[k]) if d[k] else ([] if k != "summary" else {})
            except ValueError:
                d[k] = [] if k != "summary" else {}
        out.append(d)
    return out


def auto_hunted(data_dir: Path | str) -> set[str]:
    """Addresses the threat-intel auto-hunt has already searched for (normalised)."""
    conn = connect(data_dir)
    try:
        rows = conn.execute("SELECT indicators FROM hunt_runs WHERE source = 'auto'").fetchall()
    finally:
        conn.close()
    out: set[str] = set()
    for (text,) in rows:
        try:
            for ind in json.loads(text or "[]"):
                if isinstance(ind, dict) and ind.get("kind") == "ip":
                    out.add(str(ind.get("value")))
        except ValueError:
            continue
    return out

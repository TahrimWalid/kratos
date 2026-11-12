"""Baseline tables in kratos.db (E.3 §5.1).

- ``baseline_profiles``   one row per machine, dimension and generation: status (learning |
                          active | frozen | not_learnable), when learning started, the zone the
                          hours were learned in, the high-water marks of what has been learned,
                          counts of set-aside and held-back items, and the snapshot days seen.
                          A reset or a time-zone change starts a new generation; the old rows
                          stay as history.
- ``baseline_entries``    one row per (machine, dimension, generation, subject, key): a decayed
                          weight with the time it was decayed to, a count, first and last seen,
                          held-back observations per finding, and people's marks (accepted as
                          normal, forgotten). Rows are never deleted: an entry set aside to keep
                          a dimension at `baseline.max_entries` is marked `evicted_at`, so a key
                          that comes back is still known (no false "first time").
- ``baseline_decisions``  append-only trail of people's decisions (accept, forget, freeze,
                          unfreeze, reset) with the actor; a trigger refuses UPDATE and DELETE.

Keyed by ``target_key`` (a re-paired machine keeps its baselines). Inventoried (B.5) with
backup class `include`. Nothing here deletes rows.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "baseline"
TABLES = ("baseline_profiles", "baseline_entries", "baseline_decisions")
STATUSES = ("learning", "active", "frozen", "not_learnable")
DECISION_KINDS = ("accept", "accept_from_finding", "forget", "freeze", "unfreeze", "reset")

_SCHEMA: tuple[str, ...] = (
    """
CREATE TABLE IF NOT EXISTS baseline_profiles (
      target_key TEXT NOT NULL,
      dim TEXT NOT NULL,
      generation INTEGER NOT NULL,
      status TEXT NOT NULL,
      started_at REAL NOT NULL,            -- learning of this generation counts from here
      tz TEXT,                             -- the zone hours were learned in (login_time)
      high_water INTEGER NOT NULL DEFAULT 0,       -- host_events.id learned through (event dims)
      snapshot_high_water REAL NOT NULL DEFAULT 0, -- checked_at_epoch learned through (snapshot dims)
      snapshot_days TEXT NOT NULL DEFAULT '{}',    -- JSON {UTC day: snapshots}, snapshot dims
      samples INTEGER NOT NULL DEFAULT 0,  -- observations learned
      evicted INTEGER NOT NULL DEFAULT 0,  -- entries set aside to keep max_entries
      held_back INTEGER NOT NULL DEFAULT 0,-- observations held back now (near an open serious finding)
      frozen INTEGER NOT NULL DEFAULT 0,
      note TEXT NOT NULL DEFAULT '',       -- why not learnable / why a new generation began
      ended_at REAL,                       -- set when a newer generation replaced this one
      updated_at REAL NOT NULL,
      PRIMARY KEY (target_key, dim, generation)
    )
    """,
    """
CREATE TABLE IF NOT EXISTS baseline_entries (
      target_key TEXT NOT NULL,
      dim TEXT NOT NULL,
      generation INTEGER NOT NULL,
      subject TEXT NOT NULL,
      key TEXT NOT NULL,
      weight REAL NOT NULL,
      weight_at REAL NOT NULL,             -- the weight is decayed to this time
      count INTEGER NOT NULL,
      first_seen REAL NOT NULL,
      last_seen REAL NOT NULL,
      held TEXT NOT NULL DEFAULT '{}',     -- JSON {finding_key: [count, last_ts]} not learned yet
      accepted_at REAL, accepted_by TEXT,  -- a person said "this is normal"
      forgotten_at REAL, forgotten_by TEXT,-- a person forgot it (it counts as new again)
      evicted_at REAL,                     -- set aside to keep max_entries
      last_raised REAL,                    -- the last time a finding raised this key
      PRIMARY KEY (target_key, dim, generation, subject, key)
    )
    """,
    """
CREATE INDEX IF NOT EXISTS baseline_entries_key ON baseline_entries(dim, subject, key)
    """,
    """
CREATE TABLE IF NOT EXISTS baseline_decisions (
      id INTEGER PRIMARY KEY,
      target_key TEXT NOT NULL,
      dim TEXT,
      kind TEXT NOT NULL,
      subject TEXT, key TEXT,
      actor TEXT NOT NULL, interface TEXT NOT NULL, user_id TEXT,
      reason TEXT NOT NULL DEFAULT '',
      finding_key TEXT,
      at REAL NOT NULL,
      details TEXT
    )
    """,
    """
CREATE INDEX IF NOT EXISTS baseline_decisions_target ON baseline_decisions(target_key, at)
    """,
    """
CREATE TRIGGER IF NOT EXISTS baseline_decisions_no_update BEFORE UPDATE ON baseline_decisions
BEGIN SELECT RAISE(ABORT, 'baseline_decisions is append-only'); END
    """,
    """
CREATE TRIGGER IF NOT EXISTS baseline_decisions_no_delete BEFORE DELETE ON baseline_decisions
BEGIN SELECT RAISE(ABORT, 'baseline_decisions is append-only'); END
    """,
)


def _step_1(conn: sqlite3.Connection) -> None:
    for sql in _SCHEMA:
        conn.execute(sql)


STEPS = (_step_1,)


def db_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


def connect(data_dir: Path | str) -> sqlite3.Connection:
    path = db_path(data_dir)
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path | str) -> Iterator[sqlite3.Connection]:
    conn = connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def immediate(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------
def current_profiles(conn: sqlite3.Connection, target_key: str) -> dict[str, sqlite3.Row]:
    """The newest generation of every dimension for a machine."""
    rows = conn.execute(
        "SELECT p.* FROM baseline_profiles p JOIN (SELECT dim, MAX(generation) g FROM baseline_profiles "
        "WHERE target_key = ? GROUP BY dim) m ON p.dim = m.dim AND p.generation = m.g WHERE p.target_key = ?",
        (target_key, target_key)).fetchall()
    return {r["dim"]: r for r in rows}


def history(conn: sqlite3.Connection, target_key: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM baseline_profiles WHERE target_key = ? AND ended_at IS NOT NULL "
                        "ORDER BY dim, generation", (target_key,)).fetchall()


def new_profile(conn: sqlite3.Connection, target_key: str, dim: str, *, generation: int, started_at: float,
                high_water: int, snapshot_high_water: float, tz: str | None, note: str, now: float,
                frozen: bool = False) -> None:
    conn.execute(
        "INSERT INTO baseline_profiles (target_key, dim, generation, status, started_at, tz, high_water, "
        "snapshot_high_water, frozen, note, updated_at) VALUES (?, ?, ?, 'learning', ?, ?, ?, ?, ?, ?, ?)",
        (target_key, dim, generation, started_at, tz, high_water, snapshot_high_water, int(frozen), note, now))


def end_profile(conn: sqlite3.Connection, target_key: str, dim: str, generation: int, now: float) -> None:
    conn.execute("UPDATE baseline_profiles SET ended_at = ?, updated_at = ? WHERE target_key = ? AND dim = ? "
                 "AND generation = ?", (now, now, target_key, dim, generation))


def update_profile(conn: sqlite3.Connection, target_key: str, dim: str, generation: int, **values: Any) -> None:
    allowed = {"status", "tz", "high_water", "snapshot_high_water", "snapshot_days", "samples", "evicted",
               "held_back", "frozen", "note", "updated_at", "started_at"}
    cols = [k for k in values if k in allowed]
    if not cols:
        return
    sets = ", ".join(f"{c} = ?" for c in cols)
    params = [json.dumps(values[c], sort_keys=True) if c == "snapshot_days" else values[c] for c in cols]
    conn.execute(f"UPDATE baseline_profiles SET {sets} WHERE target_key = ? AND dim = ? AND generation = ?",
                 (*params, target_key, dim, generation))


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------
ENTRY_COLS = ("subject", "key", "weight", "weight_at", "count", "first_seen", "last_seen", "held", "accepted_at",
              "accepted_by", "forgotten_at", "forgotten_by", "evicted_at", "last_raised")


def entries(conn: sqlite3.Connection, target_key: str, dim: str, generation: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM baseline_entries WHERE target_key = ? AND dim = ? AND generation = ?",
                        (target_key, dim, generation)).fetchall()


def upsert_entry(conn: sqlite3.Connection, target_key: str, dim: str, generation: int, e: dict[str, Any]) -> None:
    conn.execute(
        f"INSERT INTO baseline_entries (target_key, dim, generation, {', '.join(ENTRY_COLS)}) "
        f"VALUES (?, ?, ?, {', '.join('?' for _ in ENTRY_COLS)}) "
        "ON CONFLICT (target_key, dim, generation, subject, key) DO UPDATE SET "
        + ", ".join(f"{c} = excluded.{c}" for c in ENTRY_COLS if c not in ("subject", "key")),
        (target_key, dim, generation, *[json.dumps(e.get(c) or {}, sort_keys=True) if c == "held" else e.get(c)
                                        for c in ENTRY_COLS]))


def entries_elsewhere(conn: sqlite3.Connection, dim: str, subject: str, key: str, targets: list[str]) -> list[str]:
    """The machines among `targets` whose current baseline already has this key for this subject."""
    if not targets:
        return []
    marks = ", ".join("?" for _ in targets)
    rows = conn.execute(
        f"SELECT DISTINCT e.target_key FROM baseline_entries e JOIN (SELECT target_key, dim, MAX(generation) g "
        f"FROM baseline_profiles WHERE dim = ? AND target_key IN ({marks}) GROUP BY target_key, dim) p "
        "ON e.target_key = p.target_key AND e.dim = p.dim AND e.generation = p.g "
        "WHERE e.dim = ? AND e.subject = ? AND e.key = ? AND e.forgotten_at IS NULL AND e.count >= 2",
        (dim, *targets, dim, subject, key)).fetchall()
    return sorted(r[0] for r in rows)


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------
def add_decision(conn: sqlite3.Connection, *, target_key: str, dim: str | None, kind: str, subject: str | None,
                 key: str | None, actor: str, interface: str, user_id: str | None, reason: str, at: float,
                 finding_key: str | None = None, details: dict[str, Any] | None = None) -> int:
    if kind not in DECISION_KINDS:
        raise ValueError(f"unknown baseline decision {kind!r}")
    cur = conn.execute(
        "INSERT INTO baseline_decisions (target_key, dim, kind, subject, key, actor, interface, user_id, reason, "
        "finding_key, at, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target_key, dim, kind, subject, key, actor, interface, user_id, reason, finding_key, at,
         json.dumps(details, sort_keys=True) if details else None))
    return int(cur.lastrowid)


def decisions(conn: sqlite3.Connection, target_key: str, limit: int = 200) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM baseline_decisions WHERE target_key = ? ORDER BY at DESC, id DESC LIMIT ?",
                        (target_key, int(limit))).fetchall()


def absorbed_exceptions(conn: sqlite3.Connection, target_key: str) -> set[int]:
    """Lifecycle decision ids already turned into "accepted as normal" marks."""
    out: set[int] = set()
    for r in conn.execute("SELECT details FROM baseline_decisions WHERE target_key = ? AND kind IN "
                          "('accept', 'accept_from_finding')", (target_key,)):
        try:
            value = json.loads(r[0] or "{}").get("exception_id")
            if value is not None:
                out.add(int(value))
        except (TypeError, ValueError):
            continue
    return out


def targets(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT DISTINCT target_key FROM baseline_profiles ORDER BY target_key")]

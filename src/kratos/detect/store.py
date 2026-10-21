"""Detection bookkeeping in kratos.db.

- `detect_runs` -- one row per detection pass: which machine, which pack (id,
  version, SHA-256), which stored events it evaluated (row ids after/through, and
  their time span), how many detections, whether it finished, and the counting
  rules' state (when each group last fired) for the next pass.
- `detect_rule_overrides` -- a person turning a rule off (or back on) for one
  machine or everywhere ('*'), with who, when and why. People only: refused inside
  an agent tool call, like every decision about findings.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

COMPONENT = "detect"
EVERYWHERE = "*"
MAX_REASON = 500


class OverrideError(ValueError):
    """A rule on/off change that can't be accepted (no person, no reason, a tool call)."""


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detect_runs (
          id INTEGER PRIMARY KEY,
          target TEXT NOT NULL,              -- target_key
          pack_id TEXT NOT NULL,
          pack_version INTEGER NOT NULL,
          pack_sha256 TEXT NOT NULL,
          started_at REAL NOT NULL,
          finished_at REAL,
          after_row INTEGER NOT NULL,        -- evaluated host_events rows with id > after_row ...
          through_row INTEGER NOT NULL,      -- ... and id <= through_row
          first_ts REAL,                     -- the evaluated events' time span
          last_ts REAL,
          events INTEGER NOT NULL DEFAULT 0,
          detections INTEGER NOT NULL DEFAULT 0,
          status TEXT NOT NULL,              -- ok | partial | failed
          reason TEXT,                       -- why partial or failed, in plain words
          lookback INTEGER NOT NULL DEFAULT 0,  -- 1: a first or new-pack look back over stored events
          run_id TEXT,
          state TEXT                         -- JSON: counting rules' last fire per group
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS detect_runs_target ON detect_runs(target, pack_id, id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detect_rule_overrides (
          rule_id TEXT NOT NULL,
          target TEXT NOT NULL,              -- target_key, or '*' for every machine
          enabled INTEGER NOT NULL,
          reason TEXT NOT NULL,
          actor TEXT NOT NULL,               -- who: "user via interface"
          updated_at REAL NOT NULL,
          PRIMARY KEY (rule_id, target)
        )
        """
    )


def _step_2(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS detect_own_sessions (
          target TEXT NOT NULL,              -- target_key
          session TEXT NOT NULL,             -- the machine's audit session id of Kratos's own SSH login
          first_seen REAL NOT NULL,
          last_seen REAL NOT NULL,
          PRIMARY KEY (target, session)
        )
        """
    )


STEPS = (_step_1, _step_2)


def _connect(data_dir: Path | str) -> sqlite3.Connection:
    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@dataclass(frozen=True)
class RunRow:
    id: int
    target: str
    pack_id: str
    pack_version: int
    pack_sha256: str
    started_at: float
    finished_at: float | None
    after_row: int
    through_row: int
    first_ts: float | None
    last_ts: float | None
    events: int
    detections: int
    status: str
    reason: str | None
    lookback: bool
    run_id: str | None
    state: dict[str, dict[str, float]]


def _run_row(r: sqlite3.Row | tuple) -> RunRow:
    state: dict[str, dict[str, float]] = {}
    try:
        state = json.loads(r[17]) if r[17] else {}
    except ValueError:
        state = {}
    return RunRow(id=r[0], target=r[1], pack_id=r[2], pack_version=int(r[3]), pack_sha256=r[4], started_at=r[5],
                  finished_at=r[6], after_row=int(r[7]), through_row=int(r[8]), first_ts=r[9], last_ts=r[10],
                  events=int(r[11]), detections=int(r[12]), status=r[13], reason=r[14], lookback=bool(r[15]),
                  run_id=r[16], state=state)


_RUN_COLS = ("id, target, pack_id, pack_version, pack_sha256, started_at, finished_at, after_row, through_row, "
             "first_ts, last_ts, events, detections, status, reason, lookback, run_id, state")


def last_run(data_dir: Path | str, target: str, pack_id: str) -> RunRow | None:
    """The newest finished pass of `pack_id` over `target`'s events."""
    conn = _connect(data_dir)
    try:
        r = conn.execute(f"SELECT {_RUN_COLS} FROM detect_runs WHERE target = ? AND pack_id = ? "
                         "AND finished_at IS NOT NULL AND status != 'failed' ORDER BY id DESC LIMIT 1",
                         (target_key(target), pack_id)).fetchone()
    finally:
        conn.close()
    return _run_row(r) if r else None


def recent_runs(data_dir: Path | str, target: str | None = None, limit: int = 20) -> list[RunRow]:
    conn = _connect(data_dir)
    try:
        if target is None:
            rows = conn.execute(f"SELECT {_RUN_COLS} FROM detect_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        else:
            rows = conn.execute(f"SELECT {_RUN_COLS} FROM detect_runs WHERE target = ? ORDER BY id DESC LIMIT ?",
                                (target_key(target), limit)).fetchall()
    finally:
        conn.close()
    return [_run_row(r) for r in rows]


def last_runs_by_target(data_dir: Path | str) -> dict[str, RunRow]:
    """The newest finished pass per machine (any pack)."""
    conn = _connect(data_dir)
    try:
        rows = conn.execute(f"SELECT {_RUN_COLS} FROM detect_runs WHERE id IN "
                            "(SELECT MAX(id) FROM detect_runs WHERE finished_at IS NOT NULL GROUP BY target)").fetchall()
    finally:
        conn.close()
    return {r[1]: _run_row(r) for r in rows}


def record_run(data_dir: Path | str, *, target: str, pack_id: str, pack_version: int, pack_sha256: str,
               started_at: float, finished_at: float, after_row: int, through_row: int, first_ts: float | None,
               last_ts: float | None, events: int, detections: int, status: str, reason: str | None,
               lookback: bool, run_id: str | None, state: dict[str, dict[str, float]]) -> int:
    conn = _connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "INSERT INTO detect_runs (target, pack_id, pack_version, pack_sha256, started_at, finished_at, after_row, "
            "through_row, first_ts, last_ts, events, detections, status, reason, lookback, run_id, state) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (target_key(target), pack_id, int(pack_version), pack_sha256, started_at, finished_at, int(after_row),
             int(through_row), first_ts, last_ts, int(events), int(detections), status, reason, int(bool(lookback)),
             run_id, json.dumps(state, sort_keys=True)))
        conn.execute("COMMIT")
        return int(cur.lastrowid)
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------- rule on/off (people only)
@dataclass(frozen=True)
class Override:
    rule_id: str
    target: str            # target_key or '*'
    enabled: bool
    reason: str
    actor: str
    updated_at: float


def set_rule_enabled(data_dir: Path | str, rule_id: str, enabled: bool, *, target: str | None, reason: str,
                     actor: Any) -> Override:
    """Turn a rule off (or back on) for one machine (`target`) or everywhere (None).
    `actor` is a kratos.lifecycle.decide.Actor: a person, from the TUI or the CLI."""
    from kratos.lifecycle.decide import INTERFACES

    tool = settings_store.in_tool_call()
    if tool is not None:
        raise OverrideError(f"agent tools may not turn detection rules on or off (tool {tool!r} tried)")
    if not str(getattr(actor, "user", "") or "").strip() or getattr(actor, "interface", None) not in INTERFACES:
        raise OverrideError("turning a rule on or off needs a person: an Actor from the TUI or the CLI")
    text = str(reason or "")
    if not text.strip():
        raise OverrideError("a reason is required")
    if len(text) > MAX_REASON:
        raise OverrideError(f"the reason is too long ({len(text)} characters, at most {MAX_REASON})")
    rule_id = str(rule_id or "").strip().upper()
    where = target_key(target) if target else EVERYWHERE
    now = time.time()
    who = f"{actor.user} via {actor.interface}"
    conn = _connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO detect_rule_overrides (rule_id, target, enabled, reason, actor, updated_at) "
                     "VALUES (?,?,?,?,?,?) ON CONFLICT(rule_id, target) DO UPDATE SET enabled = excluded.enabled, "
                     "reason = excluded.reason, actor = excluded.actor, updated_at = excluded.updated_at",
                     (rule_id, where, int(bool(enabled)), text.strip(), who, now))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return Override(rule_id, where, bool(enabled), text.strip(), who, now)


def overrides(data_dir: Path | str) -> list[Override]:
    conn = _connect(data_dir)
    try:
        rows = conn.execute("SELECT rule_id, target, enabled, reason, actor, updated_at FROM detect_rule_overrides "
                            "ORDER BY rule_id, target").fetchall()
    finally:
        conn.close()
    return [Override(r[0], r[1], bool(r[2]), r[3], r[4], r[5]) for r in rows]


def disabled_rules(data_dir: Path | str, target: str) -> set[str]:
    """Rules turned off for `target`: off everywhere unless turned back on for it, or off for it."""
    key = target_key(target)
    everywhere: dict[str, bool] = {}
    here: dict[str, bool] = {}
    for o in overrides(data_dir):
        if o.target == EVERYWHERE:
            everywhere[o.rule_id] = o.enabled
        elif o.target == key:
            here[o.rule_id] = o.enabled
    out = {rid for rid, on in everywhere.items() if not on}
    out |= {rid for rid, on in here.items() if not on}
    out -= {rid for rid, on in here.items() if on}
    return out


def disabled_everywhere(data_dir: Path | str) -> set[str]:
    """Rules turned off for every machine ('*')."""
    return {o.rule_id for o in overrides(data_dir) if o.target == EVERYWHERE and not o.enabled}


def record_own_session(data_dir: Path | str, target: str, session: str, *, now: float | None = None) -> None:
    """Kratos's own SSH login on `target` has audit session id `session` (read on the machine
    from /proc/self/sessionid over Kratos's own connection: detect/own.py)."""
    now = time.time() if now is None else now
    conn = _connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO detect_own_sessions (target, session, first_seen, last_seen) VALUES (?,?,?,?) "
                     "ON CONFLICT(target, session) DO UPDATE SET last_seen = excluded.last_seen",
                     (target_key(target), str(session), now, now))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def own_sessions_recorded(data_dir: Path | str, target: str, *, since: float,
                          slack: float = 600.0) -> dict[str, list[tuple[float, float]]]:
    """{session: [(from, to)]} -- when each recorded id was Kratos's, widened by `slack` (the
    ids were read on Kratos's clock; events carry the machine's)."""
    conn = _connect(data_dir)
    try:
        rows = conn.execute("SELECT session, first_seen, last_seen FROM detect_own_sessions WHERE target = ? "
                            "AND last_seen >= ?", (target_key(target), since)).fetchall()
    finally:
        conn.close()
    out: dict[str, list[tuple[float, float]]] = {}
    for ses, first, last in rows:
        out.setdefault(str(ses), []).append((float(first) - slack, float(last) + slack))
    return out

"""Finding records, their history, and people's decisions -- in kratos.db.

- `finding_records`: one row per finding (rule × machine × subject): its state,
  latest copy, first/last seen. Updated in place every run that sees it; no
  per-run "seen" rows.
- `finding_events`: append-only history of transitions (a trigger aborts any
  UPDATE). Every row says who (a person, or "kratos" for the automatic moves),
  through which interface, why, and in which run.
- `finding_exceptions`: decisions (risk accepted / false positive / out of
  scope) at one of three scopes -- this finding, this rule on this machine,
  this rule everywhere -- with what the person saw (severity, entities).
- `finding_imports`: report files already accounted for (imported once from
  history, or written with lifecycle data).

Nothing here deletes anything. The legacy table named `findings` belongs to
AnomalyStore; it is never touched.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "lifecycle"

STATES = ("open", "verified", "mitigated", "inactive", "risk_accepted", "false_positive", "out_of_scope")
DECIDED = frozenset({"risk_accepted", "false_positive", "out_of_scope"})
SHOWN_BY_DEFAULT = frozenset({"open", "verified"})
EXCEPTION_KINDS = ("risk_accepted", "false_positive", "out_of_scope")
SCOPES = ("key", "rule_target", "rule")
EVENT_KINDS = ("created", "state_changed", "reopened", "severity_changed", "entities_changed", "expired", "imported")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_records (
          finding_key TEXT PRIMARY KEY,
          rule_id TEXT NOT NULL, target TEXT NOT NULL, subject TEXT NOT NULL,
          kind TEXT NOT NULL,                        -- condition | occurrence
          state TEXT NOT NULL,
          severity TEXT NOT NULL, title TEXT NOT NULL,
          entities TEXT NOT NULL,                    -- JSON list, latest seen
          latest TEXT NOT NULL,                      -- JSON of the latest finding dict
          first_seen REAL NOT NULL, last_seen REAL NOT NULL,
          last_checked REAL,                         -- last run that covered this rule
          last_run_id TEXT, times_seen INTEGER NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS finding_records_target ON finding_records(target, state)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_events (
          id INTEGER PRIMARY KEY,
          finding_key TEXT NOT NULL REFERENCES finding_records(finding_key),
          at REAL NOT NULL, kind TEXT NOT NULL,
          from_state TEXT, to_state TEXT,
          actor TEXT NOT NULL,
          interface TEXT,
          reason TEXT, run_id TEXT, details TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS finding_events_key ON finding_events(finding_key, at)")
    conn.execute("CREATE INDEX IF NOT EXISTS finding_events_run ON finding_events(run_id)")
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS finding_events_append_only BEFORE UPDATE ON finding_events "
        "BEGIN SELECT RAISE(ABORT, 'finding_events is append-only'); END"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_exceptions (
          id INTEGER PRIMARY KEY,
          scope TEXT NOT NULL,                       -- key | rule_target | rule
          finding_key TEXT, rule_id TEXT NOT NULL, target TEXT,
          kind TEXT NOT NULL,                        -- risk_accepted | false_positive | out_of_scope
          owner TEXT, reason TEXT NOT NULL,
          decided_severity TEXT NOT NULL, decided_entities TEXT NOT NULL,
          created_at REAL NOT NULL, created_by TEXT NOT NULL,
          expires_at REAL, revoked_at REAL, revoked_by TEXT, revoke_reason TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS finding_exceptions_rule ON finding_exceptions(rule_id, scope)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_imports (
          report_name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, imported_at REAL NOT NULL, target TEXT
        )
        """
    )


STEPS = (_step_1,)


def db_path(data_dir: Path) -> Path:
    return Path(data_dir) / "kratos.db"


def connect(data_dir: Path) -> sqlite3.Connection:
    path = db_path(data_dir)
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def immediate(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """A BEGIN IMMEDIATE transaction: the TUI, scheduled runs and the MCP server
    write the same database from separate processes."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def add_event(conn: sqlite3.Connection, key: str, *, at: float, kind: str, actor: str,
              from_state: str | None = None, to_state: str | None = None, interface: str | None = None,
              reason: str | None = None, run_id: str | None = None,
              details: dict[str, Any] | None = None) -> None:
    if kind not in EVENT_KINDS:
        raise ValueError(f"unknown finding event kind {kind!r}")
    conn.execute(
        "INSERT INTO finding_events (finding_key, at, kind, from_state, to_state, actor, interface, reason, run_id,"
        " details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (key, at, kind, from_state, to_state, actor, interface, reason, run_id,
         json.dumps(details, sort_keys=True) if details else None),
    )


def get_record(conn: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM finding_records WHERE finding_key = ?", (key,)).fetchone()


def set_state(conn: sqlite3.Connection, key: str, state: str) -> None:
    if state not in STATES:
        raise ValueError(f"unknown finding state {state!r}")
    conn.execute("UPDATE finding_records SET state = ? WHERE finding_key = ?", (state, key))


def events_for(conn: sqlite3.Connection, key: str) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM finding_events WHERE finding_key = ? ORDER BY at, id", (key,)).fetchall()


def resolve_key(conn: sqlite3.Connection, key_or_prefix: str) -> str:
    """The full key for a full key or a unique prefix (the 12 characters shown)."""
    text = str(key_or_prefix or "").strip().lower()
    if not text or any(c not in "0123456789abcdef" for c in text):
        raise LookupError(f"not a finding key: {key_or_prefix!r}")
    rows = conn.execute("SELECT finding_key FROM finding_records WHERE finding_key LIKE ? LIMIT 2",
                        (text + "%",)).fetchall()
    if not rows:
        raise LookupError(f"no finding with key {key_or_prefix!r}")
    if len(rows) > 1:
        raise LookupError(f"key {key_or_prefix!r} matches more than one finding -- give more characters")
    return rows[0][0]


def release_time(conn: sqlite3.Connection, key: str) -> float:
    """When this finding last stopped being covered by a decision: it reopened or a
    decision expired, or a person moved it back to open/verified. A decision made
    before that moment no longer applies to it (a newer decision does)."""
    row = conn.execute(
        "SELECT MAX(at) FROM finding_events WHERE finding_key = ? AND (kind IN ('reopened', 'expired') OR "
        "(kind = 'state_changed' AND actor != 'kratos' AND to_state IN ('open', 'verified')))",
        (key,),
    ).fetchone()
    return float(row[0]) if row and row[0] is not None else float("-inf")


def _scope_match(scope: str) -> str:
    return {"key": "finding_key = :key", "rule_target": "rule_id = :rule AND target = :target",
            "rule": "rule_id = :rule"}[scope]


def applicable_exception(conn: sqlite3.Connection, *, key: str, rule_id: str, target: str,
                         now: float) -> sqlite3.Row | None:
    """The decision that applies to a finding: the newest active one (not expired,
    not revoked, made after the finding was last released), checked in order this
    finding -> this rule on this machine -> this rule everywhere."""
    released = release_time(conn, key)
    params = {"key": key, "rule": rule_id, "target": target, "now": now, "released": released}
    for scope in SCOPES:
        row = conn.execute(
            f"SELECT * FROM finding_exceptions WHERE scope = '{scope}' AND {_scope_match(scope)} "
            "AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now) AND created_at > :released "
            "ORDER BY created_at DESC, id DESC LIMIT 1", params,
        ).fetchone()
        if row is not None:
            return row
    return None


def expired_exception(conn: sqlite3.Connection, *, key: str, rule_id: str, target: str,
                      now: float) -> sqlite3.Row | None:
    """The newest decision for this finding that ran out (not revoked) since it was last released."""
    released = release_time(conn, key)
    params = {"key": key, "rule": rule_id, "target": target, "now": now, "released": released}
    clauses = " OR ".join(f"(scope = '{s}' AND {_scope_match(s)})" for s in SCOPES)
    return conn.execute(
        f"SELECT * FROM finding_exceptions WHERE ({clauses}) AND revoked_at IS NULL AND expires_at IS NOT NULL "
        "AND expires_at <= :now AND created_at > :released ORDER BY expires_at DESC, id DESC LIMIT 1", params,
    ).fetchone()


def covers(exception: sqlite3.Row, *, severity: str, entities: list[str]) -> tuple[bool, str | None]:
    """Whether a decision still covers what the finding shows now: nothing it names
    that the person didn't see, and no higher severity. Counts changing don't
    matter. Returns (covers, why not)."""
    decided = set(json.loads(exception["decided_entities"] or "[]"))
    new = sorted(set(entities) - decided)
    if new:
        return False, "new " + ("entities" if len(new) > 1 else "entity") + " not covered by the decision: " + \
            ", ".join(new[:10]) + (f" (+{len(new) - 10} more)" if len(new) > 10 else "")
    was, now_sev = str(exception["decided_severity"]).lower(), str(severity).lower()
    if SEVERITY_RANK.get(now_sev, 0) > SEVERITY_RANK.get(was, 0):
        return False, f"severity rose from {was} to {now_sev} since the decision"
    return True, None


def record_import(conn: sqlite3.Connection, name: str, sha256: str, at: float, target: str | None) -> None:
    conn.execute("INSERT OR IGNORE INTO finding_imports (report_name, sha256, imported_at, target) "
                 "VALUES (?, ?, ?, ?)", (name, sha256, at, target))


def list_records(conn: sqlite3.Connection, *, target: str | None = None, states: set[str] | None = None,
                 limit: int | None = None) -> list[sqlite3.Row]:
    sql = "SELECT * FROM finding_records"
    where, params = [], []
    if target:
        where.append("target = ?")
        params.append(target)
    if states:
        where.append(f"state IN ({','.join('?' * len(states))})")
        params.extend(sorted(states))
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY last_seen DESC, finding_key"
    if limit:
        sql += f" LIMIT {int(limit)}"
    return conn.execute(sql, params).fetchall()


def decision_of(conn: sqlite3.Connection, record: sqlite3.Row, now: float) -> sqlite3.Row | None:
    """The decision behind a decided record (None for any other state)."""
    if record["state"] not in DECIDED:
        return None
    return applicable_exception(conn, key=record["finding_key"], rule_id=record["rule_id"],
                                target=record["target"], now=now)

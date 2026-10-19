"""Where verdicts and the model's suggestions are kept -- in kratos.db.

- `finding_verdicts`: one row per verification (append-only history; the newest
  per finding is what's shown). No lifecycle state lives here -- a verdict is a
  separate thing a person reads (docs/phaseB/B.1 §3.1, §3.7).
- `finding_suggestions`: the model's own notes about a finding ("looks like a
  false positive", "lower severity"), labelled as the model's suggestion.
  Sanitised like recommended_commands before they ever get here. A person
  accepts (through the normal people-only decision path) or dismisses one; the
  model can never act on its own suggestion (§3.6).

Nothing here deletes anything (Phase B: history is kept). The legacy table named
`findings` belongs to AnomalyStore; it is never touched.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.triage.verdict import Verdict, VerdictResult, VerifyCheck

COMPONENT = "triage"
SUGGEST_KINDS = ("false_positive", "lower_severity", "needs_person")
SUGGEST_STATES = ("new", "accepted", "dismissed")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_verdicts (
          id INTEGER PRIMARY KEY,
          finding_key TEXT NOT NULL,
          run_id TEXT,
          at REAL NOT NULL,
          verdict TEXT NOT NULL,                     -- reproduced | partly | not_reproduced | couldnt_check | seen
          cost TEXT NOT NULL,                        -- quick | slow
          verifier TEXT NOT NULL,                    -- the verifier's label
          detail TEXT,                               -- the partly condition / couldnt_check reason
          sentence TEXT NOT NULL,
          checks TEXT NOT NULL,                      -- JSON list of {name, transport, read_seconds}
          evidence TEXT NOT NULL,                    -- JSON list of Kratos-written lines
          duration REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS finding_verdicts_key ON finding_verdicts(finding_key, at)")
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS finding_verdicts_append_only BEFORE UPDATE ON finding_verdicts "
        "BEGIN SELECT RAISE(ABORT, 'finding_verdicts is append-only'); END"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS finding_suggestions (
          id INTEGER PRIMARY KEY,
          finding_key TEXT,                          -- NULL only until matched; usually the resolved key
          rule_id TEXT NOT NULL,
          target TEXT,
          run_id TEXT,
          at REAL NOT NULL,
          kind TEXT NOT NULL,                        -- false_positive | lower_severity | needs_person
          why TEXT NOT NULL,                         -- one sentence, the model's words (sanitised)
          state TEXT NOT NULL DEFAULT 'new',         -- new | accepted | dismissed
          resolved_at REAL, resolved_by TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS finding_suggestions_key ON finding_suggestions(finding_key, at)")
    conn.execute("CREATE INDEX IF NOT EXISTS finding_suggestions_state ON finding_suggestions(state, at)")


def _step_2(conn: sqlite3.Connection) -> None:
    # What the verdict was judged against: 'second_read' (recheck, retest, a slow
    # verifier) or 'this_run' (the automatic pass, against the read that raised it --
    # never "reproduced"). Rows before this step came from either; second_read is the
    # conservative default only because a this_run row could never hold that word now.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(finding_verdicts)")}
    if "basis" not in cols:
        conn.execute("ALTER TABLE finding_verdicts ADD COLUMN basis TEXT NOT NULL DEFAULT 'second_read'")


STEPS = (_step_1, _step_2)


def _connect(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


# --------------------------------------------------------------------------- verdicts
def record_verdict(data_dir: Path, *, finding_key: str, verdict: Verdict, verifier: str, cost: str,
                   run_id: str | None, duration: float, now: float | None = None) -> None:
    now = time.time() if now is None else now
    checks = json.dumps([{"name": c.name, "transport": c.transport, "read_seconds": round(c.read_seconds, 2)}
                         for c in verdict.checks])
    conn = _connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO finding_verdicts (finding_key, run_id, at, verdict, cost, verifier, detail, sentence, "
            "checks, evidence, duration, basis) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding_key, run_id, now, verdict.verdict, cost, verifier, verdict.detail or None, verdict.sentence,
             checks, json.dumps(list(verdict.evidence)), float(duration), verdict.basis),
        )
        conn.execute("COMMIT")
    finally:
        conn.close()


def _verdict_from_row(row: sqlite3.Row) -> VerdictResult:
    checks = tuple(VerifyCheck(name=str(c.get("name") or ""), transport=str(c.get("transport") or ""),
                               read_seconds=float(c.get("read_seconds") or 0.0))
                   for c in json.loads(row["checks"] or "[]"))
    basis = row["basis"] if "basis" in row.keys() else "second_read"
    v = Verdict(verdict=row["verdict"], sentence=row["sentence"] or "", checks=checks,
                evidence=tuple(json.loads(row["evidence"] or "[]")), detail=row["detail"] or "",
                basis=basis or "second_read")
    return VerdictResult(finding_key=row["finding_key"], verdict=v, verifier=row["verifier"],
                         cost=row["cost"], run_id=row["run_id"], at=float(row["at"]),
                         duration=float(row["duration"]))


def latest_verdict(data_dir: Path, finding_key: str) -> VerdictResult | None:
    conn = _connect(data_dir)
    try:
        row = conn.execute("SELECT * FROM finding_verdicts WHERE finding_key = ? ORDER BY at DESC, id DESC LIMIT 1",
                           (finding_key,)).fetchone()
    finally:
        conn.close()
    return _verdict_from_row(row) if row is not None else None


def latest_verdicts(data_dir: Path, keys: list[str]) -> dict[str, VerdictResult]:
    """The newest verdict for each of `keys` (missing keys are absent)."""
    out: dict[str, VerdictResult] = {}
    if not keys:
        return out
    conn = _connect(data_dir)
    try:
        for k in keys:
            row = conn.execute("SELECT * FROM finding_verdicts WHERE finding_key = ? ORDER BY at DESC, id DESC "
                               "LIMIT 1", (k,)).fetchone()
            if row is not None:
                out[k] = _verdict_from_row(row)
    finally:
        conn.close()
    return out


def verdict_history(data_dir: Path, finding_key: str, limit: int = 20) -> list[VerdictResult]:
    conn = _connect(data_dir)
    try:
        rows = conn.execute("SELECT * FROM finding_verdicts WHERE finding_key = ? ORDER BY at DESC, id DESC LIMIT ?",
                            (finding_key, int(limit))).fetchall()
    finally:
        conn.close()
    return [_verdict_from_row(r) for r in rows]


# --------------------------------------------------------------------------- suggestions
def record_suggestion(data_dir: Path, *, finding_key: str | None, rule_id: str, target: str | None,
                      run_id: str | None, kind: str, why: str, now: float | None = None) -> int:
    if kind not in SUGGEST_KINDS:
        raise ValueError(f"unknown suggestion kind {kind!r}; expected one of {SUGGEST_KINDS}")
    now = time.time() if now is None else now
    conn = _connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "INSERT INTO finding_suggestions (finding_key, rule_id, target, run_id, at, kind, why, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'new')",
            (finding_key, rule_id, target, run_id, now, kind, why),
        )
        conn.execute("COMMIT")
        return int(cur.lastrowid)
    finally:
        conn.close()


def _suggestion_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "finding_key": row["finding_key"], "rule_id": row["rule_id"],
            "target": row["target"], "run_id": row["run_id"], "at": float(row["at"]), "kind": row["kind"],
            "why": row["why"], "state": row["state"], "resolved_at": row["resolved_at"],
            "resolved_by": row["resolved_by"]}


def suggestions_for(data_dir: Path, finding_key: str, *, state: str | None = "new") -> list[dict[str, Any]]:
    conn = _connect(data_dir)
    try:
        sql = "SELECT * FROM finding_suggestions WHERE finding_key = ?"
        params: list[Any] = [finding_key]
        if state:
            sql += " AND state = ?"
            params.append(state)
        rows = conn.execute(sql + " ORDER BY at DESC, id DESC", params).fetchall()
    finally:
        conn.close()
    return [_suggestion_dict(r) for r in rows]


def open_suggestions(data_dir: Path, *, target: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    conn = _connect(data_dir)
    try:
        sql = "SELECT * FROM finding_suggestions WHERE state = 'new'"
        params: list[Any] = []
        if target:
            sql += " AND target = ?"
            params.append(target)
        rows = conn.execute(sql + " ORDER BY at DESC, id DESC LIMIT ?", params + [int(limit)]).fetchall()
    finally:
        conn.close()
    return [_suggestion_dict(r) for r in rows]


def get_suggestion(data_dir: Path, suggestion_id: int) -> dict[str, Any] | None:
    conn = _connect(data_dir)
    try:
        row = conn.execute("SELECT * FROM finding_suggestions WHERE id = ?", (int(suggestion_id),)).fetchone()
    finally:
        conn.close()
    return _suggestion_dict(row) if row is not None else None


def resolve_suggestion(data_dir: Path, suggestion_id: int, *, state: str, by: str,
                       now: float | None = None) -> None:
    """Mark a suggestion accepted or dismissed. Accepting the *decision* a suggestion
    points at is a separate, people-only step (kratos.lifecycle.decide); this only
    records what happened to the suggestion itself."""
    if state not in ("accepted", "dismissed"):
        raise ValueError(f"a suggestion can be accepted or dismissed, not {state!r}")
    now = time.time() if now is None else now
    conn = _connect(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE finding_suggestions SET state = ?, resolved_at = ?, resolved_by = ? WHERE id = ?",
                     (state, now, by, int(suggestion_id)))
        conn.execute("COMMIT")
    finally:
        conn.close()

"""Review tables in kratos.db (E.7b §5.2).

- ``review_runs``        one row per review: machine, root, the hunter and verifier profiles,
                        where the code went, the masking mode, the estimate / agreed / actual
                        cost and who raised the ceiling, reproduction on/off, who started it,
                        state, the stop reason and the per-run counts for REVIEW-003.
- ``review_slices``     the slices a run looked at: both hashes, file, span, function, class,
                        exposure, drift, served, part, and the coverage-ledger state.
- ``review_candidates`` the leads a run raised: slice, class, file, line, the model's reason
                        (<= 500 chars, secrets removed), the call ids, the source.
- ``review_verdicts``   THE CACHE, per Kratos (not per machine -- the same deployed code on a
                        fleet is reviewed once): the cache key and its parts, the verdict and
                        strength, code-owned evidence, the open question or disproof, the fix
                        words + only the added lines, the fix check, the model ids, decided_at.

File CONTENTS are never stored here or anywhere (§11): only hashes, line numbers, findings,
leads, verdicts and the few lines a model-written fix adds. Keyed by ``target_key`` except the
cache. Inventoried (B.5) with backup class ``include``; ``data_dir/.review-work/`` is scratch,
never backed up, and is in the no-automatic-deletion scan with its reason.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store, write_transaction

COMPONENT = "review"
TABLES = ("review_runs", "review_slices", "review_candidates", "review_verdicts")
RUN_STATES = ("preparing", "running", "done", "stopped", "incomplete", "error")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS review_runs (
          id INTEGER PRIMARY KEY,
          target_key TEXT NOT NULL,
          machine TEXT NOT NULL DEFAULT '',
          root TEXT NOT NULL,
          profile TEXT NOT NULL DEFAULT '',
          verifier_profile TEXT NOT NULL DEFAULT '',
          destination TEXT NOT NULL DEFAULT '',      -- 'hosted' | 'local' (for REVIEW-003 / consent)
          mask_mode TEXT NOT NULL DEFAULT '',
          estimate_usd REAL NOT NULL DEFAULT 0,
          agreed_usd REAL NOT NULL DEFAULT 0,
          actual_usd REAL NOT NULL DEFAULT 0,
          est_calls INTEGER NOT NULL DEFAULT 0,
          est_tokens INTEGER NOT NULL DEFAULT 0,
          reproduction INTEGER NOT NULL DEFAULT 0,   -- 1 = sandbox reproduction available this run
          raised_by TEXT NOT NULL DEFAULT '',        -- who raised the ceiling (gate answer 2)
          raised_to REAL,
          started_by TEXT,
          interface TEXT,
          user_id TEXT,
          state TEXT NOT NULL DEFAULT 'preparing',
          stop_reason TEXT NOT NULL DEFAULT '',
          logic_version TEXT NOT NULL DEFAULT '',
          counts TEXT NOT NULL DEFAULT '{}',         -- JSON, the REVIEW-003 tallies
          started_at REAL NOT NULL,
          finished_at REAL
        )
        """)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS review_slices (
          id INTEGER PRIMARY KEY,
          run_id INTEGER NOT NULL,
          target_key TEXT NOT NULL,
          slice_sha TEXT NOT NULL,
          context_sha TEXT NOT NULL,
          file TEXT NOT NULL,
          span_start INTEGER NOT NULL,
          span_end INTEGER NOT NULL,
          function TEXT NOT NULL,
          class TEXT NOT NULL,
          exposure TEXT NOT NULL DEFAULT 'unknown',
          drift INTEGER NOT NULL DEFAULT 0,
          served TEXT NOT NULL DEFAULT 'imported',
          part INTEGER NOT NULL DEFAULT 0,
          nbytes INTEGER NOT NULL DEFAULT 0,
          language TEXT NOT NULL DEFAULT 'python',
          ledger_state TEXT NOT NULL DEFAULT 'looked_at'
        )
        """)
    conn.execute("CREATE INDEX IF NOT EXISTS review_slices_run ON review_slices (run_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS review_candidates (
          id INTEGER PRIMARY KEY,
          run_id INTEGER NOT NULL,
          slice_sha TEXT NOT NULL,
          class TEXT NOT NULL,
          file TEXT NOT NULL,
          line INTEGER NOT NULL DEFAULT 0,
          reason TEXT NOT NULL DEFAULT '',           -- <= 500 chars, secrets removed
          call_ids TEXT NOT NULL DEFAULT '[]',
          source TEXT NOT NULL DEFAULT 'hunter',
          at REAL NOT NULL
        )
        """)
    conn.execute("CREATE INDEX IF NOT EXISTS review_candidates_run ON review_candidates (run_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS review_verdicts (
          id INTEGER PRIMARY KEY,
          cache_key TEXT NOT NULL UNIQUE,            -- slice+context+class+logic (+model ids when model-derived)
          slice_sha TEXT NOT NULL,
          context_sha TEXT NOT NULL,
          class TEXT NOT NULL,
          logic_version TEXT NOT NULL DEFAULT '',
          hunter_model TEXT NOT NULL DEFAULT '',
          verifier_model TEXT NOT NULL DEFAULT '',
          verdict TEXT NOT NULL,                     -- confirmed | needs_validation | rejected
          strength TEXT NOT NULL DEFAULT '',         -- reproduced | direct | ''
          evidence TEXT NOT NULL DEFAULT '',         -- code-owned; never model free text
          question TEXT NOT NULL DEFAULT '',         -- open question (needs_validation) or disproof (rejected)
          fix_words TEXT NOT NULL DEFAULT '',        -- the model's words for the fix (<= 500)
          fix_added TEXT NOT NULL DEFAULT '',        -- ONLY the lines the patch adds (<= 40), never machine lines
          fix_check TEXT NOT NULL DEFAULT '',        -- 'checked' | 'not_confirmed' | 'not_checked' | ''
          decided_at REAL NOT NULL
        )
        """)


def _step_2(conn: sqlite3.Connection) -> None:
    # E.7b B.1 verifier: the surface file's E.7a inventory hash at review time, so the verifier
    # can tell "code unchanged since review" from "code changed, review it again" with no new read.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(review_slices)")}
    if "file_sha" not in cols:
        conn.execute("ALTER TABLE review_slices ADD COLUMN file_sha TEXT NOT NULL DEFAULT ''")


STEPS = (_step_1, _step_2)


def connect(data_dir: Path | str) -> sqlite3.Connection:
    db = Path(data_dir) / "kratos.db"
    conn = connect_store(db)
    try:
        migrate_once(conn, db, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    conn.row_factory = sqlite3.Row
    return conn


_tx = write_transaction


def _exists(data_dir: Path | str) -> bool:
    return (Path(data_dir) / "kratos.db").exists()


# --------------------------------------------------------------------------- runs
def create_run(data_dir: Path | str, *, target_key: str, machine: str, root: str, profile: str,
               verifier_profile: str, destination: str, mask_mode: str, estimate_usd: float, agreed_usd: float,
               est_calls: int, est_tokens: int, reproduction: bool, logic_version: str, actor: Any = None,
               raised_by: str = "", raised_to: float | None = None, now: float | None = None) -> int:
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        with _tx(conn):
            cur = conn.execute(
                "INSERT INTO review_runs (target_key, machine, root, profile, verifier_profile, destination, "
                "mask_mode, estimate_usd, agreed_usd, est_calls, est_tokens, reproduction, raised_by, raised_to, "
                "started_by, interface, user_id, state, logic_version, started_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target_key, machine, root, profile, verifier_profile, destination, mask_mode, float(estimate_usd),
                 float(agreed_usd), int(est_calls), int(est_tokens), 1 if reproduction else 0, raised_by,
                 raised_to, getattr(actor, "user", None), getattr(actor, "interface", None),
                 getattr(actor, "user_id", None), "running", logic_version, now))
            return int(cur.lastrowid)
    finally:
        conn.close()


def finish_run(data_dir: Path | str, run_id: int, *, state: str, stop_reason: str = "", actual_usd: float | None = None,
               counts: dict[str, Any] | None = None, now: float | None = None) -> None:
    if state not in RUN_STATES:
        raise ValueError(state)
    conn = connect(data_dir)
    try:
        with _tx(conn):
            sets = ["state = ?", "stop_reason = ?", "finished_at = ?"]
            args: list[Any] = [state, stop_reason, time.time() if now is None else now]
            if actual_usd is not None:
                sets.append("actual_usd = ?")
                args.append(float(actual_usd))
            if counts is not None:
                sets.append("counts = ?")
                args.append(json.dumps(counts, ensure_ascii=True))
            args.append(int(run_id))
            conn.execute(f"UPDATE review_runs SET {', '.join(sets)} WHERE id = ?", args)
    finally:
        conn.close()


def set_actual(data_dir: Path | str, run_id: int, actual_usd: float) -> None:
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.execute("UPDATE review_runs SET actual_usd = ? WHERE id = ?", (float(actual_usd), int(run_id)))
    finally:
        conn.close()


def _run(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["counts"] = json.loads(d.get("counts") or "{}")
    except ValueError:
        d["counts"] = {}
    return d


def get_run(data_dir: Path | str, run_id: int) -> dict[str, Any] | None:
    if not _exists(data_dir):
        return None
    conn = connect(data_dir)
    try:
        row = conn.execute("SELECT * FROM review_runs WHERE id = ?", (int(run_id),)).fetchone()
        return _run(row) if row else None
    finally:
        conn.close()


def runs(data_dir: Path | str, target_key: str | None = None, *, root: str | None = None,
         limit: int = 100) -> list[dict[str, Any]]:
    if not _exists(data_dir):
        return []
    conn = connect(data_dir)
    try:
        q = "SELECT * FROM review_runs"
        where, args = [], []
        if target_key is not None:
            where.append("target_key = ?")
            args.append(target_key)
        if root is not None:
            where.append("root = ?")
            args.append(root)
        if where:
            q += " WHERE " + " AND ".join(where)
        q += " ORDER BY started_at DESC LIMIT ?"
        args.append(int(limit))
        return [_run(r) for r in conn.execute(q, args)]
    finally:
        conn.close()


def mark_stale_running(data_dir: Path | str, *, now: float | None = None) -> None:
    """A run left `running` by a restart is `incomplete` (§6: verdicts and cost kept, re-runnable)."""
    if not _exists(data_dir):
        return
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.execute("UPDATE review_runs SET state = 'incomplete', finished_at = ? WHERE state = 'running'",
                         (time.time() if now is None else now,))
    finally:
        conn.close()


# --------------------------------------------------------------------------- slices and candidates
def add_slices(data_dir: Path | str, run_id: int, target_key: str, rows: Iterable[dict[str, Any]]) -> None:
    rows = list(rows)
    if not rows:
        return
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.executemany(
                "INSERT INTO review_slices (run_id, target_key, slice_sha, context_sha, file, span_start, "
                "span_end, function, class, exposure, drift, served, part, nbytes, language, ledger_state, file_sha) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(int(run_id), target_key, r["slice_sha"], r["context_sha"], r["file"], int(r["span"][0]),
                  int(r["span"][1]), r["function"], r["class"], r.get("exposure", "unknown"),
                  1 if r.get("drift") else 0, r.get("served", "imported"), int(r.get("part", 0)),
                  int(r.get("nbytes", 0)), r.get("language", "python"), r.get("ledger_state", "looked_at"),
                  r.get("file_sha", ""))
                 for r in rows])
    finally:
        conn.close()


def set_ledger_state(data_dir: Path | str, run_id: int, slice_sha: str, cls: str, state: str) -> None:
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.execute("UPDATE review_slices SET ledger_state = ? WHERE run_id = ? AND slice_sha = ? AND class = ?",
                         (state, int(run_id), slice_sha, cls))
    finally:
        conn.close()


def slices(data_dir: Path | str, run_id: int) -> list[dict[str, Any]]:
    if not _exists(data_dir):
        return []
    conn = connect(data_dir)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM review_slices WHERE run_id = ? ORDER BY id",
                                              (int(run_id),))]
    finally:
        conn.close()


def latest_slice_by_prefix(data_dir: Path | str, sha_prefix: str) -> dict[str, Any] | None:
    """The most-recent review_slices row whose slice_sha starts with `sha_prefix` (the finding
    entity carries a 16-char prefix), for the B.1 verifier. None when nothing matches."""
    if not _exists(data_dir) or not sha_prefix:
        return None
    conn = connect(data_dir)
    try:
        row = conn.execute("SELECT s.*, r.root AS run_root FROM review_slices s JOIN review_runs r "
                           "ON r.id = s.run_id WHERE s.slice_sha LIKE ? ORDER BY s.run_id DESC LIMIT 1",
                           (sha_prefix + "%",)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def add_candidate(data_dir: Path | str, run_id: int, *, slice_sha: str, cls: str, file: str, line: int,
                  reason: str, call_ids: list[str], source: str = "hunter", now: float | None = None) -> None:
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.execute(
                "INSERT INTO review_candidates (run_id, slice_sha, class, file, line, reason, call_ids, source, at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (int(run_id), slice_sha, cls, file, int(line), str(reason)[:500],
                 json.dumps(list(call_ids), ensure_ascii=True), source, time.time() if now is None else now))
    finally:
        conn.close()


def candidates(data_dir: Path | str, run_id: int) -> list[dict[str, Any]]:
    if not _exists(data_dir):
        return []
    conn = connect(data_dir)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM review_candidates WHERE run_id = ? ORDER BY id",
                                              (int(run_id),))]
    finally:
        conn.close()


# --------------------------------------------------------------------------- verdicts (the cache)
def get_verdict(data_dir: Path | str, cache_key: str) -> dict[str, Any] | None:
    if not _exists(data_dir):
        return None
    conn = connect(data_dir)
    try:
        row = conn.execute("SELECT * FROM review_verdicts WHERE cache_key = ?", (cache_key,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def put_verdict(data_dir: Path | str, *, cache_key: str, slice_sha: str, context_sha: str, cls: str,
                logic_version: str, hunter_model: str, verifier_model: str, verdict: str, strength: str,
                evidence: str, question: str, fix_words: str = "", fix_added: str = "", fix_check: str = "",
                now: float | None = None) -> None:
    """Store (or replace) one cached verdict. Idempotent on the cache key."""
    conn = connect(data_dir)
    try:
        with _tx(conn):
            conn.execute(
                "INSERT INTO review_verdicts (cache_key, slice_sha, context_sha, class, logic_version, "
                "hunter_model, verifier_model, verdict, strength, evidence, question, fix_words, fix_added, "
                "fix_check, decided_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(cache_key) DO UPDATE SET verdict=excluded.verdict, strength=excluded.strength, "
                "evidence=excluded.evidence, question=excluded.question, fix_words=excluded.fix_words, "
                "fix_added=excluded.fix_added, fix_check=excluded.fix_check, decided_at=excluded.decided_at",
                (cache_key, slice_sha, context_sha, cls, logic_version, hunter_model, verifier_model, verdict,
                 strength, str(evidence)[:2000], str(question)[:500], str(fix_words)[:500], str(fix_added)[:4000],
                 fix_check, time.time() if now is None else now))
    finally:
        conn.close()

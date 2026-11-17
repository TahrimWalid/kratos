"""What the agent doors keep -- `a2a_tasks` in kratos.db (docs/phaseE/E.5 §5).

One row per A2A task and per AG-UI run: its id, the person (user id) and token that
started it, the door, the skill, the machine or group, its A2A state, the run and session
it maps to, when it started and finished, the plain reason for a rejection or failure,
and the result as the caller was given it (the answer Markdown and the findings data,
capped at RESULT_MAX bytes). Never the token, never the question text -- that is in the
session's transcript like every other question.

A task id belongs to the person who started it: every read here takes the user id, and a
task of someone else is "not found". Rows are kept (personal data, `kratos data prune
--category agent_tasks` removes finished ones); nothing is deleted automatically.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "a2a"
DOORS = ("a2a", "agui")
STATES = ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED", "TASK_STATE_FAILED",
          "TASK_STATE_CANCELED", "TASK_STATE_REJECTED")
TERMINAL = frozenset({"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"})
RESULT_MAX = 2_000_000


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS a2a_tasks (
          task_id TEXT PRIMARY KEY,
          context_id TEXT NOT NULL,
          door TEXT NOT NULL,                  -- a2a | agui
          user_id TEXT NOT NULL,               -- the person who started it (D.7)
          token_id TEXT NOT NULL,
          skill TEXT NOT NULL,
          target TEXT NOT NULL DEFAULT '',     -- the machine or '@group' (as the caller may see it)
          state TEXT NOT NULL,
          run_id TEXT,
          session_id TEXT,
          created REAL NOT NULL,
          updated REAL NOT NULL,
          finished REAL,
          reason TEXT,                         -- a plain reason for REJECTED / FAILED / CANCELED
          result TEXT                          -- JSON: {"text": markdown, "data": {...}} as the caller got it
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS a2a_tasks_user ON a2a_tasks(user_id, created)")
    conn.execute("CREATE INDEX IF NOT EXISTS a2a_tasks_open ON a2a_tasks(user_id, state)")


STEPS = (_step_1,)


def connect(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


def _row(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    try:
        d["result"] = json.loads(d["result"]) if d.get("result") else None
    except ValueError:
        d["result"] = None
    return d


def _result_text(result: dict[str, Any] | None) -> str | None:
    if result is None:
        return None
    text = json.dumps(result, ensure_ascii=False)
    if len(text.encode("utf-8")) > RESULT_MAX:
        text = json.dumps({"text": "(the result was too large to keep; it was sent to the caller once)", "data": {}})
    return text


def insert(data_dir: Path, *, task_id: str, context_id: str, door: str, user_id: str, token_id: str, skill: str,
           target: str, state: str, reason: str | None = None, result: dict[str, Any] | None = None,
           now: float | None = None) -> None:
    if door not in DOORS or state not in STATES:
        raise ValueError(f"bad task row ({door!r}, {state!r})")
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        conn.execute(
            "INSERT INTO a2a_tasks (task_id, context_id, door, user_id, token_id, skill, target, state, created, "
            "updated, finished, reason, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (task_id, context_id, door, user_id, token_id, skill, target[:300], state, now, now,
             now if state in TERMINAL else None, (reason or None) and reason[:500], _result_text(result)))
    finally:
        conn.close()


def update(data_dir: Path, task_id: str, *, state: str | None = None, run_id: str | None = None,
           session_id: str | None = None, reason: str | None = None, result: dict[str, Any] | None = None,
           now: float | None = None) -> bool:
    """Move a task on; False when it had already finished. A finished task never changes
    again (a late result after a cancel does not overwrite CANCELED): the terminal state,
    its reason and its result are written together, once."""
    if state is not None and state not in STATES:
        raise ValueError(f"unknown task state {state!r}")
    now = time.time() if now is None else now
    sets, args = ["updated = ?"], [now]
    if state is not None:
        sets.append("state = ?")
        args.append(state)
        if state in TERMINAL:
            sets.append("finished = COALESCE(finished, ?)")
            args.append(now)
    for col, val in (("run_id", run_id), ("session_id", session_id)):
        if val is not None:
            sets.append(f"{col} = ?")
            args.append(val)
    if reason is not None:
        sets.append("reason = ?")
        args.append(reason[:500])
    if result is not None:
        sets.append("result = ?")
        args.append(_result_text(result))
    conn = connect(data_dir)
    try:
        placeholders = ", ".join(sets)
        n = conn.execute(f"UPDATE a2a_tasks SET {placeholders} WHERE task_id = ? AND finished IS NULL",
                         (*args, task_id)).rowcount
    finally:
        conn.close()
    return bool(n)


def get(data_dir: Path, task_id: str, user_id: str) -> dict[str, Any] | None:
    """The task if it exists AND belongs to `user_id` -- otherwise None, the same answer
    whether it doesn't exist or is someone else's (no existence leak)."""
    conn = connect(data_dir)
    try:
        r = conn.execute("SELECT * FROM a2a_tasks WHERE task_id = ? AND user_id = ?",
                         (str(task_id), str(user_id))).fetchone()
    finally:
        conn.close()
    return _row(r) if r else None


def list_for(data_dir: Path, user_id: str, *, context_id: str | None = None, state: str | None = None,
             limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """(this person's tasks newest first, how many in all)."""
    where, args = ["user_id = ?"], [str(user_id)]
    if context_id:
        where.append("context_id = ?")
        args.append(context_id)
    if state:
        where.append("state = ?")
        args.append(state)
    clause = " AND ".join(where)
    conn = connect(data_dir)
    try:
        total = int(conn.execute(f"SELECT COUNT(*) FROM a2a_tasks WHERE {clause}", args).fetchone()[0])
        rows = conn.execute(f"SELECT * FROM a2a_tasks WHERE {clause} ORDER BY created DESC, task_id LIMIT ? OFFSET ?",
                            (*args, int(limit), int(offset))).fetchall()
    finally:
        conn.close()
    return [_row(r) for r in rows], total


def open_count(data_dir: Path, user_id: str) -> int:
    conn = connect(data_dir)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM a2a_tasks WHERE user_id = ? AND finished IS NULL",
                                (str(user_id),)).fetchone()[0])
    finally:
        conn.close()


def fail_unfinished(data_dir: Path, reason: str, now: float | None = None) -> int:
    """At server start: a task left unfinished by an earlier process can't still be running
    (runs are threads of the process that started them) -- it is FAILED with `reason`."""
    now = time.time() if now is None else now
    conn = connect(data_dir)
    try:
        return int(conn.execute("UPDATE a2a_tasks SET state = 'TASK_STATE_FAILED', reason = ?, updated = ?, "
                                "finished = ? WHERE finished IS NULL", (reason, now, now)).rowcount)
    finally:
        conn.close()

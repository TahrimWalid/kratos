"""
Interactive session (REPL) persistence -- Sprint 3, per
docs/sprint3_interactive_session_mode_design.md §6/§9.

SQLite, single local file (data_dir/kratos.db -- the same file
adapters/anomaly_store.py already uses under this data_dir, new tables
added alongside its existing ones rather than introducing a second DB
file), no auth, no server. Written continuously (after each turn/command,
not only on exit) so a crash or Ctrl+C never loses session state -- every
write here is its own committed transaction, nothing is buffered in
memory waiting for a clean shutdown that might not come.

Concurrency (§6, required verification, not assumed): WAL mode is enabled
on every connection, and every write goes through a single connection
opened with `isolation_level=None` (autocommit off, explicit BEGIN
IMMEDIATE/COMMIT per write) plus a real busy_timeout, so a second writer
hitting a locked database waits and retries rather than raising
"database is locked" immediately. See tests/test_session_store_concurrency.py
for the real two-process concurrent-write test this design doc requires.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

_BUSY_TIMEOUT_MS = 5000


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


class SessionStore:
    """SQLite-backed storage for interactive REPL sessions."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_schema()

    def _init_schema(self) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    last_active_at TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    model_backend TEXT,
                    status TEXT NOT NULL DEFAULT 'active'
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS goal_history (
                    turn_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL REFERENCES sessions(session_id),
                    seq INTEGER NOT NULL,
                    goal TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT,
                    transcript_ref TEXT,
                    archived_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_goal_history_session ON goal_history(session_id, seq)"
            )
            # Migration for a real pre-existing kratos.db created before
            # /reset and /delete existed (2026-07-17) -- CREATE TABLE IF NOT
            # EXISTS above doesn't add columns to an already-existing table.
            # Guarded on PRAGMA table_info so this is safe to run on every
            # SessionStore() construction, not just the first one against a
            # given file.
            existing_session_cols = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
            if "status" not in existing_session_cols:
                conn.execute("ALTER TABLE sessions ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
            if "name" not in existing_session_cols:
                # /rename (2026-07-18) -- nullable, no default: NULL means
                # "no custom name set", the common case, distinct from an
                # empty string (which /rename's own validation rejects
                # outright, see cli/repl.py).
                conn.execute("ALTER TABLE sessions ADD COLUMN name TEXT")
            existing_goal_cols = {r["name"] for r in conn.execute("PRAGMA table_info(goal_history)").fetchall()}
            if "archived_at" not in existing_goal_cols:
                conn.execute("ALTER TABLE goal_history ADD COLUMN archived_at TEXT")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def create_session(self, targets: list[str], model_backend: str) -> str:
        session_id = uuid.uuid4().hex[:12]
        now = datetime.now().isoformat(timespec="seconds")
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO sessions (session_id, created_at, last_active_at, targets, model_backend) "
                "VALUES (?, ?, ?, ?, ?)",
                (session_id, now, now, json.dumps(targets), model_backend),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return session_id

    def touch_session(self, session_id: str) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE sessions SET last_active_at = ? WHERE session_id = ?", (now, session_id))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def set_targets(self, session_id: str, targets: list[str]) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE sessions SET targets = ?, last_active_at = ? WHERE session_id = ?",
                (json.dumps(targets), datetime.now().isoformat(timespec="seconds"), session_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        d = dict(row)
        d["targets"] = json.loads(d["targets"])
        return d

    def get_session_by_name(self, name: str) -> dict[str, Any] | None:
        """/rename (2026-07-18) -- exact, case-sensitive match, same
        precision as get_session's exact-ID match. Searches ALL sessions
        (active AND archived), same scope as get_session -- a name is
        just an alternative identifier, not a status filter; the caller
        (cli/repl.py's ID-or-name resolution) auto-restores an archived
        match the same way an archived ID match already does."""
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM sessions WHERE name = ?", (name,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        d = dict(row)
        d["targets"] = json.loads(d["targets"])
        return d

    def name_taken(self, name: str, exclude_session_id: str | None = None) -> bool:
        """Uniqueness check for /rename -- a name that collides with
        another session's name would make --resume <name> ambiguous.
        exclude_session_id lets a session re-set its OWN existing name
        (a no-op rename) without tripping over itself."""
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT session_id FROM sessions WHERE name = ? AND session_id != ?",
                (name, exclude_session_id or ""),
            ).fetchone()
        finally:
            conn.close()
        return row is not None

    def rename_session(self, session_id: str, name: str) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE sessions SET name = ?, last_active_at = ? WHERE session_id = ?",
                (name, datetime.now().isoformat(timespec="seconds"), session_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def list_recent_sessions(self, limit: int = 10, offset: int = 0) -> list[dict[str, Any]]:
        """Most recent first, each annotated with its most recent NON-
        ARCHIVED goal (for the chooser's "goal snippet" column) -- a
        session with no (unarchived) turns yet, either genuinely new or
        because /reset just archived all its prior ones, gets goal=None,
        not an error. Archived sessions (/delete) are excluded here by
        design -- see list_archived_sessions for the recovery-path view.

        `offset` (real fix, 2026-07-17): lets the REPL chooser's "[m] more
        sessions" view page past the first CHOOSER_SESSION_LIMIT rows
        instead of a real session becoming permanently unreachable once
        enough newer sessions exist -- see cli/repl.py's real incident
        note. 0 (default) is the exact prior behavior, unaffected."""
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE status != 'archived' ORDER BY last_active_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            out = []
            for row in rows:
                d = dict(row)
                d["targets"] = json.loads(d["targets"])
                latest_goal = conn.execute(
                    "SELECT goal FROM goal_history WHERE session_id = ? AND archived_at IS NULL "
                    "ORDER BY seq DESC LIMIT 1",
                    (d["session_id"],),
                ).fetchone()
                d["latest_goal"] = latest_goal["goal"] if latest_goal else None
                out.append(d)
        finally:
            conn.close()
        return out

    def list_archived_sessions(self, limit: int = 9) -> list[dict[str, Any]]:
        """The recovery-path view for /delete's soft-delete -- same shape as
        list_recent_sessions, but only archived sessions, so the REPL's
        chooser can render them with the exact same table-building helper."""
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM sessions WHERE status = 'archived' ORDER BY last_active_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            out = []
            for row in rows:
                d = dict(row)
                d["targets"] = json.loads(d["targets"])
                latest_goal = conn.execute(
                    "SELECT goal FROM goal_history WHERE session_id = ? AND archived_at IS NULL "
                    "ORDER BY seq DESC LIMIT 1",
                    (d["session_id"],),
                ).fetchone()
                d["latest_goal"] = latest_goal["goal"] if latest_goal else None
                out.append(d)
        finally:
            conn.close()
        return out

    def archive_session(self, session_id: str) -> None:
        """Soft-delete for /delete -- marks the session row itself archived
        (hidden from list_recent_sessions) without removing it or any of
        its goal_history. Un-archived by restore_session, the recovery
        path's actual mechanism."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE sessions SET status = 'archived', last_active_at = ? WHERE session_id = ?",
                (datetime.now().isoformat(timespec="seconds"), session_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def restore_session(self, session_id: str) -> None:
        """Un-archives a session -- called when a user picks one from the
        chooser's archived-sessions recovery view."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE sessions SET status = 'active', last_active_at = ? WHERE session_id = ?",
                (datetime.now().isoformat(timespec="seconds"), session_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def archive_goal_history(self, session_id: str) -> None:
        """Full session-data reset for /reset -- stamps every currently
        non-archived goal_history row for this session with archived_at
        (idempotent: a row already archived by an earlier reset is left
        alone). Rows are never deleted, so pre-reset history stays
        recoverable via get_goal_history(include_archived=True); the
        session itself is untouched (still 'active') -- distinct from
        archive_session, which archives the SESSION row for /delete."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE goal_history SET archived_at = ? WHERE session_id = ? AND archived_at IS NULL",
                (datetime.now().isoformat(timespec="seconds"), session_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Turns (goal_history)
    # ------------------------------------------------------------------

    def start_turn(self, session_id: str, goal: str) -> int:
        """Written immediately, before the turn actually runs -- so a crash
        mid-turn still leaves a real, recoverable row (completed_at NULL,
        status 'in_progress') rather than losing the turn entirely."""
        now = datetime.now().isoformat(timespec="seconds")
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            next_seq_row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS next_seq FROM goal_history WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            seq = next_seq_row["next_seq"]
            cur = conn.execute(
                "INSERT INTO goal_history (session_id, seq, goal, started_at, status) "
                "VALUES (?, ?, ?, ?, 'in_progress')",
                (session_id, seq, goal, now),
            )
            turn_id = cur.lastrowid
            conn.execute(
                "UPDATE sessions SET last_active_at = ? WHERE session_id = ?", (now, session_id)
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return turn_id

    def complete_turn(self, turn_id: int, status: str, transcript_ref: str | None = None) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE goal_history SET completed_at = ?, status = ?, transcript_ref = ? WHERE turn_id = ?",
                (now, status, transcript_ref, turn_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_turn_duration_seconds(self, turn_id: int) -> float | None:
        """Queryable after the fact, not display-only computation thrown
        away after rendering -- §9's explicit requirement."""
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT started_at, completed_at FROM goal_history WHERE turn_id = ?", (turn_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None or row["completed_at"] is None:
            return None
        started = datetime.fromisoformat(row["started_at"])
        completed = datetime.fromisoformat(row["completed_at"])
        return (completed - started).total_seconds()

    def get_goal_history(self, session_id: str, include_archived: bool = False) -> list[dict[str, Any]]:
        """Defaults to non-archived rows only, so resume-context building
        and prompt_toolkit input-history seeding both correctly present a
        post-/reset session as blank going forward. include_archived=True
        is the DB-level recoverability check /reset's own verification
        needs -- pre-reset rows are stamped with archived_at, never
        deleted."""
        conn = _connect(self.db_path)
        try:
            if include_archived:
                rows = conn.execute(
                    "SELECT * FROM goal_history WHERE session_id = ? ORDER BY seq ASC", (session_id,)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM goal_history WHERE session_id = ? AND archived_at IS NULL "
                    "ORDER BY seq ASC",
                    (session_id,),
                ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

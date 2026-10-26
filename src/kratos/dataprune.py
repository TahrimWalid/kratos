"""`kratos data prune`: the person removes old stored data, never Kratos on its own.

Same shape as `kratos snapshots prune` (kratos.timewin.snapshots): a PLAN first --
what would go, how many, how big -- and nothing is deleted unless the caller applies
that plan (`--apply` on the CLI, a confirmation in the TUI). Applying refuses inside
an agent tool call (like settings `set`), and every applied prune is recorded in
`data_prunes` (who, when, what, how many).

Categories handled here (docs/phaseB/B.5 §5.3): `traces`, `sessions`, `host_events`, and `hunts`
(C.3: hunt records; host-event prunes also remove the hunt index's entries for those lines).
Snapshots keep their own tiered command. Data that other data depends on is named
in the plan's `blockers` and refused unless `force_orphans`:

  * host_events: log-sync coverage says Kratos holds those log lines completely;
    deleting the events would make that claim false. With `force_orphans` the
    coverage for the pruned period is removed too, so Kratos stops claiming it.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.datainv import to_epoch
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "data_prunes"
PRUNABLE = ("traces", "sessions", "host_events", "pseudonyms", "hunts")


class PruneError(ValueError):
    """A prune that may not run (unknown category, inside a tool call, blocked)."""


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS data_prunes (
            id INTEGER PRIMARY KEY,
            at REAL NOT NULL,              -- epoch UTC
            actor TEXT NOT NULL,           -- who: the surface and the OS user
            category TEXT NOT NULL,
            older_than_days INTEGER NOT NULL,
            cutoff REAL NOT NULL,
            items INTEGER NOT NULL,
            bytes INTEGER NOT NULL,
            forced INTEGER NOT NULL DEFAULT 0,
            detail TEXT                    -- JSON: counts per kind
        )
        """
    )


_STEPS = (_step_1,)


def _db(data_dir: Path) -> sqlite3.Connection:
    db_path = Path(data_dir) / "kratos.db"
    conn = connect_store(db_path)
    try:
        migrate_once(conn, db_path, COMPONENT, _STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@dataclass
class Plan:
    category: str
    older_than_days: int
    cutoff: float
    files: list[Path] = field(default_factory=list)
    rows: dict[str, list[Any]] = field(default_factory=dict)   # table -> keys to delete
    counts: dict[str, int] = field(default_factory=dict)       # plain-words kind -> how many
    bytes: int = 0
    blockers: list[str] = field(default_factory=list)          # dependent data, in plain words
    oldest_kept: str | None = None

    @property
    def items(self) -> int:
        return sum(self.counts.values())

    @property
    def empty(self) -> bool:
        return self.items == 0

    def describe(self) -> list[str]:
        lines = [f"{n} {kind}" for kind, n in self.counts.items() if n]
        return lines or ["nothing older than that"]


def _file_bytes(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _cutoff(older_than_days: int, now: float | None) -> float:
    if not isinstance(older_than_days, int) or older_than_days < 1:
        raise PruneError("--older-than must be a whole number of days, at least 1")
    return (now if now is not None else time.time()) - older_than_days * 86400


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _open_ro(data_dir: Path) -> sqlite3.Connection | None:
    from kratos.datainv import open_readonly

    return open_readonly(Path(data_dir) / "kratos.db")


# --- planning (read-only) ----------------------------------------------------

def _plan_traces(plan: Plan, data_dir: Path) -> None:
    from kratos.trace.store import trace_files

    for p in trace_files(data_dir):
        try:
            mtime = p.stat().st_mtime
        except OSError:
            continue
        if mtime < plan.cutoff:
            plan.files.append(p)
            plan.bytes += _file_bytes(p)
    plan.counts["run records"] = len(plan.files)


def _plan_sessions(plan: Plan, data_dir: Path) -> None:
    sessions_dir = Path(data_dir) / "sessions"
    conn = _open_ro(data_dir)
    turns: list[int] = []
    referenced: set[str] = set()
    sessions: list[str] = []
    try:
        if conn is not None and _table_exists(conn, "goal_history"):
            for r in conn.execute("SELECT turn_id, session_id, started_at, transcript_ref FROM goal_history"):
                ref = r["transcript_ref"]
                started = to_epoch(r["started_at"])
                if started is not None and started < plan.cutoff:
                    turns.append(int(r["turn_id"]))
                    if ref:
                        p = Path(ref)
                        if p.is_file() and sessions_dir.resolve() in p.resolve().parents:
                            plan.files.append(p)
                            plan.bytes += _file_bytes(p)
                elif ref:
                    referenced.add(str(Path(ref).resolve()))
            if _table_exists(conn, "sessions"):
                kept_turn_sessions = {r[0] for r in conn.execute(
                    f"SELECT DISTINCT session_id FROM goal_history WHERE turn_id NOT IN ({','.join('?' * len(turns)) or 'NULL'})",
                    turns)}
                for r in conn.execute("SELECT session_id, last_active_at FROM sessions"):
                    last = to_epoch(r["last_active_at"])
                    if r["session_id"] not in kept_turn_sessions and last is not None and last < plan.cutoff:
                        sessions.append(r["session_id"])
    finally:
        if conn is not None:
            conn.close()
    planned = {str(p.resolve()) for p in plan.files}
    # transcript files no turn points at any more (a turn edited away) -- old ones only
    if sessions_dir.is_dir():
        for p in sorted(sessions_dir.glob("*_turn*.json")):
            rp = str(p.resolve())
            if rp in planned or rp in referenced:
                continue
            try:
                if p.stat().st_mtime < plan.cutoff:
                    plan.files.append(p)
                    plan.bytes += _file_bytes(p)
            except OSError:
                continue
        for sid in sessions:
            w = sessions_dir / f"{sid}_windows.json"
            if w.is_file():
                plan.files.append(w)
                plan.bytes += _file_bytes(w)
    plan.rows["goal_history"] = turns
    plan.rows["sessions"] = sessions
    plan.counts["questions and answers"] = len(turns)
    plan.counts["conversations with nothing newer"] = len(sessions)
    plan.counts["transcript files"] = sum(1 for p in plan.files if p.name.endswith(".json") and "_turn" in p.name)


def _plan_host_events(plan: Plan, data_dir: Path) -> None:
    conn = _open_ro(data_dir)
    if conn is None or not _table_exists(conn, "host_events"):
        if conn is not None:
            conn.close()
        plan.counts["log lines"] = 0
        return
    try:
        n = int(conn.execute("SELECT COUNT(*) FROM host_events WHERE ts < ?", (plan.cutoff,)).fetchone()[0])
        total = int(conn.execute("SELECT COUNT(*) FROM host_events").fetchone()[0]) or 1
        try:
            size = int(conn.execute(
                "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name='host_events'").fetchone()[0])
            plan.bytes = int(size * n / total)
        except sqlite3.Error:
            plan.bytes = 0
        plan.counts["log lines"] = n
        if n and _table_exists(conn, "sync_coverage"):
            spans = int(conn.execute(
                "SELECT COUNT(*) FROM sync_coverage WHERE complete = 1 AND start_ts < ?", (plan.cutoff,)).fetchone()[0])
            if spans:
                plan.blockers.append(
                    f"log-sync coverage says Kratos holds the log lines of that period completely ({spans} "
                    "stretch(es)); deleting them would make that untrue. --force-orphans also removes that "
                    "coverage, so Kratos stops claiming it.")
                plan.rows["sync_coverage"] = [spans]
    finally:
        conn.close()


def _plan_pseudonyms(plan: Plan, data_dir: Path) -> None:
    """Placeholder maps (kratos.privacy) older than the cutoff: a run's map (scope
    `run:<id>`), and a conversation's map whose conversation is already gone. A kept
    conversation keeps its map -- resuming it shows the model the same placeholders."""
    conn = _open_ro(data_dir)
    scopes: list[str] = []
    rows = 0
    try:
        if conn is not None and _table_exists(conn, "pseudonym_map"):
            live = {r[0] for r in conn.execute("SELECT session_id FROM sessions")} \
                if _table_exists(conn, "sessions") else set()
            for r in conn.execute("SELECT scope, MAX(first_seen) AS newest, COUNT(*) AS n FROM pseudonym_map "
                                  "GROUP BY scope"):
                scope, newest = str(r["scope"]), to_epoch(r["newest"])
                if newest is None or newest >= plan.cutoff:
                    continue
                if scope.startswith("session:") and scope.split(":", 1)[1] in live:
                    continue
                scopes.append(scope)
                rows += int(r["n"])
    finally:
        if conn is not None:
            conn.close()
    plan.rows["pseudonym_map"] = scopes
    plan.counts["placeholder maps"] = len(scopes)
    plan.counts["masked values"] = rows
    plan.bytes = rows * 120


def _plan_hunts(plan: Plan, data_dir: Path) -> None:
    """Hunt records (kratos.hunt.store) older than the cutoff: they hold what was typed."""
    conn = _open_ro(data_dir)
    ids: list[int] = []
    try:
        if conn is not None and _table_exists(conn, "hunt_runs"):
            ids = [int(r[0]) for r in conn.execute("SELECT id FROM hunt_runs WHERE at < ?", (plan.cutoff,))]
    finally:
        if conn is not None:
            conn.close()
    plan.rows["hunt_runs"] = ids
    plan.counts["hunt records"] = len(ids)
    plan.bytes = len(ids) * 600


_PLANNERS = {"traces": _plan_traces, "sessions": _plan_sessions, "host_events": _plan_host_events,
             "pseudonyms": _plan_pseudonyms, "hunts": _plan_hunts}


def plan_prune(data_dir: Path, category: str, older_than_days: int, *, now: float | None = None) -> Plan:
    """What `prune` would remove. Reads only."""
    if category not in _PLANNERS:
        raise PruneError(f"`kratos data prune` handles {', '.join(PRUNABLE)}; snapshots: `kratos snapshots prune`")
    plan = Plan(category, older_than_days, _cutoff(older_than_days, now))
    _PLANNERS[category](plan, Path(data_dir))
    return plan


# --- applying ---------------------------------------------------------------

def _delete_files(data_dir: Path, files: list[Path]) -> int:
    root = Path(data_dir).resolve()
    removed = 0
    for p in files:
        rp = Path(p).resolve()
        if root not in rp.parents or not rp.is_file() or Path(p).is_symlink():
            continue
        rp.unlink()  # the person's own `kratos data prune --apply` (allowlisted)
        removed += 1
    # empty date folders under traces/ left by the prune
    traces = root / "traces"
    if traces.is_dir():
        for d in sorted(traces.iterdir()):
            if d.is_dir() and not any(d.iterdir()):
                d.rmdir()  # the person's own prune: the folder it just emptied
    return removed


def apply_prune(data_dir: Path, plan: Plan, *, actor: str, force_orphans: bool = False) -> dict[str, Any]:
    """Delete exactly what `plan` listed and record it. Refuses inside an agent tool
    call and when the plan names dependent data without `force_orphans`."""
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise PruneError(f"agent tools may not delete stored data (tool {tool!r} tried to prune {plan.category!r})")
    actor = str(actor or "").strip()
    if not actor:
        raise PruneError("a prune needs an actor -- who asked for it")
    if plan.blockers and not force_orphans:
        raise PruneError("other data depends on this: " + " ".join(plan.blockers))
    data_dir = Path(data_dir)
    done: dict[str, int] = {}
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if plan.category == "host_events":
                cur = conn.execute("DELETE FROM host_events WHERE ts < ?", (plan.cutoff,))
                done["log lines"] = cur.rowcount or 0
                from kratos.hunt import terms as _terms   # the hunt index entries of those lines go with them

                _terms.delete_older_than(conn, plan.cutoff)
                if force_orphans and _table_exists(conn, "sync_coverage"):
                    gone = conn.execute("DELETE FROM sync_coverage WHERE end_ts <= ?", (plan.cutoff,)).rowcount
                    clipped = conn.execute("UPDATE sync_coverage SET start_ts = ? WHERE start_ts < ? AND end_ts > ?",
                                           (plan.cutoff, plan.cutoff, plan.cutoff)).rowcount
                    done["coverage stretches removed or shortened"] = (gone or 0) + (clipped or 0)
            elif plan.category == "sessions":
                turns = plan.rows.get("goal_history") or []
                for i in range(0, len(turns), 500):
                    part = turns[i:i + 500]
                    conn.execute(f"DELETE FROM goal_history WHERE turn_id IN ({','.join('?' * len(part))})", part)
                done["questions and answers"] = len(turns)
                sids = plan.rows.get("sessions") or []
                for sid in sids:
                    if _table_exists(conn, "session_usage"):
                        conn.execute("DELETE FROM session_usage WHERE session_id = ?", (sid,))
                    conn.execute("DELETE FROM sessions WHERE session_id = ? AND NOT EXISTS "
                                 "(SELECT 1 FROM goal_history WHERE session_id = ?)", (sid, sid))
                    if _table_exists(conn, "pseudonym_map"):   # the conversation's placeholder map goes with it
                        conn.execute("DELETE FROM pseudonym_map WHERE scope = ? AND NOT EXISTS "
                                     "(SELECT 1 FROM sessions WHERE session_id = ?)", (f"session:{sid}", sid))
                done["conversations with nothing newer"] = len(sids)
            elif plan.category == "hunts":
                ids = plan.rows.get("hunt_runs") or []
                for i in range(0, len(ids), 500):
                    part = ids[i:i + 500]
                    conn.execute(f"DELETE FROM hunt_runs WHERE id IN ({','.join('?' * len(part))})", part)
                done["hunt records"] = len(ids)
            elif plan.category == "pseudonyms":
                scopes = plan.rows.get("pseudonym_map") or []
                for scope in scopes:
                    conn.execute("DELETE FROM pseudonym_map WHERE scope = ?", (scope,))
                done["placeholder maps"] = len(scopes)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        done_files = _delete_files(data_dir, plan.files)
        if plan.category == "traces":
            done["run records"] = done_files
        elif plan.category == "sessions":
            done["files"] = done_files
        conn.execute(
            "INSERT INTO data_prunes (at, actor, category, older_than_days, cutoff, items, bytes, forced, detail) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (time.time(), actor[:200], plan.category, plan.older_than_days, plan.cutoff,
             sum(done.values()), plan.bytes, 1 if force_orphans else 0, json.dumps(done, sort_keys=True)))
    finally:
        conn.close()
    return done


def history(data_dir: Path, limit: int = 20) -> list[dict[str, Any]]:
    """The newest recorded prunes."""
    conn = _open_ro(data_dir)
    if conn is None:
        return []
    try:
        if not _table_exists(conn, "data_prunes"):
            return []
        return [dict(r) for r in conn.execute("SELECT * FROM data_prunes ORDER BY id DESC LIMIT ?", (limit,))]
    finally:
        conn.close()


def actor_name(surface: str) -> str:
    import getpass

    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "?"
    return f"{user} via {surface}"

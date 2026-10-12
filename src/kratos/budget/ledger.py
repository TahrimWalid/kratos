"""The usage ledger: one row per model call, from every Kratos process.

`budget_ledger` is the single source of truth for model usage (docs/phase0/0.4
§3.2). A call first gets a `reserved` row holding its worst-case estimate --
written inside `BEGIN IMMEDIATE` together with the cap check, so two processes
(the TUI, `kratos scheduled-run`, `kratos mcp-serve`) can never both squeeze
under a cap -- and after the call the same row becomes `settled` with what was
actually used. A reservation whose process died is `expired` once it is older
than `RESERVATION_TTL_SECONDS`; it then counts as a call with no known usage.

Other rows: `refused` (a cap stopped the call; nothing was sent), `override` (a
person allowed this run to go over a cap) and `note` (a recorded event such as
an upgrade migration). Rows are never deleted (owner decision 5); a reservation
is updated once to settled/expired, nothing else is ever updated.

`budget_state` holds small shared flags: breaker pauses and failure history,
"already notified today" markers, one-time notices.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from kratos.llm_config import REQUEST_TIMEOUT_SECONDS
from kratos.run_context import UNATTENDED
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "budget"

RESERVED = "reserved"
SETTLED = "settled"
REFUSED = "refused"
EXPIRED = "expired"
OVERRIDE = "override"
NOTE = "note"
STATUSES = (RESERVED, SETTLED, REFUSED, EXPIRED, OVERRIDE, NOTE)

# A reservation older than this belongs to a process that died mid-call. Ten
# minutes (spec), but never shorter than one request can legitimately take
# (KRATOS_LLM_REQUEST_TIMEOUT_SECONDS, 900 s by default) -- expiring a call that
# is still running would let other calls through as if it cost nothing.
RESERVATION_TTL_SECONDS = max(600, REQUEST_TIMEOUT_SECONDS + 60)

# Rows that are model calls (spent, or may be spending right now).
_CALL_STATUSES = (RESERVED, SETTLED, EXPIRED)
_UNATTENDED_SQL = "(" + ",".join(f"'{s}'" for s in sorted(UNATTENDED)) + ")"


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS budget_ledger (
            id INTEGER PRIMARY KEY,
            at REAL NOT NULL,                 -- epoch UTC
            day TEXT NOT NULL,                -- the person's local day, YYYY-MM-DD
            status TEXT NOT NULL,             -- reserved | settled | refused | expired | override | note
            source TEXT NOT NULL,
            run_id TEXT, parent_run_id TEXT, session_id TEXT, target TEXT,
            model TEXT NOT NULL,
            local INTEGER NOT NULL,
            prompt_tokens INTEGER, completion_tokens INTEGER, total_tokens INTEGER,
            est_tokens INTEGER,               -- the reservation's worst case
            est_cost_usd REAL,                -- ... priced (NULL: no price on file)
            cost_usd REAL,
            cost_source TEXT,                 -- provider | rate_table | unknown | local
            note TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS budget_ledger_day ON budget_ledger(day, source)")
    conn.execute("CREATE INDEX IF NOT EXISTS budget_ledger_run ON budget_ledger(run_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS budget_ledger_session ON budget_ledger(session_id)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS budget_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,              -- JSON
            updated_at REAL NOT NULL
        )
        """
    )


_STEPS = (_step_1,)


@dataclass(frozen=True)
class DayTotals:
    """One local day's spending, every source (reservations at their estimate)."""
    cost_usd: float                 # calls with a price (or local: 0)
    unattended_cost_usd: float      # ... of which schedule/trigger/mcp/web
    unpriced_tokens: int            # tokens of calls with no price on file, or local
    tokens: int                     # all tokens
    calls: int


@dataclass(frozen=True)
class RunTotals:
    tokens: int
    calls: int


def _row_tokens_sql() -> str:
    # A reservation counts at its worst case; a finished call at what it used.
    return ("CASE WHEN status = 'reserved' THEN COALESCE(est_tokens, 0) "
            "ELSE COALESCE(total_tokens, COALESCE(prompt_tokens, 0) + COALESCE(completion_tokens, 0)) END")


def _row_cost_sql() -> str:
    return "CASE WHEN status = 'reserved' THEN COALESCE(est_cost_usd, 0) ELSE COALESCE(cost_usd, 0) END"


def _row_unpriced_sql() -> str:
    # Unpriced: local, or no price known (a reservation with no estimated cost).
    return ("(local = 1 OR (status = 'reserved' AND est_cost_usd IS NULL) "
            "OR (status != 'reserved' AND cost_source IN ('unknown', 'local')))")


class BudgetLedger:
    """`budget_ledger` + `budget_state` in `data_dir/kratos.db`."""

    def __init__(self, data_dir: Path | str) -> None:
        self.data_dir = Path(data_dir)
        self.db_path = self.data_dir / "kratos.db"
        conn = self._connect()
        conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = connect_store(self.db_path)
        try:
            migrate_once(conn, self.db_path, COMPONENT, _STEPS)
        except BaseException:
            conn.close()
            raise
        return conn

    @contextlib.contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """`BEGIN IMMEDIATE` ... COMMIT (ROLLBACK on error): the write lock is
        taken before anything is read, so a check-then-reserve can't interleave
        with another process's."""
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    # --- writes -----------------------------------------------------------
    @staticmethod
    def expire_stale(conn: sqlite3.Connection, now: float) -> int:
        cur = conn.execute(
            "UPDATE budget_ledger SET status = 'expired', note = 'process ended mid-call; usage unknown' "
            "WHERE status = 'reserved' AND at < ?", (now - RESERVATION_TTL_SECONDS,))
        return cur.rowcount or 0

    @staticmethod
    def insert(conn: sqlite3.Connection, *, at: float, day: str, status: str, source: str,
               model: str, local: bool, run_id: str | None = None, parent_run_id: str | None = None,
               session_id: str | None = None, target: str | None = None,
               est_tokens: int | None = None, est_cost_usd: float | None = None,
               prompt_tokens: int | None = None, completion_tokens: int | None = None,
               total_tokens: int | None = None, cost_usd: float | None = None,
               cost_source: str | None = None, note: str | None = None) -> int:
        if status not in STATUSES:
            raise ValueError(f"unknown ledger status {status!r}")
        cur = conn.execute(
            "INSERT INTO budget_ledger (at, day, status, source, run_id, parent_run_id, session_id, target, "
            "model, local, prompt_tokens, completion_tokens, total_tokens, est_tokens, est_cost_usd, cost_usd, "
            "cost_source, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (at, day, status, source, run_id, parent_run_id, session_id, target, model or "unknown",
             int(bool(local)), prompt_tokens, completion_tokens, total_tokens, est_tokens, est_cost_usd,
             cost_usd, cost_source, note))
        return int(cur.lastrowid)

    def settle(self, row_id: int, *, prompt_tokens: int, completion_tokens: int, total_tokens: int,
               cost_usd: float | None, cost_source: str, note: str | None = None) -> None:
        """Replace a reservation with what the call used. Also settles a row that
        expired while its (slow) call was still running -- the real usage wins."""
        with self.connect() as conn:
            conn.execute(
                "UPDATE budget_ledger SET status = 'settled', prompt_tokens = ?, completion_tokens = ?, "
                "total_tokens = ?, cost_usd = ?, cost_source = ?, note = COALESCE(?, note) "
                "WHERE id = ? AND status IN ('reserved', 'expired')",
                (int(prompt_tokens), int(completion_tokens), int(total_tokens), cost_usd, cost_source,
                 note, int(row_id)))

    # --- totals -----------------------------------------------------------
    @staticmethod
    def day_totals(conn: sqlite3.Connection, day: str) -> DayTotals:
        calls = ",".join(f"'{s}'" for s in _CALL_STATUSES)
        row = conn.execute(
            f"SELECT COALESCE(SUM({_row_cost_sql()}), 0) AS cost, "
            f"COALESCE(SUM(CASE WHEN source IN {_UNATTENDED_SQL} THEN {_row_cost_sql()} ELSE 0 END), 0) AS ucost, "
            f"COALESCE(SUM(CASE WHEN {_row_unpriced_sql()} THEN {_row_tokens_sql()} ELSE 0 END), 0) AS utok, "
            f"COALESCE(SUM({_row_tokens_sql()}), 0) AS tok, COUNT(*) AS calls "
            f"FROM budget_ledger WHERE day = ? AND status IN ({calls})", (day,)).fetchone()
        return DayTotals(cost_usd=float(row["cost"]), unattended_cost_usd=float(row["ucost"]),
                         unpriced_tokens=int(row["utok"]), tokens=int(row["tok"]), calls=int(row["calls"]))

    @staticmethod
    def run_totals(conn: sqlite3.Connection, run_id: str) -> RunTotals:
        calls = ",".join(f"'{s}'" for s in _CALL_STATUSES)
        row = conn.execute(
            f"SELECT COALESCE(SUM({_row_tokens_sql()}), 0) AS tok, COUNT(*) AS calls "
            f"FROM budget_ledger WHERE run_id = ? AND status IN ({calls})", (run_id,)).fetchone()
        return RunTotals(tokens=int(row["tok"]), calls=int(row["calls"]))

    @staticmethod
    def run_overrides(conn: sqlite3.Connection, run_id: str) -> set[str]:
        """The caps a person allowed this run to go over."""
        rows = conn.execute("SELECT note FROM budget_ledger WHERE run_id = ? AND status = 'override'",
                            (run_id,)).fetchall()
        out = set()
        for r in rows:
            try:
                out.add(json.loads(r["note"])["scope"])
            except (TypeError, ValueError, KeyError):
                continue
        return out

    def totals_for_day(self, day: str) -> DayTotals:
        with self.connect() as conn:
            self.expire_stale(conn, time.time())
            return self.day_totals(conn, day)

    def totals_for_run(self, run_id: str) -> RunTotals:
        with self.connect() as conn:
            return self.run_totals(conn, run_id)

    def usage_by_model(self, *, session_id: str | None = None, day: str | None = None) -> list[dict[str, Any]]:
        """Finished calls grouped by model: calls, tokens, cost (None when any
        call of that model had no price), local."""
        where, args = ["status IN ('settled', 'expired')"], []
        if session_id is not None:
            where.append("session_id = ?")
            args.append(session_id)
        if day is not None:
            where.append("day = ?")
            args.append(day)
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT model, MAX(local) AS local, COUNT(*) AS calls, "
                "COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens, "
                "COALESCE(SUM(completion_tokens), 0) AS completion_tokens, "
                "COALESCE(SUM(total_tokens), 0) AS total_tokens, "
                "SUM(cost_usd) AS cost_usd, "
                "SUM(CASE WHEN cost_source = 'unknown' THEN 1 ELSE 0 END) AS unpriced_calls "
                f"FROM budget_ledger WHERE {' AND '.join(where)} GROUP BY model ORDER BY total_tokens DESC",
                args).fetchall()
        return [dict(r) for r in rows]

    def rows(self, *, run_id: str | None = None, day: str | None = None,
             status: str | None = None) -> list[dict[str, Any]]:
        where, args = [], []
        for col, val in (("run_id", run_id), ("day", day), ("status", status)):
            if val is not None:
                where.append(f"{col} = ?")
                args.append(val)
        sql = "SELECT * FROM budget_ledger" + (f" WHERE {' AND '.join(where)}" if where else "") + " ORDER BY id"
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, args).fetchall()]

    # --- budget_state -----------------------------------------------------
    def state_get(self, key: str) -> Any:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM budget_state WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["value"])
        except ValueError:
            return None

    def state_set(self, key: str, value: Any) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO budget_state (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, json.dumps(value, sort_keys=True), time.time()))

    def state_claim(self, key: str, value: Any = True) -> bool:
        """Set `key` only if it isn't set yet; True for exactly one caller across
        every process (once-per-day notifications, one-time notices)."""
        with self.connect() as conn:
            cur = conn.execute("INSERT OR IGNORE INTO budget_state (key, value, updated_at) VALUES (?, ?, ?)",
                               (key, json.dumps(value, sort_keys=True), time.time()))
            return (cur.rowcount or 0) == 1

    def state_delete(self, key: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM budget_state WHERE key = ?", (key,))

    def state_prefix(self, prefix: str) -> dict[str, Any]:
        with self.connect() as conn:
            rows = conn.execute("SELECT key, value FROM budget_state WHERE key >= ? AND key < ?",
                                (prefix, prefix + "￿")).fetchall()
        out = {}
        for r in rows:
            try:
                out[r["key"]] = json.loads(r["value"])
            except ValueError:
                continue
        return out

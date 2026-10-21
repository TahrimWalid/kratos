"""The event store: `host_events` in kratos.db, append-only, one row per event.

Rows are never updated (a trigger aborts any UPDATE); people may delete rows
themselves, nothing in Kratos deletes them. The same line read twice -- windows
overlap all the time -- has the same `event.id` and is stored once
(`UNIQUE (target, event_id)` + `INSERT OR IGNORE`).

Events stay on this machine. Tools keep returning their usual summaries; the
store is never sent to the model as a bulk dump.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable

from kratos.events.model import Event
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

COMPONENT = "events"
MAX_LIMIT = 10_000
COLUMNS = ("target", "event_id", "ts", "dataset", "action", "outcome", "source_ip", "user_name",
           "process_name", "file_sha256", "schema_version", "run_id", "doc")


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS host_events (
          id INTEGER PRIMARY KEY,
          target TEXT NOT NULL,          -- target_key
          event_id TEXT NOT NULL,
          ts REAL NOT NULL,              -- @timestamp, epoch seconds UTC
          dataset TEXT NOT NULL,
          action TEXT,
          outcome TEXT,
          source_ip TEXT,
          user_name TEXT,
          process_name TEXT,
          file_sha256 TEXT,
          schema_version INTEGER NOT NULL,
          run_id TEXT,
          doc TEXT NOT NULL,             -- canonical JSON of Event.to_ecs(), sorted keys
          UNIQUE (target, event_id)
        )
        """
    )
    # The pivot indexes are partial (rows without the value aren't indexed): at a
    # million events that is 6% smaller at the same speed. The hash index also
    # carries ts, or a hash lookup inside a time window scans the window instead
    # (p95 38.6 ms -> 0.01 ms). Measured with scripts/bench/events_bench.py.
    conn.execute("CREATE INDEX IF NOT EXISTS host_events_ts ON host_events(target, ts)")
    for name, column in (("host_events_ip", "source_ip"), ("host_events_user", "user_name"),
                         ("host_events_proc", "process_name"), ("host_events_sha256", "file_sha256")):
        conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON host_events(target, {column}, ts) "
                     f"WHERE {column} IS NOT NULL")
    conn.execute(
        "CREATE TRIGGER IF NOT EXISTS host_events_append_only BEFORE UPDATE ON host_events "
        "BEGIN SELECT RAISE(ABORT, 'host_events is append-only'); END"
    )


STEPS = (_step_1,)


def canonical_doc(event: Event) -> str:
    return json.dumps(event.to_ecs(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _row(event: Event) -> tuple:
    return (event.host_name, event.event_id, event.ts, event.dataset, event.action, event.outcome,
            event.source_ip, event.user_name, event.process_name, event.file_sha256, event.schema_version,
            event.run_id, canonical_doc(event))


def _epoch(value: float | datetime | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("start/end datetimes must carry a zone")
        return value.timestamp()
    return float(value)


class EventStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = connect_store(self.db_path)
        try:
            migrate_once(conn, self.db_path, COMPONENT, STEPS)
        except BaseException:
            conn.close()
            raise
        return conn

    def add(self, events: Iterable[Event]) -> int:
        """Store events (one transaction); returns how many were new."""
        rows = [_row(e) for e in events]
        if not rows:
            return 0
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            before = conn.total_changes
            conn.executemany(f"INSERT OR IGNORE INTO host_events ({', '.join(COLUMNS)}) "
                             f"VALUES ({', '.join('?' for _ in COLUMNS)})", rows)
            inserted = conn.total_changes - before
            conn.execute("COMMIT")
            return inserted
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    @staticmethod
    def _where(target: str, *, start=None, end=None, source_ip=None, user=None, process=None,
               sha256=None, dataset=None, action=None, event_ids=None, rule_id=None) -> tuple[str, list]:
        """Filters, all parameterised. Time is half-open: start <= @timestamp < end.
        `event_ids`: only these events. `rule_id`: only detections (kratos.detect) by this rule."""
        clauses, params = ["target = ?"], [target_key(target)]
        if event_ids is not None:
            ids = [str(i) for i in event_ids][:MAX_LIMIT]
            clauses.append(f"event_id IN ({', '.join('?' for _ in ids) or 'NULL'})")
            params.extend(ids)
        if rule_id is not None:
            clauses.append("dataset = 'kratos.detect' AND json_extract(doc, '$.rule.id') = ?")
            params.append(str(rule_id))
        for column, value in (("source_ip", source_ip), ("user_name", user), ("process_name", process),
                              ("file_sha256", sha256), ("dataset", dataset), ("action", action)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(str(value))
        if (s := _epoch(start)) is not None:
            clauses.append("ts >= ?")
            params.append(s)
        if (e := _epoch(end)) is not None:
            clauses.append("ts < ?")
            params.append(e)
        return " AND ".join(clauses), params

    def query(self, target: str, *, start=None, end=None, source_ip=None, user=None, process=None,
              sha256=None, dataset=None, action=None, event_ids=None, rule_id=None, limit: int = 1000,
              newest_first: bool = True) -> list[Event]:
        where, params = self._where(target, start=start, end=end, source_ip=source_ip, user=user, process=process,
                                    sha256=sha256, dataset=dataset, action=action, event_ids=event_ids,
                                    rule_id=rule_id)
        limit = max(0, min(int(limit), MAX_LIMIT))
        order = "DESC" if newest_first else "ASC"
        conn = self._connect()
        try:
            rows = conn.execute(f"SELECT doc FROM host_events WHERE {where} ORDER BY ts {order}, id {order} LIMIT ?",
                                (*params, limit)).fetchall()
        finally:
            conn.close()
        return [Event.from_ecs(json.loads(r[0])) for r in rows]

    def count(self, target: str, *, start=None, end=None, source_ip=None, user=None, process=None,
              sha256=None, dataset=None, action=None, event_ids=None, rule_id=None) -> int:
        where, params = self._where(target, start=start, end=end, source_ip=source_ip, user=user, process=process,
                                    sha256=sha256, dataset=dataset, action=action, event_ids=event_ids,
                                    rule_id=rule_id)
        conn = self._connect()
        try:
            return int(conn.execute(f"SELECT COUNT(*) FROM host_events WHERE {where}", params).fetchone()[0])
        finally:
            conn.close()

    def targets(self) -> list[tuple[str, int]]:
        """(target, event count) for every machine with stored events."""
        conn = self._connect()
        try:
            return [(r[0], int(r[1])) for r in
                    conn.execute("SELECT target, COUNT(*) FROM host_events GROUP BY target ORDER BY target")]
        finally:
            conn.close()


_warned: set[str] = set()
last_error: str | None = None


def record_events(events: Iterable[Event], *, data_dir: Path | str) -> int | None:
    """Best-effort: store events, never raise. Recording must not fail, slow down
    or change an investigation -- a store problem is logged once (per kind of
    problem) and the caller carries on with its normal result. Returns the
    number of new rows, or None if storing failed."""
    global last_error
    try:
        return EventStore(Path(data_dir) / "kratos.db").add(events)
    except Exception as e:  # noqa: BLE001 -- by design: events are additive
        last_error = f"{type(e).__name__}: {e}"
        kind = type(e).__name__
        if kind not in _warned:
            _warned.add(kind)
            logger.warning("could not store events in %s (%s); the read's result is unaffected",
                           Path(data_dir) / "kratos.db", last_error)
        return None

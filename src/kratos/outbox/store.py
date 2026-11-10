"""The outbox tables in ``kratos.db`` and every state move on them.

Tables (component ``outbox``):

``outbox``           one row per message per channel. ``message_id`` is the receiver's
                     idempotency key; ``UNIQUE(channel, message_id)`` makes enqueueing the
                     same message twice a no-op. ``payload`` is the rendered, redacted
                     body (JSON); an ``events`` message holds a reference to stored host
                     events instead (rendered at send time -- see ``forward``), so the outbox
                     never becomes a second copy of the host history.
``outbox_attempts``  one row per delivery attempt (started, finished, result).
``outbox_lease``     the one delivery worker: a row claimed with a TTL in BEGIN IMMEDIATE.
``forward_cursors``  per channel and stream (``findings`` / ``events``): the last source
                     row id already turned into outbox messages.
``channels``         the receivers (``outbox.channels`` owns their rules).
``channel_events``   append-only record of every channel edit, with the person who made it.

Statuses: ``pending`` (not tried yet), ``failed`` (tried, will be tried again at
``next_attempt_at``), ``delivered``, ``dead`` (final failure or schedule used up). Nothing
here deletes a row on its own: ``prune`` is the person's command (B.5).
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from kratos.outbox import retry as _retry
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "outbox"
STATUSES = ("pending", "failed", "delivered", "dead")
OPEN_STATUSES = ("pending", "failed")
KINDS = ("alert", "notice", "finding", "findings_digest", "events", "test")
LEASE_NAME = "delivery"
LEASE_TTL_SECONDS = 30.0
MAX_ERROR_CHARS = 500
MAX_SUMMARY_CHARS = 200


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox (
          id INTEGER PRIMARY KEY,
          channel TEXT NOT NULL,
          kind TEXT NOT NULL,
          message_id TEXT NOT NULL,          -- the receiver's idempotency key
          order_key TEXT,                    -- messages sharing it go out in id order
          payload TEXT NOT NULL,             -- JSON, rendered and redacted (events: a reference)
          summary TEXT NOT NULL,             -- one line for /outbox
          severity TEXT, machine TEXT,
          status TEXT NOT NULL,              -- pending | failed | delivered | dead
          attempts INTEGER NOT NULL DEFAULT 0,
          failures INTEGER NOT NULL DEFAULT 0,    -- since the last "retry now"
          created_at REAL NOT NULL,
          next_attempt_at REAL NOT NULL,
          claimed_until REAL, claimed_by TEXT,    -- an attempt in progress
          last_attempt_at REAL, last_error TEXT,
          delivered_at REAL, dead_at REAL,
          source TEXT, run_id TEXT,
          UNIQUE (channel, message_id)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS outbox_due ON outbox(channel, status, next_attempt_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS outbox_order ON outbox(channel, order_key, id) "
                 "WHERE order_key IS NOT NULL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox_attempts (
          id INTEGER PRIMARY KEY,
          outbox_id INTEGER NOT NULL REFERENCES outbox(id),
          started_at REAL NOT NULL, finished_at REAL,
          holder TEXT NOT NULL,
          ok INTEGER, retryable INTEGER, status_code INTEGER,
          detail TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS outbox_attempts_msg ON outbox_attempts(outbox_id, id)")
    conn.execute("CREATE INDEX IF NOT EXISTS outbox_attempts_time ON outbox_attempts(started_at)")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox_lease (
          name TEXT PRIMARY KEY,
          holder TEXT NOT NULL, label TEXT, pid INTEGER, host TEXT,
          acquired_at REAL NOT NULL, renewed_at REAL NOT NULL, expires_at REAL NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS forward_cursors (
          channel TEXT NOT NULL, stream TEXT NOT NULL,   -- findings | events
          position INTEGER NOT NULL, updated_at REAL NOT NULL,
          PRIMARY KEY (channel, stream)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS channels (
          name TEXT PRIMARY KEY,
          kind TEXT NOT NULL,                -- ntfy | webhook | syslog | email
          builtin INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          config TEXT NOT NULL,              -- JSON, never a secret
          scopes TEXT NOT NULL,              -- JSON list of alerts | findings | events
          format TEXT NOT NULL,              -- text | kratos | ocsf | ecs
          filters TEXT NOT NULL,             -- JSON
          mask_values INTEGER NOT NULL DEFAULT 0,
          max_per_minute INTEGER NOT NULL DEFAULT 60,
          created_at REAL NOT NULL, created_by TEXT NOT NULL,
          updated_at REAL NOT NULL, updated_by TEXT NOT NULL,
          failing_since REAL,                -- first failure with no success after it
          outage_notified_at REAL,           -- the "can't reach" notice went out for this outage
          last_success_at REAL, last_error TEXT, last_error_at REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS channel_events (
          id INTEGER PRIMARY KEY,
          channel TEXT NOT NULL, at REAL NOT NULL,
          action TEXT NOT NULL,              -- added | edited | enabled | disabled | removed | secret_set
          detail TEXT,                       -- JSON of what changed (never a secret)
          actor TEXT NOT NULL, interface TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE TRIGGER IF NOT EXISTS channel_events_append_only BEFORE UPDATE ON channel_events "
                 "BEGIN SELECT RAISE(ABORT, 'channel_events is append-only'); END")


STEPS = (_step_1,)


def db_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / "kratos.db"


def connect(data_dir: Path | str) -> sqlite3.Connection:
    path = db_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
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
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def clip(text: Any, limit: int) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


# --- enqueue -------------------------------------------------------------------------
@dataclass(frozen=True)
class Enqueued:
    id: int
    channel: str
    message_id: str
    created: bool          # False: this channel already had this message (deduplicated)


def enqueue(conn: sqlite3.Connection, *, channel: str, kind: str, message_id: str, payload: dict[str, Any],
            summary: str, severity: str | None = None, machine: str | None = None,
            order_key: str | None = None, source: str | None = None, run_id: str | None = None,
            now: float | None = None) -> Enqueued:
    """Add one message for one channel; a message the channel already has (same
    ``message_id``) is left as it is. Never sends anything."""
    if kind not in KINDS:
        raise ValueError(f"unknown outbox kind {kind!r}")
    if not message_id or len(message_id) > 200:
        raise ValueError("a message needs a message_id of at most 200 characters")
    now = time.time() if now is None else now
    from kratos.privacy.secrets import redact

    summary, _n = redact(str(summary or ""))
    cur = conn.execute(
        "INSERT OR IGNORE INTO outbox (channel, kind, message_id, order_key, payload, summary, severity, machine,"
        " status, created_at, next_attempt_at, source, run_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)",
        (channel, kind, message_id, order_key, json.dumps(payload, sort_keys=True, ensure_ascii=False),
         clip(summary, MAX_SUMMARY_CHARS), severity, machine, now, now, source, run_id))
    if cur.rowcount:
        return Enqueued(int(cur.lastrowid), channel, message_id, True)
    row = conn.execute("SELECT id FROM outbox WHERE channel = ? AND message_id = ?", (channel, message_id)).fetchone()
    return Enqueued(int(row["id"]), channel, message_id, False)


# --- the worker lease ------------------------------------------------------------------
@dataclass(frozen=True)
class Lease:
    holder: str
    label: str
    pid: int | None
    host: str
    acquired_at: float
    renewed_at: float
    expires_at: float

    def live(self, now: float | None = None) -> bool:
        return self.expires_at > (time.time() if now is None else now)


def lease_info(conn: sqlite3.Connection) -> Lease | None:
    r = conn.execute("SELECT * FROM outbox_lease WHERE name = ?", (LEASE_NAME,)).fetchone()
    if r is None:
        return None
    return Lease(r["holder"], r["label"] or "", r["pid"], r["host"] or "", r["acquired_at"], r["renewed_at"],
                 r["expires_at"])


def acquire_lease(conn: sqlite3.Connection, *, holder: str, label: str, pid: int, host: str,
                  ttl: float = LEASE_TTL_SECONDS, now: float | None = None) -> bool:
    """Take or renew the delivery lease. True when ``holder`` holds it now: it was free,
    expired, or already ours. Atomic across processes (BEGIN IMMEDIATE)."""
    now = time.time() if now is None else now
    with immediate(conn):
        cur = lease_info(conn)
        if cur is not None and cur.holder != holder and cur.live(now):
            return False
        acquired = cur.acquired_at if cur is not None and cur.holder == holder else now
        conn.execute(
            "INSERT INTO outbox_lease (name, holder, label, pid, host, acquired_at, renewed_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET holder = excluded.holder, "
            "label = excluded.label, pid = excluded.pid, host = excluded.host, acquired_at = excluded.acquired_at, "
            "renewed_at = excluded.renewed_at, expires_at = excluded.expires_at",
            (LEASE_NAME, holder, label, pid, host, acquired, now, now + ttl))
    return True


def holds_lease(conn: sqlite3.Connection, holder: str, now: float | None = None) -> bool:
    cur = lease_info(conn)
    return cur is not None and cur.holder == holder and cur.live(now)


def release_lease(conn: sqlite3.Connection, holder: str) -> None:
    """Give the lease up (a clean stop) so another process can take over at once."""
    with immediate(conn):
        conn.execute("UPDATE outbox_lease SET expires_at = ? WHERE name = ? AND holder = ?",
                     (time.time() - 1, LEASE_NAME, holder))


# --- picking and claiming messages -------------------------------------------------------
_DUE_SQL = (
    "SELECT o.* FROM outbox o WHERE o.channel = ? AND o.status IN ('pending', 'failed') "
    "AND o.next_attempt_at <= ? AND (o.claimed_until IS NULL OR o.claimed_until < ?) "
    # per finding (or per events stream) in order: an earlier undelivered message blocks
    "AND (o.order_key IS NULL OR NOT EXISTS (SELECT 1 FROM outbox e WHERE e.channel = o.channel "
    "     AND e.order_key = o.order_key AND e.id < o.id AND e.status IN ('pending', 'failed'))) "
    "ORDER BY o.next_attempt_at, o.id LIMIT ?")


def due(conn: sqlite3.Connection, channel: str, *, now: float | None = None, limit: int = 10) -> list[sqlite3.Row]:
    now = time.time() if now is None else now
    return conn.execute(_DUE_SQL, (channel, now, now, limit)).fetchall()


def claim(conn: sqlite3.Connection, outbox_id: int, *, holder: str, ttl: float,
          now: float | None = None) -> int | None:
    """Take one due message for an attempt: at most one attempt runs at a time, across
    threads and processes. Returns the attempt id, or None (someone else has it, or it
    is no longer due). The attempt is counted before sending: if this process dies
    mid-send, the claim runs out and the next worker sends it again with the same
    message_id (the receiver drops the repeat)."""
    now = time.time() if now is None else now
    with immediate(conn):
        cur = conn.execute(
            "UPDATE outbox SET claimed_until = ?, claimed_by = ?, attempts = attempts + 1, last_attempt_at = ? "
            "WHERE id = ? AND status IN ('pending', 'failed') AND next_attempt_at <= ? "
            "AND (claimed_until IS NULL OR claimed_until < ?)",
            (now + ttl, holder, now, outbox_id, now, now))
        if not cur.rowcount:
            return None
        att = conn.execute("INSERT INTO outbox_attempts (outbox_id, started_at, holder) VALUES (?, ?, ?)",
                           (outbox_id, now, holder))
        return int(att.lastrowid)


@dataclass(frozen=True)
class Outcome:
    ok: bool
    retryable: bool = True
    detail: str = ""
    status_code: int | None = None
    retry_after: float | None = None      # the receiver asked to wait this long (seconds)


def finish(conn: sqlite3.Connection, outbox_id: int, attempt_id: int, *, holder: str, outcome: Outcome,
           now: float | None = None, rng: Any = None) -> str | None:
    """Record an attempt's result and move the message. Returns the new status, or None
    when this holder's claim was taken over meanwhile (the newer attempt decides)."""
    now = time.time() if now is None else now
    detail = clip(outcome.detail, MAX_ERROR_CHARS)
    with immediate(conn):
        conn.execute("UPDATE outbox_attempts SET finished_at = ?, ok = ?, retryable = ?, status_code = ?, detail = ? "
                     "WHERE id = ?", (now, int(outcome.ok), int(outcome.retryable), outcome.status_code, detail,
                                      attempt_id))
        row = conn.execute("SELECT * FROM outbox WHERE id = ?", (outbox_id,)).fetchone()
        if row is None or row["claimed_by"] != holder or row["status"] not in OPEN_STATUSES:
            return None
        if outcome.ok:
            conn.execute("UPDATE outbox SET status = 'delivered', delivered_at = ?, claimed_until = NULL, "
                         "claimed_by = NULL, last_error = NULL WHERE id = ?", (now, outbox_id))
            return "delivered"
        failures = int(row["failures"]) + 1
        delay = _retry.next_delay(failures, rng) if outcome.retryable else None
        if delay is not None and outcome.retry_after:
            delay = max(delay, min(float(outcome.retry_after), 24 * 3600.0))
        if delay is None:
            conn.execute("UPDATE outbox SET status = 'dead', dead_at = ?, failures = ?, last_error = ?, "
                         "claimed_until = NULL, claimed_by = NULL WHERE id = ?", (now, failures, detail, outbox_id))
            return "dead"
        conn.execute("UPDATE outbox SET status = 'failed', failures = ?, next_attempt_at = ?, last_error = ?, "
                     "claimed_until = NULL, claimed_by = NULL WHERE id = ?", (failures, now + delay, detail, outbox_id))
        return "failed"


def release_claim(conn: sqlite3.Connection, outbox_id: int, attempt_id: int, *, holder: str, reason: str) -> None:
    """Give a claimed message back untried (e.g. the channel was turned off meanwhile)."""
    with immediate(conn):
        conn.execute("UPDATE outbox_attempts SET finished_at = ?, ok = 0, retryable = 1, detail = ? WHERE id = ?",
                     (time.time(), clip(reason, MAX_ERROR_CHARS), attempt_id))
        conn.execute("UPDATE outbox SET claimed_until = NULL, claimed_by = NULL, attempts = MAX(0, attempts - 1) "
                     "WHERE id = ? AND claimed_by = ?", (outbox_id, holder))


# --- reading ------------------------------------------------------------------------------
def get(conn: sqlite3.Connection, outbox_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM outbox WHERE id = ?", (outbox_id,)).fetchone()


def statuses(conn: sqlite3.Connection, ids: Sequence[int]) -> dict[int, str]:
    if not ids:
        return {}
    marks = ",".join("?" * len(ids))
    return {int(r["id"]): r["status"] for r in conn.execute(f"SELECT id, status FROM outbox WHERE id IN ({marks})",
                                                            tuple(ids))}


def listing(conn: sqlite3.Connection, *, status: str | None = None, channel: str | None = None,
            limit: int = 50) -> list[sqlite3.Row]:
    where, args = [], []
    if status:
        where.append("status = ?")
        args.append(status)
    if channel:
        where.append("channel = ?")
        args.append(channel)
    sql = "SELECT * FROM outbox" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
    return conn.execute(sql, (*args, int(limit))).fetchall()


def attempts_of(conn: sqlite3.Connection, outbox_id: int) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM outbox_attempts WHERE outbox_id = ? ORDER BY id", (outbox_id,)).fetchall()


def counts(conn: sqlite3.Connection) -> dict[str, dict[str, int]]:
    """{channel: {status: n}}."""
    out: dict[str, dict[str, int]] = {}
    for r in conn.execute("SELECT channel, status, COUNT(*) n FROM outbox GROUP BY channel, status"):
        out.setdefault(r["channel"], {})[r["status"]] = int(r["n"])
    return out


def sent_in_window(conn: sqlite3.Connection, channel: str, *, since: float) -> int:
    """Attempts started for this channel since ``since`` (the per-minute rate cap)."""
    r = conn.execute("SELECT COUNT(*) FROM outbox_attempts a JOIN outbox o ON o.id = a.outbox_id "
                     "WHERE o.channel = ? AND a.started_at >= ?", (channel, since)).fetchone()
    return int(r[0])


def backlog(conn: sqlite3.Connection, channel: str, kind: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM outbox WHERE channel = ? AND status IN ('pending', 'failed')"
    args: tuple[Any, ...] = (channel,)
    if kind:
        sql += " AND kind = ?"
        args += (kind,)
    return int(conn.execute(sql, args).fetchone()[0])


# --- cursors --------------------------------------------------------------------------------
def cursor(conn: sqlite3.Connection, channel: str, stream: str) -> int | None:
    r = conn.execute("SELECT position FROM forward_cursors WHERE channel = ? AND stream = ?",
                     (channel, stream)).fetchone()
    return int(r["position"]) if r else None


def set_cursor(conn: sqlite3.Connection, channel: str, stream: str, position: int, now: float | None = None) -> None:
    conn.execute("INSERT INTO forward_cursors (channel, stream, position, updated_at) VALUES (?, ?, ?, ?) "
                 "ON CONFLICT(channel, stream) DO UPDATE SET position = excluded.position, "
                 "updated_at = excluded.updated_at", (channel, stream, int(position),
                                                      time.time() if now is None else now))


# --- the person's commands ---------------------------------------------------------------------
def retry_now(conn: sqlite3.Connection, *, ids: Sequence[int] | None = None, channel: str | None = None,
              statuses_: Sequence[str] = ("dead", "failed")) -> int:
    """Make failed / dead messages due again at once, with a fresh retry schedule (the
    person fixed the receiver). Returns how many were moved."""
    _authorize_change(_conn_data_dir(conn), "outbox retry now")
    now = time.time()
    where = [f"status IN ({','.join('?' * len(statuses_))})"]
    args: list[Any] = list(statuses_)
    if ids:
        where.append(f"id IN ({','.join('?' * len(ids))})")
        args.extend(int(i) for i in ids)
    if channel:
        where.append("channel = ?")
        args.append(channel)
    with immediate(conn):
        cur = conn.execute(f"UPDATE outbox SET status = 'pending', failures = 0, next_attempt_at = ?, dead_at = NULL "
                           f"WHERE {' AND '.join(where)}", (now, *args))
        return int(cur.rowcount)


def prune_candidates(conn: sqlite3.Connection, *, statuses_: Sequence[str], before: float,
                     channel: str | None = None) -> list[int]:
    bad = [s for s in statuses_ if s not in ("delivered", "dead")]
    if bad:
        raise ValueError("only delivered and dead messages can be pruned (pending and failed ones still go out)")
    sql = (f"SELECT id FROM outbox WHERE status IN ({','.join('?' * len(statuses_))}) "
           "AND COALESCE(delivered_at, dead_at, created_at) < ?")
    args: list[Any] = [*statuses_, before]
    if channel:
        sql += " AND channel = ?"
        args.append(channel)
    return [int(r[0]) for r in conn.execute(sql, args)]


def prune(conn: sqlite3.Connection, ids: Sequence[int]) -> int:
    """Delete these delivered / dead messages and their attempts -- only on the person's
    own ``kratos outbox prune --apply`` (nothing in Kratos calls this on its own)."""
    _authorize_change(_conn_data_dir(conn), "outbox prune")
    if not ids:
        return 0
    n = 0
    with immediate(conn):
        for start in range(0, len(ids), 500):
            chunk = [int(i) for i in ids[start:start + 500]]
            marks = ",".join("?" * len(chunk))
            conn.execute(f"DELETE FROM outbox_attempts WHERE outbox_id IN ({marks})", chunk)
            n += conn.execute(f"DELETE FROM outbox WHERE id IN ({marks}) AND status IN ('delivered', 'dead')",
                              chunk).rowcount
    return n


def _authorize_change(data_dir, what: str) -> None:
    """D.7: the owner, at the Kratos host -- recorded in the audit trail."""
    from kratos import authz

    try:
        authz.require_person(authz.P.CHANNELS_MANAGE, data_dir=data_dir, obj=what)
    except authz.Denied as e:
        raise PermissionError(str(e)) from None


def _conn_data_dir(conn: sqlite3.Connection):
    """The data folder a kratos.db connection belongs to."""
    from pathlib import Path

    row = conn.execute("PRAGMA database_list").fetchone()
    return Path(row[2]).parent if row and row[2] else None

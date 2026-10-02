"""
SQLite persistence for the Kratos sub-agent telemetry channel (capability 1
-- docs/subagent_architecture.md). Same file as SessionStore/AnomalyStore
(`data_dir/kratos.db`, see session_store.py's module docstring) -- new tables
added alongside their existing ones rather than a second DB file.

WAL mode + a real busy_timeout + explicit BEGIN IMMEDIATE/COMMIT per write,
identical pattern to session_store.py, for the same reason: the core server
and a separate CLI invocation (`kratos subagent-status`, `subagent-pair`,
...) can touch this file concurrently.

Scope: this store only ever records read-only telemetry FROM a paired
target and the pairing/auth state needed to accept it. There is no table,
column, or method here that represents a command TO be sent to a target --
capability 2 (direct execution) is separate, gated, and not built.

Connection truth across processes (docs/subagent_connection_ux.md WS1/WS10):
the listener (`kratos subagent-serve`, often a systemd service) and the TUI
are different processes, so live-socket state can't be read from memory.
The listener writes it here instead:
  - `subagent_listeners` -- every running listener registers itself and
    heartbeats; a listener whose heartbeat stops is treated as gone, so a
    crashed listener never leaves targets looking "connected".
  - `subagent_connections` -- one row per target: which listener holds its
    socket, when it connected/disconnected and why, and when the last frame
    and the last telemetry snapshot arrived (a socket that pings but sends no
    telemetry is a zombie, not "connected").
  - `subagent_connection_events` -- a bounded history of connects,
    disconnects and rejected attempts (revoked token, expired pairing code),
    so a flaky link or a still-running revoked agent is visible.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path
from typing import Any

from kratos.utils.timeutil import utc_now_iso

_BUSY_TIMEOUT_MS = 5000

# Matches the pairing-wizard mockup's stated "expires in 15 min" (see
# tui_mk2/screens/phase2_preview.py::_pairing_wizard).
PAIRING_CODE_TTL_SECONDS = 15 * 60

# How many connection events to keep per target (connects, disconnects,
# rejections) -- enough to judge an hour of a flaky link.
CONNECTION_EVENT_RETENTION_PER_TARGET = 200
# Expired, unused pairing codes older than this are purged when a new code is
# created -- they can never be used again and would otherwise pile up.
PAIRING_CODE_PURGE_AFTER_SECONDS = 7 * 24 * 3600

# Bounded per target -- an always-on stream must not grow the DB without
# limit. 500 rows at the default 30s collection interval is ~4 hours of
# history, enough to see a real investigation's worth of recent state
# without needing a separate retention/rollup design for capability 1.
TELEMETRY_RETENTION_PER_TARGET = 500


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _new_target_id() -> str:
    return "tgt_" + secrets.token_hex(6)


def _new_token() -> str:
    return secrets.token_urlsafe(32)


def _new_pairing_code() -> str:
    # Human-typeable-ish, matches the pairing-wizard mockup's "CODE-7F2A" shape.
    raw = secrets.token_hex(4).upper()
    return f"{raw[:4]}-{raw[4:]}"


class SubAgentStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_schema()

    def _init_schema(self) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_pairing_codes (
                    code TEXT PRIMARY KEY,
                    name TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    used_by_target_id TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_targets (
                    target_id TEXT PRIMARY KEY,
                    name TEXT,
                    token TEXT NOT NULL UNIQUE,
                    agent_id TEXT,
                    hostname TEXT,
                    agent_version TEXT,
                    paired_at TEXT NOT NULL,
                    last_seen TEXT,
                    revoked_at TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_subagent_targets_token ON subagent_targets(token)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL REFERENCES subagent_targets(target_id),
                    seq INTEGER,
                    collected_at TEXT,
                    received_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_subagent_telemetry_target ON subagent_telemetry(target_id, id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_listeners (
                    listener_id TEXT PRIMARY KEY,
                    pid INTEGER,
                    host TEXT,
                    port INTEGER,
                    mode TEXT,
                    build TEXT,
                    started_at TEXT NOT NULL,
                    heartbeat_at TEXT NOT NULL,
                    stopped_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_connections (
                    target_id TEXT PRIMARY KEY,
                    listener_id TEXT,
                    peer TEXT,
                    connected_at TEXT,
                    disconnected_at TEXT,
                    disconnect_reason TEXT,
                    last_frame_at TEXT,
                    last_telemetry_at TEXT,
                    collect_interval REAL,
                    ping_interval REAL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_connection_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT NOT NULL,
                    at TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detail TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_subagent_conn_events ON subagent_connection_events(target_id, id)"
            )
            # Which session target (an IP/hostname, lowercased) is read through
            # which paired sub-agent -- only ever set explicitly by the user
            # (docs/subagent_read_routing.md D3). mode: 'subagent' | 'ssh_first'.
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS subagent_links (
                    host TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            # Additive migration of an existing pairing-codes table.
            have = {r["name"] for r in conn.execute("PRAGMA table_info(subagent_pairing_codes)")}
            for col in ("replaces_target_id", "last_attempt_at", "last_attempt_host", "last_attempt_reason", "core_host"):
                if col not in have:
                    conn.execute(f"ALTER TABLE subagent_pairing_codes ADD COLUMN {col} TEXT")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Pairing
    # ------------------------------------------------------------------
    def create_pairing_code(
        self, name: str | None = None, *, replaces_target_id: str | None = None, core_host: str | None = None
    ) -> dict[str, Any]:
        """A single-use code. `replaces_target_id` makes this a RE-PAIR: when
        the new agent checks in, the old target is revoked in the same
        transaction -- so the old pairing keeps working right up until its
        replacement is actually live, and never both at once."""
        code = _new_pairing_code()
        now = utc_now_iso()
        expires_at = _expiry_iso(PAIRING_CODE_TTL_SECONDS)
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM subagent_pairing_codes WHERE used_at IS NULL AND expires_at < ?",
                (_expiry_iso(-PAIRING_CODE_PURGE_AFTER_SECONDS),),
            )
            conn.execute(
                "INSERT INTO subagent_pairing_codes (code, name, created_at, expires_at, replaces_target_id, core_host) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (code, name, now, expires_at, replaces_target_id, core_host),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"code": code, "created_at": now, "expires_at": expires_at, "ttl_seconds": PAIRING_CODE_TTL_SECONDS}

    def get_pairing_code(self, code: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM subagent_pairing_codes WHERE code = ?", (code,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def list_pending_pairing_codes(self, *, include_expired_since_seconds: int = 3600) -> list[dict[str, Any]]:
        """Unused codes: still valid, or expired within the last hour (so the
        UI can say "expired -- make a new one" instead of silently dropping
        them). Newest first."""
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM subagent_pairing_codes WHERE used_at IS NULL AND expires_at >= ? ORDER BY created_at DESC",
                (_expiry_iso(-include_expired_since_seconds),),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def cancel_pairing_code(self, code: str) -> None:
        """Make an unused code unusable now (e.g. superseded by a fresh one)."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM subagent_pairing_codes WHERE code = ? AND used_at IS NULL", (code,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_pairing_attempt(self, code: str, host: str | None, reason: str) -> None:
        """A rejected attempt to pair with a code that EXISTS (expired or
        already used). Unknown codes are not stored -- a stranger guessing
        codes must not be able to write into this table."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE subagent_pairing_codes SET last_attempt_at = ?, last_attempt_host = ?, last_attempt_reason = ? "
                "WHERE code = ?",
                (utc_now_iso(), (host or "")[:200] or None, reason[:200], code),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def redeem_pairing_code(self, code: str, agent_id: str | None, hostname: str | None, agent_version: str | None) -> dict[str, Any] | None:
        """Validate an unused, unexpired code and mint a new paired target +
        token. Returns None (never raises) on any invalid/expired/already-
        used code -- the caller (core_server) turns that into a generic
        hello_reject so a probing client learns nothing about *why*."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT code, name, expires_at, used_at, replaces_target_id FROM subagent_pairing_codes WHERE code = ?",
                (code,),
            ).fetchone()
            if row is None or row["used_at"] is not None or _is_expired(row["expires_at"]):
                conn.execute("ROLLBACK")
                return None
            target_id = _new_target_id()
            token = _new_token()
            now = utc_now_iso()
            conn.execute(
                """
                INSERT INTO subagent_targets (target_id, name, token, agent_id, hostname, agent_version, paired_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                # The name the operator chose when creating the code (e.g. the
                # address they onboarded) wins; the agent's own hostname is
                # only a fallback. It used to be discarded, so a server added as
                # "203.0.113.9" was stored as its hostname "web-01" and nothing could
                # connect the two again.
                (target_id, (row["name"] or "").strip() or hostname, token, agent_id, hostname, agent_version, now, now),
            )
            conn.execute(
                "UPDATE subagent_pairing_codes SET used_at = ?, used_by_target_id = ? WHERE code = ?",
                (now, target_id, code),
            )
            if row["replaces_target_id"]:
                conn.execute(
                    "UPDATE subagent_targets SET revoked_at = ? WHERE target_id = ? AND revoked_at IS NULL",
                    (now, row["replaces_target_id"]),
                )
                # A re-paired box is the same box: its target links follow it.
                conn.execute("UPDATE subagent_links SET target_id = ?, updated_at = ? WHERE target_id = ?",
                             (target_id, now, row["replaces_target_id"]))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"target_id": target_id, "token": token}

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------
    def find_target_by_token_any(self, token: str) -> dict[str, Any] | None:
        """Like get_target_by_token but also finds a REVOKED target -- only to
        record that a revoked agent is still trying to connect."""
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM subagent_targets WHERE token = ?", (token,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def get_target_by_token(self, token: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM subagent_targets WHERE token = ? AND revoked_at IS NULL", (token,)
            ).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM subagent_targets WHERE target_id = ?", (target_id,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def list_targets(self, *, include_revoked: bool = True) -> list[dict[str, Any]]:
        conn = _connect(self.db_path)
        try:
            where = "" if include_revoked else " WHERE revoked_at IS NULL"
            rows = conn.execute(f"SELECT * FROM subagent_targets{where} ORDER BY paired_at DESC").fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def record_connected(self, target_id: str, hostname: str | None, agent_version: str | None) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE subagent_targets SET last_seen = ?, hostname = COALESCE(?, hostname), agent_version = COALESCE(?, agent_version) WHERE target_id = ?",
                (utc_now_iso(), hostname, agent_version, target_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def touch_last_seen(self, target_id: str) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            now = utc_now_iso()
            conn.execute("UPDATE subagent_targets SET last_seen = ? WHERE target_id = ?", (now, target_id))
            conn.execute("UPDATE subagent_connections SET last_frame_at = ? WHERE target_id = ?", (now, target_id))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def revoke_target(self, target_id: str) -> None:
        """Invalidate a target's token: its next hello is rejected, and a
        running listener drops its open connection within a heartbeat (see
        CoreServer's heartbeat loop). The agent on the box keeps running and
        retrying until someone stops it there -- the UI says so."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE subagent_targets SET revoked_at = ? WHERE target_id = ?", (utc_now_iso(), target_id))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def forget_target(self, target_id: str) -> bool:
        """Delete a REVOKED target and everything recorded about it. Refuses
        (returns False) for a target that isn't revoked -- unpair first."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT revoked_at FROM subagent_targets WHERE target_id = ?", (target_id,)).fetchone()
            if row is None or row["revoked_at"] is None:
                conn.execute("ROLLBACK")
                return False
            for table in ("subagent_telemetry", "subagent_connections", "subagent_connection_events", "subagent_links"):
                conn.execute(f"DELETE FROM {table} WHERE target_id = ?", (target_id,))
            conn.execute("UPDATE subagent_pairing_codes SET replaces_target_id = NULL WHERE replaces_target_id = ?",
                         (target_id,))
            conn.execute("DELETE FROM subagent_targets WHERE target_id = ?", (target_id,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return True

    # ------------------------------------------------------------------
    # Target links (session target -> sub-agent), see kratos.subagent.routing
    # ------------------------------------------------------------------
    def set_link(self, host: str, target_id: str, mode: str) -> None:
        from kratos.subagent.routing import MODES, normalize_host

        host = normalize_host(host)
        if not host:
            raise ValueError("a target address is required")
        if mode not in MODES:
            raise ValueError(f"unknown link mode {mode!r}")
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM subagent_targets WHERE target_id = ?", (target_id,)).fetchone() is None:
                conn.execute("ROLLBACK")
                raise ValueError(f"no paired sub-agent {target_id!r}")
            conn.execute(
                "INSERT INTO subagent_links (host, target_id, mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(host) DO UPDATE SET target_id = excluded.target_id, mode = excluded.mode, "
                "updated_at = excluded.updated_at",
                (host, target_id, mode, now, now),
            )
            conn.execute("COMMIT")
        except ValueError:
            raise
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        _clear_link_cache()

    def remove_link(self, host: str) -> bool:
        from kratos.subagent.routing import normalize_host

        conn = _connect(self.db_path)
        try:
            cur = conn.execute("DELETE FROM subagent_links WHERE host = ?", (normalize_host(host),))
            removed = cur.rowcount > 0
        finally:
            conn.close()
        _clear_link_cache()
        return removed

    def get_link(self, host: str) -> dict[str, Any] | None:
        from kratos.subagent.routing import normalize_host

        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM subagent_links WHERE host = ?", (normalize_host(host),)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def core_host_for_target(self, target_id: str) -> str | None:
        """The Kratos address this box was told to dial when it paired (from
        its pairing code), so an update keeps the same one."""
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT core_host FROM subagent_pairing_codes WHERE used_by_target_id = ? AND core_host IS NOT NULL "
                "ORDER BY used_at DESC LIMIT 1", (target_id,)).fetchone()
        finally:
            conn.close()
        return row["core_host"] if row else None

    def list_links(self) -> list[dict[str, Any]]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute("SELECT * FROM subagent_links ORDER BY host").fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def revoked_among(self, target_ids: list[str]) -> set[str]:
        if not target_ids:
            return set()
        conn = _connect(self.db_path)
        try:
            marks = ",".join("?" * len(target_ids))
            rows = conn.execute(
                f"SELECT target_id FROM subagent_targets WHERE revoked_at IS NOT NULL AND target_id IN ({marks})",
                target_ids,
            ).fetchall()
        finally:
            conn.close()
        return {r["target_id"] for r in rows}

    # ------------------------------------------------------------------
    # Listeners + live connections (written by the listener process)
    # ------------------------------------------------------------------
    def register_listener(self, listener_id: str, *, pid: int, host: str, port: int, mode: str, build: str) -> None:
        now = utc_now_iso()
        self._write(
            "INSERT OR REPLACE INTO subagent_listeners (listener_id, pid, host, port, mode, build, started_at, heartbeat_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (listener_id, pid, host, port, mode, build, now, now),
        )

    def heartbeat_listener(self, listener_id: str) -> None:
        self._write("UPDATE subagent_listeners SET heartbeat_at = ? WHERE listener_id = ?", (utc_now_iso(), listener_id))

    def stop_listener(self, listener_id: str) -> None:
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE subagent_listeners SET stopped_at = ?, heartbeat_at = ? WHERE listener_id = ?",
                         (now, now, listener_id))
            self._close_connections_of(conn, "listener_id = ?", (listener_id,), now, "the Kratos listener stopped")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def live_listeners(self, max_age_seconds: float) -> list[dict[str, Any]]:
        """Listeners that are running now (fresh heartbeat, not stopped)."""
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM subagent_listeners WHERE stopped_at IS NULL AND heartbeat_at >= ? ORDER BY started_at DESC",
                (_expiry_iso(-max_age_seconds),),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def close_orphaned_connections(self, max_age_seconds: float) -> int:
        """Close connection rows held by listeners that died without saying so
        (crash, SIGKILL, power loss). Run by every listener at start-up."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            n = self._close_connections_of(
                conn,
                "listener_id NOT IN (SELECT listener_id FROM subagent_listeners WHERE stopped_at IS NULL AND heartbeat_at >= ?)",
                (_expiry_iso(-max_age_seconds),),
                utc_now_iso(),
                "the Kratos listener stopped unexpectedly",
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return n

    def _close_connections_of(self, conn: sqlite3.Connection, where: str, args: tuple, now: str, reason: str) -> int:
        rows = conn.execute(
            f"SELECT target_id FROM subagent_connections WHERE disconnected_at IS NULL AND {where}", args
        ).fetchall()
        for r in rows:
            conn.execute(
                "UPDATE subagent_connections SET disconnected_at = ?, disconnect_reason = ? WHERE target_id = ?",
                (now, reason, r["target_id"]),
            )
            self._add_event(conn, r["target_id"], "disconnected", reason, now)
        return len(rows)

    def record_connection_open(
        self, target_id: str, *, listener_id: str, peer: str | None,
        collect_interval: float | None = None, ping_interval: float | None = None,
    ) -> None:
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO subagent_connections
                    (target_id, listener_id, peer, connected_at, disconnected_at, disconnect_reason, last_frame_at,
                     collect_interval, ping_interval)
                VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    listener_id = excluded.listener_id, peer = excluded.peer, connected_at = excluded.connected_at,
                    disconnected_at = NULL, disconnect_reason = NULL, last_frame_at = excluded.last_frame_at,
                    collect_interval = excluded.collect_interval, ping_interval = excluded.ping_interval
                """,
                (target_id, listener_id, (peer or "")[:100] or None, now, now, collect_interval, ping_interval),
            )
            self._add_event(conn, target_id, "connected", peer, now)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_connection_closed(self, target_id: str, *, listener_id: str, reason: str) -> None:
        """Only closes the row if THIS listener still owns it -- a newer
        connection (e.g. through another listener) is never marked closed by
        an old one tearing down."""
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            n = self._close_connections_of(conn, "target_id = ? AND listener_id = ?", (target_id, listener_id),
                                           now, reason[:200])
            if not n:
                conn.execute("ROLLBACK")
                return
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_connection_event(self, target_id: str, event: str, detail: str | None = None) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._add_event(conn, target_id, event, detail, utc_now_iso())
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _add_event(self, conn: sqlite3.Connection, target_id: str, event: str, detail: str | None, at: str) -> None:
        conn.execute(
            "INSERT INTO subagent_connection_events (target_id, at, event, detail) VALUES (?, ?, ?, ?)",
            (target_id, at, event, (detail or "")[:300] or None),
        )
        conn.execute(
            """
            DELETE FROM subagent_connection_events WHERE target_id = ? AND id NOT IN (
                SELECT id FROM subagent_connection_events WHERE target_id = ? ORDER BY id DESC LIMIT ?
            )
            """,
            (target_id, target_id, CONNECTION_EVENT_RETENTION_PER_TARGET),
        )

    def get_connection(self, target_id: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM subagent_connections WHERE target_id = ?", (target_id,)).fetchone()
        finally:
            conn.close()
        return dict(row) if row else None

    def list_connections(self) -> dict[str, dict[str, Any]]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute("SELECT * FROM subagent_connections").fetchall()
        finally:
            conn.close()
        return {r["target_id"]: dict(r) for r in rows}

    def recent_events(self, target_id: str, since_seconds: float) -> list[dict[str, Any]]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM subagent_connection_events WHERE target_id = ? AND at >= ? ORDER BY id",
                (target_id, _expiry_iso(-since_seconds)),
            ).fetchall()
        finally:
            conn.close()
        return [dict(r) for r in rows]

    def telemetry_received_times(self, target_id: str, limit: int = 6) -> list[str]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT received_at FROM subagent_telemetry WHERE target_id = ? ORDER BY id DESC LIMIT ?",
                (target_id, limit),
            ).fetchall()
        finally:
            conn.close()
        return [r["received_at"] for r in rows]

    def _write(self, sql: str, args: tuple) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(sql, args)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Telemetry
    # ------------------------------------------------------------------
    def record_telemetry(self, target_id: str, payload: dict[str, Any], seq: int | None, collected_at: str | None) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            now = utc_now_iso()
            conn.execute(
                "INSERT INTO subagent_telemetry (target_id, seq, collected_at, received_at, payload_json) VALUES (?, ?, ?, ?, ?)",
                (target_id, seq, collected_at, now, json.dumps(payload)),
            )
            conn.execute("UPDATE subagent_targets SET last_seen = ? WHERE target_id = ?", (now, target_id))
            conn.execute(
                "UPDATE subagent_connections SET last_frame_at = ?, last_telemetry_at = ? WHERE target_id = ?",
                (now, now, target_id),
            )
            # Bounded retention: prune anything beyond the newest N rows for
            # this target, in the same transaction as the insert.
            conn.execute(
                """
                DELETE FROM subagent_telemetry
                WHERE target_id = ? AND id NOT IN (
                    SELECT id FROM subagent_telemetry WHERE target_id = ? ORDER BY id DESC LIMIT ?
                )
                """,
                (target_id, target_id, TELEMETRY_RETENTION_PER_TARGET),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_latest_telemetry(self, target_id: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM subagent_telemetry WHERE target_id = ? ORDER BY id DESC LIMIT 1", (target_id,)
            ).fetchone()
        finally:
            conn.close()
        return _row_to_telemetry(row) if row else None

    def list_recent_telemetry(self, target_id: str, limit: int = 20) -> list[dict[str, Any]]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM subagent_telemetry WHERE target_id = ? ORDER BY id DESC LIMIT ?", (target_id, limit)
            ).fetchall()
        finally:
            conn.close()
        return [_row_to_telemetry(r) for r in rows]


def _clear_link_cache() -> None:
    from kratos.subagent import routing

    routing.clear_cache()


def _row_to_telemetry(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["payload"] = json.loads(d.pop("payload_json"))
    return d


def _expiry_iso(ttl_seconds: int) -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")


def _is_expired(expires_at_iso: str) -> bool:
    from kratos.utils.timeutil import parse_stored_instant, utc_now

    dt = parse_stored_instant(expires_at_iso)
    return dt is None or dt < utc_now()

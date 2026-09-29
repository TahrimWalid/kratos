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
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Pairing
    # ------------------------------------------------------------------
    def create_pairing_code(self, name: str | None = None) -> dict[str, Any]:
        code = _new_pairing_code()
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO subagent_pairing_codes (code, name, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (code, name, now, _expiry_iso(PAIRING_CODE_TTL_SECONDS)),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return {"code": code, "created_at": now, "ttl_seconds": PAIRING_CODE_TTL_SECONDS}

    def redeem_pairing_code(self, code: str, agent_id: str | None, hostname: str | None, agent_version: str | None) -> dict[str, Any] | None:
        """Validate an unused, unexpired code and mint a new paired target +
        token. Returns None (never raises) on any invalid/expired/already-
        used code -- the caller (core_server) turns that into a generic
        hello_reject so a probing client learns nothing about *why*."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT code, name, expires_at, used_at FROM subagent_pairing_codes WHERE code = ?", (code,)
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
                # "15.204.216.9" was stored as "devserver3" and nothing could
                # connect the two again.
                (target_id, (row["name"] or "").strip() or hostname, token, agent_id, hostname, agent_version, now, now),
            )
            conn.execute(
                "UPDATE subagent_pairing_codes SET used_at = ?, used_by_target_id = ? WHERE code = ?",
                (now, target_id, code),
            )
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

    def list_targets(self) -> list[dict[str, Any]]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute("SELECT * FROM subagent_targets ORDER BY paired_at DESC").fetchall()
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
            conn.execute("UPDATE subagent_targets SET last_seen = ? WHERE target_id = ?", (utc_now_iso(), target_id))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def revoke_target(self, target_id: str) -> None:
        """Invalidate a target's token (its next hello is rejected). Kept
        deliberately simple -- no execution/whitelist state exists to tear
        down alongside it, since capability 2 isn't built."""
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

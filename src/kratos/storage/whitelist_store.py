"""
Per-target CRUD storage for the whitelist's user layer + maintainer
per-target overrides (design doc §6/§9 #3/#4). Same physical file as
SessionStore/AnomalyStore/SubAgentStore (`data_dir/kratos.db`), new tables
alongside their existing ones -- same WAL + busy_timeout + explicit
BEGIN IMMEDIATE/COMMIT convention as `subagent_store.py`.

Two kinds of row, matching the two-layer authoring model:
  - `whitelist_user_entries` -- a user's OWN instance of a maintainer
    TEMPLATE (never a raw new action; see `subagent.whitelist_templates`),
    scoped to one target. Every write re-validates through
    `whitelist_templates.build_effective_spec()` (which itself ends in
    `whitelist.validate_spec()`) BEFORE it is ever persisted, and every READ
    re-validates again (design doc §9 #3/#4: "re-validated against schema +
    §5 at load") -- a row that fails to rebuild (e.g. a future code change
    removed/narrowed its template) is surfaced as invalid, never silently
    dropped or silently trusted.
  - `whitelist_maintainer_overrides` -- per-target enable/disable of a
    maintainer default (§6: "they can only *disable* a default for a target
    (opt-out), never redefine it"). Absence of a row means "use the
    tier-derived default" (`whitelist.default_enabled_for_tier`) -- low/medium
    tiers are enabled by default once a target has execution enabled at all;
    high-tier actions stay disabled until this table has an explicit
    enable=1 row for them (§9 #2's "disabled-by-default per-action").

This module itself signs nothing -- but it DOES own two more tables that the
execution channel/consent UI need, because they're just as much "what does
this target's current policy look like" state as the two above:
  - `whitelist_execution_opt_in` -- control 6's per-target, off-by-default,
    reversible-any-time consent flag. This table is the ONLY thing standing
    between a target's whitelist and it ever being dispatched to; nothing
    reads it as "on" unless a human explicitly set it, and clearing it here
    is immediate and sufficient to stop future dispatch (in-flight ones are
    a separate, already-signed concern the execution channel itself owns).
  - `whitelist_dispatch_requests` -- a small durable QUEUE, not a live RPC
    channel: the consent/approval UI (running in the TUI process) and the
    `kratos subagent-serve` process (running `CoreServer`) are separate OS
    processes today, so "TUI asks core to dispatch" is mediated through this
    table rather than an in-process call. `CoreServer`'s watch loop polls
    this LOCAL SQLite table (not the agent -- same "poll the DB, only ever
    push to the agent" pattern the whitelist-version watch loop already
    uses) for pending rows against its live targets, actually dispatches via
    `dispatch_action`, and writes the result back onto the same row. The UI
    then polls the row for completion. This keeps the actual signing/
    dispatch/re-validation logic in exactly one place (CoreServer/agent.py)
    -- this table is transport for a request/result pair, nothing more.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos.subagent import whitelist as W
from kratos.subagent import whitelist_templates as T
from kratos.utils.timeutil import utc_now_iso

_BUSY_TIMEOUT_MS = 5000


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _new_entry_id() -> str:
    return secrets.token_hex(8)  # [a-f0-9]+ -- matches whitelist_templates' instance_id shape


@dataclass
class WhitelistEntryStatus:
    """One user entry as returned by `list_user_entries` -- either a usable
    `effective_spec` + its computed `tier`, or (if re-validation at load
    failed) an `error` explaining why, with no spec to act on."""

    entry_id: str
    target_id: str
    template_id: str
    enabled: bool
    selected_values: dict[str, tuple[str, ...]]
    extra_values: dict[str, tuple[str, ...]]
    created_at: str
    updated_at: str
    effective_spec: W.ActionSpec | None
    tier: W.Sensitivity | None
    error: str | None


class WhitelistStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_schema()

    def _init_schema(self) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_user_entries (
                    entry_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    template_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    selected_values_json TEXT NOT NULL,
                    extra_values_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_whitelist_user_entries_target ON whitelist_user_entries(target_id)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_maintainer_overrides (
                    target_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target_id, action_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_versions (
                    target_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_execution_opt_in (
                    target_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist_dispatch_requests (
                    request_id TEXT PRIMARY KEY,
                    target_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    slot_values_json TEXT NOT NULL,
                    whitelist_version INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    result_json TEXT,
                    requested_at TEXT NOT NULL,
                    completed_at TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_whitelist_dispatch_pending "
                "ON whitelist_dispatch_requests(target_id, status)"
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Whitelist version -- design doc §9 #5: part of the signed dispatch
    # envelope (anti-rollback) and what the core-side push loop watches for
    # a target's action set having changed. Bumped after every successful
    # mutation below (never before -- a version bump with no matching
    # content change is harmless noise; the reverse would be a real bug).
    # ------------------------------------------------------------------
    def get_whitelist_version(self, target_id: str) -> int:
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT version FROM whitelist_versions WHERE target_id = ?", (target_id,)
            ).fetchone()
        finally:
            conn.close()
        return row["version"] if row else 0

    def _bump_whitelist_version(self, target_id: str) -> int:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT version FROM whitelist_versions WHERE target_id = ?", (target_id,)
            ).fetchone()
            new_version = (row["version"] if row else 0) + 1
            conn.execute(
                """
                INSERT INTO whitelist_versions (target_id, version, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET version = excluded.version, updated_at = excluded.updated_at
                """,
                (target_id, new_version, utc_now_iso()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return new_version

    # ------------------------------------------------------------------
    # User layer -- instances of vetted templates.
    # ------------------------------------------------------------------
    def create_user_entry(
        self,
        target_id: str,
        template_id: str,
        *,
        selected_values: dict[str, tuple[str, ...]] | None = None,
        extra_values: dict[str, tuple[str, ...]] | None = None,
    ) -> str:
        """Validates by actually building the effective spec (raises
        T.TemplateInstanceError / W.ActionSpecError / W.HardExclusionError on
        anything unsafe) BEFORE writing a single byte -- never persists an
        entry that wouldn't itself pass `whitelist.validate_spec`."""
        if not target_id:
            raise ValueError("target_id is required -- whitelist entries are per-target scoped (design doc §6)")
        template = T.get_template(template_id)
        if template is None:
            raise ValueError(f"no such template {template_id!r}")
        entry_id = _new_entry_id()
        T.build_effective_spec(  # validate before persisting anything
            template, instance_id=entry_id, selected_values=selected_values, extra_values=extra_values
        )
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO whitelist_user_entries
                    (entry_id, target_id, template_id, enabled, selected_values_json, extra_values_json,
                     created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?)
                """,
                (
                    entry_id, target_id, template_id,
                    json.dumps(selected_values or {}), json.dumps(extra_values or {}),
                    now, now,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._bump_whitelist_version(target_id)
        return entry_id

    def update_user_entry(
        self,
        entry_id: str,
        *,
        selected_values: dict[str, tuple[str, ...]] | None = None,
        extra_values: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        row = self._get_user_entry_row(entry_id)
        if row is None:
            raise ValueError(f"no such whitelist entry {entry_id!r}")
        template = T.get_template(row["template_id"])
        if template is None:
            raise ValueError(f"entry {entry_id!r} references an unknown template {row['template_id']!r}")
        T.build_effective_spec(  # re-validate the NEW values before writing
            template, instance_id=entry_id, selected_values=selected_values, extra_values=extra_values
        )
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE whitelist_user_entries SET selected_values_json = ?, extra_values_json = ?, updated_at = ? "
                "WHERE entry_id = ?",
                (json.dumps(selected_values or {}), json.dumps(extra_values or {}), utc_now_iso(), entry_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._bump_whitelist_version(row["target_id"])

    def set_user_entry_enabled(self, entry_id: str, enabled: bool) -> None:
        """Enable/disable an existing entry -- low-friction by design (design
        doc §9 #3/architecture doc 3a: 'enabling/disabling ... cannot create a
        new capability'). No re-validation needed: toggling never changes
        WHAT the entry could do, only whether it currently may."""
        row = self._get_user_entry_row(entry_id)
        if row is None:
            raise ValueError(f"no such whitelist entry {entry_id!r}")
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE whitelist_user_entries SET enabled = ?, updated_at = ? WHERE entry_id = ?",
                (1 if enabled else 0, utc_now_iso(), entry_id),
            )
            if cur.rowcount == 0:
                raise ValueError(f"no such whitelist entry {entry_id!r}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._bump_whitelist_version(row["target_id"])

    def delete_user_entry(self, entry_id: str) -> None:
        row = self._get_user_entry_row(entry_id)
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM whitelist_user_entries WHERE entry_id = ?", (entry_id,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        if row is not None:
            self._bump_whitelist_version(row["target_id"])

    def _get_user_entry_row(self, entry_id: str) -> sqlite3.Row | None:
        conn = _connect(self.db_path)
        try:
            return conn.execute("SELECT * FROM whitelist_user_entries WHERE entry_id = ?", (entry_id,)).fetchone()
        finally:
            conn.close()

    def list_user_entries(self, target_id: str) -> list[WhitelistEntryStatus]:
        """Re-validates every row's effective spec at LOAD time (design doc
        §9 #3/#4) -- a row whose template no longer exists, or whose stored
        values no longer pass validation (e.g. a code update tightened a
        rule), comes back with `effective_spec=None` and a real `error`
        string rather than being silently dropped or silently trusted."""
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM whitelist_user_entries WHERE target_id = ? ORDER BY created_at", (target_id,)
            ).fetchall()
        finally:
            conn.close()

        out: list[WhitelistEntryStatus] = []
        for row in rows:
            selected = {k: tuple(v) for k, v in json.loads(row["selected_values_json"]).items()}
            extra = {k: tuple(v) for k, v in json.loads(row["extra_values_json"]).items()}
            effective_spec: W.ActionSpec | None = None
            tier: W.Sensitivity | None = None
            error: str | None = None
            template = T.get_template(row["template_id"])
            if template is None:
                error = f"template {row['template_id']!r} no longer exists"
            else:
                try:
                    effective_spec = T.build_effective_spec(
                        template, instance_id=row["entry_id"], selected_values=selected, extra_values=extra
                    )
                    tier = W.compute_sensitivity_tier(effective_spec)
                except (T.TemplateInstanceError, W.ActionSpecError) as e:
                    error = str(e)
            out.append(
                WhitelistEntryStatus(
                    entry_id=row["entry_id"], target_id=row["target_id"], template_id=row["template_id"],
                    enabled=bool(row["enabled"]), selected_values=selected, extra_values=extra,
                    created_at=row["created_at"], updated_at=row["updated_at"],
                    effective_spec=effective_spec, tier=tier, error=error,
                )
            )
        return out

    # ------------------------------------------------------------------
    # Maintainer layer -- per-target enable/disable override only (§6: never
    # redefine, only opt out of -- or, for a high-tier default, opt into).
    # ------------------------------------------------------------------
    def set_maintainer_override(self, target_id: str, action_id: str, enabled: bool) -> None:
        if T.get_template(action_id) is None and action_id not in {s.id for s in W.list_builtin_action_specs()}:
            raise ValueError(f"no such maintainer action {action_id!r}")
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO whitelist_maintainer_overrides (target_id, action_id, enabled, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_id, action_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (target_id, action_id, 1 if enabled else 0, utc_now_iso()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._bump_whitelist_version(target_id)

    def clear_maintainer_override(self, target_id: str, action_id: str) -> None:
        """Removes any override, reverting to the tier-derived default."""
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM whitelist_maintainer_overrides WHERE target_id = ? AND action_id = ?",
                (target_id, action_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._bump_whitelist_version(target_id)

    def _maintainer_overrides(self, target_id: str) -> dict[str, bool]:
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT action_id, enabled FROM whitelist_maintainer_overrides WHERE target_id = ?", (target_id,)
            ).fetchall()
        finally:
            conn.close()
        return {r["action_id"]: bool(r["enabled"]) for r in rows}

    def list_maintainer_status(self, target_id: str) -> list[dict[str, Any]]:
        """Every maintainer default with its tier and whether it's actually
        enabled for `target_id` right now (an explicit override if one
        exists, else the tier-derived default)."""
        overrides = self._maintainer_overrides(target_id)
        out = []
        for spec in W.list_builtin_action_specs():
            tier = W.compute_sensitivity_tier(spec)
            enabled = overrides.get(spec.id, W.default_enabled_for_tier(tier))
            out.append({"spec": spec, "tier": tier, "enabled": enabled, "overridden": spec.id in overrides})
        return out

    # ------------------------------------------------------------------
    # Combined view -- what the (not-yet-built) execution channel / consent
    # UI would read to know a target's real, currently-enabled action set.
    # ------------------------------------------------------------------
    def effective_action_set(self, target_id: str) -> list[dict[str, Any]]:
        """Every currently-ENABLED action for `target_id`, maintainer
        defaults and valid user entries alike, each with its computed tier.
        A user entry whose re-validation failed (see `list_user_entries`) is
        never included here -- it can't be dispatched until fixed. This is
        the whitelist SHAPE regardless of opt-in -- deliberately still
        returned (and pushed to the agent -- see core_server.py) even when
        `get_execution_opt_in` is False, so the agent always has an
        up-to-date copy ready the instant a human opts in, without that
        first push racing the opt-in action itself. Opt-in is what gates
        actually DISPATCHING to it (`get_execution_opt_in`), checked by the
        consent/approval UI before ever calling `create_dispatch_request`."""
        out: list[dict[str, Any]] = []
        for row in self.list_maintainer_status(target_id):
            if row["enabled"]:
                out.append({"spec": row["spec"], "tier": row["tier"], "source": "maintainer"})
        for entry in self.list_user_entries(target_id):
            if entry.enabled and entry.effective_spec is not None:
                out.append({"spec": entry.effective_spec, "tier": entry.tier, "source": "user", "entry_id": entry.entry_id})
        return out

    # ------------------------------------------------------------------
    # Control 6 -- per-target direct-execution opt-in. Off by default,
    # reversible any time, never folded into pairing. This flag alone is
    # what a consent/approval UI must check before ever creating a dispatch
    # request; it does not change what's IN the whitelist (effective_action_set
    # above is opt-in-independent), only whether dispatching against it is
    # currently permitted for this target.
    # ------------------------------------------------------------------
    def get_execution_opt_in(self, target_id: str) -> bool:
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT enabled FROM whitelist_execution_opt_in WHERE target_id = ?", (target_id,)
            ).fetchone()
        finally:
            conn.close()
        return bool(row["enabled"]) if row else False

    def set_execution_opt_in(self, target_id: str, enabled: bool) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO whitelist_execution_opt_in (target_id, enabled, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET enabled = excluded.enabled, updated_at = excluded.updated_at
                """,
                (target_id, 1 if enabled else 0, utc_now_iso()),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Dispatch request queue -- see this module's own docstring for why this
    # exists (the TUI and `kratos subagent-serve` are separate processes).
    # ------------------------------------------------------------------
    def create_dispatch_request(
        self, target_id: str, action_id: str, slot_values: dict[str, Any], whitelist_version: int
    ) -> str:
        """Enqueues a dispatch request. Does NOT check execution opt-in or
        re-validate the action -- that's the caller's (the consent/approval
        UI's) job before it ever calls this, and CoreServer's own dispatch
        path re-validates independently regardless (defense in depth, same
        as everywhere else in this mechanism)."""
        if not self.get_execution_opt_in(target_id):
            raise ValueError(f"target {target_id!r} has not opted into direct execution (control 6)")
        request_id = secrets.token_hex(8)
        now = utc_now_iso()
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO whitelist_dispatch_requests
                    (request_id, target_id, action_id, slot_values_json, whitelist_version, status, requested_at)
                VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (request_id, target_id, action_id, json.dumps(slot_values), whitelist_version, now),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return request_id

    def get_dispatch_request(self, request_id: str) -> dict[str, Any] | None:
        conn = _connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM whitelist_dispatch_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        d = dict(row)
        d["slot_values"] = json.loads(d.pop("slot_values_json"))
        d["result"] = json.loads(d.pop("result_json")) if d.get("result_json") else None
        return d

    def list_pending_dispatch_requests(self, target_id: str) -> list[dict[str, Any]]:
        """Used by CoreServer's watch loop -- pending rows for a LIVE
        target, oldest first (serviced in order, never reordered)."""
        conn = _connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM whitelist_dispatch_requests WHERE target_id = ? AND status = 'pending' "
                "ORDER BY requested_at",
                (target_id,),
            ).fetchall()
        finally:
            conn.close()
        out = []
        for row in rows:
            d = dict(row)
            d["slot_values"] = json.loads(d.pop("slot_values_json"))
            d["result"] = None
            out.append(d)
        return out

    def complete_dispatch_request(self, request_id: str, result: dict[str, Any]) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE whitelist_dispatch_requests SET status = 'done', result_json = ?, completed_at = ? "
                "WHERE request_id = ?",
                (json.dumps(result), utc_now_iso(), request_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

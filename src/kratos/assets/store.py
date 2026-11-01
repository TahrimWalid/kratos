"""The asset record: one row per machine in kratos.db -> ``assets`` (Phase D README §4.2).

What a person says about a machine -- how much it matters (``criticality``), how badly a
compromise could hurt people outside the organisation (``wellbeing``), whether it is
reachable from the internet (``exposure_override``), a free ``role`` label, the
``groups`` it belongs to (D.2) and an ``owner_note`` -- keyed by ``target_key``. Every
edit is a person's (refused inside a tool run, like settings and finding decisions)
and is recorded in ``asset_events`` (append-only) with the actor.

``role`` and ``owner_note`` are for people: they are never sent to the model.

A machine Kratos holds data for but has no row yet is listed as "not set up" by
``known_machines`` (never hidden). Unset criticality is asked once per machine
(``mark_asked``); until answered, SSVC computes with "medium" and says so.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from kratos import settings_store
from kratos.lifecycle.decide import Actor
from kratos.ssvc.mission import CRITICALITIES, WELLBEING
from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.target_key import target_key

COMPONENT = "assets"
EXPOSURE_OVERRIDES = ("internet", "private")      # "reachable from the internet" / "not reachable from it"
ACTOR_INTERFACES = ("tui", "cli")                 # asset edits come from a person at the TUI or CLI
MAX_TEXT = 200
MAX_GROUPS = 32
FIELDS = ("criticality", "wellbeing", "exposure_override", "role", "groups", "owner_note")


class AssetError(ValueError):
    """A value outside its set, a forbidden caller, or no person behind the edit."""


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
          target TEXT PRIMARY KEY,                  -- target_key form
          criticality TEXT,                         -- low | medium | high | critical; NULL = not set
          wellbeing TEXT NOT NULL DEFAULT 'minimal', -- minimal | material | irreversible
          exposure_override TEXT,                   -- internet | private; NULL = measured only
          role TEXT, groups TEXT NOT NULL DEFAULT '[]', owner_note TEXT,
          asked_at REAL,                            -- the one-time criticality question was asked
          created_at REAL NOT NULL, updated_at REAL NOT NULL, updated_by TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_events (
          id INTEGER PRIMARY KEY,
          target TEXT NOT NULL, at REAL NOT NULL,
          field TEXT NOT NULL, old_value TEXT, new_value TEXT,
          actor TEXT NOT NULL, interface TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS asset_events_target ON asset_events(target, at)")
    conn.execute("CREATE TRIGGER IF NOT EXISTS asset_events_append_only BEFORE UPDATE ON asset_events "
                 "BEGIN SELECT RAISE(ABORT, 'asset_events is append-only'); END")


STEPS = (_step_1,)


@dataclass(frozen=True)
class Asset:
    target: str
    criticality: str | None = None
    wellbeing: str = "minimal"
    exposure_override: str | None = None
    role: str = ""
    groups: tuple[str, ...] = ()
    owner_note: str = ""
    asked_at: float | None = None
    updated_at: float | None = None
    updated_by: str = ""
    set_up: bool = True                     # False: Kratos holds data for it, no row yet
    seen_in: tuple[str, ...] = field(default_factory=tuple)

    @property
    def criticality_set(self) -> bool:
        return self.criticality in CRITICALITIES

    def to_dict(self) -> dict[str, Any]:
        return {"target": self.target, "criticality": self.criticality, "wellbeing": self.wellbeing,
                "exposure_override": self.exposure_override, "role": self.role, "groups": list(self.groups),
                "owner_note": self.owner_note, "set_up": self.set_up, "updated_by": self.updated_by,
                "updated_at": self.updated_at}


def db_path(data_dir: Path) -> Path:
    return Path(data_dir) / "kratos.db"


def connect(data_dir: Path) -> sqlite3.Connection:
    path = db_path(data_dir)
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


@contextlib.contextmanager
def opened(data_dir: Path) -> Iterator[sqlite3.Connection]:
    conn = connect(data_dir)
    try:
        yield conn
    finally:
        conn.close()


def _row_asset(r: sqlite3.Row) -> Asset:
    try:
        groups = tuple(str(g) for g in json.loads(r["groups"] or "[]"))
    except (TypeError, ValueError):
        groups = ()
    return Asset(r["target"], r["criticality"], r["wellbeing"] or "minimal", r["exposure_override"],
                 r["role"] or "", groups, r["owner_note"] or "", r["asked_at"], r["updated_at"], r["updated_by"] or "")


def get(data_dir: Path, target: str) -> Asset | None:
    """The machine's asset row, or None. Never creates one, never raises for a missing DB."""
    if not db_path(data_dir).exists():
        return None
    try:
        with opened(data_dir) as conn:
            r = conn.execute("SELECT * FROM assets WHERE target = ?", (target_key(target),)).fetchone()
    except sqlite3.Error:
        return None
    return _row_asset(r) if r else None


def _check_actor(actor: Actor) -> None:
    tool = settings_store.in_tool_call()
    if tool is not None:
        raise AssetError(f"agent tools may not change what a person says about a machine (tool {tool!r} tried)")
    if not isinstance(actor, Actor) or actor.interface not in ACTOR_INTERFACES or not str(actor.user or "").strip():
        raise AssetError("an asset edit needs a person: an Actor from the TUI or the CLI")


def _text(value: Any, name: str) -> str:
    text = " ".join(str(value or "").split())
    if len(text) > MAX_TEXT:
        raise AssetError(f"{name} is at most {MAX_TEXT} characters")
    if any(ord(ch) < 32 for ch in text):
        raise AssetError(f"{name} must be plain text")
    return text


def _clean(field_name: str, value: Any) -> Any:
    if field_name == "criticality":
        v = str(value or "").strip().lower()
        if v in ("", "unset", "none"):
            return None
        if v not in CRITICALITIES:
            raise AssetError(f"criticality is one of: {', '.join(CRITICALITIES)} (or unset)")
        return v
    if field_name == "wellbeing":
        v = str(value or "minimal").strip().lower()
        if v not in WELLBEING:
            raise AssetError(f"public well-being impact is one of: {', '.join(WELLBEING)}")
        return v
    if field_name == "exposure_override":
        v = str(value or "").strip().lower()
        if v in ("", "unset", "none", "measured"):
            return None
        if v not in EXPOSURE_OVERRIDES:
            raise AssetError("exposure is 'internet' (reachable from the internet), 'private' (not reachable "
                             "from it) or unset (Kratos's measurement only)")
        return v
    if field_name == "groups":
        items = value if isinstance(value, (list, tuple)) else str(value or "").split(",")
        out: list[str] = []
        for g in items:
            name = _text(g, "a group name")
            if name and name not in out:
                out.append(name)
        if len(out) > MAX_GROUPS:
            raise AssetError(f"at most {MAX_GROUPS} groups")
        return out
    if field_name in ("role", "owner_note"):
        return _text(value, field_name.replace("_", " "))
    raise AssetError(f"unknown asset field {field_name!r}")


def update(data_dir: Path, target: str, actor: Actor, **changes: Any) -> Asset:
    """Set fields of a machine's asset record (creating it), each change recorded with
    the actor. Raises AssetError for a bad value or caller; nothing is written then."""
    _check_actor(actor)
    key = target_key(target)
    if not key:
        raise AssetError("which machine?")
    cleaned = {k: _clean(k, v) for k, v in changes.items()}
    now = time.time()
    who = f"{actor.user}"[:120]
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            r = conn.execute("SELECT * FROM assets WHERE target = ?", (key,)).fetchone()
            if r is None:
                conn.execute("INSERT INTO assets (target, created_at, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                             (key, now, now, who))
                r = conn.execute("SELECT * FROM assets WHERE target = ?", (key,)).fetchone()
            for name, value in cleaned.items():
                stored = json.dumps(value) if name == "groups" else value
                old = r[name]
                if (old or None) == (stored or None) and name != "groups":
                    continue
                if name == "groups" and json.loads(old or "[]") == value:
                    continue
                conn.execute(f"UPDATE assets SET {name} = ?, updated_at = ?, updated_by = ? WHERE target = ?",
                             (stored if name == "groups" else value, now, who, key))
                conn.execute("INSERT INTO asset_events (target, at, field, old_value, new_value, actor, interface) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?)", (key, now, name, old, stored, who, actor.interface))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        r = conn.execute("SELECT * FROM assets WHERE target = ?", (key,)).fetchone()
    return _row_asset(r)


def mark_asked(data_dir: Path, target: str, actor: Actor) -> None:
    """Record that the person was asked this machine's criticality (whatever they answered),
    so it is asked once per machine."""
    _check_actor(actor)
    key = target_key(target)
    now = time.time()
    with opened(data_dir) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if conn.execute("SELECT 1 FROM assets WHERE target = ?", (key,)).fetchone() is None:
                conn.execute("INSERT INTO assets (target, created_at, updated_at, updated_by, asked_at) "
                             "VALUES (?, ?, ?, ?, ?)", (key, now, now, actor.user[:120], now))
            else:
                conn.execute("UPDATE assets SET asked_at = COALESCE(asked_at, ?) WHERE target = ?", (now, key))
            conn.execute("INSERT INTO asset_events (target, at, field, old_value, new_value, actor, interface) "
                         "VALUES (?, ?, 'asked', NULL, NULL, ?, ?)", (key, now, actor.user[:120], actor.interface))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise


def needs_question(data_dir: Path, target: str) -> bool:
    """True when this machine's criticality is unset and the person was never asked."""
    a = get(data_dir, target)
    return a is None or (not a.criticality_set and a.asked_at is None)


def events(data_dir: Path, target: str, limit: int = 50) -> list[dict[str, Any]]:
    if not db_path(data_dir).exists():
        return []
    with opened(data_dir) as conn:
        rows = conn.execute("SELECT * FROM asset_events WHERE target = ? ORDER BY id DESC LIMIT ?",
                            (target_key(target), int(limit))).fetchall()
    return [dict(r) for r in rows]


def _table_targets(conn: sqlite3.Connection, sql: str) -> set[str]:
    try:
        return {target_key(r[0]) for r in conn.execute(sql) if r[0]}
    except sqlite3.Error:
        return set()


def known_machines(data_dir: Path, *, configured: str | None = None) -> list[Asset]:
    """Every machine Kratos knows: those with an asset row, and those it holds data for
    without one (`set_up=False`, shown as "not set up", never hidden). Kratos's own host
    (loopback) only when it has a row or data."""
    rows: dict[str, Asset] = {}
    seen: dict[str, set[str]] = {}
    if db_path(data_dir).exists():
        with opened(data_dir) as conn:
            for r in conn.execute("SELECT * FROM assets ORDER BY target"):
                rows[r["target"]] = _row_asset(r)
            for label, sql in (("findings", "SELECT DISTINCT target FROM finding_records"),
                               ("packages", "SELECT DISTINCT target FROM pkg_inventory"),
                               ("checks", "SELECT DISTINCT target FROM collect_state")):
                for t in _table_targets(conn, sql):
                    seen.setdefault(t, set()).add(label)
    if configured:
        seen.setdefault(target_key(configured), set()).add("configured target")
    out: list[Asset] = []
    for key in sorted(set(rows) | set(seen)):
        where = tuple(sorted(seen.get(key, ())))
        if key in rows:
            a = rows[key]
            out.append(Asset(**{**a.__dict__, "seen_in": where}))
        else:
            out.append(Asset(key, set_up=False, seen_in=where))
    return out

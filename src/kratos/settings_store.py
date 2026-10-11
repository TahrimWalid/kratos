"""Settings the user edits: limits and toggles shared by every Kratos process.

They live in `kratos.db` (`app_settings`), not in `.env`, so the TUI,
`kratos scheduled-run` and `kratos mcp-serve` -- separate processes -- all read
the same value, and a change applies on the next read without a restart. `.env`
stays for connection settings (model, keys, target login).

Each feature registers its own keys at import time, namespaced by feature
(`findings.*`, `budget.*`, `logs.*`), with a default, a validator and one plain
sentence for the Settings screen.

The model suggests, people decide: no agent tool may change a setting. A static
scan in the tests checks every registered tool's module, and `set` itself
refuses while a tool is running (`agent/loop.py::execute_tool_call` opens
`tool_call_scope()` around every handler, kept self-written tools included).
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store
from kratos.utils.timeutil import utc_now_iso

logger = logging.getLogger(__name__)

COMPONENT = "settings"
_MAX_ACTOR_LEN = 120


class SettingError(ValueError):
    """An unknown key, a value its validator rejects, or a forbidden caller."""


@dataclass(frozen=True)
class SettingSpec:
    key: str                              # e.g. "budget.daily_cost_usd"
    default: Any
    validate: Callable[[Any], Any]        # returns the cleaned value or raises SettingError
    doc: str                              # one plain sentence, shown in Settings


_REGISTRY: dict[str, SettingSpec] = {}
_IN_TOOL: contextvars.ContextVar[str | None] = contextvars.ContextVar("kratos_settings_in_tool", default=None)
_warned_bad: set[tuple[str, str]] = set()


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,      -- JSON
            updated_at TEXT,
            updated_by TEXT
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


def register(spec: SettingSpec) -> None:
    """Called at import time by the feature that owns the key. Registering the
    same spec again (a module re-imported) is fine; a different spec under an
    existing key is a programming error."""
    if not spec.key or "." not in spec.key or spec.key != spec.key.strip():
        raise SettingError(f"setting keys are namespaced by feature, e.g. 'budget.daily_cost_usd': {spec.key!r}")
    existing = _REGISTRY.get(spec.key)
    if existing is not None and existing != spec:
        raise SettingError(f"setting {spec.key!r} is already registered differently")
    spec.validate(spec.default)  # a default its own validator rejects is a bug -- fail at import
    _REGISTRY[spec.key] = spec


def specs() -> list[SettingSpec]:
    """Every registered setting, sorted by key (for the Settings screen)."""
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def _spec(key: str) -> SettingSpec:
    try:
        return _REGISTRY[key]
    except KeyError:
        raise SettingError(f"unknown setting {key!r}") from None


def get(key: str, *, data_dir: Path) -> Any:
    """The stored value, else the default. A stored value that no longer
    validates (edited by hand, or written by an older Kratos with different
    rules) is logged once and the default is used -- never an exception."""
    spec = _spec(key)
    try:
        conn = _db(data_dir)
    except sqlite3.Error as e:
        logger.warning("could not read setting %s (%s); using its default", key, e)
        return spec.default
    try:
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    except sqlite3.Error as e:
        logger.warning("could not read setting %s (%s); using its default", key, e)
        return spec.default
    finally:
        conn.close()
    if row is None:
        return spec.default
    try:
        return spec.validate(json.loads(row[0]))
    except Exception as e:  # noqa: BLE001 -- a bad stored value must never break the caller
        marker = (key, row[0])
        if marker not in _warned_bad:
            _warned_bad.add(marker)
            logger.warning("stored value for setting %s is not valid (%s); using its default", key, e)
        return spec.default


def set(key: str, value: Any, *, data_dir: Path, actor: str) -> None:  # noqa: A001 -- the README §4.5 contract
    """Validate and store `value`, recording who changed it and when. `actor`
    names the person-facing surface (e.g. "tui:settings", "cli")."""
    tool = _IN_TOOL.get()
    if tool is not None:
        raise SettingError(f"agent tools may not change settings (tool {tool!r} tried to change {key!r})")
    spec = _spec(key)
    actor = str(actor or "").strip()
    if not actor:
        raise SettingError("set() needs an actor -- who changed the setting")
    cleaned = spec.validate(value)
    encoded = json.dumps(cleaned, sort_keys=True)
    conn = _db(data_dir)
    try:
        conn.execute(
            "INSERT INTO app_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at, "
            "updated_by = excluded.updated_by",
            (key, encoded, utc_now_iso(), actor[:_MAX_ACTOR_LEN]),
        )
    finally:
        conn.close()


def last_change(key: str, *, data_dir: Path) -> tuple[str, str] | None:
    """(updated_at, updated_by) for a stored setting, or None if it was never set."""
    _spec(key)
    conn = _db(data_dir)
    try:
        row = conn.execute("SELECT updated_at, updated_by FROM app_settings WHERE key = ?", (key,)).fetchone()
    finally:
        conn.close()
    return (row[0], row[1]) if row else None


@contextlib.contextmanager
def tool_call_scope(tool_name: str) -> Iterator[None]:
    """Open around an agent tool's handler: `set` refuses inside it."""
    token = _IN_TOOL.set(tool_name or "?")
    try:
        yield
    finally:
        _IN_TOOL.reset(token)

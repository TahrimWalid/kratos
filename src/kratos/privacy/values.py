"""The values Kratos already knows before a request is built -- the field-aware half of masking.

Kratos's own readers type what they find: the privileged-account read lists every local
account, account findings name accounts, and the configuration names the targets, the
SSH login and the sub-agents. Those TRUSTED values are masked wherever they appear as
whole words, even in prose with no field name next to them. Names the event store only
saw in logs (`user.name`) may be an attacker's text: they are replaced only where they
appear as a name. `mask.py`'s patterns catch what typing missed, the same way.

A registry (`register_value_source`), like the collection checks and snapshot sources:
a later feature that learns names adds a source, nothing else changes. Each source gets
the machine under investigation and the data folder, returns a `KnownValues`, and may
fail -- a failing source is skipped (logged once), it never stops a request.
"""
from __future__ import annotations

import contextvars
import json
import logging
import socket
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from kratos.target_key import LOOPBACK_KEY, target_key

logger = logging.getLogger(__name__)


@dataclass
class KnownValues:
    # TRUSTED names (masked as whole words everywhere): the machine's own account list,
    # the configured login, accounts its privileged-account findings name.
    accounts: dict[str, int | None] = field(default_factory=dict)  # name -> UID (None: unknown) on the target
    account_list_complete: bool = False   # `accounts` is the machine's whole account list
    # Names only SEEN in logs (stored events): may be chosen by an attacker, so they are
    # replaced only where they appear as a name, never as a free word.
    seen_names: set[str] = field(default_factory=set)
    nonexistent: set[str] = field(default_factory=set)     # names the machine said don't exist
    target_names: set[str] = field(default_factory=set)    # the machine under investigation's names
    target_ips: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)           # other machines' names

    def merge(self, other: "KnownValues") -> None:
        for name, uid in other.accounts.items():
            if self.accounts.get(name) is None:
                self.accounts[name] = uid
        self.account_list_complete = self.account_list_complete or other.account_list_complete
        self.seen_names |= other.seen_names
        self.nonexistent |= other.nonexistent
        self.target_names |= other.target_names
        self.target_ips |= other.target_ips
        self.hosts |= other.hosts


ValueSource = Callable[[str, Path], KnownValues]
_SOURCES: dict[str, ValueSource] = {}
_warned: set[str] = set()


def register_value_source(name: str, fn: ValueSource) -> None:
    """Add (or replace) a source: `fn(target_key, data_dir) -> KnownValues`."""
    _SOURCES[name] = fn


def value_sources() -> list[str]:
    return list(_SOURCES)


# Recomputed at most this often within one run: tools write new snapshots as the run goes.
_CACHE_SECONDS = 15.0
_CACHE: contextvars.ContextVar[tuple[tuple, float, KnownValues] | None] = contextvars.ContextVar(
    "kratos_privacy_values", default=None)


def gather(target: str, data_dir: Path) -> KnownValues:
    """Every source's values for `target` (a target key), cached briefly per run."""
    from kratos import run_context

    key = (run_context.current_run_id(), target, str(data_dir))
    cached = _CACHE.get()
    now = time.monotonic()
    if cached and cached[0] == key and now - cached[1] < _CACHE_SECONDS:
        return cached[2]
    out = KnownValues()
    for name, fn in list(_SOURCES.items()):
        try:
            out.merge(fn(target, data_dir))
        except Exception as e:  # noqa: BLE001 -- a source that fails is skipped, never fatal
            if name not in _warned:
                _warned.add(name)
                logger.warning("privacy value source %s failed (%s: %s); masking goes on without it",
                               name, type(e).__name__, e)
    if key[0] is not None:
        _CACHE.set((key, now, out))
    return out


def _is_ip(text: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _add_machine(values: KnownValues, raw: str | None, *, is_target: bool) -> None:
    host = target_key(raw)
    if not host or host == LOOPBACK_KEY:
        return
    if _is_ip(host):
        if is_target:
            values.target_ips.add(host)     # other machines' addresses are caught by the IP pattern
    elif is_target:
        values.target_names.add(host)       # as configured: a tool argument restores to exactly this
    else:
        values.hosts.add(host)
        values.hosts.add(host.split(".", 1)[0])


# --- built-in sources ---------------------------------------------------------------

def _config_source(target: str, data_dir: Path) -> KnownValues:
    """The machine under investigation, the SSH login on it, and Kratos's own name."""
    from kratos import kratos_config

    v = KnownValues()
    _add_machine(v, target, is_target=True)
    active = kratos_config.get_active_target() or ""
    host = active if target_key(active) == target else target
    try:
        user = kratos_config.ssh_user_for(host, data_dir)
    except Exception:  # noqa: BLE001 -- no remembered login: the configured default
        user = kratos_config.SSH_TARGET_USER
    if user and target != LOOPBACK_KEY:
        v.accounts.setdefault(str(user), None)
    for name in {socket.gethostname(), socket.getfqdn()}:
        name = (name or "").strip().lower()
        if name and name not in ("localhost", "localhost.localdomain") and not _is_ip(name):
            v.hosts.add(name)
            v.hosts.add(name.split(".", 1)[0])
    return v


def _subagent_source(target: str, data_dir: Path) -> KnownValues:
    """Names of the paired sub-agent machines (as named in Kratos and as they report)."""
    v = KnownValues()
    db = data_dir / "kratos.db"
    if not db.exists():
        return v
    from kratos.storage.sqlite_files import connect_store

    conn = connect_store(db)
    try:
        rows = conn.execute("SELECT name, hostname FROM subagent_targets").fetchall()
    except sqlite3.Error:
        return v
    finally:
        conn.close()
    for name, hostname in rows:
        for raw in (name, hostname):
            if raw and not _is_ip(str(raw).strip()):
                is_target = target_key(raw) == target or target_key(raw).split(".", 1)[0] == target.split(".", 1)[0]
                _add_machine(v, str(raw), is_target=is_target)
    return v


def _privileged_snapshot_source(target: str, data_dir: Path) -> KnownValues:
    """The newest privileged-account read of this machine: every local account and UID."""
    from kratos.adapters.findings_engine import _latest_input_for

    v = KnownValues()
    path = _latest_input_for(data_dir / "context", "privileged_accounts_*.json", "privileged_accounts", target)
    if path is None:
        return v
    doc = json.loads(path.read_text(encoding="utf-8"))
    local = doc.get("local_accounts")
    if isinstance(local, dict) and local:
        for name, uid in local.items():
            v.accounts[str(name)] = uid if isinstance(uid, int) else None
        v.account_list_complete = True
    for name, acct in (doc.get("accounts") or {}).items():
        uid = acct.get("uid") if isinstance(acct, dict) else None
        if v.accounts.get(str(name)) is None:
            v.accounts[str(name)] = uid if isinstance(uid, int) else None
    return v


def _events_source(target: str, data_dir: Path) -> KnownValues:
    """Account names in this machine's stored events (last 30 days)."""
    v = KnownValues()
    db = data_dir / "kratos.db"
    if not db.exists():
        return v
    from kratos.storage.sqlite_files import connect_store

    conn = connect_store(db)
    try:
        rows = conn.execute(
            "SELECT DISTINCT user_name FROM host_events WHERE target = ? AND user_name IS NOT NULL AND ts >= ? "
            "LIMIT 2000", (target, time.time() - 30 * 86400)).fetchall()
    except sqlite3.Error:     # no event table yet
        return v
    finally:
        conn.close()
    for (name,) in rows:
        v.seen_names.add(str(name))           # from logs: possibly an attacker's text
    return v


def _account_findings_source(target: str, data_dir: Path) -> KnownValues:
    """Accounts named by this machine's privileged-account findings."""
    v = KnownValues()
    db = data_dir / "kratos.db"
    if not db.exists():
        return v
    from kratos.storage.sqlite_files import connect_store

    conn = connect_store(db)
    try:
        rows = conn.execute("SELECT subject, entities FROM finding_records WHERE target = ? AND rule_id LIKE 'PRIV-%'",
                            (target,)).fetchall()
    except sqlite3.Error:
        return v
    finally:
        conn.close()
    for subject, entities in rows:
        names = [subject]
        try:
            names += list(json.loads(entities or "[]"))
        except ValueError:
            pass
        for n in names:
            if isinstance(n, str) and n and not n.startswith("%"):
                v.accounts.setdefault(n, None)
    return v


register_value_source("config", _config_source)
register_value_source("subagents", _subagent_source)
register_value_source("privileged_accounts", _privileged_snapshot_source)
register_value_source("events", _events_source)
register_value_source("account_findings", _account_findings_source)

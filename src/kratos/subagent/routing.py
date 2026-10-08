"""
Which way Kratos reaches the active target for an investigation read: SSH,
the target's paired sub-agent, or SSH first with the sub-agent as a visible
fallback (docs/subagent_read_routing.md §3, D3).

A target (the IP/hostname a session investigates) is tied to a sub-agent only
by an EXPLICIT link the user made or accepted -- never guessed from a name or
address, which could silently read the wrong box (the host-confusion bug
class). Links live in kratos.db (`subagent_links`, see SubAgentStore).

Link modes:
  - "subagent": reads go through the sub-agent only (no SSH to this box).
    Anything that needs SSH (kept tools) or a network path from Kratos
    (nmap, vuln scan) says so plainly instead of running.
  - "ssh_first": SSH as today; if SSH can't connect, the same named read
    goes through the sub-agent and the result says so.

Every routed read leaves a short note (collect_notes) that the tool dispatcher
attaches to the tool result, so the model and the person both see how a fact
was obtained.

Core-side only (never shipped to a target).
"""
from __future__ import annotations

import contextlib
import contextvars
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from kratos.storage.sqlite_files import prepare_private_db
from kratos import kratos_config as _kconfig

MODE_SUBAGENT = "subagent"
MODE_SSH_FIRST = "ssh_first"
MODES = (MODE_SUBAGENT, MODE_SSH_FIRST)
MODE_LABELS = {
    MODE_SUBAGENT: "through its sub-agent only",
    MODE_SSH_FIRST: "SSH first, sub-agent if SSH fails",
}

_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
# After an SSH connection failure, skip straight to the sub-agent for this long
# instead of paying the connect timeout on every read of one investigation.
SSH_DOWN_TTL_SECONDS = 60.0
_LINK_CACHE_TTL_SECONDS = 2.0


@dataclass(frozen=True)
class Link:
    host: str
    target_id: str
    mode: str
    name: str | None = None
    revoked: bool = False

    @property
    def label(self) -> str:
        return self.name or self.target_id


def normalize_host(host: str) -> str:
    return (host or "").strip().lower()


# ---------------------------------------------------------------------------
# Link lookup (read-only, cheap -- runs on every routed read)
# ---------------------------------------------------------------------------
_cache_lock = threading.Lock()
_link_cache: dict[tuple[str, str], tuple[float, Link | None]] = {}


def clear_cache() -> None:
    with _cache_lock:
        _link_cache.clear()


def link_for(host: str, data_dir: Path | None) -> Link | None:
    host = normalize_host(host)
    if not host or host in _LOOPBACK or data_dir is None:
        return None
    db = Path(data_dir) / "kratos.db"
    key = (str(db), host)
    now = time.monotonic()
    with _cache_lock:
        hit = _link_cache.get(key)
        if hit and now - hit[0] < _LINK_CACHE_TTL_SECONDS:
            return hit[1]
    link = _read_link(db, host)
    with _cache_lock:
        _link_cache[key] = (now, link)
    return link


def _read_link(db: Path, host: str) -> Link | None:
    if not db.exists():
        return None
    try:
        prepare_private_db(db, create=False)
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(
            "SELECT l.host, l.target_id, l.mode, t.name, t.hostname, t.revoked_at "
            "FROM subagent_links l LEFT JOIN subagent_targets t ON t.target_id = l.target_id WHERE l.host = ?",
            (host,),
        ).fetchone()
    except sqlite3.Error:  # table not created yet (no link ever made)
        return None
    finally:
        conn.close()
    if row is None:
        return None
    mode = row[2] if row[2] in MODES else MODE_SSH_FIRST
    return Link(host=row[0], target_id=row[1], mode=mode, name=row[3] or row[4], revoked=bool(row[5]))


def active_link() -> Link | None:
    return link_for(_kconfig.get_active_target(), _kconfig.get_active_data_dir())


def is_subagent_only(host: str | None = None) -> bool:
    link = active_link() if host is None else link_for(host, _kconfig.get_active_data_dir())
    return link is not None and link.mode == MODE_SUBAGENT


# ---------------------------------------------------------------------------
# SSH-down memory (per host, short)
# ---------------------------------------------------------------------------
_ssh_down: dict[str, tuple[float, str]] = {}


def mark_ssh_down(host: str, reason: str) -> None:
    _ssh_down[normalize_host(host)] = (time.monotonic(), reason)


def ssh_down_reason(host: str) -> str | None:
    hit = _ssh_down.get(normalize_host(host))
    if hit and time.monotonic() - hit[0] < SSH_DOWN_TTL_SECONDS:
        return hit[1]
    return None


def clear_ssh_down(host: str | None = None) -> None:
    if host is None:
        _ssh_down.clear()
    else:
        _ssh_down.pop(normalize_host(host), None)


# ---------------------------------------------------------------------------
# Transport notes (attached to each tool result by the dispatcher)
# ---------------------------------------------------------------------------
_notes: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar("kratos_transport_notes", default=None)


@contextlib.contextmanager
def collect_notes() -> Iterator[list[str]]:
    bucket: list[str] = []
    token = _notes.set(bucket)
    try:
        yield bucket
    finally:
        _notes.reset(token)


def note(text: str) -> None:
    bucket = _notes.get()
    if bucket is not None and text not in bucket:
        bucket.append(text)


# ---------------------------------------------------------------------------
# One read through the agent
# ---------------------------------------------------------------------------
def agent_read(link: Link, probe: str, params: dict[str, Any]) -> dict[str, Any]:
    """{status, reason?, data?}. Never raises."""
    if link.revoked:
        return {"status": "offline", "reason": f"{link.label} is no longer paired with Kratos -- pair it again "
                                               "from /subagent, or unlink this target with /target link"}
    data_dir = _kconfig.get_active_data_dir()
    if data_dir is None:
        return {"status": "error", "reason": "Kratos doesn't know its data folder in this process"}
    from kratos.subagent.local_reads import LocalReadError, request_read

    try:
        return request_read(data_dir, link.target_id, probe, params)
    except LocalReadError as e:
        return {"status": "no_listener" if e.kind == "no_listener" else "error", "reason": str(e)}


def network_scan_refusal(host: str | None = None) -> str | None:
    """Why a network scan (nmap/vuln) can't run against a sub-agent-only target,
    or None. Never scan a substitute address instead."""
    target = host or _kconfig.get_active_target()
    link = link_for(target, _kconfig.get_active_data_dir())
    if link is None or link.mode != MODE_SUBAGENT:
        return None
    return (f"network scan not available for {target}: Kratos reaches this box only through its sub-agent "
            "(no direct network path from Kratos), so open ports/exposure were NOT checked. The sub-agent "
            "can't run network scans. If this box should be reachable from Kratos, set up direct access and "
            "switch it with /target link.")

"""
Liveness derivation for a paired sub-agent target (capability 1). Pure
functions, no I/O -- usable identically from inside the running core-server
process (which also has real live-socket state) and from a separate CLI
invocation like `kratos subagent-status` (which only has the persisted
last_seen timestamp).

Three real states, matching the design canvas's status chip
(tui_mk2/screens/phase2_preview.py::_subagent_status): connected, stale
("zombie" from the outside -- was alive, has gone quiet), unreachable. A
fourth, never_connected, covers a paired-but-never-checked-in target.
"""
from __future__ import annotations

from datetime import datetime

from kratos.utils.timeutil import parse_stored_instant, utc_now

STATUS_CONNECTED = "connected"
STATUS_STALE = "stale"
STATUS_UNREACHABLE = "unreachable"
STATUS_NEVER = "never_connected"

# Generous versus the agent's default 10s ping interval -- tolerates one
# missed beat (a slow collection cycle, a brief GC-style pause) without
# flapping between connected/stale on every status query.
CONNECTED_WINDOW_SECONDS = 30
# Beyond this with no signal at all, treat the target as unreachable rather
# than merely stale -- matches PING_TIMEOUT_SECONDS-scale reasoning on the
# core server side (a live socket that's gone this quiet gets closed there
# too, so "stale" and "no live socket" converge here anyway).
STALE_WINDOW_SECONDS = 120


def derive_status(last_seen: str | None, *, live: bool | None = None, now: datetime | None = None) -> str:
    """
    last_seen: the persisted ISO timestamp of the most recent hello/
      telemetry/ping received from this target, or None if it has never
      connected.
    live: True/False when the caller has real socket state for this target
      (the core-server process itself); None when it doesn't (a separate
      CLI query) -- in that case status is derived purely from last_seen
      recency.
    """
    if last_seen is None:
        return STATUS_NEVER
    now = now or utc_now()
    seen = parse_stored_instant(last_seen)
    if seen is None:
        return STATUS_NEVER
    age = (now - seen).total_seconds()

    if live is False:
        return STATUS_UNREACHABLE
    if live is True:
        # A real open socket is ground truth over pure time -- but if it's
        # been open a long time with no recent signal at all, the design's
        # own "network up, process not responding" zombie case still reads
        # as stale here, not a blind "connected".
        return STATUS_CONNECTED if age <= STALE_WINDOW_SECONDS else STATUS_STALE

    if age <= CONNECTED_WINDOW_SECONDS:
        return STATUS_CONNECTED
    if age <= STALE_WINDOW_SECONDS:
        return STATUS_STALE
    return STATUS_UNREACHABLE

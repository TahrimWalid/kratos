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


# ---------------------------------------------------------------------------
# Full connection assessment (docs/subagent_connection_ux.md WS1 + WS10).
#
# derive_status() above only knows last_seen age, which can't tell a zombie
# (socket up, telemetry stopped) from a healthy agent, can't tell "the agent
# is down" from "no Kratos listener is running", and can't say "the link just
# dropped and the agent is retrying". assess() uses what the listener records
# (subagent_store: listeners + connections + events) to give one truthful
# state with a plain reason. Pure -- the caller passes everything in.
# ---------------------------------------------------------------------------
from dataclasses import dataclass  # noqa: E402
from typing import Any  # noqa: E402

STATE_CONNECTED = "connected"
STATE_STALLED = "telemetry_stalled"        # socket up and answering pings, but no snapshots (a zombie)
STATE_UNRESPONSIVE = "unresponsive"        # socket open but nothing at all is arriving
STATE_RECONNECTING = "reconnecting"        # dropped recently; the agent retries on its own
STATE_OFFLINE = "offline"                  # not connected for longer than any retry would take
STATE_NOT_WATCHED = "not_watched"          # no Kratos listener is running, so nothing can be known
STATE_NEVER = STATUS_NEVER
STATE_REVOKED = "revoked"
STATE_SUPERSEDED = "superseded"            # down, and a newer pairing from the same machine is live

LISTENER_HEARTBEAT_SECONDS = 5.0
# A listener whose heartbeat is older than this is treated as gone.
LISTENER_STALE_AFTER_SECONDS = 20.0
DEFAULT_PING_INTERVAL = 10.0
DEFAULT_COLLECT_INTERVAL = 30.0
# The agent's reconnect backoff tops out at 60s (agent.BACKOFF_MAX_SECONDS);
# a drop younger than this is "reconnecting", not "offline".
RECONNECT_GRACE_SECONDS = 90.0
# core_server's reason when IT closed a link that went silent (the agent may
# not have noticed yet).
SILENT_DROP_PREFIX = "no message from the agent"
FLAKY_DISCONNECTS_PER_HOUR = 3
# A revoked agent that tried to connect this recently is still running on its box.
REVOKED_STILL_TRYING_SECONDS = 600.0


@dataclass(frozen=True)
class ConnectionState:
    state: str
    label: str
    reason: str
    severity: str  # ok | attention | critical | muted
    last_contact: str | None = None
    flaky: bool = False


def _age(iso: str | None, now: datetime) -> float | None:
    dt = parse_stored_instant(iso) if iso else None
    return None if dt is None else max(0.0, (now - dt).total_seconds())


def human_age(seconds: float | None) -> str:
    if seconds is None:
        return "never"
    s = int(seconds)
    if s < 90:
        return f"{s}s ago"
    if s < 90 * 60:
        return f"{s // 60} min ago"
    if s < 48 * 3600:
        return f"{s // 3600} h ago"
    return f"{s // 86400} days ago"


def estimate_collect_interval(connection: dict[str, Any] | None, received_times: list[str]) -> float:
    """The agent's snapshot interval: what it announced at connect, else the
    median spacing of the last few snapshots, else the default."""
    announced = (connection or {}).get("collect_interval")
    if isinstance(announced, (int, float)) and announced > 0:
        return float(announced)
    stamps = sorted(t for t in (parse_stored_instant(x) for x in received_times) if t is not None)
    gaps = sorted((b - a).total_seconds() for a, b in zip(stamps, stamps[1:]) if (b - a).total_seconds() > 0)
    return gaps[len(gaps) // 2] if gaps else DEFAULT_COLLECT_INTERVAL


def assess(
    target: dict[str, Any],
    *,
    connection: dict[str, Any] | None,
    listener_live: bool,
    events: list[dict[str, Any]],
    collect_interval: float = DEFAULT_COLLECT_INTERVAL,
    now: datetime | None = None,
) -> ConnectionState:
    """One truthful state for a paired target.

    `connection` is its subagent_connections row (or None); `listener_live`
    whether any listener heartbeat is fresh; `events` its connection events
    from the last hour."""
    now = now or utc_now()
    last_seen_age = _age(target.get("last_seen"), now)
    last_contact = target.get("last_seen")
    disconnects = sum(1 for e in events if e.get("event") == "disconnected")
    flaky = disconnects >= FLAKY_DISCONNECTS_PER_HOUR
    flaky_note = f" · unstable link: {disconnects} drops in the last hour" if flaky else ""

    if target.get("revoked_at"):
        tries = [e for e in events if e.get("event") == "rejected"]
        last_try = _age(tries[-1]["at"], now) if tries else None
        if last_try is not None and last_try <= REVOKED_STILL_TRYING_SECONDS:
            return ConnectionState(STATE_REVOKED, "revoked", f"unpaired, but its agent is still running on the box "
                                   f"and trying to connect (last try {human_age(last_try)}) -- stop it there",
                                   "attention", last_contact)
        return ConnectionState(STATE_REVOKED, "revoked", f"unpaired {human_age(_age(target.get('revoked_at'), now))}",
                               "muted", last_contact)

    if last_seen_age is None:
        return ConnectionState(STATE_NEVER, "never connected", "paired but has not checked in yet", "muted", None)

    if not listener_live:
        return ConnectionState(STATE_NOT_WATCHED, "not watched",
                               f"no Kratos listener is running, so its state is unknown "
                               f"(last contact {human_age(last_seen_age)})", "attention", last_contact)

    conn = connection or {}
    open_now = bool(conn.get("connected_at")) and not conn.get("disconnected_at")
    if open_now:
        ping = conn.get("ping_interval") if isinstance(conn.get("ping_interval"), (int, float)) else DEFAULT_PING_INTERVAL
        frame_age = _age(conn.get("last_frame_at"), now)
        if frame_age is not None and frame_age > max(2.5 * ping, 25.0):
            return ConnectionState(STATE_UNRESPONSIVE, "unresponsive",
                                   f"connection is open but nothing has arrived for {int(frame_age)}s", "critical",
                                   last_contact, flaky)
        tel_age = _age(conn.get("last_telemetry_at"), now)
        since_connect = _age(conn.get("connected_at"), now) or 0.0
        stall_after = max(90.0, 3 * collect_interval)
        if (tel_age is None and since_connect > stall_after) or (tel_age is not None and tel_age > stall_after):
            return ConnectionState(STATE_STALLED, "telemetry stalled",
                                   f"connected and answering, but no snapshot for "
                                   f"{int(tel_age if tel_age is not None else since_connect)}s "
                                   f"(expected every ~{int(collect_interval)}s){flaky_note}", "attention",
                                   last_contact, flaky)
        return ConnectionState(STATE_CONNECTED, "connected",
                               f"live · last snapshot {human_age(tel_age) if tel_age is not None else 'pending'}"
                               f"{flaky_note}", "attention" if flaky else "ok", last_contact, flaky)

    down_age = _age(conn.get("disconnected_at"), now)
    why = conn.get("disconnect_reason") or "connection closed"
    if down_age is not None and down_age <= RECONNECT_GRACE_SECONDS:
        if why.startswith(SILENT_DROP_PREFIX):
            # Core gave up on a silent link; the agent notices on its own
            # timer, so a countdown from core's drop time would be wrong
            # (a real link drill showed it hitting "~1s" again and again).
            when = "retries on its own once it notices the silence, then at most a minute apart"
        else:
            when = f"tries again in ~{max(1, round(next_agent_retry_in(down_age)))}s"
        return ConnectionState(STATE_RECONNECTING, "reconnecting",
                               f"dropped {human_age(down_age)} ({why}); if its agent is still running it {when}"
                               f"{flaky_note}", "attention", last_contact, flaky)
    if not conn and last_seen_age <= CONNECTED_WINDOW_SECONDS:
        # Recorded before connection tracking existed; fall back to recency.
        return ConnectionState(STATE_CONNECTED, "connected", f"last contact {human_age(last_seen_age)}", "ok",
                               last_contact)
    detail = f"; last disconnect: {why}" if conn else ""
    return ConnectionState(STATE_OFFLINE, "offline",
                           f"no contact since {human_age(last_seen_age)}{detail}. If its agent is still running it "
                           f"retries about once a minute and reappears on its own when the link is back{flaky_note}",
                           "critical", last_contact, flaky)


def next_agent_retry_in(down_age: float) -> float:
    """Seconds until a still-running agent's next reconnect attempt, from its
    backoff policy (agent.py: 2s doubling to 60s, reset by a working session)
    counted from the drop. An estimate: a connect attempt over a dead link can
    itself take a while."""
    from kratos.subagent.agent import BACKOFF_INITIAL_SECONDS, BACKOFF_MAX_SECONDS

    t, step = 0.0, BACKOFF_INITIAL_SECONDS
    while True:
        t += step
        if t > down_age:
            return t - down_age
        step = min(step * 2, BACKOFF_MAX_SECONDS)


def assess_all(store: Any, now: datetime | None = None) -> list[tuple[dict[str, Any], ConnectionState]]:
    """(target, state) for every paired target, from what the listener
    recorded. Shared by `kratos subagent-status` and the /subagent screen."""
    now = now or utc_now()
    listener_live = bool(store.live_listeners(LISTENER_STALE_AFTER_SECONDS))
    connections = store.list_connections()
    out = []
    for t in store.list_targets():
        conn = connections.get(t["target_id"])
        events = store.recent_events(t["target_id"], 3600)
        interval = estimate_collect_interval(conn, store.telemetry_received_times(t["target_id"]))
        out.append((t, assess(t, connection=conn, listener_live=listener_live, events=events,
                              collect_interval=interval, now=now)))
    return mark_superseded(out, {tid: (c or {}).get("peer") for tid, c in connections.items()})


def mark_superseded(assessed: list[tuple[dict[str, Any], ConnectionState]],
                    peers: dict[str, str | None]) -> list[tuple[dict[str, Any], ConnectionState]]:
    """An offline pairing is almost certainly a machine's OLD identity -- left
    behind when the box was reinstalled or paired again outside the re-pair
    flow -- when a NEWER pairing that is connected reports the same hostname
    AND connects from the same address. Both must match: cloud VMs often share
    a default hostname, and a real outage must never be relabelled on a
    hostname alone. Still an action item for the operator (unpair it)."""
    live: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for t, st in assessed:
        peer = peers.get(t["target_id"])
        if st.state == STATE_CONNECTED and t.get("hostname") and peer:
            live.setdefault((t["hostname"], peer), []).append(t)
    out = []
    for t, st in assessed:
        peer = peers.get(t["target_id"])
        if st.state == STATE_OFFLINE and t.get("hostname") and peer:
            newer = [o for o in live.get((t["hostname"], peer), [])
                     if o["target_id"] != t["target_id"] and (o.get("paired_at") or "") > (t.get("paired_at") or "")]
            if newer:
                n = newer[0]
                st = ConnectionState(
                    STATE_SUPERSEDED, "replaced?",
                    f"probably an old identity: {n.get('name') or n['target_id']} from the same machine "
                    f"({t['hostname']}, {peer}) paired later and is live. Unpair this row (u) if so.",
                    "attention", st.last_contact, st.flaky)
        out.append((t, st))
    return out


def _version_tuple(v: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in (v or "").strip().split(".")[:3])
    except ValueError:
        return ()


def agent_outdated(version: str | None) -> bool:
    """True when a machine's agent is older than the agent this Kratos ships
    (so `g` in /subagent would update it). Unknown versions aren't flagged."""
    from kratos.subagent.agent import AGENT_VERSION

    have = _version_tuple(version)
    return bool(have) and have < _version_tuple(AGENT_VERSION)

"""Continuous detection on agents -- Kratos's side (phase C.2).

What a person turns on per machine (people only, like every decision), what each
agent should run (the rule packs, the rules turned off for that machine, the
watcher's limits -- pushed as signed, versioned DATA by the listener), and what
comes back:

  * a **detection** from an agent becomes a detection event in the event store
    (dataset kratos.detect), with the same id the scheduled pass would give it --
    so the same match seen live and later over the synced logs is stored once --
    and then a finding through the ONE path C.1 uses: the detections snapshot ->
    findings.build -> the lifecycle -> trigger evaluation -> notify. Detections of
    one machine arriving within `detect.alert_batch_seconds` are published together,
    so a burst is one alert;
  * a **watch status** updates `detect_watch` (per machine and log source: state,
    watching since, events per minute, lag, drops, gaps) -- what /subagent, /detect,
    /doctor and C.3's hunt coverage read.

Health is a finding: DETECT-002 ("continuous detection isn't running on <machine>")
is open while a watched machine's watcher has stopped, its link has been down
longer than `detect.watch.offline_minutes`, nothing was heard from the watcher for
3 minutes while connected, its rules were refused, or a stretch of log went
unwatched within the last hour; it closes by itself when watching resumes.

Nothing here can act on a machine: no command text is ever sent, and a trigger's
actions stay notify / playbook / read-only investigation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos import run_context, settings_store
from kratos.detect import pack as packs_mod
from kratos.detect import settings as S
from kratos.detect import store as dstore
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

WATCH_MIN_AGENT_VERSION = (0, 9, 0)
STATUS_STALE_SECONDS = 180.0          # no watch status for this long while connected: not watching
GAP_RECENT_SECONDS = 3600.0           # an unwatched stretch keeps DETECT-002 open this long after it is reported
UNCONFIRMED_SECONDS = 180.0           # turned on, but the agent hasn't confirmed the rules for this long
SOURCE_RESTART_GRACE_SECONDS = 60.0   # a watcher restarting for longer than this counts as stopped
MAX_GAPS = 500
PACK_CACHE_SECONDS = 30.0
DETECTION_RULE = "DETECT-002"
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_RULE_ID = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,63}$")
SOURCE_LABELS = {"journal": "the systemd journal (sign-ins, sudo, cron, services, firewall)",
                 "auditd": "the audit log (program starts, account changes, file creation)"}
# Which log a dataset's lines come from when an agent watches them.
WATCHED_DATASETS = {"kratos.auth": "journal", "kratos.cron": "journal", "kratos.systemd": "journal",
                    "kratos.firewall": "journal", "kratos.auditd": "auditd"}


class WatchSetupError(ValueError):
    """Watching can't be turned on or off as asked (plain words for the person)."""


def _now() -> float:
    return time.time()


def _db(data_dir: Path | str) -> Any:
    return dstore._connect(data_dir)


def parse_version(value: Any) -> tuple[int, ...] | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,4}(\.\d{1,4}){1,3}", value.strip()):
        return None
    return tuple(int(x) for x in value.strip().split("."))


def agent_can_watch(agent_version: Any) -> bool:
    v = parse_version(agent_version)
    return v is not None and v >= WATCH_MIN_AGENT_VERSION


UPDATE_HINT = ("update the agent to watch continuously (/subagent, select the machine, press g) -- it needs agent "
               f"{'.'.join(map(str, WATCH_MIN_AGENT_VERSION))} or newer")


# ---------------------------------------------------------------------------- which machine
def machine_for(target: dict[str, Any], links: list[dict[str, Any]]) -> str:
    """The name a paired agent's detections and findings are filed under: the address
    a person linked to it (what investigations of it use), else its name."""
    mine = [l for l in links if l.get("target_id") == target.get("target_id")]
    if mine:
        mine.sort(key=lambda l: str(l.get("updated_at") or ""), reverse=True)
        return target_key(mine[0]["host"])
    return target_key(str(target.get("name") or target.get("hostname") or target.get("target_id")))


def _subagent_store(data_dir: Path | str) -> Any:
    from kratos.storage.subagent_store import SubAgentStore

    return SubAgentStore(Path(data_dir) / "kratos.db")


# ---------------------------------------------------------------------------- what an agent should run
def agent_settings(data_dir: Path | str) -> dict[str, int]:
    """Kratos's detect.watch.* settings as the watcher's closed settings (watch.SETTINGS)."""
    def g(key: str) -> int:
        return int(settings_store.get(key, data_dir=data_dir))

    return {"spool_max_detections": g(S.WATCH_SPOOL_DETECTIONS), "spool_max_bytes": g(S.WATCH_SPOOL_MB) * 1024 * 1024,
            "max_catchup_seconds": g(S.WATCH_CATCHUP_HOURS) * 3600, "max_catchup_entries": g(S.WATCH_CATCHUP_ENTRIES),
            "max_per_rule_minute": g(S.WATCH_PER_RULE_MINUTE), "max_cpu_percent": g(S.WATCH_CPU_PERCENT),
            "follow_auditd": 1}


_pack_cache: dict[str, tuple[float, Any]] = {}
_pack_lock = threading.Lock()


def loaded_packs(data_dir: Path | str) -> Any:
    """The rule packs (shipped + imported), re-read at most every PACK_CACHE_SECONDS."""
    key = str(Path(data_dir).resolve())
    with _pack_lock:
        hit = _pack_cache.get(key)
        if hit is not None and _now() - hit[0] < PACK_CACHE_SECONDS:
            return hit[1]
    loaded = packs_mod.load(data_dir)
    with _pack_lock:
        _pack_cache[key] = (_now(), loaded)
    return loaded


def desired_config(data_dir: Path | str, target_id: str, *, state: dict[str, Any] | None = None,
                   machine: str | None = None) -> dict[str, Any]:
    """What `target_id`'s agent should run now (the body of a detect_pack_push)."""
    state = state if state is not None else (pack_state(data_dir, target_id) or {})
    machine = machine or state.get("machine") or ""
    enabled = bool(state.get("enabled"))
    loaded = loaded_packs(data_dir)
    return {
        "enabled": enabled,
        "machine": machine,
        "packs": [lp.pack.raw for lp in loaded.loaded] if enabled else [],
        "disabled": sorted(dstore.disabled_rules(data_dir, machine)) if enabled and machine else [],
        "settings": agent_settings(data_dir),
    }


def config_digest(cfg: dict[str, Any]) -> str:
    body = {k: v for k, v in cfg.items() if k != "packs"}
    body["packs"] = [(p.get("pack_id"), p.get("pack_version"), p.get("sha256")) for p in cfg.get("packs") or []]
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def sync_version(data_dir: Path | str, target_id: str) -> tuple[int, dict[str, Any]] | None:
    """(push version, configuration) for a target whose watching was ever turned on --
    the version counts up whenever the configuration changes. None: never turned on."""
    state = pack_state(data_dir, target_id)
    if state is None:
        return None
    try:
        target = _subagent_store(data_dir).get_target(target_id)
        links = _subagent_store(data_dir).list_links()
    except Exception:  # noqa: BLE001
        target, links = None, []
    machine = machine_for(target, links) if target else state.get("machine") or ""
    cfg = desired_config(data_dir, target_id, state=state, machine=machine)
    digest = config_digest(cfg)
    if digest == state.get("desired_digest") and machine == state.get("machine"):
        return int(state["push_version"]), cfg
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT push_version, desired_digest FROM detect_pack_state WHERE target_id = ?",
                           (target_id,)).fetchone()
        version = int(row[0]) if row else 0
        if row is None or row[1] != digest:
            version += 1
            conn.execute("UPDATE detect_pack_state SET push_version = ?, desired_digest = ?, machine = ? "
                         "WHERE target_id = ?", (version, digest, machine, target_id))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return version, cfg


# ---------------------------------------------------------------------------- people turn it on and off
def set_watching(data_dir: Path | str, target_id: str, on: bool, *, actor: Any) -> dict[str, Any]:
    """Turn continuous detection on or off for one paired machine. People only: refused
    inside an agent tool call, and `actor` must be a person (lifecycle.decide.Actor)."""
    from kratos.lifecycle.decide import INTERFACES

    tool = settings_store.in_tool_call()
    if tool is not None:
        raise WatchSetupError(f"agent tools may not turn continuous detection on or off (tool {tool!r} tried)")
    if not str(getattr(actor, "user", "") or "").strip() or getattr(actor, "interface", None) not in INTERFACES:
        raise WatchSetupError("turning continuous detection on or off needs a person (the TUI or the CLI)")
    store = _subagent_store(data_dir)
    target = store.get_target(target_id)
    if target is None or target.get("revoked_at"):
        raise WatchSetupError("that machine isn't paired with Kratos")
    if on:
        if not agent_can_watch(target.get("agent_version")):
            raise WatchSetupError(f"this machine runs agent {target.get('agent_version') or '(unknown)'}; "
                                  + UPDATE_HINT)
        if target.get("link_mode") != "tls-pinned" and not _plaintext_trusted(data_dir, target_id):
            raise WatchSetupError("continuous detection sends matched log lines to Kratos, so it needs an encrypted "
                                  "agent link -- update the agent (g in /subagent) so it connects over TLS")
    machine = machine_for(target, store.list_links())
    who = f"{actor.user} via {actor.interface}"
    now = _now()
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO detect_pack_state (target_id, machine, enabled, changed_by, changed_at) "
                     "VALUES (?,?,?,?,?) ON CONFLICT(target_id) DO UPDATE SET machine = excluded.machine, "
                     "enabled = excluded.enabled, changed_by = excluded.changed_by, changed_at = excluded.changed_at",
                     (target_id, machine, int(bool(on)), who, now))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    sync_version(data_dir, target_id)
    try:
        store.record_connection_event(target_id, "watch_on" if on else "watch_off",
                                      f"continuous detection turned {'on' if on else 'off'} by {who}")
    except Exception:  # noqa: BLE001
        pass
    return pack_state(data_dir, target_id) or {}


def _plaintext_trusted(data_dir: Path | str, target_id: str) -> bool:
    """An agent without pins whose own transport check passes (loopback / Tailscale):
    the older trusted-transport rule. From the ceiling report it sent in its hello."""
    try:
        from kratos.storage.whitelist_store import WhitelistStore

        state = WhitelistStore(Path(data_dir) / "kratos.db").get_agent_state(target_id) or {}
        return bool((state.get("ceiling") or {}).get("transport_trusted"))
    except Exception:  # noqa: BLE001 -- unknown: not trusted
        return False


def mark_trigger_offered(data_dir: Path | str, target_id: str) -> None:
    conn = _db(data_dir)
    try:
        conn.execute("UPDATE detect_pack_state SET trigger_offered = 1 WHERE target_id = ?", (target_id,))
        conn.commit()
    finally:
        conn.close()


def any_trigger_offered(data_dir: Path | str) -> bool:
    conn = _db(data_dir)
    try:
        return conn.execute("SELECT 1 FROM detect_pack_state WHERE trigger_offered = 1 LIMIT 1").fetchone() is not None
    finally:
        conn.close()


# ---------------------------------------------------------------------------- reading the state
_PACK_COLS = ("target_id, machine, enabled, changed_by, changed_at, push_version, desired_digest, acked_version, "
              "ack_status, ack_reason, ack_at, agent_packs, last_status_at, health, trigger_offered")


def _pack_row(r: Any) -> dict[str, Any]:
    d = dict(zip([c.strip() for c in _PACK_COLS.split(",")], r))
    for key in ("agent_packs", "health"):
        try:
            d[key] = json.loads(d[key]) if d[key] else None
        except ValueError:
            d[key] = None
    d["enabled"] = bool(d["enabled"])
    return d


def pack_state(data_dir: Path | str, target_id: str) -> dict[str, Any] | None:
    conn = _db(data_dir)
    try:
        r = conn.execute(f"SELECT {_PACK_COLS} FROM detect_pack_state WHERE target_id = ?", (target_id,)).fetchone()
    finally:
        conn.close()
    return _pack_row(r) if r else None


def pack_states(data_dir: Path | str) -> list[dict[str, Any]]:
    conn = _db(data_dir)
    try:
        rows = conn.execute(f"SELECT {_PACK_COLS} FROM detect_pack_state ORDER BY target_id").fetchall()
    finally:
        conn.close()
    return [_pack_row(r) for r in rows]


def watched_targets(data_dir: Path | str, machine: str | None = None) -> list[dict[str, Any]]:
    out = [s for s in pack_states(data_dir) if s["enabled"]]
    if machine is not None:
        key = target_key(machine)
        out = [s for s in out if s.get("machine") == key]
    return out


def watch_rows(data_dir: Path | str, target_id: str | None = None) -> list[dict[str, Any]]:
    cols = ("target_id, source, machine, state, since, watching_since, last_event_ts, events_per_min, matches, "
            "lag_seconds, dropped, skipped, gaps, error, updated_at")
    conn = _db(data_dir)
    try:
        if target_id is None:
            rows = conn.execute(f"SELECT {cols} FROM detect_watch ORDER BY target_id, source").fetchall()
        else:
            rows = conn.execute(f"SELECT {cols} FROM detect_watch WHERE target_id = ? ORDER BY source",
                                (target_id,)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(zip([c.strip() for c in cols.split(",")], r))
        try:
            d["gaps"] = json.loads(d["gaps"]) if d["gaps"] else []
        except ValueError:
            d["gaps"] = []
        out.append(d)
    return out


# ---------------------------------------------------------------------------- what agents report
def record_ack(data_dir: Path | str, target_id: str, msg: dict[str, Any]) -> None:
    version = msg.get("version") if type(msg.get("version")) is int else None
    status = "ok" if msg.get("status") == "ok" else "refused"
    reason = str(msg.get("reason") or "")[:500] or None
    packs = msg.get("packs") if isinstance(msg.get("packs"), list) else None
    clean = None
    if packs is not None:
        clean = [{"pack_id": str(p.get("pack_id"))[:64], "pack_version": p.get("pack_version")
                  if type(p.get("pack_version")) is int else None, "sha256": str(p.get("sha256"))[:64]}
                 for p in packs[:16] if isinstance(p, dict)]
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if status == "ok":
            conn.execute("UPDATE detect_pack_state SET acked_version = ?, ack_status = 'ok', ack_reason = NULL, "
                         "ack_at = ?, agent_packs = ? WHERE target_id = ?",
                         (version, _now(), json.dumps(clean) if clean is not None else None, target_id))
        else:
            conn.execute("UPDATE detect_pack_state SET ack_status = 'refused', ack_reason = ?, ack_at = ? "
                         "WHERE target_id = ?", (reason, _now(), target_id))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _num(v: Any, lo: float = 0.0, hi: float = 1e13) -> float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v) if lo <= v <= hi else None


def _clean_gaps(raw: Any, seen_at: float) -> list[dict[str, Any]]:
    out = []
    for g in (raw if isinstance(raw, list) else [])[:100]:
        if not isinstance(g, dict):
            continue
        a, b = _num(g.get("from")), _num(g.get("to"))
        if a is None or b is None or b < a:
            continue
        out.append({"from": a, "to": b, "reason": re.sub(r"[\x00-\x1f\x7f]", " ", str(g.get("reason") or ""))[:300],
                    "kind": "spool" if g.get("kind") == "spool" else "watch", "seen_at": seen_at})
    return out


def record_status(data_dir: Path | str, target_id: str, msg: dict[str, Any]) -> list[dict[str, Any]]:
    """Store one watch_status. Returns the gaps it reported that Kratos hadn't seen."""
    state = pack_state(data_dir, target_id) or {}
    machine = state.get("machine")
    now = _now()
    new_gaps: list[dict[str, Any]] = []
    conn = _db(data_dir)
    try:
        conn.execute("BEGIN IMMEDIATE")
        for src in (msg.get("sources") if isinstance(msg.get("sources"), list) else [])[:4]:
            if not isinstance(src, dict) or src.get("name") not in SOURCE_LABELS:
                continue
            name = src["name"]
            row = conn.execute("SELECT gaps, state, watching_since FROM detect_watch WHERE target_id = ? AND source = ?",
                               (target_id, name)).fetchone()
            old_gaps = json.loads(row[0]) if row and row[0] else []
            known = {(g.get("from"), g.get("to"), g.get("reason")) for g in old_gaps}
            gaps = list(old_gaps)
            for g in _clean_gaps(src.get("gaps"), now):
                if (g["from"], g["to"], g["reason"]) not in known:
                    gaps.append(g)
                    new_gaps.append({**g, "source": name})
            gaps = gaps[-MAX_GAPS:]
            st = str(src.get("state") or "off")
            st = st if st in ("watching", "restarting", "not_available", "error", "off") else "error"
            since = _num(src.get("since"))
            watching_since = (row[2] if row and row[1] == "watching" and st == "watching" and row[2] else
                              (since or now) if st == "watching" else None)
            conn.execute(
                "INSERT INTO detect_watch (target_id, source, machine, state, since, watching_since, last_event_ts, "
                "events_per_min, matches, lag_seconds, dropped, skipped, gaps, error, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(target_id, source) DO UPDATE SET "
                "machine = excluded.machine, state = excluded.state, since = excluded.since, "
                "watching_since = excluded.watching_since, last_event_ts = excluded.last_event_ts, "
                "events_per_min = excluded.events_per_min, matches = excluded.matches, "
                "lag_seconds = excluded.lag_seconds, dropped = excluded.dropped, skipped = excluded.skipped, "
                "gaps = excluded.gaps, error = excluded.error, updated_at = excluded.updated_at",
                (target_id, name, machine, st, since, watching_since, _num(src.get("last_event_ts")),
                 int(_num(src.get("events_per_min"), 0, 10**9) or 0), int(_num(src.get("matches"), 0, 10**12) or 0),
                 _num(src.get("lag_seconds"), 0, 10**9), int(_num(src.get("dropped"), 0, 10**12) or 0),
                 int(_num(src.get("skipped"), 0, 10**12) or 0), json.dumps(gaps),
                 re.sub(r"[\x00-\x1f\x7f]", " ", str(src.get("error") or ""))[:300] or None, now))
        conn.execute("UPDATE detect_pack_state SET last_status_at = ? WHERE target_id = ?", (now, target_id))
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()
    return new_gaps


# ---------------------------------------------------------------------------- health
@dataclass
class Health:
    watched: bool                        # a person turned watching on
    healthy: bool = True
    reasons: list[tuple[str, str]] = field(default_factory=list)   # (code, plain words)
    sources: list[dict[str, Any]] = field(default_factory=list)
    since: float | None = None           # watching continuously since (all sources that can be watched)

    @property
    def codes(self) -> list[str]:
        return sorted({c for c, _ in self.reasons})


def _connected(store: Any, target_id: str) -> tuple[bool, float | None]:
    """(connected now, when it went down) from the listener's connection records."""
    from kratos.utils.timeutil import parse_stored_instant

    try:
        conn = store.get_connection(target_id) or {}
    except Exception:  # noqa: BLE001
        conn = {}
    down = parse_stored_instant(conn.get("disconnected_at")) if conn.get("disconnected_at") else None
    up = parse_stored_instant(conn.get("connected_at")) if conn.get("connected_at") else None
    if up is not None and (down is None or down < up):
        listeners = []
        try:
            from kratos.subagent.status import LISTENER_STALE_AFTER_SECONDS

            listeners = store.live_listeners(LISTENER_STALE_AFTER_SECONDS)
        except Exception:  # noqa: BLE001
            pass
        if listeners:
            return True, None
        return False, None
    return False, down.timestamp() if down is not None else None


def health(data_dir: Path | str, target_id: str, *, connected: bool | None = None,
           down_since: float | None = None, now: float | None = None) -> Health:
    now = _now() if now is None else now
    state = pack_state(data_dir, target_id)
    if not state or not state["enabled"]:
        return Health(watched=False)
    h = Health(watched=True)
    store = _subagent_store(data_dir)
    target = store.get_target(target_id) or {}
    if connected is None:
        connected, down_since = _connected(store, target_id)
    offline = int(settings_store.get(S.WATCH_OFFLINE_MINUTES, data_dir=data_dir)) * 60
    if not agent_can_watch(target.get("agent_version")):
        h.reasons.append(("agent_too_old", f"this machine's agent ({target.get('agent_version') or '?'}) is too "
                                           "old to watch -- " + UPDATE_HINT))
    if state.get("ack_status") == "refused":
        h.reasons.append(("rules_refused", f"the agent refused the rules: {state.get('ack_reason') or 'no reason'}"))
    elif (state.get("acked_version") or 0) < (state.get("push_version") or 0) and connected \
            and now - (state.get("changed_at") or now) > UNCONFIRMED_SECONDS:
        h.reasons.append(("not_confirmed", "the agent hasn't confirmed the current rules"))
    if not connected:
        if down_since is not None and now - down_since >= offline:
            h.reasons.append(("link_down", "the link to the agent has been down since "
                              + datetime.fromtimestamp(down_since, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                              + " -- the agent keeps watching and sends what it saw when the link is back, but "
                                "nothing reaches you meanwhile"))
        elif down_since is None and now - (state.get("last_status_at") or state.get("changed_at") or now) >= offline:
            h.reasons.append(("link_down", "Kratos hasn't heard from the agent in over "
                              f"{offline // 60} minutes (is the always-on listener running?)"))
    elif state.get("last_status_at") is not None and now - state["last_status_at"] > STATUS_STALE_SECONDS:
        h.reasons.append(("no_status", f"no word from the watcher for {int((now - state['last_status_at']) // 60)} "
                                       "min while the agent is connected"))
    rows = watch_rows(data_dir, target_id)
    h.sources = rows
    starts = []
    for r in rows:
        stuck = r["state"] == "restarting" and (r["since"] is None or now - r["since"] >= SOURCE_RESTART_GRACE_SECONDS)
        if r["state"] == "error" or stuck:
            h.reasons.append((f"stopped:{r['source']}", f"watching {SOURCE_LABELS[r['source']]} stopped: "
                                                         f"{r['error'] or r['state']}"))
        for g in r["gaps"]:
            if now - float(g.get("seen_at") or 0) < GAP_RECENT_SECONDS:
                h.reasons.append((f"gap:{r['source']}",
                                  f"{SOURCE_LABELS[r['source']]} was not watched from "
                                  f"{_utc(g['from'])} to {_utc(g['to'])}: {g['reason']}"))
        if r["state"] == "watching" and r["watching_since"]:
            starts.append(r["watching_since"])
    h.since = max(starts) if starts else None
    h.healthy = not h.reasons
    return h


def health_changes(data_dir: Path | str, *, live: dict[str, tuple[bool, float | None]] | None = None,
                   now: float | None = None) -> list[str]:
    """Machines whose watch health changed since it was last turned into findings (the
    listener publishes those). Stored, so every listener and restart agrees."""
    now = _now() if now is None else now
    out: list[str] = []
    for st in pack_states(data_dir):
        prev = list((st.get("health") or {}).get("codes") or [])
        if not st["enabled"] and not prev:
            continue
        conn, down = (live or {}).get(st["target_id"], (None, None))
        h = health(data_dir, st["target_id"], connected=conn, down_since=down, now=now)
        codes = h.codes if h.watched else []
        if codes == prev:
            continue
        db = _db(data_dir)
        try:
            db.execute("UPDATE detect_pack_state SET health = ? WHERE target_id = ?",
                       (json.dumps({"codes": codes, "at": now}), st["target_id"]))
            db.commit()
        finally:
            db.close()
        if st.get("machine"):
            out.append(st["machine"])
    return sorted(set(out))


def _utc(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OSError):
        return "?"


def watch_summary(data_dir: Path | str, machine: str, *, now: float | None = None,
                  live: dict[str, tuple[bool, float | None]] | None = None) -> dict[str, Any] | None:
    """The `watch` section of a detections snapshot for `machine`: None when no agent
    watches it. `live`: per target, (connected, down since) known first-hand (the listener)."""
    targets = watched_targets(data_dir, machine)
    if not targets:
        return None
    now = _now() if now is None else now
    reasons: list[tuple[str, str]] = []
    sources: list[dict[str, Any]] = []
    since = None
    for st in targets:
        conn, down = (live or {}).get(st["target_id"], (None, None))
        h = health(data_dir, st["target_id"], connected=conn, down_since=down, now=now)
        reasons += h.reasons
        sources += [{"name": r["source"], "state": r["state"], "watching_since": r["watching_since"],
                     "last_event_ts": r["last_event_ts"], "events_per_min": r["events_per_min"],
                     "lag_seconds": r["lag_seconds"], "dropped": r["dropped"], "error": r["error"]} for r in h.sources]
        if h.since is not None:
            since = h.since if since is None else min(since, h.since)
    return {"enabled": True, "healthy": not reasons, "reasons": [{"code": c, "text": t} for c, t in reasons],
            "since": since, "sources": sources, "targets": [t["target_id"] for t in targets]}


# ---------------------------------------------------------------------------- detections from agents
def _clean_text(v: Any, limit: int) -> str | None:
    if not isinstance(v, str):
        return None
    return v[:limit]


def matched_event(machine: str, ev: dict[str, Any], created: datetime) -> Any:
    """The matched event as an Event (identity and the fields a finding names), every
    value checked by the event model; a value that fails its check is left out."""
    from kratos.detect.findings import valid_ip, valid_path, valid_user
    from kratos.events.model import Event, EventError, parse_timestamp
    from kratos.subagent import detect as D

    try:
        ts = parse_timestamp(str(ev.get("@timestamp")))
    except (ValueError, EventError):
        return None
    eid = str(ev.get("event.id") or "")
    dataset = ev.get("event.dataset")
    if not _HEX32.match(eid) or dataset not in D.DATASETS:
        return None
    values: dict[str, Any] = {}
    for name, attr, check in (("source.ip", "source_ip", valid_ip), ("user.name", "user_name", valid_user),
                              ("user.target.name", "user_target_name", valid_user),
                              ("user.effective.name", "user_effective_name", valid_user),
                              ("process.executable", "process_executable", valid_path),
                              ("file.path", "file_path", valid_path)):
        v = check(ev.get(name)) if ev.get(name) is not None else None
        if v:
            values[attr] = v
    for name, attr, limit in (("process.name", "process_name", 256), ("service.name", "service_name", 256),
                              ("network.transport", "network_transport", 32), ("event.provider", "provider", 256),
                              ("event.action", "action", 128), ("kratos.audit.session", "audit_session", 16)):
        v = _clean_text(ev.get(name), limit)
        if v:
            values[attr] = v
    try:
        return Event(timestamp=ts, created=created, event_id=eid, kind="event", dataset=dataset, host_name=machine,
                     transport="agent", read="watch", parser="watch/1", **values)
    except EventError:
        return Event(timestamp=ts, created=created, event_id=eid, kind="event", dataset=dataset, host_name=machine,
                     transport="agent", read="watch", parser="watch/1")


def summary_event(machine: str, rule: dict[str, Any], lp: Any, minute: float, suppressed: int, first_ts: float,
                  last_ts: float, created: datetime) -> Any:
    """'+N more matches of this rule this minute' as one detection event."""
    from kratos.detect.run import DATASET, PARSER, _authors
    from kratos.events.model import Event

    eid = hashlib.sha256("\x1f".join((target_key(machine), rule["id"], "suppressed", str(int(minute))))
                         .encode()).hexdigest()[:32]
    return Event(
        timestamp=datetime.fromtimestamp(float(last_ts), timezone.utc), created=created, event_id=eid, kind="alert",
        category=("intrusion_detection",), type=("info",), action="rule_matches_suppressed", dataset=DATASET,
        provider="kratos-detect",
        message=f"{suppressed} more match(es) of {rule['title']} (rule {rule['id']} by {rule['author']}) in one "
                "minute, not sent one by one"[:4096],
        host_name=target_key(machine), rule_id=rule["id"], rule_uuid=str(rule.get("sigma_id") or "")[:64] or None,
        rule_name=rule["title"][:256], rule_author=_authors(rule["author"]),
        rule_reference=str((rule.get("source") or {}).get("url") or "")[:1024] or None,
        rule_license=str(rule.get("license") or "")[:64] or None, rule_ruleset=lp.pack_id[:64],
        rule_version=str(lp.version)[:32], detect_level=rule["level"], detect_count=int(suppressed),
        read="watch", transport="agent", parser=PARSER)


@dataclass
class Batch:
    first: float
    rules: set[str] = field(default_factory=set)
    health: bool = False


class LiveDetections:
    """The listener's side of continuous detection. Thread-safe: its handlers run on the
    listener's detection worker threads, never on its event loop."""

    def __init__(self, data_dir: Path | str):
        self.data_dir = Path(data_dir)
        self._lock = threading.Lock()
        self._dirty: dict[str, Batch] = {}            # machine -> what to publish
        self._own: dict[str, tuple[float, Any]] = {}  # machine -> (when read, Kratos's own SSH sessions)
        self.stats = {"received": 0, "stored": 0, "duplicates": 0, "dropped": 0, "own": 0}

    # -- incoming ------------------------------------------------------------
    def _own_sessions(self, machine: str) -> Any:
        from kratos.detect import own as own_mod
        from kratos.storage.sqlite_files import connect_store

        hit = self._own.get(machine)
        if hit is not None and _now() - hit[0] < 60:
            return hit[1]
        intervals: Any = {}
        try:
            conn = connect_store(self.data_dir / "kratos.db")
            try:
                since = _now() - own_mod.WINDOW_DAYS * 86400
                intervals = own_mod.own_sessions(conn, machine, since=since, fp=own_mod.kratos_fingerprint())
            finally:
                conn.close()
            intervals = own_mod.merge(intervals, dstore.own_sessions_recorded(
                self.data_dir, machine, since=_now() - own_mod.WINDOW_DAYS * 86400, slack=own_mod.RECORDED_SLACK_SECONDS))
        except Exception:  # noqa: BLE001 -- without it Kratos's own reads may show up; never a failure
            logger.debug("live detect: own sessions unavailable for %s", machine, exc_info=True)
        self._own[machine] = (_now(), intervals)
        return intervals

    def handle_detection(self, target_id: str, msg: dict[str, Any]) -> bool:
        """Store one detection. True: Kratos has it (acknowledge it); False: try again
        later (the agent keeps it). A detection that can never be stored (unknown rule,
        malformed, watching off) is acknowledged and dropped, with a log line."""
        from kratos.detect import own as own_mod
        from kratos.detect.run import detection_event
        from kratos.events.store import EventStore
        from kratos.subagent import detect as D

        self.stats["received"] += 1
        state = pack_state(self.data_dir, target_id)
        if not state or not state["enabled"] or not state.get("machine"):
            self.stats["dropped"] += 1
            return True
        machine = state["machine"]
        rule_id = msg.get("rule_id")
        if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
            self.stats["dropped"] += 1
            return True
        found = loaded_packs(self.data_dir).rule(rule_id)
        if found is None:
            logger.warning("live detect: %s sent a match of %s, a rule Kratos doesn't have -- dropped", target_id, rule_id)
            self.stats["dropped"] += 1
            return True
        lp, rule = found
        created = datetime.now(timezone.utc)
        summary = msg.get("summary")
        if isinstance(summary, dict):
            n, minute = summary.get("suppressed"), summary.get("minute")
            ts, first = _num(msg.get("ts")), _num(msg.get("first_ts"))
            if type(n) is not int or n < 1 or _num(minute) is None or ts is None:
                self.stats["dropped"] += 1
                return True
            det = summary_event(machine, rule.meta, lp, float(minute), min(n, 10**9), first or ts, ts, created)
        else:
            ev = msg.get("event")
            matched = matched_event(machine, ev, created) if isinstance(ev, dict) else None
            ts = _num(msg.get("ts"))
            if matched is None or ts is None:
                self.stats["dropped"] += 1
                return True
            if matched.dataset == "kratos.auditd" and matched.audit_session:
                own = self._own_sessions(machine)
                if own and own_mod.is_own(matched.audit_session, matched.ts, own):
                    self.stats["own"] += 1
                    return True
            group = msg.get("group") if isinstance(msg.get("group"), str) else None
            count = msg.get("count") if type(msg.get("count")) is int and msg["count"] > 0 else None
            ids = [i for i in (msg.get("event_ids") or [])[:D.MAX_MATCHED_IDS]
                   if isinstance(i, str) and _HEX32.match(i)] or [matched.event_id]
            first = _num(msg.get("first_ts")) or ts
            m = D.Match(rule_id, matched.event_id, ts, group=(group or "")[:256] or None, count=count,
                        event_ids=ids, first_ts=first)
            det = detection_event(m, rule.meta, lp, matched, machine, created=created, run_id=None, read="watch")
        stored = EventStore(self.data_dir / "kratos.db").add([det])
        if stored:
            self.stats["stored"] += 1
            self._mark(machine, rule_id)
        else:
            self.stats["duplicates"] += 1
        return True

    def handle_status(self, target_id: str, msg: dict[str, Any]) -> None:
        state = pack_state(self.data_dir, target_id)
        if state is None:
            return                      # never turned on here: nothing to keep
        new_gaps = record_status(self.data_dir, target_id, msg)
        if new_gaps and state and state["enabled"] and state.get("machine"):
            self._mark(state["machine"], None, health=True)

    def _mark(self, machine: str, rule_id: str | None, health: bool = False) -> None:
        with self._lock:
            b = self._dirty.get(machine)
            if b is None:
                b = self._dirty[machine] = Batch(first=time.monotonic())
            if rule_id:
                b.rules.add(rule_id)
            b.health = b.health or health

    def mark_health(self, machine: str) -> None:
        self._mark(machine, None, health=True)

    def due(self) -> list[tuple[str, Batch]]:
        """Batches whose first detection is at least `detect.alert_batch_seconds` old."""
        wait = float(settings_store.get(S.ALERT_BATCH_SECONDS, data_dir=self.data_dir))
        out = []
        with self._lock:
            for machine in list(self._dirty):
                b = self._dirty[machine]
                if time.monotonic() - b.first >= wait or (b.health and not b.rules):
                    out.append((machine, self._dirty.pop(machine)))
        return out

    # -- outgoing: findings and alerts --------------------------------------------
    def publish(self, machine: str, batch: Batch, *, live: dict[str, tuple[bool, float | None]] | None = None,
                notifier: Any = None, investigate_fn: Any = None) -> dict[str, Any]:
        return publish(self.data_dir, machine, rules=batch.rules, health_changed=batch.health, live=live,
                       notifier=notifier, investigate_fn=investigate_fn)


def publish(data_dir: Path | str, machine: str, *, rules: set[str] = frozenset(), health_changed: bool = False,
            live: dict[str, tuple[bool, float | None]] | None = None, notifier: Any = None,
            investigate_fn: Any = None, now: float | None = None) -> dict[str, Any]:
    """The machine's stored detections -> findings (lifecycle) -> triggers -> notify:
    the same functions the scheduled pass's report uses. Returns what happened."""
    from kratos.adapters.findings_engine import _apply_lifecycle, finding_dict
    from kratos.agent.trigger_eval import evaluate_triggers
    from kratos.detect import findings as findings_mod
    from kratos.detect import run as run_mod

    from kratos.events.store import EventStore

    data_dir = Path(data_dir)
    now = _now() if now is None else now
    EventStore(data_dir / "kratos.db")._connect().close()     # a fresh data folder: the event table, empty
    with run_context.run_scope("watch", target=machine):
        loaded = packs_mod.load(data_dir)
        report = run_mod.PassReport(target=machine, target_key=target_key(machine), started=now)
        report.packs = [run_mod.PackPass(pack_id=lp.pack_id, version=lp.version, origin=lp.origin)
                        for lp in loaded.loaded]
        report.refused = [{"path": r.path, "reason": r.reason} for r in loaded.refused]
        report.disabled = sorted(dstore.disabled_rules(data_dir, machine))
        try:
            report.coverage = run_mod.coverage(data_dir, machine, loaded, now=now)
        except Exception:  # noqa: BLE001
            logger.warning("live detect: coverage for %s could not be worked out", machine, exc_info=True)
        report.finished = _now()
        path = findings_mod.write_snapshot(data_dir, machine, report, loaded, now=now, live=live, source="live")
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
        findings = [finding_dict(f) for f in findings_mod.build(doc)]
        annotated, summary = _apply_lifecycle(findings, data_dir=data_dir, target=target_key(machine),
                                              inputs={"detections": Path(path)}, auth_stats=None,
                                              patterns_stats=None, snapshots={"detections": doc})
        affected = [f for f in annotated if f.get("id") in rules
                    or (health_changed and f.get("id") == DETECTION_RULE)]
        fired: list[dict[str, Any]] = []
        if affected:
            kwargs: dict[str, Any] = {}
            if notifier is not None:
                kwargs["notifier"] = notifier
            if investigate_fn is not None:
                kwargs["investigate_fn"] = investigate_fn
            fired = evaluate_triggers(data_dir, affected, target_key(machine), **kwargs)
    return {"machine": machine, "snapshot": str(path), "findings": annotated, "affected": affected,
            "fired": fired, "lifecycle": summary}


# ---------------------------------------------------------------------------- one line for people (and the model)
def watch_line(data_dir: Path | str, machine: str, *, now: float | None = None) -> str | None:
    """'watching continuously since <when>; N detections in the last 24 h (see findings)' --
    or why not -- for a watched machine; None when no agent watches it. Kratos-written."""
    summary = watch_summary(data_dir, machine, now=now)
    if summary is None:
        return None
    now = _now() if now is None else now
    if not summary["healthy"]:
        why = "; ".join(r["text"] for r in summary["reasons"][:2])
        return f"continuous detection is turned on but NOT running ({why[:300]}) -- see DETECT-002"
    hours = int(settings_store.get(S.FINDING_WINDOW_HOURS, data_dir=data_dir))
    try:
        from kratos.events.store import EventStore

        dets = EventStore(Path(data_dir) / "kratos.db").query(machine, start=now - hours * 3600,
                                                              dataset="kratos.detect", limit=10000)
        live = sum(int(d.detect_count or 0) if d.action == "rule_matches_suppressed" else 1
                   for d in dets if d.read == "watch")
    except Exception:  # noqa: BLE001
        live = 0
    since = summary.get("since")
    when = (datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if since else "now")
    unwatched = [s["name"] for s in summary["sources"] if s.get("state") == "not_available"]
    extra = (f"; not available on this machine: {', '.join(sorted(set(unwatched)))}" if unwatched else "")
    return (f"watching continuously since {when}; {live} live detection(s) in the last {hours} h "
            f"(see findings){extra}")

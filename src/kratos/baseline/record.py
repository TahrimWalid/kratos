"""One baseline run for one machine: learn what's new since the last run, judge it against
what was learned before, and keep one snapshot per machine
(`baseline_runs/baseline_<machine-hash>.json`, replaced in place, evidence-recorded).

Reads only what Kratos already stores: sign-in and sudo events and audit program starts
(log sync), and saved running-process reads (live response). Nothing is read from the
machine, nothing calls a model. Deviations raised in the last 24 hours stay in the snapshot
(they are BASE-001..006 / BASE-008 findings until then); BASE-007 always says how much has
been learned and what couldn't be.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone, tzinfo
from pathlib import Path
from typing import Any

from kratos.baseline import dims as D
from kratos.baseline import judge as J
from kratos.baseline import learn as L
from kratos.baseline import store as S
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

FOLDER = "baseline_runs"
PATTERN = "baseline_*.json"
KEEP_RAISED_HOURS = 24
MAX_KEPT = 200
# The root reads Kratos itself runs over SSH (`sudo -n ...`), by their fixed argument shapes:
# the setup checklist's pinned sudoers lines (adapters/target_setup.py), the journal reads, and
# the privileged-accounts read's sudoers parse. A program alone isn't enough -- `sudo awk` on
# any other file, or `sudo iptables -F`, is the user's own and is learned and judged.
_OWN_SUDO = tuple(re.compile(p) for p in (
    r"^/(usr/)?s?bin/journalctl( |$)",
    r"^/(usr/)?s?bin/sshd -T$",
    r"^/(usr/)?s?bin/ufw status( verbose)?$",
    r"^/(usr/)?s?bin/nft (-j )?list ruleset$",
    r"^/(usr/)?s?bin/iptables -L -n$",
    r"^/(usr/)?s?bin/ip6?tables-save$",
    r"^/(usr/)?s?bin/fail2ban-client (status( [A-Za-z0-9_.-]+)?|get [A-Za-z0-9_.-]+ (maxretry|bantime|findtime))$",
    r"^/(usr/)?s?bin/auditctl -[sl]$",
    r"^/(usr/)?s?bin/true$",
    r"^/(usr/)?s?bin/find /etc/sudoers\.d -maxdepth 1 -type f",
    r"^/(usr/)?s?bin/(awk|grep) .*/etc/sudoers",
    r"^/(usr/)?s?bin/(lsof|ps|ss|date|stat|gzip|cat)( |$)",
))


def is_own_sudo(user: str, command: str, own_user: str | None) -> bool:
    return bool(own_user) and user == own_user and any(p.search(command or "") for p in _OWN_SUDO)


def path_for(data_dir: Path | str, target: str) -> Path:
    return Path(data_dir) / FOLDER / f"baseline_{hashlib.sha256(target_key(target).encode()).hexdigest()[:8]}.json"


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds") if ts else None


# ---------------------------------------------------------------------------
# What the machine looks like from Kratos's side
# ---------------------------------------------------------------------------
def machine_zone(data_dir: Path, target: str) -> tuple[tzinfo | None, str | None]:
    """The machine's time zone as the newest sign-in measurement saw it (timewin)."""
    from kratos.adapters.findings_engine import find_latest_inputs
    from kratos.utils.timeutil import zone_from_name

    path = find_latest_inputs(data_dir, target).get("auth_stats")
    if path is None:
        return None, None
    try:
        tz = (json.loads(Path(path).read_text(encoding="utf-8", errors="replace")) or {}).get("target_timezone")
    except (OSError, ValueError):
        return None, None
    if not isinstance(tz, dict):
        return None, None
    name = str(tz.get("name") or "").strip()
    zone = zone_from_name(name) if name else None
    if zone is not None:
        return zone, name
    off = str(tz.get("offset") or "").strip()
    m = re.fullmatch(r"([+-])(\d\d)(\d\d)", off)
    if m:
        from datetime import timedelta

        sign = -1 if m.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))), off
    return None, None


ASSUMED_UTC = "UTC (assumed)"
_UTC_NAMES = {"utc", "etc/utc", "etc/universal", "universal", "zulu", "etc/zulu", "gmt", "etc/gmt", "+0000",
              ASSUMED_UTC.lower()}


def same_zone(a: str | None, b: str | None) -> bool:
    """Two zone names that give the same hours: equal, or both UTC (the assumed UTC included)."""
    a, b = str(a or "").strip().lower(), str(b or "").strip().lower()
    return a == b or (a in _UTC_NAMES and b in _UTC_NAMES)


def zone_for_hours(data_dir: Path, target: str) -> tuple[tzinfo, str]:
    """The zone sign-in hours are learned in: the machine's own when a read recorded it, else
    UTC, labelled as assumed (most servers keep UTC; the pattern stays consistent either way, and
    a different zone recorded later starts the hours afresh)."""
    tz, name = machine_zone(data_dir, target)
    if tz is not None and name:
        return tz, name
    return timezone.utc, ASSUMED_UTC


def privileged_accounts(data_dir: Path, target: str) -> set[str]:
    from kratos.adapters.findings_engine import find_latest_inputs

    path = find_latest_inputs(data_dir, target).get("privileged_accounts")
    out = {"root"}
    if path is None:
        return out
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return out
    for a in (doc or {}).get("privileged_accounts") or []:
        if isinstance(a, dict) and a.get("user"):
            out.add(str(a["user"]))
    return out


def local_accounts(data_dir: Path, target: str) -> set[str]:
    """The machine's local accounts as its newest privileged-accounts read listed them
    (empty when unknown)."""
    from kratos.adapters.findings_engine import find_latest_inputs

    path = find_latest_inputs(data_dir, target).get("privileged_accounts")
    if path is None:
        return set()
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return set()
    names = (doc or {}).get("local_accounts") or []
    return {str(n.get("user") if isinstance(n, dict) else n) for n in names if n}


def _own_user(target: str, data_dir: Path) -> str | None:
    """The login Kratos reads this machine as: its own `sudo -n` reads are set aside."""
    try:
        from kratos import kratos_config

        return kratos_config.ssh_user_for(target, data_dir)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------
def _ensure_profiles(conn, tk: str, data_dir: Path, now: float, tz_name: str | None,
                     max_row: int) -> tuple[dict[str, Any], list[str]]:
    """Current profile per dimension, created on first sight; a time-zone change starts a new
    login_time generation (the old one kept, labelled)."""
    notes: list[str] = []
    profiles = S.current_profiles(conn, tk)
    for dim in D.DIMS:
        p = profiles.get(dim.name)
        if p is None:
            started = _first_data(conn, data_dir, tk, dim) or now
            S.new_profile(conn, tk, dim.name, generation=1, started_at=started, high_water=0,
                          snapshot_high_water=0.0, tz=tz_name if dim.name == "login_time" else None,
                          note="", now=now)
        elif dim.name == "login_time" and tz_name and p["tz"] and not same_zone(p["tz"], tz_name):
            S.end_profile(conn, tk, dim.name, p["generation"], now)
            S.new_profile(conn, tk, dim.name, generation=int(p["generation"]) + 1, started_at=now,
                          high_water=max_row, snapshot_high_water=0.0, tz=tz_name, frozen=bool(p["frozen"]),
                          note=f"the machine's time zone changed from {p['tz']} to {tz_name}: sign-in hours are "
                               "learned afresh", now=now)
            notes.append(f"sign-in hours: the machine's time zone changed from {p['tz']} to {tz_name}, so hours "
                         "are learned afresh (the old pattern is kept as history)")
        elif dim.name == "login_time" and tz_name and p["tz"] != tz_name:
            # first known, or the assumed UTC confirmed: the hours learned so far still hold
            S.update_profile(conn, tk, dim.name, p["generation"], tz=tz_name, updated_at=now)
        if p is not None and int(p["generation"]) == 1:
            # The first profile follows the earliest stored history: older events can arrive
            # after the profile was made (a sub-agent catching up, a restored store). A reset or
            # a time-zone change starts at a fixed moment instead.
            first = _first_data(conn, data_dir, tk, dim)
            if first is not None and first < float(p["started_at"]):
                S.update_profile(conn, tk, dim.name, 1, started_at=first, updated_at=now)
    return S.current_profiles(conn, tk), notes


def _first_data(conn, data_dir: Path, tk: str, dim: D.Dim) -> float | None:
    if dim.source == D.SNAPSHOT:
        times = [d.get("checked_at_epoch") for d in _snapshot_docs(data_dir, tk, 0.0, limit=1)]
        return float(times[0]) if times else None
    dataset = "kratos.auditd" if dim.name == "program" else "kratos.auth"
    try:
        row = conn.execute("SELECT MIN(ts) FROM host_events WHERE target = ? AND dataset = ?", (tk, dataset)).fetchone()
    except Exception:  # noqa: BLE001 -- no event table yet
        return None
    return float(row[0]) if row and row[0] is not None else None


def _snapshot_docs(data_dir: Path, tk: str, after: float, *, limit: int) -> list[dict[str, Any]]:
    folder = Path(data_dir) / "live"
    try:
        files = sorted(folder.glob("live_response_*.json"), key=lambda f: f.stat().st_mtime)
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for f in files:
        try:
            if f.stat().st_mtime + 5 < after:
                continue
            doc = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict) or target_key(str(doc.get("target") or "")) != tk:
            continue
        when = float(doc.get("checked_at_epoch") or 0)
        if when > after:
            out.append(doc)
    out.sort(key=lambda d: float(d.get("checked_at_epoch") or 0))
    return out[:limit]


def _models(conn, tk: str, profiles: dict[str, Any], st: L.Settings, data_dir: Path) -> dict[str, L.Model]:
    models: dict[str, L.Model] = {}
    for dim in D.DIMS:
        p = profiles[dim.name]
        ents = {(r["subject"], r["key"]): L.Entry.from_row(r) for r in S.entries(conn, tk, dim.name, p["generation"])}
        try:
            snap_days = json.loads(p["snapshot_days"] or "{}")
        except ValueError:
            snap_days = {}
        if dim.source == D.SNAPSHOT:
            covered = sorted(int(d) for d, n in snap_days.items() if int(n) >= L.SNAPSHOT_DAY_MIN)
        else:
            covered = L.covered_days_from_spans(L.coverage_spans(conn, tk, dim.sync_source or "auth"))
        models[dim.name] = L.Model(dim=dim, generation=int(p["generation"]), profile=dict(p), entries=ents,
                                   learning=L.Learning(covered, float(p["started_at"])), settings=st,
                                   frozen=bool(p["frozen"]), samples=int(p["samples"]),
                                   snapshot_days={str(k): int(v) for k, v in snap_days.items()})
    return models


def _absorb_false_positives(conn, tk: str, models: dict[str, L.Model], now: float) -> int:
    """A person marked a BASE finding a false positive in /findings: its keys are normal now
    (the decision is theirs; this only records what it means for the baseline)."""
    done = S.absorbed_exceptions(conn, tk)
    try:
        rows = conn.execute(
            "SELECT x.id, x.rule_id, x.decided_entities, x.created_by, x.created_at, x.finding_key, r.subject "
            "FROM finding_exceptions x LEFT JOIN finding_records r ON r.finding_key = x.finding_key "
            "WHERE x.kind = 'false_positive' AND x.revoked_at IS NULL AND x.rule_id LIKE 'BASE-%' AND "
            "x.scope = 'key' AND r.target = ?", (tk,)).fetchall()
    except Exception:  # noqa: BLE001 -- no lifecycle tables yet
        return 0
    n = 0
    for r in rows:
        if int(r["id"]) in done or r["rule_id"] not in D.BY_RULE:
            continue
        dim = D.BY_RULE[r["rule_id"]]
        model = models[dim.name]
        try:
            keys = [str(k) for k in json.loads(r["decided_entities"] or "[]")]
        except ValueError:
            keys = []
        for key in keys[:200]:
            e = model.entries.get((r["subject"], key))
            if e is None:
                e = L.Entry(r["subject"], key, 0.0, now, 0, now, now)
                model._put(e)
            e.accepted_at, e.accepted_by, e.dirty = float(r["created_at"]), str(r["created_by"]), True
            L.add_weight(e, now, 1.0, model.half_life_s)
            e.forgotten_at = None
            n += 1
        S.add_decision(conn, target_key=tk, dim=dim.name, kind="accept_from_finding", subject=r["subject"],
                       key=", ".join(keys)[:500], actor=str(r["created_by"]), interface="findings", user_id=None,
                       reason="marked a false positive in /findings: treated as normal", at=now,
                       finding_key=r["finding_key"], details={"exception_id": int(r["id"]), "keys": keys[:200]})
    return n


def _event_observations(conn, tk: str, after: int, cap: int, tz: tzinfo | None, ident: Any, own_user: str | None,
                        own_sessions: dict[str, list[tuple[float, float]]]) -> tuple[list[D.Obs], int, int, int]:
    """(observations, last row id read, rows read, Kratos's own set aside)."""
    from kratos.detect import own as own_mod

    try:
        rows = conn.execute(
            "SELECT id, ts, action, source_ip, user_name, doc FROM host_events WHERE target = ? AND id > ? AND "
            "action IN ('ssh_success_login', 'sudo_command', 'process_started') ORDER BY id LIMIT ?",
            (tk, after, cap)).fetchall()
    except Exception:  # noqa: BLE001 -- no event table yet
        return [], after, 0, 0
    obs: list[D.Obs] = []
    own = 0
    pid_exe: dict[int, tuple[str, float]] = {}
    last = after
    for r in sorted(rows, key=lambda r: (float(r["ts"]), int(r["id"]))):
        last = max(last, int(r["id"]))
        ts = float(r["ts"])
        try:
            doc = json.loads(r["doc"])
        except ValueError:
            continue
        action = r["action"]
        message = str(doc.get("message") or "")
        if action == "ssh_success_login":
            if own_mod.is_own_login(action, message, ident):
                own += 1
                continue
            obs.extend(D.from_login(ts=ts, user=r["user_name"] or "", source_ip=r["source_ip"] or "",
                                    message=message, tz=tz, row_id=int(r["id"])))
        elif action == "sudo_command":
            proc = doc.get("process") or {}
            command = str(proc.get("command_line") or "")
            user = r["user_name"] or ""
            if is_own_sudo(user, command, own_user):
                own += 1
                continue
            run_as = (((doc.get("user") or {}).get("effective") or {}).get("name")) or "root"
            obs.extend(D.from_sudo(ts=ts, user=user, run_as=str(run_as),
                                   program=str(proc.get("executable") or proc.get("name") or ""),
                                   command=command, row_id=int(r["id"])))
        elif action == "process_started":
            session = (((doc.get("kratos") or {}).get("audit") or {}).get("session"))
            if own_mod.is_own(str(session) if session else None, ts, own_sessions):
                own += 1
                continue
            proc = doc.get("process") or {}
            exe = str(proc.get("executable") or "")
            pid, ppid = proc.get("pid"), (proc.get("parent") or {}).get("pid")
            parent = None
            if isinstance(ppid, int) and ppid in pid_exe and ts - pid_exe[ppid][1] <= L.DAY:
                parent = pid_exe[ppid][0]
            if isinstance(pid, int) and exe:
                pid_exe[pid] = (exe, ts)
            obs.extend(D.from_program(ts=ts, exe=exe, parent=parent, row_id=int(r["id"])))
    return obs, last, len(rows), own


def _group_context(data_dir: Path, tk: str, conn, dev: L.Deviation) -> dict[str, Any] | None:
    """The same account normally signs in from this bucket on another machine of one of this
    machine's groups. Machine names are never written here (a viewer of this finding may not
    see the other machine); /baseline shows them, scoped."""
    try:
        from kratos.fleet import groups as G

        names = G.groups_of(data_dir, tk)
        if not names:
            return None
        with G.opened(data_dir) as gconn:
            members = {g: [target_key(m) for m in G._members(gconn, g)] for g in names}
    except Exception:  # noqa: BLE001 -- no groups table
        return None
    for g, ms in members.items():
        others = [m for m in ms if m != tk]
        found = S.entries_elsewhere(conn, dev.dim, dev.subject, dev.key, others)
        if found:
            return {"group": g, "machines": len(found)}
    return None


def run(data_dir: Path | str, target: str, *, now: float | None = None, fingerprint: Any = None) -> dict[str, Any]:
    from kratos.detect import own as own_mod

    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    tk = target_key(target)
    st = L.Settings.load(data_dir)
    gaps: list[str] = []
    notes: list[str] = []
    tz, tz_name = zone_for_hours(data_dir, target)
    ident = fingerprint if fingerprint is not None else own_mod.kratos_identity(data_dir)
    own_user = _own_user(target, data_dir)
    privileged = privileged_accounts(data_dir, target)
    previous = load(path_for(data_dir, target)) or {}
    with S.opened(data_dir) as conn:
        try:
            max_row = int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM host_events WHERE target = ?",
                                       (tk,)).fetchone()[0])
        except Exception:  # noqa: BLE001
            max_row = 0
        try:
            own_sessions = own_mod.own_sessions(conn, tk, since=now - 30 * L.DAY, fp=ident)
            from kratos.detect import store as dstore

            own_sessions = own_mod.merge(own_sessions, dstore.own_sessions_recorded(
                data_dir, target, since=now - 30 * L.DAY, slack=own_mod.RECORDED_SLACK_SECONDS))
        except Exception:  # noqa: BLE001 -- without it Kratos's own commands may be learned; never a failure
            own_sessions = {}
        with S.immediate(conn):
            profiles, zone_notes = _ensure_profiles(conn, tk, data_dir, now, tz_name, max_row)
        notes.extend(zone_notes)
        models = _models(conn, tk, profiles, st, data_dir)
        hold_list = L.holds(conn, tk)
        with S.immediate(conn):
            accepted_from_findings = _absorb_false_positives(conn, tk, models, now)

        # -- events ----------------------------------------------------------
        event_dims = [m for m in models.values() if m.dim.source == D.EVENT]
        after = min(int(m.profile["high_water"]) for m in event_dims)
        obs, last_row, read, own_n = _event_observations(conn, tk, after, st.max_events_per_run, tz, ident,
                                                         own_user, own_sessions)
        waiting = 0
        if read >= st.max_events_per_run:
            try:
                waiting = int(conn.execute(
                    "SELECT COUNT(*) FROM host_events WHERE target = ? AND id > ? AND action IN "
                    "('ssh_success_login', 'sudo_command', 'process_started')", (tk, last_row)).fetchone()[0])
            except Exception:  # noqa: BLE001
                waiting = 0
            if waiting:
                gaps.append(f"{waiting:,} stored events wait for the next run (at most {st.max_events_per_run:,} "
                            "are learned per run)")
        # -- snapshots ---------------------------------------------------------
        snap_dims = [m for m in models.values() if m.dim.source == D.SNAPSHOT]
        snap_after = min(float(m.profile["snapshot_high_water"]) for m in snap_dims)
        snaps = _snapshot_docs(data_dir, tk, snap_after, limit=L.MAX_SNAPSHOTS_PER_RUN)
        snap_obs: list[D.Obs] = []
        snap_notes: list[str] = []
        snap_times: list[float] = []
        for doc in snaps:
            o, n = D.from_snapshot(doc)
            snap_obs.extend(o)
            snap_notes = n or snap_notes
            snap_times.append(float(doc.get("checked_at_epoch") or 0))

        candidates: list[L.Deviation] = []
        older = 0
        raise_from = now - L.RAISE_LOOKBACK_DAYS * L.DAY
        sudo_users_before: set[str] = {s for (s, _), e in models["sudo_use"].entries.items() if e.live and e.count}
        all_obs = sorted(obs + snap_obs, key=lambda o: o.ts)
        snap_idx = 0
        # Every kind one event (or one read) feeds is judged before any of them is learned: a
        # sign-in's new source must not show up as "usual" next to its unusual hour.
        pending: list[tuple[L.Model, D.Obs, Any]] = []
        group: tuple[Any, ...] | None = None

        def flush() -> None:
            for pm, po, ph in pending:
                if not pm.frozen:
                    pm.learn(po, ph)
                if po.dim == "sudo_use" and ph is None and not pm.frozen:
                    sudo_users_before.add(po.subject)
            pending.clear()

        for o in all_obs:
            key = (o.row_id, o.ts) if o.row_id else ("snap", o.ts)
            if key != group:
                flush()
                group = key
            model = models[o.dim]
            if model.dim.source == D.EVENT and o.row_id <= int(model.profile["high_water"]):
                continue
            if model.dim.source == D.SNAPSHOT:
                while snap_idx < len(snap_times) and snap_times[snap_idx] <= o.ts:
                    _count_snapshot(models, snap_times[snap_idx], snap_dims)
                    snap_idx += 1
                if o.ts <= float(model.profile["snapshot_high_water"]):
                    continue
            hold = L.held_by(hold_list, o.ts)
            dev = model.judge(o)
            if dev is not None:
                dev.held = hold is not None
                dev.machine_sudo_users = len(sudo_users_before)
                if o.ts < raise_from:
                    older += 1
                else:
                    if o.dim == "sudo_use":
                        dev.detail["user_used_sudo_before"] = o.subject in sudo_users_before
                    # what was usual BEFORE this observation is learned
                    dev.detail["_usual"] = usual_pattern(models, dev, o.ts)
                    dev.detail["_learned"] = learned_words(model, o.ts)
                    candidates.append(dev)
            pending.append((model, o, hold))
        flush()
        while snap_idx < len(snap_times):
            _count_snapshot(models, snap_times[snap_idx], snap_dims)
            snap_idx += 1

        released_n = 0
        for m in models.values():
            keys = m.held_keys()
            if keys:
                released_n += m.release(L.released(conn, keys))

        # -- judge -------------------------------------------------------------
        prior = [d for d in previous.get("deviations") or []
                 if isinstance(d, dict) and float(d.get("raised_at") or 0) >= now - KEEP_RAISED_HOURS * 3600]
        cooldown_s = st.cooldown_hours * 3600
        forgot = _forget_times(conn, tk)
        fresh: list[dict[str, Any]] = []
        cooled = 0
        for dev in candidates:
            model = models[dev.dim]
            e = model.entries.get((dev.subject, dev.key))
            if e is not None and e.last_raised and now - float(e.last_raised) < cooldown_s:
                cooled += 1
                continue
            since = forgot.get((dev.dim, dev.subject, dev.key), 0.0)    # a person forgot it: raise it again
            same = [p for p in prior + fresh if p.get("rule") == dev.rule and p.get("subject") == dev.subject
                    and p.get("key") == dev.key]
            if any("raised_at" not in p or float(p["raised_at"]) >= since for p in same):
                cooled += 1
                continue
            if dev.rule == "BASE-001":
                ctx = _group_context(data_dir, tk, conn, dev)
                if ctx:
                    dev.detail["usual_elsewhere"] = ctx
            sev = J.severity(dev, privileged=privileged,
                             sudo_users=set() if not dev.detail.get("user_used_sudo_before") else {dev.subject})
            usual, learned = dev.detail.pop("_usual", []), dev.detail.pop("_learned", "")
            fresh.append({**dev.as_dict(), "severity": sev, "usual": usual, "learned": learned,
                          "machine_time": machine_time(dev.ts, tz, tz_name == ASSUMED_UTC)})
        # The budget is per machine per day (the day the deviation happened, machine time): a
        # run that catches up on several days doesn't let one day crowd out another.
        raised, over = [], []
        by_day: dict[str, list[dict[str, Any]]] = {}
        for d in fresh:
            by_day.setdefault(_day(float(d["ts"]), tz), []).append(d)
        for day, devs in sorted(by_day.items()):
            used = sum(1 for p in prior if _day(float(p.get("ts") or 0), tz) == day)
            r, o = J.select(devs, room=st.max_per_day - used)
            raised.extend(r)
            over.extend(o)
        for d in raised:
            d["raised_at"] = now
            e = models[d["dim"]].entries.get((d["subject"], d["key"]))
            if e is not None:
                e.last_raised, e.dirty = now, True

        # -- save ----------------------------------------------------------------
        statuses: dict[str, dict[str, Any]] = {}
        with S.immediate(conn):
            for name, m in models.items():
                evicted = m.evict(now)
                m.profile["evicted"] = int(m.profile["evicted"]) + evicted
                for e in m.entries.values():
                    if e.dirty:
                        S.upsert_entry(conn, tk, name, m.generation, e.as_row())
                status = dim_status(m, data_dir, conn, tk, now, tz_name, snap_notes)
                statuses[name] = status
                hw = max(int(m.profile["high_water"]), last_row) if m.dim.source == D.EVENT else int(m.profile["high_water"])
                shw = max([float(m.profile["snapshot_high_water"])] + snap_times) if m.dim.source == D.SNAPSHOT \
                    else float(m.profile["snapshot_high_water"])
                S.update_profile(conn, tk, name, m.generation, status=status["status"], high_water=hw,
                                 snapshot_high_water=shw, snapshot_days=m.snapshot_days, samples=m.samples,
                                 evicted=int(m.profile["evicted"]), held_back=m.held_now(),
                                 note=status.get("reason") or "", updated_at=now)
    kept = (prior + raised)[-MAX_KEPT:]
    doc = {
        "target": tk, "checked_at": _iso(now), "checked_at_epoch": now,
        "complete": not gaps, "coverage_gaps": gaps, "notes": notes, "zone": tz_name,
        "learn_days": st.learn_days, "max_per_day": st.max_per_day,
        "dims": statuses,
        "deviations": kept,
        "today": {"raised": len(kept), "over_budget": len(over) + int((previous.get("today") or {}).get(
            "over_budget", 0) if prior else 0), "cooled": cooled},
        "older_not_raised": older, "own_set_aside": own_n, "held_back": sum(m.held_now() for m in models.values()),
        "released": released_n, "accepted_from_findings": accepted_from_findings,
        "read": {"events": read, "snapshots": len(snaps), "waiting_events": waiting},
    }
    path = path_for(data_dir, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)
    from kratos import evidence as _evidence

    _evidence.record(path, data_dir=data_dir, category="baseline", machine=target, read="baseline",
                     transport="local")
    return {**doc, "file": str(path)}


def _forget_times(conn, tk: str) -> dict[tuple[str, str, str], float]:
    out: dict[tuple[str, str, str], float] = {}
    for r in conn.execute("SELECT dim, subject, key, MAX(at) FROM baseline_decisions WHERE target_key = ? AND "
                          "kind = 'forget' GROUP BY dim, subject, key", (tk,)):
        out[(r[0], r[1], r[2])] = float(r[3])
    return out


def _count_snapshot(models: dict[str, L.Model], ts: float, snap_dims: list[L.Model]) -> None:
    day = str(L.day_of(ts))
    for m in snap_dims:
        if ts <= float(m.profile["snapshot_high_water"]):
            continue
        m.snapshot_days[day] = m.snapshot_days.get(day, 0) + 1
        if len(m.snapshot_days) > 400:
            for k in sorted(m.snapshot_days, key=int)[:-400]:
                m.snapshot_days.pop(k, None)
        m.samples += 1
        if m.snapshot_days[day] == L.SNAPSHOT_DAY_MIN:
            bisect_insert(m.learning.covered, int(day))


def bisect_insert(lst: list[int], v: int) -> None:
    import bisect

    i = bisect.bisect_left(lst, v)
    if i == len(lst) or lst[i] != v:
        lst.insert(i, v)


def _day(ts: float, tz: tzinfo | None) -> str:
    return datetime.fromtimestamp(ts, tz or timezone.utc).strftime("%Y-%m-%d")


def machine_time(ts: float, tz: tzinfo | None, assumed: bool = False) -> str:
    if tz is None or assumed:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d %H:%M (machine time)")


def learned_words(m: L.Model, now: float) -> str:
    days = m.learning.days_since_start(now)
    covered = m.learning.covered_before(now + L.DAY)
    return f"learned over {days} days ({covered} covered)"


def usual_pattern(models: dict[str, L.Model], dev: L.Deviation, now: float) -> list[str]:
    """Kratos-written lines describing what was usual for this subject before the deviation
    (its own key left out); for a subject never seen, what is usual on the machine."""
    m = models[dev.dim]
    out: list[str] = []
    if dev.dim in D.LOGIN_DIMS:
        own = {"login_source": dev.key if dev.dim == "login_source" else None,
               "login_method": dev.key if dev.dim == "login_method" else None}
        src = [k for k, _, _ in L.top(models["login_source"], dev.subject, now, n=4) if k != own["login_source"]][:3]
        if src:
            out.append("from " + ", ".join(src))
        hours = L.usual_hours(models["login_time"], dev.subject, now)
        if hours:
            zone = "UTC" if models["login_time"].profile.get("tz") == ASSUMED_UTC else "machine time"
            out.append(f"{hours} ({zone})")
        meth = [k for k, _, _ in L.top(models["login_method"], dev.subject, now, n=3) if k != own["login_method"]][:2]
        if meth:
            out.append("by " + " or ".join(meth))
        if not out:
            out.append(f"this account had not signed in here before ({m.subject_count(dev.subject)} earlier sign-ins)")
        return out
    tops = [t for t in L.top(m, dev.subject, now, n=4) if t[0] != dev.key][:3]
    if tops:
        out.append(", ".join(f"{k} (x{c})" for k, _, c in tops))
    else:
        machine = L.top_all(m, now, n=4)
        word = {"listener": "listening on this machine", "outbound": "talking out from this machine",
                "sudo_use": "sudo use on this machine", "program": "program starts on this machine"}.get(dev.dim, "")
        if machine:
            out.append(f"nothing recorded for {dev.subject} before; usual {word}: " +
                       ", ".join(f"{s} {k}" for s, k, _ in machine))
    return out


def dim_status(m: L.Model, data_dir: Path, conn, tk: str, now: float, tz_name: str | None,
               snap_notes: list[str]) -> dict[str, Any]:
    dim = m.dim
    covered = m.learning.covered_before(now + L.DAY)
    days = m.learning.days_since_start(now)
    live = [e for e in m.entries.values() if e.live and e.evicted_at is None]
    base = {"label": dim.label, "rule": dim.rule, "generation": m.generation, "learned_days": days,
            "covered_days": covered, "learn_days": m.settings.learn_days, "samples": m.samples,
            "entries": len(live), "evicted": int(m.profile["evicted"]), "held_back": m.held_now(),
            "subjects": len({e.subject for e in live})}
    reason = ""
    if dim.source == D.EVENT and m.samples == 0 and not live:
        source = dim.sync_source or "auth"
        has_events = _has_events(conn, tk, "kratos.auditd" if dim.name == "program" else "kratos.auth")
        if dim.name == "program" and not has_events:
            reason = "no auditd: program starts aren't recorded on this machine (install auditd with exec rules)"
        elif not has_events:
            spans = L.coverage_spans(conn, tk, source)
            gap = L.gap_notes(conn, tk, source, 1)
            reason = ("log sync has not stored any sign-in or sudo history for this machine yet"
                      + (f" ({gap[0]})" if gap else "") if not spans else
                      "no sign-ins or sudo use recorded in the synced history yet")
    if dim.name == "login_time" and tz_name == ASSUMED_UTC:
        base["zone_note"] = "hours in UTC: the machine's own time zone isn't known"
    if dim.source == D.SNAPSHOT and m.samples == 0:
        reason = "no running-process reads saved for this machine yet"
    if dim.name == "outbound" and m.samples and not live and snap_notes:
        reason = ""
    ready_subjects = any(m.subject_count(e.subject) >= dim.min_samples for e in live) if dim.per_subject else \
        m.samples >= dim.min_samples
    status = "not_learnable" if reason else ("frozen" if m.frozen else
                                             "active" if covered >= m.settings.learn_days and ready_subjects
                                             else "learning")
    if status == "learning":
        need = []
        if covered < m.settings.learn_days:
            need.append(f"{covered} of {m.settings.learn_days} covered days")
            if dim.source == D.EVENT:
                gaps = L.gap_notes(conn, tk, dim.sync_source or "auth", 2)
                if gaps:
                    need.append("not covered: " + "; ".join(gaps))
        if m.samples < dim.min_samples and not dim.per_subject:
            need.append(f"{m.samples} of {dim.min_samples} {'reads' if dim.source == D.SNAPSHOT else 'events'}")
        if dim.per_subject and covered >= m.settings.learn_days:
            need.append(f"no {dim.subject_word} has {dim.min_samples} sign-ins yet ({m.samples} seen besides "
                        "Kratos's own)")
        base["learning"] = ", ".join(need) or "learning"
    if dim.per_subject and status == "active":
        waiting = sorted(s for s in {e.subject for e in live} if m.subject_count(s) < dim.min_samples)
        if waiting:
            base["subjects_learning"] = len(waiting)
    if snap_notes and dim.source == D.SNAPSHOT:
        base["read_notes"] = snap_notes[:3]
    return {**base, "status": status, "reason": reason}


def _has_events(conn, tk: str, dataset: str) -> bool:
    try:
        return conn.execute("SELECT 1 FROM host_events WHERE target = ? AND dataset = ? LIMIT 1",
                            (tk, dataset)).fetchone() is not None
    except Exception:  # noqa: BLE001
        return False


def load(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def summary_line(doc: dict[str, Any]) -> str:
    """One short Kratos-written line for the digest, conclusion first: counts and status words,
    never names. "No deviation" is only said for kinds that are learned."""
    dims = doc.get("dims") or {}
    active = sum(1 for s in dims.values() if s.get("status") == "active")
    learning = [s for s in dims.values() if s.get("status") == "learning"]
    unlearnable = sum(1 for s in dims.values() if s.get("status") == "not_learnable")
    devs = len(doc.get("deviations") or [])
    if not active and learning:
        days = max(int(s.get("covered_days") or 0) for s in learning)
        return f"still learning ({days} of {doc.get('learn_days')} days); no deviation can be reported yet"
    if not active:
        return "can't learn what's normal here yet (see BASE-007)"
    head = f"{devs} deviation(s) from normal" if devs else f"no deviation in {active} learned kind(s)"
    rest = [f"{len(learning)} still learning" if learning else "", f"{unlearnable} not learnable" if unlearnable
            else ""]
    rest = [r for r in rest if r]
    return head + ("; " + ", ".join(rest) if rest else "")

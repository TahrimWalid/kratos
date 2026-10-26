"""The detection pass: evaluate the stored events of one machine against the rule packs.

For each pack, the pass reads the events stored for the machine since that pack's
last pass (by row id -- log sync may store old lines late, so time is not a
position), in chunks, each evaluated in time order. A counting rule also sees the
stored events of its window from before this pass (re-fed as history: they count
but raise nothing), so a burst that straddles two passes is counted -- and
reported -- once. A pack that is new or has changed first looks back over the
last `detect.lookback_hours` once.

Every match becomes a detection event (dataset kratos.detect, event.kind alert)
in the event store; its id is derived from the rule, the machine and the matched
event, so evaluating the same events again stores nothing new. The pass stops
starting new work at its time and event budget; what is left is said ("behind")
and picked up next time. No model is called, nothing is sent to the machine.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos import run_context, settings_store
from kratos.detect import own as own_mod
from kratos.detect import pack as packs_mod
from kratos.detect import settings as S
from kratos.detect import store
from kratos.detect.flat import flat
from kratos.events import sigma_fields as SF
from kratos.events.model import Event
from kratos.events.store import EventStore
from kratos.storage.sqlite_files import connect_store
from kratos.subagent import detect as D
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

DATASET = "kratos.detect"
PARSER = "detect/1"
CHUNK = 2000
HISTORY_MAX = 20000
COVERAGE_SAMPLE = 500
# Identity fields a detection event copies from the event it matched, for hunting and
# for the finding's subject and entities.
_COPY = ("source_ip", "user_name", "user_target_name", "user_effective_name", "process_executable",
         "process_name", "service_name", "file_path", "group_name", "transport")


@dataclass
class SourceCoverage:
    key: str                  # "linux/auditd", "linux/process_creation", ...
    label: str
    state: str                # checked | partial | not_checked
    rules: int                # rules in the packs that read it
    note: str = ""            # plain words, for anything but "checked"
    datasets: tuple[str, ...] = ()   # the datasets that feed it (C.2: is it watched live?)


@dataclass
class PackPass:
    pack_id: str
    version: int
    origin: str
    events: int = 0
    detections: int = 0       # matches raised in this pass
    stored: int = 0           # of which new in the store
    status: str = "ok"        # ok | partial | failed
    reason: str = ""
    lookback: bool = False
    behind: bool = False


@dataclass
class PassReport:
    target: str
    target_key: str
    started: float = 0.0
    finished: float = 0.0
    packs: list[PackPass] = field(default_factory=list)
    refused: list[dict[str, str]] = field(default_factory=list)
    coverage: list[SourceCoverage] = field(default_factory=list)
    matches: list[dict[str, Any]] = field(default_factory=list)   # this pass's matches: rule, event id, group
    disabled: list[str] = field(default_factory=list)
    snapshot: str | None = None
    own_rows: set[int] = field(default_factory=set, repr=False)   # Kratos's own SSH logins' events, set aside

    @property
    def own_events(self) -> int:
        """Events from Kratos's own SSH logins set aside (detect/own.py): each event once,
        however many packs read it (a per-pack sum counted it once per pack)."""
        return len(self.own_rows)

    @property
    def status(self) -> str:
        if any(p.status == "failed" for p in self.packs):
            return "failed" if all(p.status == "failed" for p in self.packs) else "partial"
        return "partial" if any(p.status == "partial" for p in self.packs) else "ok"

    @property
    def behind(self) -> bool:
        return any(p.behind for p in self.packs)

    @property
    def events(self) -> int:
        return max((p.events for p in self.packs), default=0)

    @property
    def new_detections(self) -> int:
        return sum(p.stored for p in self.packs)


# ---------------------------------------------------------------------------- reading the store
def _rows(conn: Any, key: str, after: int, *, since: float | None, limit: int) -> list[tuple[int, float, str]]:
    sql = "SELECT id, ts, doc FROM host_events WHERE target = ? AND id > ? AND dataset != ?"
    params: list[Any] = [key, after, DATASET]
    if since is not None:
        sql += " AND ts >= ?"
        params.append(since)
    sql += " ORDER BY id LIMIT ?"
    params.append(limit)
    return conn.execute(sql, params).fetchall()


def _history(conn: Any, key: str, through: int, since: float, datasets: set[str]) -> list[tuple[int, float, str]]:
    if not datasets:
        return []
    marks = ",".join("?" for _ in datasets)
    return conn.execute(f"SELECT id, ts, doc FROM host_events WHERE target = ? AND id <= ? AND ts >= ? "
                        f"AND dataset IN ({marks}) ORDER BY ts DESC LIMIT ?",
                        (key, through, since, *sorted(datasets), HISTORY_MAX)).fetchall()[::-1]


def _max_row(conn: Any, key: str) -> int:
    r = conn.execute("SELECT MAX(id) FROM host_events WHERE target = ?", (key,)).fetchone()
    return int(r[0] or 0)


def _event(doc: str) -> Event | None:
    try:
        return Event.from_ecs(json.loads(doc))
    except Exception:  # noqa: BLE001 -- one unreadable row must not stop the pass
        logger.debug("detect: skipped an unreadable stored event", exc_info=True)
        return None


# ---------------------------------------------------------------------------- detection events
def detection_id(target: str, rule_id: str, event_id: str, group: str | None) -> str:
    raw = "\x1f".join((target_key(target), rule_id, event_id, group or ""))
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def _authors(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for part in str(text or "").replace(" and ", ",").split(","):
        name = part.strip()[:256]
        if name and name not in out:
            out.append(name)
    return tuple(out[:16])


def detection_event(m: D.Match, rule: dict[str, Any], lp: packs_mod.LoadedPack, matched: Event,
                    target: str, *, created: datetime, run_id: str | None, read: str = "detect_pass") -> Event:
    """One detection as an event. Its message is Kratos-shipped text only (the rule's
    title and author); what the machine logged stays in the matched event."""
    values = {a: getattr(matched, a) for a in _COPY if getattr(matched, a) is not None}
    group = (m.group or "")[:256] or None
    return Event(
        timestamp=datetime.fromtimestamp(float(m.ts), timezone.utc),
        created=created,
        event_id=detection_id(target, rule["id"], m.event_id, group),
        kind="alert",
        category=("intrusion_detection",),
        type=("info",),
        action="rule_match",
        dataset=DATASET,
        provider="kratos-detect",
        message=f"{rule['title']} (rule {rule['id']} by {rule['author']})"[:4096],
        host_name=target_key(target),
        related_ip=tuple(v for v in (values.get("source_ip"),) if v),
        related_user=tuple(dict.fromkeys(v for v in (values.get("user_name"), values.get("user_target_name"),
                                                         values.get("user_effective_name")) if v)),
        rule_id=rule["id"],
        rule_uuid=str(rule.get("sigma_id") or "")[:64] or None,
        rule_name=rule["title"][:256],
        rule_author=_authors(rule["author"]),
        rule_reference=str((rule.get("source") or {}).get("url") or "")[:1024] or None,
        rule_license=str(rule.get("license") or "")[:64] or None,
        rule_ruleset=lp.pack_id[:64],
        rule_version=str(lp.version)[:32],
        detect_matched=tuple(dict.fromkeys(m.event_ids))[:D.MAX_MATCHED_IDS],
        detect_level=rule["level"],
        detect_group=group,
        detect_count=m.count,
        read=read,
        run_id=run_id,
        parser=PARSER,
        **values,
    )


# ---------------------------------------------------------------------------- coverage
def _ls_key(rule: dict[str, Any]) -> tuple[str, str | None, str | None]:
    ls = rule.get("logsource") or {}
    return (ls.get("product") or "", ls.get("service"), ls.get("category"))


def coverage(data_dir: Path | str, target: str, loaded: packs_mod.Packs, *, now: float) -> list[SourceCoverage]:
    """For every log source the rules read: does Kratos hold recent events from it for
    this machine? A rule whose log source isn't there can't see anything -- said, never
    treated as "nothing found"."""
    days = int(settings_store.get(S.COVERAGE_DAYS, data_dir=data_dir))
    since = now - days * 86400
    by_ls: dict[tuple, list[dict[str, Any]]] = {}
    for _lp, r in loaded.rules():
        by_ls.setdefault(_ls_key(r.meta), []).append(r.meta)
    conn = connect_store(Path(data_dir) / "kratos.db")
    out: list[SourceCoverage] = []
    try:
        key = target_key(target)
        for ls_key, rules in sorted(by_ls.items(), key=lambda kv: "/".join(p or "" for p in kv[0])):
            ls = SF.LOGSOURCES.get(ls_key)
            name = "/".join(p for p in ls_key if p)
            if ls is None:
                out.append(SourceCoverage(name, name, "not_checked", len(rules),
                                          "Kratos doesn't read this log source"))
                continue
            seen = _source_seen(conn, key, since, ls)
            held_note = _held_note(data_dir, key, ls_key, now) if seen else None
            if held_note:
                out.append(SourceCoverage(name, ls.label, "partial", len(rules), held_note, tuple(ls.datasets)))
                continue
            if seen and ls.partial:
                full = _full_source_seen(conn, key, since, ls_key)
                state = "checked" if full else "partial"
                note = "" if full else f"{ls.partial} -- {ls.needs} isn't there on this machine"
            elif seen:
                state, note = "checked", ""
            elif ls.partial and _partial_source_seen(conn, key, since, ls_key):
                state, note = "partial", f"{ls.partial} -- {ls.needs} isn't there on this machine"
            else:
                state = "not_checked"
                note = f"not checked -- no events in the last {days} days; needs {ls.needs}"
            out.append(SourceCoverage(name, ls.label, state, len(rules), note, tuple(ls.datasets)))
    finally:
        conn.close()
    return out


# The log a log source's rules mostly read, as log sync names it (collect/sync). Sources
# mixing several logs (Linux logs, system log) are not judged by one of them.
_PRIMARY_SYNC = {
    ("linux", "auditd", None): "auditd", ("linux", None, "process_creation"): "auditd",
    ("linux", None, "file_event"): "auditd", ("linux", "sshd", None): "auth", ("linux", "sudo", None): "auth",
    ("linux", "auth", None): "auth", ("linux", "cron", None): "cron",
}
HELD_ENOUGH = 0.95


def _held_note(data_dir: Path | str, key: str, ls_key: tuple, now: float) -> str | None:
    """Why the rules of this log source could only look at part of the finding window, or None.
    From log sync's own record of what it holds completely (sync_coverage) -- never inferred from
    the store being quiet (a first sync of a busy audit log can hold only seconds of the day)."""
    source = _PRIMARY_SYNC.get(ls_key)
    if source is None:
        return None
    from kratos.collect.sync import cursors

    if not cursors.spans(data_dir, key, source):
        return None                       # not kept by log sync here (read another way): nothing to judge
    hours = int(settings_store.get(S.FINDING_WINDOW_HOURS, data_dir=data_dir))
    held_s, first = cursors.held(data_dir, key, source, now - hours * 3600, now)
    if held_s >= HELD_ENOUGH * hours * 3600:
        return None
    if held_s < 120:
        amount = f"{held_s:.0f} s"
    elif held_s < 7200:
        amount = f"{held_s / 60:.0f} min"
    else:
        amount = f"{held_s / 3600:.1f} h"
    since = (f" (from {datetime.fromtimestamp(first, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"
             if first is not None else "")
    return (f"only {amount} of the last {hours} h of the {source} log could be read{since}; "
            "the rest was not checked")


def _where_sql(node: dict[str, Any] | None) -> tuple[str, list[Any]] | None:
    """A log source's condition (closed operators) as SQL over the stored documents, for the
    shapes log sources use: eq / in (case-sensitive), exists, all_of / any_of. None if it
    can't be said exactly in SQL."""
    if node is None:
        return "1", []
    op = node["op"]
    if op in ("all_of", "any_of"):
        parts = [_where_sql(c) for c in node["args"]]
        if any(p is None for p in parts):
            return None
        joiner = " AND " if op == "all_of" else " OR "
        return "(" + joiner.join(p[0] for p in parts) + ")", [x for p in parts for x in p[1]]   # type: ignore[index]
    path = "$." + node.get("field", "")
    if op == "eq" and node.get("cased"):
        return "json_extract(doc, ?) = ?", [path, node["value"]]
    if op == "in" and node.get("cased"):
        return (f"json_extract(doc, ?) IN ({', '.join('?' for _ in node['values'])})",
                [path, *node["values"]])
    if op == "exists":
        return ("json_extract(doc, ?) IS NOT NULL" if node["value"] else "json_extract(doc, ?) IS NULL"), [path]
    return None


def _source_seen(conn: Any, key: str, since: float, ls: Any) -> bool:
    """Does the store hold an event of log source `ls` for this machine since `since`?"""
    marks = ",".join("?" for _ in ls.datasets)
    sql = _where_sql(ls.where)
    if sql is not None:
        r = conn.execute(f"SELECT 1 FROM host_events WHERE target = ? AND dataset IN ({marks}) AND ts >= ? "
                         f"AND {sql[0]} LIMIT 1", (key, *ls.datasets, since, *sql[1])).fetchone()
        return r is not None
    where = D._Node(ls.where)
    for (doc,) in conn.execute(f"SELECT doc FROM host_events WHERE target = ? AND dataset IN ({marks}) AND ts >= ? "
                               "ORDER BY ts DESC LIMIT ?", (key, *ls.datasets, since, COVERAGE_SAMPLE)):
        ev = _event(doc)
        if ev is not None and where.test(flat(ev)):
            return True
    return False


def _full_source_seen(conn: Any, key: str, since: float, ls_key: tuple) -> bool:
    """Program starts: auditd recording every exec (not only sudo's own log)."""
    if ls_key != ("linux", None, "process_creation"):
        return True
    r = conn.execute("SELECT 1 FROM host_events WHERE target = ? AND dataset = 'kratos.auditd' "
                     "AND action = 'process_started' AND ts >= ? LIMIT 1", (key, since)).fetchone()
    return r is not None


def _partial_source_seen(conn: Any, key: str, since: float, ls_key: tuple) -> bool:
    if ls_key != ("linux", None, "process_creation"):
        return False
    r = conn.execute("SELECT 1 FROM host_events WHERE target = ? AND dataset = 'kratos.auth' "
                     "AND action = 'sudo_command' AND ts >= ? LIMIT 1", (key, since)).fetchone()
    return r is not None


# ---------------------------------------------------------------------------- the pass
def _pass_one(lp: packs_mod.LoadedPack, target: str, data_dir: Path, *, now: float, deadline: float,
              max_events: int, disabled: set[str], created: datetime, run_id: str | None,
              report: PassReport, own: own_mod.Intervals | None = None, own_fp: str | None = None) -> PackPass:
    pp = PackPass(pack_id=lp.pack_id, version=lp.version, origin=lp.origin)
    key = target_key(target)
    last = store.last_run(data_dir, target, lp.pack_id)
    lookback_hours = int(settings_store.get(S.LOOKBACK_HOURS, data_dir=data_dir))
    state: dict[str, Any] = {}
    if last is None or last.pack_sha256 != lp.pack.sha256:
        after, since, pp.lookback = 0, now - lookback_hours * 3600, True
        fired: dict[str, dict[str, float]] = {}
    else:
        after = last.through_row
        fired = {k: v for k, v in (last.state or {}).items() if not k.startswith("_")}
        cutoff = (last.state or {}).get("_lookback_cutoff")
        since = None
        if last.lookback and last.status == "partial" and isinstance(cutoff, (int, float)):
            since, pp.lookback = float(cutoff), True
    if pp.lookback and since is not None:
        state["_lookback_cutoff"] = since
    evaluator = D.Evaluator(lp.pack, disabled=disabled, fired=fired)
    started = time.time()
    first_ts = last_ts = None
    through = after
    store_events = EventStore(Path(data_dir) / "kratos.db")
    conn = connect_store(Path(data_dir) / "kratos.db")
    try:
        end_row = _max_row(conn, key)
        history_done = not evaluator.has_counting_rules or after == 0
        while True:
            out_of_time = time.monotonic() >= deadline
            if out_of_time or pp.events >= max_events:
                if _rows(conn, key, through, since=since, limit=1) and through < end_row:
                    pp.status, pp.behind = "partial", True
                    pp.reason = ("the pass ran out of time" if out_of_time
                                 else f"the pass read its limit of {max_events:,} events") + \
                        "; the rest is checked next time"
                break
            rows = _rows(conn, key, through, since=since, limit=min(CHUNK, max_events - pp.events))
            rows = [r for r in rows if r[0] <= end_row]
            if not rows:
                break
            batch: list[tuple[float, int, Event, bool]] = []
            if not history_done:
                window_start = min(r[1] for r in rows) - evaluator.longest_window
                datasets = {d for r in evaluator.active if r.count for d in r.datasets}
                for _id, ts, doc in _history(conn, key, after, window_start, datasets):
                    ev = _event(doc)
                    if ev is not None:
                        batch.append((ts, _id, ev, True))
                history_done = True
            for _id, ts, doc in rows:
                ev = _event(doc)
                if ev is not None:
                    batch.append((ts, _id, ev, False))
            batch.sort(key=lambda b: (b[0], b[1]))
            detections: list[Event] = []
            for ts, _id, ev, is_history in batch:
                if (own and ev.dataset == "kratos.auditd" and own_mod.is_own(ev.audit_session, ts, own)) or (
                        own_fp and ev.dataset == "kratos.auth" and own_mod.is_own_login(ev.action, ev.message, own_fp)):
                    if not is_history:          # Kratos's own read, not something that happened on the machine
                        pp.events += 1
                        report.own_rows.add(_id)
                    continue
                if not is_history:
                    pp.events += 1
                    first_ts = ts if first_ts is None else min(first_ts, ts)
                    last_ts = ts if last_ts is None else max(last_ts, ts)
                for m in evaluator.evaluate(flat(ev), ts, history=is_history):
                    rule = lp.pack.by_id[m.rule_id].meta
                    detections.append(detection_event(m, rule, lp, ev, target, created=created, run_id=run_id))
                    report.matches.append({"rule_id": m.rule_id, "event_id": m.event_id, "group": m.group,
                                           "pack": lp.pack_id})
            if detections:
                pp.detections += len(detections)
                pp.stored += store_events.add(detections)
            through = rows[-1][0]
    except Exception as e:  # noqa: BLE001 -- reported as a failed pass, never as "nothing found"
        logger.warning("detect: pass of %s over %s failed", lp.pack_id, key, exc_info=True)
        pp.status, pp.reason = "failed", f"{type(e).__name__}: {str(e)[:200]}"
    finally:
        conn.close()
    if pp.status != "failed":
        state.update(evaluator.fired_state(now))
        if not pp.lookback or pp.status == "ok":
            state.pop("_lookback_cutoff", None)
        store.record_run(data_dir, target=target, pack_id=lp.pack_id, pack_version=lp.version,
                         pack_sha256=lp.pack.sha256, started_at=started, finished_at=time.time(), after_row=after,
                         through_row=through, first_ts=first_ts, last_ts=last_ts, events=pp.events,
                         detections=pp.detections, status=pp.status, reason=pp.reason or None,
                         lookback=pp.lookback, run_id=run_id, state=state)
    return pp


def run_pass(target: str, data_dir: Path | str, *, now: float | None = None, deadline: float | None = None,
             write_snapshot: bool = True) -> PassReport:
    """One detection pass over `target`'s stored events, every pack. Never raises for a
    problem with the data: a failed pack is reported as failed."""
    from kratos.detect import findings as findings_mod

    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    report = PassReport(target=target, target_key=target_key(target), started=time.time())
    budget = float(settings_store.get(S.PASS_BUDGET, data_dir=data_dir))
    deadline = min(deadline, time.monotonic() + budget) if deadline is not None else time.monotonic() + budget
    max_events = int(settings_store.get(S.MAX_EVENTS, data_dir=data_dir))
    EventStore(data_dir / "kratos.db")._connect().close()     # a fresh data folder: the event table, empty
    loaded = packs_mod.load(data_dir)
    report.refused = [{"path": r.path, "reason": r.reason} for r in loaded.refused]
    disabled = store.disabled_rules(data_dir, target)
    report.disabled = sorted(disabled)
    ctx = run_context.current()
    created = datetime.now(timezone.utc)
    own: own_mod.Intervals = {}
    own_fp = own_mod.kratos_fingerprint()
    try:
        conn = connect_store(data_dir / "kratos.db")
        try:
            since = now - own_mod.WINDOW_DAYS * 86400
            own = own_mod.own_sessions(conn, target_key(target), since=since, fp=own_fp)
            own = own_mod.merge(own, store.own_sessions_recorded(data_dir, target, since=since,
                                                                 slack=own_mod.RECORDED_SLACK_SECONDS))
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 -- without it Kratos's own reads may show up as matches; never a failure
        logger.warning("detect: could not tell Kratos's own logins on %s apart", target, exc_info=True)
    for lp in loaded.loaded:
        report.packs.append(_pass_one(lp, target, data_dir, now=now, deadline=deadline, max_events=max_events,
                                      disabled=disabled, created=created, run_id=ctx.run_id if ctx else None,
                                      report=report, own=own, own_fp=own_fp))
    try:
        report.coverage = coverage(data_dir, target, loaded, now=now)
    except Exception:  # noqa: BLE001
        logger.warning("detect: coverage for %s could not be worked out", target, exc_info=True)
    report.finished = time.time()
    if write_snapshot:
        report.snapshot = str(findings_mod.write_snapshot(data_dir, target, report, loaded, now=now))
    return report

"""Detection events -> findings: the one path (docs/phaseC/README.md §4.2).

After a pass (kratos.detect.run), `write_snapshot` summarises the machine's stored
detection events of the last `detect.finding_window_hours` into a snapshot file
(<data folder>/detect/results/detections_<time>.json); the findings engine turns
the newest one into findings through `build` (registered as a snapshot source, like
the persistence and package checks). C.2's continuous detections land in the same
store and come out through the same `summarize` and `build`.

- `SIGMA-<id>` -- one finding per rule and subject: the counting rule's group value,
  else the matched event's validated identity (source address, user, program, in
  that order). Title, severity, ATT&CK labels and author come from the rule (Kratos-
  shipped text); what the machine logged is never in a title.
- `DETECT-001` -- a run note: log sources the rules need that this machine doesn't
  provide, a pass that fell behind or failed, an imported pack that was refused.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.detect import settings as S
from kratos.events.model import Event
from kratos.target_key import target_key

RESULTS_DIR = Path("detect") / "results"
PATTERN = "detections_*.json"
CATEGORY = "detections"
RULE_PREFIX = "SIGMA-"
MAX_AGE_HOURS = 24          # a snapshot older than this is not a current reading
MAX_DETECTIONS_READ = 10000
MAX_EVENT_IDS = 20
_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}\$?$")
_PATH = re.compile(r"^/[^\x00-\x1f\x7f]{0,1023}$")
_LEVEL_SEVERITY = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


# ---------------------------------------------------------------------------- validated identities (A.4)
def valid_ip(value: Any) -> str | None:
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        return None


def valid_user(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if _USER.match(text) else None


def valid_path(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if _PATH.match(text) else None


def _valid_group(value: Any) -> str | None:
    return valid_ip(value) or valid_user(value) or valid_path(value)


def _identity(ev: Event) -> tuple[str, str] | None:
    """(kind, value) of the first validated identity: source address, user, program."""
    for kind, value in (("ip", valid_ip(ev.source_ip) if ev.source_ip else None),
                        ("user", valid_user(ev.user_name) if ev.user_name else None),
                        ("program", valid_path(ev.process_executable) if ev.process_executable else None)):
        if value:
            return kind, value
    return None


def _entities(ev: Event) -> set[str]:
    out = set()
    for value in (valid_ip(ev.source_ip) if ev.source_ip else None,
                  valid_user(ev.user_name) if ev.user_name else None,
                  valid_user(ev.user_target_name) if ev.user_target_name else None,
                  valid_path(ev.process_executable) if ev.process_executable else None):
        if value:
            out.add(value)
    return out


# ---------------------------------------------------------------------------- summary of stored detections
def _read_detections(data_dir: Path, target: str, since: float) -> list[Event]:
    from kratos.events.store import EventStore

    return EventStore(data_dir / "kratos.db").query(target, start=since, dataset="kratos.detect",
                                                    limit=MAX_DETECTIONS_READ, newest_first=False)


def _rule_meta(rule_id: str, loaded: Any) -> dict[str, Any] | None:
    found = loaded.rule(rule_id) if loaded is not None else None
    return dict(found[1].meta, _pack=found[0].pack_id, _pack_version=found[0].version) if found else None


def summarize(data_dir: Path | str, target: str, *, now: float, loaded: Any = None) -> list[dict[str, Any]]:
    """The machine's detections of the finding window, one entry per rule and subject."""
    data_dir = Path(data_dir)
    hours = int(settings_store.get(S.FINDING_WINDOW_HOURS, data_dir=data_dir))
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in _read_detections(data_dir, target, now - hours * 3600):
        rule_id = str(ev.rule_id or "")
        if not rule_id.startswith(RULE_PREFIX):
            continue
        meta = _rule_meta(rule_id, loaded)
        if ev.detect_group:
            subject = _valid_group(ev.detect_group) or ""
        else:
            ident = _identity(ev)
            subject = ident[1] if ident else ""
        g = groups.get((rule_id, subject))
        if g is None:
            src = (meta or {}).get("source") or {}
            g = groups[(rule_id, subject)] = {
                "rule_id": rule_id,
                "title": (meta or {}).get("title") or ev.rule_name or rule_id,
                "level": (meta or {}).get("level") or ev.detect_level or "info",
                "author": (meta or {}).get("author") or ", ".join(ev.rule_author),
                "sigma_id": (meta or {}).get("sigma_id") or ev.rule_uuid,
                "source_url": src.get("url") or ev.rule_reference,
                "license": (meta or {}).get("license") or ev.rule_license,
                "pack": (meta or {}).get("_pack") or ev.rule_ruleset,
                "pack_version": (meta or {}).get("_pack_version") or ev.rule_version,
                "attack": list((meta or {}).get("attack") or []),
                "tags": list((meta or {}).get("tags") or []),
                "falsepositives": list((meta or {}).get("falsepositives") or []),
                "logsource": (meta or {}).get("logsource") or {},
                "count_rule": (meta or {}).get("count"),
                "subject": subject, "entities": set(), "detections": 0, "events": [],
                "first_ts": ev.ts, "last_ts": ev.ts, "max_count": None, "transports": set(),
                "live": 0, "scheduled": 0,
            }
        if ev.action == "rule_matches_suppressed":     # C.2: "+N more this minute" from a watching agent
            g["detections"] += int(ev.detect_count or 0)
            g["live"] += int(ev.detect_count or 0)
            g["first_ts"] = min(g["first_ts"], ev.ts)
            g["last_ts"] = max(g["last_ts"], ev.ts)
            continue
        g["detections"] += 1
        g["live" if ev.read == "watch" else "scheduled"] += 1
        g["entities"] |= _entities(ev)
        if ev.detect_group and _valid_group(ev.detect_group):
            g["entities"].add(_valid_group(ev.detect_group))
        for eid in ev.detect_matched:
            if eid not in g["events"] and len(g["events"]) < MAX_EVENT_IDS:
                g["events"].append(eid)
        g["first_ts"] = min(g["first_ts"], ev.ts)
        g["last_ts"] = max(g["last_ts"], ev.ts)
        if ev.detect_count:
            g["max_count"] = max(g["max_count"] or 0, ev.detect_count)
        if ev.transport:
            g["transports"].add(ev.transport)
    out = []
    for g in groups.values():
        g["entities"] = sorted(g["entities"])
        g["transports"] = sorted(g["transports"])
        out.append(g)
    return sorted(out, key=lambda g: (g["rule_id"], g["subject"]))


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def write_snapshot(data_dir: Path | str, target: str, report: Any, loaded: Any, *, now: float,
                   live: Any = None, source: str = "schedule") -> Path:
    """`source`: "schedule" (a pass over the stored logs) or "live" (an agent's detections
    arrived). `live`: per agent, (connected, down since) as the listener knows it first-hand."""
    from kratos import paths

    data_dir = Path(data_dir)
    hours = int(settings_store.get(S.FINDING_WINDOW_HOURS, data_dir=data_dir))
    doc = {
        "target": target_key(target),
        "checked_at": _iso(now),
        "window_hours": hours,
        "complete": report.status == "ok" and not report.behind,
        "status": report.status,
        "packs": [{"pack_id": p.pack_id, "version": p.version, "origin": p.origin, "status": p.status,
                   "events": p.events, "detections": p.detections, "behind": p.behind, "reason": p.reason,
                   "lookback": p.lookback} for p in report.packs],
        "refused_packs": list(report.refused),
        "coverage": [{"key": c.key, "label": c.label, "state": c.state, "rules": c.rules, "note": c.note,
                      "datasets": list(getattr(c, "datasets", ()) or ())} for c in report.coverage],
        "source": source,
        "watch": _watch_summary(data_dir, target, now=now, live=live),
        "disabled": list(report.disabled),
        "kratos_own_events": int(getattr(report, "own_events", 0)),
        "detections": summarize(data_dir, target, now=now, loaded=loaded),
    }
    folder = data_dir / RESULTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    # the written time plus the machine: two machines' passes in the same instant never share a file
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    machine = hashlib.sha256(doc["target"].encode("utf-8")).hexdigest()[:8]
    path = folder / f"detections_{stamp}_{machine}.json"
    paths.write_private_text(path, json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return path


def _watch_summary(data_dir: Path, target: str, *, now: float, live: Any) -> dict[str, Any] | None:
    """C.2: whether an agent watches this machine continuously, and how that is going."""
    try:
        from kratos.detect import live as live_mod

        return live_mod.watch_summary(data_dir, target, now=now, live=live)
    except Exception:  # noqa: BLE001 -- the scheduled pass must not fail on it
        import logging

        logging.getLogger(__name__).warning("watch status for %s could not be read", target, exc_info=True)
        return None


# ---------------------------------------------------------------------------- the findings engine's side
def load_recent(path: Path | None) -> dict[str, Any] | None:
    """The newest detection snapshot of the machine, if it is recent enough to be
    a current reading (find_latest_inputs already picked one about this machine)."""
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("detections"), list):
        return None
    try:
        captured = datetime.fromisoformat(str(data.get("checked_at"))).timestamp()
    except (TypeError, ValueError):
        captured = Path(path).stat().st_mtime
    if time.time() - captured > MAX_AGE_HOURS * 3600:
        return None
    return data


def _when(ts: float) -> str:
    """'2026-10-21 09:14:02 UTC' -- evidence wording, as the findings engine writes it."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def labels(d: dict[str, Any]) -> list[dict[str, Any]]:
    """ATT&CK labels of a detection: its rule's techniques through the pinned v19 table,
    under the tactics the rule's tags name when the technique is listed there."""
    from kratos.attack.table import LabelError, label, technique

    tag_tactics = {str(t)[7:].replace("_", "-") for t in d.get("tags") or [] if str(t).startswith("attack.")}
    out = []
    for tid in d.get("attack") or []:
        t = technique(tid)
        if t is None:
            continue
        chosen = [s for s in t["tactics"] if s in tag_tactics]
        try:
            out.append(label(tid, *chosen))
        except LabelError:
            continue
    return out


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding, normalise_entities

    out: list[Any] = []
    target = doc.get("target") or "the machine"
    hours = doc.get("window_hours") or 24
    for d in doc.get("detections") or []:
        rule_id = str(d.get("rule_id") or "")
        if not rule_id.startswith(RULE_PREFIX):
            continue
        n = int(d.get("detections") or 0)
        span = (f"at {_when(d['first_ts'])}" if d["first_ts"] == d["last_ts"]
                else f"between {_when(d['first_ts'])} and {_when(d['last_ts'])}")
        evidence = [
            f"Detection rule {rule_id}: \"{d.get('title')}\" by {d.get('author')} "
            f"(SigmaHQ rule {d.get('sigma_id')}, {d.get('license') or 'DRL-1.1'})",
            f"{n} match(es) on {target} {span}, in the last {hours} h of stored logs"
            + (f" -- up to {d['max_count']} events in one counting window" if d.get("max_count") else ""),
            _how_seen(d),
        ]
        if d.get("subject"):
            evidence.append(f"About: {d['subject']}")
        if d.get("events"):
            evidence.append("Matched stored events: " + ", ".join(d["events"][:MAX_EVENT_IDS]))
            evidence.append(f"Show them: kratos events --target {target} --rule {rule_id}")
        if d.get("source_url"):
            evidence.append(f"Rule source: {d['source_url']}")
        recommendation = [
            "Look at the matched log lines (kratos events, or /findings in the TUI) and decide whether this "
            "was expected on this machine.",
        ]
        if d.get("falsepositives"):
            recommendation.append("The rule's authors list these possible false positives: "
                                  + "; ".join(d["falsepositives"][:5]))
        recommendation.append(f"If it is expected here, turn the rule off for this machine: kratos detect rules "
                              f"disable {rule_id} --target {target} --reason \"...\"")
        f = Finding(
            id=rule_id,
            title=str(d.get("title") or rule_id)[:256],
            severity=_LEVEL_SEVERITY.get(str(d.get("level")), "info"),
            evidence=evidence,
            recommendation=recommendation,
            subject=str(d.get("subject") or ""),
            entities=normalise_entities("text", d.get("entities") or []),
            attack=labels(d),
            detection_rule={"id": rule_id, "title": d.get("title"), "author": d.get("author"),
                            "sigma_id": d.get("sigma_id"), "source_url": d.get("source_url"),
                            "license": d.get("license") or "DRL-1.1", "pack": d.get("pack"),
                            "pack_version": d.get("pack_version"), "matches": n, "live": int(d.get("live") or 0)},
        )
        out.append(f)
    note = run_note(doc)
    if note is not None:
        out.append(Finding(id="DETECT-001", **note))
    health = watch_finding(doc)
    if health is not None:
        out.append(Finding(id="DETECT-002", **health))
    return out


def _how_seen(d: dict[str, Any]) -> str:
    live, scheduled = int(d.get("live") or 0), int(d.get("scheduled") or 0)
    if live and not scheduled:
        return "Seen live: the machine's agent matched it as the log was written (continuous detection)"
    if live:
        return (f"Seen live by the machine's agent ({live}) and on schedule over the logs Kratos collected "
                f"({scheduled})")
    return "Checked on schedule over the logs Kratos collected, not continuously"


def watch_finding(doc: dict[str, Any]) -> dict[str, Any] | None:
    """DETECT-002: continuous detection is turned on for this machine but isn't running
    (or a stretch of its log went unwatched in the last hour). None when it is running,
    or nobody turned it on."""
    w = doc.get("watch")
    if not isinstance(w, dict) or not w.get("enabled") or w.get("healthy"):
        return None
    from kratos.adapters.findings_engine import normalise_entities

    reasons = [r for r in w.get("reasons") or [] if isinstance(r, dict)]
    evidence = [str(r.get("text") or r.get("code"))[:400] for r in reasons][:12]
    evidence.append("While continuous detection isn't running, detections on this machine come only from the "
                    "scheduled pass over the logs Kratos collects -- an attack is seen later, not as it happens.")
    return {"title": "Continuous detection isn't running on this machine", "severity": "medium",
            "evidence": evidence,
            "recommendation": [
                "Open /subagent and select the machine: it shows the watcher's state and why it stopped.",
                "If the link is down, check the machine and the network; the agent sends what it saw once it is back.",
                "If the rules were refused or the agent is too old, update it (press g in /subagent).",
                "Alerts while Kratos is closed need the always-on listener (press L in /subagent)."],
            "subject": "",
            "entities": normalise_entities("text", sorted({str(r.get("code")) for r in reasons if r.get("code")}))}


def run_note(doc: dict[str, Any]) -> dict[str, Any] | None:
    """What the detection rules could not check on this machine (DETECT-001), or None."""
    lines: list[str] = []
    watched = _watched_now(doc)
    for c in doc.get("coverage") or []:
        if c.get("state") in ("not_checked", "partial"):
            feeds = [d for d in c.get("datasets") or [] if d in _WATCH_FEEDS]
            if feeds and all(_WATCH_FEEDS[d] in watched for d in feeds):
                continue          # the agent reads this log as it is written (C.2)
            lines.append(f"{c.get('label')} rules ({c.get('rules')}): {c.get('note')}")
    for p in doc.get("packs") or []:
        if p.get("status") == "failed":
            lines.append(f"rule pack {p.get('pack_id')} could not be evaluated: {p.get('reason')}")
        elif p.get("behind"):
            lines.append(f"rule pack {p.get('pack_id')} is behind: {p.get('reason')}")
    for r in doc.get("refused_packs") or []:
        lines.append(f"an imported rule pack was refused ({Path(str(r.get('path'))).name}): {r.get('reason')}")
    if not lines:
        return None
    return {"title": "Detection rules: what could not be checked on this machine", "severity": "info",
            "evidence": lines,
            "recommendation": ["A rule that could not look found nothing -- it does not mean the machine is clean.",
                               "To check program starts and file changes, install auditd on the machine with rules "
                               "that record them (GUIDE: Detection rules)."]}


# The datasets an agent's watcher reads, and from which log (kratos.detect.live).
_WATCH_FEEDS = {"kratos.auth": "journal", "kratos.cron": "journal", "kratos.systemd": "journal",
                "kratos.firewall": "journal", "kratos.auditd": "auditd"}


def _watched_now(doc: dict[str, Any]) -> set[str]:
    w = doc.get("watch")
    if not isinstance(w, dict) or not w.get("enabled"):
        return set()
    return {str(s.get("name")) for s in w.get("sources") or [] if isinstance(s, dict) and s.get("state") == "watching"}


def closes_findings(doc: dict[str, Any]) -> bool:
    return bool(doc.get("complete"))


def credit_line(finding: dict[str, Any]) -> str | None:
    """'rule by <author> (Sigma, DRL 1.1)' for a finding raised by a detection rule, else
    None -- shown with every SIGMA finding, alert and report entry (the licence asks it)."""
    rule = finding.get("detection_rule") if isinstance(finding, dict) else None
    if not isinstance(rule, dict) or not rule.get("author"):
        return None
    n = rule.get("matches")
    count = f"{n} match{'es' if n != 1 else ''}; " if isinstance(n, int) and n > 0 else ""
    return f"{count}rule by {rule['author']} (Sigma, {rule.get('license') or 'DRL-1.1'})"

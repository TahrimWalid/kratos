"""BASE-* findings from the machine's baseline snapshot (kratos.baseline.record), as a
snapshot source. One finding per (rule, subject): its entities are the new keys, so a
person's "this is normal" covers exactly what they saw. Titles are Kratos's own words and
never carry a name from the machine (they reach the model's digest as they are)."""
from __future__ import annotations

from typing import Any

from kratos.baseline import buckets as B
from kratos.baseline import dims as D
from kratos.baseline import record

CATEGORY = "baseline"
MAX_AGE_HOURS = 24
TITLES = {
    "BASE-001": "An account signed in from a place it never signed in from before",
    "BASE-002": "An account signed in at an hour it doesn't usually sign in",
    "BASE-003": "An account signed in in a way it never used before",
    "BASE-004": "Someone used sudo in a way never seen on this machine before",
    "BASE-005": "A program listens on a port it never listened on before",
    "BASE-006": "A program talked to an outside address it never talked to before",
    "BASE-007": "What Kratos has learned about what's normal on this machine",
    "BASE-008": "A program was started by a parent program it never ran under before",
}
_KIND_WORDS = {"new": "for the first time", "rare": "rarely seen before", "unusual_time": "at an unusual hour"}
_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_recent(path: Any) -> dict[str, Any] | None:
    import time

    doc = record.load(path)
    if doc is None or not isinstance(doc.get("dims"), dict):
        return None
    if time.time() - float(doc.get("checked_at_epoch") or 0) > MAX_AGE_HOURS * 3600:
        return None
    return doc


def _seen(d: dict[str, Any]) -> str:
    if d.get("kind") == "rare":
        return f"seen only {d.get('seen_before')} time(s) before" + (
            f", last on {record._iso(d.get('last_seen_before'))[:10]}" if d.get("last_seen_before") else "")
    if d.get("kind") == "new" and d.get("seen_before"):
        return f"last seen more than {d.get('forget_days', 90)} days ago"
    return _KIND_WORDS.get(str(d.get("kind")), "")


def _line(d: dict[str, Any]) -> str:
    det = d.get("detail") or {}
    who, key, when = d.get("subject"), d.get("key"), d.get("machine_time")
    rule = d.get("rule")
    if rule == "BASE-001":
        cls = B.CLASS_WORDS.get(str(det.get("class")), "")
        text = f"'{who}' signed in from {key} ({cls}) {_seen(d)} -- address {det.get('address')}, {when}"
        ctx = det.get("usual_elsewhere")
        if ctx:
            text += (f"; first time HERE, but usual for this account on {ctx.get('machines')} other machine(s) "
                     f"in group '{ctx.get('group')}' (/baseline shows which)")
        return text
    if rule == "BASE-002":
        zone = "UTC" if str(when or "").endswith("UTC") else "machine time"
        return f"'{who}' signed in at {D.hour_words(str(key))} ({zone}), {when} -- from {det.get('address')}"
    if rule == "BASE-003":
        return f"'{who}' signed in by {key} {_seen(d)} -- from {det.get('address')}, {when}"
    if rule == "BASE-004":
        cmd = det.get("command") or "?"
        first = "" if det.get("user_used_sudo_before") else " (this user had never used sudo here)"
        return f"'{who}' ran sudo {key} {_seen(d)}{first} -- command '{cmd}', {when}"
    if rule == "BASE-005":
        return f"{who} listens on {key} {_seen(d)} (address {det.get('address') or '?'}), read {when}"
    if rule == "BASE-006":
        cls = B.CLASS_WORDS.get(str(det.get("class")), "")
        return f"{who} connected to {key} ({cls}) {_seen(d)} -- address {det.get('address')}, read {when}"
    if rule == "BASE-008":
        return f"{who} started {key} {_seen(d)}, {when}"
    return f"{who}: {key}"


_RECOMMEND = {
    "BASE-001": ["If you know this sign-in (a new office, a VPN, travel), accept it as normal in /baseline -- it "
                 "won't be raised again.", "If you don't: treat the account as possibly in someone else's hands -- "
                 "check what the session did (kratos hunt <address>), its keys and its sudo use."],
    "BASE-002": ["If the hour is expected (on call, a new job), accept it as normal in /baseline.",
                 "If not: check what the session did and whether the account's key or password was shared."],
    "BASE-003": ["A password sign-in to an account that always used a key often means the key isn't the only way "
                 "in: check sshd's PasswordAuthentication and whether the password is known to others.",
                 "If expected, accept it as normal in /baseline."],
    "BASE-004": ["Check the command was meant to be run (who, why); accept it as normal in /baseline if so.",
                 "A user running something as root they never ran before is how a stolen sudo account looks."],
    "BASE-005": ["Check the program and port are meant to be open (ss -ltnp on the machine); close or firewall "
                 "them if not.", "Accept it as normal in /baseline if it is a service you installed."],
    "BASE-006": ["Check why this program talks to that address (a new update mirror is normal; a shell or "
                 "web server talking out is not).", "Accept it as normal in /baseline if expected."],
    "BASE-008": ["Check what the program did (kratos hunt <program>); a web server or database starting a shell "
                 "or downloader is how an exploited service looks.", "Accept it as normal in /baseline if expected."],
}


def _make(rule: str, **kw: Any) -> Any:
    """Each rule's Finding with a literal id (the lifecycle completeness test scans for them)."""
    from kratos.adapters.findings_engine import Finding

    if rule == "BASE-001":
        return Finding(id="BASE-001", **kw)
    if rule == "BASE-002":
        return Finding(id="BASE-002", **kw)
    if rule == "BASE-003":
        return Finding(id="BASE-003", **kw)
    if rule == "BASE-004":
        return Finding(id="BASE-004", **kw)
    if rule == "BASE-005":
        return Finding(id="BASE-005", **kw)
    if rule == "BASE-006":
        return Finding(id="BASE-006", **kw)
    if rule == "BASE-008":
        return Finding(id="BASE-008", **kw)
    if rule == "BASE-007":
        return Finding(id="BASE-007", **kw)
    raise KeyError(rule)


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import normalise_entities

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for d in doc.get("deviations") or []:
        if isinstance(d, dict) and d.get("rule") in D.BY_RULE and d.get("subject"):
            groups.setdefault((str(d["rule"]), str(d["subject"])), []).append(d)
    out: list[Any] = []
    for (rule, subject), devs in sorted(groups.items()):
        devs.sort(key=lambda d: float(d.get("ts") or 0), reverse=True)
        sev = max((str(d.get("severity") or "low") for d in devs), key=lambda s: _SEV.get(s, 0))
        evidence = [_line(d) for d in devs[:5]]
        if len(devs) > 5:
            evidence.append(f"... and {len(devs) - 5} more today")
        usual = devs[0].get("usual") or []
        evidence.append("Usual: " + ("; ".join(usual) if usual else "nothing else recorded for it yet") + ".")
        evidence.append(f"{str(devs[0].get('learned') or '').capitalize()}. A deviation from what's normal is never "
                        "above medium on its own; other rules carry their own verdicts.")
        if any(d.get("held") for d in devs):
            evidence.append("Happened near an open serious finding: not learned as normal until that finding is "
                            "closed as a false positive or mitigated.")
        ips = [str((d.get("detail") or {}).get("address")) for d in devs
               if rule in ("BASE-001", "BASE-002", "BASE-003") and (d.get("detail") or {}).get("address")]
        out.append(_make(rule, title=TITLES[rule], severity=sev, evidence=evidence,
                         recommendation=list(_RECOMMEND[rule]), subject=subject,
                         entities=normalise_entities("text", [d.get("key") for d in devs]),
                         source_ips=normalise_entities("ip", ips)))
    out.append(_make("BASE-007", title=TITLES["BASE-007"], severity="info", evidence=run_note(doc),
                     recommendation=["See every kind of normal and its learning status: /baseline (or kratos "
                                     "baseline show).", "'Still learning' means no deviation can be reported yet "
                                     "-- not that nothing unusual happened."], subject=""))
    return out


def run_note(doc: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for name, s in (doc.get("dims") or {}).items():
        label = s.get("label") or name
        st = s.get("status")
        if st == "active":
            text = f"{label}: learned ({s.get('learned_days')} days, {s.get('covered_days')} covered; " \
                   f"{s.get('entries')} usual things)"
            if s.get("subjects_learning"):
                text += f"; {s['subjects_learning']} {D.BY_NAME[name].subject_word}(s) still learning"
        elif st == "learning":
            text = f"{label}: still learning ({s.get('learning')}) -- no deviation reported yet"
        elif st == "frozen":
            text = f"{label}: frozen by a person -- deviations are raised, nothing is learned"
        else:
            text = f"{label}: not learnable here: {s.get('reason')}"
        if s.get("evicted"):
            text += f"; {s['evicted']} rarely used thing(s) set aside to stay within the limit"
        if s.get("zone_note"):
            text += f"; {s['zone_note']}"
        lines.append(text)
    today = doc.get("today") or {}
    if today.get("over_budget"):
        lines.append(f"{today['over_budget']} more deviation(s) today beyond the daily limit of "
                     f"{doc.get('max_per_day')} -- see /baseline {doc.get('target')}")
    if doc.get("held_back"):
        lines.append(f"{doc['held_back']} observation(s) held back (near an open serious finding, or one a person "
                     "confirmed real): not learned as normal until it is closed as a false positive or mitigated")
    if doc.get("older_not_raised"):
        lines.append(f"{doc['older_not_raised']} deviation(s) found in history older than a week: learned, not "
                     "raised")
    if doc.get("own_set_aside"):
        lines.append(f"{doc['own_set_aside']} of Kratos's own logins and reads set aside (never learned)")
    for name in ("listener", "outbound"):
        for n in (doc.get("dims") or {}).get(name, {}).get("read_notes") or []:
            if n not in lines:
                lines.append(n)
    for g in doc.get("coverage_gaps") or []:
        lines.append(g)
    for n in doc.get("notes") or []:
        lines.append(n)
    lines.append("Deviations are raised on the next collection after they happen (minutes), not live.")
    return lines


def closes_findings(doc: dict[str, Any]) -> bool:
    # A run that learned everything waiting is complete enough to say yesterday's deviation
    # did not happen again (occurrence -> inactive). It never touches another rule's finding.
    return bool(doc.get("complete"))


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=record.FOLDER, pattern=record.PATTERN,
                                            rule_prefix="BASE-", load=load_recent, build=build,
                                            closes_findings=closes_findings))

"""OCSF output, pinned to one schema version (``VERSION``) with the ``host`` profile.

Findings changes become one of three Findings classes, chosen by the rule (``CLASS_OF``,
completeness-tested against every rule id Kratos has):

* **Vulnerability Finding** (2002) -- package and service vulnerabilities (PKG-*, VULN-*)
* **Detection Finding** (2004) -- behaviour: something happened (the ATT&CK mapping says
  so), and every detection rule (SIGMA-*, KRATOS-*)
* **Compliance Finding** (2003) -- posture: how a machine is set up (the ATT&CK mapping's
  Posture rules: exposure, configuration, logging, sealing, container settings)

The lifecycle change sets ``activity_id`` (new -> Create, mitigated / gone / decided ->
Close, everything else -> Update) and ``status_id`` (open -> New / In Progress, decided ->
Suppressed, mitigated / gone -> Resolved). Kratos's own fields (``finding_key``, the
change, entities, SSVC decision) go in ``unmapped.kratos``.

Host events map to Authentication (3002), Process Activity (1007), Network Activity
(4001) and File System Activity (1001) by their ECS ``event.category``; others have no
OCSF event class here and are skipped (and counted).

Every object this module produces is validated in the tests against the JSON Schema the
OCSF server publishes for ``VERSION`` (vendored under tests/fixtures/ocsf, Apache-2.0).
"""
from __future__ import annotations

from typing import Any

from kratos.outbox.formats import FindingChange

VERSION = "1.9.0"
PROFILES = ("host",)
VULNERABILITY_FINDING, COMPLIANCE_FINDING, DETECTION_FINDING = 2002, 2003, 2004
AUTHENTICATION, PROCESS_ACTIVITY, NETWORK_ACTIVITY, FILE_ACTIVITY = 3002, 1007, 4001, 1001
CLASS_NAMES = {VULNERABILITY_FINDING: "Vulnerability Finding", COMPLIANCE_FINDING: "Compliance Finding",
               DETECTION_FINDING: "Detection Finding", AUTHENTICATION: "Authentication",
               PROCESS_ACTIVITY: "Process Activity", NETWORK_ACTIVITY: "Network Activity",
               FILE_ACTIVITY: "File System Activity"}
CATEGORY = {2002: (2, "Findings"), 2003: (2, "Findings"), 2004: (2, "Findings"), 3002: (3, "Identity & Access Management"),
            1007: (1, "System Activity"), 1001: (1, "System Activity"), 4001: (4, "Network Activity")}
SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_NAME = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 0: "Unknown"}
FINDING_ACTIVITY = {1: "Create", 2: "Update", 3: "Close"}
FINDING_STATUS = {1: "New", 2: "In Progress", 3: "Suppressed", 4: "Resolved"}
_VULN_PREFIXES = ("PKG-", "VULN-")
DEVICE_SERVER = 1


def _product() -> dict[str, Any]:
    try:
        from importlib.metadata import version

        v = version("kratos-security-assistant")
    except Exception:  # noqa: BLE001 -- running from a checkout without metadata
        v = "0"
    return {"name": "Kratos", "vendor_name": "Kratos", "version": v}


def _ms(epoch: float | None) -> int | None:
    return int(round(float(epoch) * 1000)) if epoch is not None else None


def _iso_ms(text: Any) -> int | None:
    from kratos.utils.timeutil import parse_stored_instant

    when = parse_stored_instant(text) if text else None
    return int(when.timestamp() * 1000) if when is not None else None


def class_of(rule_id: str) -> int:
    """The OCSF Findings class for a rule (see the module doc)."""
    rid = str(rule_id or "").upper()
    if rid.startswith(_VULN_PREFIXES):
        return VULNERABILITY_FINDING
    from kratos.attack.mapping import Behaviour, Posture, entry
    from kratos.detect.ids import is_detection_rule

    if is_detection_rule(rid):
        return DETECTION_FINDING
    e = entry(rid)
    if isinstance(e, Behaviour):
        return DETECTION_FINDING
    if isinstance(e, Posture):
        return COMPLIANCE_FINDING
    raise KeyError(f"rule {rule_id!r} has no OCSF class (it needs an ATT&CK mapping entry)")


def _device(machine: str, label: str) -> dict[str, Any]:
    import ipaddress

    d: dict[str, Any] = {"type_id": DEVICE_SERVER, "type": "Server"}
    try:
        ipaddress.ip_address(machine)
        d["ip"] = machine
    except ValueError:
        d["hostname"] = machine
    if label and label != machine:
        d["name"] = label
    return d


def _metadata(uid: str, *, logged_ms: int | None = None) -> dict[str, Any]:
    m: dict[str, Any] = {"product": _product(), "version": VERSION, "profiles": list(PROFILES), "uid": uid}
    if logged_ms is not None:
        m["logged_time"] = logged_ms
    return m


def _attacks(finding: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for lab in finding.get("attack") or []:
        if not isinstance(lab, dict) or not lab.get("technique_id"):
            continue
        a: dict[str, Any] = {"technique": {"uid": str(lab["technique_id"]), "name": str(lab.get("technique") or "")}}
        if lab.get("tactic_id"):
            a["tactic"] = {"uid": str(lab["tactic_id"]), "name": str(lab.get("tactic") or "")}
        if lab.get("version"):
            a["version"] = str(lab["version"])
        out.append(a)
    return out


def _activity_and_status(c: FindingChange) -> tuple[int, int]:
    if c.change == "new":
        return 1, 1
    if c.change in ("mitigated", "inactive"):
        return 3, 4
    if c.change == "decided":
        return 3, 3
    return 2, 2


def finding(c: FindingChange) -> dict[str, Any]:
    cls = class_of(c.rule_id)
    activity, status = _activity_and_status(c)
    sev = SEVERITY_ID.get(c.severity, 0)
    f = c.finding
    info: dict[str, Any] = {"uid": c.finding_key, "title": c.title[:500], "types": [c.rule_id],
                            "product": _product()}
    for key, field in (("first_seen", "first_seen_time"), ("last_seen", "last_seen_time")):
        ms = _iso_ms(f.get(key))
        if ms is not None:
            info[field] = ms
    attacks = _attacks(f)
    if attacks:
        info["attacks"] = attacks
    rule = f.get("detection_rule") if isinstance(f.get("detection_rule"), dict) else None
    if rule and rule.get("id"):
        info["analytic"] = {"uid": str(rule.get("sigma_id") or rule["id"]), "name": str(rule.get("title") or rule["id"]),
                            "type_id": 1, "type": "Rule"}
    out: dict[str, Any] = {
        "class_uid": cls, "class_name": CLASS_NAMES[cls], "category_uid": CATEGORY[cls][0],
        "category_name": CATEGORY[cls][1], "activity_id": activity, "activity_name": FINDING_ACTIVITY[activity],
        "type_uid": cls * 100 + activity, "severity_id": sev, "severity": SEVERITY_NAME[sev],
        "status_id": status, "status": FINDING_STATUS[status], "time": _ms(c.at), "message": c.title[:500],
        "finding_info": info, "metadata": _metadata(c.message_id),
        "device": _device(c.machine, c.machine_label),
    }
    recs = [str(r) for r in f.get("recommendation") or [] if str(r).strip()]
    remediation = {"desc": " ".join(recs)[:4000]} if recs else None
    if cls == VULNERABILITY_FINDING:            # a Vulnerability Finding carries remediation per vulnerability
        out["vulnerabilities"] = _vulnerabilities(c)
        if remediation:
            for v in out["vulnerabilities"]:
                v["remediation"] = remediation
    elif remediation:
        out["remediation"] = remediation
    if cls == COMPLIANCE_FINDING:
        out["compliance"] = {"control": c.rule_id, "status_id": 3 if c.state in ("open", "verified") else 1,
                             "status": "Fail" if c.state in ("open", "verified") else "Pass"}
    out["unmapped"] = {"kratos": {k: v for k, v in {
        "change": c.change, "state": c.state, "from_state": c.from_state, "to_state": c.to_state,
        "reason": c.reason, "decided_by": c.actor if c.change == "decided" else None,
        "subject": f.get("subject") or None, "entities": f.get("entities") or None,
        "evidence": [str(e) for e in (f.get("evidence") or [])][:20] or None,
        "ssvc": _ssvc(f), "lifecycle_event": c.event_id}.items() if v not in (None, "", [])}}
    return out


def _ssvc(f: dict[str, Any]) -> dict[str, Any] | None:
    s = f.get("ssvc")
    if not isinstance(s, dict) or not s.get("outcome"):
        return None
    return {"outcome": s.get("outcome"), "label": s.get("label"), "tree": s.get("tree"), "cve": s.get("cve")}


def _vulnerabilities(c: FindingChange) -> list[dict[str, Any]]:
    f = c.finding
    ents = [str(e) for e in f.get("entities") or []]
    cves: list[tuple[str, str | None]] = []
    for e in ents:
        pkg, _, cve = e.rpartition(":") if ":" in e else ("", "", e)
        if cve.upper().startswith("CVE-"):
            cves.append((cve.upper(), pkg or None))
    package = f.get("subject") if str(c.rule_id).upper() == "PKG-001" else None
    fixed = str(c.rule_id).upper() == "PKG-001"
    out = []
    for cve, pkg in cves[:100]:
        v: dict[str, Any] = {"cve": {"uid": cve}, "title": c.title[:500], "severity": c.severity.capitalize(),
                             "is_fix_available": fixed}
        if pkg or package:
            v["desc"] = f"package {pkg or package}"
        out.append(v)
    if not out:            # a service finding with no CVE named (e.g. VULN-002): Kratos's rule as the advisory
        out.append({"advisory": {"uid": c.rule_id, "title": c.title[:500]}, "title": c.title[:500],
                    "severity": c.severity.capitalize()})
    return out


# --- host events -------------------------------------------------------------------------
def _get(doc: dict[str, Any], dotted: str) -> Any:
    """A field of a nested ECS document (``doc["event"]["category"]`` for "event.category")."""
    if dotted == "@timestamp":
        return doc.get(dotted)
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _first(v: Any) -> Any:
    return v[0] if isinstance(v, list) and v else v


def _event_ms(doc: dict[str, Any]) -> int:
    from kratos.utils.timeutil import parse_stored_instant

    when = parse_stored_instant(_get(doc, "@timestamp"))
    return int(when.timestamp() * 1000) if when is not None else 0


def event_class(doc: dict[str, Any]) -> int | None:
    cats = _get(doc, "event.category") or []
    cats = cats if isinstance(cats, list) else [cats]
    if "authentication" in cats:
        return AUTHENTICATION
    if "process" in cats and _get(doc, "process.name"):
        return PROCESS_ACTIVITY
    if "network" in cats:
        return NETWORK_ACTIVITY
    if "file" in cats and _get(doc, "file.path"):
        return FILE_ACTIVITY
    return None


def event(doc: dict[str, Any], *, machine: str, row_id: int) -> dict[str, Any] | None:
    """One stored ECS event as an OCSF event, or None when no class here fits it."""
    cls = event_class(doc)
    if cls is None:
        return None
    types = _get(doc, "event.type") or []
    types = types if isinstance(types, list) else [types]
    outcome = str(_get(doc, "event.outcome") or "")
    status = {"success": 1, "failure": 2}.get(outcome, 0)
    msg = str(_get(doc, "message") or _get(doc, "event.original") or _get(doc, "event.action") or "")[:2000]
    uid = str(_get(doc, "event.id") or row_id)
    out: dict[str, Any] = {"class_uid": cls, "class_name": CLASS_NAMES[cls], "category_uid": CATEGORY[cls][0],
                           "category_name": CATEGORY[cls][1], "severity_id": 1, "severity": "Informational",
                           "time": _event_ms(doc), "metadata": _metadata(uid, logged_ms=None),
                           "device": _device(machine, ""), "status_id": status,
                           "status": {1: "Success", 2: "Failure"}.get(status, "Unknown")}
    if msg:
        out["message"] = msg
    user = _get(doc, "user.name")
    src = _get(doc, "source.ip")
    if cls == AUTHENTICATION:
        activity = 2 if "end" in types else 1
        out["user"] = {"name": str(user)} if user else {"name": "unknown"}
        # the machine signed in to, and the program that took the sign-in (OCSF asks for one)
        out["dst_endpoint"] = {k: v for k, v in _device(machine, "").items() if k in ("ip", "hostname")}
        provider = _get(doc, "event.provider") or _get(doc, "process.name")
        if provider:
            out["service"] = {"name": str(provider)}
        if src:
            ep: dict[str, Any] = {"ip": str(src)}
            if _get(doc, "source.port"):
                ep["port"] = int(_get(doc, "source.port"))
            out["src_endpoint"] = ep
    elif cls == PROCESS_ACTIVITY:
        activity = 2 if "end" in types else 1
        proc: dict[str, Any] = {"name": str(_get(doc, "process.name"))}
        if _get(doc, "process.pid") is not None:
            proc["pid"] = int(_get(doc, "process.pid"))
        else:              # OCSF needs one identifier: the stored event's own id stands in when no pid was logged
            proc["uid"] = uid
        if _get(doc, "process.command_line"):
            proc["cmd_line"] = str(_get(doc, "process.command_line"))[:4000]
        out["process"] = proc
        out["actor"] = {"user": {"name": str(user)}} if user else {"app_name": str(_get(doc, "event.provider") or "")}
    elif cls == NETWORK_ACTIVITY:
        activity = 5 if outcome == "failure" or "denied" in types else 6
        if src:
            out["src_endpoint"] = {"ip": str(src)}
        dst = _get(doc, "destination.ip")
        if dst:
            ep2: dict[str, Any] = {"ip": str(dst)}
            if _get(doc, "destination.port"):
                ep2["port"] = int(_get(doc, "destination.port"))
            out["dst_endpoint"] = ep2
    else:
        activity = 1 if "creation" in types else 4 if "deletion" in types else 3 if "change" in types else 99
        path = str(_get(doc, "file.path"))
        out["file"] = {"name": path.rsplit("/", 1)[-1] or path, "path": path, "type_id": 1, "type": "Regular File"}
        out["actor"] = {"user": {"name": str(user)}} if user else {"app_name": str(_get(doc, "event.provider") or "")}
    out["activity_id"] = activity
    out["type_uid"] = cls * 100 + activity
    out["unmapped"] = {"kratos": {"row": row_id, "dataset": _get(doc, "event.dataset"),
                                  "action": _get(doc, "event.action")}}
    if activity == 99:
        out["activity_name"] = str(_get(doc, "event.action") or "other")
    return out

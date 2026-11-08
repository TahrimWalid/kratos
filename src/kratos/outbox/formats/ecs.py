"""ECS output (the ECS version Kratos stores events in, ``kratos.events.fields.ECS_VERSION``).

Host events go out exactly as stored -- the stored document is already ECS, so it is
forwarded unchanged (``event``). A findings change becomes an ECS document of its own:
``event.kind`` ``alert`` for behaviour (something happened) and ``state`` for posture and
vulnerabilities, ``rule.*`` for the rule, ``vulnerability.id`` for CVEs, ``threat.*`` for
the ATT&CK labels, and Kratos's lifecycle fields under ``kratos.*`` (custom fields go in
their own top-level object, as ECS asks)."""
from __future__ import annotations

from typing import Any

from kratos.outbox.formats import FindingChange
from kratos.outbox.formats.kratos_json import iso

SEVERITY_NUMBER = {"info": 21, "low": 47, "medium": 73, "high": 85, "critical": 99}


def ecs_version() -> str:
    from kratos.events.fields import ECS_VERSION

    return ECS_VERSION


def event(doc: dict[str, Any]) -> dict[str, Any]:
    """A stored host event, unchanged."""
    return doc


def finding(c: FindingChange) -> dict[str, Any]:
    from kratos.outbox.formats.ocsf import COMPLIANCE_FINDING, VULNERABILITY_FINDING, class_of

    f = c.finding
    cls = class_of(c.rule_id)
    kind = "alert" if cls not in (COMPLIANCE_FINDING, VULNERABILITY_FINDING) else "state"
    category = (["vulnerability"] if cls == VULNERABILITY_FINDING else ["configuration"]
                if cls == COMPLIANCE_FINDING else ["intrusion_detection"])
    etype = {"new": ["creation"], "mitigated": ["end"], "inactive": ["end"], "decided": ["change"]}.get(
        c.change, ["change"])
    doc: dict[str, Any] = {
        "@timestamp": iso(c.at), "ecs": {"version": ecs_version()},
        "event": {"kind": kind, "category": category, "type": etype, "action": f"finding-{c.change}",
                  "dataset": "kratos.finding", "module": "kratos", "provider": "kratos",
                  "severity": SEVERITY_NUMBER.get(c.severity, 21), "id": c.message_id,
                  "outcome": "unknown"},
        "message": c.title,
        "rule": {"id": c.rule_id, "name": c.title, "ruleset": "kratos"},
        "host": {"name": c.machine},
        "labels": {"kratos_finding_key": c.finding_key, "kratos_change": c.change, "kratos_state": c.state},
        "kratos": {k: v for k, v in {
            "finding_key": c.finding_key, "change": c.change, "state": c.state, "from_state": c.from_state,
            "to_state": c.to_state, "severity": c.severity, "reason": c.reason,
            "decided_by": c.actor if c.change == "decided" else None, "machine_label": c.machine_label or None,
            "subject": f.get("subject") or None, "entities": f.get("entities") or None,
            "evidence": [str(e) for e in f.get("evidence") or []][:20] or None,
            "recommendation": [str(r) for r in f.get("recommendation") or []] or None,
            "ssvc": ({"outcome": f["ssvc"].get("outcome"), "label": f["ssvc"].get("label")}
                     if isinstance(f.get("ssvc"), dict) and f["ssvc"].get("outcome") else None),
            "lifecycle_event": c.event_id}.items() if v not in (None, "", [])},
    }
    rule = f.get("detection_rule") if isinstance(f.get("detection_rule"), dict) else None
    if rule and rule.get("author"):
        doc["rule"]["author"] = [str(rule["author"])]
        if rule.get("license"):
            doc["rule"]["license"] = str(rule["license"])
    cves = sorted({str(e).rpartition(":")[2].upper() for e in f.get("entities") or []
                   if str(e).rpartition(":")[2].upper().startswith("CVE-")})
    if cves:
        doc["vulnerability"] = {"id": cves if len(cves) > 1 else cves[0], "severity": c.severity}
    attacks = [a for a in f.get("attack") or [] if isinstance(a, dict) and a.get("technique_id")]
    if attacks:
        doc["threat"] = {"framework": "MITRE ATT&CK",
                         "technique": {"id": [a["technique_id"] for a in attacks],
                                       "name": [str(a.get("technique") or "") for a in attacks]},
                         "tactic": {"id": sorted({a["tactic_id"] for a in attacks if a.get("tactic_id")}),
                                    "name": sorted({str(a.get("tactic")) for a in attacks if a.get("tactic")})}}
    ips = [str(i) for i in f.get("source_ips") or []]
    if ips:
        doc["source"] = {"ip": ips[0]}
        doc["related"] = {"ip": ips}
    return doc

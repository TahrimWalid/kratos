"""Kratos's own JSON, in the Standard Webhooks payload shape: ``{"type", "timestamp", "data"}``.

``type`` is ``kratos.alert``, ``kratos.notice``, ``kratos.test``, ``kratos.finding.<change>``
or ``kratos.events``; ``data`` carries the message. Serialised compactly with sorted keys,
so the bytes signed are the bytes sent and the same message always renders the same."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterable

from kratos.outbox.formats import Alert, FindingChange

SCHEMA = "kratos.outbox/1"


def iso(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def alert(a: Alert) -> dict[str, Any]:
    return {"type": f"kratos.{a.kind}", "timestamp": iso(a.at), "data": {
        "schema": SCHEMA, "id": a.message_id, "severity": a.worst or {"critical": "high", "warning": "medium"}.get(
            a.bucket, "info"),
        "text": a.text, "machine": a.machine, "source": a.source, "name": a.name,
        "findings": [dict(f) for f in a.findings]}}


_FINDING_FIELDS = ("id", "title", "severity", "evidence", "recommendation", "subject", "entities", "attack", "ssvc",
                   "detection_rule", "source_ips", "also_matched", "collected_at", "first_seen", "last_seen", "state",
                   "triage")


def finding_data(c: FindingChange) -> dict[str, Any]:
    f = {k: c.finding.get(k) for k in _FINDING_FIELDS if c.finding.get(k) not in (None, "", [], {})}
    return {"schema": SCHEMA, "id": c.message_id, "change": c.change, "finding_key": c.finding_key,
            "rule_id": c.rule_id, "machine": c.machine, "machine_label": c.machine_label or None,
            "state": c.state, "from_state": c.from_state, "to_state": c.to_state, "severity": c.severity,
            "title": c.title, "reason": c.reason, "decided_by": c.actor if c.change == "decided" else None,
            "lifecycle_event": c.event_id, "finding": f}


def finding(c: FindingChange) -> dict[str, Any]:
    return {"type": f"kratos.finding.{c.change}", "timestamp": iso(c.at), "data": finding_data(c)}


def events(docs: Iterable[dict[str, Any]], *, machine: str | None, first_row: int, last_row: int,
           at: float) -> dict[str, Any]:
    docs = list(docs)
    return {"type": "kratos.events", "timestamp": iso(at), "data": {
        "schema": SCHEMA, "machine": machine, "count": len(docs), "first_row": first_row, "last_row": last_row,
        "events": docs}}

"""The findings engine's side of compliance: COMP-001 from the saved result
(kratos.compliance.record), registered as a snapshot source (category `compliance`)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from kratos.compliance import record

CATEGORY = "compliance"
MAX_AGE_HOURS = 24


def load_recent(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("signals"), list):
        return None
    if time.time() - float(data.get("checked_at_epoch") or 0) > MAX_AGE_HOURS * 3600:
        return None
    return data


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding, normalise_entities

    out: list[Any] = []
    for s in doc.get("signals") or []:
        if isinstance(s, dict) and s.get("rule") == "COMP-001":
            out.append(Finding(id="COMP-001", title=str(s.get("title") or "Hardening checks fail"),
                               severity=str(s.get("severity") or "low"),
                               evidence=[str(x) for x in s.get("evidence") or []],
                               recommendation=[str(x) for x in s.get("recommendation") or []],
                               subject=str(s.get("subject") or ""),
                               entities=normalise_entities("check", s.get("entities") or [])))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    """Only a fresh, complete hardening read can say COMP-001 is gone."""
    return bool(doc.get("complete"))


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=record.FOLDER, pattern=record.PATTERN,
                                            rule_prefix="COMP-", load=load_recent, build=build,
                                            closes_findings=closes_findings))

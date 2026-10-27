"""The findings engine's side of the web-server signals: WEB-001 / WEB-002 from the
saved snapshot (kratos.websig.record), registered as a snapshot source."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from kratos.websig import record

CATEGORY = "web_signals"
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


def _kwargs(sig: dict[str, Any]) -> dict[str, Any]:
    from kratos.adapters.findings_engine import normalise_entities

    return {"title": str(sig.get("title") or sig.get("rule")), "severity": str(sig.get("severity") or "info"),
            "evidence": [str(x) for x in sig.get("evidence") or []],
            "recommendation": [str(r) for r in sig.get("recommendation") or []],
            "subject": str(sig.get("subject") or ""),
            "entities": normalise_entities("text", sig.get("entities") or [])}


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding

    out: list[Any] = []
    for s in doc.get("signals") or []:
        if not isinstance(s, dict):
            continue
        if s.get("rule") == "WEB-001":
            out.append(Finding(id="WEB-001", **_kwargs(s)))
        elif s.get("rule") == "WEB-002":
            out.append(Finding(id="WEB-002", **_kwargs(s)))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    return bool(doc.get("complete"))


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=record.FOLDER, pattern=record.PATTERN,
                                            rule_prefix="WEB-", load=load_recent, build=build,
                                            closes_findings=closes_findings))

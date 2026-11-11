"""The findings engine's side of file-hash reputation: HASH-001/002/003 from the saved
result (kratos.hashdb.record), registered as a snapshot source."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from kratos.hashdb import record

CATEGORY = "hash_reputation"
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


def _kwargs(sig: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    from kratos.adapters.findings_engine import normalise_entities

    evidence = [str(x) for x in sig.get("evidence") or []]
    if str(sig.get("rule")) != "HASH-003" and doc.get("coverage_gaps"):
        evidence.append("Not every file could be checked -- see HASH-003 for which and why.")
    return {"title": str(sig.get("title") or sig.get("rule")), "severity": str(sig.get("severity") or "info"),
            "evidence": evidence, "recommendation": [str(r) for r in sig.get("recommendation") or []],
            "subject": str(sig.get("subject") or ""),
            "entities": normalise_entities("path", sig.get("entities") or [])}


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding

    out: list[Any] = []
    for s in doc.get("signals") or []:
        if not isinstance(s, dict):
            continue
        if s.get("rule") == "HASH-001":
            out.append(Finding(id="HASH-001", **_kwargs(s, doc)))
        elif s.get("rule") == "HASH-002":
            out.append(Finding(id="HASH-002", **_kwargs(s, doc)))
        elif s.get("rule") == "HASH-003":
            out.append(Finding(id="HASH-003", **_kwargs(s, doc)))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    return bool(doc.get("complete"))


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=record.FOLDER, pattern=record.PATTERN,
                                            rule_prefix="HASH-", load=load_recent, build=build,
                                            closes_findings=closes_findings))

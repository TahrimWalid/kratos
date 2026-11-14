"""The findings engine's side of the deployed-code checks: CODE-001..006 from the saved
result (kratos.code.record), registered as a snapshot source."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

CATEGORY = "code"
FOLDER = "code/results"          # kratos.code.record writes here
PATTERN = "code_*.json"
MAX_AGE_HOURS = 24


def load_recent(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("signals"), list) or "roots" not in data:
        return None
    if time.time() - float(data.get("checked_at_epoch") or 0) > MAX_AGE_HOURS * 3600:
        return None
    return data


def _kwargs(sig: dict[str, Any], doc: dict[str, Any]) -> dict[str, Any]:
    evidence = [str(x) for x in sig.get("evidence") or []]
    if str(sig.get("rule")) != "CODE-006" and doc.get("coverage_gaps"):
        evidence.append("Not every part of every code folder could be checked -- see CODE-006.")
    kw = {"title": str(sig.get("title") or sig.get("rule")), "severity": str(sig.get("severity") or "info"),
          "evidence": evidence, "recommendation": [str(r) for r in sig.get("recommendation") or []],
          "subject": str(sig.get("subject") or ""), "entities": sorted({str(e) for e in sig.get("entities") or []})}
    if sig.get("fix"):
        kw["fix"] = [f for f in sig["fix"] if isinstance(f, dict)]
    return kw


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding

    out: list[Any] = []
    for s in doc.get("signals") or []:
        if not isinstance(s, dict):
            continue
        rule = s.get("rule")
        if rule == "CODE-001":
            out.append(Finding(id="CODE-001", **_kwargs(s, doc)))
        elif rule == "CODE-002":
            out.append(Finding(id="CODE-002", **_kwargs(s, doc)))
        elif rule == "CODE-003":
            out.append(Finding(id="CODE-003", **_kwargs(s, doc)))
        elif rule == "CODE-004":
            out.append(Finding(id="CODE-004", **_kwargs(s, doc)))
        elif rule == "CODE-005":
            out.append(Finding(id="CODE-005", **_kwargs(s, doc)))
        elif rule == "CODE-006":
            out.append(Finding(id="CODE-006", **_kwargs(s, doc)))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    return bool(doc.get("complete"))


def blind(doc: dict[str, Any]):
    """(rule, entity) -> why this read could not have seen it: a finding about a folder that
    wasn't fully read this time is never closed by it."""
    partial = [r["path"] for r in doc.get("roots") or [] if r.get("status") != "ok"]

    def why(_rule: str, _entity: str) -> str | None:
        return f"{len(partial)} code folder(s) not fully read" if partial else None
    return why if partial else None


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=FOLDER, pattern=PATTERN,
                                            rule_prefix="CODE-", load=load_recent, build=build,
                                            closes_findings=closes_findings, blind=blind))

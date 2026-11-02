"""The findings engine's side of the container checks (D.5): CONT-001..008 from the
container snapshot, and PKG-001 / PKG-002 / CONT-008 from the container package snapshot,
each registered as a snapshot source."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from kratos.containers import packages as _pkgs
from kratos.containers import record

CATEGORY = "containers"
PACKAGES_CATEGORY = "container_packages"
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


def _with_fix(finding: Any, sig: dict[str, Any]) -> Any:
    fix = [f for f in sig.get("fix") or [] if isinstance(f, dict) and f.get("text")]
    if fix:
        finding.fix = [{"title": str(f.get("title") or "Fix"), "text": str(f["text"])} for f in fix[:4]]
    return finding


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding

    out: list[Any] = []
    for s in doc.get("signals") or []:
        if not isinstance(s, dict):
            continue
        rule = s.get("rule")
        if rule == "CONT-001":
            out.append(_with_fix(Finding(id="CONT-001", **_kwargs(s)), s))
        elif rule == "CONT-002":
            out.append(_with_fix(Finding(id="CONT-002", **_kwargs(s)), s))
        elif rule == "CONT-003":
            out.append(_with_fix(Finding(id="CONT-003", **_kwargs(s)), s))
        elif rule == "CONT-004":
            out.append(_with_fix(Finding(id="CONT-004", **_kwargs(s)), s))
        elif rule == "CONT-005":
            out.append(_with_fix(Finding(id="CONT-005", **_kwargs(s)), s))
        elif rule == "CONT-006":
            out.append(_with_fix(Finding(id="CONT-006", **_kwargs(s)), s))
        elif rule == "CONT-007":
            out.append(_with_fix(Finding(id="CONT-007", **_kwargs(s)), s))
        elif rule == "CONT-008":
            out.append(Finding(id="CONT-008", **_kwargs(s)))
    return out


def build_packages(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding

    out: list[Any] = []
    for s in doc.get("signals") or []:
        if not isinstance(s, dict):
            continue
        rule = s.get("rule")
        if rule == "PKG-001" and _pkgs.is_image_subject(s.get("subject")):
            out.append(Finding(id="PKG-001", **_kwargs(s)))
        elif rule == "PKG-002" and _pkgs.is_image_subject(s.get("subject")):
            out.append(Finding(id="PKG-002", **_kwargs(s)))
        elif rule == "CONT-008":
            out.append(Finding(id="CONT-008", **_kwargs(s)))
    return out


def closes_findings(doc: dict[str, Any]) -> bool:
    return bool(doc.get("complete"))


def blind(doc: dict[str, Any]) -> Any:
    """Over SSH the engine's settings are not read: a settings finding seen earlier through
    the agent is not 'gone' because an SSH read didn't see it."""
    if doc.get("via") in ("agent", "subagent"):
        return None

    def why(rule: str, _entity: str) -> str | None:
        if rule in ("CONT-001", "CONT-002", "CONT-003", "CONT-004", "CONT-005", "CONT-007"):
            return "the engine's settings are only readable through the sub-agent"
        return None
    return why


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source

    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=record.FOLDER, pattern=record.PATTERN,
                                            rule_prefix="CONT-", load=load_recent, build=build,
                                            closes_findings=closes_findings, blind=blind))
    register_snapshot_source(SnapshotSource(category=PACKAGES_CATEGORY, folder=record.FOLDER, pattern=_pkgs.PATTERN,
                                            rule_prefix="PKG-", load=load_recent, build=build_packages,
                                            closes_findings=closes_findings, owns_prefix=False))

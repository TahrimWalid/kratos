"""The findings-engine side of attack paths: PATH-001..005 from a path-build snapshot.

E.1 does **not** emit PATH findings during a per-machine ``correlate`` (a path build is a
group synthesis, written by :mod:`kratos.attackpaths.build` straight through the lifecycle).
This module is registered as a snapshot source so the engine knows the ``PATH-`` prefix and
its input category, and so the lifecycle / ATT&CK completeness tests find the literal rule
ids here -- but its ``load_recent`` returns ``None`` (inert), so a single-machine correlate
never re-emits a group's PATH findings.

``build`` and ``findings_for`` reconstruct :class:`Finding` objects from the snapshot
payload; ``build.py`` uses ``findings_for`` to apply each machine's PATH findings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

CATEGORY = "attack_paths"
FOLDER = "paths"
PATTERN = "paths_*.json"


def load_recent(path: Path | None) -> dict[str, Any] | None:
    """Inert: a group path snapshot is not a per-machine correlate input. PATH findings are
    written by kratos.attackpaths.build through the lifecycle, never re-derived here."""
    return None


def _finding(spec: dict[str, Any]):
    """One Finding from a stored payload. Rule ids are literals so the lifecycle / ATT&CK
    completeness tests (which scan this module) see every id the build can emit."""
    from kratos.adapters.findings_engine import Finding

    rid = str(spec.get("id") or "")
    kw = dict(title=str(spec.get("title") or rid), severity=str(spec.get("severity") or "info"),
              evidence=[str(x) for x in spec.get("evidence") or []],
              recommendation=[str(r) for r in spec.get("recommendation") or []],
              subject=str(spec.get("subject") or ""),
              entities=sorted({str(e) for e in spec.get("entities") or []}))
    if spec.get("fix"):
        kw["fix"] = [f for f in spec["fix"] if isinstance(f, dict)]
    if rid == "PATH-001":
        return Finding(id="PATH-001", **kw)
    if rid == "PATH-002":
        return Finding(id="PATH-002", **kw)
    if rid == "PATH-003":
        return Finding(id="PATH-003", **kw)
    if rid == "PATH-004":
        return Finding(id="PATH-004", **kw)
    return Finding(id="PATH-005", **kw)


def findings_for(doc: dict[str, Any], target_key: str) -> list[Any]:
    """The PATH findings a path-build snapshot holds for one machine."""
    out = []
    for spec in doc.get("findings") or []:
        if str(spec.get("target_key") or "") == target_key:
            out.append(_finding(spec))
    return out


def build(doc: dict[str, Any]) -> list[Any]:
    """Every PATH finding in a snapshot (used by the completeness scanner; never called at
    correlate because load_recent is inert)."""
    return [_finding(spec) for spec in doc.get("findings") or []]


def closes_findings(doc: dict[str, Any]) -> bool:
    return False       # inert source: it never closes a finding during correlate


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source
    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=FOLDER, pattern=PATTERN,
                                            rule_prefix="PATH-", load=load_recent, build=build,
                                            closes_findings=closes_findings))

"""SARIF 2.1.0 out (E.7b §3.14 surfaces): REVIEW findings (and CODE findings on request) as
results with rule ids, relative paths, line regions, severity, verdict and open question in
properties -- and **no `snippet` and no code text**, so it complements GitHub code scanning /
DefectDojo rather than leaking the machine's code.

Built from the stored review snapshots (`review/results`, written by judge.py) -- no live run,
no model call. Validated against the official SARIF 2.1.0 schema in tests.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/sarif-2.1/schema/sarif-schema-2.1.0.json"
TOOL_NAME = "Kratos"
INFO_URI = "https://github.com/"

# severity -> SARIF level
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

_RULE_META = {
    "REVIEW-001": ("Confirmed weakness in deployed code",
                   "A request-reachable dangerous call confirmed by a reproduction or a direct rule."),
    "REVIEW-002": ("Possible weakness awaiting validation",
                   "A lead that a reproduction or rule could neither confirm nor disprove."),
    "REVIEW-003": ("AI code-review run note", "The review's profile, cost, coverage and any gaps."),
}
_CODE_RULE_META = {
    "CODE-001": ("Untracked file in served code", "A served file that isn't in the repository."),
    "CODE-002": ("Modified file in served code", "A served file that differs from the repository."),
    "CODE-003": ("Vulnerable dependency in served code", "A dependency with a known advisory."),
    "CODE-004": ("Secret in served code", "A credential-shaped value in deployed code (fingerprint only)."),
    "CODE-005": ("Web-shell signature in served code", "A served file matches a web-shell YARA rule."),
}


def _level(severity: str) -> str:
    return _LEVEL.get(str(severity).lower(), "note")


def _result_from_review_finding(f: dict[str, Any]) -> dict[str, Any]:
    from kratos.review.judge import severity_for
    rel = str(f.get("rel") or "")
    line = int(f.get("line") or 1)
    sev = severity_for(f)
    props = {"verdict": f.get("verdict", ""), "strength": f.get("strength", ""),
             "class": f.get("cls", ""), "exposure": f.get("exposure", "unknown"),
             "severity": sev, "function": f.get("function", "")}
    if f.get("question"):
        props["openQuestion"] = str(f["question"])
    if f.get("drift"):
        props["changedOnServer"] = True
    msg = str(f.get("evidence") or f.get("verdict") or "review finding")        # never the code
    return {
        "ruleId": "REVIEW-001" if f.get("verdict") == "confirmed" else "REVIEW-002",
        "level": _level(sev),
        "message": {"text": msg},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": rel},
                                            "region": {"startLine": max(1, line)}}}],
        "properties": props,
    }


def _rules_block(rule_ids: set[str], meta: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    out = []
    for rid in sorted(rule_ids):
        name, desc = meta.get(rid, (rid, rid))
        out.append({"id": rid, "name": name.replace(" ", ""), "shortDescription": {"text": name},
                    "fullDescription": {"text": desc}})
    return out


def build_sarif(review_findings: list[dict[str, Any]], *, code_findings: list[dict[str, Any]] | None = None,
                tool_version: str = "") -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    for f in review_findings:
        if f.get("verdict") not in ("confirmed", "needs_validation"):
            continue
        r = _result_from_review_finding(f)
        rule_ids.add(r["ruleId"])
        results.append(r)
    rules = _rules_block(rule_ids, _RULE_META)
    for cf in code_findings or []:
        rid = str(cf.get("id") or "")
        if rid not in _CODE_RULE_META:
            continue
        rule_ids.add(rid)
        results.append({
            "ruleId": rid, "level": _level(cf.get("severity", "info")),
            "message": {"text": str(cf.get("title") or rid)},        # title only, never code
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(e)}}}
                          for e in (cf.get("entities") or [])[:1] if e] or
                         [{"physicalLocation": {"artifactLocation": {"uri": str(cf.get("subject") or "code")}}}],
            "properties": {"severity": cf.get("severity", "info")},
        })
        rules = _rules_block(rule_ids, {**_RULE_META, **_CODE_RULE_META})
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "informationUri": INFO_URI,
                                "version": tool_version or "0", "rules": rules}},
            "results": results,
        }],
    }


def latest_review_findings(data_dir: Path | str, machine: str | None = None) -> list[dict[str, Any]]:
    """The findings from the newest review snapshot per machine (review/results)."""
    from kratos.review import judge as J
    from kratos.target_key import target_key
    folder = Path(data_dir) / J.FOLDER
    out: list[dict[str, Any]] = []
    if not folder.exists():
        return out
    want = target_key(machine) if machine else None
    latest: dict[str, tuple[float, dict[str, Any]]] = {}
    for p in folder.glob(J.PATTERN):
        doc = J.load_recent(p)
        if doc is None:
            continue
        tk = str(doc.get("target") or "")
        if want and tk != want:
            continue
        ts = float(doc.get("checked_at_epoch") or 0)
        if tk not in latest or ts > latest[tk][0]:
            latest[tk] = (ts, doc)
    for _ts, doc in latest.values():
        out.extend(doc.get("findings") or [])
    return out


def write_sarif(data_dir: Path | str, out_path: Path | str, *, machine: str | None = None,
                include_code: bool = False) -> Path:
    review = latest_review_findings(data_dir, machine)
    code: list[dict[str, Any]] = []
    if include_code:
        code = _latest_code_findings(data_dir, machine)
    doc = build_sarif(review, code_findings=code, tool_version=_version())
    out = Path(out_path)
    out.write_text(json.dumps(doc, ensure_ascii=True, indent=2), encoding="utf-8")
    return out


def _version() -> str:
    try:
        from kratos import __version__
        return str(__version__)
    except Exception:  # noqa: BLE001
        return "0"


def _latest_code_findings(data_dir: Path | str, machine: str | None) -> list[dict[str, Any]]:
    """CODE-001..005 from the newest findings report on disk, for `--sarif` with CODE findings
    requested. Best-effort: returns [] when no report is present."""
    reports = sorted((Path(data_dir) / "reports").glob("findings_*.json"), reverse=True)
    for p in reports:
        try:
            rep = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if isinstance(rep, dict) and isinstance(rep.get("findings"), list):
            return [f for f in rep["findings"] if str(f.get("id", "")).startswith("CODE-")]
    return []

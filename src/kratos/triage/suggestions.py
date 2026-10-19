"""The model's `finding_notes` suggestions (docs/phaseB/B.1 §3.6).

The model MAY add, to its final answer, notes that a finding looks like a false
positive, is less serious, or needs a person to judge. They are the model's
SUGGESTION, never a decision: shown labelled "the model suggests", stored in
`finding_suggestions`, and acted on only when a PERSON accepts (through the
normal people-only decision path) or dismisses one.

Sanitised exactly like recommended_commands: a bounded count, a length cap, the
finding it names must exist in THIS run, and `why` is cleaned for display (A.4) on
the way out -- the one place an injected instruction in model output could reach a
person.
"""
from __future__ import annotations

from typing import Any

from kratos import untrusted
from kratos.triage.store import SUGGEST_KINDS

MAX_NOTES = 12
MAX_WHY_LEN = 300


def sanitize_finding_notes(raw: Any, findings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Clean `finding_notes` into a bounded list of
    {finding_key, rule_id, kind, why}. Drops any entry that is malformed or names a
    finding not in this run; never raises."""
    if not isinstance(raw, list):
        return []
    by_id, by_key = _index(findings)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if len(out) >= MAX_NOTES or not isinstance(item, dict):
            continue
        kind = str(item.get("suggest") or "").strip().lower()
        if kind not in SUGGEST_KINDS:
            continue
        match = _resolve(str(item.get("finding") or "").strip(), by_id, by_key)
        if match is None:
            continue
        why = untrusted.for_display(str(item.get("why") or "").strip())[:MAX_WHY_LEN]
        if not why:
            continue
        dedupe = (str(match.get("finding_key") or match.get("id")), kind)
        if dedupe in seen:
            continue
        seen.add(dedupe)
        out.append({"finding_key": str(match.get("finding_key") or ""), "rule_id": str(match.get("id") or ""),
                    "kind": kind, "why": why})
    return out


def _index(findings: list[dict[str, Any]] | None) -> tuple[dict[str, dict], dict[str, dict]]:
    by_id: dict[str, dict] = {}
    by_key: dict[str, dict] = {}
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        if fid:
            by_id.setdefault(fid, f)
        key = str(f.get("finding_key") or "")
        if key:
            by_key[key] = f
    return by_id, by_key


def _resolve(name: str, by_id: dict[str, dict], by_key: dict[str, dict]) -> dict[str, Any] | None:
    """A finding named by the model: a rule id, a full finding_key, or a key prefix."""
    if not name:
        return None
    if name in by_id:
        return by_id[name]
    if name in by_key:
        return by_key[name]
    low = name.lower()
    hits = [f for k, f in by_key.items() if k.startswith(low)]
    if len(hits) == 1:
        return hits[0]
    return None


def record_notes(data_dir: Any, notes: list[dict[str, Any]], *, target: str | None, run: Any = None,
                 now: float | None = None) -> list[int]:
    """Store sanitised suggestions. Returns the new suggestion ids."""
    from pathlib import Path

    from kratos.target_key import target_key
    from kratos.triage import store as _store

    ids: list[int] = []
    tgt = target_key(target) if target else None
    for n in notes or []:
        try:
            ids.append(_store.record_suggestion(
                Path(data_dir), finding_key=n.get("finding_key") or None, rule_id=str(n.get("rule_id") or ""),
                target=tgt, run_id=getattr(run, "run_id", None), kind=str(n.get("kind")),
                why=str(n.get("why") or ""), now=now))
        except Exception:  # noqa: BLE001 -- a bad note must never fail the run
            continue
    return ids


_SUGGEST_WORDS = {"false_positive": "this is probably a false positive",
                  "lower_severity": "this is probably less serious than its severity",
                  "needs_person": "a person should judge this"}
# What accepting each suggestion maps to in the people-only decision flow.
SUGGEST_TO_DECISION = {"false_positive": "false_positive", "lower_severity": None, "needs_person": None}


def suggestion_phrase(kind: str) -> str:
    return _SUGGEST_WORDS.get(kind, kind)

"""REVIEW-001/002/003 and the review snapshot source (E.7b §3.12).

A finished review writes one snapshot per machine (`review/results/review_*.json`, never any
code); this module builds findings from it and is registered as a findings-engine snapshot source
so REVIEW findings flow through lifecycle, triage, export, OCSF and the digest like every other.

- **REVIEW-001** -- a `confirmed` weakness in served/executed code.
  - `reproduced`: high for an execution/deserialisation class on an internet-exposed process,
    else medium; a root whose process isn't running caps at low.
  - `direct`: high only for an execution/deserialisation class **and** internet exposure, else
    medium; not-running caps at low.
- **REVIEW-002** -- a `needs_validation` lead; <= medium (medium for an exec/deserialisation class
  on an internet-exposed path, low otherwise).
- **REVIEW-003** -- the run note (profile, cost, coverage, drops, reproduction off, stop reason).

`rejected` is never a finding (it lives in the verdict cache). REVIEW-001/002 are **conditions**:
a later review of the root that doesn't raise them again mitigates them; REVIEW-003 is a run note.
Verdicts are code-made upstream (`verdict.py`); nothing here reads model text.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from kratos.review import classes as C
from kratos.utils.stamped import reserve
from kratos.utils.timeutil import epoch_to_utc_iso

CATEGORY = "review"
FOLDER = "review/results"
PATTERN = "review_*.json"
MAX_AGE_DAYS = 400               # a review is on-demand; keep the latest per machine, don't age it out


# --------------------------------------------------------------------------- severity (§3.12)
def _exec_like(cls: str) -> bool:
    return cls in C.EXEC_LIKE


def severity_for(f: dict[str, Any]) -> str:
    verdict = f.get("verdict")
    strength = f.get("strength")
    exposure = f.get("exposure", "unknown")
    exec_like = _exec_like(f.get("cls", ""))
    internet = exposure == "internet"
    not_running = exposure == "not_running"
    if verdict == "confirmed":
        if strength == "reproduced":
            sev = "high" if (exec_like and internet) else "medium"
        else:                       # direct
            sev = "high" if (exec_like and internet) else "medium"
        return "low" if not_running else sev
    if verdict == "needs_validation":
        return "medium" if (exec_like and internet) else "low"
    return "info"


# --------------------------------------------------------------------------- snapshot
def build_doc(plan: Any, findings_data: list[dict[str, Any]], run: dict[str, Any],
              counts: dict[str, Any], actual: float, agreed: float, *, now: float | None = None) -> dict[str, Any]:
    from kratos.target_key import target_key
    now = time.time() if now is None else now
    return {
        "target": target_key(plan.machine), "machine": plan.machine, "root": plan.root,
        "checked_at": epoch_to_utc_iso(now), "checked_at_epoch": now,
        "profile": plan.profile.name, "verifier_profile": (plan.verifier.name if plan.verifier else plan.profile.name),
        "destination": plan.profile.destination, "mask_mode": plan.mask_mode,
        "reproduction": plan.reproduction, "complete": True,
        "estimate_usd": plan.estimate.usd, "actual_usd": actual, "agreed_usd": agreed,
        "raised_by": run.get("raised_by", ""), "raised_to": run.get("raised_to"),
        "stop_reason": run.get("stop_reason", ""), "state": run.get("state", "done"),
        "counts": counts, "reachability": [r.__dict__ if hasattr(r, "__dict__") else r for r in plan.reachability],
        "findings": findings_data,
    }


def write_snapshot(data_dir: Path | str, machine: str, doc: dict[str, Any]) -> Path:
    from kratos.target_key import target_key
    folder = Path(data_dir) / FOLDER
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"review_{target_key(machine)}"
    path, _stamp = reserve(folder, stem, ".json")
    path.write_text(json.dumps(doc, ensure_ascii=True, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    _record_evidence(data_dir, path, machine)
    return path


def _record_evidence(data_dir: Path | str, path: Path, machine: str) -> None:
    try:
        from kratos.evidence import record as ev_record
        ev_record(path, data_dir=Path(data_dir), category=CATEGORY, machine=machine, read="review",
                  transport="local")
    except Exception:  # noqa: BLE001 -- evidence recording never fails a review
        pass


def publish(data_dir: Path | str, machine: str) -> None:
    """Run the findings engine for this machine so REVIEW findings flow through lifecycle/triage."""
    from kratos import kratos_config
    from kratos.adapters.findings_engine import write_findings_report
    with kratos_config.pinned_target(machine):
        write_findings_report(Path(data_dir))


# --------------------------------------------------------------------------- the findings source
def load_recent(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "findings" not in data or "root" not in data:
        return None
    if time.time() - float(data.get("checked_at_epoch") or 0) > MAX_AGE_DAYS * 86400:
        return None
    return data


def _entity(f: dict[str, Any]) -> str:
    return f"{f.get('rel')}:{f.get('function')}:{f.get('cls')}"


def _subject(root: str, f: dict[str, Any]) -> str:
    return f"{root} {f.get('rel')} {f.get('cls')}"


def _reach_note(doc: dict[str, Any]) -> list[str]:
    out = []
    for r in doc.get("reachability") or []:
        if r.get("status") == "reached":
            ids = ", ".join(r.get("advisories") or [])
            out.append(f"dependency {r.get('package')} (CODE-003{': ' + ids if ids else ''}) is reached from a "
                       "network route")
    return out


def build(doc: dict[str, Any]) -> list[Any]:
    from kratos.adapters.findings_engine import Finding

    root = str(doc.get("root") or "")
    out: list[Any] = []
    reach = _reach_note(doc)
    for f in doc.get("findings") or []:
        if not isinstance(f, dict):
            continue
        verdict = f.get("verdict")
        cls = C.CLASSES.get(f.get("cls", ""))
        label = cls.label if cls else f.get("cls", "")
        sev = severity_for(f)
        ev = [f"{verdict}" + (f" ({f['strength']})" if f.get("strength") else "") + f": {label}",
              f"at {f.get('rel')}:{f.get('function')}"]
        if f.get("evidence"):
            ev.append(str(f["evidence"]))
        if f.get("question"):
            ev.append("open question: " + str(f["question"]))
        if f.get("drift"):
            ev.append("this file is changed on the server (reviewed first)")
        ev.append(f"exposure: {f.get('exposure', 'unknown')}")
        if f.get("fix_check"):
            ev.append({"checked": "a proposed fix was checked in the sandbox: the canary no longer reaches the call",
                       "not_confirmed": "a proposed fix was NOT confirmed by the sandbox",
                       "not_checked": "a fix was proposed but not sandbox-checked"}.get(f["fix_check"], ""))
        ev += reach
        sub = _subject(root, f)
        ents = [_entity(f), (f.get("slice_sha") or "")[:16]]
        rec = []
        if f.get("fix_words"):
            rec.append("proposed fix: " + str(f["fix_words"]))
        if verdict == "confirmed":
            out.append(Finding(id="REVIEW-001", title=f"{label} in served code ({f.get('rel')})", severity=sev,
                               evidence=[e for e in ev if e], recommendation=rec, subject=sub,
                               entities=sorted(e for e in ents if e)))
        elif verdict == "needs_validation":
            out.append(Finding(id="REVIEW-002", title=f"possible {label} ({f.get('rel')})", severity=sev,
                               evidence=[e for e in ev if e], recommendation=rec, subject=sub,
                               entities=sorted(e for e in ents if e)))
    note = _run_note(doc)
    if note is not None:
        out.append(note)
    return out


def _run_note(doc: dict[str, Any]):
    from kratos.adapters.findings_engine import Finding
    counts = doc.get("counts") or {}
    ev = [f"profile: {doc.get('profile')} ({doc.get('destination')}); masking {doc.get('mask_mode')}; "
          "secrets always removed",
          f"cost: estimate ${float(doc.get('estimate_usd') or 0):.4f}, agreed ${float(doc.get('agreed_usd') or 0):.4f}, "
          f"actual ${float(doc.get('actual_usd') or 0):.4f}",
          f"slices reviewed {counts.get('reviewed', 0)}, cached {counts.get('cached', 0)}, "
          f"reproduced {counts.get('reproduced', 0)}, dropped by cap {counts.get('dropped_by_cap', 0)}, "
          f"too large {counts.get('too_large', 0)}, changed since consent {counts.get('changed_since_consent', 0)}"]
    drops = counts.get("leads_dropped") or {}
    if any(drops.values()):
        ev.append(f"leads dropped: {drops.get('outside', 0)} outside what was sent, "
                  f"{drops.get('over_cap_call', 0)} over the per-call cap, {drops.get('over_cap_run', 0)} over the run cap")
    cov = (counts.get("coverage") or {}).get("incomplete") or []
    if cov:
        ev.append("incomplete coverage: " + ", ".join(f"{c['class']} {c['pct']}%" for c in cov))
    langs = counts.get("incomplete_languages") or {}
    if langs:
        ev.append("not sliced (no review extra): " + ", ".join(f"{n} {ext}" for ext, n in langs.items())
                  + " -- install the `review` extra (tree-sitter) for PHP/JS/TS")
    if not doc.get("reproduction"):
        ev.append("reproduction is off on this computer (no Incus or review.sandbox_reproduction=false): leads are "
                  "confirmed by a direct rule or checked by a person, never reproduced")
    if doc.get("stop_reason"):
        ev.append("stopped: " + str(doc["stop_reason"]) + " -- what wasn't reviewed is above")
    if doc.get("raised_by"):
        ev.append(f"the cost ceiling was raised to ${float(doc.get('raised_to') or 0):.2f} by {doc['raised_by']}")
    return Finding(id="REVIEW-003", title=f"AI code review of {doc.get('root')}", severity="info",
                   evidence=ev, recommendation=[], subject=f"{doc.get('root')} review", entities=[])


def closes_findings(doc: dict[str, Any]) -> bool:
    """A completed review of a root covers its REVIEW findings: a look-alike no longer raised is
    mitigated. A stopped/partial review does not close (it didn't review everything)."""
    return bool(doc.get("complete")) and doc.get("state") == "done"


def blind(doc: dict[str, Any]):
    return None


def register() -> None:
    from kratos.adapters.findings_engine import SnapshotSource, register_snapshot_source
    register_snapshot_source(SnapshotSource(category=CATEGORY, folder=FOLDER, pattern=PATTERN,
                                            rule_prefix="REVIEW-", load=load_recent, build=build,
                                            closes_findings=closes_findings, blind=blind))

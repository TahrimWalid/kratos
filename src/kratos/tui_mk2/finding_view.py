"""Which findings a conversation shows in full, and which it folds into one line.

correlate_findings reports EVERYTHING on record for the target -- including data
collected by earlier questions -- so every answer used to re-list the same
background findings (sudo activity, an old burst, privileged accounts), even for
"is there any malware?". This decides, per finding:

- shown in full: new in this conversation, or changed since it was last shown,
  and built from data collected in THIS investigation (or high/critical);
- folded: unchanged since it was already shown, or built only from data an earlier
  check collected ("still on record, not re-checked now").

Nothing is hidden anywhere else: /report, the model and the answer checks always see
every finding. UI-free, so the rules are tested directly.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

_URGENT = ("high", "critical")
# Evidence lines that change on every run without the finding changing.
_VOLATILE = ("Time window:", "Coverage:", "From ", "Checked ", "One finding for this burst")
_FRESH_SLACK_SECONDS = 10.0


def fingerprint(finding: dict[str, Any]) -> str:
    """Same fingerprint = nothing a reader needs to see again. Info findings are
    background facts (a sudo count creeping up is not news); anything above info
    counts as changed when its severity or real evidence does."""
    severity = str(finding.get("severity") or "info").lower()
    if severity == "info":
        return "info"
    lines = [ln for ln in finding.get("evidence") or [] if not str(ln).startswith(_VOLATILE)]
    return severity + "\n" + "\n".join(map(str, lines))


def _collected(finding: dict[str, Any]) -> float | None:
    try:
        return datetime.fromisoformat(str(finding["collected_at"])).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def plan(findings: list[dict[str, Any]], shown: dict[str, str], turn_started: float | None
         ) -> tuple[list[tuple[dict[str, Any], str]], list[tuple[dict[str, Any], str]]]:
    """(full, folded): `full` is [(finding, why)] with why in {"new", "updated",
    "earlier"}; `folded` is [(finding, why)] with why in {"unchanged", "earlier"}.
    Updates `shown` (finding id -> fingerprint) for what is shown in full."""
    full: list[tuple[dict[str, Any], str]] = []
    folded: list[tuple[dict[str, Any], str]] = []
    for f in findings:
        fid = str(f.get("id") or "")
        fp = fingerprint(f)
        collected = _collected(f)
        fresh = turn_started is None or collected is None or collected >= turn_started - _FRESH_SLACK_SECONDS
        urgent = str(f.get("severity") or "").lower() in _URGENT
        if fid in shown:
            if shown[fid] == fp:
                folded.append((f, "unchanged"))
                continue
            if not fresh and not urgent:
                folded.append((f, "earlier"))
                continue
            full.append((f, "updated"))
        elif fresh:
            full.append((f, "new"))
        elif urgent:
            full.append((f, "earlier"))  # never fold an unseen high/critical
        else:
            folded.append((f, "earlier"))
            continue
        shown[fid] = fp
    return full, folded


def folded_summary(folded: list[tuple[dict[str, Any], str]]) -> str | None:
    """One line for the folded findings, e.g. 'Still on record (unchanged): AUTH-003
    (info) · not re-checked now: PRIV-004 (info) -- /report shows them in full.'"""
    if not folded:
        return None
    def names(why: str) -> str:
        return ", ".join(f"{f.get('id')} ({str(f.get('severity') or 'info').lower()})"
                         for f, w in folded if w == why)
    parts = []
    if names("unchanged"):
        parts.append(f"unchanged since shown above: {names('unchanged')}")
    if names("earlier"):
        parts.append(f"from earlier checks, not re-checked now: {names('earlier')}")
    return "Also on record — " + " · ".join(parts) + ". /report shows them in full."

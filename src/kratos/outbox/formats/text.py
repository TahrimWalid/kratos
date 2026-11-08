"""Plain-text wording for findings changes (email digests, syslog text messages).

Kratos-written words and finding titles first; machine-controlled text (evidence lines,
entity values) is cleaned (``kratos.untrusted.for_display``) before it is placed here."""
from __future__ import annotations

from typing import Iterable

from kratos.outbox.formats import FindingChange

_CHANGE_WORDS = {
    "new": "NEW", "worse": "WORSE", "recurred": "BACK", "reopened": "REOPENED", "changed": "CHANGED",
    "verified": "CONFIRMED", "mitigated": "FIXED", "inactive": "GONE", "decided": "DECIDED",
}
MAX_EVIDENCE = 5
MAX_LINE = 300


def _clean(text: object) -> str:
    from kratos.untrusted import for_display

    s = for_display(" ".join(str(text or "").split()))
    return s if len(s) <= MAX_LINE else s[: MAX_LINE - 1] + "…"


def change_word(change: str) -> str:
    return _CHANGE_WORDS.get(change, change.upper())


def headline(c: FindingChange) -> str:
    where = c.machine_label or c.machine
    decided = ""
    if c.change == "decided" and c.to_state:
        decided = f" ({c.to_state.replace('_', ' ')} by {_clean(c.actor)})"
    return f"[{c.severity.upper()}] {change_word(c.change)} on {_clean(where)}: {_clean(c.title)} ({c.rule_id}){decided}"


def lines(c: FindingChange, *, evidence: bool = True) -> list[str]:
    out = [headline(c)]
    ssvc = c.finding.get("ssvc") if isinstance(c.finding.get("ssvc"), dict) else None
    if ssvc and ssvc.get("label"):
        out.append(f"  decision: {ssvc['label']}")
    if c.reason and c.change in ("worse", "changed", "mitigated", "inactive", "reopened", "recurred"):
        out.append(f"  why: {_clean(c.reason)}")
    if evidence:
        ev = [e for e in c.finding.get("evidence") or [] if str(e).strip()]
        for e in ev[:MAX_EVIDENCE]:
            out.append(f"  - {_clean(e)}")
        if len(ev) > MAX_EVIDENCE:
            out.append(f"  - and {len(ev) - MAX_EVIDENCE} more evidence line(s)")
    return out


def digest(changes: Iterable[FindingChange]) -> tuple[str, str]:
    """(subject, body) for an email of several findings changes (one run or batch)."""
    items = sorted(changes, key=lambda c: (-_rank(c.severity), c.machine, c.rule_id, c.event_id))
    if not items:
        return "Kratos: no changes", ""
    news = [c for c in items if c.is_news]
    worst = items[0].severity.upper()
    machines = sorted({c.machine_label or c.machine for c in items})
    where = machines[0] if len(machines) == 1 else f"{len(machines)} machines"
    subject = (f"Kratos: {worst} -- {len(news)} new or worse finding(s) on {where}" if news
               else f"Kratos: {len(items)} finding change(s) on {where}")
    body = []
    for c in items:
        body.extend(lines(c))
        body.append("")
    body.append("Next: open Kratos and type /findings (or run: kratos findings show). Evidence files are not "
                "attached; they stay on the Kratos computer.")
    return subject, "\n".join(body)


def _rank(sev: str) -> int:
    from kratos.outbox.formats import SEVERITY_RANK

    return SEVERITY_RANK.get(sev, 0)

"""Where a retest is offered after a fix (docs/phaseB/B.1 §5.3).

The fix channel is OFF, so a real `/whitelist` dispatch or `/run-fix` never runs on a
target today; this maps an action's `source_recommendation` back to the open finding(s)
it was meant to fix, so the UI can offer "/retest" the moment a fix is applied. Pure and
read-only -- it decides nothing.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from kratos.lifecycle.keys import short

_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")


def rule_ids_in(source_recommendation: Iterable[str] | None) -> list[str]:
    """The finding rule ids named in an action's source_recommendation (ignoring the
    `check:FAIL`-shaped audit references, which name a check, not a finding rule)."""
    out: list[str] = []
    for token in source_recommendation or ():
        t = str(token).strip()
        if _RULE_ID_RE.match(t) and t not in out:
            out.append(t)
    return out


def retest_offer(data_dir: Path, source_recommendation: Iterable[str] | None,
                 target: str | None) -> dict[str, Any] | None:
    """The open finding to offer a retest for after an action with this
    `source_recommendation` is applied, or None. Picks the newest-seen open/verified
    finding on `target` whose rule the action was recommended for."""
    rule_ids = set(rule_ids_in(source_recommendation))
    if not rule_ids:
        return None
    from kratos.lifecycle import query as Q

    rows = Q.list_findings(Path(data_dir), target=target or None, state="open_verified")
    for r in rows:                       # list_findings is newest-seen first
        if str(r.get("rule_id") or "") in rule_ids:
            return {"finding_key": r["finding_key"], "short_key": short(r["finding_key"]),
                    "rule_id": r["rule_id"], "title": r.get("title") or ""}
    return None


def retest_offer_text(offer: dict[str, Any]) -> str:
    """One plain line a surface shows after a fix is applied."""
    return (f"This was recommended for {offer['rule_id']}. Once the change has taken effect, retest it: "
            f"press t, or run `kratos findings retest {offer['short_key']}`.")

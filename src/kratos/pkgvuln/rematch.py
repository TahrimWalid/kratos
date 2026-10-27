"""Match every machine's stored package list again after the vulnerability data changes.

`kratos vulndb-update` used to only mark each machine's package check as due, so a CVE
published -- or added to CISA's exploited-now list -- this morning stayed invisible until
the next live read of each machine. `rematch_all` runs right after a successful update:
for each machine with a stored list (`pkg_inventory`) read in the last
`vulndb.rematch_max_list_age_days`, it matches that list against the new data (code only:
no model, nothing read from or sent to the machine) and publishes the result through the
same path as the detections and the threat-intel hunt (findings engine -> lifecycle ->
triggers -> notify). A finding that is new, came back, or got more severe (a vulnerable
package whose CVE is now known to be exploited) reaches the person's triggers.

What a stored list can't do: say a package was upgraded since it was read. So a
re-matched result never closes a finding (the snapshot source's `closes_findings`), and
every finding it raises says when the list was read.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.pkgvuln import inventory_store
from kratos.pkgvuln import settings as S
from kratos.target_key import target_key

logger = logging.getLogger(__name__)

CATEGORY = "packages"
RULES = ("PKG-001", "PKG-002", "PKG-003")
NEWS = ("new", "recurred", "reopened", "worse")


@dataclass
class MachineResult:
    machine: str
    list_age_days: float
    status: str                      # "matched" | "skipped_old" | "error"
    detail: str = ""
    news: list[dict[str, Any]] = field(default_factory=list)   # findings new/back/worse this time
    fired: list[dict[str, Any]] = field(default_factory=list)


def rematch_all(data_dir: Path | str, *, notifier: Any = None, investigate_fn: Any = None,
                now: float | None = None) -> list[MachineResult]:
    """Match every machine's stored package list against the current data and publish
    the results. Never raises for one machine -- its error is recorded and the rest run."""
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    max_age = int(settings_store.get(S.REMATCH_MAX_LIST_AGE_DAYS, data_dir=data_dir))
    out: list[MachineResult] = []
    for machine in inventory_store.machines(data_dir):
        row = inventory_store.latest(data_dir, machine)
        if row is None:
            continue
        age = max(0.0, (now - row.last_seen_at) / 86400)
        if age > max_age:
            out.append(MachineResult(machine, age, "skipped_old",
                                     f"its package list is {age:.0f} days old -- run a package check of it"))
            continue
        try:
            out.append(_one(data_dir, machine, age, now, notifier, investigate_fn))
        except Exception as exc:          # one machine's failure must not stop the others
            logger.exception("re-matching the stored package list of %s failed", machine)
            out.append(MachineResult(machine, age, "error", f"{type(exc).__name__}: {exc}"[:300]))
    return out


def _one(data_dir: Path, machine: str, age: float, now: float, notifier: Any,
         investigate_fn: Any) -> MachineResult:
    from kratos import run_context
    from kratos.adapters.findings_engine import _apply_lifecycle, _package_findings, finding_dict
    from kratos.agent.trigger_eval import evaluate_triggers
    from kratos.pkgvuln import record

    key = target_key(machine)
    with run_context.run_scope("trigger", target=key):
        doc = record.rematch(data_dir, key, now=now)
        if doc is None:
            return MachineResult(machine, age, "error", "no stored package list")
        findings = [finding_dict(f) for f in _package_findings(doc)]
        annotated, _summary = _apply_lifecycle(findings, data_dir=data_dir, target=key,
                                               inputs={CATEGORY: Path(doc["file"])}, auth_stats=None,
                                               patterns_stats=None, snapshots={CATEGORY: doc})
        news = [f for f in annotated if f.get("id") in RULES and f.get("change") in NEWS]
        fired: list[dict[str, Any]] = []
        if news:
            kwargs: dict[str, Any] = {}
            if notifier is not None:
                kwargs["notifier"] = notifier
            if investigate_fn is not None:
                kwargs["investigate_fn"] = investigate_fn
            fired = evaluate_triggers(data_dir, news, key, **kwargs)
    return MachineResult(machine, age, "matched", record.summary_line(doc), news, fired)


def report_lines(results: list[MachineResult]) -> list[str]:
    """Plain lines for the CLI: what the new data changed, per machine."""
    lines: list[str] = []
    for r in results:
        if r.status == "skipped_old":
            lines.append(f"{r.machine}: not matched again -- {r.detail}")
        elif r.status == "error":
            lines.append(f"{r.machine}: could not be matched again -- {r.detail}")
        elif not r.news:
            lines.append(f"{r.machine}: nothing new (package list read {_age(r.list_age_days)})")
        else:
            lines.append(f"{r.machine}: {len(r.news)} new or more severe (package list read {_age(r.list_age_days)}):")
            for f in sorted(r.news, key=lambda f: _RANK.get(str(f.get("severity")), 0), reverse=True)[:8]:
                why = {"worse": "more severe", "reopened": "back", "recurred": "back"}.get(str(f.get("change")), "new")
                lines.append(f"  [{str(f.get('severity', '')).upper()}] {f.get('title')} ({why})")
            if len(r.news) > 8:
                lines.append(f"  ... and {len(r.news) - 8} more (`kratos findings`)")
        for fire in r.fired:
            lines.append(f"  trigger '{fire.get('trigger')}' fired")
    return lines


_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _age(days: float) -> str:
    if days * 1440 < 2:
        return "just now"
    if days < 1 / 24:
        return f"{days * 1440:.0f} min ago"
    if days < 1:
        return f"{days * 24:.0f} h ago"
    return f"{days:.0f} day(s) ago"

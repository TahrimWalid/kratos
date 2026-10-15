"""The two collection checks (A.0 §5.3): `persistence` and `persistence_verify`.

A.1 adds no tool to the model's list (docs/phaseA/README.md §4.1/§4.2): Kratos
reads the persistence locations itself, as part of collection, and the model
reasons over the digest line and the PERSIST-* findings `correlate_findings`
raises from the saved snapshot.

- `persistence` (quick) -- the inventory: measured at 1-2 s per lab machine over
  SSH, so it fits the start budget; re-read when its result is over an hour old.
- `persistence_verify` (slow) -- the same read plus asking the package manager
  whether the files it owns still match what it installed (`dpkg --verify`,
  `rpm -V`, `apk audit`). That is the slow part, so it runs in the standard
  audit, in schedules and on demand, never before an interactive investigation.
"""
from __future__ import annotations

from typing import Any

from kratos import settings_store
from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.persist import record
from kratos.settings_store import SettingError, SettingSpec

VERIFY_PACKAGES = "persist.verify_packages"


def _on_off(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("on", "yes", "true", "1"):
        return True
    if text in ("off", "no", "false", "0"):
        return False
    raise SettingError("on or off")


settings_store.register(SettingSpec(
    VERIFY_PACKAGES, True, _on_off,
    "In the full audit, ask the package manager whether the files it installed still match what it shipped."))


def _run(ctx: CheckContext, *, verify: bool) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target, verify=verify)
    if doc.get("status") != "ok":
        return CheckResult("failed", "could not be checked",
                           ["where someone could keep access: could not be checked"],
                           detail=str(doc.get("observation") or "")[:300])
    # the short lines (record.answer_gaps): they become the answer's "not checked" NOTE
    gaps = [f"persistence: {g}" for g in doc.get("answer_gaps", doc.get("coverage_gaps")) or []]
    status = "ok" if doc.get("complete") and not gaps else "partial"
    if verify and doc.get("verify", {}).get("requested") and not doc.get("verify", {}).get("done"):
        status = "partial"
        gaps.append("persistence: the package manager could not verify its own files"
                    + (f" ({doc['verify'].get('error')})" if doc["verify"].get("error") else ""))
    return CheckResult(status, record.summary_line(doc), gaps, tools=[],
                       detail=f"{doc.get('file')}")


def _run_persistence(ctx: CheckContext) -> CheckResult:
    return _run(ctx, verify=False)


def _run_persistence_verify(ctx: CheckContext) -> CheckResult:
    if not settings_store.get(VERIFY_PACKAGES, data_dir=ctx.data_dir):
        return CheckResult("skipped", "turned off in Settings", detail=f"{VERIFY_PACKAGES} is off")
    return _run(ctx, verify=True)


register(Check(
    name="persistence", cost="quick", ttl_setting="collect.ttl.persistence_minutes", default_ttl_minutes=60,
    run=_run_persistence, inputs=("persistence",), transports=frozenset({"ssh", "agent"}),
    budget_seconds=40.0, label="where someone could keep access", order=50, short="persistence"))
register(Check(
    name="persistence_verify", cost="slow", ttl_setting="collect.ttl.persistence_verify_minutes",
    default_ttl_minutes=1440, run=_run_persistence_verify, inputs=("persistence",),
    transports=frozenset({"ssh", "agent"}), budget_seconds=300.0,
    label="files changed since their package installed them", order=90, short="package files"))

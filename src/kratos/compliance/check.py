"""The `hardening` collection check (E.2 §5.1): read the machine's hardening facts and
evaluate Kratos's compliance checks over them and the reads Kratos already has. Quick
(one fixed script, about a second); fresh for twelve hours by default. It runs after
the reads whose facts it reuses, when the same collection runs them."""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.compliance import record
from kratos.compliance import settings as _settings  # noqa: F401 -- registers compliance.* settings


def _run(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    gaps = [f"compliance: {g}" for g in doc.get("coverage_gaps") or []]
    if any("too old for the hardening read" in g for g in gaps) and not doc.get("read_at_epoch"):
        return CheckResult("not_supported", "not available for this machine", gaps, detail=str(doc.get("file")))
    status = "ok" if doc.get("complete") and not gaps else "partial"
    return CheckResult(status, record.summary_line(doc), gaps, detail=str(doc.get("file")))


register(Check(
    name="hardening", cost="quick", ttl_setting="collect.ttl.hardening_minutes", default_ttl_minutes=720,
    run=_run, inputs=("compliance",), transports=frozenset({"ssh", "agent"}), budget_seconds=60.0,
    label="hardening against CIS / ISO 27001 / NIS2", order=65, short="hardening",
    after=("config_audit", "persistence", "packages", "privileged_accounts", "log_integrity", "live_response")))

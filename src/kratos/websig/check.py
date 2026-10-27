"""The `web_signals` collection check: web-server worker crash bursts and PHP served to
the network without package-check coverage. Runs after the reads it judges (log sync,
the package list, the running-process read) and reads nothing itself."""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.websig import record


def _run(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    gaps = [f"web server: {g}" for g in doc.get("coverage_gaps") or []]
    return CheckResult("ok" if doc.get("complete") else "partial", record.summary_line(doc), gaps,
                       detail=str(doc.get("file")))


register(Check(
    name="web_signals", cost="quick", ttl_setting="collect.ttl.web_signals_minutes", default_ttl_minutes=10,
    run=_run, inputs=("web_signals",), transports=frozenset({"ssh", "agent", "local"}), budget_seconds=20.0,
    label="web server crashes and PHP exposure", order=74, short="web", after=("log_sync", "packages", "live_response")))

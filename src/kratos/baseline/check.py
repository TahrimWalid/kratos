"""The `baseline` collection check (E.3 §3.11): after log sync, the running-process read and
the detection pass, learn what's new and judge it against what's normal. Reads nothing from
the machine itself (only what Kratos already stored)."""
from __future__ import annotations

from kratos.baseline import record
from kratos.collect.registry import Check, CheckContext, CheckResult, register


def _run(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    gaps = [f"what's normal: {g}" for g in doc.get("coverage_gaps") or []]
    return CheckResult("ok" if doc.get("complete") else "partial", record.summary_line(doc), gaps,
                       detail=str(doc.get("file")))


register(Check(
    name="baseline", cost="quick", ttl_setting="collect.ttl.baseline_minutes", default_ttl_minutes=10,
    run=_run, inputs=("baseline",), transports=frozenset({"ssh", "agent", "local"}), budget_seconds=30.0,
    label="what's normal here", order=74, short="normal", after=("log_sync", "live_response", "detect")))

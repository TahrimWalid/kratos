"""The collection check (A.0 §5.3): `live_response`.

A.5 adds no tool to the model's list (docs/phaseA/README.md §4.1/§4.2): Kratos
reads what is running itself, as part of collection, and the model reasons over
the digest line and the LIVE-* findings `correlate_findings` raises from the
saved snapshot.

`live_response` is a quick check (one /proc walk, measured at ~1 s on a lab
machine over SSH), re-read when its result is over an hour old.
"""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.live import record


def _run_live_response(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    if doc.get("status") != "ok":
        return CheckResult("failed", "could not be checked",
                           ["what is running right now: could not be checked"],
                           detail=str(doc.get("observation") or "")[:300])
    # the short lines (record.answer_gaps): they become the answer's "not checked" NOTE --
    # the restart-needed hint is not one of them
    gaps = [f"live response: {g}" for g in doc.get("answer_gaps", doc.get("coverage_gaps")) or []]
    status = "ok" if doc.get("complete") and not gaps else "partial"
    return CheckResult(status, record.summary_line(doc), gaps, tools=[], detail=f"{doc.get('file')}")


register(Check(
    name="live_response", cost="quick", ttl_setting="collect.ttl.live_response_minutes", default_ttl_minutes=60,
    run=_run_live_response, inputs=("live_response",), transports=frozenset({"ssh", "agent"}),
    budget_seconds=40.0, label="what is running right now", order=45, short="live response"))

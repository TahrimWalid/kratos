"""The `hash_reputation` collection check (E.4 §3.9): look up the reputation of the
executables the persistence and running-process reads found. A slow check (it reads
files on the machine): it runs in the full audit, schedules and on demand, after those
two reads, and its result stays fresh for six hours by default."""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.hashdb import record


def _run(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    gaps = [f"file reputation: {g}" for g in doc.get("answer_gaps") or []]
    return CheckResult("ok" if doc.get("complete") and not gaps else "partial", record.summary_line(doc), gaps,
                       detail=str(doc.get("file")))


register(Check(
    name="hash_reputation", cost="slow", ttl_setting="collect.ttl.hash_reputation_minutes", default_ttl_minutes=360,
    run=_run, inputs=("hash_reputation",), transports=frozenset({"ssh", "agent"}), budget_seconds=200.0,
    label="what the programs on the machine are known to be", order=92, short="file reputation",
    after=("persistence", "live_response")))

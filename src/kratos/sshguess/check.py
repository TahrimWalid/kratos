"""The `ssh_guess` collection check: after log sync stores this machine's sign-in events,
look for a login from an address that was guessing passwords (CORR-SSH-002). Reads
nothing from the machine itself."""
from __future__ import annotations

from kratos.collect.registry import Check, CheckContext, CheckResult, register
from kratos.sshguess import record


def _run(ctx: CheckContext) -> CheckResult:
    doc = record.run(ctx.data_dir, ctx.target)
    gaps = [f"sign-ins after guessing: {g}" for g in doc.get("coverage_gaps") or []]
    return CheckResult("ok" if doc.get("complete") else "partial", record.summary_line(doc), gaps,
                       detail=str(doc.get("file")))


register(Check(
    name="ssh_guess", cost="quick", ttl_setting="collect.ttl.ssh_guess_minutes", default_ttl_minutes=10,
    run=_run, inputs=("ssh_guess",), transports=frozenset({"ssh", "agent", "local"}), budget_seconds=20.0,
    label="logins after password guessing", order=73, short="guess+login", after=("log_sync",)))

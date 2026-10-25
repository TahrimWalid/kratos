"""The `detect` collection check: run the detection rules over what log sync just stored.

Runs after `log_sync` in the same collection (Check.after), entirely on this host --
it reads the event store and writes detections and a snapshot for the findings
engine. Nothing is sent to the machine and no model is called. Its one-line summary
reaches the model's first-turn digest: Kratos-written words, rule ids and counts only.
"""
from __future__ import annotations

import time

from kratos.collect.registry import Check, CheckContext, CheckResult, register

SCHEDULE_NOTE = "rules run on the logs Kratos collected (on schedule, not continuously)"


def _run_detect(ctx: CheckContext) -> CheckResult:
    from kratos.detect import own
    from kratos.detect import run as detect_run

    if ctx.transport == "ssh" and own.audited(ctx.data_dir, ctx.target):   # only where auditd records programs
        try:
            own.read_current_session(ctx.target, ctx.data_dir)   # so Kratos's own reads are never matches
        except Exception:  # noqa: BLE001 -- the logs still tell Kratos's logins apart once synced
            pass
    report = detect_run.run_pass(ctx.target, ctx.data_dir, deadline=ctx.deadline - 1.0)
    if report.status == "failed":
        reason = "; ".join(p.reason for p in report.packs if p.reason)[:300]
        return CheckResult("failed", "could not be checked", ["detection rules: could not be checked"],
                           detail=reason)
    rules_hit = sorted({m["rule_id"] for m in report.matches})
    parts = [SCHEDULE_NOTE]
    try:
        from kratos.detect import live as L

        watch = L.watch_line(ctx.data_dir, ctx.target)    # C.2: Kratos-written, counts only
    except Exception:  # noqa: BLE001
        watch = None
    if watch:
        parts.append(watch)
    if report.matches:
        shown = ", ".join(rules_hit[:6]) + (f" (+{len(rules_hit) - 6} more)" if len(rules_hit) > 6 else "")
        parts.append(f"{len(report.matches)} new match(es) of {len(rules_hit)} rule(s): {shown}")
    else:
        parts.append(f"no new matches in {report.events:,} new log event(s)")
    if report.own_events:
        parts.append(f"{report.own_events:,} of them Kratos's own commands, set aside")
    gaps: list[str] = []
    unchecked = [f"{c.label} ({c.rules})" for c in report.coverage if c.state == "not_checked"]
    partial = [f"{c.label} ({c.rules}): {c.note.split(' -- ')[0].split('; the rest')[0]}" for c in report.coverage
               if c.state == "partial"]
    if unchecked or partial:
        from kratos import settings_store
        from kratos.detect import settings as DS

        days = settings_store.get(DS.COVERAGE_DAYS, data_dir=ctx.data_dir)
        if unchecked:
            gaps.append(f"detection rules with no log to read on this machine in the last {days} days: "
                        + ", ".join(unchecked))
        if partial:
            gaps.append("detection rules that could look at only part of their log: " + "; ".join(partial))
    if report.behind:
        parts.append("still catching up on older stored logs")
    for r in report.refused:
        gaps.append("an imported rule pack was refused: " + str(r.get("reason"))[:200])
    status = "partial" if report.status != "ok" or report.behind else "ok"
    return CheckResult(status, "; ".join(parts), gaps,
                       detail=f"{report.events} events, {report.new_detections} new detection events, "
                              f"{time.time() - report.started:.1f}s")


register(Check(
    name="detect", cost="quick", ttl_setting="collect.ttl.detect_minutes", default_ttl_minutes=1,
    run=_run_detect, inputs=("detections",), transports=frozenset({"ssh", "agent", "local"}), budget_seconds=90.0,
    label="detection rules", order=72, short="rules", after=("log_sync",)))

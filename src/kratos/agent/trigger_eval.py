"""A6.4 -- evaluate triggers against a run's findings and fire their actions.

Called after a run produces findings (a scheduled run, or an interactive /run) --
this is the "monitoring" step, riding the existing scheduled cadence, NOT a new
always-on poll loop (design doc §7 "bounded cadence, not LLM-per-poll").

Boundaries this module obeys:

* **Structured matching only.** A trigger matches on a finding's ``id`` /
  ``severity`` -- engine-generated, trustworthy fields -- NEVER on ``evidence``
  (attacker-influenced). ``_matched`` reads no evidence, proven by test.
* **Recommend/notify/read-only actions only (INVARIANT 1).** ``notify`` and
  ``playbook`` are pure (no run at all). ``investigate`` delegates to
  ``scheduled_run.run_headless_investigation``, which strips every approval-gated
  tool and installs a deny-provider, so it can never act on the target. NOTHING
  here dispatches a state-changing tool. Asserted structurally in the tests.
* **Cooldown/dedupe (design doc §7 flapping).** A trigger fires at most once per
  its ``cooldown_minutes`` window, so a persistent condition pages once, not every
  run. The matched signature is recorded for a future fire-on-change refinement.
* **Spending limits (kratos.budget).** A trigger fires at most
  ``budget.trigger_fires_per_day`` times per local day (counted from its own
  fire ledger), with one "limit reached" notification per day; an
  ``investigate`` action runs only while ``budget.trigger_investigations_allowed``
  is on -- otherwise it notifies and says how to turn investigations on.
* **Coverage honesty.** A fired notification is stamped "as of <run time>" -- it
  reflects the moment of that run, never an implied continuous watch.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from kratos.adapters.findings_engine import finding_ids
from kratos.agent import triggers as _triggers
from kratos.agent.scheduled_run import Notifier, _NTFY_BUCKET, _SEVERITY_RANK
from kratos.utils.timeutil import utc_now_iso

InvestigateFn = Callable[[str, Path], dict[str, Any]]
# kratos.lifecycle `change` values that count as news (an expired acceptance reopens)
_NEW_CHANGES = frozenset({"new", "reopened", "recurred"})


def _matched(trigger: "_triggers.Trigger", findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The findings that satisfy the trigger's condition. Reads ONLY id/severity/
    change (structured, engine/lifecycle-generated) -- never evidence."""
    floor = _SEVERITY_RANK.get(trigger.min_severity or "", -1) if trigger.min_severity else None
    out = []
    for f in findings:
        if trigger.finding_id and trigger.finding_id.upper() not in {i.upper() for i in finding_ids(f)}:
            continue  # its own id, or one it absorbed (e.g. CORR-001 folded into CORR-SSH-001)
        if floor is not None and _SEVERITY_RANK.get(str(f.get("severity") or "info").lower(), 0) < floor:
            continue
        if getattr(trigger, "only_new_or_reopened", False) and f.get("change") not in _NEW_CHANGES:
            continue  # still open from before (or no lifecycle data): not news
        out.append(f)
    return out


def _cooldown_elapsed(data_dir: Path, trigger: "_triggers.Trigger", now: datetime) -> bool:
    last = _triggers.last_fire_record(data_dir, trigger.name)
    if not last or not last.get("fired_at"):
        return True
    try:
        prev = datetime.fromisoformat(str(last["fired_at"]))
    except ValueError:
        return True
    if prev.tzinfo is None:
        prev = prev.replace(tzinfo=timezone.utc)
    elapsed_min = (now - prev).total_seconds() / 60.0
    return elapsed_min >= trigger.cooldown_minutes


def _worst(findings: list[dict[str, Any]]) -> str:
    worst, rank = "info", -1
    for f in findings:
        s = str(f.get("severity") or "info").lower()
        if _SEVERITY_RANK.get(s, 0) > rank:
            worst, rank = s, _SEVERITY_RANK.get(s, 0)
    return worst


def _investigation_goal(finding: dict[str, Any]) -> str:
    """Build a read-only investigation goal from a finding's STRUCTURED fields
    (id + title, both engine-generated) -- never its evidence, so attacker text in
    a log line can't steer the investigation or a command it might recommend."""
    fid = str(finding.get("id") or "a finding")
    title = str(finding.get("title") or "").strip()
    title_part = f" ({title})" if title else ""
    return (
        f"A '{fid}'{title_part} security finding was detected on the monitored target. "
        "Investigate it READ-ONLY: confirm whether it is real, determine its scope and "
        "source, and recommend response steps for a human. Do not run any state-changing "
        "command; you are only observing and recommending."
    )


def _playbook_text(findings: list[dict[str, Any]]) -> Optional[str]:
    """A compact, recommend-only response-plan summary for the matched findings
    (reuses A6.2's curated build_response_plan; evidence never enters a command)."""
    try:
        from kratos.agent.ir_playbooks import build_response_plan
    except Exception:  # noqa: BLE001
        return None
    lines: list[str] = []
    seen: set[str] = set()
    for f in findings:
        fid = str(f.get("id") or "")
        if fid in seen:
            continue
        seen.add(fid)
        plan = build_response_plan(f)
        if plan is None:
            continue
        lines.append(f"Response plan for {plan.finding_id}:")
        for i, step in enumerate(plan.steps[:4], start=1):
            lines.append(f"  {i}. {step.title}")
        if plan.escalate:
            lines.append(f"  escalate: {plan.escalate[0]}")
    return "\n".join(lines) if lines else None


def evaluate_triggers(
    data_dir: Path,
    findings: list[dict[str, Any]],
    target: str,
    *,
    now: Optional[datetime] = None,
    notifier: Optional[Notifier] = None,
    deliver: bool = True,
    run_investigations: bool = True,
    investigate_fn: Optional[InvestigateFn] = None,
) -> list[dict[str, Any]]:
    """Evaluate every trigger against ``findings`` (from a run on ``target``) and
    fire the matching ones (respecting cooldown). Returns a fire record per fired
    trigger. Never raises for one trigger's failure -- it is recorded and the rest
    still evaluate.

    ``run_investigations=False`` (e.g. a snappy interactive /run) turns an
    ``investigate`` action into a notify that says the deeper look will run on the
    scheduled cadence, instead of blocking on an LLM call inline."""
    now = now or datetime.now(timezone.utc)
    notifier = notifier or _default_notifier()
    if investigate_fn is None:
        from kratos.agent.scheduled_run import run_headless_investigation
        investigate_fn = run_headless_investigation

    budget = _budget_limits(Path(data_dir))
    fired: list[dict[str, Any]] = []
    triggers, _errors = _triggers.list_triggers(data_dir)
    for trigger in triggers:
        try:
            if not trigger.is_valid:
                continue
            if trigger.target and trigger.target != target:
                continue
            matched = _matched(trigger, findings)
            if not matched:
                continue
            if not _cooldown_elapsed(data_dir, trigger, now):
                continue
            if _fires_on_day(data_dir, trigger, now) >= budget.trigger_fires_per_day:
                _cap_reached(data_dir, trigger, now, budget.trigger_fires_per_day, notifier, deliver)
                continue
            record = _fire(data_dir, trigger, matched, target, now, notifier,
                           deliver, run_investigations, investigate_fn,
                           investigations_allowed=budget.trigger_investigations_allowed)
            fired.append(record)
        except Exception as e:  # noqa: BLE001 -- one trigger's failure never sinks the rest
            rec = {"trigger": trigger.name, "fired_at": utc_now_iso(),
                   "action": trigger.action, "error": f"trigger evaluation failed: {e}",
                   "notified": False}
            _triggers.append_fire_record(data_dir, trigger.name, rec)
            fired.append(rec)
    return fired


def _budget_limits(data_dir: Path) -> Any:
    """The spending limits that govern triggers (kratos.budget), read fresh. The
    first read on an upgraded install carries an existing 'investigate' trigger's
    choice over (budget.guard.ensure_upgrade_migration)."""
    from kratos.budget import guard as _budget
    from kratos.budget import limits as _limits

    _budget.ensure_upgrade_migration(data_dir)
    return _limits.read(data_dir)


def _fires_on_day(data_dir: Path, trigger: "_triggers.Trigger", now: datetime) -> int:
    """How many times `trigger` fired on the person's local day containing `now`
    (from its own <name>.fired.jsonl ledger)."""
    from kratos.budget.guard import local_day
    from kratos.utils.timeutil import parse_stored_instant

    today = local_day(now.timestamp(), data_dir)
    count = 0
    for rec in _triggers.read_fire_records(data_dir, trigger.name):
        when = parse_stored_instant(rec.get("fired_at"))
        if when is not None and local_day(when.timestamp(), data_dir) == today:
            count += 1
    return count


def _cap_reached(data_dir: Path, trigger: "_triggers.Trigger", now: datetime, cap: int,
                 notifier: Notifier, deliver: bool) -> None:
    """A trigger at its daily fire limit waits for the next local day; say so ONCE
    per trigger per day (claimed in budget_state, across processes)."""
    if not deliver:
        return
    from kratos.budget.guard import local_day
    from kratos.budget.ledger import BudgetLedger

    day = local_day(now.timestamp(), data_dir)
    if BudgetLedger(data_dir).state_claim(f"notified:trigger_cap:{trigger.name}:{day}"):
        notifier(f"Trigger '{trigger.name}' reached its limit of {cap} fires today and stops firing until "
                 "tomorrow (local time). Change the limit in Settings -> Budget.", "warning")


_INVESTIGATIONS_OFF = (
    "This trigger is set to start a deeper investigation, but triggers may not start investigations "
    "(each one spends model money with nobody watching), so it only notified. To allow it: "
    "Settings -> Budget -> 'Triggers may start investigations'.")


def _build_body(data_dir, trigger, matched, target, now, run_investigations, investigate_fn,
                investigations_allowed: bool = True):
    """The notification body + the investigation (if one was run). Shared by the
    real fire and the side-effect-free preview."""
    matched_ids = sorted({str(f.get("id") or "") for f in matched if f.get("id")})
    worst = _worst(matched)
    stamp = now.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = _alert_text(data_dir, trigger, matched, matched_ids, worst, target, stamp)
    action = trigger.action
    investigation: Optional[dict[str, Any]] = None
    if action == "notify":
        body = header
    elif action == "playbook":
        pb = _playbook_text(matched)
        body = header + (("\n\n" + pb) if pb else "\n\n(no curated response plan for these findings)")
    elif action == "investigate" and not investigations_allowed:
        body = header + "\n\n" + _INVESTIGATIONS_OFF
    elif action == "investigate" and run_investigations:
        investigation = investigate_fn(_investigation_goal(matched[0]), Path(data_dir))
        ans = str(investigation.get("final_answer") or "").strip()
        body = header + "\n\nDeeper investigation (read-only):\n" + (ans[:800] or f"(status: {investigation.get('status')})")
    else:  # investigate action but investigations disabled inline
        body = header + "\n\nA deeper read-only investigation is configured; it will run on the next scheduled run."
    return body, worst, matched_ids, investigation


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ALERT_LINES_MAX = 5


def machine_label(data_dir: Any, target: str) -> str:
    """How a person knows the machine: its sub-agent name when it is paired (with the
    address in brackets), else the address/host Kratos investigates."""
    try:
        from kratos.storage.subagent_store import SubAgentStore

        store = SubAgentStore(Path(data_dir) / "kratos.db")
        link = store.get_link(target)
        row = store.get_target(link["target_id"]) if link else None
        name = str((row or {}).get("name") or "").strip()
        if name and name != target:
            return f"{name} ({target})"
    except Exception:  # noqa: BLE001 -- the label is a nicety; the address always works
        pass
    return target


def _alert_text(data_dir, trigger, matched, matched_ids, worst, target, stamp) -> str:
    """The alert a person reads on their phone: what happened and where first, in plain
    words; then when, what to do next, and only then the trigger and the rule credits
    (a Sigma rule's author goes with every alert it raises -- DRL 1.1). Kratos-written
    words and finding titles only: no machine text, no new personal data (it may travel
    through a public ntfy server)."""
    from kratos import finding_facts, untrusted
    from kratos.detect.findings import credit_line

    label = machine_label(data_dir, target)
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in matched:
        groups.setdefault(str(f.get("id") or ""), []).append(f)
    order = sorted(groups, key=lambda rid: (min(_SEV_RANK.get(str(f.get("severity") or "info").lower(), 9)
                                                for f in groups[rid]), rid))
    lines: list[str] = []
    credits: list[str] = []
    for rid in order:
        same = groups[rid]
        sev = min((str(f.get("severity") or "info").lower() for f in same), key=lambda v: _SEV_RANK.get(v, 9))
        what = untrusted.for_display(finding_facts.describe(same[0]) or rid)[:120]
        n = sum(int((f.get("detection_rule") or {}).get("matches") or 0) for f in same)
        count = f" -- {n} time(s)" if n > 1 else (f" -- {len(same)} findings" if len(same) > 1 else "")
        lines.append(f"- {sev.upper()} {what}{count}")
        credit = next((c for c in (credit_line(f) for f in same) if c), None)
        if credit:
            credits.append(f"{rid}: rule by " + credit.split("rule by ", 1)[-1])
    first = untrusted.for_display(finding_facts.describe(groups[order[0]][0]) or order[0])[:120] if order else "a finding"
    more = f" (+{len(order) - 1} more)" if len(order) > 1 else ""
    shown = lines[:ALERT_LINES_MAX] + ([f"- and {len(lines) - ALERT_LINES_MAX} more"] if len(lines) > ALERT_LINES_MAX else [])
    text = (f"{worst.upper()} on {label}: {first}{more}\n"
            + "\n".join(shown) + "\n"
            + f"When: {stamp}\n"
            + "Next: open Kratos and type /findings (or run: kratos findings show)\n"
            + f"Trigger '{trigger.name}' ({trigger.condition_text}) -- ids: {', '.join(matched_ids) or '(finding)'}")
    if credits:
        text += "\nRules: " + "; ".join(credits)
    return text


def preview_trigger(data_dir: Path, trigger: "_triggers.Trigger",
                    findings: list[dict[str, Any]], target: str,
                    *, now: Optional[datetime] = None) -> dict[str, Any]:
    """What a trigger WOULD do on ``findings`` — no delivery, no persistence, no
    cooldown, no investigation (run_investigations=False). For /trigger test."""
    now = now or datetime.now(timezone.utc)
    matched = _matched(trigger, findings)
    if not matched:
        return {"would_fire": False, "matched_ids": [], "body": None}
    body, worst, ids, _inv = _build_body(data_dir, trigger, matched, target, now,
                                         run_investigations=False, investigate_fn=None,
                                         investigations_allowed=_budget_limits(Path(data_dir))
                                         .trigger_investigations_allowed)
    return {"would_fire": True, "matched_ids": ids, "worst": worst, "body": body}


def _fire(data_dir, trigger, matched, target, now, notifier, deliver,
          run_investigations, investigate_fn, investigations_allowed: bool = True) -> dict[str, Any]:
    stamp = now.isoformat()
    body, worst, matched_ids, investigation = _build_body(
        data_dir, trigger, matched, target, now, run_investigations, investigate_fn,
        investigations_allowed=investigations_allowed)
    ntfy_sev = _NTFY_BUCKET.get(worst, "info")

    delivered = None
    if deliver:
        delivered = notifier(body, ntfy_sev)

    record = {
        "trigger": trigger.name,
        "fired_at": stamp,
        "target": target,
        "action": trigger.action,
        "matched_ids": matched_ids,
        "worst_severity": worst,
        "notified": isinstance(delivered, dict) and delivered.get("status") == "sent",
        "delivered": delivered,
        "investigation_status": (investigation or {}).get("status") if investigation else None,
        "error": None,
    }
    _triggers.append_fire_record(data_dir, trigger.name, record)
    return record


def _default_notifier() -> Notifier:
    from kratos.agent.scheduled_run import _default_notifier as d
    return d

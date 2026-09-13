"""A6.3 -- the headless scheduled-run worker: run a schedule's unit of work with
NO human present, persist a report, then deliver it. This is what a systemd user
timer invokes (via ``kratos scheduled-run <name>``); it is UI-free and returns a
structured result.

The two in-slice guardrails (owner-required, 2026-09-10):

1. **Headless = no human, resolved in two independent layers (INVARIANT 5).**
   - **Belt (covers every tool):** BEFORE anything runs we install a headless
     approval provider that DENIES every prompt, so nothing can ever block, and a
     tool with an OPTIONAL gated sub-step (``run_vuln_scan``'s CVE-DB update,
     ``check_ip_reputation``'s live tier) still runs — the optional prompt is just
     denied, which is that tool's correct default (scan with current DB / cache
     only). So a read-only tool keeps FULL coverage in a scheduled run.
   - **Suspenders (only the genuinely sensitive tools):** we exclude a tool from a
     scheduled run iff its ``requires_approval`` FLAG is True — i.e. its PRIMARY
     action is gated: the built-ins ``run_linux_command`` / ``capture_traffic``
     (local privileged / resource-heavy), and any KEPT tool the user has left on
     "required" (respecting the per-tool auto/required setting — set it to "auto"
     in Settings → Tools and it runs here too). Deliberately NOT the source-scan
     ``tool_reaches_approval`` (which over-excludes the read-only optional-substep
     tools above); the belt already makes those safe. For an agentic preset we
     REMOVE the flagged tools from the registry (the model can't select one); for
     the deterministic audit we FILTER them from the step list. Every excluded
     tool is recorded (``omitted_gated_tools``) with a why+remedy note, never
     silently dropped.
   (MCP uses the stricter source-scan exclusion because it has no deny-provider
   belt — a stdio prompt would hang the transport; a scheduled run has the belt,
   so it can safely keep the optional-substep tools.)
2. **Cloud-cost visibility.** ``active_backend_is_cloud()`` lets the schedule-
   creation UI warn before an agentic preset is scheduled on a paid backend. The
   deterministic audit makes no LLM calls, so it is free regardless.

Delivery is persist-FIRST-then-send (design doc §6 "never lose a report because
delivery failed"): the report is written to disk before any notification, and a
delivery failure is recorded, never raised. A target-unreachable / run-failure
still produces a record AND a notification, so silence never means "all clear".
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Optional

from kratos import kratos_config as _kconfig
from kratos.adapters.findings_engine import write_findings_report
from kratos.agent import schedules as _sched
from kratos.agent import target_lock as _target_lock
from kratos.agent import tools as _tools
from kratos.utils.timeutil import utc_now_iso

# A notifier has send_notification's shape: (message, severity) -> result dict.
Notifier = Callable[[str, str], dict[str, Any]]

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Finding severity -> ntfy severity bucket (mirrors mcp_server's notify mapping).
_NTFY_BUCKET = {"critical": "critical", "high": "critical", "medium": "warning",
                "low": "info", "info": "info"}
_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def active_backend_is_cloud() -> bool:
    """True if the active LLM endpoint is remote (not loopback) -- i.e. an
    agentic scheduled run would spend money unattended. Same detection the
    /usage meter uses."""
    from kratos.llm_config import get_active_llm_base_url

    base = (get_active_llm_base_url() or "").lower()
    return not any(h in base for h in _LOOPBACK_HOSTS)


def _default_notifier(message: str, severity: str) -> dict[str, Any]:
    from kratos.agent.notify import send_notification

    return send_notification(message, severity)


def _extract_findings(transcript: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings from an agentic transcript's correlate_findings steps (same data
    path mcp_server/_collect_session_findings use; reimplemented locally so this
    headless module doesn't import the Rich/console or MCP layers)."""
    out: list[dict[str, Any]] = []
    for step in transcript:
        if step.get("tool") != "correlate_findings":
            continue
        obs = step.get("observation")
        result = obs.get("result") if isinstance(obs, dict) else None
        if isinstance(result, dict) and isinstance(result.get("findings"), list):
            out.extend(result["findings"])
    return out


def _worst_severity(findings: list[dict[str, Any]]) -> Optional[str]:
    worst = None
    worst_rank = -1
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        r = _SEVERITY_RANK.get(sev, 0)
        if r > worst_rank:
            worst_rank, worst = r, sev
    return worst


def _severity_tally(findings: list[dict[str, Any]]) -> dict[str, int]:
    tally: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        tally[sev] = tally.get(sev, 0) + 1
    return tally


def _build_message(*, schedule_name: str, target: str, status: str,
                   findings: list[dict[str, Any]], report_path: Optional[str],
                   error: Optional[str], omitted: Optional[list[str]] = None,
                   jobs: Optional[list[dict[str, Any]]] = None) -> str:
    lines = [f"Scheduled run '{schedule_name}' — target {target}", f"status: {status}"]
    if error:
        lines.append(f"note: {error}")
    if jobs:
        lines.append(f"jobs ({len(jobs)}):")
        for j in jobs:
            jt = j.get("severity_tally") or {}
            found = sum(jt.values())
            lines.append(f"  - {j.get('label')}: {j.get('status')}"
                         + (f", {found} finding(s)" if found else "")
                         + (f" — {j.get('error')}" if j.get("error") else ""))
    if omitted:
        lines.append(
            f"excluded (approval=required, so not run unattended): {', '.join(omitted)}. "
            "Set a tool to 'auto' in Settings → Tools to include it in scheduled runs.")
    if findings:
        tally = _severity_tally(findings)
        order = ("critical", "high", "medium", "low", "info")
        lines.append("findings: " + "  ".join(f"{tally[s]} {s}" for s in order if tally.get(s)))
        top = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")][:5]
        for f in top:
            lines.append(f"  [{str(f.get('severity','')).upper()}] {f.get('id')} — {f.get('title','')}")
    else:
        lines.append("findings: none raised")
    if report_path:
        lines.append(f"report: {report_path}")
    return "\n".join(lines)


def _run_audit(data_dir: Path, gated: set[str]) -> tuple[str, list[dict[str, Any]], list[str], Optional[str]]:
    """Run the standard audit with gated-tool steps filtered out. Returns
    (status, findings, omitted_tools, error)."""
    from kratos.agent.pipeline import run_pipeline, standard_audit_steps

    steps = standard_audit_steps()
    kept = [s for s in steps if s.tool not in gated]
    omitted = [s.tool for s in steps if s.tool in gated]
    outcome = run_pipeline(kept, data_dir)
    status = "completed" if outcome.status == "completed" else "aborted"
    error = None if outcome.status == "completed" else (
        f"required step '{outcome.aborted_on}' did not succeed (target may be unreachable)")
    return status, outcome.findings, omitted, error


def _run_preset_named(preset_name: str, data_dir: Path) -> tuple[str, list[dict[str, Any]], Optional[str]]:
    """Run a named goal preset through the agentic loop with gated tools already
    removed from the registry by the caller. Returns (status, findings, error)."""
    from kratos.agent import presets as _presets
    from kratos.agent.loop import run_agent

    preset = _presets.load_preset(data_dir, preset_name or "")
    if preset is None:
        return "error", [], f"preset '{preset_name}' is missing (was it deleted?)"
    if not preset.is_runnable_tier1:
        return "error", [], preset.unsupported_reason or "preset is not runnable"

    result = run_agent(preset.goal, data_dir)
    status = str(result.get("status") or "error")
    findings = _extract_findings(result.get("transcript", []))
    error = None
    if status in ("error", "llm_unavailable"):
        error = f"agentic run did not complete cleanly (status: {status})"
    return status, findings, error


def _run_preset(schedule: "_sched.Schedule", data_dir: Path) -> tuple[str, list[dict[str, Any]], Optional[str]]:
    return _run_preset_named(schedule.preset or "", data_dir)


_JOB_OK = {"completed", "final_answer", "max_iters_reached"}


def _run_group(schedule: "_sched.Schedule", data_dir: Path, gated: set[str]) -> tuple[
        str, list[dict[str, Any]], list[str], Optional[str], list[dict[str, Any]]]:
    """A6.5 -- run a group's ordered jobs as ONE unit (design doc §8). The caller
    holds the single target lock + the deny-provider belt for the whole group.
    We strip gated tools from the registry ONCE (covers preset jobs) and filter
    audit steps by the same set, so every job is headless-safe. Jobs run in order;
    on a job failure the ``on_failure`` policy decides continue-vs-abort. Returns
    (group_status, union_findings, omitted_tools, error, per_job_records).

    Per-job partial-failure reporting reuses the same record shape as a single
    run (design doc §8 "reuse PipelineOutcome's per-step shape")."""
    excluded = {name: _tools.TOOL_REGISTRY[name] for name in gated}
    for name in excluded:
        del _tools.TOOL_REGISTRY[name]

    union: list[dict[str, Any]] = []
    omitted_all: set[str] = set()
    job_records: list[dict[str, Any]] = []
    any_failed = False
    aborted = False
    try:
        for idx, job in enumerate(schedule.jobs):
            label = schedule.job_label(job, idx)
            if job["kind"] == "audit":
                j_status, j_findings, j_omitted, j_error = _run_audit(data_dir, gated)
            else:  # preset (registry already stripped)
                j_status, j_findings, j_error = _run_preset_named(job.get("preset") or "", data_dir)
                j_omitted = sorted(excluded.keys())
            omitted_all.update(j_omitted)
            union.extend(j_findings)
            ok = j_status in _JOB_OK
            any_failed = any_failed or not ok
            job_records.append({
                "label": label, "kind": job["kind"], "preset": job.get("preset"),
                "status": j_status, "findings_count": len(j_findings),
                "severity_tally": _severity_tally(j_findings), "error": j_error,
            })
            if not ok and schedule.on_failure == "abort":
                aborted = True
                # Mark the remaining jobs skipped so the report is honest.
                for skip in schedule.jobs[idx + 1:]:
                    job_records.append({
                        "label": schedule.job_label(skip, 0), "kind": skip["kind"],
                        "preset": skip.get("preset"), "status": "skipped",
                        "findings_count": 0, "severity_tally": {},
                        "error": "skipped — an earlier job failed and on_failure=abort",
                    })
                break
    finally:
        _tools.TOOL_REGISTRY.update(excluded)

    if aborted:
        status = "aborted"
        error = "a job failed and on_failure=abort — remaining jobs were skipped"
    elif any_failed:
        status = "completed_with_failures"
        error = "one or more jobs failed (on_failure=continue)"
    else:
        status = "completed"
        error = None
    return status, union, sorted(omitted_all), error, job_records


def run_headless_investigation(goal: str, data_dir: Path, *, run_agent_fn=None) -> dict[str, Any]:
    """Run an agentic investigation with NO human present -- the self-contained
    headless guard used by A6.4's ``investigate`` trigger action (design doc §7
    "deeper read-only investigation"). Installs the deny-everything approval
    provider (belt) and removes every ``requires_approval``-flagged tool from the
    registry (suspenders) so a state-changing/approval tool can never be selected,
    then restores both. Read-only + recommend-only by construction: run_agent's
    observe-and-recommend boundary holds and nothing acts on the target.

    Does NOT acquire the target lock -- callers (the scheduled worker, the
    interactive /run worker) already hold it for the surrounding run. Returns
    {status, findings, final_answer}."""
    if run_agent_fn is None:
        from kratos.agent.loop import run_agent as run_agent_fn

    prior_provider = _tools._approval_prompt_provider
    _tools.set_approval_prompt_provider(lambda tool, details: False)
    gated = {name for name, tool in _tools.TOOL_REGISTRY.items() if tool.requires_approval}
    excluded = {name: _tools.TOOL_REGISTRY[name] for name in gated}
    for name in excluded:
        del _tools.TOOL_REGISTRY[name]
    try:
        result = run_agent_fn(goal, data_dir)
    finally:
        _tools.TOOL_REGISTRY.update(excluded)
        _tools.set_approval_prompt_provider(prior_provider)
    return {
        "status": str(result.get("status") or "error"),
        "findings": _extract_findings(result.get("transcript", [])),
        "final_answer": result.get("final_answer"),
    }


def run_scheduled(
    schedule: "_sched.Schedule",
    data_dir: Path,
    *,
    deliver: bool = True,
    notifier: Optional[Notifier] = None,
) -> dict[str, Any]:
    """Execute one scheduled run headlessly and record it. Never raises for an
    operational failure (unreachable target, delivery failure, missing preset);
    those become a recorded + notified result. Returns the run record."""
    notifier = notifier or _default_notifier
    data_dir = Path(data_dir)
    started_at = utc_now_iso()

    # Guardrail 1a: nothing can EVER block on approval in a headless run.
    prior_provider = _tools._approval_prompt_provider
    _tools.set_approval_prompt_provider(lambda tool, details: False)

    # Resolve + pin the target for this run, restore after (like a preset run).
    prior_target = None
    active = _kconfig.get_active_target()
    target = schedule.target or active
    if schedule.target and schedule.target != active:
        prior_target = active
        _kconfig.set_active_target(schedule.target)

    # Concurrency (design doc §6): only one Kratos run may touch a given target at
    # a time. A scheduled run DEFERS to any run already in progress (e.g. an
    # interactive investigation) rather than colliding (interleaved data_dir
    # writes / two SSH sessions) — it records + notifies a 'skipped', never blocks
    # a timer. NON-blocking, keyed by target.
    lock = _target_lock.try_acquire_target(data_dir, target)
    if lock is None:
        _tools.set_approval_prompt_provider(prior_provider)
        if prior_target is not None:
            _kconfig.set_active_target(prior_target)
        record = {
            "schedule": schedule.name, "started_at": started_at,
            "finished_at": utc_now_iso(), "status": "skipped", "target": target,
            "kind": schedule.kind, "findings_count": 0, "severity_tally": {},
            "omitted_gated_tools": [], "report_json": None, "report_md": None,
            "delivered": None, "notified": False,
            "error": f"another Kratos run is active on {target}; deferred to the next scheduled time",
        }
        if deliver and "ntfy" in schedule.deliver:
            record["delivered"] = notifier(
                f"Scheduled run '{schedule.name}' skipped — another run is active on "
                f"{target}. It will run at the next scheduled time.", "info")
            record["notified"] = record["delivered"] is not None
        _sched.append_run_record(data_dir, schedule.name, record)
        return record

    # Guardrail 1b (suspenders): exclude only tools whose PRIMARY action is gated
    # -- the requires_approval FLAG (run_linux_command / capture_traffic, and any
    # kept tool the user left on "required"). NOT the source-scan: a read-only
    # tool with an optional gated sub-step keeps full coverage, protected by the
    # deny-provider belt above. Setting a kept tool to "auto" clears its flag, so
    # it runs here too.
    gated = {name for name, tool in _tools.TOOL_REGISTRY.items()
             if tool.requires_approval}

    findings: list[dict[str, Any]] = []
    omitted: list[str] = []
    status = "error"
    error: Optional[str] = None
    excluded: dict[str, Any] = {}
    job_records: list[dict[str, Any]] = []

    try:
        if not schedule.is_runnable:
            status, error = "error", schedule.unsupported_reason
        elif schedule.kind == "audit":
            status, findings, omitted, error = _run_audit(data_dir, gated)
        elif schedule.kind == "preset":
            # Remove gated tools from the registry so the model can't select one,
            # and record them so a review shows what was unavailable + why.
            excluded = {name: _tools.TOOL_REGISTRY[name] for name in gated}
            omitted = sorted(excluded.keys())
            for name in excluded:
                del _tools.TOOL_REGISTRY[name]
            try:
                status, findings, error = _run_preset(schedule, data_dir)
            finally:
                _tools.TOOL_REGISTRY.update(excluded)
        elif schedule.kind == "group":
            # A6.5: ordered multi-job run under this one lock + deny-provider.
            status, findings, omitted, error, job_records = _run_group(schedule, data_dir, gated)
        else:
            status, error = "error", schedule.unsupported_reason
    except Exception as e:  # noqa: BLE001 -- a run failure must be recorded, not crash the timer
        status, error = "error", f"unexpected error: {e}"
    finally:
        _tools.set_approval_prompt_provider(prior_provider)
        if prior_target is not None:
            _kconfig.set_active_target(prior_target)

    # Persist the report to disk FIRST (never lose it to a delivery failure).
    report_json: Optional[str] = None
    report_md: Optional[str] = None
    try:
        j, m = write_findings_report(data_dir)
        report_json, report_md = str(j), str(m)
    except Exception as e:  # noqa: BLE001 -- a report-write failure shouldn't sink the run record
        error = (error + "; " if error else "") + f"report write failed: {e}"

    # Deliver (persist-first is done). Failure is recorded, never raised. A
    # FAILED run always notifies (silence must never read as 'all clear').
    delivered: Optional[dict[str, Any]] = None
    worst = _worst_severity(findings)
    threshold_met = (
        schedule.min_severity is None or status != "completed"
        or (worst is not None and _SEVERITY_RANK.get(worst, 0)
            >= _SEVERITY_RANK.get(schedule.min_severity, 0))
    )
    if deliver and "ntfy" in schedule.deliver and threshold_met:
        ntfy_sev = _NTFY_BUCKET.get(worst or "info", "info")
        if status != "completed":
            ntfy_sev = "warning"
        message = _build_message(schedule_name=schedule.name, target=target, status=status,
                                 findings=findings, report_path=report_md, error=error,
                                 omitted=omitted, jobs=job_records)
        delivered = notifier(message, ntfy_sev)

    # A6.4: evaluate triggers against this run's structured findings (the
    # monitoring step rides the scheduled cadence). Investigations may run here
    # (this run still holds the target lock). Never sinks the run on failure.
    triggers_fired: list[dict[str, Any]] = []
    try:
        from kratos.agent.trigger_eval import evaluate_triggers
        triggers_fired = evaluate_triggers(data_dir, findings, target,
                                           notifier=notifier, deliver=deliver)
    except Exception as e:  # noqa: BLE001
        error = (error + "; " if error else "") + f"trigger evaluation failed: {e}"

    record = {
        "schedule": schedule.name,
        "started_at": started_at,
        "finished_at": utc_now_iso(),
        "status": status,
        "target": target,
        "kind": schedule.kind,
        "findings_count": len(findings),
        "severity_tally": _severity_tally(findings),
        "omitted_gated_tools": omitted,
        "report_json": report_json,
        "report_md": report_md,
        "delivered": delivered,
        "notified": delivered is not None,
        "triggers_fired": [t.get("trigger") for t in triggers_fired],
        "jobs": job_records,  # A6.5: per-job partial-failure reporting (empty for non-groups)
        "error": error,
    }
    _sched.append_run_record(data_dir, schedule.name, record)
    _target_lock.release_target(lock)  # (also released by the process exiting)
    return record

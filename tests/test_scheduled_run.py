"""Scripted tests for the A6.3 headless worker (agent/scheduled_run.py).

No real SSH/LLM/ntfy: the pipeline dispatcher and run_agent are canned and the
notifier is a spy. These verify the two guardrails (headless approval-gate
exclusion + a deny-provider installed for the run), persist-FIRST-then-deliver,
target-unreachable still notifies, the min_severity threshold, missing-preset
handling, and that the registry / target / approval-provider are all restored.
"""
from __future__ import annotations

import pytest

from kratos.agent import schedules as S
from kratos.agent import scheduled_run as W
from kratos.agent import tools as T


@pytest.fixture(autouse=True)
def _lab_target(monkeypatch):
    """Kratos ships no default target, so these runs name the one they investigate."""
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_HOST", "10.136.28.168")


class _Spy:
    def __init__(self):
        self.calls = []

    def __call__(self, message, severity):
        self.calls.append((message, severity))
        return {"status": "sent", "severity": severity}


def _audit_dispatch(findings=None, fail_nmap=False):
    """A canned execute_tool_call for run_pipeline."""
    def dispatch(tool, args, data_dir):
        if fail_nmap and tool == "run_nmap_scan":
            return {"status": "error", "observation": "target unreachable"}
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings or []}}
        return {"status": "ok", "result": {}}
    return dispatch


def test_audit_run_excludes_gated_and_notifies(tmp_path, monkeypatch):
    sch = S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly", deliver=["ntfy"])
    findings = [{"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed"}]
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _audit_dispatch(findings))
    spy = _Spy()

    rec = W.run_scheduled(sch, tmp_path, notifier=spy)

    assert rec["status"] == "completed"
    assert rec["findings_count"] == 1
    # Guardrail 1 (flag-based): the standard audit's tools are all
    # requires_approval=False (run_vuln_scan's only prompt is the OPTIONAL CVE-DB
    # update, denied by the belt), so NOTHING is excluded -- the scheduled audit
    # keeps full coverage including vuln scanning. Nothing silently dropped.
    assert rec["omitted_gated_tools"] == []
    assert "run_vuln_scan" not in rec["omitted_gated_tools"]
    # Persist-FIRST: a report file exists.
    assert rec["report_md"] and rec["report_json"]
    # Delivered, severity mapped from the HIGH finding.
    assert rec["notified"] is True
    assert spy.calls and spy.calls[0][1] == "critical"
    assert "CORR-SSH-001" in spy.calls[0][0]
    # Recorded in the ledger.
    assert S.last_run_record(tmp_path, "wk")["status"] == "completed"


def test_deny_provider_installed_during_run_and_restored(tmp_path, monkeypatch):
    sch = S.save_schedule(tmp_path, name="prov", kind="audit")
    seen = {}

    def dispatch(tool, args, data_dir):
        # Capture the approval provider active DURING the run.
        seen["provider"] = T._approval_prompt_provider
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": []}}
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", dispatch)
    before = T._approval_prompt_provider
    W.run_scheduled(sch, tmp_path, notifier=_Spy())
    # During the run a provider was installed; it denies by construction.
    assert seen["provider"] is not None
    assert seen["provider"]("run_linux_command", {}) is False
    # Restored afterwards (no leak into other code paths).
    assert T._approval_prompt_provider is before


def test_target_unreachable_still_notifies(tmp_path, monkeypatch):
    sch = S.save_schedule(tmp_path, name="down", kind="audit", deliver=["ntfy"])
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call",
                        _audit_dispatch(fail_nmap=True))
    spy = _Spy()
    rec = W.run_scheduled(sch, tmp_path, notifier=spy)
    assert rec["status"] == "aborted"
    assert rec["error"] and "unreachable" in rec["error"]
    # Silence must never read as "all clear": a failed run still notifies (warning).
    assert rec["notified"] is True and spy.calls[0][1] == "warning"


def test_min_severity_threshold_suppresses_low_only_findings(tmp_path, monkeypatch):
    sch = S.save_schedule(tmp_path, name="quiet", kind="audit", deliver=["ntfy"],
                          min_severity="high")
    findings = [{"id": "NET-001", "severity": "info", "title": "clean"}]
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _audit_dispatch(findings))
    spy = _Spy()
    rec = W.run_scheduled(sch, tmp_path, notifier=spy)
    assert rec["status"] == "completed"
    # No finding >= high, and the run completed, so no notification is sent.
    assert rec["notified"] is False and spy.calls == []


def test_deliver_false_writes_report_but_skips_notify(tmp_path, monkeypatch):
    sch = S.save_schedule(tmp_path, name="silent", kind="audit")
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _audit_dispatch([]))
    spy = _Spy()
    rec = W.run_scheduled(sch, tmp_path, deliver=False, notifier=spy)
    assert rec["report_md"] and rec["notified"] is False and spy.calls == []


def test_preset_run_excludes_gated_from_registry(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    P.save_preset(tmp_path, name="deep", goal="hunt for ssh brute force")
    sch = S.save_schedule(tmp_path, name="nightly", kind="preset", preset="deep",
                          cadence="daily", deliver=["ntfy"])

    seen = {}

    def fake_run_agent(goal, data_dir, **kw):
        # The registry the model sees must have NO approval-gated tool.
        seen["registry"] = set(T.TOOL_REGISTRY.keys())
        return {"status": "final_answer", "final_answer": "done", "transcript": [
            {"tool": "correlate_findings",
             "observation": {"status": "ok", "result": {"findings": [
                 {"id": "CORR-SSH-001", "severity": "high", "title": "x"}]}}}
        ]}

    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_run_agent)
    before = set(T.TOOL_REGISTRY.keys())
    rec = W.run_scheduled(sch, tmp_path, notifier=_Spy())

    assert rec["status"] == "final_answer" and rec["findings_count"] == 1
    # No gated tool was visible to the model during the run.
    assert "run_linux_command" not in seen["registry"]
    assert "capture_traffic" not in seen["registry"]
    # ...and they're RECORDED (never silently dropped) with a why+remedy note.
    assert "run_linux_command" in rec["omitted_gated_tools"]
    assert "capture_traffic" in rec["omitted_gated_tools"]
    # Registry fully restored afterwards.
    assert set(T.TOOL_REGISTRY.keys()) == before


def test_scheduled_run_defers_when_target_busy(tmp_path, monkeypatch):
    """A6 §6 concurrency: if another run holds the target lock, a scheduled run
    SKIPS (records + notifies), never collides or blocks the timer."""
    from kratos.agent import target_lock as L
    from kratos import kratos_config

    sch = S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly", deliver=["ntfy"])
    target = sch.target or kratos_config.get_active_target()
    held = L.try_acquire_target(tmp_path, target)
    assert held is not None
    spy = _Spy()
    try:
        rec = W.run_scheduled(sch, tmp_path, notifier=spy)
    finally:
        L.release_target(held)

    assert rec["status"] == "skipped"
    assert "active on" in (rec["error"] or "")
    assert rec["notified"] is True           # a skip is visible; silence != all-clear
    assert S.last_run_record(tmp_path, "wk")["status"] == "skipped"


def test_missing_preset_is_recorded_not_crashed(tmp_path, monkeypatch):
    sch = S.save_schedule(tmp_path, name="orphan", kind="preset", preset="gone",
                          deliver=["ntfy"])
    spy = _Spy()
    rec = W.run_scheduled(sch, tmp_path, notifier=spy)
    assert rec["status"] == "error"
    assert "missing" in (rec["error"] or "")
    assert rec["notified"] is True  # a dangling preset still tells the human


def test_active_backend_is_cloud_detection(monkeypatch):
    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url",
                        lambda: "https://generativelanguage.googleapis.com/v1")
    assert W.active_backend_is_cloud() is True
    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url",
                        lambda: "http://127.0.0.1:11434/v1")
    assert W.active_backend_is_cloud() is False


# --------------------------------------------------------------------------- #
# A2 Tier 2 interlock -- a kind="pipeline" preset runs headless (schedule+group)
# --------------------------------------------------------------------------- #
def _pipeline_dispatch(findings=None, fail_nmap=False):
    """Canned execute_tool_call recording call order, for pipeline-preset runs."""
    calls: list[str] = []

    def dispatch(tool, args, data_dir):
        calls.append(tool)
        if fail_nmap and tool == "run_nmap_scan":
            return {"status": "error", "observation": "target unreachable"}
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings or []}}
        return {"status": "ok", "result": {}}

    return dispatch, calls


def test_pipeline_preset_scheduled_runs_via_engine(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    P.save_preset(tmp_path, name="sweep", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True},
    ])
    sch = S.save_schedule(tmp_path, name="nightly-pipe", kind="preset", preset="sweep",
                          cadence="daily", deliver=["ntfy"])
    findings = [{"id": "CORR-SSH-001", "severity": "high", "title": "x"}]
    dispatch, calls = _pipeline_dispatch(findings)
    # A pipeline preset dispatches through run_pipeline's execute_tool_call, NOT
    # run_agent -- so make run_agent explode to prove the deterministic path is used.
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", dispatch)
    monkeypatch.setattr("kratos.agent.loop.run_agent",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("run_agent must not run for a pipeline preset")))

    rec = W.run_scheduled(sch, tmp_path, notifier=_Spy())

    assert rec["status"] == "completed"
    assert rec["findings_count"] == 1
    assert calls == ["run_nmap_scan", "correlate_findings"]  # deterministic, in order


def test_pipeline_preset_required_step_abort_notifies(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    P.save_preset(tmp_path, name="sweep", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True},
    ])
    sch = S.save_schedule(tmp_path, name="np", kind="preset", preset="sweep",
                          cadence="daily", deliver=["ntfy"])
    dispatch, _ = _pipeline_dispatch(fail_nmap=True)
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", dispatch)
    spy = _Spy()

    rec = W.run_scheduled(sch, tmp_path, notifier=spy)

    assert rec["status"] == "aborted"
    assert rec["error"] and "aborted" in rec["error"]
    assert rec["notified"] is True and spy.calls[0][1] == "warning"


def test_valid_when_pipeline_preset_runs_headless(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    # Slice 4: a VALID bounded `when` runs headless. The condition is false
    # (no HIGH finding), so the gated step SKIPS, and the run still completes.
    P.save_preset(tmp_path, name="cond", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "run_vuln_scan", "required": False, "when": "has_finding(min_severity='high')"},
        {"tool": "correlate_findings", "required": True},
    ])
    sch = S.save_schedule(tmp_path, name="csched", kind="preset", preset="cond",
                          cadence="daily", deliver=["ntfy"])
    calls = []

    def dispatch(tool, args, data_dir):
        calls.append(tool)
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": []}}  # no HIGH -> when skips vuln
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", dispatch)
    rec = W.run_scheduled(sch, tmp_path, notifier=_Spy())

    assert rec["status"] == "completed"
    # The conditional step was SKIPPED (no HIGH finding existed when it was reached).
    assert calls == ["run_nmap_scan", "correlate_findings"]


def test_invalid_when_pipeline_preset_declined_not_crashed(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    # A pipeline with an INVALID `when` predicate is a structural error -> not
    # runnable -> the headless worker DECLINES it with a reason, never crashes.
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "bad.toml").write_text(
        'name = "bad"\nkind = "pipeline"\n'
        '[[steps]]\ntool = "run_nmap_scan"\n'
        '[[steps]]\ntool = "run_config_audit"\nwhen = "__import__(\'os\')"\n',
        encoding="utf-8")
    sch = S.save_schedule(tmp_path, name="bsched", kind="preset", preset="bad",
                          cadence="daily", deliver=["ntfy"])
    spy = _Spy()

    rec = W.run_scheduled(sch, tmp_path, notifier=spy)

    assert rec["status"] == "error"
    assert rec["error"] and "invalid" in rec["error"].lower()
    assert rec["notified"] is True  # a failed run always notifies


def test_pipeline_preset_in_group_runs(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    P.save_preset(tmp_path, name="sweep", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True},
    ])
    findings = [{"id": "CORR-001", "severity": "medium", "title": "y"}]
    dispatch, _ = _pipeline_dispatch(findings)
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", dispatch)
    sch = S.save_schedule(
        tmp_path, name="grp", kind="group", cadence="daily", deliver=["ntfy"],
        jobs=[{"kind": "audit"}, {"kind": "preset", "preset": "sweep"}],
        on_failure="continue")

    rec = W.run_scheduled(sch, tmp_path, notifier=_Spy())

    assert rec["status"] == "completed"
    # Two jobs recorded; the pipeline preset job completed.
    assert len(rec["jobs"]) == 2
    preset_job = [j for j in rec["jobs"] if j["kind"] == "preset"][0]
    assert preset_job["status"] == "completed"


def test_headless_refuses_ungraduated_generated_pipeline_then_runs(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    # An AI-drafted (generated=True) pipeline must NOT run unattended until a
    # human has acknowledged it live (graduating it to generated=False).
    P.save_preset(tmp_path, name="ai", kind="pipeline", generated=True, steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True}])
    sch = S.save_schedule(tmp_path, name="aisched", kind="preset", preset="ai",
                          cadence="daily", deliver=["ntfy"])

    dispatch, calls = _pipeline_dispatch([{"id": "X", "severity": "low"}])
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", dispatch)
    spy = _Spy()

    rec = W.run_scheduled(sch, tmp_path, notifier=spy)
    assert rec["status"] == "error"
    assert rec["error"] and "hasn't been confirmed" in rec["error"]
    assert calls == []                      # nothing dispatched
    assert rec["notified"] is True          # a refused run still notifies

    # Graduate it (as an accepted interactive confirm would), then it schedules.
    P.save_preset(tmp_path, name="ai", kind="pipeline", generated=False, steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True}])
    rec2 = W.run_scheduled(sch, tmp_path, notifier=_Spy())
    assert rec2["status"] == "completed"
    assert calls == ["run_nmap_scan", "correlate_findings"]


@pytest.mark.parametrize("outcome", ["not_configured", "refused", "failed"])
def test_an_unsent_notification_is_not_reported_as_notified(tmp_path, monkeypatch, outcome):
    """The run record said "notified: yes" whenever delivery was attempted, even
    with no ntfy topic set up."""
    from kratos.tui_mk2 import render as R

    sch = S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly", deliver=["ntfy"])
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _audit_dispatch(
        [{"id": "NET-002", "severity": "medium", "title": "ports"}]))
    rec = W.run_scheduled(sch, tmp_path, notifier=lambda msg, sev: {"status": outcome})
    assert rec["notified"] is False
    from rich.console import Console

    console = Console(width=120, record=True)
    console.print(R.scheduled_run_result_panel(rec))
    assert "notified: no (" in console.export_text()

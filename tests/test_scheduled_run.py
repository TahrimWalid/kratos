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

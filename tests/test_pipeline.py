"""Scripted tests for the PreA2 deterministic engine (agent/pipeline.py).

No real SSH/LLM: a canned `dispatch` stands in for `execute_tool_call` (mirroring
how test_execute_tool_call_guards.py swaps tool handlers), so these verify the
engine's own control flow -- ordering, fail-fast on required steps, resilience on
optional ones, finding threading, the `when` conditional seam, and the standard-
audit step list's target-correctness.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from kratos.agent.pipeline import (
    PipelineStep,
    PipelineContext,
    run_pipeline,
    standard_audit_steps,
)


def _ok(result=None):
    return {"status": "ok", "result": result or {}}


def _err(msg="boom"):
    return {"status": "error", "observation": msg}


def _canned(script):
    """Build a dispatch that returns script[tool] (a dict), recording call order
    into `calls`. Missing tool -> ok with empty result."""
    calls: list[str] = []

    def dispatch(tool, args, data_dir):
        calls.append(tool)
        return script.get(tool, _ok())

    return dispatch, calls


DATA_DIR = Path("/tmp/kratos-pipeline-test")  # never actually written (canned dispatch)


def test_all_steps_ok_completes_and_threads_findings():
    findings = [{"id": "NET-001", "severity": "high", "title": "t"}]
    dispatch, calls = _canned({
        "run_nmap_scan": _ok({"open_ports": 1}),
        "correlate_findings": _ok({"findings": findings, "count": 1}),
    })
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("correlate_findings", required=True),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)

    assert outcome.status == "completed"
    assert calls == ["run_nmap_scan", "correlate_findings"]
    assert outcome.ran == 2
    assert outcome.findings == findings
    assert outcome.severity_tally == {"high": 1}


def test_required_step_failure_fail_fasts():
    dispatch, calls = _canned({"run_nmap_scan": _err("target unreachable")})
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("run_config_audit", required=False),
        PipelineStep("correlate_findings", required=True),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)

    assert outcome.status == "aborted"
    assert outcome.aborted_on == "run_nmap_scan"
    # Nothing after the aborting required step runs (single transaction).
    assert calls == ["run_nmap_scan"]
    assert outcome.steps[0].status == "error"
    assert outcome.steps[0].detail == "target unreachable"


def test_optional_step_failure_continues():
    dispatch, calls = _canned({
        "run_nmap_scan": _ok(),
        "run_config_audit": _err("ssh denied"),
        "correlate_findings": _ok({"findings": []}),
    })
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("run_config_audit", required=False),
        PipelineStep("correlate_findings", required=True),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)

    assert outcome.status == "completed"
    assert calls == ["run_nmap_scan", "run_config_audit", "correlate_findings"]
    # The optional failure is recorded, not swallowed.
    assert [s.status for s in outcome.steps] == ["ok", "error", "ok"]


def test_not_approved_on_optional_step_continues():
    dispatch, _ = _canned({
        "run_nmap_scan": _ok(),
        "some_gated_tool": {"status": "not_approved", "observation": "declined"},
        "correlate_findings": _ok({"findings": []}),
    })
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("some_gated_tool", required=False),
        PipelineStep("correlate_findings", required=True),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert outcome.status == "completed"
    assert outcome.steps[1].status == "not_approved"


def test_when_predicate_skips_step():
    dispatch, calls = _canned({"run_nmap_scan": _ok(), "run_vuln_scan": _ok()})
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("run_vuln_scan", required=True, when=lambda ctx: False),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)

    assert outcome.status == "completed"  # a skipped step is not a failure
    assert calls == ["run_nmap_scan"]      # the skipped tool never dispatched
    assert outcome.steps[1].status == "skipped"


def test_when_predicate_sees_prior_findings():
    seen = {}
    high = [{"id": "CORR-001", "severity": "high"}]
    dispatch, calls = _canned({
        "correlate_findings": _ok({"findings": high}),
        "run_vuln_scan": _ok(),
    })

    def gate(ctx: PipelineContext) -> bool:
        seen["has_high"] = ctx.has_finding(min_severity="high")
        seen["has_critical"] = ctx.has_finding(min_severity="critical")
        return ctx.has_finding(min_severity="high")

    steps = [
        PipelineStep("correlate_findings", required=True),
        PipelineStep("run_vuln_scan", required=False, when=gate),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)

    assert seen == {"has_high": True, "has_critical": False}
    assert "run_vuln_scan" in calls  # gate passed (a HIGH finding existed)
    assert outcome.status == "completed"


def test_on_step_called_once_per_step_in_order():
    dispatch, _ = _canned({"run_nmap_scan": _ok(), "correlate_findings": _ok({"findings": []})})
    seen: list[tuple[str, str]] = []
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("correlate_findings", required=True),
    ]
    run_pipeline(steps, DATA_DIR, dispatch=dispatch,
                 on_step=lambda sr: seen.append((sr.tool, sr.status)))
    assert seen == [("run_nmap_scan", "ok"), ("correlate_findings", "ok")]


def test_standard_audit_is_target_correct():
    steps = standard_audit_steps()
    tools = [s.tool for s in steps]

    # Target-facing tools only -- the cmd_run §6.2 host-confusion bug is
    # structurally impossible here because the LOCAL tools are absent.
    assert "parse_auth_log" not in tools
    assert "collect_system_context" not in tools

    # The essential spine is present and required; the extras are resilient.
    assert tools[0] == "run_nmap_scan"
    assert tools[-1] == "correlate_findings"
    by_tool = {s.tool: s for s in steps}
    assert by_tool["run_nmap_scan"].required is True
    assert by_tool["correlate_findings"].required is True
    assert by_tool["run_vuln_scan"].required is False
    assert by_tool["run_config_audit"].required is False
    assert by_tool["read_journalctl"].required is False
    # Every step is a real, resolvable label.
    assert all(s.label for s in steps)


def test_default_dispatch_is_execute_tool_call_and_rejects_unknown_tool():
    # No injected dispatch -> the real execute_tool_call runs. A bogus tool name
    # returns a registry error WITHOUT any SSH/LLM, so this cheaply proves the
    # engine is wired to the real dispatcher and fail-fasts on a required error.
    steps = [PipelineStep("this_tool_does_not_exist", required=True)]
    outcome = run_pipeline(steps, DATA_DIR)
    assert outcome.status == "aborted"
    assert outcome.aborted_on == "this_tool_does_not_exist"
    assert outcome.steps[0].status == "error"
    assert "not a real tool" in (outcome.steps[0].detail or "")

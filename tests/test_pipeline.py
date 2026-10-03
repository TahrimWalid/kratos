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
    LOCAL_HOST_TOOLS,
    PipelineStep,
    PipelineContext,
    is_local_host_tool,
    run_pipeline,
    standard_audit_steps,
    steps_from_specs,
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


# --------------------------------------------------------------------------- #
# A2 Tier 2 -- local/target classification + spec->PipelineStep conversion
# --------------------------------------------------------------------------- #
def test_local_host_tool_classification():
    # The four Kratos-host tools (Piece D target-correctness source of truth).
    for t in ("parse_auth_log", "collect_system_context", "capture_traffic", "run_linux_command"):
        assert is_local_host_tool(t) is True
        assert t in LOCAL_HOST_TOOLS
    # Target-facing / host-agnostic tools are NOT local.
    for t in ("run_nmap_scan", "read_journalctl", "correlate_findings", "run_config_audit"):
        assert is_local_host_tool(t) is False


def test_steps_from_specs_builds_pipeline_steps():
    specs = [
        {"tool": "run_nmap_scan", "required": True, "label": "ports", "args": {"a": 1}},
        {"tool": "run_vuln_scan", "required": False},
    ]
    steps = steps_from_specs(specs)
    assert [s.tool for s in steps] == ["run_nmap_scan", "run_vuln_scan"]
    assert steps[0].required is True and steps[0].label == "ports" and steps[0].args == {"a": 1}
    assert steps[1].required is False
    # No `when` -> plain linear steps.
    assert all(s.when is None for s in steps)


def test_steps_from_specs_when_becomes_conditional_marker():
    steps = steps_from_specs([{"tool": "run_config_audit", "when": "has_finding()"}])
    # A `when` spec produces a non-None marker so a preview flags it conditional;
    # it is never executed (a when-bearing preset is blocked from running upstream).
    assert steps[0].when is not None


def test_steps_from_specs_compiles_when_into_real_predicate():
    from kratos.agent.pipeline import PipelineContext
    steps = steps_from_specs([{"tool": "run_vuln_scan", "when": "has_finding(min_severity='high')"}])
    pred = steps[0].when
    assert pred is not None
    assert pred(PipelineContext(data_dir=DATA_DIR, findings=[{"severity": "high"}])) is True
    assert pred(PipelineContext(data_dir=DATA_DIR, findings=[{"severity": "low"}])) is False


def test_run_pipeline_compiled_when_skips_and_runs():
    # A real compiled predicate gates a step on a prior step's findings.
    high = [{"id": "CORR-001", "severity": "high"}]
    dispatch, calls = _canned({
        "correlate_findings": _ok({"findings": high}),
        "run_vuln_scan": _ok(),
    })
    steps = steps_from_specs([
        {"tool": "correlate_findings", "required": True},
        {"tool": "run_vuln_scan", "required": False, "when": "has_finding(min_severity='high')"},
    ])
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert outcome.status == "completed"
    assert "run_vuln_scan" in calls  # a HIGH finding existed -> the gated step ran

    # Now with no HIGH finding: the gated step skips.
    dispatch2, calls2 = _canned({"correlate_findings": _ok({"findings": []}), "run_vuln_scan": _ok()})
    steps2 = steps_from_specs([
        {"tool": "correlate_findings", "required": True},
        {"tool": "run_vuln_scan", "required": True, "when": "has_finding(min_severity='high')"},
    ])
    outcome2 = run_pipeline(steps2, DATA_DIR, dispatch=dispatch2)
    assert outcome2.status == "completed"        # a skipped required step is NOT a failure
    assert "run_vuln_scan" not in calls2
    assert outcome2.steps[1].status == "skipped"


def test_run_pipeline_when_that_raises_is_failsafe_skip():
    # A predicate that throws at run time -> the step is SKIPPED (fail-safe),
    # recorded with a reason, and the run continues -- never crashes.
    def boom(_ctx):
        raise RuntimeError("kaboom")

    dispatch, calls = _canned({"run_nmap_scan": _ok(), "correlate_findings": _ok({"findings": []})})
    steps = [
        PipelineStep("run_nmap_scan", required=True),
        PipelineStep("run_vuln_scan", required=True, when=boom),
        PipelineStep("correlate_findings", required=True),
    ]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert outcome.status == "completed"
    assert "run_vuln_scan" not in calls
    skipped = outcome.steps[1]
    assert skipped.status == "skipped" and "fail-safe" in (skipped.detail or "")


# --------------------------------------------------------------------------- #
# A2 Piece C -- output threading through the engine
# --------------------------------------------------------------------------- #
def test_run_pipeline_threads_output_into_later_step():
    captured = {}

    def dispatch(tool, args, data_dir):
        if tool == "correlate_findings":
            return _ok({"findings": [{"id": "CORR-SSH-001", "severity": "high",
                                      "source_ips": ["203.0.113.7"]}]})
        if tool == "check_ip_reputation":
            captured["ip"] = args.get("ip")
            return _ok({"source": "none"})
        return _ok()

    steps = steps_from_specs([
        {"tool": "correlate_findings", "label": "correlate", "required": True},
        {"tool": "check_ip_reputation", "required": False,
         "args": {"ip": {"from": "correlate", "field": "top_source_ip"}}},
    ])
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert outcome.status == "completed"
    assert captured["ip"] == "203.0.113.7"          # a real value was threaded, not the ref dict


def test_run_pipeline_failsafe_skips_consumer_when_producer_has_no_value():
    captured = {}

    def dispatch(tool, args, data_dir):
        if tool == "correlate_findings":
            return _ok({"findings": [{"id": "NET-002", "severity": "medium"}]})  # no source_ips
        if tool == "check_ip_reputation":
            captured["ran"] = True
            return _ok()
        return _ok()

    steps = steps_from_specs([
        {"tool": "correlate_findings", "label": "correlate", "required": True},
        {"tool": "check_ip_reputation", "required": True,
         "args": {"ip": {"from": "correlate", "field": "top_source_ip"}}},
    ])
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert outcome.status == "completed"            # a fail-safe skip is not a failure
    assert "ran" not in captured                    # consumer never dispatched with a bad value
    assert outcome.steps[1].status == "skipped"
    assert "no 'top_source_ip'" in (outcome.steps[1].detail or "")


# ---- a tool that ran but reported failure (2026-10-03) ----------------------


def test_a_tool_reporting_error_is_a_failed_step_not_a_pass():
    dispatch, calls = _canned({
        "read_journalctl": _ok({"status": "error", "observation": "journalctl over SSH failed: timeout"}),
        "run_vuln_scan": _ok({"status": "error", "errors": ["vulscan: x", "nuclei: y"], "findings": []}),
    })
    steps = [PipelineStep("read_journalctl", required=False), PipelineStep("run_vuln_scan", required=False),
             PipelineStep("correlate_findings", required=True)]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert [s.status for s in outcome.steps] == ["error", "error", "ok"]
    assert outcome.steps[0].detail == "journalctl over SSH failed: timeout"
    assert outcome.steps[1].detail == "vulscan: x; nuclei: y"
    assert outcome.status == "completed"


def test_a_required_tool_reporting_error_aborts():
    dispatch, calls = _canned({"run_nmap_scan": _ok({"status": "error", "observation": "nmap not found"})})
    outcome = run_pipeline([PipelineStep("run_nmap_scan"), PipelineStep("correlate_findings")], DATA_DIR,
                           dispatch=dispatch)
    assert outcome.status == "aborted" and calls == ["run_nmap_scan"]


def test_a_deliberate_coverage_refusal_is_skipped_and_the_audit_goes_on():
    """A box reached only through its sub-agent can't be port-scanned: that step is
    skipped with its reason, and the reads that do work still run."""
    gap = {"status": "error", "observation": "network scan not available for edge-03",
           "coverage_gap": "network exposure (open ports/services)"}
    dispatch, calls = _canned({"run_nmap_scan": _ok(gap)})
    outcome = run_pipeline(standard_audit_steps(), DATA_DIR, dispatch=dispatch)
    assert outcome.steps[0].status == "skipped" and "network scan not available" in outcome.steps[0].detail
    assert outcome.status == "completed" and calls[-1] == "correlate_findings"


def test_raw_scan_rows_are_not_threaded_as_findings():
    raw = [{"source": "vulscan", "port": 22, "cve_ids": ["CVE-2023-1"]}]
    seen = {}
    dispatch, _ = _canned({"run_vuln_scan": _ok({"status": "ok", "findings": raw})})
    steps = [PipelineStep("run_vuln_scan"),
             PipelineStep("check_ip_reputation", when=lambda ctx: seen.setdefault("f", list(ctx.findings)) or True)]
    outcome = run_pipeline(steps, DATA_DIR, dispatch=dispatch)
    assert seen["f"] == [] and outcome.findings == []

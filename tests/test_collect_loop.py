"""run_agent with collection: the digest, the seeded correlation (Guards 1/3/4), coverage
gaps, and the re-correlation by code. The model and the target are scripted; the loop,
its guards and execute_tool_call run unmodified."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from kratos import kratos_config
from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY, Tool
from kratos.collect.runner import CheckOutcome, CollectionReport
from tests.test_agent_loop_guards import (
    CORRECTED_ANSWER, HIGH_FINDING, MOCK_STALENESS_WARNING,
    RAW_OBSERVATIONS_ANSWER, TIMEFRAME_CLAIM_ANSWER, TIMEFRAME_CORRECTED_ANSWER, _final_json, _tool_json,
)

TARGET = "10.0.0.5"
CLEAN_DISMISSIVE = "No suspicious activity was detected; the system appears secure."


class Chat:
    def __init__(self, responses: list[str]) -> None:
        self.responses, self.systems, self.users = list(responses), [], []

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        self.systems.append(system_prompt)
        self.users.append(user_prompt)
        if not self.responses:
            raise AssertionError("scripted model ran out of replies")
        return self.responses.pop(0)


def make_report(findings=None, *, stale=None, gaps=(), correlated=True) -> CollectionReport:
    now = time.time()
    outcome = CheckOutcome(
        name="ports", label="open ports", cost="quick", status="ok", source="ran",
        summary="1 open port(s): 22/tcp ssh", finished_at=now, age_seconds=0.0, tools=["run_nmap_scan"],
        inputs=("nmap_parsed",), gaps=list(gaps),
        steps=[{"tool": "run_nmap_scan", "args": {}, "observation": {"status": "ok", "result": {"open_ports_total": 1}}}])
    corr = {"findings": list(findings or []), "staleness_warning": stale} if correlated else None
    return CollectionReport(
        target=TARGET, target_key=TARGET, transport="ssh", checks=[outcome], correlation=corr,
        correlation_step={"tool": "correlate_findings", "args": {},
                          "observation": {"status": "ok", "result": corr}} if corr else None,
        started=now, finished=now + 1, budget_seconds=15)


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    for sub in ("scans", "logs", "context", "reports", "baseline"):
        (d / sub).mkdir(parents=True)
    kratos_config.set_active_target(TARGET)
    return d


@pytest.fixture
def collected(monkeypatch):
    """Install a collection report the loop will find at the start of the run."""
    def install(report):
        monkeypatch.setattr(agent_loop, "_collect_first", lambda dd, ss: report)
    return install


def run(data_dir, chat, monkeypatch, goal="check this system"):
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    return agent_loop.run_agent(goal, data_dir, max_iters=8)


# ----------------------------------------------------------------------------- the digest
def test_the_model_starts_from_the_digest(data_dir, collected, monkeypatch):
    collected(make_report([HIGH_FINDING]))
    chat = Chat([_final_json(CORRECTED_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    first = chat.users[0]
    assert "WHAT KRATOS ALREADY CHECKED ON 10.0.0.5" in first
    assert first.index("Investigation goal:") < first.index("WHAT KRATOS ALREADY CHECKED")
    assert "CORR-SSH-001 (high)" in first
    assert "WHAT KRATOS ALREADY CHECKED" in chat.systems[0]          # the one added sentence
    assert result["status"] == "final_answer"


def test_without_collection_the_prompt_is_unchanged(data_dir, monkeypatch):
    chat = Chat([_tool_json("correlate_findings"), _final_json(CORRECTED_ANSWER)])
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **kw: {"findings": [], "staleness_warning": None})
    run(data_dir, chat, monkeypatch)
    assert "ALREADY CHECKED" not in chat.users[0] and "ALREADY CHECKED" not in chat.systems[0]
    assert chat.systems[0] == agent_loop.build_system_prompt("check this system")


def test_the_transcript_records_the_digest_and_what_was_collected(data_dir, collected, monkeypatch):
    collected(make_report([HIGH_FINDING]))
    result = run(data_dir, Chat([_final_json(CORRECTED_ANSWER)]), monkeypatch)
    tx = result["transcript"]
    assert tx[0]["status"] == "collection" and "WHAT KRATOS ALREADY CHECKED" in tx[0]["digest"]
    assert tx[0]["summary_line"].startswith("Checked first: ")
    collected_steps = [s for s in tx if s.get("collected")]
    assert [s["tool"] for s in collected_steps] == ["run_nmap_scan", "correlate_findings"]


# ----------------------------------------------------------------------------- Guard 1 is satisfied by code
def test_guard1_is_satisfied_by_the_seeded_correlation(data_dir, collected, monkeypatch):
    collected(make_report([]))
    chat = Chat([_final_json(RAW_OBSERVATIONS_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    assert len(chat.users) == 1 and result["status"] == "final_answer"
    assert not [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]


def test_guard1_still_fires_when_no_correlation_succeeds(data_dir, collected, monkeypatch):
    """Collection could not correlate, and the by-code retry at conclusion fails too: the answer
    is still held to Guard 1 (a real error is fed back; the model retries)."""
    collected(make_report(correlated=False))
    calls = []

    def flaky(**kw):
        calls.append(1)
        if len(calls) == 1:
            return {"status": "error", "observation": "disk full"}
        return {"findings": [], "staleness_warning": None}

    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", flaky)
    chat = Chat([_final_json(RAW_OBSERVATIONS_ANSWER), _tool_json("correlate_findings"),
                 _final_json(RAW_OBSERVATIONS_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and "missing_correlation" in rejected[0]["violations"]
    assert len(calls) == 2                                           # by code (failed), then the model's own


def test_the_same_answer_without_collection_is_rejected_by_guard1(data_dir, monkeypatch):
    chat = Chat([_final_json(RAW_OBSERVATIONS_ANSWER), _tool_json("correlate_findings"),
                 _final_json(RAW_OBSERVATIONS_ANSWER)])
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **kw: {"findings": [], "staleness_warning": None})
    result = run(data_dir, chat, monkeypatch)
    assert [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]


# ----------------------------------------------------------------------------- Guards 3 and 4 judge the seeded findings
def test_guard3_fires_on_a_seeded_high_finding(data_dir, collected, monkeypatch):
    collected(make_report([HIGH_FINDING]))
    chat = Chat([_final_json(CLEAN_DISMISSIVE), _final_json(CORRECTED_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and "dismissive_verdict_contradiction" in rejected[0]["violations"]
    assert "CORR-SSH-001" in result["final_answer"]


def test_guard3_stays_quiet_when_the_seeded_findings_are_not_high(data_dir, collected, monkeypatch):
    collected(make_report([{**HIGH_FINDING, "severity": "info"}]))
    result = run(data_dir, Chat([_final_json(CLEAN_DISMISSIVE)]), monkeypatch)
    assert not [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]


def test_guard4_fires_on_a_seeded_staleness_warning(data_dir, collected, monkeypatch):
    collected(make_report([], stale=MOCK_STALENESS_WARNING))
    chat = Chat([_final_json(TIMEFRAME_CLAIM_ANSWER), _final_json(TIMEFRAME_CORRECTED_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and "staleness_timeframe_contradiction" in rejected[0]["violations"]


# ----------------------------------------------------------------------------- coverage gaps
def test_a_check_gap_is_named_in_the_answer(data_dir, collected, monkeypatch):
    gap = "network exposure (open ports/services) of 10.0.0.5 was not checked -- it is reached only through its sub-agent"
    collected(make_report([], gaps=[gap]))
    result = run(data_dir, Chat([_final_json(RAW_OBSERVATIONS_ANSWER)]), monkeypatch)
    assert "[NOTE:" in result["final_answer"] and "network exposure" in result["final_answer"]


# ----------------------------------------------------------------------------- re-correlation by code
@pytest.fixture
def refresh_tool(monkeypatch, data_dir):
    def handler(data_dir: Path) -> dict[str, Any]:
        f = Path(data_dir) / "scans" / f"parsed_{time.time_ns()}.json"
        f.write_text(json.dumps({"target": TARGET, "hosts": []}))
        return {"status": "ok", "wrote": str(f)}

    monkeypatch.setitem(TOOL_REGISTRY, "t_refresh", Tool(
        name="t_refresh", description="writes a scan", handler=handler,
        parameters={"data_dir": {"type": "path", "description": "d"}}))


def counting_correlate(monkeypatch, findings):
    calls = []

    def handler(**kw):
        calls.append(1)
        return {"findings": findings, "staleness_warning": None}

    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", handler)
    return calls


def test_new_data_is_correlated_by_code_before_the_guards_judge_the_answer(
        data_dir, collected, monkeypatch, refresh_tool):
    collected(make_report([]))
    calls = counting_correlate(monkeypatch, [HIGH_FINDING])          # what the refreshed data now shows
    chat = Chat([_tool_json("t_refresh"), _final_json(CLEAN_DISMISSIVE), _final_json(CORRECTED_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    assert calls == [1], "correlate_findings should have run exactly once, by code"
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and "dismissive_verdict_contradiction" in rejected[0]["violations"]
    by_code = [s for s in result["transcript"] if s.get("collected") and s.get("iteration", 0) > 0]
    assert len(by_code) == 1 and by_code[0]["tool"] == "correlate_findings"


def test_no_data_change_means_no_second_correlation(data_dir, collected, monkeypatch):
    collected(make_report([]))
    calls = counting_correlate(monkeypatch, [HIGH_FINDING])
    run(data_dir, Chat([_final_json(RAW_OBSERVATIONS_ANSWER)]), monkeypatch)
    assert calls == []


def test_a_correlation_the_model_ran_after_the_refresh_is_not_repeated(
        data_dir, collected, monkeypatch, refresh_tool):
    collected(make_report([]))
    calls = counting_correlate(monkeypatch, [])
    chat = Chat([_tool_json("t_refresh"), _tool_json("correlate_findings"), _final_json(RAW_OBSERVATIONS_ANSWER)])
    run(data_dir, chat, monkeypatch)
    assert calls == [1]                                              # the model's own, nothing extra


def test_without_collection_nothing_is_correlated_behind_the_models_back(data_dir, monkeypatch, refresh_tool):
    calls = counting_correlate(monkeypatch, [])
    chat = Chat([_tool_json("t_refresh"), _final_json(RAW_OBSERVATIONS_ANSWER), _tool_json("correlate_findings"),
                 _final_json(RAW_OBSERVATIONS_ANSWER)])
    run(data_dir, chat, monkeypatch)
    assert calls == [1]                                              # only the one the model made after Guard 1 asked


# ----------------------------------------------------------------------------- when collection does not run
def test_collection_is_skipped_for_the_kratos_host_and_when_off(data_dir, monkeypatch):
    from kratos import collect

    called = []
    monkeypatch.delenv("KRATOS_COLLECT", raising=False)
    monkeypatch.setattr("kratos.collect.runner.prepare", lambda *a, **k: called.append(1))
    kratos_config.set_active_target("127.0.0.1")
    assert agent_loop._collect_first(data_dir, None) is None and not called          # /investigate-host
    kratos_config.set_active_target(TARGET)
    monkeypatch.setenv("KRATOS_COLLECT", "off")
    assert collect.forced_off() and agent_loop._collect_first(data_dir, None) is None and not called


def test_a_collection_that_crashes_never_stops_the_investigation(data_dir, monkeypatch):
    monkeypatch.delenv("KRATOS_COLLECT", raising=False)

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr("kratos.collect.runner.prepare", boom)
    assert agent_loop._collect_first(data_dir, None) is None


def test_stop_before_collection_stops_the_run(data_dir, monkeypatch):
    monkeypatch.delenv("KRATOS_COLLECT", raising=False)
    monkeypatch.setattr("kratos.collect.runner.prepare", lambda *a, **k: pytest.fail("must not collect after Stop"))
    with pytest.raises(agent_loop.InvestigationStopped):
        agent_loop._collect_first(data_dir, lambda: True)


# ----------------------------------------------------------------------------- the frozen tool list
FROZEN_LISTED_TOOLS = frozenset({
    "check_file_integrity", "check_ip_reputation", "collect_system_context", "compare_periods", "correlate_findings",
    "list_open_files", "list_privileged_accounts", "list_processes", "measure_auth_activity", "parse_auth_log",
    "read_host_logs", "read_journalctl", "run_config_audit", "run_nmap_scan", "run_vuln_scan", "run_yara_scan",
    "send_notification", "state_as_of",
})


def test_the_models_tool_list_is_frozen():
    """The tools the investigating model is shown (remote target) are exactly this set. Adding one, or
    changing what the model sees, needs the tool-selection eval (docs/phaseA/README.md §4.2) with no
    regression -- and then this set updated on purpose. New detection reads are collection checks."""
    import re

    kratos_config.set_active_target(TARGET)
    prompt = agent_loop.build_system_prompt("anything")
    section = prompt[prompt.index("AVAILABLE TOOLS:"):prompt.index("LOCAL HOST VS. MONITORED TARGET")]
    builtin = {n for n, t in TOOL_REGISTRY.items() if t.handler.__module__ == "kratos.agent.tools"}
    listed = frozenset(re.findall(r"^- ([a-z_]+):", section, re.M)) & builtin     # kept (self-written) tools come on top
    assert listed == FROZEN_LISTED_TOOLS, (sorted(listed - FROZEN_LISTED_TOOLS), sorted(FROZEN_LISTED_TOOLS - listed))


def test_the_goal_regex_is_gone():
    assert not hasattr(agent_loop, "_HOST_LOGS_GOAL_RE") and not hasattr(agent_loop, "goal_unlisted_tools")


def test_a_check_that_finishes_in_the_background_is_settled_before_the_answer(data_dir, collected, monkeypatch):
    """The investigation started while 'what is running right now' was still running; it
    finished before the answer, so its 'still running' gap is gone from the answer."""
    from kratos.collect.runner import STILL_RUNNING, _Pending

    report = make_report([HIGH_FINDING])
    running = CheckOutcome(name="live_response", label="what is running right now", cost="quick", status="running",
                           source="background", summary=STILL_RUNNING,
                           gaps=[f"what is running right now: {STILL_RUNNING}"])
    report.checks.append(running)
    pend = _Pending(check=type("C", (), {"name": "live_response"})())
    pend.final = CheckOutcome(name="live_response", label="what is running right now", cost="quick", status="ok",
                              source="ran", summary="40 running process(es) checked; nothing unusual")
    pend.recorded.set()
    report.pending.append(pend)
    collected(report)
    chat = Chat([_final_json(CORRECTED_ANSWER)])
    result = run(data_dir, chat, monkeypatch)
    assert STILL_RUNNING not in result["final_answer"]
    assert any(s.get("status") == "collection_settled" for s in result["transcript"])

"""
DEPRECATED (2026-09-06): superseded by the durable Sprint 4 eval harness
(~/kratos_eval_artifacts/) -- it measures the same tool-selection/detection
behavior on the same backend + target far more thoroughly, and is the current
source of truth. Kept opt-in (still excluded from bare `pytest`) as a small
standalone smoke check; not re-baselined against gemini-3.1-flash-lite.

Repeatable test-scenario suite for the Kratos ReAct agent loop
(agent/loop.py + agent/tools.py) -- so tool-selection behavior can be
verified with real assertions instead of manually eyeballing transcripts
every time a prompt or tool changes.

These are integration tests: they invoke the REAL agent loop against a REAL
LLM backend and the REAL configured target (nothing mocked), so each one can
take anywhere from ~1-2 minutes (Gemini, via the openai_compatible backend --
KRATOS_LLM_BACKEND was renamed from openai_fallback on 2026-07-15, see
CLAUDE.md's "LLM backend refactor") to ~10-20 minutes (local qwen2.5:7b via
Ollama), and results can vary run to run since the model's exact tool
choices aren't deterministic. Assertions below are deliberately loose where
the underlying behavior is legitimately allowed to vary (e.g. "at least N
distinct tools" rather than an exact set), and any known-flaky check is
called out in that scenario's `notes`.

Run (excluded from a bare `pytest` run -- opt in explicitly):

    # Fast pass -- validates the test harness/assertions themselves, not the
    # local model. Requires .env with LLM_BASE_URL/LLM_API_KEY/LLM_MODEL set
    # to real Gemini values for this invocation only, not left in .env (see
    # docs/llm_configuration.md).
    KRATOS_LLM_BACKEND=openai_compatible pytest tests/agent_scenarios.py -m agent_llm -v -s

    # Slow pass -- the real target combo. Local runs are expensive: pick a
    # subset with -k rather than running all 6 by default. LLM_MODEL
    # defaults to qwen2.5:7b (see llm_config.py); override only if that's
    # not the model actually pulled.
    pytest tests/agent_scenarios.py -m agent_llm -v -s \\
        -k "scenario_1 or scenario_3 or scenario_6"
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

REPO_ROOT = Path(__file__).parent.parent
RUNNER_SCRIPT = Path(__file__).parent / "_agent_runner.py"
DEFAULT_MAX_ITERS = 10
SUBPROCESS_TIMEOUT_SECONDS = 1800  # 30 min hard ceiling per scenario

# Tools that don't represent a distinct "investigation category" on their
# own (synthesis/action tools rather than data-collection ones) -- excluded
# from the min_distinct_tools breadth check so it measures actual coverage
# breadth, not call count.
_NON_CATEGORY_TOOLS = {"correlate_findings", "send_notification", "run_linux_command"}


@dataclass
class Scenario:
    id: str
    goal: str
    min_tools: set[str] = field(default_factory=set)                 # ALL must appear at least once
    min_tools_any_of: list[set[str]] = field(default_factory=list)   # at least one full set must be satisfied
    excluded_tools: set[str] = field(default_factory=set)            # none of these may appear
    min_distinct_tools: int = 0                                      # breadth check, see _NON_CATEGORY_TOOLS
    answer_contains_any: list[str] = field(default_factory=list)     # case-insensitive substring, >=1 must match
    custom_check: Callable[[list[dict], dict], list[str]] | None = None
    notes: str = ""
    max_iters: int = DEFAULT_MAX_ITERS


@dataclass
class ScenarioResult:
    scenario_id: str
    goal: str
    passed: bool
    failures: list[str]
    tools_called: list[str]
    transcript: list[dict]
    final_status: str
    final_answer: str | None
    wall_clock_seconds: float


def _hallucination_recovery_check(transcript: list[dict], result: dict) -> list[str]:
    """
    Custom check for scenario 6. Whether the model actually attempts a
    hallucinated file path is non-deterministic -- if it never happens,
    that's a fine outcome (nothing to recover from) and this passes
    trivially. If it DOES happen, verify the system caught it with a clear
    rejection (not a silent substitution -- see agent/tools.py's
    correlate_findings path-existence check) and that the run still reached
    a real conclusion afterward instead of getting stuck.
    """
    failures: list[str] = []
    hallucination_attempts = []

    for step in transcript:
        if step.get("tool") != "correlate_findings":
            continue
        args = step.get("args") or {}
        file_args = {k: v for k, v in args.items() if k.endswith("_file") and v}
        if not file_args:
            continue
        obs_text = json.dumps(step.get("observation") or {}).lower()
        if "does not exist" in obs_text or "do not exist" in obs_text:
            hallucination_attempts.append(step)

    if not hallucination_attempts:
        return failures  # nothing to recover from this run -- fine

    for step in hallucination_attempts:
        obs_text = json.dumps(step.get("observation")).lower()
        if "do not guess" not in obs_text:
            failures.append(
                f"Hallucinated file path at iteration {step.get('iteration')} was not clearly "
                f"rejected with corrective guidance: {step.get('observation')}"
            )

    status = result.get("status")
    if status not in ("final_answer", "max_iters_reached"):
        failures.append(f"Run did not reach a real conclusion after a hallucination attempt (status={status})")
    if status == "max_iters_reached" and not result.get("final_answer"):
        failures.append("Hit max_iters with no fallback answer after a hallucination attempt")

    return failures


SCENARIOS: list[Scenario] = [
    Scenario(
        id="scenario_1_suspicious_activity",
        goal="check for suspicious activity on this system",
        min_tools={"collect_system_context", "parse_auth_log", "run_nmap_scan"},
        notes="Baseline phrasing -- was already reliable before the num_ctx fix.",
    ),
    Scenario(
        id="scenario_2_break_in",
        goal="has anyone tried to break in",
        min_tools={"parse_auth_log"},
        notes=(
            "The original wording-sensitivity failure case: this phrasing used to never call "
            "run_nmap_scan at all. We deliberately do NOT hard-assert run_nmap_scan here -- "
            "'at least considered' is softer than 'called', and the model's own judgment that "
            "it isn't needed for a narrowly-auth-focused goal is a legitimate outcome, not a "
            "bug. The test prints whether it was called as an informational note instead."
        ),
    ),
    Scenario(
        id="scenario_3_full_security_check",
        goal="run a full security check",
        min_distinct_tools=4,
        notes=(
            "Was the actively failing case pre-num_ctx-fix (hit max_iters_reached with "
            "hallucinated tool names in 2 of 3 runs). Breadth check rather than a fixed tool "
            "set, since the INVESTIGATION SCOPE prompt guidance intentionally lets the model "
            "skip categories it judges irrelevant rather than forcing blind exhaustiveness."
        ),
    ),
    Scenario(
        id="scenario_4_is_my_server_okay",
        goal="is my server okay",
        min_distinct_tools=3,
        notes="Phrasing never used to tune the prompt -- tests generalization, not memorization.",
    ),
    Scenario(
        id="scenario_5_whats_listening",
        goal="what's listening on the network",
        min_tools_any_of=[{"run_nmap_scan"}, {"list_open_files"}],
        excluded_tools={"parse_auth_log"},
        notes="Narrow goal -- should not need authentication logs at all.",
    ),
    Scenario(
        id="scenario_6_hallucination_recovery",
        goal="Generate a findings report and summarize the security posture of this system.",
        custom_check=_hallucination_recovery_check,
        notes=(
            "Goal phrasing emphasizes 'findings report' (maps to correlate_findings by name) "
            "without emphasizing step-by-step data collection first -- designed to tempt an "
            "early correlate_findings call before real data exists, mirroring the hallucination "
            "seen organically in original testing. Non-deterministic by design: if the model "
            "just does the right thing without ever hallucinating, the check passes trivially."
        ),
    ),
]


def run_scenario(scenario: Scenario, data_dir: Path) -> ScenarioResult:
    t0 = time.time()
    proc = subprocess.run(
        [sys.executable, str(RUNNER_SCRIPT), scenario.goal, str(data_dir), str(scenario.max_iters)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
    )
    elapsed = time.time() - t0

    marker = "===SCENARIO_RESULT_JSON==="
    if marker not in proc.stdout:
        return ScenarioResult(
            scenario_id=scenario.id, goal=scenario.goal, passed=False,
            failures=[
                f"Runner produced no result JSON (exit code {proc.returncode}).\n"
                f"stdout tail:\n{proc.stdout[-2000:]}\nstderr tail:\n{proc.stderr[-1000:]}"
            ],
            tools_called=[], transcript=[], final_status="runner_error", final_answer=None,
            wall_clock_seconds=elapsed,
        )

    result: dict[str, Any] = json.loads(proc.stdout.split(marker, 1)[1].strip())
    transcript: list[dict] = result.get("transcript", [])
    tools_called = [step["tool"] for step in transcript if step.get("tool")]

    failures: list[str] = []

    missing = scenario.min_tools - set(tools_called)
    if missing:
        failures.append(f"Missing required tool(s): {sorted(missing)}")

    if scenario.min_tools_any_of and not any(
        alt_set.issubset(set(tools_called)) for alt_set in scenario.min_tools_any_of
    ):
        failures.append(
            f"None of the acceptable tool sets were satisfied: "
            f"{[sorted(s) for s in scenario.min_tools_any_of]} (got: {sorted(set(tools_called))})"
        )

    unexpected = set(tools_called) & scenario.excluded_tools
    if unexpected:
        failures.append(f"Called excluded tool(s): {sorted(unexpected)}")

    if scenario.min_distinct_tools:
        distinct_category_tools = set(tools_called) - _NON_CATEGORY_TOOLS
        if len(distinct_category_tools) < scenario.min_distinct_tools:
            failures.append(
                f"Expected at least {scenario.min_distinct_tools} distinct category tools, "
                f"got {len(distinct_category_tools)}: {sorted(distinct_category_tools)}"
            )

    final_answer = result.get("final_answer")
    if scenario.answer_contains_any:
        haystack = (final_answer or "").lower()
        if not any(needle.lower() in haystack for needle in scenario.answer_contains_any):
            failures.append(f"Final answer matched none of {scenario.answer_contains_any}. Got: {final_answer!r}")

    if scenario.custom_check:
        failures.extend(scenario.custom_check(transcript, result))

    return ScenarioResult(
        scenario_id=scenario.id, goal=scenario.goal, passed=not failures, failures=failures,
        tools_called=tools_called, transcript=transcript,
        final_status=result.get("status", "unknown"), final_answer=final_answer,
        wall_clock_seconds=elapsed,
    )


def _print_result(r: ScenarioResult) -> None:
    status = "PASS" if r.passed else "FAIL"
    print(f"\n{'=' * 70}\n[{status}] {r.scenario_id}: {r.goal!r}  ({r.wall_clock_seconds:.0f}s)\n{'=' * 70}")
    print(f"Final status : {r.final_status}")
    print(f"Tools called : {r.tools_called}")
    if not r.passed:
        print("Failures:")
        for f in r.failures:
            print(f"  - {f}")
        print("Full transcript:")
        for step in r.transcript:
            label = step.get("tool") or step.get("status") or "?"
            print(f"  iter {step.get('iteration')}: {label} -- {(step.get('reasoning') or '')[:150]}")
    print(f"Final answer : {(r.final_answer or '')[:400]}")


@pytest.mark.agent_llm
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_agent_scenario(scenario: Scenario, tmp_path: Path) -> None:
    data_dir = tmp_path / "kratos_data"
    for sub in ("scans", "logs", "context", "reports", "baseline"):
        (data_dir / sub).mkdir(parents=True, exist_ok=True)

    result = run_scenario(scenario, data_dir)
    _print_result(result)

    if scenario.id == "scenario_2_break_in":
        print(f"[INFO] run_nmap_scan considered: {'run_nmap_scan' in result.tools_called} (tracked, not asserted)")

    assert result.passed, "\n".join(result.failures)

"""
Scripted-mock tests for agent/loop.py's 4 structural final_answer guards
(correlate_findings-required, file-integrity contradiction, dismissive-verdict
contradiction, staleness-vs-claimed-timeframe contradiction), driven through
the REAL run_agent() loop.

Unlike tests/agent_scenarios.py (which is explicitly real-LLM-only by design,
see its module docstring), these tests need fully deterministic, instant
control over both the "model"'s responses AND the tool results the guards
check answers against -- so this is a different file, not an addition to
agent_scenarios.py. Two things are mocked:

  1. agent_chat (patched on kratos.agent.loop, where it was imported via
     `from kratos.llm_interface import agent_chat`) -- returns a scripted
     queue of raw JSON-string responses, one per call, via ScriptedChat.
  2. TOOL_REGISTRY["check_file_integrity"]/["correlate_findings"].handler --
     swapped for canned handlers so a diff/finding exists to contradict
     without touching a real SSH target or real baseline files.

Everything else (execute_tool_call, the 3 guards, retry/reject-count
bookkeeping, force-accept + [NOTE:...] tagging) runs unmodified.

IMPORTANT finding baked into this file's scenario choice: the literally
requested "all 3 guards violated by one final_answer" is impossible to
construct. Guard 1 (correlate_findings_called == False) and Guard 3 (requires
last_correlate_findings to hold a real HIGH/CRITICAL finding) are mutually
exclusive by construction -- last_correlate_findings is only ever populated
inside the same `if tool_name == "correlate_findings":` block that sets
correlate_findings_called = True (agent/loop.py, current version around
lines 535-544), and that flag is never reset. A final_answer cannot both
"never called correlate_findings" and "contradict a correlate_findings
result" in the same investigation. The scenarios below instead cover both
FEASIBLE pairs (guard2+guard3, guard1+guard2), which is the real worst case
reachable in practice.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY

FILE_INTEGRITY_DIFF = {
    "changed": [{"path": "/etc/ssh/sshd_config", "old_hash": "aaa111", "new_hash": "bbb222"}],
    "added": [],
    "removed": [],
}

HIGH_FINDING = {
    "id": "CORR-SSH-001",
    "title": "SSH exposed with failed-login burst activity observed",
    "severity": "high",
    "evidence": ["mocked evidence: ssh exposed + failed-login burst"],
    "recommendation": ["mocked recommendation"],
}

# Deliberately trips BOTH the file-integrity guard's phrase set (Guard 2:
# "not ... tampered with", "integrity remains intact") AND the
# dismissive-verdict guard's phrase set (Guard 3: "no suspicious activity",
# "appears secure") in one answer, without mentioning "correlat"/"rule
# engine" (which would matter for Guard 1 if it were still open).
DISMISSIVE_AND_FILE_CLEAN_ANSWER = (
    "No suspicious activity was detected on this system; overall the system appears secure. "
    "Critical configuration files such as sshd_config have not been tampered with, and "
    "integrity remains intact."
)

# Fixes both violations: acknowledges the real HIGH finding and the real
# file-integrity diff instead of contradicting them.
CORRECTED_ANSWER = (
    "A HIGH-severity finding (CORR-SSH-001: SSH exposed with failed-login burst activity) was "
    "identified and requires attention. Additionally, /etc/ssh/sshd_config has changed since "
    "the last baseline (aaa111 -> bbb222), which should be treated as a possible tampering or "
    "persistence indicator and investigated. Recommend restricting SSH access and reviewing the "
    "modified sshd_config file immediately."
)

# Guard1 (never called correlate_findings) + Guard2 (contradicts a real file
# diff) -- deliberately omits "correlat"/"rule engine" so Guard 1 stays
# violated, and omits the Guard-3 dismissive phrase set (irrelevant here
# since correlate_findings was never called, so Guard 3 can't fire anyway).
NO_CORRELATION_AND_FILE_CLEAN_ANSWER = (
    "Based on the checks performed, critical configuration files have not been modified and "
    "integrity is intact. The investigation is complete."
)

CORRECTED_NO_CORRELATION_ANSWER = (
    "concluding without correlate_findings because the investigation only needed the "
    "file-integrity check for this goal. /etc/ssh/sshd_config has changed since baseline "
    "(aaa111 -> bbb222) and should be investigated as a possible tampering indicator."
)


def _tool_json(tool: str, args: dict[str, Any] | None = None, reasoning: str = "calling tool") -> str:
    return json.dumps({"reasoning": reasoning, "tool": tool, "args": args or {}})


def _final_json(text: str, reasoning: str = "concluding") -> str:
    return json.dumps({"reasoning": reasoning, "final_answer": text})


class ScriptedChat:
    """Replaces agent_chat: returns queued responses in order, one per call."""

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls: list[str] = []

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        self.calls.append(user_prompt)
        if not self.responses:
            raise AssertionError(
                f"ScriptedChat exhausted after {len(self.calls)} calls -- scenario ran longer "
                "than scripted (check the guard reject-count budget assumptions)"
            )
        return self.responses.pop(0)


def _mock_check_file_integrity(**kwargs: Any) -> dict[str, Any]:
    return {
        "status": "ok",
        "diff": FILE_INTEGRITY_DIFF,
        "baseline_name": kwargs.get("baseline_name", "default"),
        "checked_at": "mock",
    }


def _mock_correlate_findings(**kwargs: Any) -> dict[str, Any]:
    return {
        "findings_json_file": "mock_findings.json",
        "findings_md_file": "mock_findings.md",
        "inputs_used": {},
        "missing_inputs": [],
        "input_errors": {},
        "staleness_warning": None,
        "findings": [HIGH_FINDING],
        "count": 1,
    }


# Real staleness_warning shape (adapters/findings_engine.py::_staleness_warning),
# the exact text pattern from the real 2026-07-17 incident this guard fixes.
MOCK_STALENESS_WARNING = (
    "Auto-discovered inputs span 101.3h (> 24h threshold): 'auth_patterns' is from "
    "2026-07-17T01:18:25, 'system_context' is from 2026-07-12T20:14:21. This correlation "
    "mixes fresher and staler data -- treat any finding that depends on the older input(s) "
    "as reflecting that input's collection time, not necessarily the current state."
)


def _mock_correlate_findings_stale(**kwargs: Any) -> dict[str, Any]:
    return {
        "findings_json_file": "mock_findings.json",
        "findings_md_file": "mock_findings.md",
        "inputs_used": {},
        "missing_inputs": [],
        "input_errors": {},
        "staleness_warning": MOCK_STALENESS_WARNING,
        "findings": [],
        "count": 0,
    }


# Real incident text (2026-07-17): a specific timeframe claim on top of an
# unrelated headline number -- deliberately doesn't touch guards 1-3's
# phrase sets so this isolates guard 4 only.
TIMEFRAME_CLAIM_ANSWER = "There were 200 sudo activities observed in the last 24 hours."

# Fixes the violation by dropping the specific timeframe claim.
TIMEFRAME_CORRECTED_ANSWER = (
    "There were 125 sudo session-open events recorded, though the underlying data spans a wider, "
    "uncertain window rather than a confirmed last-24-hours snapshot."
)


# The real 2026-07-15 failure this mock reproduces: correlate_findings's
# actual handler validates that any EXPLICIT file-path arg exists on disk
# and returns this exact shape (a domain-level error result, not a raised
# exception) for a guessed/hallucinated one -- see
# adapters/findings_engine.py's real validation and its real error text,
# quoted (abridged) here.
CORRELATE_FINDINGS_GUESSED_PATH_ERROR = (
    "These file paths do not exist on disk: nmap_parsed_file='data_dir/scans/10.136.28.168_nmap.json'. "
    "Do not guess file paths -- use the exact path from a previous tool's Observation "
    "(e.g. run_nmap_scan's parsed_json_file, collect_system_context's context_file, "
    "parse_auth_log's stats_file), or omit the argument entirely to auto-discover the "
    "latest file in data_dir."
)


class _CorrelateFindingsFailsOnGuessedPath:
    """
    Stateful mock: an explicit nmap_parsed_file arg (simulating a
    hallucinated/guessed path, exactly what the real 2026-07-15 run's model
    did) returns a real-shaped domain-level error; omitting it (simulating
    a corrected retry that lets auto-discovery take over, or a real path)
    succeeds. Tracks every call's kwargs so a test can assert on what the
    "model" actually retried with.
    """

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if kwargs.get("nmap_parsed_file"):
            return {"status": "error", "observation": CORRELATE_FINDINGS_GUESSED_PATH_ERROR}
        return _mock_correlate_findings(**kwargs)


# Deliberately avoids both Guard 2's phrase set (no file-integrity claim) and
# Guard 3's dismissive-verdict phrase set ("no suspicious activity", "clean",
# "secure", etc.) so this scenario isolates Guard 1 only -- whether it's
# violated is driven purely by whether correlate_findings has SUCCEEDED, not
# by any other guard's text-matching.
RAW_OBSERVATIONS_ANSWER = (
    "SSH is exposed on port 22 with failed-login burst activity observed in recent auth data."
)


def _old_guard1_correlate_missing(correlate_findings_called: bool) -> bool:
    """
    Literal reproduction of the REMOVED pre-2026-07-15 Guard 1 formula
    (agent/loop.py, before the fix): `correlate_missing = not
    correlate_findings_called`. Attempt alone satisfied it, regardless of
    whether the call succeeded or failed -- that's exactly the gap the fix
    closed. Kept only here, not in production code, so a test can show a
    concrete before/after on the same real (mocked) scenario instead of
    asserting the difference in a comment alone.
    """
    return not correlate_findings_called


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "kratos_data"
    for sub in ("scans", "logs", "context", "reports", "baseline"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def mocked_tools(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(TOOL_REGISTRY["check_file_integrity"], "handler", _mock_check_file_integrity)
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", _mock_correlate_findings)


@pytest.fixture
def mocked_tools_stale(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", _mock_correlate_findings_stale)


def _print_transcript(transcript: list[dict[str, Any]]) -> None:
    print()
    for step in transcript:
        it = step.get("iteration")
        if step.get("tool"):
            print(f"  iter {it}: tool={step['tool']}")
        elif step.get("status") == "final_answer_rejected":
            print(f"  iter {it}: REJECTED violations={step.get('violations')}")
        elif "final_answer" in step:
            note_count = step["final_answer"].count("[NOTE:")
            print(f"  iter {it}: ACCEPTED final_answer ({note_count} [NOTE:...] tag(s))")
        else:
            print(f"  iter {it}: status={step.get('status')}")


def test_guard2_and_guard3_stubborn_model_force_accepts_with_both_notes(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Worst-case reachable combo (Guard1+Guard3 is impossible, see module
    docstring): correlate_findings returns a real HIGH finding AND
    check_file_integrity shows a real diff, then the "model" submits the
    SAME answer -- contradicting both -- three times in a row without ever
    fixing it (MAX_..._REJECTIONS=2 for each guard). Expect: both guards'
    corrections are combined into ONE observation per rejected attempt (not
    one iteration per guard), both reject budgets exhaust in lockstep, and
    the 3rd submission is force-accepted with BOTH [NOTE:...] tags present
    -- i.e. force-accept can happen with genuine unresolved contradictions,
    just visibly labeled rather than silently accepted as clean.
    """
    chat = ScriptedChat([
        _tool_json("check_file_integrity"),
        _tool_json("correlate_findings"),
        _final_json(DISMISSIVE_AND_FILE_CLEAN_ANSWER),  # attempt 1: rejected (both guards)
        _final_json(DISMISSIVE_AND_FILE_CLEAN_ANSWER),  # attempt 2: rejected (both guards, budget now exhausted)
        _final_json(DISMISSIVE_AND_FILE_CLEAN_ANSWER),  # attempt 3: force-accepted with both NOTEs
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer", f"Expected clean termination, got {result['status']}"
    assert len(chat.calls) == 5, f"Expected exactly 5 LLM calls to resolution, got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected_steps) == 2, f"Expected 2 rejected attempts, got {len(rejected_steps)}"
    for step in rejected_steps:
        assert set(step["violations"]) == {"file_integrity_contradiction", "dismissive_verdict_contradiction"}, (
            "Expected BOTH guard2 and guard3 combined into one rejection observation "
            f"(not one gate at a time), got: {step['violations']}"
        )

    final_answer = result["final_answer"]
    assert final_answer.count("[NOTE:") == 2, (
        f"Expected the force-accepted answer to carry both unresolved-violation NOTE tags, "
        f"got {final_answer.count('[NOTE:')}: {final_answer!r}"
    )
    assert "file/config integrity" in final_answer
    assert "HIGH/CRITICAL" in final_answer


def test_guard2_and_guard3_self_correcting_model_converges_cleanly(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Same setup, but the model fixes BOTH contradictions on its very next
    attempt after the combined rejection observation. Confirms the combined-
    feedback mechanism actually lets a compliant model clear both guards in
    a single retry (1 rejected attempt, not 2 -- one per guard).
    """
    chat = ScriptedChat([
        _tool_json("check_file_integrity"),
        _tool_json("correlate_findings"),
        _final_json(DISMISSIVE_AND_FILE_CLEAN_ANSWER),  # attempt 1: rejected (both guards)
        _final_json(CORRECTED_ANSWER),                  # attempt 2: clean, accepted
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer"
    assert len(chat.calls) == 4, f"Expected exactly 4 LLM calls to resolution, got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected_steps) == 1
    assert set(rejected_steps[0]["violations"]) == {"file_integrity_contradiction", "dismissive_verdict_contradiction"}

    final_answer = result["final_answer"]
    assert "[NOTE:" not in final_answer, f"Expected a clean accepted answer, got NOTE tag(s): {final_answer!r}"


def test_guard1_rejects_failed_attempt_then_accepts_after_real_retry(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    2026-07-15 fix verification (Sprint 2 closing regression): Guard 1's
    pass condition changed from "correlate_findings was attempted" to
    "correlate_findings actually succeeded". Reproduces the real failure
    mode -- a correlate_findings call with a guessed/hallucinated file path,
    which fails with a real domain-level error, not an exception -- and
    proves two things in one scenario:

    1. A final_answer submitted right after that FAILED attempt is now
       REJECTED (violations includes "missing_correlation") purely because
       the call never succeeded. Under the OLD attempt-only guard,
       correlate_findings_called would already be True at this point and
       this exact same final_answer would have been silently ACCEPTED --
       the real gap this fix closes.
    2. Once the model retries with a corrected call (no guessed path, so
       the mock's auto-discovery branch succeeds), the SAME final_answer
       text is accepted cleanly, with last_correlate_findings genuinely
       populated -- confirming the guard isn't just stricter, it correctly
       recognizes a real subsequent success.
    """
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", _CorrelateFindingsFailsOnGuessedPath())
    mock = TOOL_REGISTRY["correlate_findings"].handler

    chat = ScriptedChat([
        _tool_json("correlate_findings", {"nmap_parsed_file": "data_dir/scans/10.136.28.168_nmap.json"}),
        _final_json(RAW_OBSERVATIONS_ANSWER),  # attempt 1: REJECTED (failed attempt, not success)
        _tool_json("correlate_findings"),      # corrected retry: no guessed path -> succeeds
        _final_json(RAW_OBSERVATIONS_ANSWER),  # attempt 2: ACCEPTED (now a real success exists)
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer", f"Expected clean termination, got {result['status']}"
    assert len(chat.calls) == 4, f"Expected exactly 4 LLM calls to resolution, got {len(chat.calls)}"

    # Point 1: the failed-attempt final_answer was really rejected, not
    # silently accepted the way the old attempt-only guard would have.
    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected_steps) == 1, f"Expected exactly 1 rejected attempt, got {len(rejected_steps)}"
    assert rejected_steps[0]["violations"] == ["missing_correlation"]

    # Concrete OLD-vs-NEW comparison on this SAME real scenario (not just
    # asserted in a docstring): by the time the first final_answer was
    # submitted, correlate_findings HAD been called once (real, observed
    # via mock.calls below) -- under the OLD formula that alone would have
    # made correlate_missing False, i.e. guard 1 NOT violated, i.e. the old
    # code would have silently ACCEPTED this exact final_answer despite the
    # real failure above. The NEW code, observed one line above, actually
    # rejected it.
    assert len(mock.calls) >= 1, "correlate_findings must have really been called for this comparison to mean anything"
    old_correlate_missing = _old_guard1_correlate_missing(correlate_findings_called=True)
    assert old_correlate_missing is False, (
        "OLD Guard 1 formula on this real scenario: correlate_findings_called=True after the "
        "first (failed) attempt -> correlate_missing=False -> guard1_violated=False -> the old "
        "attempt-only code would NOT have rejected this final_answer -- it would have been "
        "silently accepted despite the real hallucinated-path failure. The new code (asserted "
        "above) actually rejected it: this is the real behavior divergence the fix closes."
    )

    # The rejection's real error text (not a generic message) must have
    # actually reached the model, matching the retry pattern proven to work
    # for the real YARA timeout self-correction.
    assert any(CORRELATE_FINDINGS_GUESSED_PATH_ERROR in prompt for prompt in chat.calls[2:]), (
        "Expected the real correlate_findings error text to be fed back into a later prompt"
    )
    assert any("Do not guess a new path" in prompt for prompt in chat.calls[2:])

    # Point 2: the corrected retry really succeeded and the final_answer
    # went through clean -- no [NOTE:...] tag, since Guard 1 is no longer
    # violated once a real success exists.
    assert mock.calls[0].get("nmap_parsed_file"), "First call should be the guessed-path attempt"
    assert not mock.calls[1].get("nmap_parsed_file"), "Retry should be the corrected (no guessed path) call"
    final_answer = result["final_answer"]
    assert "[NOTE:" not in final_answer, f"Expected a clean accepted answer, got NOTE tag(s): {final_answer!r}"


def test_guard1_no_friction_when_correlate_findings_succeeds_first_try(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Regression check for the common/expected case (Verification item 5):
    when correlate_findings succeeds on the very first real attempt (as it
    did in Sprint 2's first closing-regression run, real CORR-SSH-001), the
    new success-based Guard 1 must add ZERO extra friction -- no rejection,
    no [NOTE:...] tag, straight to an accepted final_answer. Isolated from
    the other guards (no check_file_integrity call, neutral answer text) so
    this is purely a Guard 1 measurement.
    """
    chat = ScriptedChat([
        _tool_json("correlate_findings"),
        _final_json(RAW_OBSERVATIONS_ANSWER),  # first attempt: correlate_findings already succeeded -> accepted immediately
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer"
    assert len(chat.calls) == 2, f"Expected exactly 2 LLM calls (no rejection round-trip), got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert rejected_steps == [], f"Expected zero rejections for a first-try success, got {rejected_steps}"

    final_answer = result["final_answer"]
    assert "[NOTE:" not in final_answer, f"Expected a clean accepted answer, got NOTE tag(s): {final_answer!r}"


def test_guard1_and_guard2_self_correcting_model_converges_cleanly(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    The OTHER feasible pair: correlate_findings is never called (Guard 1)
    while the model also contradicts a real file-integrity diff (Guard 2).
    Confirms this pair also combines into one rejection observation and
    converges within budget once the model self-corrects.
    """
    # Self-correcting now means ACTUALLY running correlate_findings after the
    # rejection: check_file_integrity already returned real data, so the old
    # "explain why you skipped correlation" exemption no longer applies (E26,
    # docs/time_window_design.md -- that exemption was the loophole).
    chat = ScriptedChat([
        _tool_json("check_file_integrity"),
        _final_json(NO_CORRELATION_AND_FILE_CLEAN_ANSWER),  # attempt 1: rejected (guard1 + guard2)
        _tool_json("correlate_findings"),                   # the real fix: run the engine
        _final_json(CORRECTED_ANSWER),                      # attempt 2: clean, accepted
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer"
    assert len(chat.calls) == 4, f"Expected exactly 4 LLM calls to resolution, got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected_steps) == 1
    assert set(rejected_steps[0]["violations"]) == {"missing_correlation", "file_integrity_contradiction"}

    final_answer = result["final_answer"]
    assert "[NOTE:" not in final_answer, f"Expected a clean accepted answer, got NOTE tag(s): {final_answer!r}"


def test_guard4_stubborn_model_force_accepts_with_note(
    data_dir: Path, mocked_tools_stale, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Real-incident reproduction (2026-07-17): correlate_findings succeeds and
    returns a real staleness_warning (inputs span 101.3h, not 24h), and the
    model states "in the last 24 hours" anyway, three times in a row without
    ever dropping the claim (MAX_STALENESS_TIMEFRAME_REJECTIONS=2). Expect:
    2 rejections, then force-accept with the [NOTE:...] tag visibly present
    -- same worst-case shape as guards 2/3's stubborn-model test.
    """
    chat = ScriptedChat([
        _tool_json("correlate_findings"),
        _final_json(TIMEFRAME_CLAIM_ANSWER),  # attempt 1: rejected (guard4)
        _final_json(TIMEFRAME_CLAIM_ANSWER),  # attempt 2: rejected (guard4, budget now exhausted)
        _final_json(TIMEFRAME_CLAIM_ANSWER),  # attempt 3: force-accepted with NOTE
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer", f"Expected clean termination, got {result['status']}"
    assert len(chat.calls) == 4, f"Expected exactly 4 LLM calls to resolution, got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected_steps) == 2, f"Expected 2 rejected attempts, got {len(rejected_steps)}"
    for step in rejected_steps:
        assert step["violations"] == ["staleness_timeframe_contradiction"]

    final_answer = result["final_answer"]
    assert final_answer.count("[NOTE:") == 1, (
        f"Expected the force-accepted answer to carry the unresolved-violation NOTE tag, "
        f"got {final_answer.count('[NOTE:')}: {final_answer!r}"
    )
    assert MOCK_STALENESS_WARNING in final_answer
    # The bogus "200"/timeframe claim itself is untouched by the NOTE prefix
    # (same "flag, don't silently rewrite" philosophy as the other 3 guards).
    assert TIMEFRAME_CLAIM_ANSWER in final_answer


def test_guard4_self_correcting_model_converges_cleanly(
    data_dir: Path, mocked_tools_stale, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same setup, but the model drops the specific timeframe claim on its
    very next attempt -- confirms the rejection message alone is enough for
    a compliant model to converge within 1 retry, no [NOTE:...] tag."""
    chat = ScriptedChat([
        _tool_json("correlate_findings"),
        _final_json(TIMEFRAME_CLAIM_ANSWER),      # attempt 1: rejected (guard4)
        _final_json(TIMEFRAME_CORRECTED_ANSWER),  # attempt 2: clean, accepted
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer"
    assert len(chat.calls) == 3, f"Expected exactly 3 LLM calls to resolution, got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected_steps) == 1
    assert rejected_steps[0]["violations"] == ["staleness_timeframe_contradiction"]

    final_answer = result["final_answer"]
    assert "[NOTE:" not in final_answer, f"Expected a clean accepted answer, got NOTE tag(s): {final_answer!r}"


def test_guard4_no_friction_when_no_staleness_warning(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """
    Regression check (Verification item, mirrors guard 1's no-friction
    test): a final_answer stating a specific timeframe when
    correlate_findings' staleness_warning is None (mocked_tools' default,
    the common/expected case) must add ZERO extra friction -- guard 4 is
    architecturally incapable of firing without a real staleness_warning
    present, regardless of how the answer is phrased.
    """
    chat = ScriptedChat([
        _tool_json("correlate_findings"),
        _final_json(TIMEFRAME_CLAIM_ANSWER),  # states a timeframe, but no staleness_warning exists
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    _print_transcript(result["transcript"])

    assert result["status"] == "final_answer"
    assert len(chat.calls) == 2, f"Expected exactly 2 LLM calls (no rejection round-trip), got {len(chat.calls)}"

    rejected_steps = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert rejected_steps == [], f"Expected zero rejections when there's no staleness_warning, got {rejected_steps}"

    final_answer = result["final_answer"]
    assert "[NOTE:" not in final_answer, f"Expected a clean accepted answer, got NOTE tag(s): {final_answer!r}"



# ---------------------------------------------------------------------------
# E26: Guard 1's explain-and-skip loophole + Guard 5 (claims a tool never run)
# ---------------------------------------------------------------------------
LOOPHOLE_ANSWER = (
    "There were no failed SSH login attempts on the target within the last 5 minutes. Note the "
    "target's clock is 7 minutes behind, which may affect correlation with other logs."
)


def test_guard1_loophole_mentioning_correlation_no_longer_skips_the_engine(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live incident: this exact phrasing used to satisfy the exemption, so the
    counting engine never ran and a real burst was reported as 'none'."""
    chat = ScriptedChat([
        _tool_json("check_file_integrity"),
        _final_json(LOOPHOLE_ANSWER),         # must be REJECTED now (data existed)
        _tool_json("correlate_findings"),
        _final_json(CORRECTED_ANSWER),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert rejected and "missing_correlation" in rejected[0]["violations"]
    assert "[NOTE:" not in result["final_answer"]


def test_guard1_exemption_still_applies_when_no_tool_returned_data(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The legitimate case the exemption exists for: nothing could be gathered."""
    def _ssh_down(**_kwargs):
        return {"status": "error", "observation": "journalctl over SSH failed: connection refused"}

    monkeypatch.setattr(TOOL_REGISTRY["read_journalctl"], "handler", _ssh_down)
    chat = ScriptedChat([
        _tool_json("read_journalctl"),
        _final_json("I could not reach the target (SSH refused), so there was no data to correlate."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    assert [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"] == []
    assert "[NOTE:" not in result["final_answer"]


def test_guard5_rejects_answer_claiming_an_uncalled_tool_then_notes_if_stubborn(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Benchmark incident: 'Key Findings (synthesized via correlate_findings)' with
    correlate_findings never called."""
    fake = "Key findings (synthesized via correlate_findings): no suspicious activity detected."
    chat = ScriptedChat([_tool_json("check_file_integrity")] + [_final_json(fake)] * 6)
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert rejected and "claims_uncalled_tool" in rejected[0]["violations"]
    assert "correlate_findings, which was never run" in result["final_answer"]


def test_guard5_other_tool_claim_rejected_even_when_correlation_succeeded(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = ScriptedChat([
        _tool_json("correlate_findings"),
        _final_json(CORRECTED_ANSWER + " run_yara_scan found no malware on the host."),
        _final_json(CORRECTED_ANSWER),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and rejected[0]["violations"] == ["claims_uncalled_tool"]
    assert "[NOTE:" not in result["final_answer"]


def test_guard5_allows_negated_mentions_of_uncalled_tools(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = ScriptedChat([
        _tool_json("correlate_findings"),
        _final_json(CORRECTED_ANSWER + " I did not run run_vuln_scan; consider it as a follow-up."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    assert [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"] == []


# ---------------------------------------------------------------------------
# Guard 8 -- a capability gap stated in prose but never proposed (eval G1).
# ---------------------------------------------------------------------------
GAP_ANSWER = (CORRECTED_ANSWER + " A scan for SUID binaries was not performed because Kratos currently "
              "lacks a remote-target file-listing tool.")


def _proposal_json(name: str = "find_suid_binaries") -> str:
    return json.dumps({"reasoning": "gap", "tool_proposal": {"name": name, "description": "Lists SUID binaries on the target."}})


def test_guard8_asks_once_for_a_proposal_and_accepts_after_it(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = ScriptedChat([_tool_json("correlate_findings"), _final_json(GAP_ANSWER), _proposal_json(),
                         _final_json(GAP_ANSWER)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("find SUID binaries", data_dir, max_iters=10)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert len(rejected) == 1 and rejected[0]["violations"] == ["unproposed_capability_gap"]
    assert [s["tool_proposal"]["name"] for s in result["transcript"] if s.get("tool_proposal")] == ["find_suid_binaries"]  # no derived duplicate
    assert result["status"] == "final_answer" and "[NOTE:" not in result["final_answer"]


def test_guard8_asks_only_once_and_never_tags_the_answer(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = ScriptedChat([_tool_json("correlate_findings")] + [_final_json(GAP_ANSWER)] * 3)
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("find SUID binaries", data_dir, max_iters=10)
    assert len([s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]) == 1
    assert result["final_answer"] == GAP_ANSWER  # accepted as-is: advisory, not a correctness guard
    # ...but the gap still reaches the human, as a suggestion derived from the answer's own sentence
    [derived] = [s["tool_proposal"] for s in result["transcript"] if s.get("tool_proposal")]
    assert derived["derived_from_answer"] is True and derived["name"] == ""
    assert derived["description"].startswith("A scan for SUID binaries was not performed")


def test_guard8_silent_when_a_proposal_was_already_made_or_no_gap_is_claimed(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = ScriptedChat([_proposal_json(), _tool_json("correlate_findings"), _final_json(GAP_ANSWER)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("find SUID binaries", data_dir, max_iters=10)
    assert [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"] == []

    chat = ScriptedChat([_tool_json("correlate_findings"),
                         _final_json(CORRECTED_ANSWER + " The target lacks a firewall rule for port 22.")])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("check the firewall", data_dir, max_iters=10)
    assert [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"] == []


@pytest.mark.parametrize("text,expected", [
    ("Kratos does not possess a tool to perform geographic mapping (GeoIP).", True),
    ("Kratos currently lacks a remote-target file-listing tool.", True),
    ("The scan was not performed because it requires local shell access that is not supported.", True),
    ("There is no existing tool for listing cron jobs.", True),
    ("However, there is no tool available in my registry that allows recursive scanning.", True),
    ("A direct enumeration of SUID binaries is not possible with current tools.", True),
    ("An exhaustive enumeration is not supported by current tools.", True),
    ("Such a capability is currently unavailable.", True),
    ("I do not have the capability to perform GeoIP mapping.", True),
    ("I could not list them as no specific tool for this purpose is available.", True),
    ("There are no tools in my suite to enumerate SUID binaries.", True),
    ("While I could not enumerate SUID binaries due to the inability to execute arbitrary filesystem searches, the host is fine.", True),
    ("I am unable to enumerate SUID binaries as that requires direct shell execution.", True),
    ("Such tools are not part of my current toolkit.", True),
    ("I could not determine the attacker's identity because the logs were rotated.", False),
    ("The check could not be completed because the target was unreachable.", False),
    ("No findings are available for this period.", False),
    ("The firewall is not available on this host.", False),
    ("No tool calls failed.", False),
    ("No suspicious cron jobs were identified.", False),
    ("The system does not have fail2ban installed.", False),
    ("The target lacks a firewall.", False),
    ("These private addresses cannot be mapped using GeoIP data.", False),
    ("The investigation could not be completed because the target was unreachable.", False),
])
def test_guard8_gap_phrase_matching(text: str, expected: bool) -> None:
    assert bool(agent_loop._CAPABILITY_GAP_RE.search(text)) is expected


def test_derived_suggestion_panel_text() -> None:
    from kratos.tui_mk2 import render as R

    title, body = R.evolve_suggestion_text({"name": "", "description": "No tool lists SUID files.", "derived_from_answer": True})
    assert title == "Missing capability noticed" and "No tool lists SUID files." in body and "/evolve" in body
    title, body = R.evolve_suggestion_text({"name": "find_suid", "description": "Lists SUID files."})
    assert title == "Evo-loop suggestion" and body.startswith("find_suid")


# ---------------------------------------------------------------------------
# Local-only tools are not offered to the model for a remote target (eval G1).
# ---------------------------------------------------------------------------
from kratos import kratos_config as _kcfg  # noqa: E402


@pytest.fixture
def remote_target():
    prev = _kcfg.get_active_target()
    _kcfg.set_active_target("10.136.28.168")
    yield
    _kcfg.set_active_target(prev)


def test_run_linux_command_hidden_and_refused_for_a_remote_target(
    data_dir: Path, mocked_tools, remote_target, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompt = agent_loop.build_system_prompt()
    assert "- run_linux_command" not in prompt
    assert "Not offered here: run_linux_command" in prompt and "respond with a tool_proposal for it" in prompt
    assert "3 of the tools listed above are the exception" in prompt  # the local-tool note matches what is offered
    calls = []
    monkeypatch.setattr(TOOL_REGISTRY["run_linux_command"], "handler", lambda **kw: calls.append(kw) or {"status": "ok"})
    chat = ScriptedChat([_tool_json("run_linux_command", {"command": "find / -perm -4000"}),
                         _tool_json("correlate_findings"), _final_json(CORRECTED_ANSWER)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("find SUID binaries", data_dir, max_iters=10)
    step = next(s for s in result["transcript"] if s.get("tool") == "run_linux_command")
    assert calls == [] and "not available in this investigation" in json.dumps(step["observation"])


def test_run_linux_command_still_offered_when_investigating_kratos_itself(
    remote_target, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent_loop, "_loopback_ssh_ok", lambda: True)
    _kcfg.set_active_target("127.0.0.1")
    prompt = agent_loop.build_system_prompt()
    assert "- run_linux_command" in prompt and "4 of the tools listed above are the exception" in prompt


def test_host_mode_without_self_ssh_hides_ssh_tools_and_says_whose_machine(
    remote_target, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live: /investigate-host ran a kept tool that SSHed to ubuntu@127.0.0.1 (refused) and the
    answer called this machine 'the target'."""
    monkeypatch.setattr(agent_loop, "_loopback_ssh_ok", lambda: False)
    _kcfg.set_active_target("127.0.0.1")
    hidden = agent_loop._agent_hidden_tools()
    assert {"read_journalctl", "list_processes", "run_config_audit"} <= hidden
    assert not {"run_linux_command", "collect_system_context", "run_nmap_scan", "parse_auth_log"} & hidden
    prompt = agent_loop.build_system_prompt()
    assert "THIS RUN IS ABOUT KRATOS'S OWN MACHINE" in prompt and "never \"the target\"" in prompt
    assert "- read_journalctl" not in prompt and "SSH into this Kratos machine isn't set up" in prompt


def test_host_mode_keeps_ssh_tools_when_self_ssh_works(remote_target, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_loop, "_loopback_ssh_ok", lambda: True)
    _kcfg.set_active_target("127.0.0.1")
    assert agent_loop._agent_hidden_tools() == frozenset()


def test_remote_target_prompt_has_no_host_mode_note(remote_target) -> None:
    assert "THIS RUN IS ABOUT KRATOS'S OWN MACHINE" not in agent_loop.build_system_prompt()


def test_a_proposal_to_run_commands_on_the_target_is_not_surfaced(
    data_dir: Path, mocked_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live finding: asked to run `uptime` on the target, the model proposed
    `run_target_command` ("Executes a specified ... shell command on the target")
    as an /evolve suggestion. Kratos observes and recommends; it never offers that."""
    execute = json.dumps({"reasoning": "need it", "tool_proposal": {
        "name": "run_target_command",
        "description": "Executes a specified, non-interactive shell command on the target device via SSH."}})
    chat = ScriptedChat([execute, _proposal_json(), _tool_json("correlate_findings"), _final_json(CORRECTED_ANSWER)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("run uptime on the target", data_dir, max_iters=10)
    surfaced = [s["tool_proposal"]["name"] for s in result["transcript"] if s.get("tool_proposal")]
    assert surfaced == ["find_suid_binaries"]           # the read-only one still goes through
    refused = [s for s in result["transcript"] if s.get("status") == "tool_proposal_refused_execution"]
    assert refused and refused[0]["attempted_tool_proposal"]["name"] == "run_target_command"
    assert any("never runs commands on" in c for c in chat.calls)   # the model is told why


# --- Guard 9: a past state Kratos has no record of -------------------------
def _mock_state_no_record(**kwargs: Any) -> dict[str, Any]:
    return {"status": "ok", "category": "open_ports", "requested_at": "2026-10-03T12:00:00+00:00",
            "snapshot": None, "history": None,
            "note": "no record: Kratos has no open_ports snapshot at or before that time"}


def _mock_state_found(**kwargs: Any) -> dict[str, Any]:
    return {"status": "ok", "category": "open_ports", "requested_at": "2026-10-03T12:00:00+00:00",
            "snapshot": {"snapshot_id": "s1", "open_ports": [22]}, "note": "nearest snapshot 2h before"}


def _mock_correlate_clean(**kwargs: Any) -> dict[str, Any]:
    return {"findings_json_file": "f.json", "findings_md_file": "f.md", "inputs_used": {}, "missing_inputs": [],
            "input_errors": {}, "staleness_warning": None, "findings": [], "count": 0}


INFERRED_STATE_ANSWER = "Port 22 was confirmed open and functional throughout the whole period."
HONEST_STATE_ANSWER = ("Kratos has no saved record of the open ports at that time, so it can't tell whether "
                       "port 22 was open then. A port scan saved at that time would answer it next time.")


@pytest.fixture
def state_tools(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", _mock_correlate_clean)
    monkeypatch.setattr(TOOL_REGISTRY["state_as_of"], "handler", _mock_state_no_record)


def test_guard9_stubborn_inferred_state_is_rejected_once_then_noted(
    data_dir: Path, state_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live incident (2026-10-04): state_as_of said 'no record', the answer said 'confirmed open'."""
    chat = ScriptedChat([
        _tool_json("state_as_of", {"category": "open_ports", "at": "2026-10-03 12:00"}),
        _tool_json("correlate_findings"),
        _final_json(INFERRED_STATE_ANSWER),
        _final_json(INFERRED_STATE_ANSWER),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert [s["violations"] for s in rejected] == [["past_state_without_record"]]
    assert result["final_answer"].startswith("[NOTE: Kratos has no saved record of open ports at 2026-10-03 12:00 UTC")
    assert INFERRED_STATE_ANSWER in result["final_answer"]


def test_guard9_honest_answer_after_one_correction_is_accepted_clean(
    data_dir: Path, state_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    chat = ScriptedChat([
        _tool_json("state_as_of", {"category": "open_ports", "at": "2026-10-03 12:00"}),
        _tool_json("correlate_findings"),
        _final_json(INFERRED_STATE_ANSWER),
        _final_json(HONEST_STATE_ANSWER),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    assert result["final_answer"] == HONEST_STATE_ANSWER


def test_guard9_no_friction_when_a_record_exists(
    data_dir: Path, state_tools, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(TOOL_REGISTRY["state_as_of"], "handler", _mock_state_found)
    chat = ScriptedChat([
        _tool_json("state_as_of", {"category": "open_ports", "at": "2026-10-03 12:00"}),
        _tool_json("correlate_findings"),
        _final_json(INFERRED_STATE_ANSWER),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("test goal", data_dir, max_iters=10)
    assert not [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert result["final_answer"] == INFERRED_STATE_ANSWER

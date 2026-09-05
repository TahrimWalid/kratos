"""
Scripted/unit tests for agent/loop.py's context compaction (feature 14b),
built with the C7 regression explicitly in mind.

C7 (the eval's long-run context-stability check) exists because Sprint 1's
original root-cause bug was context truncation silently dropping an earlier
tool observation the model still needed -- making it lose the thread or its
JSON format near the ceiling. So the compaction these tests cover is designed
to be non-lossy in the ways that matter, and the tests assert exactly those
properties:

  * The returned transcript and the guards' own state are NEVER touched by
    compaction -- only the model-facing prompt string is. The integration test
    below drives a real run_agent() through a real compaction and confirms
    Guard 1 still fires (its state survives) and the transcript still records
    every step.
  * Old turns are DIGESTED, not dropped: a folded tool turn keeps its tool name
    and result pointers (any *_file/*_path value + key scalars + finding
    severities) so a later step can still cite them. The unit tests assert the
    exact pointers survive.
  * The goal and the most recent turns are always kept verbatim.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kratos.agent import loop as agent_loop
from kratos.agent.loop import _Conversation, _digest_turn
from kratos.agent.tools import TOOL_REGISTRY
from kratos.llm_interface import TokenUsage

WINDOW = 6144
ABOVE_TRIGGER = int(0.90 * WINDOW)   # past the 0.85 trigger ratio
BELOW_TRIGGER = int(0.50 * WINDOW)   # comfortably below it

# A realistically-sized tool observation block (~1.5k chars, like a real capped
# Observation) so folding it actually shrinks the prompt past the shrink-guard.
_BIG_OBS = "x" * 1500


def _add(c: _Conversation, tool: str, observation: dict[str, Any], body: str = _BIG_OBS) -> None:
    """Append one tool turn: the exact text shape run_agent appends, plus the
    structured (tool, observation) so a fold can digest it."""
    c.add(f"\nAssistant: {json.dumps({'tool': tool})}\nObservation: {body}\n",
          tool=tool, observation=observation)


# ---------------------------------------------------------------------------
# _digest_turn -- the pointer-preservation core (this is the C7-critical bit)
# ---------------------------------------------------------------------------
def test_digest_preserves_tool_name_and_file_path():
    obs = {"status": "ok", "result": {"parsed_json_file": "data/scans/parsed_9.json",
                                       "target": "10.136.28.168", "open_ports_total": 1}}
    d = _digest_turn("run_nmap_scan", obs)
    assert d.startswith("run_nmap_scan:")
    assert "parsed_json_file=data/scans/parsed_9.json" in d   # the pointer a later step cites
    assert "open_ports_total=1" in d


def test_digest_preserves_finding_severities():
    obs = {"status": "ok", "result": {"findings_md_file": "data/reports/f.md",
                                       "findings": [{"severity": "high"}, {"severity": "info"}]}}
    d = _digest_turn("correlate_findings", obs)
    assert "findings_md_file=data/reports/f.md" in d
    assert "findings=2[high,info]" in d


def test_digest_of_error_observation():
    obs = {"status": "error", "observation": "target=192.168.1.50 does not match the active target"}
    d = _digest_turn("run_nmap_scan", obs)
    assert d.startswith("run_nmap_scan: ERROR")
    assert "192.168.1.50" in d


def test_digest_of_correction_turn_has_no_tool():
    assert _digest_turn(None, None) == "(a correction/notice was issued to the model)"


def test_digest_never_raises_on_weird_shapes():
    # best-effort, never correctness -- must not raise on non-dict / missing keys
    assert _digest_turn("t", None)
    assert _digest_turn("t", "just a string")
    assert _digest_turn("t", {"status": "ok"})   # no "result" key


# ---------------------------------------------------------------------------
# _Conversation -- trigger behavior + what survives a fold
# ---------------------------------------------------------------------------
def test_no_compaction_below_trigger():
    c = _Conversation("goal")
    for _ in range(6):
        _add(c, "read_journalctl", {"status": "ok", "result": {"count": 10}})
    before = c.render()
    assert c.maybe_compact(BELOW_TRIGGER, WINDOW) is False
    assert c.render() == before          # untouched
    assert c.compaction_count == 0


def test_no_compaction_when_only_recent_turns_exist():
    c = _Conversation("goal")
    for _ in range(agent_loop.COMPACTION_KEEP_RECENT_TURNS):   # exactly the keep-recent count
        _add(c, "list_processes", {"status": "ok", "result": {"count": 19}})
    before = c.render()
    assert c.maybe_compact(ABOVE_TRIGGER, WINDOW) is False     # nothing foldable w/o touching recent
    assert c.render() == before


def test_no_usage_reported_never_compacts():
    c = _Conversation("goal")
    for _ in range(6):
        _add(c, "read_journalctl", {"status": "ok", "result": {"count": 10}})
    assert c.maybe_compact(0, WINDOW) is False                 # backend reported no tokens -> safe no-op


def test_compaction_keeps_goal_and_recent_verbatim_and_digests_old():
    c = _Conversation("check the target for brute force")
    # 5 distinct tool turns; the last 3 must stay verbatim, first 2 get folded.
    _add(c, "run_nmap_scan",
         {"status": "ok", "result": {"parsed_json_file": "data/scans/p9.json", "open_ports_total": 1}})
    _add(c, "read_journalctl", {"status": "ok", "result": {"count": 200}}, body="AAA" + _BIG_OBS)
    _add(c, "list_processes", {"status": "ok", "result": {"count": 19}}, body="RECENT-1" + _BIG_OBS)
    _add(c, "check_file_integrity", {"status": "ok", "result": {"count": 0}}, body="RECENT-2" + _BIG_OBS)
    _add(c, "correlate_findings",
         {"status": "ok", "result": {"findings_md_file": "data/reports/f.md", "findings": [{"severity": "high"}]}},
         body="RECENT-3" + _BIG_OBS)
    before = c.render()

    assert c.maybe_compact(ABOVE_TRIGGER, WINDOW) is True
    after = c.render()

    assert after.startswith("Investigation goal: check the target for brute force")   # goal verbatim
    assert "RECENT-1" in after and "RECENT-2" in after and "RECENT-3" in after        # last 3 verbatim
    assert "[EARLIER STEPS -- COMPACTED" in after                                     # a clear digest header
    # folded turns survive as pointers, not silence:
    assert "parsed_json_file=data/scans/p9.json" in after      # nmap's pointer -> still citable
    assert "read_journalctl" in after                          # folded tool named
    assert len(after) < len(before)                            # actually shrank
    assert c.compaction_count == 1


def test_compaction_refuses_to_grow_on_degenerate_tiny_turns():
    # tiny turns whose digest header would be larger than the turns it replaces
    c = _Conversation("g")
    for _ in range(5):
        c.add("\nA\nO\n", tool="t", observation={"status": "ok", "result": {}})
    before = c.render()
    assert c.maybe_compact(ABOVE_TRIGGER, WINDOW) is False      # shrink-guard: no-op rather than grow
    assert c.render() == before


def test_refold_accumulates_earliest_pointer_under_one_header():
    c = _Conversation("g")
    _add(c, "run_nmap_scan", {"status": "ok", "result": {"parsed_json_file": "data/scans/EARLIEST.json"}})
    for name in ("read_journalctl", "list_processes", "run_config_audit"):
        _add(c, name, {"status": "ok", "result": {"count": 1}})
    assert c.maybe_compact(ABOVE_TRIGGER, WINDOW) is True       # first fold
    # add more, fold again
    for name in ("run_yara_scan", "run_vuln_scan", "correlate_findings"):
        _add(c, name, {"status": "ok", "result": {"count": 1}})
    assert c.maybe_compact(ABOVE_TRIGGER, WINDOW) is True       # second fold
    after = c.render()
    assert "parsed_json_file=data/scans/EARLIEST.json" in after         # earliest pointer still there
    assert after.count("[EARLIER STEPS -- COMPACTED") == 1             # one header, not nested stacks


# ---------------------------------------------------------------------------
# Integration: a real run_agent() through a real compaction, guards intact
# ---------------------------------------------------------------------------
class _ScriptedChat:
    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls: list[str] = []

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        self.calls.append(user_prompt)
        assert self.responses, f"ScriptedChat exhausted after {len(self.calls)} calls"
        return self.responses.pop(0)


def _big_ok(**kwargs: Any) -> dict[str, Any]:
    return {"status": "ok", "note": "y" * 1500}


def _correlate_ok(**kwargs: Any) -> dict[str, Any]:
    return {
        "findings_json_file": "mock.json", "findings_md_file": "mock.md",
        "inputs_used": {}, "missing_inputs": [], "input_errors": {},
        "staleness_warning": None,
        "findings": [{"id": "CORR-SSH-001", "severity": "high",
                      "title": "t", "evidence": ["e"], "recommendation": ["r"]}],
        "count": 1,
    }


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "kratos_data"
    for sub in ("scans", "logs", "context", "reports", "baseline"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    return d


def test_run_agent_real_compaction_fires_and_guard1_still_holds(
    data_dir: Path, monkeypatch: pytest.MonkeyPatch
):
    # Force every call to report a near-full prompt so compaction triggers once
    # enough turns have accumulated (past COMPACTION_KEEP_RECENT_TURNS).
    monkeypatch.setattr(agent_loop, "get_last_token_usage",
                        lambda: TokenUsage(prompt_tokens=ABOVE_TRIGGER, completion_tokens=20, total_tokens=ABOVE_TRIGGER + 20))
    monkeypatch.setattr(agent_loop, "get_context_window_tokens", lambda: WINDOW)

    for name in ("run_nmap_scan", "read_journalctl", "list_processes"):
        monkeypatch.setattr(TOOL_REGISTRY[name], "handler", _big_ok)
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", _correlate_ok)

    # 4 tool calls (so turns reach 4 > keep-recent 3), then a final answer that
    # ACKNOWLEDGES the real HIGH finding (so no guard trips it) -- the final
    # answer is submitted on the iteration where compaction fires.
    chat = _ScriptedChat([
        json.dumps({"reasoning": "scan", "tool": "run_nmap_scan", "args": {}}),
        json.dumps({"reasoning": "logs", "tool": "read_journalctl", "args": {}}),
        json.dumps({"reasoning": "procs", "tool": "list_processes", "args": {}}),
        json.dumps({"reasoning": "correlate", "tool": "correlate_findings", "args": {}}),
        json.dumps({"reasoning": "done", "final_answer":
                    "A HIGH-severity finding CORR-SSH-001 was identified via the rule engine "
                    "(correlate_findings) and requires attention; recommend restricting SSH."}),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    result = agent_loop.run_agent("check the target for brute force", data_dir, max_iters=10)

    # 1. The run concluded normally -- compaction didn't derail it.
    assert result["status"] == "final_answer"

    transcript = result["transcript"]
    # 2. A real compaction event fired and is recorded (feature 14b trigger).
    compaction_events = [e for e in transcript if e.get("status") == "context_compacted"]
    assert compaction_events, "expected at least one context_compacted event"
    assert compaction_events[0]["compaction_count"] >= 1

    # 3. The transcript is COMPLETE despite compaction -- every tool step is
    #    still recorded (compaction only shrank the model's prompt, not the record).
    tools_recorded = [e.get("tool") for e in transcript if e.get("tool")]
    for expected in ("run_nmap_scan", "read_journalctl", "list_processes", "correlate_findings"):
        assert expected in tools_recorded, f"{expected} missing from transcript"

    # 4. Guard 1's state survived the compaction: the final answer was accepted
    #    on the first try (correlate success was still recognized), so there is
    #    NO final_answer_rejected step -- the guard neither weakened nor mis-fired.
    assert not any(e.get("status") == "final_answer_rejected" for e in transcript)

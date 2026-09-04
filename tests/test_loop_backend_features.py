"""
Scripted-mock tests for the two cross-cutting backend features added for the
TUI (driven through the REAL run_agent loop, same style as
tests/test_agent_loop_guards.py):

  7c  -- run_agent returns real per-run token accounting (token_usage,
         context_tokens, context_window), accumulated from each LLM call.
  19b -- run_agent parses/sanitizes optional structured recommended_commands
         on a final_answer and returns them (also on the transcript's final
         entry), without changing any existing return key.

agent_chat is patched on kratos.agent.loop; the canned "model" also records
usage via llm_interface._record_usage so the loop's accumulation has real
numbers to fold in. correlate_findings' handler is swapped for a canned one so
guard 1 passes without a real SSH target.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from kratos.agent import loop as agent_loop
from kratos.agent.loop import _sanitize_recommended_commands
from kratos.agent.tools import TOOL_REGISTRY
from kratos import llm_interface as L


# ---------------------------------------------------------------------------
# 19b -- sanitizer unit tests
# ---------------------------------------------------------------------------
def test_sanitize_drops_malformed_and_normalizes_run_on():
    raw = [
        {"command": " sudo systemctl enable --now fail2ban ", "explanation": "start", "run_on": "target"},
        {"command": "", "explanation": "empty dropped"},
        {"explanation": "no command dropped"},
        "not a dict",
        {"command": "whoami", "run_on": "weird"},  # invalid run_on -> target
        {"command": "ss -tlnp", "run_on": "kratos_host"},
    ]
    out = _sanitize_recommended_commands(raw)
    assert [c["command"] for c in out] == [
        "sudo systemctl enable --now fail2ban",
        "whoami",
        "ss -tlnp",
    ]
    assert out[0]["run_on"] == "target"
    assert out[1]["run_on"] == "target"  # normalized from "weird"
    assert out[2]["run_on"] == "kratos_host"


def test_sanitize_non_list_returns_empty():
    assert _sanitize_recommended_commands(None) == []
    assert _sanitize_recommended_commands("nope") == []
    assert _sanitize_recommended_commands({}) == []


def test_sanitize_caps_count_and_length():
    raw = [{"command": "x" * 999} for _ in range(50)]
    out = _sanitize_recommended_commands(raw)
    assert len(out) == agent_loop._MAX_RECOMMENDED_COMMANDS
    assert all(len(c["command"]) <= agent_loop._MAX_COMMAND_LEN for c in out)


# ---------------------------------------------------------------------------
# End-to-end through run_agent
# ---------------------------------------------------------------------------
class _ScriptedChat:
    """Returns queued raw JSON responses, recording a real usage block per
    call so the loop's token accounting has something to fold in."""

    def __init__(self, responses: list[str], per_call_prompt_tokens: list[int]):
        self._responses = responses
        self._prompt_tokens = per_call_prompt_tokens
        self.n = 0

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int) -> str:
        i = self.n
        self.n += 1
        pt = self._prompt_tokens[i]
        L._record_usage({"prompt_tokens": pt, "completion_tokens": 20, "total_tokens": pt + 20})
        return self._responses[i]


@pytest.fixture
def canned_correlate():
    orig = TOOL_REGISTRY["correlate_findings"].handler

    def _fake(**kwargs: Any):
        return {
            "status": "ok",
            "findings": [{"id": "CORR-1", "title": "x", "severity": "medium"}],
            "staleness_warning": None,
        }

    TOOL_REGISTRY["correlate_findings"].handler = _fake
    try:
        yield
    finally:
        TOOL_REGISTRY["correlate_findings"].handler = orig


@pytest.fixture(autouse=True)
def _reset_usage():
    L.reset_session_token_usage()
    yield
    L.reset_session_token_usage()


def test_run_agent_returns_usage_and_commands(tmp_path: Path, canned_correlate, monkeypatch):
    responses = [
        json.dumps({"reasoning": "correlate", "tool": "correlate_findings", "args": {}}),
        json.dumps({
            "reasoning": "done",
            "final_answer": "fail2ban is inactive; enable it.",
            "recommended_commands": [
                {"command": "sudo systemctl enable --now fail2ban", "explanation": "start it", "run_on": "target"}
            ],
        }),
    ]
    scripted = _ScriptedChat(responses, per_call_prompt_tokens=[100, 200])
    monkeypatch.setattr(agent_loop, "agent_chat", scripted)

    res = agent_loop.run_agent("check fail2ban", tmp_path, max_iters=5)

    assert res["status"] == "final_answer"
    # 7c: accumulated across both calls; context_tokens is the LAST call's prompt.
    assert res["token_usage"]["total_tokens"] == (120 + 220)
    assert res["token_usage"]["prompt_tokens"] == 300
    assert res["context_tokens"] == 200
    assert res["context_window"] == L.get_context_window_tokens()
    # 19b: commands on both the return and the transcript's final entry.
    assert res["recommended_commands"][0]["command"] == "sudo systemctl enable --now fail2ban"
    assert res["transcript"][-1]["recommended_commands"][0]["run_on"] == "target"


def test_run_agent_final_answer_without_commands_is_empty_list(tmp_path: Path, canned_correlate, monkeypatch):
    responses = [
        json.dumps({"reasoning": "correlate", "tool": "correlate_findings", "args": {}}),
        json.dumps({"reasoning": "done", "final_answer": "All clear."}),
    ]
    scripted = _ScriptedChat(responses, per_call_prompt_tokens=[50, 60])
    monkeypatch.setattr(agent_loop, "agent_chat", scripted)

    res = agent_loop.run_agent("status check", tmp_path, max_iters=5)
    assert res["status"] == "final_answer"
    assert res["recommended_commands"] == []
    # usage still present and additive-safe
    assert res["token_usage"]["total_tokens"] == (70 + 80)


def test_run_agent_usage_present_even_on_llm_unavailable(tmp_path: Path, monkeypatch):
    # agent_chat returning None -> llm_unavailable, but the return still carries
    # the (zero) usage keys so a consumer can read them uniformly.
    monkeypatch.setattr(agent_loop, "agent_chat", lambda **kwargs: None)
    res = agent_loop.run_agent("x", tmp_path, max_iters=3)
    assert res["status"] == "llm_unavailable"
    assert res["token_usage"] == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    assert res["context_window"] == L.get_context_window_tokens()

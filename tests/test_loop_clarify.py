"""
Mid-investigation clarify action (agent/loop.py's {"clarify": {...}}).

Driven through the REAL run_agent loop with agent_chat scripted (same pattern as
test_agent_loop_guards.py). The clarify action is non-terminal and AUTHORIZES
NOTHING — it only pulls the user's intent back in as an Observation:
  - with a provider installed, the answer is fed back and the loop continues;
  - with no provider (CLI/MCP/headless), the model is told to proceed;
  - a malformed (question-less) clarify is corrected like a parse error;
  - a clarify on the final iteration is ignored (fallback answer), same as a
    late tool call / tool_proposal.

Each final answer deliberately contains "correlation" so Guard 1
(correlate_findings-required) treats it as an explained skip and doesn't reject
— these tests are about the clarify branch, not the guards.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from kratos.agent import loop as agent_loop

_FINAL = _final = (
    "Concluding: this was a routing clarification, no target correlation was required."
)


def _clarify_json(question: str = "Target or the Kratos host?",
                  options: list[dict[str, Any]] | None = None) -> str:
    body: dict[str, Any] = {"reasoning": "ambiguous", "clarify": {"question": question}}
    if options is not None:
        body["clarify"]["options"] = options
    return json.dumps(body)


def _final_json(text: str = _FINAL) -> str:
    return json.dumps({"reasoning": "done", "final_answer": text})


class ScriptedChat:
    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls: list[str] = []

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        self.calls.append(user_prompt)
        if not self.responses:
            raise AssertionError(f"ScriptedChat exhausted after {len(self.calls)} calls")
        return self.responses.pop(0)


@pytest.fixture(autouse=True)
def _clear_provider():
    agent_loop.set_clarify_provider(None)
    yield
    agent_loop.set_clarify_provider(None)


def _steps(result, status):
    return [s for s in result["transcript"] if s.get("status") == status]


def test_clarify_with_provider_feeds_answer_and_continues(tmp_path, monkeypatch):
    chat = ScriptedChat([
        _clarify_json(options=[{"label": "The monitored target", "recommended": True},
                               {"label": "This Kratos host"}]),
        _final_json(),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    seen: dict[str, Any] = {}

    def _provider(question, options):
        seen["question"] = question
        seen["options"] = options
        return "The monitored target"

    agent_loop.set_clarify_provider(_provider)

    result = agent_loop.run_agent("check things", tmp_path, max_iters=5)
    assert result["status"] == "final_answer"
    assert seen["question"] == "Target or the Kratos host?"
    assert [o["label"] for o in seen["options"]] == ["The monitored target", "This Kratos host"]
    clar = _steps(result, "clarify")
    assert len(clar) == 1 and clar[0]["clarify_answer"] == "The monitored target"
    # The answer was fed back into the NEXT prompt.
    assert "The user answered your question: The monitored target" in chat.calls[1]


def test_clarify_without_provider_proceeds(tmp_path, monkeypatch):
    chat = ScriptedChat([_clarify_json(), _final_json()])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    # provider left as None by the autouse fixture

    result = agent_loop.run_agent("check things", tmp_path, max_iters=5)
    assert result["status"] == "final_answer"
    clar = _steps(result, "clarify")
    assert len(clar) == 1 and clar[0]["clarify_answer"] is None
    assert "No interactive user is available" in chat.calls[1]


def test_clarify_provider_exception_treated_as_no_answer(tmp_path, monkeypatch):
    chat = ScriptedChat([_clarify_json(), _final_json()])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)

    def _boom(question, options):
        raise RuntimeError("provider blew up")

    agent_loop.set_clarify_provider(_boom)

    result = agent_loop.run_agent("check things", tmp_path, max_iters=5)
    assert result["status"] == "final_answer"          # run survives a broken provider
    assert _steps(result, "clarify")[0]["clarify_answer"] is None
    assert "did not choose an answer" in chat.calls[1]


def test_clarify_malformed_question_is_corrected(tmp_path, monkeypatch):
    chat = ScriptedChat([json.dumps({"reasoning": "x", "clarify": {"question": "  "}}), _final_json()])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    agent_loop.set_clarify_provider(lambda q, o: "unused")

    result = agent_loop.run_agent("check things", tmp_path, max_iters=5)
    assert result["status"] == "final_answer"
    assert _steps(result, "clarify_malformed")
    assert "clarify action needs a non-empty" in chat.calls[1]


def test_clarify_on_final_iteration_is_ignored(tmp_path, monkeypatch):
    chat = ScriptedChat([_clarify_json()])  # only one call — it's the final iteration
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    called = {"n": 0}
    agent_loop.set_clarify_provider(lambda q, o: called.__setitem__("n", called["n"] + 1) or "x")

    result = agent_loop.run_agent("check things", tmp_path, max_iters=1)
    assert result["status"] == "max_iters_reached"
    assert result.get("final_answer")                      # fallback synthesized
    assert _steps(result, "final_iteration_clarify_ignored")
    assert called["n"] == 0                                 # provider never invoked on final iter

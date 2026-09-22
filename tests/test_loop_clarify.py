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
        self.system_prompts: list[str] = []

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        self.calls.append(user_prompt)
        self.system_prompts.append(system_prompt)
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


def test_clarify_budget_allows_up_to_the_cap(tmp_path, monkeypatch):
    """Lever 2: a genuinely big/vague task may ask more than one question in
    a single run, up to MAX_CLARIFY_QUESTIONS -- each one reaches the
    provider and gets fed back normally."""
    n = agent_loop.MAX_CLARIFY_QUESTIONS
    chat = ScriptedChat([_clarify_json(question=f"Q{i}") for i in range(1, n + 1)] + [_final_json()])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    answers: list[str] = []

    def _provider(question, options):
        answers.append(question)
        return f"answer to {question}"

    agent_loop.set_clarify_provider(_provider)

    result = agent_loop.run_agent("check things", tmp_path, max_iters=n + 3)
    assert result["status"] == "final_answer"
    assert answers == [f"Q{i}" for i in range(1, n + 1)]
    clar = _steps(result, "clarify")
    assert len(clar) == n
    assert not _steps(result, "clarify_budget_exhausted")


def test_clarify_budget_exhausted_is_corrected_not_asked(tmp_path, monkeypatch):
    """A clarify attempted PAST the cap is corrected like a malformed one --
    the provider is never called for it, and the model is told to proceed."""
    n = agent_loop.MAX_CLARIFY_QUESTIONS
    chat = ScriptedChat(
        [_clarify_json(question=f"Q{i}") for i in range(1, n + 1)]
        + [_clarify_json(question="one too many"), _final_json()]
    )
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    call_count = {"n": 0}

    def _provider(question, options):
        call_count["n"] += 1
        return "some answer"

    agent_loop.set_clarify_provider(_provider)

    result = agent_loop.run_agent("check things", tmp_path, max_iters=n + 5)
    assert result["status"] == "final_answer"
    assert call_count["n"] == n                      # the (n+1)th never reached the provider
    exhausted = _steps(result, "clarify_budget_exhausted")
    assert len(exhausted) == 1
    assert exhausted[0]["attempted_clarify"]["question"] == "one too many"
    assert f"limit ({n} per run)" in chat.calls[-1]


def test_clarify_budget_exhausted_twice_forces_an_early_conclusion(tmp_path, monkeypatch):
    """Review finding #2: a stubborn model that keeps asking PAST the budget
    doesn't get to burn the rest of max_iters doing it -- a second over-budget
    attempt forces a conclusion right there, from whatever transcript exists
    so far, instead of continuing to correct-and-continue indefinitely."""
    n = agent_loop.MAX_CLARIFY_QUESTIONS
    # n legitimate questions, then TWO more attempts past the budget. If the
    # loop kept tolerating these it would need a 4th response (_final_json())
    # to conclude -- ScriptedChat raising on exhaustion proves that never
    # gets reached; the 2nd over-budget attempt ends the run by itself.
    chat = ScriptedChat(
        [_clarify_json(question=f"Q{i}") for i in range(1, n + 1)]
        + [_clarify_json(question="first over-budget try"),
           _clarify_json(question="second over-budget try")]
    )
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    call_count = {"n": 0}
    agent_loop.set_clarify_provider(lambda q, o: call_count.__setitem__("n", call_count["n"] + 1) or "x")

    result = agent_loop.run_agent("check things", tmp_path, max_iters=n + 10)
    assert result["status"] == "max_iters_reached"          # forced, not organic
    assert call_count["n"] == n                              # neither over-budget try reached the provider
    assert len(chat.calls) == n + 2                          # exactly 2 over-budget attempts happened, not more
    forced = _steps(result, "clarify_budget_exhausted_forced_conclusion")
    assert len(forced) == 1
    assert forced[0]["attempted_clarify"]["question"] == "second over-budget try"
    assert "[NOTE:" in result["final_answer"]
    assert "kept asking clarifying questions" in result["final_answer"]


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


# --- provider-aware system prompt (review finding: CLI/MCP/scheduled runs
# never install a provider, so the prompt itself must not invite a clarify
# attempt nobody can answer -- checked at build_system_prompt() time, once
# per run_agent call, same as the rest of the prompt) ------------------------

def test_system_prompt_omits_clarify_guidance_with_no_provider():
    agent_loop.set_clarify_provider(None)
    prompt = agent_loop.build_system_prompt()
    assert "You may ask the user a clarifying question" not in prompt
    assert '"clarify": {"question"' not in prompt          # the invitation/schema example is gone
    assert "Do NOT emit" in prompt and '{"clarify": ...}' in prompt  # still named, only to forbid it
    assert "No interactive user is available to answer questions during this run" in prompt


def test_system_prompt_includes_clarify_guidance_with_provider():
    agent_loop.set_clarify_provider(lambda q, o: "x")
    prompt = agent_loop.build_system_prompt()
    assert "You may ask the user a clarifying question" in prompt
    assert f"capped at {agent_loop.MAX_CLARIFY_QUESTIONS} per investigation" in prompt


def test_headless_run_never_sees_clarify_guidance_in_any_call(tmp_path, monkeypatch):
    """End-to-end (not just build_system_prompt in isolation): a real
    no-provider run_agent call never sends a system prompt inviting a
    clarify, across every iteration's call, not just the first."""
    chat = ScriptedChat([_final_json(), _final_json()])  # in case of >1 call
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    # provider left as None by the autouse fixture

    result = agent_loop.run_agent("check things", tmp_path, max_iters=5)
    assert result["status"] == "final_answer"
    assert chat.system_prompts  # at least one call happened
    for sp in chat.system_prompts:
        assert "You may ask the user a clarifying question" not in sp

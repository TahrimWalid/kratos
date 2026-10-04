"""A Yes/No answer to "more/fewer ... than ...?" must match Kratos's comparison verdict.
Seen live (demo pass 4): "were there more failed logins this week than last week?" ->
"Yes, there were fewer ... (136 vs 257)"."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.timewin.yes_no import yes_no_problem

W = {"w1": SimpleNamespace(phrase="this week", label="this week so far"),
     "w2": SimpleNamespace(phrase="last week", label="last calendar week")}
DOWN = [{"from": "w2", "to": "w1", "verdict": "decrease"}]
GOAL = "were there more failed logins this week than last week?"


def test_yes_to_more_when_it_went_down_is_wrong():
    p = yes_no_problem(GOAL, "Yes, there were fewer failed logins this week.", DOWN, W)
    assert p["expected"] == "No" and p["got"] == "Yes" and "went down" in p["why"]


def test_correct_answers_and_unreadable_cases_pass():
    assert yes_no_problem(GOAL, "No, there were fewer this week.", DOWN, W) is None
    assert yes_no_problem("were there fewer failed logins this week than last week?", "Yes, fewer.", DOWN, W) is None
    # subject after "than" flips the reading: last week WAS higher than this week
    assert yes_no_problem("were there more failed logins last week than this week?", "Yes.", DOWN, W) is None
    assert yes_no_problem(GOAL, "There were fewer this week.", DOWN, W) is None          # no Yes/No opening
    assert yes_no_problem("how many failed logins this week?", "Yes.", DOWN, W) is None  # not a more/than question
    flat = [{"from": "w2", "to": "w1", "verdict": "no_meaningful_change"}]
    assert yes_no_problem(GOAL, "Yes, slightly more.", flat, W)["expected"] == "No"
    unsure = [{"from": "w2", "to": "w1", "verdict": "not_comparable"}]
    assert yes_no_problem(GOAL, "Yes.", unsure, W) is None


def test_note_tags_before_the_opening_are_skipped():
    assert yes_no_problem(GOAL, "[NOTE: partial coverage.] Yes, fewer.", DOWN, W)["got"] == "Yes"


def _compare(**kw):
    return {"status": "ok", "metric": "ssh_failed_logins",
            "pairs": [{"from": "w2", "to": "w1", "verdict": "decrease", "rate_change_percent": -57.4}]}


def _correlate(**kw):
    return {"status": "ok", "findings": []}


def test_loop_rejects_a_contradicting_yes_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(TOOL_REGISTRY["compare_periods"], "handler", _compare)
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler", _correlate)
    wrong = json.dumps({"reasoning": "r", "final_answer": "Yes, there were fewer failed logins this week than last week."})
    right = json.dumps({"reasoning": "r", "final_answer": "No, there were fewer failed logins this week than last week."})
    replies = [json.dumps({"reasoning": "r", "tool": "compare_periods", "args": {"metric": "ssh_failed_logins", "windows": ["w1", "w2"]}}),
               json.dumps({"reasoning": "r", "tool": "correlate_findings", "args": {}}), wrong, right]
    monkeypatch.setattr(agent_loop, "agent_chat", lambda *a, **k: replies.pop(0) if replies else right)
    result = agent_loop.run_agent(GOAL, tmp_path, max_iters=10, timezone="UTC", now=1791100000.0)
    rejected = [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    # (the mocked comparison never marks its windows queried, so the time-scope guards
    # also speak up here; only Guard 11 is under test)
    hits = [s for s in rejected if "yes_no_contradicts_comparison" in s["violations"]]
    assert len(hits) == 1 and hits[0] is rejected[0]
    assert "No, there were fewer" in result["final_answer"]
    assert "so the answer to the question is" not in result["final_answer"]

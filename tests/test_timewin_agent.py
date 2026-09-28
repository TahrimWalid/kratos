"""Agent integration of the time layer (docs/time_window_design.md §2C, §4, §12 item 10,
§15): goal pre-scan, clarify-or-investigate-every-reading, the TIME CONTEXT block, the
double-entry cross-check, Guard 6 (time scope), per-session named windows, MCP timezone.
No real LLM or SSH -- the model is scripted and the time-aware tool is a stand-in that
goes through the real tool-boundary resolver."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.timewin.agentwin import prepare_time_context, render_time_block
from kratos.timewin.toolwin import resolve_tool_window
from kratos.timewin.windows import TimeIntentError

NY = "America/New_York"
NOW = datetime(2026, 3, 8, 10, 30, tzinfo=ZoneInfo(NY)).timestamp()


class ScriptedChat:
    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls: list[str] = []

    def __call__(self, *, system_prompt: str, user_prompt: str, **_kw) -> str:
        self.calls.append(user_prompt)
        return self.responses.pop(0)


def _tool(name: str, args: dict[str, Any] | None = None) -> str:
    return json.dumps({"reasoning": "r", "tool": name, "args": args or {}})


def _final(text: str) -> str:
    return json.dumps({"reasoning": "done", "final_answer": text})


@pytest.fixture
def fake_journal(monkeypatch):
    """read_journalctl stand-in: resolves its window through the REAL tool-boundary
    helper (so ids, the cross-check and 'queried' tracking are all exercised)."""
    seen: list[dict[str, Any]] = []

    def handler(data_dir, unit=None, since=None, lines=200, until=None, window=None):
        try:
            tw = resolve_tool_window(window=window, since=since, until=until, tool="read_journalctl")
        except TimeIntentError as e:
            return {"status": "error", "observation": f"invalid time window: {e}"}
        seen.append({"window": tw.window.id if tw else None})
        return {"status": "ok", "entries": [], "window": {"id": tw.window.id, "chip": tw.window.summary()} if tw else None}

    monkeypatch.setattr(TOOL_REGISTRY["read_journalctl"], "handler", handler)
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **k: {"findings": [], "count": 0, "staleness_warning": None})
    agent_loop.set_clarify_provider(None)
    yield seen
    agent_loop.set_clarify_provider(None)


# ---------------------------------------------------------------------------
# pre-scan / TIME CONTEXT
# ---------------------------------------------------------------------------
def test_goal_periods_are_resolved_by_code_and_listed_with_defaults(tmp_path):
    ctx, _ = prepare_time_context("compare failed logins last week with last month", tmp_path,
                                  timezone_name=NY, now=NOW)
    assert ctx.goal_ids == ["w1", "w2"]
    block = render_time_block(ctx)
    assert "w1 last 7 days" in block and "w2 February 2026" in block
    assert "rolling" in block and "previous calendar month" in block  # defaults disclosed
    assert "never compute dates" in block


def test_ambiguous_phrase_asks_the_user_when_someone_can_answer(tmp_path):
    asked = []

    def provider(q, opts):
        asked.append((q, [o["label"] for o in opts]))
        return opts[1]["label"]

    ctx, log = prepare_time_context("anything on 03/04?", tmp_path, timezone_name=NY, now=NOW, clarify=provider)
    assert asked and "03/04" in asked[0][0]
    assert len(ctx.goal_ids) == 1 and ctx.unresolved == [] and log[0]["answer"]


def test_free_text_clarification_is_resolved_deterministically(tmp_path):
    ctx, _ = prepare_time_context("what happened 3 hours ago", tmp_path, timezone_name=NY, now=NOW,
                                  clarify=lambda q, o: "the last 3 hours")
    w = ctx.windows[ctx.goal_ids[0]]
    assert w.end_utc - w.start_utc == 3 * 3600


def test_ambiguous_phrase_with_nobody_to_ask_investigates_every_reading(tmp_path):
    ctx, _ = prepare_time_context("anything on 03/04?", tmp_path, timezone_name=NY, now=NOW)
    assert len(ctx.goal_ids) == 2
    assert ctx.unresolved[0]["status"] == "ambiguous"
    assert "Investigate EACH of w1, w2" in render_time_block(ctx)


def test_future_phrase_is_flagged_not_resolved(tmp_path):
    ctx, _ = prepare_time_context("any attacks next week?", tmp_path, timezone_name=NY, now=NOW)
    assert ctx.goal_ids == [] and ctx.unresolved[0]["status"] == "future"
    assert "cannot be investigated" in render_time_block(ctx)


def test_invalid_timezone_refuses_to_start(tmp_path):
    out = agent_loop.run_agent("check logins yesterday", tmp_path, timezone="Mars/Olympus")
    assert out["status"] == "invalid_input" and "unknown timezone" in out["final_answer"]


# ---------------------------------------------------------------------------
# run_agent end-to-end with a scripted model
# ---------------------------------------------------------------------------
def test_guard6_rejects_an_answer_that_never_queried_the_goal_period(tmp_path, fake_journal, monkeypatch):
    chat = ScriptedChat([
        _tool("correlate_findings"),
        _final("No failed logins in the last 24 hours."),          # rejected: w1 never queried
        _tool("read_journalctl", {"window": {"id": "w1"}}),
        _final("No failed logins in the last 24 hours (w1)."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("any failed logins in the last 24 hours?", tmp_path, timezone=NY, now=NOW)
    rejected = [s for s in out["transcript"] if s.get("status") == "final_answer_rejected"]
    assert rejected and "time_scope_not_queried" in rejected[0]["violations"]
    assert out["status"] == "final_answer" and "[NOTE:" not in out["final_answer"]
    assert out["time"]["queried"] == {"w1": ["read_journalctl"]}
    assert "TIME CONTEXT" in chat.calls[0] and "w1 last 24 hours" in chat.calls[0]


def test_guard6_notes_the_answer_when_the_model_never_complies(tmp_path, fake_journal, monkeypatch):
    chat = ScriptedChat([_tool("correlate_findings")] + [_final("All quiet last week.")] * 5)
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("anything suspicious last week?", tmp_path, timezone=NY, now=NOW)
    assert "no data for that period was queried" in out["final_answer"]


def test_cross_check_rejects_a_near_miss_of_the_goal_window(tmp_path, fake_journal, monkeypatch):
    # goal says "last week" (rolling 7 days); model builds the calendar week instead
    chat = ScriptedChat([
        _tool("read_journalctl", {"window": {"kind": "calendar", "unit": "week", "offset": -1}}),
        _tool("read_journalctl", {"window": {"id": "w1"}}),
        _tool("correlate_findings"),
        _final("Nothing unusual in the last 7 days (w1)."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("anything suspicious last week?", tmp_path, timezone=NY, now=NOW)
    first = out["transcript"][0]["observation"]
    assert "different reading of the goal's" in json.dumps(first) and '\\"id\\": \\"w1\\"' in json.dumps(first)
    assert fake_journal == [{"window": "w1"}]


def test_model_can_add_other_windows_via_intents(tmp_path, fake_journal, monkeypatch):
    chat = ScriptedChat([
        _tool("read_journalctl", {"window": {"id": "w1"}}),
        _tool("read_journalctl", {"window": {"kind": "relative_to", "window": "w1",
                                             "shift": {"amount": -1, "unit": "month"}}}),
        _tool("correlate_findings"),
        _final("Compared w1 with the same span a month earlier (w2)."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    out = agent_loop.run_agent("failed logins this month so far", tmp_path, timezone=NY, now=NOW)
    assert [f["window"] for f in fake_journal] == ["w1", "w2"]
    w2 = next(w for w in out["time"]["windows"] if w["id"] == "w2")
    assert w2["start_iso"].startswith("2026-02-01")


def test_saved_windows_persist_across_turns_of_a_session(tmp_path, fake_journal, monkeypatch):
    chat = ScriptedChat([
        _tool("read_journalctl", {"window": {"kind": "local_range", "start": "2026-03-07T18:40",
                                             "end": "2026-03-07T18:55", "save_as": "incident"}}),
        _tool("correlate_findings"),
        _final("Burst found in the incident window."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    agent_loop.run_agent("look at 18:40-18:55 yesterday", tmp_path, timezone=NY, now=NOW, session_id="s1")
    chat2 = ScriptedChat([
        _tool("read_journalctl", {"window": "incident"}),
        _tool("correlate_findings"),
        _final("Re-checked the incident window."),
    ])
    monkeypatch.setattr(agent_loop, "agent_chat", chat2)
    out = agent_loop.run_agent("recheck the incident window", tmp_path, timezone=NY, now=NOW + 86400, session_id="s1")
    assert "incident =" in chat2.calls[0]  # offered in the next turn's TIME CONTEXT
    assert out["status"] == "final_answer" and fake_journal[-1]["window"]


def test_mcp_rejects_unknown_timezone():
    from kratos import mcp_server

    with pytest.raises(ValueError, match="unknown timezone"):
        mcp_server.kratos_investigate("check yesterday", "10.0.0.1", timezone="Nowhere/Nope")

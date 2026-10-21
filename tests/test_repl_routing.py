"""The classic REPL routes a message with the TUI's router (found during B.3: its own
one-sentinel prompt answered "has anyone been trying to log in?" as small talk)."""
from __future__ import annotations

import pytest

from kratos.cli import repl
from kratos.tui_mk2 import command_intent as ci


@pytest.mark.parametrize("result,expected", [
    (ci.RouteResult(kind="investigate"), (True, None)),
    (ci.RouteResult(kind="investigate_host"), (True, None)),
    (ci.RouteResult(kind="clarify_host"), (True, None)),
    (ci.RouteResult(kind="chat", reply=" hi there "), (False, "hi there")),
    (ci.RouteResult(kind="failed", reason="503"), (None, "503")),
])
def test_route_kinds_map_to_the_repls_contract(monkeypatch, result, expected):
    monkeypatch.setattr(ci, "route_message", lambda goal, ctx="", **kw: result)
    assert repl._route_input("x") == expected


def test_a_control_request_points_at_the_slash_command(monkeypatch):
    monkeypatch.setattr(ci, "route_message", lambda goal, ctx="", **kw: ci.RouteResult(kind="command", command="model"))
    investigate, reply = repl._route_input("switch the model")
    assert investigate is False and "/model" in reply


def test_the_login_question_is_investigated_through_the_real_router(monkeypatch):
    seen = {}

    def fake_chat(system_prompt, prompt, **kw):
        seen["system"] = system_prompt
        return "INVESTIGATE"

    monkeypatch.setattr(ci, "agent_chat", fake_chat)
    assert repl._route_input("has anyone been trying to log in?") == (True, None)
    assert seen["system"] == ci._system_prompt()          # the TUI's routing prompt, not a second one

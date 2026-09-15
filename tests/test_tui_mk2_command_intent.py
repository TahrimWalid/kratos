"""
Conversational command routing (tui_mk2/command_intent.py).

route_message makes one no-tools LLM call classifying the user's message into a
control request / investigation / chat, with a 'failed' outcome when the LLM is
unreachable. agent_chat is mocked so these are deterministic and offline. The
key safety property (this runs on user input only, never tool output, and is not
a TOOL_REGISTRY entry) is structural — documented in the module — not asserted here.
"""
from __future__ import annotations

import pytest

from kratos.tui_mk2 import command_intent as ci


@pytest.mark.parametrize("raw,name,args", [
    ("COMMAND: model | qwen2.5:7b", "model", "qwen2.5:7b"),
    ("COMMAND: target | 10.0.0.5", "target", "10.0.0.5"),
    ("COMMAND: report |", "report", ""),
    ("COMMAND: help", "help", ""),
    ("command: timezone | Asia/Dhaka", "timezone", "Asia/Dhaka"),  # case-insensitive prefix
])
def test_parse_command_forms(raw, name, args):
    r = ci._parse(raw)
    assert r.kind == "command" and r.command == name and r.args == args


def test_parse_investigate():
    assert ci._parse("INVESTIGATE").kind == "investigate"
    assert ci._parse("investigate.").kind == "investigate"  # tolerant of trailing period


def test_parse_investigate_host():
    # Self-host investigation is a distinct kind; the host sentinel is NOT
    # mistaken for the plain one (which is a prefix of it).
    assert ci._parse("INVESTIGATE_HOST").kind == "investigate_host"
    assert ci._parse("investigate_host.").kind == "investigate_host"
    assert ci._parse("INVESTIGATE").kind == "investigate"  # still the target


def test_route_message_investigate_host(monkeypatch):
    monkeypatch.setattr(ci, "agent_chat", lambda *a, **k: "INVESTIGATE_HOST")
    assert ci.route_message("how's your own host doing?").kind == "investigate_host"


def test_parse_preset_new():
    r = ci._parse("PRESET_NEW: weekly-audit | review ssh and firewall hardening")
    assert r.kind == "preset_new"
    assert r.preset_name == "weekly-audit"
    assert r.preset_goal == "review ssh and firewall hardening"


def test_parse_preset_run():
    r = ci._parse("PRESET_RUN: nightly")
    assert r.kind == "preset_run" and r.preset_name == "nightly"


def test_parse_preset_new_malformed_falls_through_to_chat():
    # No goal after the pipe -> don't save a goalless preset; treat as chat.
    assert ci._parse("PRESET_NEW: onlyname").kind == "chat"
    assert ci._parse("PRESET_RUN:").kind == "chat"


def test_capabilities_are_in_system_prompt():
    # The capability-awareness nudge must actually be present (regression guard
    # for the "I don't support presets" false-denial bug).
    prompt = ci._system_prompt()
    assert "/preset-new" in prompt
    assert "PRESET_NEW:" in prompt and "PRESET_RUN:" in prompt


def test_parse_clarify_host():
    assert ci._parse("CLARIFY_HOST").kind == "clarify_host"
    assert ci._parse("clarify_host.").kind == "clarify_host"
    # Not confused with the other investigate sentinels.
    assert ci._parse("INVESTIGATE").kind == "investigate"
    assert ci._parse("INVESTIGATE_HOST").kind == "investigate_host"


def test_route_message_clarify_host(monkeypatch):
    monkeypatch.setattr(ci, "agent_chat", lambda *a, **k: "CLARIFY_HOST")
    assert ci.route_message("check port 3000").kind == "clarify_host"


def test_parse_unknown_command_falls_through_to_chat():
    # A control name that isn't in the allowed set must NOT be acted on.
    r = ci._parse("COMMAND: shutdown | now")
    assert r.kind == "chat"


def test_parse_plain_chat():
    r = ci._parse("Hi! I'm doing well, how can I help?")
    assert r.kind == "chat" and "Hi!" in r.reply


def test_route_message_command(monkeypatch):
    monkeypatch.setattr(ci, "agent_chat", lambda *a, **k: "COMMAND: target | 10.0.0.5")
    r = ci.route_message("point yourself at 10.0.0.5")
    assert r.kind == "command" and r.command == "target" and r.args == "10.0.0.5"


def test_route_message_investigate(monkeypatch):
    monkeypatch.setattr(ci, "agent_chat", lambda *a, **k: "INVESTIGATE")
    assert ci.route_message("check the target for brute force").kind == "investigate"


def test_route_message_chat(monkeypatch):
    monkeypatch.setattr(ci, "agent_chat", lambda *a, **k: "Hello there!")
    r = ci.route_message("hi")
    assert r.kind == "chat" and r.reply == "Hello there!"


def test_route_message_failed_when_llm_unreachable(monkeypatch):
    monkeypatch.setattr(ci, "agent_chat", lambda *a, **k: None)
    r = ci.route_message("anything")
    assert r.kind == "failed" and r.reason


def test_model_and_target_need_approval_others_dont():
    assert ci.COMMANDS_NEEDING_APPROVAL == frozenset({"model", "target"})
    for name in ("report", "tools", "help", "rename", "timezone"):
        assert name not in ci.COMMANDS_NEEDING_APPROVAL


def test_parse_pipeline_describe_nudge():
    r = ci._parse("PIPELINE_DESCRIBE: scan then look up the top source IP")
    assert r.kind == "pipeline_suggest"
    assert r.preset_goal == "scan then look up the top source IP"
    # No goal still surfaces the nudge (the flow prompts for a description).
    assert ci._parse("PIPELINE_DESCRIBE:").kind == "pipeline_suggest"


def test_pipeline_describe_capability_in_prompt():
    sys = ci._system_prompt()
    assert "PIPELINE_DESCRIBE" in sys and "/preset-describe" in sys

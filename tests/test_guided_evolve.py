"""
Headless tests for the UI-agnostic guided-build core (agent/guided_evolve.py, A7).

Uses a scripted FakePrompter (no Textual, no real LLM, no sandbox) and mocks the
heavy pipeline (run_self_write_loop) so the guided FLOW + edge cases are tested
deterministically. The pipeline itself is tested elsewhere / for real; here we
verify the surface: claims extraction faithfulness, name-collision handling, the
draft/edit/discard branches, cancels, and outcome->result mapping.
"""
from __future__ import annotations

import types
from pathlib import Path
from unittest.mock import patch

import pytest

from kratos.agent import guided_evolve as G
from kratos.agent.guided_evolve import (
    GuidedPrompter,
    describe_harness_claims,
    check_name_collision,
    run_guided_build,
)


class FakePrompter(GuidedPrompter):
    """Scripted answers; records what was said/shown. ask_* pop from a queue;
    an empty text queue returns the default (simulates pressing Enter)."""

    def __init__(self, texts=None, confirms=None, choices=None):
        self.texts = list(texts or [])
        self.confirms = list(confirms or [])
        self.choices = list(choices or [])
        self.said: list[tuple[str, str]] = []
        self.shown: list = []

    def say(self, message, kind="note"):
        self.said.append((kind, message))

    def show(self, renderable):
        self.shown.append(renderable)

    def ask_text(self, title, hint="", default=""):
        return self.texts.pop(0) if self.texts else default

    def ask_confirm(self, title, body=""):
        return self.confirms.pop(0) if self.confirms else False

    def ask_choice(self, title, options, subtitle=""):
        return self.choices.pop(0) if self.choices else None

    def all_text(self) -> str:
        return "\n".join(m for _, m in self.said)


# --------------------------------------------------------------------------
# describe_harness_claims -- faithfulness
# --------------------------------------------------------------------------

_TARGET_HARNESS = '''
from unittest.mock import patch
from kratos.adapters.ssh_remote import SSHResult
import pytest

TOOL_NAME = "list_sudo"

@pytest.fixture
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY
    assert TOOL_NAME in TOOL_REGISTRY, "must register"
    return TOOL_REGISTRY[TOOL_NAME].handler

def test_it(registered_handler):
    with patch("kratos.adapters.ssh_remote.run_remote_command",
               return_value=SSHResult(ok=True, returncode=0, stdout="sudo:x:27:alice,bob", stderr="")):
        result = registered_handler()
    assert isinstance(result, dict)
    assert "users" in result, "Result must list users with sudo access"
    assert len(result["users"]) >= 1
    assert "root" in result["users"]
'''


def test_claims_use_human_message_when_present():
    c = describe_harness_claims(_TARGET_HARNESS)
    assert "Result must list users with sudo access" in c.claims
    # the fixture's `assert TOOL_NAME in TOOL_REGISTRY, "must register"` is
    # boilerplate, NOT a behavioral claim -- must be excluded.
    assert "must register" not in c.all_text() if hasattr(c, "all_text") else True
    assert not any("register" in x.lower() for x in c.claims)


def test_claims_gloss_structural_asserts():
    c = describe_harness_claims(_TARGET_HARNESS)
    assert any("is a dict" in x for x in c.claims)
    assert any("at least" in x and "item" in x for x in c.claims)
    # membership on a subscript renders faithfully (not "the result includes")
    assert any("result['users'] includes 'root'" == x for x in c.claims)


def test_claims_detect_target_facing_and_assumed_output():
    c = describe_harness_claims(_TARGET_HARNESS)
    assert c.is_target_facing is True
    assert "sudo:x:27:alice,bob" in c.assumed_target_output


def test_claims_unrecognized_assert_shown_verbatim_not_invented():
    src = '''
def test_x(registered_handler):
    result = registered_handler()
    assert result["a"] + result["b"] > result["c"] * 2
'''
    c = describe_harness_claims(src)
    # a compound arithmetic comparison isn't confidently glossable -> verbatim
    assert c.verbatim_checks
    assert any("result['a']" in v for v in c.verbatim_checks)


def test_claims_parse_error_is_reported_not_raised():
    c = describe_harness_claims("def broken(:\n")
    assert c.parse_error is not None
    assert c.claims == []


# --------------------------------------------------------------------------
# check_name_collision
# --------------------------------------------------------------------------

def test_collision_none_when_unknown():
    with patch("kratos.agent.tools.TOOL_REGISTRY", {}):
        nc = check_name_collision("brand_new_tool")
    assert nc.exists is False and nc.kind == "none"


def test_collision_builtin():
    with patch("kratos.agent.tools.TOOL_REGISTRY", {"run_nmap_scan": object()}), \
         patch("kratos.agent.self_write_loop._read_metadata", return_value={}):
        nc = check_name_collision("run_nmap_scan")
    assert nc.exists and nc.kind == "builtin"


def test_collision_kept():
    with patch("kratos.agent.tools.TOOL_REGISTRY", {"my_kept": object()}), \
         patch("kratos.agent.self_write_loop._read_metadata",
               return_value={"my_kept": {"kept_at": "2026-01-01T00:00:00"}}):
        nc = check_name_collision("my_kept")
    assert nc.exists and nc.kind == "kept" and nc.kept_at == "2026-01-01T00:00:00"


# --------------------------------------------------------------------------
# run_guided_build -- flow + edge cases
# --------------------------------------------------------------------------

def _fake_outcome(status, tool_name=None, requires_approval=None, kept_path=None):
    kd = None
    if tool_name is not None:
        kd = types.SimpleNamespace(tool_name=tool_name, requires_approval=requires_approval)
    return types.SimpleNamespace(status=status, keep_decision=kd, kept_path=kept_path)


@pytest.fixture
def no_collision():
    with patch.object(G, "check_name_collision", return_value=G.NameCollision(exists=False, kind="none")):
        yield


def test_existing_harness_confirm_and_keep(tmp_path, monkeypatch, no_collision):
    hpath = tmp_path / "test_list_sudo.py"
    hpath.write_text(_TARGET_HARNESS, encoding="utf-8")
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)

    prompter = FakePrompter(confirms=[True])  # "build against this test?" yes
    with patch("kratos.agent.self_write_loop.run_self_write_loop",
               return_value=_fake_outcome("approved", "list_sudo", True, tmp_path / "k.py")):
        res = run_guided_build("list sudo users", prompter, suggested_name="list_sudo")

    assert res.status == "kept"
    assert res.tool_name == "list_sudo"
    assert res.requires_approval is True
    # the plain-English claims were shown (a Panel), not just raw source
    assert prompter.shown, "claims panel should have been shown"


def test_cancel_at_naming(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    prompter = FakePrompter(texts=[None])  # naming prompt cancelled
    res = run_guided_build("some idea", prompter, suggested_name="some_tool")
    assert res.status == "cancelled"


def test_name_collision_declined_aborts(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    with patch.object(G, "check_name_collision",
                      return_value=G.NameCollision(exists=True, kind="builtin")):
        prompter = FakePrompter(confirms=[False])  # decline "continue with this name?"
        res = run_guided_build("idea", prompter, suggested_name="run_nmap_scan")
    assert res.status == "cancelled"


def test_missing_harness_draft_then_edit_writes_and_stops(tmp_path, monkeypatch, no_collision):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    prompter = FakePrompter(confirms=[True], choices=["edit"])  # draft? yes; then edit
    with patch.object(G, "_draft_evolve_harness", return_value=_TARGET_HARNESS):
        res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == "no_harness"
    saved = tmp_path / "test_list_sudo.py"
    assert saved.exists()
    assert saved.read_text() == _TARGET_HARNESS


def test_missing_harness_draft_then_build(tmp_path, monkeypatch, no_collision):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    prompter = FakePrompter(confirms=[True], choices=["build"])
    with patch.object(G, "_draft_evolve_harness", return_value=_TARGET_HARNESS), \
         patch("kratos.agent.self_write_loop.run_self_write_loop",
               return_value=_fake_outcome("approved", "list_sudo", False, tmp_path / "k.py")):
        res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == "kept" and res.requires_approval is False
    assert (tmp_path / "test_list_sudo.py").exists()


def test_missing_harness_discard_writes_nothing(tmp_path, monkeypatch, no_collision):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    prompter = FakePrompter(confirms=[True], choices=["discard"])
    with patch.object(G, "_draft_evolve_harness", return_value=_TARGET_HARNESS):
        res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == "cancelled"
    assert not (tmp_path / "test_list_sudo.py").exists()


def test_missing_harness_declined_draft_falls_back_to_template(tmp_path, monkeypatch, no_collision):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    # decline drafting -> static template; then edit to save it
    prompter = FakePrompter(confirms=[False], choices=["edit"])
    res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == "no_harness"
    saved = tmp_path / "test_list_sudo.py"
    assert saved.exists()
    assert 'TOOL_NAME = "list_sudo"' in saved.read_text()


@pytest.mark.parametrize("loop_status,mapped", [
    ("write_failed", "write_failed"),
    ("stalled_no_variation", "stalled"),
    ("exhausted_retries", "exhausted"),
    ("infra_error", "infra_error"),
    ("denied", "declined"),
])
def test_recovery_guidance_per_failure(tmp_path, monkeypatch, no_collision, loop_status, mapped):
    hpath = tmp_path / "test_list_sudo.py"
    hpath.write_text(_TARGET_HARNESS, encoding="utf-8")
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    prompter = FakePrompter(confirms=[True])
    with patch("kratos.agent.self_write_loop.run_self_write_loop",
               return_value=_fake_outcome(loop_status)):
        res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == mapped
    # a concrete recovery line was surfaced to the user
    assert prompter.said and prompter.said[-1][1]


def test_empty_idea_asks_and_cancels_when_blank(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    prompter = FakePrompter(texts=[""])  # asked for idea, submitted blank
    res = run_guided_build("", prompter)
    assert res.status == "cancelled"

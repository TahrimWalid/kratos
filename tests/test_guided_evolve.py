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


@pytest.fixture(autouse=True)
def _no_clarify_by_default(monkeypatch):
    """These tests exercise the write/test/keep surface, not the lever-3
    idea-clarity check (docs/clarify_expansion.md) -- default the underlying
    LLM check to "clear, proceed" so the existing suite never makes a real
    LLM call for it (mirrors how every test here already supplies
    `suggested_name` to skip _suggest_evolve_tool_name's own LLM call).
    _maybe_clarify_idea itself is left real/testable; tests for the clarify
    behavior override assess_intake_clarity explicitly."""
    monkeypatch.setattr("kratos.agent.clarify_intake.assess_intake_clarity", lambda *a, **k: None)
    yield


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
    assert any("the result's 'users' includes 'root'" == x for x in c.claims)


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


# ---------------------------------------------------------------------------
# lever 3 (docs/clarify_expansion.md): the guided evo-loop idea intake -------
# ---------------------------------------------------------------------------

class _ClarifyQ:
    def __init__(self, question, options=None):
        self.question = question
        self.options = options or []


def test_maybe_clarify_idea_proceeds_when_check_says_clear(monkeypatch):
    with patch("kratos.agent.clarify_intake.assess_intake_clarity", return_value=None):
        prompter = FakePrompter()
        assert G._maybe_clarify_idea("list sudo users on the target", prompter) == "list sudo users on the target"
    assert prompter.choices == [] and not prompter.shown  # never asked anything


def test_maybe_clarify_idea_asks_and_folds_in_the_answer(monkeypatch):
    q = _ClarifyQ("Which target?", [{"label": "The monitored target", "recommended": True}])
    with patch("kratos.agent.clarify_intake.assess_intake_clarity", return_value=q):
        prompter = FakePrompter(choices=["The monitored target"])
        goal = G._maybe_clarify_idea("do a thing", prompter)
    assert "The monitored target" in goal and "Which target?" in goal
    assert goal.startswith("do a thing")


def test_maybe_clarify_idea_other_option_uses_free_text(monkeypatch):
    q = _ClarifyQ("Which target?", [{"label": "The monitored target"}])
    with patch("kratos.agent.clarify_intake.assess_intake_clarity", return_value=q):
        prompter = FakePrompter(choices=[G._CLARIFY_OTHER], texts=["a third system entirely"])
        goal = G._maybe_clarify_idea("do a thing", prompter)
    assert "a third system entirely" in goal


def test_maybe_clarify_idea_declined_proceeds_unchanged(monkeypatch):
    q = _ClarifyQ("Which target?", [{"label": "The monitored target"}])
    with patch("kratos.agent.clarify_intake.assess_intake_clarity", return_value=q):
        prompter = FakePrompter(choices=[None])  # dismissed
        goal = G._maybe_clarify_idea("do a thing", prompter)
    assert goal == "do a thing"  # unchanged, never blocked


def test_maybe_clarify_idea_check_failure_proceeds_unchanged():
    with patch("kratos.agent.clarify_intake.assess_intake_clarity", side_effect=RuntimeError("boom")):
        prompter = FakePrompter()
        goal = G._maybe_clarify_idea("do a thing", prompter)
    assert goal == "do a thing"


# --- review finding #3: skip the extra LLM call entirely for an already-long,
# detailed idea -- it's very unlikely to be judged "too thin" and shouldn't
# cost a guaranteed classifier call every time -------------------------------

def test_maybe_clarify_idea_skips_the_llm_call_for_a_long_idea():
    long_idea = " ".join(["word"] * G._CLARIFY_INTAKE_SKIP_WORD_COUNT)
    calls = {"n": 0}

    def _spy(*a, **k):
        calls["n"] += 1
        return _ClarifyQ("irrelevant")  # even if it WOULD ask, the call must never happen

    with patch("kratos.agent.clarify_intake.assess_intake_clarity", side_effect=_spy):
        prompter = FakePrompter()
        goal = G._maybe_clarify_idea(long_idea, prompter)
    assert calls["n"] == 0
    assert goal == long_idea
    assert prompter.choices == [] and not prompter.shown


def test_maybe_clarify_idea_still_checks_a_short_idea_below_the_threshold():
    short_idea = " ".join(["word"] * (G._CLARIFY_INTAKE_SKIP_WORD_COUNT - 1))
    calls = {"n": 0}

    def _spy(*a, **k):
        calls["n"] += 1
        return None

    with patch("kratos.agent.clarify_intake.assess_intake_clarity", side_effect=_spy):
        prompter = FakePrompter()
        G._maybe_clarify_idea(short_idea, prompter)
    assert calls["n"] == 1  # right below the threshold -> still checked


def test_run_guided_build_threads_clarified_goal_into_the_build(tmp_path, monkeypatch, no_collision):
    """Integration: the augmented goal from _maybe_clarify_idea is what
    actually reaches run_self_write_loop, not the original short idea."""
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    monkeypatch.setattr(G, "_maybe_clarify_idea",
                        lambda goal, prompter: f"{goal}\n\n(Clarification: the monitored target)")
    hpath = tmp_path / "test_list_sudo.py"
    hpath.write_text(_TARGET_HARNESS, encoding="utf-8")
    prompter = FakePrompter(confirms=[True])
    seen_goal = {}

    def _fake_loop(write_request, *args, **kwargs):
        seen_goal["goal"] = write_request.goal
        return _fake_outcome("approved", "list_sudo", True, tmp_path / "k.py")

    with patch("kratos.agent.self_write_loop.run_self_write_loop", side_effect=_fake_loop):
        res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == "kept"
    assert "Clarification: the monitored target" in seen_goal["goal"]


# ---------------------------------------------------------------------------
# P1 (2026-09-21): harness round-trip -- regenerate from corrected plain-English
# claims, gated on a mutation guard so a regenerated test can never silently
# rubber-stamp the trust anchor.
# ---------------------------------------------------------------------------
_RT_CONV = '''
import importlib.util, os
from pathlib import Path
import pytest
CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "rt_demo"
def _load():
    spec = importlib.util.spec_from_file_location("cand", Path(CANDIDATE_MODULE_PATH))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
@pytest.fixture
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY
    _load()
    return TOOL_REGISTRY[TOOL_NAME].handler
'''
_DISC_HARNESS = _RT_CONV + '''
def test_returns_sudo_users(registered_handler):
    r = registered_handler(data_dir=None)
    assert isinstance(r, dict) and "sudo_users" in r and isinstance(r["sudo_users"], list)
'''
_RUBBER_HARNESS = _RT_CONV + '''
def test_registered(registered_handler):
    assert registered_handler is not None
'''
_NO_TESTS_HARNESS = 'TOOL_NAME = "rt_demo"\nX = 1\n'


def test_mutation_guard_accepts_discriminating_harness():
    ok, reason = G.harness_discriminates(_DISC_HARNESS, "rt_demo")
    assert ok, reason


def test_mutation_guard_rejects_rubber_stamp():
    ok, reason = G.harness_discriminates(_RUBBER_HARNESS, "rt_demo")
    assert not ok
    assert "PASSES even a deliberately-wrong" in reason


def test_mutation_guard_rejects_no_tests():
    ok, reason = G.harness_discriminates(_NO_TESTS_HARNESS, "rt_demo")
    assert not ok


def test_regenerate_success(monkeypatch):
    monkeypatch.setattr(G, "agent_chat", lambda **k: _DISC_HARNESS)
    code = G.regenerate_harness_from_claims("rt_demo", "list sudo users", "returns a list of sudo users")
    assert code is not None and 'TOOL_NAME = "rt_demo"' in code


def test_regenerate_rejects_wrong_tool_name(monkeypatch):
    wrong = _DISC_HARNESS.replace('TOOL_NAME = "rt_demo"', 'TOOL_NAME = "something_else"')
    monkeypatch.setattr(G, "agent_chat", lambda **k: wrong)
    assert G.regenerate_harness_from_claims("rt_demo", "g", "claims") is None


def test_regenerate_rejects_invalid_python(monkeypatch):
    monkeypatch.setattr(G, "agent_chat", lambda **k: "def broken(:\n  pass")
    assert G.regenerate_harness_from_claims("rt_demo", "g", "claims") is None


def test_regenerate_none_on_empty_or_no_llm(monkeypatch):
    assert G.regenerate_harness_from_claims("rt_demo", "g", "   ") is None
    monkeypatch.setattr(G, "agent_chat", lambda **k: None)
    assert G.regenerate_harness_from_claims("rt_demo", "g", "claims") is None


def test_claims_roundtrip_accepts_discriminating(monkeypatch):
    monkeypatch.setattr(G, "agent_chat", lambda **k: _DISC_HARNESS)
    p = FakePrompter(texts=["returns a list of sudo users"])
    claims = G.describe_harness_claims(_RUBBER_HARNESS)   # weak current claims
    new = G._claims_roundtrip("list sudo users", "rt_demo", _RUBBER_HARNESS, claims, p)
    assert new is not None and "sudo_users" in new
    assert any("correctly rejects" in m for _, m in p.said)


def test_claims_roundtrip_rejects_regenerated_rubber_stamp(monkeypatch):
    # The regenerated harness is a rubber stamp -> mutation guard rejects it ->
    # keep the current one (return None), never silently accept.
    monkeypatch.setattr(G, "agent_chat", lambda **k: _RUBBER_HARNESS)
    p = FakePrompter(texts=["returns something"])
    claims = G.describe_harness_claims(_DISC_HARNESS)
    assert G._claims_roundtrip("g", "rt_demo", _DISC_HARNESS, claims, p) is None
    assert any("Not using that version" in m for _, m in p.said)


def test_claims_roundtrip_none_on_empty_input():
    p = FakePrompter(texts=[""])
    claims = G.describe_harness_claims(_DISC_HARNESS)
    assert G._claims_roundtrip("g", "rt_demo", _DISC_HARNESS, claims, p) is None


def test_failure_phrased_messages_become_the_assertions_own_meaning():
    """Seen live (demo pass 3): 'It checks that: • The cron command for root was not
    parsed correctly' -- a failure message listed as a claim."""
    src = '''
def test_x(registered_handler):
    result = registered_handler()
    assert "root" in result, "Result must contain cron jobs for the root user"
    assert "/usr/bin/backup.sh" in result["root"][0], "The cron command for root was not parsed correctly"
    assert result == {}, "Missing key"
'''
    c = describe_harness_claims(src)
    assert "Result must contain cron jobs for the root user" in c.claims
    assert not any("not parsed" in x or "Missing" in x for x in c.claims)
    assert "the first item of the result's 'root' includes '/usr/bin/backup.sh'" in c.claims
    assert "the result equals {}" in c.claims


_PYTEST_FAIL = """
    def test_x(registered_handler):
>       assert "www-data" in result, "The result must capture crontabs for non-root users"
E       AssertionError: The result must capture crontabs for non-root users
E       assert 'www-data' in {'/var/spool/cron/crontabs/www-data': 'x'}
"""


def test_failing_checks_reads_message_and_values():
    assert G.failing_checks(_PYTEST_FAIL) == [
        "The result must capture crontabs for non-root users — assert 'www-data' in "
        "{'/var/spool/cron/crontabs/www-data': 'x'}"]
    assert G.failing_checks("E       assert 3 == 4\n") == ["assert 3 == 4"]       # no message
    assert G.failing_checks("all good\n") == []


def test_a_stalled_build_names_the_failing_check(tmp_path, monkeypatch, no_collision):
    """Seen live (demo pass 5): the drafted test could never pass, and the user was only
    told 'a test check may be impossible' -- not which one."""
    hpath = tmp_path / "test_list_sudo.py"
    hpath.write_text(_TARGET_HARNESS, encoding="utf-8")
    monkeypatch.setattr(G, "_HARNESS_DIR", tmp_path)
    tr = types.SimpleNamespace(passed=False, infra_error=None, stdout=_PYTEST_FAIL, stderr="")
    outcome = types.SimpleNamespace(status="stalled_no_variation", keep_decision=None, kept_path=None,
                                    attempt_history=[types.SimpleNamespace(test_result=tr)])
    prompter = FakePrompter(confirms=[True])
    with patch("kratos.agent.self_write_loop.run_self_write_loop", return_value=outcome):
        res = run_guided_build("list sudo", prompter, suggested_name="list_sudo")
    assert res.status == "stalled"
    assert "The check that kept failing: “The result must capture crontabs for non-root users" in prompter.all_text()
    assert str(hpath) in prompter.all_text()

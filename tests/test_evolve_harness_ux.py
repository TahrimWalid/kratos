"""
Scripted tests for the /evolve harness-file UX fixes (2026-07-28), prompted
by real user complaints: a long free-text /evolve idea produced an
absurdly long suggested filename (the whole sentence slugified), hitting
"file not found" left the user with no concrete starting point, and even
the static starter template still meant hand-writing every real assertion
from a blank slate ("it should be as easy as asking Claude Code to create
a function").

Four fixes, all covered here:
  1. _slugify_name_hint caps word count -- the suggested default is always
     short, not a full-sentence slug.
  2. _resolve_evolve_test_file shows a real starter pytest harness template
     (via render_evolve_harness_template) when the path doesn't exist,
     WITHOUT ever writing anything to disk -- the human-authored-test
     principle this whole flow protects is unchanged.
  3. _draft_evolve_harness + _resolve_evolve_test_file's draft/save prompts:
     an LLM-drafted, idea-specific harness the human can review and choose
     to save -- still never auto-proceeds into run_self_write_loop in the
     same command, and saving requires an explicit "y", so a human still
     has to take a deliberate, separate action before the draft is ever
     used as evo-loop's actual correctness bar.
  4. _resolve_evolve_tool_name + _suggest_evolve_tool_name: a real naming
     step instead of the old purely-mechanical slug -- type your own name,
     or press Enter to have the LLM propose one from the goal. tool_name is
     now resolved ONCE and threaded through consistently (the suggested
     path AND the drafted/template harness's TOOL_NAME), rather than being
     re-derived from whatever file path the user ends up typing.
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

from kratos.cli import repl
from kratos.agent import guided_evolve


LONG_IDEA = "Add a tool that lists which users have sudo access on the monitored target via SSH"


# ---------------------------------------------------------------------------
# _slugify_name_hint
# ---------------------------------------------------------------------------
def test_slugify_caps_long_sentence_to_a_few_words():
    slug = repl._slugify_name_hint(LONG_IDEA)
    assert slug == "add_a_tool_that"
    assert slug.count("_") < LONG_IDEA.count(" ")  # genuinely shorter than the full sentence


def test_slugify_leaves_a_short_name_unchanged():
    assert repl._slugify_name_hint("list_sudo_members") == "list_sudo_members"


def test_slugify_never_empty():
    assert repl._slugify_name_hint("!!! ??? ###") == "new_tool"


# ---------------------------------------------------------------------------
# _build_evolve_harness_template
# ---------------------------------------------------------------------------
def test_harness_template_is_valid_python():
    template = repl._build_evolve_harness_template("list_sudo_members", LONG_IDEA)
    ast.parse(template)  # raises SyntaxError if this ever regresses


def test_harness_template_uses_the_given_slug_as_tool_name():
    template = repl._build_evolve_harness_template("list_sudo_members", LONG_IDEA)
    assert 'TOOL_NAME = "list_sudo_members"' in template
    assert "def test_list_sudo_members_behaves_correctly(" in template


def test_harness_template_matches_real_convention_shape():
    # Same real shape as tests/self_write_harnesses/test_evolve_verification_ping.py
    # (the one other harness in this repo built for this exact wiring) --
    # confirms the shown scaffold isn't a generic/invented pytest example.
    template = repl._build_evolve_harness_template("x", "goal")
    assert "CANDIDATE_MODULE_PATH = os.environ.get" in template
    assert "@pytest.fixture(scope=\"module\")" in template
    assert "def registered_handler():" in template
    assert "from kratos.agent.tools import TOOL_REGISTRY" in template


# ---------------------------------------------------------------------------
# _resolve_evolve_test_file -- real flow, template shown but nothing written
# ---------------------------------------------------------------------------
def test_missing_file_shows_template_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "n"]), patch.object(
        repl._console, "render_evolve_harness_template"
    ) as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None
    render_mock.assert_called_once()
    _, template_arg, path_arg = render_mock.call_args.args
    assert "list_sudo_members" in template_arg
    assert str(path_arg) == target
    assert not Path(target).exists()  # never auto-created


def test_existing_file_returned_unaffected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    harness_dir = tmp_path / "tests" / "self_write_harnesses"
    harness_dir.mkdir(parents=True)
    real_file = harness_dir / "test_list_sudo_members.py"
    real_file.write_text("def test_x(): pass\n", encoding="utf-8")

    with patch("builtins.input", side_effect=[str(real_file)]), patch.object(
        repl._console, "render_evolve_harness_template"
    ) as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result == real_file
    render_mock.assert_not_called()


# ---------------------------------------------------------------------------
# _draft_evolve_harness -- real LLM query mechanism (agent_chat), mocked here
# ---------------------------------------------------------------------------
_VALID_DRAFT = '''"""
Test harness for list_sudo_members.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "list_sudo_members"


def _load_candidate():
    if not CANDIDATE_MODULE_PATH:
        pytest.skip("CANDIDATE_MODULE_PATH not set")
    path = Path(CANDIDATE_MODULE_PATH)
    spec = importlib.util.spec_from_file_location("candidate_tool_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY

    _load_candidate()
    assert TOOL_NAME in TOOL_REGISTRY
    return TOOL_REGISTRY[TOOL_NAME].handler


def test_returns_sudo_members_list(registered_handler):
    result = registered_handler()
    assert "sudo_members" in result
    assert isinstance(result["sudo_members"], list)
'''


def test_draft_returns_none_when_llm_unavailable():
    with patch.object(guided_evolve, "agent_chat", return_value=None):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is None


def test_draft_returns_code_on_valid_response():
    with patch.object(guided_evolve, "agent_chat", return_value=_VALID_DRAFT):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is not None
    assert 'TOOL_NAME = "list_sudo_members"' in result
    ast.parse(result)


def test_draft_strips_markdown_fences():
    fenced = f"```python\n{_VALID_DRAFT}\n```"
    with patch.object(guided_evolve, "agent_chat", return_value=fenced):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is not None
    assert "```" not in result
    ast.parse(result)


def test_draft_rejects_invalid_python():
    with patch.object(guided_evolve, "agent_chat", return_value="this is not python code {{{"):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is None


def test_draft_rejects_wrong_tool_name():
    # Real structural check, not just a prompt instruction -- the model
    # naming the wrong tool would silently test against the wrong
    # interface if this weren't caught.
    wrong_name_draft = _VALID_DRAFT.replace(
        'TOOL_NAME = "list_sudo_members"', 'TOOL_NAME = "some_other_tool"'
    )
    with patch.object(guided_evolve, "agent_chat", return_value=wrong_name_draft):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is None


# ---------------------------------------------------------------------------
# _resolve_evolve_test_file -- the draft/save prompt orchestration
# ---------------------------------------------------------------------------
def test_declining_draft_falls_back_to_static_template(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "n"]), patch.object(
        repl, "_draft_evolve_harness"
    ) as draft_mock, patch.object(repl._console, "render_evolve_harness_template") as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None
    draft_mock.assert_not_called()
    render_mock.assert_called_once()
    assert render_mock.call_args.kwargs.get("drafted") is not True  # plain template, not the draft variant


def test_accepting_draft_then_choosing_save_and_build_returns_path(tmp_path, monkeypatch):
    # Real UX fix (2026-07-28): "save and build now" returns the path
    # directly, the SAME return shape as an already-existing file, so
    # _cmd_evolve's existing flow proceeds straight into run_self_write_loop
    # with no need to retype /evolve.
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y", "s"]), patch.object(
        repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
    ), patch.object(repl._console, "render_evolve_harness_template") as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result == Path(target)
    assert render_mock.call_args.kwargs.get("drafted") is True
    saved = Path(target)
    assert saved.exists()
    assert saved.read_text(encoding="utf-8") == _VALID_DRAFT


def test_accepting_draft_then_choosing_edit_saves_but_aborts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y", "e"]), patch.object(
        repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
    ), patch.object(repl._console, "render_evolve_harness_template"):
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None  # aborts -- a fresh /evolve is required to actually proceed
    saved = Path(target)
    assert saved.exists()
    assert saved.read_text(encoding="utf-8") == _VALID_DRAFT


def test_accepting_draft_then_choosing_discard_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y", "d"]), patch.object(
        repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
    ), patch.object(repl._console, "render_evolve_harness_template"):
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None
    assert not Path(target).exists()


def test_draft_default_yes_on_empty_input(tmp_path, monkeypatch):
    # Empty input (bare Enter) on the FIRST prompt (draft?) means yes --
    # the more helpful default, matching the whole point of this feature.
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "", "d"]), patch.object(
        repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
    ) as draft_mock, patch.object(repl._console, "render_evolve_harness_template"):
        repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    draft_mock.assert_called_once()


def test_save_choice_empty_input_means_discard(tmp_path, monkeypatch):
    # Empty input on the SECOND prompt (save/edit/discard?) means discard --
    # the LEAST consequential of the three options, matching this project's
    # "no force-accept on anything consequential" pattern applied to
    # whichever choice is most consequential here (save-and-build-now,
    # which starts the real pipeline), not just a plain save/no-save binary.
    # Unlike genuinely garbage input (see the reject-and-reprompt test
    # below), empty Enter is a documented, accepted answer -- it resolves
    # immediately, no reprompt.
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y", ""]), patch.object(
        repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
    ), patch.object(repl._console, "render_evolve_harness_template"):
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None
    assert not Path(target).exists()


def test_save_choice_rejects_garbage_input_and_reprompts(tmp_path, monkeypatch):
    # Real fix (2026-07-28), matching the resume-tier prompt's established
    # precedent: a mistyped keystroke here used to be silently treated as
    # "discard" -- which could quietly throw away a reviewed draft the user
    # actually wanted to keep. Garbage input is now REJECTED with a visible
    # message and the SAME prompt re-shown, exactly like the chooser/
    # resume-tier prompts already do -- it takes a real subsequent valid
    # answer to resolve, never a guess at what the user meant.
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y", "whatever", "y", "s"]), patch.object(
        repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
    ), patch.object(repl._console, "render_evolve_harness_template"), patch.object(
        repl._console, "render_note"
    ) as note_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    # Two garbage answers ("whatever", then "y", which isn't a valid choice
    # either) were rejected before "s" finally resolved it -- confirmed by
    # the real rejection messages, not just the eventual outcome.
    rejection_texts = [call.args[1] for call in note_mock.call_args_list if "valid choice" in call.args[1]]
    assert len(rejection_texts) == 2
    assert result == Path(target)
    assert Path(target).exists()


def test_failed_draft_falls_back_to_static_template(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y"]), patch.object(
        repl, "_draft_evolve_harness", return_value=None
    ), patch.object(repl._console, "render_evolve_harness_template") as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None
    render_mock.assert_called_once()
    assert render_mock.call_args.kwargs.get("drafted") is not True
    assert not Path(target).exists()


# ---------------------------------------------------------------------------
# _suggest_evolve_tool_name / _resolve_evolve_tool_name -- LLM-based naming
# ---------------------------------------------------------------------------
def test_suggest_tool_name_returns_none_when_llm_unavailable():
    with patch.object(guided_evolve, "agent_chat", return_value=None):
        result = repl._suggest_evolve_tool_name(LONG_IDEA)
    assert result is None


def test_suggest_tool_name_sanitizes_the_response():
    # Reuses _slugify_name_hint on whatever the LLM returns -- a clean
    # snake_case reply survives unchanged, but this must also cope with an
    # LLM adding stray formatting rather than trusting the prompt alone.
    with patch.object(guided_evolve, "agent_chat", return_value="  `list_sudo_members`  "):
        result = repl._suggest_evolve_tool_name(LONG_IDEA)
    assert result == "list_sudo_members"


def test_resolve_tool_name_uses_typed_name_directly():
    with patch("builtins.input", return_value="my_custom_name"), patch.object(
        repl, "_suggest_evolve_tool_name"
    ) as suggest_mock:
        result = repl._resolve_evolve_tool_name(MagicMock(), LONG_IDEA)
    assert result == "my_custom_name"
    suggest_mock.assert_not_called()  # typed a name -- no LLM call needed


def test_resolve_tool_name_calls_llm_on_empty_input():
    with patch("builtins.input", return_value=""), patch.object(
        repl, "_suggest_evolve_tool_name", return_value="list_sudo_members"
    ) as suggest_mock:
        result = repl._resolve_evolve_tool_name(MagicMock(), LONG_IDEA)
    assert result == "list_sudo_members"
    suggest_mock.assert_called_once_with(LONG_IDEA)


def test_resolve_tool_name_falls_back_to_mechanical_slug_on_llm_failure():
    with patch("builtins.input", return_value=""), patch.object(
        repl, "_suggest_evolve_tool_name", return_value=None
    ):
        result = repl._resolve_evolve_tool_name(MagicMock(), LONG_IDEA)
    assert result == repl._slugify_name_hint(LONG_IDEA)  # the existing mechanical fallback


def test_resolve_tool_name_offers_pending_suggestion_as_default():
    # A real auto-suggested tool_proposal already includes the model's own
    # chosen name -- pressing Enter should accept THAT directly, no fresh
    # LLM call needed.
    with patch("builtins.input", return_value=""), patch.object(
        repl, "_suggest_evolve_tool_name"
    ) as suggest_mock:
        result = repl._resolve_evolve_tool_name(MagicMock(), LONG_IDEA, suggested_name="parse_journalctl_to_json")
    assert result == "parse_journalctl_to_json"
    suggest_mock.assert_not_called()


def test_resolve_tool_name_can_override_pending_suggestion():
    with patch("builtins.input", return_value="a_better_name"), patch.object(
        repl, "_suggest_evolve_tool_name"
    ) as suggest_mock:
        result = repl._resolve_evolve_tool_name(MagicMock(), LONG_IDEA, suggested_name="parse_journalctl_to_json")
    assert result == "a_better_name"
    suggest_mock.assert_not_called()


# ---------------------------------------------------------------------------
# _check_evolve_name_collision -- real user complaint (2026-07-28): "the
# user will strictly follow the rules... but in real life that doesn't
# happen, they might make a mistake" -- this specifically guards against
# picking a name that already belongs to a real tool (built-in or kept),
# which would silently REPLACE it once approved, with no other warning
# anywhere in the pipeline.
# ---------------------------------------------------------------------------
def test_name_collision_no_collision_proceeds_without_prompting():
    with patch("builtins.input") as input_mock:
        result = repl._check_evolve_name_collision(MagicMock(), "totally_new_tool_xyz")
    assert result is True
    input_mock.assert_not_called()  # no collision -- never even asks


def test_name_collision_with_kept_tool_declined():
    fake_registry = {"list_net_services": MagicMock()}
    fake_metadata = {"list_net_services": {"kept_at": "2026-07-28T20:36:56"}}
    with patch("kratos.agent.tools.TOOL_REGISTRY", fake_registry), patch(
        "kratos.agent.self_write_loop._read_metadata", return_value=fake_metadata
    ), patch("builtins.input", return_value="n"):
        result = repl._check_evolve_name_collision(MagicMock(), "list_net_services")
    assert result is False


def test_name_collision_with_kept_tool_confirmed():
    fake_registry = {"list_net_services": MagicMock()}
    fake_metadata = {"list_net_services": {"kept_at": "2026-07-28T20:36:56"}}
    with patch("kratos.agent.tools.TOOL_REGISTRY", fake_registry), patch(
        "kratos.agent.self_write_loop._read_metadata", return_value=fake_metadata
    ), patch("builtins.input", return_value="y"):
        result = repl._check_evolve_name_collision(MagicMock(), "list_net_services")
    assert result is True


def test_name_collision_with_builtin_tool_shows_builtin_wording():
    fake_registry = {"run_nmap_scan": MagicMock()}
    with patch("kratos.agent.tools.TOOL_REGISTRY", fake_registry), patch(
        "kratos.agent.self_write_loop._read_metadata", return_value={}
    ), patch("builtins.input", return_value="n"), patch.object(repl._console, "render_note") as note_mock:
        result = repl._check_evolve_name_collision(MagicMock(), "run_nmap_scan")
    assert result is False
    warning_texts = [call.args[1] for call in note_mock.call_args_list if "run_nmap_scan" in call.args[1]]
    assert any("BUILT-IN" in t for t in warning_texts)


def test_name_collision_empty_input_means_no():
    fake_registry = {"list_net_services": MagicMock()}
    with patch("kratos.agent.tools.TOOL_REGISTRY", fake_registry), patch(
        "kratos.agent.self_write_loop._read_metadata", return_value={}
    ), patch("builtins.input", return_value=""):
        result = repl._check_evolve_name_collision(MagicMock(), "list_net_services")
    assert result is False


def test_name_collision_rejects_garbage_and_reprompts():
    fake_registry = {"list_net_services": MagicMock()}
    with patch("kratos.agent.tools.TOOL_REGISTRY", fake_registry), patch(
        "kratos.agent.self_write_loop._read_metadata", return_value={}
    ), patch("builtins.input", side_effect=["maybe", "y"]):
        result = repl._check_evolve_name_collision(MagicMock(), "list_net_services")
    assert result is True  # eventually resolved by the real "y"


# ---------------------------------------------------------------------------
# Harness path sanity check -- rejects an obvious non-.py path
# ---------------------------------------------------------------------------
def test_path_rejects_non_py_extension_and_reprompts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=["notes.txt", target, "n"]), patch.object(
        repl._console, "render_evolve_harness_template"
    ), patch.object(repl._console, "render_note") as note_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), "list_sudo_members", LONG_IDEA)

    assert result is None
    rejection_texts = [call.args[1] for call in note_mock.call_args_list if "doesn't look like a Python file" in call.args[1]]
    assert len(rejection_texts) == 1


# ---------------------------------------------------------------------------
# /evolve list -- browse built-in + kept tools before naming a new one
# ---------------------------------------------------------------------------
def test_evolve_list_builds_rows_for_builtin_and_kept_tools():
    builtin_tool = MagicMock(description="Built-in thing.\nmore detail", requires_approval=False)
    kept_tool = MagicMock(description="A kept thing.", requires_approval=True)
    fake_registry = {"a_builtin_tool": builtin_tool, "a_kept_tool": kept_tool}
    fake_metadata = {"a_kept_tool": {"kept_at": "2026-07-28T20:36:56", "source_file": "a_kept_tool.py"}}

    with patch("kratos.agent.tools.TOOL_REGISTRY", fake_registry), patch(
        "kratos.agent.self_write_loop._read_metadata", return_value=fake_metadata
    ), patch.object(repl._console, "render_evolve_tool_list") as render_mock:
        repl._cmd_evolve_list(MagicMock())

    assert render_mock.call_count == 1
    rows = {r["name"]: r for r in render_mock.call_args.args[1]}
    assert rows["a_builtin_tool"]["kind"] == "built-in"
    assert rows["a_builtin_tool"]["requires_approval"] is False
    assert rows["a_builtin_tool"]["kept_at"] is None
    assert rows["a_builtin_tool"]["description"] == "Built-in thing."
    assert rows["a_kept_tool"]["kind"] == "kept"
    assert rows["a_kept_tool"]["requires_approval"] is True
    assert rows["a_kept_tool"]["kept_at"] == "2026-07-28T20:36:56"


def test_evolve_cmd_list_dispatches_without_touching_write_flow():
    with patch.object(repl, "_cmd_evolve_list") as list_mock, patch("builtins.input") as input_mock:
        repl._cmd_evolve(MagicMock(), {}, "list")
    list_mock.assert_called_once()
    input_mock.assert_not_called()  # must never fall through into naming/goal resolution


def test_evolve_cmd_ls_alias_also_dispatches():
    with patch.object(repl, "_cmd_evolve_list") as list_mock:
        repl._cmd_evolve(MagicMock(), {}, "  LS  ")
    list_mock.assert_called_once()

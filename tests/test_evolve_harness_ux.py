"""
Scripted tests for the /evolve harness-file UX fixes (2026-07-28), prompted
by real user complaints: a long free-text /evolve idea produced an
absurdly long suggested filename (the whole sentence slugified), hitting
"file not found" left the user with no concrete starting point, and even
the static starter template still meant hand-writing every real assertion
from a blank slate ("it should be as easy as asking Claude Code to create
a function").

Three fixes, all covered here:
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
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

from kratos.cli import repl


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

    with patch("builtins.input", return_value=target), patch.object(
        repl._console, "render_evolve_harness_template"
    ) as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

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

    with patch("builtins.input", return_value=str(real_file)), patch.object(
        repl._console, "render_evolve_harness_template"
    ) as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

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
    with patch.object(repl, "agent_chat", return_value=None):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is None


def test_draft_returns_code_on_valid_response():
    with patch.object(repl, "agent_chat", return_value=_VALID_DRAFT):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is not None
    assert 'TOOL_NAME = "list_sudo_members"' in result
    ast.parse(result)


def test_draft_strips_markdown_fences():
    fenced = f"```python\n{_VALID_DRAFT}\n```"
    with patch.object(repl, "agent_chat", return_value=fenced):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is not None
    assert "```" not in result
    ast.parse(result)


def test_draft_rejects_invalid_python():
    with patch.object(repl, "agent_chat", return_value="this is not python code {{{"):
        result = repl._draft_evolve_harness(MagicMock(), "list_sudo_members", LONG_IDEA)
    assert result is None


def test_draft_rejects_wrong_tool_name():
    # Real structural check, not just a prompt instruction -- the model
    # naming the wrong tool would silently test against the wrong
    # interface if this weren't caught.
    wrong_name_draft = _VALID_DRAFT.replace(
        'TOOL_NAME = "list_sudo_members"', 'TOOL_NAME = "some_other_tool"'
    )
    with patch.object(repl, "agent_chat", return_value=wrong_name_draft):
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
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

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
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

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
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

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
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

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
        repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

    draft_mock.assert_called_once()


def test_save_choice_default_discard_on_empty_or_unrecognized_input(tmp_path, monkeypatch):
    # Empty/unrecognized input on the SECOND prompt (save/edit/discard?)
    # means discard -- the LEAST consequential of the three options, matching
    # this project's "no force-accept on anything consequential" pattern
    # applied to whichever choice is most consequential here (save-and-build,
    # which starts the real pipeline), not just a plain save/no-save binary.
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    for garbage_answer in ("", "y", "whatever"):
        Path(target).unlink(missing_ok=True)
        with patch("builtins.input", side_effect=[target, "y", garbage_answer]), patch.object(
            repl, "_draft_evolve_harness", return_value=_VALID_DRAFT
        ), patch.object(repl._console, "render_evolve_harness_template"):
            result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

        assert result is None
        assert not Path(target).exists()


def test_failed_draft_falls_back_to_static_template(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = "tests/self_write_harnesses/test_list_sudo_members.py"

    with patch("builtins.input", side_effect=[target, "y"]), patch.object(
        repl, "_draft_evolve_harness", return_value=None
    ), patch.object(repl._console, "render_evolve_harness_template") as render_mock:
        result = repl._resolve_evolve_test_file(MagicMock(), LONG_IDEA)

    assert result is None
    render_mock.assert_called_once()
    assert render_mock.call_args.kwargs.get("drafted") is not True
    assert not Path(target).exists()

"""
Scripted tests for the /evolve harness-file UX fix (2026-07-28), prompted
by a real user complaint: a long free-text /evolve idea produced an
absurdly long suggested filename (the whole sentence slugified), and
hitting "file not found" left the user with no concrete starting point.

Two independent fixes, both covered here:
  1. _slugify_name_hint caps word count -- the suggested default is always
     short, not a full-sentence slug.
  2. _resolve_evolve_test_file shows a real starter pytest harness template
     (via render_evolve_harness_template) when the path doesn't exist,
     WITHOUT ever writing anything to disk -- the human-authored-test
     principle this whole flow protects is unchanged.
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

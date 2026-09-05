"""
Tests for the mk2 general Settings screen + model management (Piece 3).

Two layers:
  * _validate_window -- the pure hard/soft context-window rule (no app needed):
    above a known max = hard reject; above the currently-loaded-but-<=max = a
    soft heads-up (still allowed); undetectable = the user's own number.
  * Headless Textual pilots (App.run_test wrapped in asyncio.run) for the screen:
    the Models tab lists profiles with the active marker + per-profile window,
    the Switch button reports 'already active', and the Add/Edit modals dismiss
    with the correct values after validation.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.app import App
from textual.widgets import Button, DataTable, Input, Static

from kratos.tui_mk2.screens.settings import (
    AddModelModal, EditWindowModal, SettingsScreen, _validate_window,
)

_ENV = (
    "LLM_BASE_URL=https://api.gemini.example/v1\nLLM_API_KEY=gk\n"
    "LLM_MODEL=gemini-3.1-pro\nKRATOS_LLM_BACKEND=openai_compatible\n\n"
    "# LLM_BASE_URL=http://127.0.0.1:11434/v1\n# LLM_API_KEY=ollama\n"
    "# LLM_MODEL=qwen2.5:7b\n# KRATOS_LLM_BACKEND=openai_compatible\n# LLM_CONTEXT_WINDOW=131072\n"
)


# ---------------------------------------------------------------------------
# _validate_window -- the hard/soft rule (this is the load-bearing safety logic)
# ---------------------------------------------------------------------------
def test_validate_window_empty_is_auto():
    assert _validate_window("", 1000, 500) == (None, None, None)


def test_validate_window_non_numeric_is_hard_error():
    value, hard, soft = _validate_window("abc", None, None)
    assert value is None and hard is not None and soft is None


def test_validate_window_above_known_max_is_hard_reject():
    value, hard, soft = _validate_window("300000", 262144, 262144)
    assert value is None and "Exceeds" in hard and "262,144" in hard


def test_validate_window_above_loaded_below_max_is_soft_allowed():
    value, hard, soft = _validate_window("64000", 131072, 32768)
    assert value == 64000 and hard is None and "currently has loaded (32,768)" in soft


def test_validate_window_within_loaded_is_clean():
    assert _validate_window("30000", 131072, 32768) == (30000, None, None)


def test_validate_window_undetectable_allows_any_positive():
    assert _validate_window("999999", None, None) == (999999, None, None)


# ---------------------------------------------------------------------------
# pilot helpers
# ---------------------------------------------------------------------------
class _FakeSession:
    def __init__(self):
        self.session_state = {"backend": "gemini-3.1-pro"}

    @staticmethod
    def _profile_blurb(values):
        url = (values.get("LLM_BASE_URL") or "").lower()
        return "local · free · private" if "127.0.0.1" in url else "cloud API · billed"

    def _refresh_footer(self):
        pass


def _write_env(tmp_path: Path, monkeypatch) -> Path:
    env = tmp_path / ".env"
    env.write_text(_ENV, encoding="utf-8")
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", env)
    return env


class _ScreenHost(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


# ---------------------------------------------------------------------------
# Settings screen -- Models tab listing + switch button
# ---------------------------------------------------------------------------
def test_models_tab_lists_profiles_with_marker_and_windows(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(_FakeSession()))
        async with app.run_test() as pilot:
            await pilot.pause()
            t = app.screen.query_one("#ms-table", DataTable)
            return [[str(t.get_cell_at((r, c))) for c in range(4)] for r in range(t.row_count)]

    rows = asyncio.run(_run())
    by_model = {r[1]: r for r in rows}
    assert set(by_model) == {"gemini-3.1-pro", "qwen2.5:7b"}
    assert "●" in by_model["gemini-3.1-pro"][0] and "●" not in by_model["qwen2.5:7b"][0]
    assert by_model["qwen2.5:7b"][3] == "131,072" and by_model["gemini-3.1-pro"][3] == "auto"


def test_switch_button_on_active_model_reports_already_active(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(_FakeSession()))
        async with app.run_test() as pilot:
            await pilot.pause()
            app.screen.query_one("#ms-table", DataTable).move_cursor(row=0)  # active gemini
            app.screen.action_switch()  # keyboard-first: 's'/Enter (buttons removed)
            await pilot.pause()
            return str(app.screen.query_one("#ms-status", Static).render())

    assert "already active" in asyncio.run(_run()).lower()


# ---------------------------------------------------------------------------
# Add / Edit modals -- dismiss with the right values after validation
# ---------------------------------------------------------------------------
def test_add_modal_saves_values_with_window():
    async def _run():
        app = _ScreenHost(AddModelModal())
        async with app.run_test() as pilot:
            await pilot.pause()
            modal = app.screen
            captured = {}
            modal.dismiss = lambda result=None: captured.__setitem__("r", result)
            modal.query_one("#add-url", Input).value = "http://127.0.0.1:11434/v1"
            modal.query_one("#add-model", Input).value = "qwen2.5:7b"
            modal.query_one("#add-window", Input).value = "8000"
            modal.action_save()
            await pilot.pause()
            return captured.get("r")

    values = asyncio.run(_run())
    assert values["LLM_MODEL"] == "qwen2.5:7b"
    assert values["LLM_BASE_URL"] == "http://127.0.0.1:11434/v1"
    assert values["LLM_CONTEXT_WINDOW"] == "8000"
    assert values["KRATOS_LLM_BACKEND"] == "openai_compatible"


def test_add_modal_hard_window_blocks_save():
    async def _run():
        app = _ScreenHost(AddModelModal())
        async with app.run_test() as pilot:
            await pilot.pause()
            modal = app.screen
            dismissed = {"called": False}
            modal.dismiss = lambda result=None: dismissed.__setitem__("called", True)
            modal.query_one("#add-url", Input).value = "https://openrouter.ai/api/v1"
            modal.query_one("#add-model", Input).value = "m"
            modal.query_one("#add-window", Input).value = "500000"
            modal._ctx.detected_max = 262144   # a known ceiling
            modal.action_save()
            await pilot.pause()
            return dismissed["called"], str(modal.query_one("#add-hint", Static).render())

    called, hint = asyncio.run(_run())
    assert called is False               # blocked
    assert "Exceeds" in hint


def test_edit_modal_empty_clears_and_number_sets():
    async def _run(initial, typed):
        app = _ScreenHost(EditWindowModal({"LLM_MODEL": "m", "LLM_BASE_URL": "x", "LLM_CONTEXT_WINDOW": initial}))
        async with app.run_test() as pilot:
            await pilot.pause()
            modal = app.screen
            captured = {}
            modal.dismiss = lambda result=None: captured.__setitem__("r", result)
            modal.query_one("#edit-window", Input).value = typed
            modal.action_save()
            await pilot.pause()
            return captured.get("r")

    assert asyncio.run(_run("131072", "")) == "clear"     # empty -> clear to auto
    assert asyncio.run(_run("", "48000")) == 48000        # number -> int

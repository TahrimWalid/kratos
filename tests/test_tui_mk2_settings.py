"""
Headless pilot tests for the mk2 model-settings screen (ModelSettingsScreen,
Piece 3a). Driven through a real Textual App via App.run_test(), wrapped in
asyncio.run() so no async-pytest plugin config is needed. Covers the listing
(profiles, active marker, per-profile context window vs. 'auto') and the
deterministic 'already active' switch path -- the network/worker switch itself
reuses the exact validate/reachable/switch_profile logic already unit-tested in
test_llm_profiles_context.py.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.app import App
from textual.widgets import DataTable, Static

from kratos.tui_mk2.screens.settings import ModelSettingsScreen

_ENV = (
    "LLM_BASE_URL=https://api.gemini.example/v1\n"
    "LLM_API_KEY=gk\n"
    "LLM_MODEL=gemini-3.1-pro\n"
    "KRATOS_LLM_BACKEND=openai_compatible\n"
    "\n"
    "# LLM_BASE_URL=http://127.0.0.1:11434/v1\n"
    "# LLM_API_KEY=ollama\n"
    "# LLM_MODEL=qwen2.5:7b\n"
    "# KRATOS_LLM_BACKEND=openai_compatible\n"
    "# LLM_CONTEXT_WINDOW=131072\n"
)


class _FakeSession:
    def __init__(self):
        self.session_state = {"backend": "gemini-3.1-pro"}
        self.refreshed = False

    @staticmethod
    def _profile_blurb(values):
        url = (values.get("LLM_BASE_URL") or "").lower()
        return "local · free · private" if "127.0.0.1" in url else "cloud API · billed"

    def _refresh_footer(self):
        self.refreshed = True


class _Host(App):
    def __init__(self, session):
        super().__init__()
        self._session = session

    def on_mount(self):
        self.push_screen(ModelSettingsScreen(self._session))


def _write_env(tmp_path: Path, monkeypatch) -> Path:
    env = tmp_path / ".env"
    env.write_text(_ENV, encoding="utf-8")
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", env)
    return env


def test_lists_profiles_with_active_marker_and_windows(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _Host(_FakeSession())
        async with app.run_test() as pilot:
            await pilot.pause()
            t = app.screen.query_one("#ms-table", DataTable)
            return [[str(t.get_cell_at((r, c))) for c in range(4)] for r in range(t.row_count)]

    rows = asyncio.run(_run())
    assert len(rows) == 2
    by_model = {r[1]: r for r in rows}
    assert "gemini-3.1-pro" in by_model and "qwen2.5:7b" in by_model
    # active marker on the active (gemini) profile only
    assert "●" in by_model["gemini-3.1-pro"][0]
    assert "●" not in by_model["qwen2.5:7b"][0]
    # explicit per-profile window shown for ollama; 'auto' for gemini (none set)
    assert by_model["qwen2.5:7b"][3] == "131,072"
    assert by_model["gemini-3.1-pro"][3] == "auto"
    # local vs cloud where-column
    assert "local" in by_model["qwen2.5:7b"][2] and "cloud" in by_model["gemini-3.1-pro"][2]


def test_selecting_the_active_row_reports_already_active(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _Host(_FakeSession())
        async with app.run_test() as pilot:
            await pilot.pause()
            # row 0 is the active gemini profile; Enter -> RowSelected -> switch
            app.screen.query_one("#ms-table", DataTable).move_cursor(row=0)
            await pilot.press("enter")
            await pilot.pause()
            return str(app.screen.query_one("#ms-status", Static).render())

    status = asyncio.run(_run())
    assert "already active" in status.lower()

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
from textual.widgets import Button, DataTable, Input, Static, TabbedContent

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
        self._data_dir = None
        self._name_set = None

    @staticmethod
    def _profile_blurb(values):
        url = (values.get("LLM_BASE_URL") or "").lower()
        return "local · free · private" if "127.0.0.1" in url else "cloud API · billed"

    def _refresh_footer(self):
        pass

    def _set_user_name(self, name):
        self._name_set = name


class _FakeSessionFull(_FakeSession):
    """A session stub with the bits the 'This session' tab needs: targets, a
    session_id, a store that returns a name, and the four action flows (which
    just record the call so we can assert dispatch)."""

    def __init__(self):
        super().__init__()
        self.session_state = {"backend": "gemini-3.1-pro", "targets": ["10.0.0.1"], "session_id": "abc123"}
        self.calls: list = []

        class _Store:
            def get_session(self, sid):
                return {"name": "myproj"}

        self._store = _Store()

    def _target_flow(self, rest):
        self.calls.append(("target", rest))

    def _rename_flow(self, rest):
        self.calls.append(("name", rest))

    def _reset_flow(self):
        self.calls.append(("reset",))

    def _delete_flow(self):
        self.calls.append(("delete",))


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
            modal.query_one("#add-key", Input).value = "ollama"
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
            modal.query_one("#add-key", Input).value = "sk-x"
            modal.query_one("#add-model", Input).value = "m"
            modal.query_one("#add-window", Input).value = "500000"
            modal._ctx.detected_max = 262144   # a known ceiling
            modal.action_save()
            await pilot.pause()
            return dismissed["called"], str(modal.query_one("#add-hint", Static).render())

    called, hint = asyncio.run(_run())
    assert called is False               # blocked
    assert "Exceeds" in hint


def test_add_modal_requires_api_key():
    async def _run():
        app = _ScreenHost(AddModelModal())
        async with app.run_test() as pilot:
            await pilot.pause()
            modal = app.screen
            dismissed = {"called": False}
            modal.dismiss = lambda result=None: dismissed.__setitem__("called", True)
            modal.query_one("#add-url", Input).value = "https://api.example/v1"
            modal.query_one("#add-model", Input).value = "m"  # no key
            modal.action_save()
            await pilot.pause()
            return dismissed["called"], str(modal.query_one("#add-hint", Static).render())

    called, hint = asyncio.run(_run())
    assert called is False
    assert "api key" in hint.lower()


def test_add_duplicate_model_name_is_rejected(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(_FakeSession()))
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _dup(_modal):
                return {"LLM_BASE_URL": "https://api.gemini.example/v1", "LLM_API_KEY": "k",
                        "LLM_MODEL": "gemini-3.1-pro", "KRATOS_LLM_BACKEND": "openai_compatible"}

            monkeypatch.setattr(app, "push_screen_wait", _dup)
            app.screen.action_add()
            await pilot.pause()
            await pilot.pause()
            return str(app.screen.query_one("#ms-status", Static).render())

    assert "already exists" in asyncio.run(_run()).lower()


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


# ---------------------------------------------------------------------------
# Model delete -- active is guarded; an inactive profile is removed from .env
# ---------------------------------------------------------------------------
def test_delete_active_model_is_guarded(tmp_path, monkeypatch):
    env = _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(_FakeSession()))
        async with app.run_test() as pilot:
            await pilot.pause()
            app.screen.query_one("#ms-table", DataTable).move_cursor(row=0)  # active gemini
            app.screen.action_delete()
            await pilot.pause()
            return str(app.screen.query_one("#ms-status", Static).render())

    status = asyncio.run(_run())
    assert "active model" in status.lower()
    # nothing removed
    assert "gemini-3.1-pro" in env.read_text()


def test_delete_inactive_model_removes_it(tmp_path, monkeypatch):
    env = _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(_FakeSession()))
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_modal):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            app.screen.query_one("#ms-table", DataTable).move_cursor(row=1)  # inactive qwen
            app.screen.action_delete()
            await pilot.pause()
            await pilot.pause()
            return str(app.screen.query_one("#ms-status", Static).render())

    status = asyncio.run(_run())
    assert "deleted" in status.lower()
    assert "qwen2.5:7b" not in env.read_text()


# ---------------------------------------------------------------------------
# General tab -- setting your name persists + live-updates the session label
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Tools tab -- source resolution for code review (built-in via inspect, kept
# from its .py file)
# ---------------------------------------------------------------------------
def test_tool_source_reads_builtin_via_inspect():
    from kratos.agent.tools import TOOL_REGISTRY

    name = next(iter(TOOL_REGISTRY))  # any real built-in tool
    code, title, err = SettingsScreen._tool_source(object(), name, is_kept=False)
    assert err is None
    assert "def " in code
    assert name in title and "built-in" in title


def test_tool_source_reads_kept_from_file(tmp_path, monkeypatch):
    import json

    d = tmp_path / "kept_tools"
    d.mkdir()
    (d / "foo.py").write_text("# kept foo tool\ndef handler():\n    return {}\n", encoding="utf-8")
    (d / "metadata.json").write_text(json.dumps({"foo": {"source_file": "foo.py"}}), encoding="utf-8")
    monkeypatch.setattr("kratos.agent.self_write_loop.KEPT_TOOLS_DIR", d)

    code, title, err = SettingsScreen._tool_source(object(), "foo", is_kept=True)
    assert err is None
    assert "kept foo tool" in code
    assert "foo.py" in title


def test_general_tab_sets_user_name(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)
    fake = _FakeSession()
    fake._data_dir = tmp_path

    async def _run():
        app = _ScreenHost(SettingsScreen(fake))
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _name(_modal):
                return "Alice"

            monkeypatch.setattr(app, "push_screen_wait", _name)
            app.screen.query_one(TabbedContent).active = "tab-general"
            await pilot.pause()
            app.screen.action_set_name()
            await pilot.pause()
            await pilot.pause()
            # General tab is now a table: row 0 = name, col 1 = its value.
            return app.screen.query_one("#gen-table", DataTable).get_row_at(0)[1].plain

    shown = asyncio.run(_run())
    from kratos import kratos_config as kc

    assert kc.load_local_config(tmp_path).get("user_name") == "Alice"
    assert fake._name_set == "Alice"
    assert "Alice" in shown


def test_general_tab_theme_switch_applies_and_updates_label(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)
    from kratos.tui_mk2 import theme as T

    # Isolate the pref file + restore palette globals so this never touches
    # ~/.config or leaks the accent into other tests.
    monkeypatch.setattr(T, "_pref_path", lambda: tmp_path / "mk2_theme")
    snap = (T.ACCENT, T.KRATOS_RED, T.ADMIN)

    async def _run():
        app = _ScreenHost(SettingsScreen(_FakeSession()))
        calls = []
        async with app.run_test() as pilot:
            await pilot.pause()

            def _apply(name):  # stand-in for KratosTUI.apply_theme_pack (no theme registry here)
                calls.append(name)
                T.set_active_pack(name)
                app.screen.refresh_theme()
                return True

            monkeypatch.setattr(app, "apply_theme_pack", _apply, raising=False)

            async def _pick(_modal):
                return "kratos-blue"

            monkeypatch.setattr(app, "push_screen_wait", _pick)
            app.screen.query_one(TabbedContent).active = "tab-general"
            await pilot.pause()
            app.screen.action_set_theme()
            await pilot.pause()
            await pilot.pause()
            return (calls,
                    app.screen.query_one("#gen-table", DataTable).get_row_at(1)[1].plain,  # row 1 = theme
                    str(app.screen.query_one("#gen-status", Static).render()))

    try:
        calls, theme_label, status = asyncio.run(_run())
    finally:
        T.ACCENT, T.KRATOS_RED, T.ADMIN = snap
        monkeypatch.delenv("KRATOS_THEME", raising=False)

    assert calls == ["kratos-blue"]          # switcher delegated to the app
    assert "Slate Blue" in theme_label       # gen-theme label refreshed live
    assert "Slate Blue" in status


def test_general_tab_is_navigable_and_enter_dispatches(tmp_path, monkeypatch):
    # The General tab is a ↑↓ table (name / theme / timezone); Enter on the
    # highlighted row invokes that setting's flow.
    _write_env(tmp_path, monkeypatch)
    fake = _FakeSession()
    fake._data_dir = tmp_path
    fired: list[str] = []

    async def _run():
        app = _ScreenHost(SettingsScreen(fake))
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            monkeypatch.setattr(screen, "_set_name_flow", lambda: fired.append("name"))
            monkeypatch.setattr(screen, "_set_theme_flow", lambda: fired.append("theme"))
            monkeypatch.setattr(screen, "_set_timezone_flow", lambda: fired.append("timezone"))
            screen.query_one(TabbedContent).active = "tab-general"
            await pilot.pause()
            gen = screen.query_one("#gen-table", DataTable)
            assert gen.row_count == 3            # name / theme / timezone
            for row, expected in [(1, "theme"), (2, "timezone"), (0, "name")]:
                gen.move_cursor(row=row)
                screen.action_primary()          # Enter
                await pilot.pause()
            return fired

    assert asyncio.run(_run()) == ["theme", "timezone", "name"]


def test_settings_opens_from_home_with_no_session(tmp_path, monkeypatch):
    # Home-screen path: SettingsScreen(session=None, data_dir=...) must render
    # the (global) Models + General tabs without a live session, using the
    # data_dir directly and the shared profile blurb.
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(data_dir=tmp_path))  # no session
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            models = screen.query_one("#ms-table", DataTable).row_count
            assert screen._data_dir() == tmp_path      # data_dir came through directly
            gen = screen.query_one("#gen-table", DataTable).row_count
            return models, gen

    models, gen = asyncio.run(_run())
    assert models >= 1   # profiles listed (blurb rendered without a session)
    assert gen == 3      # name / theme / timezone present


def test_this_session_tab_absent_from_home(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)

    async def _run():
        app = _ScreenHost(SettingsScreen(data_dir=tmp_path))  # no session
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            return "tab-session" in screen._TABS, len(screen.query("#sess-table"))

    in_tabs, tables = asyncio.run(_run())
    assert in_tabs is False   # no session -> no session tab
    assert tables == 0        # and no session table rendered


def test_this_session_tab_dispatches_and_closes(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)
    fake = _FakeSessionFull()

    async def _run():
        app = _ScreenHost(SettingsScreen(fake))
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            assert "tab-session" in screen._TABS
            sess = screen.query_one("#sess-table", DataTable)
            assert sess.row_count == 4                       # target/name/reset/delete
            assert sess.get_row_at(0)[1].plain == "10.0.0.1"  # current target shown
            assert sess.get_row_at(1)[1].plain == "myproj"    # current name shown
            screen.query_one(TabbedContent).active = "tab-session"
            await pilot.pause()
            sess.move_cursor(row=3)          # Delete session
            screen.action_primary()          # Enter -> closes settings, acts in session
            await pilot.pause()
            return fake.calls

    assert asyncio.run(_run()) == [("delete",)]


def test_this_session_tab_target_row_dispatches(tmp_path, monkeypatch):
    _write_env(tmp_path, monkeypatch)
    fake = _FakeSessionFull()

    async def _run():
        app = _ScreenHost(SettingsScreen(fake))
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            screen.query_one(TabbedContent).active = "tab-session"
            await pilot.pause()
            screen.query_one("#sess-table", DataTable).move_cursor(row=0)  # Target
            screen.action_primary()
            await pilot.pause()
            return fake.calls

    assert asyncio.run(_run()) == [("target", "")]

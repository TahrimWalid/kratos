"""
Headless pilots for the mk2 SessionScreen's screen-management commands
(/clear and /reset). These are the shell-like "wipe the screen + reset the
working context" behaviors: /clear keeps the stored session history, /reset
archives it. The network-touching parts of /target (the SSH setup checklist +
probe, isolated in a thread worker) are verified manually, not here.
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos import llm_interface
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make_screen(tmp_path, monkeypatch, resume_context="prior resume context"):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], resume_context)


def test_clear_wipes_context_and_resets_token_meter(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Simulate a prior LLM call that filled the 7c context meter.
            llm_interface._last_usage = llm_interface.TokenUsage(
                prompt_tokens=5000, completion_tokens=0, total_tokens=5000)
            screen._dispatch_slash("/clear")
            await pilot.pause()
            return screen.session_state["resume_context"], llm_interface.get_last_token_usage()

    ctx, usage = asyncio.run(_run())
    assert ctx == ""            # working context cleared
    assert usage is None        # meter reset to 0 (was 5000)


def test_tools_command_renders_without_error(tmp_path, monkeypatch):
    # /tools classifies the real TOOL_REGISTRY into Default/Kept/Installed and
    # writes grouped tables — smoke-check it renders (no crash, content added).
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            before = len(screen._log.lines)
            screen._dispatch_slash("/tools")
            await pilot.pause()
            return before, len(screen._log.lines)

    before, after = asyncio.run(_run())
    assert after > before  # tables were written to the transcript


def test_reset_archives_history_and_clears(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    # Give the session a real turn so /reset has something to archive.
    turn_id = store.start_turn(sid, "look for brute force")
    store.complete_turn(turn_id, "final_answer", transcript_ref=None)
    assert store.get_goal_history(sid)  # precondition: history present

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_modal):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._dispatch_slash("/reset")
            await pilot.pause()
            await pilot.pause()
            return screen.session_state["resume_context"]

    ctx = asyncio.run(_run())
    assert ctx == ""
    assert store.get_goal_history(sid) == []  # archived (soft-deleted) — not shown going forward

"""
LaunchScreen (session picker) navigation — the archived-view back behavior.

Two fixes covered:
  * `b` (action_back) steps out of the archived view back to the recent list.
  * Backing out of the resume-tier prompt for an ARCHIVED session must NOT
    un-archive it and must NOT drop to the recent view — it stays archived and
    the archived view stays put. Committing a tier restores + opens it.
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.launch import LaunchScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make_launch(tmp_path):
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return store, sid, LaunchScreen(store, tmp_path)


def test_action_back_exits_archived_view(tmp_path):
    store, sid, screen = _make_launch(tmp_path)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_archived()
            await pilot.pause()
            assert screen._archived_mode is True
            screen.action_back()
            await pilot.pause()
            return screen._archived_mode

    assert asyncio.run(_run()) is False


def test_archived_tier_backout_keeps_view_and_does_not_restore(tmp_path, monkeypatch):
    store, sid, screen = _make_launch(tmp_path)
    store.archive_session(sid)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_archived()
            await pilot.pause()

            async def _backout(_modal):
                return None  # backed out of the tier prompt

            monkeypatch.setattr(app, "push_screen_wait", _backout)
            screen._resume_flow({"session_id": sid, "targets": ["10.0.0.1"], "status": "archived"})
            await pilot.pause()
            await pilot.pause()
            return screen._archived_mode, store.get_session(sid)["status"]

    mode, status = asyncio.run(_run())
    assert mode is True             # stayed in the archived view
    assert status == "archived"     # backing out did NOT un-archive it


def test_archived_resume_with_tier_restores_and_opens(tmp_path, monkeypatch):
    store, sid, screen = _make_launch(tmp_path)
    store.archive_session(sid)
    opened: list = []
    monkeypatch.setattr(screen, "_open_session", lambda *a, **k: opened.append(a))
    monkeypatch.setattr(screen, "_build_context", lambda s, t: "")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_archived()
            await pilot.pause()

            async def _light(_modal):
                return "l"

            monkeypatch.setattr(app, "push_screen_wait", _light)
            screen._resume_flow({"session_id": sid, "targets": ["10.0.0.1"], "status": "archived"})
            await pilot.pause()
            await pilot.pause()
            return store.get_session(sid)["status"], bool(opened)

    status, opened_ok = asyncio.run(_run())
    assert status == "active"       # committing a tier restores it
    assert opened_ok                # and opens the session

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


def test_guide_opens_from_launcher(tmp_path):
    # A first-time user must be able to learn about Kratos from the very first
    # screen (the session picker), via ? or g.
    from kratos.tui_mk2.modals import GuideModal

    store, sid, screen = _make_launch(tmp_path)

    async def _run():
        app = _Host(screen)
        async with app.run_test(size=(100, 32)) as pilot:
            await pilot.pause()
            await pilot.press("question_mark")
            await pilot.pause()
            return type(app.screen).__name__

    assert asyncio.run(_run()) == GuideModal.__name__


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


def test_bucket_for_relative_dates(tmp_path):
    from datetime import timedelta

    from kratos.utils import timeutil

    store, sid, screen = _make_launch(tmp_path)
    now = timeutil.utc_now()

    def ago(days):
        return (now - timedelta(days=days)).isoformat()

    assert screen._bucket_for(now.isoformat()) == "Today"
    assert screen._bucket_for(ago(1)) == "Yesterday"
    assert screen._bucket_for(ago(3)) == "This week"
    assert screen._bucket_for(ago(10)) == "This month"
    assert screen._bucket_for(ago(60)) == "Older"


def test_filter_narrows_sessions(tmp_path):
    store = SessionStore(tmp_path / "kratos.db")
    a = store.create_session(["10.0.0.1"], "m")
    store.rename_session(a, "alpha")
    b = store.create_session(["10.0.0.2"], "m")
    store.rename_session(b, "beta")
    screen = LaunchScreen(store, tmp_path)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            total = sum(1 for d in screen._display if d["kind"] == "session")
            screen._filter = "alpha"
            screen._rebuild_display()
            await pilot.pause()
            matched = [d["session"]["name"] for d in screen._display if d["kind"] == "session"]
            return total, matched

    total, matched = asyncio.run(_run())
    assert total == 2
    assert matched == ["alpha"]  # filtered to the one match


def test_bucket_header_row_is_inert(tmp_path):
    store = SessionStore(tmp_path / "kratos.db")
    store.create_session(["10.0.0.1"], "m")  # created now -> "Today" bucket
    screen = LaunchScreen(store, tmp_path)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            kinds = [d["kind"] for d in screen._display]
            return kinds, screen._session_at(0), screen._session_at(1)

    kinds, at0, at1 = asyncio.run(_run())
    assert kinds[0] == "header"   # a bucket header leads the unfiltered list
    assert at0 is None            # header row is inert (Enter does nothing)
    assert at1 is not None        # the session sits right beneath it


def test_id_column_is_dropped_on_a_narrow_terminal_and_returns_when_wide(tmp_path):
    """At 80 columns the 12-character id squeezed the name a newcomer scans by. Below 100
    columns it is hidden (the resume prompt still shows the full id); a resize brings it back."""
    store, sid, screen = _make_launch(tmp_path)
    store.rename_session(sid, "a fairly descriptive session name")
    seen: dict = {}

    def labels(table):
        return [str(c.label) for c in table.columns.values()]

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            table = screen.query_one("#sessions")
            seen["narrow"] = labels(table)
            seen["name_cell"] = next(str(c) for c in table.get_row_at(1) if "fairly" in str(c))
            await pilot.resize_terminal(140, 40)
            for _ in range(4):
                await pilot.pause()
            seen["wide"] = labels(table)
            await pilot.press("enter")  # the row still maps to the right session
            await pilot.pause()
            seen["resume_title"] = getattr(app.screen, "_session_id", None)

    asyncio.run(run())
    assert "id" not in seen["narrow"] and seen["narrow"][1] == "name"
    assert seen["name_cell"].startswith("a fairly descriptive session")  # ~12 chars with the id column
    assert "id" in seen["wide"]
    assert seen["resume_title"] == sid


def test_enter_in_filter_opens_a_single_match_and_lists_several(tmp_path, monkeypatch):
    """Typing a filter and pressing Enter opens the session when exactly one matches;
    with several it moves into the list so ↑↓ + Enter picks one."""
    store = SessionStore(tmp_path / "kratos.db")
    for name in ("alpha", "beta one", "beta two"):
        store.rename_session(store.create_session(["10.0.0.1"], "m"), name)
    screen = LaunchScreen(store, tmp_path)
    opened: list = []
    monkeypatch.setattr(screen, "_resume_flow", lambda s: opened.append(s["name"]))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            for q, expect_open in (("alpha", True), ("beta", False)):
                await pilot.press("slash")
                inp = screen.query_one("#filter")
                inp.value = ""
                for ch in q:
                    await pilot.press(ch)
                await pilot.press("enter")
                await pilot.pause()
                if expect_open:
                    assert opened == ["alpha"]
                else:
                    assert opened == ["alpha"]  # nothing new opened
                    assert app.focused is screen.query_one("#sessions")

    asyncio.run(_run())

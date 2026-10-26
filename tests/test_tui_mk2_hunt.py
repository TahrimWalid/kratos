"""C.3: /hunt in the TUI -- runs with no model, asks when a word is ambiguous, and the
report joins the conversation (as data) for a follow-up question."""
from __future__ import annotations

import asyncio
import time

from textual.app import App

from hunt_fixtures import event
from kratos.events.store import EventStore
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.modals import ClarifyModal
from kratos.tui_mk2.screens.session import SessionScreen

NOW = time.time()


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["web01"], "m")
    screen = SessionScreen(store, tmp_path, sid, ["web01"], "")
    shown: list[str] = []
    for name in ("_emit", "_emit_from_worker"):
        orig = getattr(screen, name)

        def capture(renderable, _orig=orig):
            shown.append(getattr(renderable, "plain", str(renderable)))
            return _orig(renderable)
        monkeypatch.setattr(screen, name, capture)

    def no_model(*_a, **_k):
        raise AssertionError("/hunt must not call the model")
    monkeypatch.setattr("kratos.llm_interface.agent_chat", no_model)
    return store, sid, screen, shown


async def _pump(pilot, screen, shown, tries=400):
    for _ in range(tries):
        await pilot.pause()
        if any("What was searched" in s for s in shown) and not screen._busy:
            return


def test_hunt_shows_the_report_and_keeps_it_as_context(tmp_path, monkeypatch):
    EventStore(tmp_path / "kratos.db").add([event(NOW - 3600, source_ip="198.51.100.7")])
    store, sid, screen, shown = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/hunt 198.51.100.7")
            await _pump(pilot, screen, shown)

    asyncio.run(_run())
    text = "\n".join(shown)
    assert "FOUND on web01" in text and "What was searched" in text
    ctx = screen.session_state["resume_context"]
    assert ctx.startswith("You: /hunt 198.51.100.7") and "FOUND on web01" in ctx
    assert any((t.get("goal") or "").startswith("/hunt") for t in store.get_goal_history(sid))
    from kratos.hunt import store as hstore

    assert hstore.recent(tmp_path)[0]["source"] == "tui"


def test_an_ambiguous_word_asks_which_kind(tmp_path, monkeypatch):
    EventStore(tmp_path / "kratos.db").add([event(NOW - 3600, user_name="alice")])
    _store, _sid, screen, shown = _make(tmp_path, monkeypatch)
    asked = {}

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                asked["modal"] = modal
                return "account"
            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/hunt alice")
            await _pump(pilot, screen, shown)

    asyncio.run(_run())
    assert isinstance(asked.get("modal"), ClarifyModal)
    assert "account name alice" in "\n".join(shown) and "FOUND on web01" in "\n".join(shown)


def test_a_bad_indicator_is_explained_not_run(tmp_path, monkeypatch):
    _store, _sid, screen, shown = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/hunt " + "a" * 32)
            for _ in range(50):
                await pilot.pause()

    asyncio.run(_run())
    text = "\n".join(shown)
    assert "SHA-256 hashes only" in text and "What was searched" not in text

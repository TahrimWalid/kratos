"""Headless pilots for group sessions (D.2): a question goes to the fleet front door (one
checked answer per machine), /run-fix is refused there, /look only opens machines of the
group, /groups edits are recorded as the TUI user."""
from __future__ import annotations

import asyncio

from kratos.fleet import groups as G
from kratos.fleet import run as fleet_run
from kratos.lifecycle.decide import Actor
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen
from tests.test_tui_mk2_session import _Host

A, B, C = "10.0.0.11", "10.0.0.12", "10.0.0.13"


def _screen(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    G.create_group(tmp_path, "lab", Actor("alice", "cli"), members=[A, B])
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["@lab"], "m")
    return SessionScreen(store, tmp_path, sid, ["@lab"], "")


def _text(screen) -> str:
    log = screen.query_one("#transcript")
    return "\n".join(str(getattr(line, "text", line)) for line in getattr(log, "lines", []))


def test_a_group_session_asks_the_fleet_and_refuses_fixes(tmp_path, monkeypatch):
    screen = _screen(tmp_path, monkeypatch)
    calls: list = []

    def fake_run(req):
        calls.append(req)
        return fleet_run.FleetOutcome("final_answer", "2 machines · 2 fully read\n== 10.0.0.11 -- fully read",
                                      group_label="@lab", results=[])

    monkeypatch.setattr(fleet_run, "run_fleet", fake_run)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._run_goal("who gained sudo this week?")
            for _ in range(50):                       # the turn runs on a thread worker
                await pilot.pause()
                if calls:
                    break
            await asyncio.sleep(0.3)
            await pilot.pause()
            screen._dispatch_slash("/run-fix")
            screen._dispatch_slash("/look 10.0.0.99")
            screen._dispatch_slash("/groups add lab 10.0.0.13")
            await pilot.pause()
            return _text(screen)

    text = asyncio.run(_run())
    assert calls and calls[0].group == "@lab" and calls[0].actor.interface == "tui"
    assert calls[0].question == "who gained sudo this week?"
    assert "never runs a fix on several machines" in text
    assert "10.0.0.99 is not a machine of @lab" in text
    assert C in G.get_group(tmp_path, "lab").members

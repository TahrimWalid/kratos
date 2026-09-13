"""Headless pilots for the A6.5 /schedule new → group flow (mk2)."""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.agent import presets as P
from kratos.agent import schedules as S
from kratos.agent import schedule_units as U
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


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
    sid = store.create_session(["10.0.0.1"], "m")
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def _answers(app, monkeypatch, values):
    it = iter(values)

    async def _fn(modal):
        return next(it)

    monkeypatch.setattr(app, "push_screen_wait", _fn)


def test_new_group_audit_plus_preset(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="deep", goal="deep hunt")
    monkeypatch.setattr("kratos.agent.scheduled_run.active_backend_is_cloud", lambda: False)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # kind, job1, job2, done, on_failure, name, cadence, min_sev
            _answers(app, monkeypatch,
                     ["group", "audit", "preset:deep", "__done__", "abort",
                      "nightly-suite", "daily", ""])
            screen._dispatch_slash("/schedule new")
            for _ in range(200):
                await pilot.pause()
                if S.schedule_exists(tmp_path, "nightly-suite"):
                    break

    asyncio.run(_run())
    g = S.load_schedule(tmp_path, "nightly-suite")
    assert g is not None and g.kind == "group" and g.on_failure == "abort"
    assert [j["kind"] for j in g.jobs] == ["audit", "preset"]
    assert g.jobs[1]["preset"] == "deep"
    assert (U.units_dir(tmp_path) / "kratos-nightly-suite.timer").exists()


def test_new_group_with_preset_on_cloud_warns_and_aborts(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="deep", goal="deep hunt")
    monkeypatch.setattr("kratos.agent.scheduled_run.active_backend_is_cloud", lambda: True)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # kind, job1(preset), done, cost-confirm=False -> abort
            _answers(app, monkeypatch, ["group", "preset:deep", "__done__", False])
            screen._dispatch_slash("/schedule new")
            for _ in range(120):
                await pilot.pause()

    asyncio.run(_run())
    assert not S.schedule_exists(tmp_path, "deep")
    assert all(s.kind != "group" for s in S.list_schedules(tmp_path)[0])


def test_new_group_cancel_at_first_job(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            _answers(app, monkeypatch, ["group", None])  # esc at the first job picker
            screen._dispatch_slash("/schedule new")
            for _ in range(80):
                await pilot.pause()

    asyncio.run(_run())
    assert S.list_schedules(tmp_path)[0] == []  # nothing created

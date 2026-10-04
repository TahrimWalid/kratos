"""Headless pilots for the A6.3 /schedule TUI flow.

The guided modals are answered via a monkeypatched push_screen_wait (matching
test_tui_mk2_presets.py); run_scheduled is spied so no real SSH/LLM runs. Verifies
the audit-schedule creation path writes a definition + systemd units, the cloud
cost-warning fires for an agentic preset on a cloud backend, and run-now invokes
the worker.
"""
from __future__ import annotations

import asyncio

from textual.app import App

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


def test_schedule_new_audit_writes_definition_and_units(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # kind, cadence, min_severity, name (asked last)
            _answers(app, monkeypatch, ["audit", "weekly", "high", "weekly-audit"])
            screen._dispatch_slash("/schedule new")
            for _ in range(200):
                await pilot.pause()
                if S.schedule_exists(tmp_path, "weekly-audit"):
                    break

    asyncio.run(_run())
    sch = S.load_schedule(tmp_path, "weekly-audit")
    assert sch is not None and sch.kind == "audit" and sch.cadence == "weekly"
    assert sch.min_severity == "high"
    # systemd units were staged
    assert (U.units_dir(tmp_path) / "kratos-weekly-audit.service").exists()
    assert (U.units_dir(tmp_path) / "kratos-weekly-audit.timer").exists()


def test_schedule_new_preset_on_cloud_warns_and_can_abort(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    store, sid, screen = _make(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="deep", goal="hunt ssh brute force")
    # Force a cloud backend so the cost warning fires.
    monkeypatch.setattr("kratos.agent.scheduled_run.active_backend_is_cloud", lambda: True)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # kind=preset, preset=deep, cost-confirm=False (abort)
            _answers(app, monkeypatch, ["preset", "deep", False])
            screen._dispatch_slash("/schedule new")
            for _ in range(120):
                await pilot.pause()

    asyncio.run(_run())
    # Aborted at the cost warning -> no schedule created.
    assert not S.schedule_exists(tmp_path, "deep")
    assert S.list_schedules(tmp_path)[0] == []


def test_schedulable_presets_excludes_ungraduated_generated(tmp_path, monkeypatch):
    """A generated (AI-drafted, un-acknowledged) pipeline is excluded from the
    schedulable set until it's graduated (confirmed once interactively) — so it
    can't be scheduled into a timer that would skip every fire. Confirming it
    (generated=False) makes it schedulable."""
    from kratos.agent import presets as P

    store, sid, screen = _make(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="normal", goal="hunt ssh brute force")
    P.save_preset(tmp_path, name="drafted", kind="pipeline", generated=True,
                  steps=[{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])

    schedulable, ungraduated = screen._schedulable_presets()
    assert "normal" in {p.name for p in schedulable}
    assert "drafted" not in {p.name for p in schedulable}
    assert [p.name for p in ungraduated] == ["drafted"]

    # Graduate it -> now schedulable, no longer flagged.
    P.save_preset(tmp_path, name="drafted", kind="pipeline", generated=False,
                  steps=[{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])
    schedulable2, ungraduated2 = screen._schedulable_presets()
    assert "drafted" in {p.name for p in schedulable2}
    assert ungraduated2 == []


def test_schedule_run_now_invokes_worker(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly")

    called = {}

    def _fake_run(schedule, data_dir, deliver=True, notifier=None):
        called["name"] = schedule.name
        return {"schedule": schedule.name, "status": "completed", "target": "10.0.0.1",
                "severity_tally": {}, "notified": False}

    monkeypatch.setattr("kratos.agent.scheduled_run.run_scheduled", _fake_run)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/schedule run-now wk")
            for _ in range(300):
                await pilot.pause()
                if called and not screen._busy and screen._busy_since is None:
                    break

    asyncio.run(_run())
    assert called.get("name") == "wk"


def test_schedule_list_renders_without_error(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    S.save_schedule(tmp_path, name="wk", kind="audit")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/schedule list")
            for _ in range(60):
                await pilot.pause()

    asyncio.run(_run())  # must not raise


def _recording_answers(app, monkeypatch, values, seen):
    it = iter(values)

    async def _fn(modal):
        seen.append(modal)
        return next(it)

    monkeypatch.setattr(app, "push_screen_wait", _fn)


def _drive(screen, monkeypatch, values, seen, done):
    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            _recording_answers(app, monkeypatch, values, seen)
            screen._dispatch_slash("/schedule new")
            for _ in range(200):
                await pilot.pause()
                if done():
                    break

    asyncio.run(_run())


def test_schedule_name_is_asked_last_and_enter_accepts_the_suggestion(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import PromptModal

    store, sid, screen = _make(tmp_path, monkeypatch)
    seen: list = []
    # kind, cadence, min_severity, then a blank name (= just pressing Enter)
    _drive(screen, monkeypatch, ["audit", "daily", "", ""], seen,
           lambda: S.schedule_exists(tmp_path, "daily-audit"))
    assert isinstance(seen[-1], PromptModal)                 # the name comes last
    assert seen[-1]._initial == "daily-audit"                # pre-filled from the answers
    assert S.load_schedule(tmp_path, "daily-audit").cadence == "daily"


def test_schedule_suggestion_skips_names_already_taken(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    S.save_schedule(tmp_path, name="weekly-audit", kind="audit", cadence="weekly")
    seen: list = []
    _drive(screen, monkeypatch, ["audit", "weekly", "", ""], seen,
           lambda: S.schedule_exists(tmp_path, "weekly-audit-2"))
    assert seen[-1]._initial == "weekly-audit-2"
    assert S.load_schedule(tmp_path, "weekly-audit").cadence == "weekly"   # untouched


def test_typing_an_existing_schedule_name_asks_before_replacing(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import ConfirmModal

    store, sid, screen = _make(tmp_path, monkeypatch)
    S.save_schedule(tmp_path, name="nightly", kind="audit", cadence="daily")
    seen: list = []
    # name "nightly" -> decline replace -> name prompt again -> "other"
    _drive(screen, monkeypatch, ["audit", "weekly", "", "nightly", False, "other"], seen,
           lambda: S.schedule_exists(tmp_path, "other"))
    assert any(isinstance(m, ConfirmModal) for m in seen)
    assert S.load_schedule(tmp_path, "nightly").cadence == "daily"   # not replaced
    assert S.load_schedule(tmp_path, "other").cadence == "weekly"


def test_schedule_list_says_when_ntfy_delivery_is_not_set_up(tmp_path, monkeypatch):
    from rich.console import Console

    from kratos.tui_mk2 import render as R

    sch = S.save_schedule(tmp_path, name="nightly", kind="audit", cadence="daily", deliver=["ntfy"])
    con = Console(width=120, record=True, color_system=None)
    monkeypatch.setattr("kratos.agent.notify.notify_config_status", lambda: ("off", ""))
    con.print(R.schedule_table([sch], []))
    assert "ntfy (not set up)" in con.export_text()
    monkeypatch.setattr("kratos.agent.notify.notify_config_status", lambda: ("ok", ""))
    con.print(R.schedule_table([sch], []))
    out = con.export_text()
    assert "ntfy" in out and "not set up" not in out

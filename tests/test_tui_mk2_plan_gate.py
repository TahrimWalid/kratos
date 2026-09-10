"""Headless tests for A6.1 in the mk2 TUI:

* the PlanPreviewModal's fail-safe key behaviour (y=run, n/esc=cancel);
* the pre-run gate wiring on /run (confirm -> the audit runs; cancel -> nothing
  runs and no turn is recorded);
* /plan gate on|off persistence.

No real SSH/LLM: the pipeline dispatcher is canned and the gate's modal is
driven either with real keys (the modal test) or via a monkeypatched
push_screen_wait (the wiring tests), matching test_tui_mk2_presets.py.
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos import kratos_config as _kc
from kratos.agent.plan_preview import preview_pipeline
from kratos.agent.pipeline import standard_audit_steps
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.modals import PlanPreviewModal
from kratos.tui_mk2.screens.session import SessionScreen


# --------------------------------------------------------------------------- #
# PlanPreviewModal fail-safe (INVARIANT 2: no force-accept)
# --------------------------------------------------------------------------- #
class _ModalHost(App):
    def __init__(self, modal):
        super().__init__()
        self._modal = modal
        self.result = "unset"

    def on_mount(self):
        self.push_screen(self._modal, lambda r: setattr(self, "result", r))


def _drive_modal(key: str):
    async def _run():
        preview = preview_pipeline(standard_audit_steps(), "10.0.0.1")
        app = _ModalHost(PlanPreviewModal(preview))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press(key)
            await pilot.pause()
            return app.result

    return asyncio.run(_run())


def test_modal_y_runs():
    assert _drive_modal("y") is True


def test_modal_n_cancels():
    assert _drive_modal("n") is False


def test_modal_escape_cancels():
    assert _drive_modal("escape") is False


# --------------------------------------------------------------------------- #
# Gate wiring on /run
# --------------------------------------------------------------------------- #
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
    screen = SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")

    findings = [{"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed",
                 "evidence": ["port 22 open"]}]

    def _canned(tool, args, data_dir):
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings, "count": 1}}
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _canned)
    return store, sid, screen


def _pump(pilot, screen, tries=400):
    async def _wait():
        for _ in range(tries):
            await pilot.pause()
            if not screen._busy and screen._busy_since is None:
                return

    return _wait()


def test_gate_confirm_runs_the_audit(tmp_path, monkeypatch):
    # Default gate ON. Confirm (push_screen_wait -> True, i.e. the user pressed y)
    # must run the audit and record a completed turn.
    store, sid, screen = _make(tmp_path, monkeypatch)
    seen = {}

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _confirm(modal):
                seen["modal"] = modal
                return True

            monkeypatch.setattr(app, "push_screen_wait", _confirm)
            screen._dispatch_slash("/run")
            await _pump(pilot, screen)

    asyncio.run(_run())
    assert isinstance(seen.get("modal"), PlanPreviewModal)
    turns = store.get_goal_history(sid)
    assert any(t.get("status") == "final_answer" and "standard audit" in (t.get("goal") or "")
               for t in turns), turns


def test_gate_cancel_runs_nothing(tmp_path, monkeypatch):
    # Cancel (push_screen_wait -> False) must NOT run the audit: no turn recorded,
    # clean state (INVARIANT 2 fail-safe).
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "push_screen_wait", lambda modal: _false())
            screen._dispatch_slash("/run")
            await _pump(pilot, screen)

    async def _false():
        return False

    asyncio.run(_run())
    turns = store.get_goal_history(sid)
    assert not any("standard audit" in (t.get("goal") or "") for t in turns), turns


# --------------------------------------------------------------------------- #
# /plan gate on|off persistence
# --------------------------------------------------------------------------- #
def test_plan_gate_toggle_persists(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    assert screen._plan_gate_enabled() is True  # default on

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/plan gate off")
            for _ in range(200):
                await pilot.pause()
                if screen._plan_gate_enabled() is False:
                    break

    asyncio.run(_run())
    assert screen._plan_gate_enabled() is False
    assert _kc.load_local_config(tmp_path).get("plan_gate") is False


def test_plan_no_arg_does_not_run(tmp_path, monkeypatch):
    # /plan with no arg only PREVIEWS -- it must never start a run (no turn).
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/plan")
            for _ in range(120):
                await pilot.pause()

    asyncio.run(_run())
    turns = store.get_goal_history(sid)
    assert not any("standard audit" in (t.get("goal") or "") for t in turns), turns

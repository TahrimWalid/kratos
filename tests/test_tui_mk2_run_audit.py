"""Headless pilot: the mk2 `/run` deterministic standard audit end-to-end.

Drives SessionScreen._run_standard_audit through the real Textual worker, with
the pipeline's dispatcher (execute_tool_call) swapped for a canned one so no real
SSH/LLM/nmap runs. Confirms the command wires to the engine, renders findings,
and records a completed turn.
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make_screen(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    # A6.1: /run is now gated by a pre-run preview+confirm (default on). This
    # test targets the engine-wiring path, so disable the gate to run directly;
    # the gate itself is covered by test_tui_mk2_plan_gate.py.
    from kratos import kratos_config as _kc
    _kc.save_local_config(tmp_path, plan_gate=False)
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def test_run_standard_audit_end_to_end(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    findings = [{"id": "NET-001", "severity": "high", "title": "SSH exposed",
                 "evidence": ["port 22 open"]}]

    def _canned(tool, args, data_dir):
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings, "count": 1,
                                               "findings_json_file": "/tmp/f.json"}}
        return {"status": "ok", "result": {}}

    # The engine uses `dispatch or execute_tool_call`; patch the module global.
    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _canned)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/run")
            # Wait for the thread worker to finish (it clears _busy in finally).
            for _ in range(400):
                await pilot.pause()
                if not screen._busy and screen._busy_since is None:
                    break
            return screen._collect_session_findings()

    collected = asyncio.run(_run())

    # A completed turn was recorded for the audit.
    turns = store.get_goal_history(sid)
    assert any(t.get("status") == "final_answer" for t in turns), turns
    assert any("standard audit" in (t.get("goal") or "") for t in turns), turns

    # /report's data path (_collect_session_findings) must surface the audit's
    # findings -- regression guard for the "no findings recorded" bug where the
    # audit transcript stored no wrapped `observation` for correlate_findings.
    assert [f[0]["id"] for f in collected] == ["NET-001"], collected


def test_run_audit_defers_when_target_busy(tmp_path, monkeypatch):
    """A6 §6: if the target is already locked (e.g. a background scheduled run),
    an interactive /run must defer -- dispatch nothing, record no turn."""
    from kratos.agent import target_lock as L

    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    ran = {"n": 0}

    def _canned(tool, args, data_dir):
        ran["n"] += 1
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _canned)
    # Don't actually wait 20s in the test — simulate "waited, still busy".
    monkeypatch.setattr("kratos.agent.target_lock.acquire_target_blocking",
                        lambda *a, **k: None)
    held = L.try_acquire_target(tmp_path, "10.0.0.1")  # the session's active target
    assert held is not None

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/run")
            for _ in range(60):
                await pilot.pause()
                if not screen._busy and screen._busy_since is None:
                    break

    try:
        asyncio.run(_run())
    finally:
        L.release_target(held)

    assert ran["n"] == 0  # deferred: nothing dispatched
    assert not any("standard audit" in (t.get("goal") or "") for t in store.get_goal_history(sid))


def test_pipeline_preset_run_records_turn_and_surfaces_findings(tmp_path, monkeypatch):
    """A2 Tier 2: running a kind='pipeline' preset drives the SAME shared
    _run_pipeline_turn worker, records a completed turn, and its findings reach
    /report (the wrapped-observation path). Canned dispatch -- no real SSH."""
    from kratos.agent import presets as P

    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="sweep", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True},
    ])
    findings = [{"id": "CORR-SSH-001", "severity": "high", "title": "brute force",
                 "evidence": ["many failed logins"]}]
    calls = []

    def _canned(tool, args, data_dir):
        calls.append(tool)
        if tool == "correlate_findings":
            return {"status": "ok", "result": {"findings": findings, "count": 1}}
        return {"status": "ok", "result": {}}

    monkeypatch.setattr("kratos.agent.pipeline.execute_tool_call", _canned)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset run sweep")
            for _ in range(400):
                await pilot.pause()
                if not screen._busy and screen._busy_since is None and calls:
                    break
            return screen._collect_session_findings()

    collected = asyncio.run(_run())

    assert calls == ["run_nmap_scan", "correlate_findings"]  # deterministic order
    turns = store.get_goal_history(sid)
    assert any(t.get("status") == "final_answer"
               and "sweep" in (t.get("goal") or "") for t in turns), turns
    assert [f[0]["id"] for f in collected] == ["CORR-SSH-001"], collected

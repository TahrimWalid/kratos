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
            return

    asyncio.run(_run())

    # A completed turn was recorded for the audit.
    turns = store.get_goal_history(sid)
    assert any(t.get("status") == "final_answer" for t in turns), turns
    assert any("standard audit" in (t.get("goal") or "") for t in turns), turns

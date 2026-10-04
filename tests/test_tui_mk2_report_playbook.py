"""Headless integration test for A6.2 auto-attach in /report.

Seeds a session with a completed turn whose transcript carries a HIGH finding
and an info finding (the shape _collect_session_findings reads), then drives
/report and spies on the response-plan renderer to confirm:
  * a HIGH finding gets a recommend-only response plan attached, and
  * an info finding does NOT (no manufactured urgency).
No real SSH/LLM.
"""
from __future__ import annotations

import asyncio
import json

from textual.app import App

from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _seed(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")

    findings = [
        {"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed",
         "evidence": ["port 22 open", "user=<script>evil</script>"]},
        {"id": "NET-001", "severity": "info", "title": "No open ports",
         "evidence": ["none"]},
    ]
    tid = store.start_turn(sid, "investigate ssh")
    transcripts = tmp_path / "sessions"
    transcripts.mkdir(parents=True, exist_ok=True)
    ref = transcripts / f"{sid}_turn{tid}.json"
    ref.write_text(json.dumps([
        {"tool": "correlate_findings",
         "observation": {"status": "ok", "result": {"findings": findings}}}
    ]), encoding="utf-8")
    store.complete_turn(tid, "final_answer", transcript_ref=str(ref))
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def test_report_attaches_plan_for_high_not_info(tmp_path, monkeypatch):
    store, sid, screen = _seed(tmp_path, monkeypatch)

    plans_rendered = []
    import kratos.tui_mk2.render as R

    real = R.response_plan_panel

    def _spy(plan, time_str=None):
        plans_rendered.append(plan)
        return real(plan, time_str=time_str)

    monkeypatch.setattr(R, "response_plan_panel", _spy)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._render_report()
            await pilot.pause()

    asyncio.run(_run())

    # Exactly one plan, for the HIGH finding; the info finding got none.
    assert [p.finding_id for p in plans_rendered] == ["CORR-SSH-001"]
    plan = plans_rendered[0]
    # Recommend-only + injection boundary holds end-to-end: the attacker payload
    # in the finding's evidence never reaches a command.
    allcmds = " ".join(c.command for s in plan.steps for c in s.commands)
    assert "evil" not in allcmds
    assert plan.has_destructive is True  # ufw/systemctl remediation flagged


def test_report_plan_commands_wrap_and_ctrl_y_copies_them(tmp_path, monkeypatch):
    """A long plan command was cut off at the panel edge ('... | ta'); it now wraps,
    so every character is on screen, and Ctrl+Y copies the plan's commands exactly."""
    from rich.console import Console

    import kratos.tui_mk2.render as R
    from kratos.agent.ir_playbooks import build_response_plan

    plan = build_response_plan({"id": "CORR-SSH-001", "severity": "high", "title": "SSH exposed",
                                "evidence": []})
    longest = max((c.command for s in plan.steps for c in s.commands), key=len)
    con = Console(width=70, record=True, color_system=None)
    con.print(R.response_plan_panel(plan))
    text = con.export_text()
    shown = "".join(line.strip("│ ") for line in text.splitlines())
    assert "".join(longest.split()) in "".join(shown.split())  # nothing cut off
    assert "Ctrl+Y copies this plan's commands" in text

    store, sid, screen = _seed(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._render_report()
            await pilot.pause()
            return list(screen._last_commands)

    copied = asyncio.run(_run())
    assert copied == [c.command for s in plan.steps for c in s.commands]

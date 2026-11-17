"""D.3 headless pilots: /assets (every machine, "not set up" shown, edits confirmed and
recorded), the one-time "how much does this machine matter?" question, and the
decision / exposure columns in /findings."""
from __future__ import annotations

import asyncio
import time
import uuid

from textual.app import App

from kratos import settings_store
from kratos.assets import store as AS
from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import nothing
from kratos.lifecycle.decide import Actor
from kratos.run_context import RunContext
from kratos.ssvc import settings as SS
from kratos.tui_mk2.screens import assets as SA
from kratos.tui_mk2.screens.findings import FindingsScreen

T = "10.0.0.5"


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _seed_findings(tmp_path):
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    act = {"outcome": "act", "label": "Act", "inputs": {}, "exposure": {"value": "internet", "reason": "r"}}
    track = {"outcome": "track", "label": "Track", "inputs": {}, "exposure": {"value": "not running", "reason": "r"}}
    A.apply_run([
        {"id": "PKG-001", "title": "low-sev act", "severity": "medium", "evidence": [], "subject": "openssh",
         "entities": ["CVE-2024-0001"], "ssvc": act},
        {"id": "PKG-001", "title": "crit track", "severity": "critical", "evidence": [], "subject": "curl",
         "entities": ["CVE-2024-0002"], "ssvc": track},
        {"id": "NET-002", "title": "ports", "severity": "high", "evidence": [], "subject": "", "entities": ["22/tcp"]},
    ], target=T, coverage=nothing(), run=r, data_dir=tmp_path)


def test_findings_rank_by_decision_and_show_its_columns(tmp_path):
    async def go():
        _seed_findings(tmp_path)
        screen = FindingsScreen(tmp_path, target=T)
        async with _Host(screen).run_test(size=(200, 40)) as pilot:
            await pilot.pause()
            rows = screen.visible_rows()
            assert [r["title"] for r in rows] == ["low-sev act", "ports", "crit track"]
            from kratos.ssvc import present
            assert [present.cell(r) for r in rows] == ["Act", "", "Track"]
            assert [present.exposure_cell(r) for r in rows] == ["internet", "", "not running"]
    asyncio.run(go())


def test_assets_screen_lists_machines_with_data_as_not_set_up(tmp_path):
    async def go():
        _seed_findings(tmp_path)
        AS.update(tmp_path, "10.0.0.6", Actor(user="alice", interface="tui"), criticality="low")
        screen = SA.AssetsScreen(tmp_path, configured=T)
        async with _Host(screen).run_test(size=(200, 40)) as pilot:
            await pilot.pause()
            rows = {a.target: a for a in screen._rows}
            assert not rows[T].set_up and rows["10.0.0.6"].criticality == "low"
    asyncio.run(go())


class _FakeApp:
    def __init__(self, answers):
        self.answers = list(answers)
        self.asked = []

    async def push_screen_wait(self, screen):
        self.asked.append(screen)
        return self.answers.pop(0)


def test_the_question_is_asked_once_and_any_answer_is_remembered(tmp_path):
    async def go():
        app = _FakeApp(["high"])
        assert await SA.ask_criticality_once(app, tmp_path, T, why="w") == "high"
        assert AS.get(tmp_path, T).criticality == "high" and len(app.asked) == 1
        app2 = _FakeApp([])
        assert await SA.ask_criticality_once(app2, tmp_path, T, why="w") is None and not app2.asked
        later = _FakeApp(["later"])
        assert await SA.ask_criticality_once(later, tmp_path, "10.0.0.7", why="w") is None
        assert AS.get(tmp_path, "10.0.0.7").criticality is None and not AS.needs_question(tmp_path, "10.0.0.7")
        events = AS.events(tmp_path, "10.0.0.7")
        assert [e["field"] for e in events] == ["asked"] and events[0]["interface"] == "tui"
    asyncio.run(go())


def test_the_question_can_be_turned_off(tmp_path):
    async def go():
        settings_store.set(SS.ASK_CRITICALITY, "off", data_dir=tmp_path, actor="test")
        app = _FakeApp(["high"])
        assert await SA.ask_criticality_once(app, tmp_path, T, why="w") is None and not app.asked
    asyncio.run(go())


def test_assets_fits_80_columns_with_role_and_note_in_the_detail_pane(tmp_path):
    """TUI review: role and owner note were cut at 80 columns; they are in the detail pane now."""
    from kratos.tui_mk2.screens.assets import AssetsScreen

    AS.update(tmp_path, "web-01.example.test", Actor("owner", "cli"), criticality="high", role="customer site",
              owner_note="ops team")

    class _A(App):
        def on_mount(self):
            self.push_screen(AssetsScreen(tmp_path))

    async def go():
        app = _A()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            scr = app.screen
            detail = str(scr.query_one("#as-detail")._Static__content)
            assert "role customer site" in detail and "note: ops team" in detail
            assert "esc back" in str(scr.query_one("#as-hints")._Static__content)
    asyncio.run(go())

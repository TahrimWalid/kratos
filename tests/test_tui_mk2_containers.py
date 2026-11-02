"""D.5 headless pilots: /containers (the table, stopped containers listed, details with
environment names only) and the copy-safe fix box in /findings."""
from __future__ import annotations

import asyncio
import time
import uuid

from textual.app import App

from kratos.containers import record as R
from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import nothing
from kratos.run_context import RunContext
from kratos.tui_mk2.modals import CommandModal, InfoModal
from kratos.tui_mk2.screens.containers import ContainersScreen
from kratos.tui_mk2.screens.findings import FindingsScreen

from test_containers_judge import PUBLISHED, ctr, inv

T = "192.0.2.10"


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def test_containers_screen_lists_running_then_stopped_with_marks_and_details(tmp_path):
    cs = [ctr("web", ports=PUBLISHED, env_keys=["DB_PASSWORD"]), ctr("old", running=False, state="exited"),
          ctr("p", privileged=True)]
    R.run(tmp_path, T, reader=lambda: inv(*cs), connect=lambda a, p: True)

    async def go():
        screen = ContainersScreen(tmp_path, target=T)
        async with _Host(screen).run_test(size=(200, 40)) as pilot:
            await pilot.pause()
            names = [r["name"] for r in screen._rows]
            assert names[-1] == "old" and set(names[:2]) == {"web", "p"}
            web = next(r for r in screen._rows if r["name"] == "web")
            assert any("reachable despite firewall" in p for p in web["ports"])
            table = screen.query_one("#ct-table")
            table.move_cursor(row=names.index("web"))
            await pilot.press("enter")
            await pilot.pause()
            modal = screen.app.screen
            assert isinstance(modal, InfoModal)
            text = str(modal._body.columns[1]._cells)
            assert "DB_PASSWORD" in text and "names only" in text
    asyncio.run(go())


def test_findings_x_opens_the_fix_in_the_copy_box(tmp_path):
    fix = [{"title": "Publish 8080 on 127.0.0.1 only", "text": "docker run ... -p 127.0.0.1:8080:80 ..."}]
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([{"id": "CONT-004", "title": "A container's published port(s) 8080/tcp reachable despite the firewall",
                  "severity": "high", "evidence": ["e"], "recommendation": ["r"], "subject": "web",
                  "entities": ["port:8080/tcp"], "fix": fix},
                 {"id": "NET-002", "title": "ports", "severity": "medium", "evidence": [], "subject": "",
                  "entities": ["22/tcp"]}], target=T, coverage=nothing(), run=r, data_dir=tmp_path)

    async def go():
        screen = FindingsScreen(tmp_path, target=T)
        async with _Host(screen).run_test(size=(200, 40)) as pilot:
            await pilot.pause()
            rows = screen.visible_rows()
            table = screen.query_one("#fd-table")
            table.move_cursor(row=[x["rule_id"] for x in rows].index("CONT-004"))
            await pilot.press("x")
            await pilot.pause()
            modal = screen.app.screen
            assert isinstance(modal, CommandModal)
            assert "-p 127.0.0.1:8080:80" in modal._command and "Kratos does not run this" in modal._note
            await pilot.press("escape")
            table.move_cursor(row=[x["rule_id"] for x in rows].index("NET-002"))
            await pilot.press("x")
            await pilot.pause()
            assert not isinstance(screen.app.screen, CommandModal)
    asyncio.run(go())

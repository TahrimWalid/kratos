"""/machines (A5): one row per machine, the selected one explained underneath."""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.storage.session_store import SessionStore
from kratos.storage.subagent_store import SubAgentStore
from kratos.tui_mk2.screens.machines import MachinesScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _seed(tmp_path):
    st = SessionStore(tmp_path / "kratos.db")
    st.create_session(["web-01"], "m")
    st.create_session(["10.0.4.12"], "m")
    st.create_session(["127.0.0.1"], "m")            # Kratos's own host is not a machine row
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="db-01")["code"]
    tid = sa.redeem_pairing_code(code, agent_id="a1", hostname="db-01", agent_version="0.3.0")["target_id"]
    sa.set_link("db-01", tid, "subagent")
    from kratos.tui_mk2 import target_memory as TM
    TM.record_check(tmp_path, "10.0.4.12", "ssh", [{"check": "a", "status": "FAIL"}, {"check": "b", "status": "PASS"}])


def test_every_known_machine_gets_one_row(tmp_path):
    _seed(tmp_path)

    async def _run():
        app = _Host(MachinesScreen(tmp_path, active="web-01"))
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            scr = app.screen
            return [m["host"] for m in scr._rows], {m["host"]: m for m in scr._rows}

    hosts, by = asyncio.run(_run())
    assert sorted(hosts) == ["10.0.4.12", "db-01", "web-01"]
    assert by["db-01"]["reached"] == "agent"
    assert by["10.0.4.12"]["setup"] == "issues" and by["10.0.4.12"]["needs_look"]
    assert hosts.index("10.0.4.12") < hosts.index("web-01")     # needs-a-look first


def test_enter_opens_findings_for_the_selected_machine(tmp_path):
    _seed(tmp_path)

    async def _run():
        app = _Host(MachinesScreen(tmp_path, active="web-01"))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            scr = app.screen
            want = scr._rows[0]["host"]
            await pilot.press("enter")
            await pilot.pause()
            return want, type(app.screen).__name__, getattr(app.screen, "_target", None)

    want, name, target = asyncio.run(_run())
    assert name == "FindingsScreen" and want.lower() in str(target).lower()


def test_allowlist_needs_a_paired_agent(tmp_path):
    _seed(tmp_path)

    async def _run():
        app = _Host(MachinesScreen(tmp_path))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            scr = app.screen
            row = next(i for i, m in enumerate(scr._rows) if m["host"] == "web-01")
            scr.query_one("#m-table").move_cursor(row=row)
            await pilot.press("x")
            await pilot.pause()
            first = type(app.screen).__name__
            row = next(i for i, m in enumerate(scr._rows) if m["host"] == "db-01")
            scr.query_one("#m-table").move_cursor(row=row)
            await pilot.press("x")
            await pilot.pause()
            return first, type(app.screen).__name__

    first, second = asyncio.run(_run())
    assert first == "MachinesScreen"          # SSH-only machine: nothing can run there, so no allowlist
    assert second == "WhitelistScreen"

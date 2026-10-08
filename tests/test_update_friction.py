"""
Keeping the listener and the agents current without remembering to:

- an always-on listener restarts itself onto newer code once the code has
  settled and it is idle (never mid-read, never mid-run, never for a process
  started by hand);
- /subagent and /doctor say when a machine's agent is older than this Kratos,
  and that `g` updates it.
"""
from __future__ import annotations

import argparse
import asyncio
from types import SimpleNamespace

import pytest

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import core_server as CS
from kratos.subagent import status as ST
from kratos.subagent.agent import AGENT_VERSION
from kratos.utils import build_info as B


class _Clock:
    def __init__(self):
        self.t = 10_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def server(tmp_path, monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(CS.time, "monotonic", clock)
    srv = CS.CoreServer(SubAgentStore(tmp_path / "kratos.db"), host="127.0.0.1", port=0, mode="service")
    srv._stop_event = asyncio.Event()
    srv.clock = clock
    disk = {"build": "0.1.0+bbbb.f2"}
    monkeypatch.setattr(B, "newer_build_on_disk", lambda: disk["build"])
    srv.disk = disk
    monkeypatch.delenv("KRATOS_LISTENER_AUTO_RESTART", raising=False)
    return srv


def _tick(srv):
    return asyncio.run(srv._ready_to_restart_for_update())


def test_restarts_only_after_the_code_settles_and_the_listener_is_idle(server):
    server._last_activity = server.clock.t - 3600
    assert _tick(server) is False                                  # first sight of new code
    server.clock.t += CS.CODE_SETTLE_SECONDS - 1
    assert _tick(server) is False                                  # still settling
    server.clock.t += 2
    assert _tick(server) is True and server.restart_for_update == "0.1.0+bbbb.f2"
    assert server._stop_event.is_set()


def test_code_that_keeps_changing_resets_the_wait(server):
    server._last_activity = server.clock.t - 3600
    _tick(server)
    server.clock.t += CS.CODE_SETTLE_SECONDS + 1
    server.disk["build"] = "0.1.0+cccc.f3"                         # a pull still in progress
    assert _tick(server) is False
    server.clock.t += CS.CODE_SETTLE_SECONDS + 1
    assert _tick(server) is True


def test_never_while_busy_or_recently_active(server):
    _tick(server)
    server.clock.t += CS.CODE_SETTLE_SECONDS + 1
    server._last_activity = server.clock.t - 5                     # a read a few seconds ago
    assert _tick(server) is False
    server._last_activity = server.clock.t - 3600
    server._pending_reads["r1"] = ("t1", None)                     # a read in flight
    assert _tick(server) is False
    server._pending_reads.clear()
    server._servicing_dispatch = True                              # a fix being sent
    assert _tick(server) is False
    server._servicing_dispatch = False
    assert _tick(server) is True


@pytest.mark.parametrize("mode", ["process", "in_process"])
def test_only_a_service_restarts_itself(server, mode):
    server.mode = mode
    server._last_activity = server.clock.t - 3600
    _tick(server)
    server.clock.t += CS.CODE_SETTLE_SECONDS + 1
    assert _tick(server) is False and not server._stop_event.is_set()


def test_it_can_be_turned_off(server, monkeypatch):
    monkeypatch.setenv("KRATOS_LISTENER_AUTO_RESTART", "0")
    server._last_activity = server.clock.t - 3600
    _tick(server)
    server.clock.t += CS.CODE_SETTLE_SECONDS + 1
    assert _tick(server) is False


def test_same_code_never_restarts(server):
    server.disk["build"] = None
    server._last_activity = server.clock.t - 3600
    for _ in range(3):
        server.clock.t += CS.CODE_SETTLE_SECONDS + 1
        assert _tick(server) is False


def test_subagent_serve_exits_so_systemd_restarts_it(tmp_path, monkeypatch):
    from kratos.cli import app as cli
    from kratos.subagent import core_server

    class _Restarting:
        def __init__(self, store, **kw):
            self.host = kw.get("host")
            self.restart_for_update = "0.1.0+bbbb.f2"

        async def serve_forever(self):
            return None

        async def close(self):
            return None

    monkeypatch.setattr(core_server, "CoreServer", _Restarting)
    code = cli.cmd_subagent_serve(argparse.Namespace(data_dir=tmp_path, host="127.0.0.1", port=0))
    assert code == CS.RESTART_EXIT_CODE != 0


def test_listener_line_says_a_service_updates_itself():
    from kratos.subagent import core_listener as CL

    lst = [{"mode": "service", "pid": 1, "build": "0.1.0+aaaa.f1"}]
    msg, _sev, _offer = CL.describe_listener(lst, in_process_here=False, disk_build="0.1.0+bbbb.f2",
                                             scope="user", linger=True)
    assert "restarts itself" in msg


@pytest.mark.parametrize("version,outdated", [
    ("0.3.0", True), ("0.1.0", True), (AGENT_VERSION, False), ("9.0.0", False), (None, False), ("weird", False),
])
def test_agent_outdated(version, outdated):
    assert ST.agent_outdated(version) is outdated


def test_subagent_screen_offers_the_update(tmp_path):
    from textual.app import App

    from kratos.tui_mk2.screens.subagent import SubAgentScreen

    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="db-01")["code"]
    sa.redeem_pairing_code(code, agent_id="a1", hostname="db-01", agent_version="0.3.0")
    screen = SubAgentScreen(tmp_path)
    out = {}

    class Host(App):
        def on_mount(self):
            self.push_screen(screen)

    async def run():
        async with Host().run_test(size=(200, 50)) as pilot:
            await pilot.pause()
            out["line"] = str(screen.query_one("#sa-listener")._Static__content)

    asyncio.run(run())
    assert f"agent update ({AGENT_VERSION}) is ready for db-01" in out["line"] and "press g" in out["line"]


def test_doctor_warns_about_an_outdated_agent(monkeypatch, tmp_path):
    from kratos import kratos_config as kc
    from kratos.agent import doctor
    from kratos.subagent import local_reads, routing

    kc.set_active_data_dir(tmp_path)
    link = SimpleNamespace(mode=routing.MODE_SUBAGENT, revoked=False, label="db-01", target_id="t1")
    monkeypatch.setattr(routing, "link_for", lambda target, d: link)
    monkeypatch.setattr(local_reads, "listener_status", lambda d: {
        "mode": "service", "live": {"t1": {"agent_version": "0.3.0", "reads": True, "read_probes": ["clock"]}}})
    out: list = []
    try:
        assert doctor._check_transport(out, "10.0.0.5") is True
    finally:
        kc.set_active_data_dir(None)
    row = out[-1]
    assert row["status"] == "warn" and "press g" in row["fix"] and AGENT_VERSION in row["detail"]


def test_the_service_unit_treats_the_update_restart_as_deliberate(tmp_path):
    from kratos.subagent import core_listener as CL

    unit = CL.core_service_unit(tmp_path, user_mode=True)
    assert "Restart=always" in unit
    assert f"SuccessExitStatus={CS.RESTART_EXIT_CODE}" in unit and f"RestartForceExitStatus={CS.RESTART_EXIT_CODE}" in unit

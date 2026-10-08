"""
Review v2 F-3: the whitelist version is bounded, a refused push is answered
(not dropped), and the operator can recover when a machine has applied a
newer version than Kratos's own count (Kratos's database restored from an
older copy, or something else holding the pairing pushed to it).

Nothing here enables execution: every agent runs against a loopback test
server with execution off (pushes don't need it).
"""
from __future__ import annotations

import asyncio
import io
import shutil
import subprocess

import pytest
from rich.console import Console
from textual.app import App

from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import core_server as core_mod
from kratos.subagent import installer
from kratos.subagent import protocol as proto
from kratos.subagent import signing
from kratos.tui_mk2.modals import CommandModal, ConfirmModal
from kratos.tui_mk2.screens.whitelist import WhitelistScreen

from test_subagent_execution_channel import _free_port, _pair_agent, _start_server, _stop_agent, _wait_until


def _pair(sa: SubAgentStore, name: str = "web-01") -> str:
    code = sa.create_pairing_code(name=name)["code"]
    return sa.redeem_pairing_code(code, agent_id="a1", hostname=name, agent_version="0.3.5")["target_id"]


# --- store --------------------------------------------------------------
def test_catch_up_moves_only_forward_and_past_the_agents_version(tmp_path):
    wl = WhitelistStore(tmp_path / "kratos.db")
    with pytest.raises(ValueError, match="nothing to catch up"):
        wl.catch_up_whitelist_version("t1")
    wl.request_resync("t1")                                   # Kratos's count: 1
    wl.record_push_refused("t1", 1, 40, "version 1 is older than 40 (anti-rollback)")
    assert wl.push_refusal_needs_catch_up("t1")
    assert wl.catch_up_whitelist_version("t1") == 41
    assert not wl.push_refusal_needs_catch_up("t1")          # Kratos is ahead now
    wl.record_push_ack("t1", 41, [], None)
    assert wl.get_push_refusal("t1") is None                 # an accepted push clears it


def test_a_refusal_that_is_not_about_age_does_not_offer_catch_up(tmp_path):
    wl = WhitelistStore(tmp_path / "kratos.db")
    wl.request_resync("t1")
    wl.record_push_refused("t1", None, None, "actions is not a list")
    assert not wl.push_refusal_needs_catch_up("t1")
    wl.record_push_refused("t1", 1, 1, "something else")      # same version: not behind
    assert not wl.push_refusal_needs_catch_up("t1")


def test_catch_up_at_the_top_of_the_range_needs_the_targets_admin(tmp_path):
    wl = WhitelistStore(tmp_path / "kratos.db")
    wl.record_push_refused("t1", 1, proto.MAX_WHITELIST_VERSION, "older")
    with pytest.raises(ValueError, match="admin has to reset it"):
        wl.catch_up_whitelist_version("t1")


def test_kratos_never_counts_past_what_an_agent_accepts(tmp_path):
    wl = WhitelistStore(tmp_path / "kratos.db")
    wl.record_push_refused("t1", 1, proto.MAX_WHITELIST_VERSION - 1, "older")
    assert wl.catch_up_whitelist_version("t1") == proto.MAX_WHITELIST_VERSION
    with pytest.raises(ValueError, match="would pass"):
        wl.request_resync("t1")


# --- real socket: refusal reaches core, no re-push storm, catch-up recovers --
def test_refused_push_is_recorded_not_retried_and_catch_up_recovers(tmp_path, monkeypatch):
    monkeypatch.setattr(core_mod, "WHITELIST_WATCH_INTERVAL_SECONDS", 0.05)

    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        wl = WhitelistStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port, whitelist_store=wl)
        try:
            agent, task, tid = await _pair_agent(store, port, tmp_path)
            try:
                await _wait_until(lambda: agent._whitelist_version == 0)
                # Something else holding this pairing pushes version 50 (or
                # Kratos's DB is restored from before it had sent 50).
                token = store.get_target(tid)["token"]
                env = {"type": proto.MSG_WHITELIST_PUSH, "version": 50, "actions": []}
                env["sig"] = signing.sign_envelope(signing.derive_signing_key(token), env)
                await proto.write_frame(server._live[tid], env)
                await _wait_until(lambda: agent._whitelist_version == 50)

                pushes = []
                real_push = server.push_whitelist

                async def counting_push(*a, **kw):
                    pushes.append(a[3])
                    return await real_push(*a, **kw)

                server.push_whitelist = counting_push
                wl.request_resync(tid)                                   # Kratos's count: 1
                await _wait_until(lambda: wl.get_push_refusal(tid) is not None)
                refusal = wl.get_push_refusal(tid)
                assert refusal["refused_version"] == 1 and refusal["agent_floor"] == 50
                assert "anti-rollback" in refusal["reason"]
                assert wl.push_refusal_needs_catch_up(tid)
                await asyncio.sleep(0.5)                                 # ~10 watch ticks
                assert pushes == [1]                                     # not re-pushed every tick
                assert agent._whitelist_version == 50                    # and nothing rolled back

                assert wl.catch_up_whitelist_version(tid) == 51
                await _wait_until(lambda: agent._whitelist_version == 51)
                await _wait_until(lambda: wl.get_push_refusal(tid) is None)
                assert pushes == [1, 51]
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


def test_an_agent_refusing_a_huge_version_tells_core_and_keeps_working(tmp_path):
    async def run():
        store = SubAgentStore(tmp_path / "kratos.db")
        port = _free_port()
        server = await _start_server(store, port)
        try:
            agent, task, tid = await _pair_agent(store, port, tmp_path)
            try:
                token = store.get_target(tid)["token"]
                assert await server.push_whitelist(tid, token, [], 2**70) is False
                assert server._push_refused[tid] == 2**70
                assert agent._version_floor() is None
                assert await server.push_whitelist(tid, token, [], 1) is True
                assert agent._whitelist_version == 1 and tid not in server._push_refused
            finally:
                await _stop_agent(agent, task)
        finally:
            await server.close()

    asyncio.run(run())


# --- the target-side reset command --------------------------------------
@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh available")
def test_reset_command_is_valid_sh_and_names_the_service():
    cmd = installer.reset_whitelist_floor_command("kratos-subagent")
    assert subprocess.run(["sh", "-n", "-c", cmd], capture_output=True).returncode == 0
    assert "--reset-whitelist-floor" in cmd and "systemctl stop kratos-subagent" in cmd
    with pytest.raises(installer.InstallerError):
        installer.reset_whitelist_floor_command("x; id")


# --- /whitelist ---------------------------------------------------------
class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _banner(screen) -> str:
    buf = io.StringIO()
    Console(file=buf, width=300).print(screen.query_one("#wl-banner").render())
    return buf.getvalue()


def test_whitelist_screen_explains_and_catches_up_on_a_real_keypress(tmp_path):
    sa, wl = SubAgentStore(tmp_path / "kratos.db"), WhitelistStore(tmp_path / "kratos.db")
    tid = _pair(sa)
    before = wl.get_whitelist_version(tid)
    wl.record_push_refused(tid, before, 40, f"version {before} is older than 40 (anti-rollback)")
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()
            banner = _banner(screen)
            await pilot.press("s")
            await pilot.pause()
            assert isinstance(app.screen, ConfirmModal)
            await pilot.press("y")
            await pilot.pause()
            return banner

    banner = asyncio.run(run())
    assert "already applied allowlist version 40" in banner and "press s to catch up" in banner
    assert wl.get_whitelist_version(tid) == 41


def test_whitelist_catch_up_declined_by_a_stray_key_changes_nothing(tmp_path):
    sa, wl = SubAgentStore(tmp_path / "kratos.db"), WhitelistStore(tmp_path / "kratos.db")
    tid = _pair(sa)
    before = wl.get_whitelist_version(tid)
    wl.record_push_refused(tid, before, 40, "older (anti-rollback)")
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            await pilot.press("q")
            await pilot.pause()

    asyncio.run(run())
    assert wl.get_whitelist_version(tid) == before


def test_whitelist_at_the_top_of_the_range_shows_the_target_side_reset(tmp_path):
    sa, wl = SubAgentStore(tmp_path / "kratos.db"), WhitelistStore(tmp_path / "kratos.db")
    tid = _pair(sa)
    before = wl.get_whitelist_version(tid)
    wl.record_push_refused(tid, before, proto.MAX_WHITELIST_VERSION, "older (anti-rollback)")
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            return app.screen

    shown = asyncio.run(run())
    assert isinstance(shown, CommandModal)
    assert "--reset-whitelist-floor" in shown._command
    assert wl.get_whitelist_version(tid) == before

"""
Headless Textual pilots for the sub-agent onboarding screen
(tui_mk2/screens/subagent.py). Nothing here connects to a target or runs the
agent -- the add-a-server flow is driven with canned modal responses, and the
"waiting for check-in" poll is exercised both ways (times out with no agent;
succeeds when a target row appears in the store).
"""
from __future__ import annotations

import asyncio
import io

from rich.console import Console
from textual.app import App

from kratos.storage.subagent_store import SubAgentStore
from kratos.tui_mk2.screens import subagent as sa_mod
from kratos.tui_mk2.screens.subagent import SubAgentScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _log_texts(screen: SubAgentScreen) -> list[str]:
    out = []
    for st in screen.query("#sa-log Static"):
        content = getattr(st, "_Static__content", None)
        if content is None:
            continue
        buf = io.StringIO()
        Console(file=buf, width=160).print(content)
        out.append(buf.getvalue())
    return out


def _pair(sa: SubAgentStore, name: str = "web-01") -> str:
    code = sa.create_pairing_code(name=name)["code"]
    return sa.redeem_pairing_code(code, agent_id="a1", hostname=name, agent_version="0.3.0")["target_id"]


def test_empty_state_shows_no_targets_row(tmp_path):
    screen = SubAgentScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            table = screen.query_one("#sa-table")
            assert table.row_count == 1  # the "— no paired targets yet —" placeholder

    asyncio.run(run())


def test_paired_target_appears_with_status(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    _pair(sa, "web-01")
    screen = SubAgentScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            table = screen.query_one("#sa-table")
            assert table.row_count == 1
            assert len(screen._targets) == 1
            assert screen._targets[0]["name"] == "web-01"

    asyncio.run(run())


def test_add_server_flow_writes_installer_and_creates_code(tmp_path, monkeypatch):
    # Fast, deterministic: canned modal answers, no serve socket, quick timeout.
    screen = SubAgentScreen(tmp_path)
    captured: dict[str, list[str]] = {}

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            # name, hub address pick, deploy-over-SSH? (decline)
            answers = iter(["web-01", "100.97.223.65", False])

            async def canned(_modal):
                return next(answers)

            monkeypatch.setattr(app, "push_screen_wait", canned)

            screen.action_add_server()
            await app.workers.wait_for_complete()
            await pilot.pause()
            captured["texts"] = _log_texts(screen)  # capture before the app tears down

    asyncio.run(run())

    # A pairing code was created and an installer script was written to data_dir.
    scripts = list(tmp_path.glob("kratos-subagent-install-*.sh"))
    assert len(scripts) == 1
    body = scripts[0].read_text()
    assert body.startswith("#!/bin/sh")
    assert "100.97.223.65" in body
    assert "--enable-execution" not in body  # onboarding never enables cap2

    texts = captured["texts"]
    assert any("Pairing code for web-01" in t for t in texts)
    assert any("Saved a one-command installer" in t for t in texts)
    # _Host has no ensure_core_listener, so the flow falls to the manual-listener hint.
    assert any("No listener is running" in t for t in texts)


def test_check_in_is_announced_by_the_refresh_not_a_blocking_wait(tmp_path):
    """WS7: a code started here is announced once when it's used -- from the
    regular refresh, so it works even after the add flow has returned."""
    sa = SubAgentStore(tmp_path / "kratos.db")
    screen = SubAgentScreen(tmp_path)
    captured: dict = {}

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            code = sa.create_pairing_code(name="web-02", core_host="10.0.0.1")["code"]
            screen._watched_codes[code] = {"name": "web-02", "host": "10.0.0.1"}
            screen._refresh()
            captured["pending_row"] = str(screen.query_one("#sa-table").get_row_at(0)[5])
            sa.redeem_pairing_code(code, agent_id="a", hostname="web-02", agent_version="0.2.0")
            screen._refresh()
            screen._refresh()  # announced once, not twice
            captured["texts"] = _log_texts(screen)

    asyncio.run(run())
    assert "expires in" in captured["pending_row"]
    assert sum("web-02 paired" in t for t in captured["texts"]) == 1


def test_command_modal_copies_and_closes(monkeypatch):
    from kratos.tui_mk2.modals import CommandModal

    cmd = "echo 'ssh-ed25519 AAAA x@y' >> ~/.ssh/authorized_keys"
    copied: list[str] = []

    class _App(App):
        def on_mount(self):
            pass

    async def run():
        app = _App()
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "copy_to_clipboard", lambda t: copied.append(t))
            app.push_screen(CommandModal(cmd, title="Authorize", note="run on target"))
            await pilot.pause()
            await pilot.press("c")  # copy
            await pilot.pause()
            assert copied == [cmd]
            await pilot.press("escape")  # close
            await pilot.pause()
            assert not any(isinstance(s, CommandModal) for s in app.screen_stack)

    asyncio.run(run())


def test_copy_commands_action(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import CommandModal

    sa = SubAgentStore(tmp_path / "kratos.db")
    _pair(sa, "web-01")
    screen = SubAgentScreen(tmp_path)
    notes: list[str] = []

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "notify", lambda *a, **k: notes.append(a[0] if a else ""))
            # Nothing added yet in this session -> notify, no modal.
            screen.action_copy_commands()
            await pilot.pause()
            assert notes and "add a server first" in notes[0]
            assert not any(isinstance(s, CommandModal) for s in app.screen_stack)
            # Once commands exist, 'c' pops a copy box with them.
            screen._last_deploy_commands = screen._deploy_commands(tmp_path / "install-web-01.sh", "ubuntu@1.2.3.4")
            screen.action_copy_commands()
            await pilot.pause()
            modal = next((s for s in app.screen_stack if isinstance(s, CommandModal)), None)
            assert modal is not None
            assert "scp" in modal._command and "ubuntu@1.2.3.4" in modal._command

    asyncio.run(run())


def test_deploy_commands_shape(tmp_path):
    screen = SubAgentScreen(tmp_path)
    cmds = screen._deploy_commands(tmp_path / "kratos-subagent-install-web-01.sh", "ubuntu@host")
    assert "scp" in cmds and "ubuntu@host:~/" in cmds
    assert "ssh ubuntu@host 'sh kratos-subagent-install-web-01.sh && rm -f kratos-subagent-install-web-01.sh'" in cmds


def test_valid_ssh_address():
    assert sa_mod.valid_ssh_address("ubuntu@203.0.113.5") is None
    assert sa_mod.valid_ssh_address("myhost") is None
    assert sa_mod.valid_ssh_address("-oProxyCommand=evil") is not None  # would be an ssh option
    assert sa_mod.valid_ssh_address("ubuntu@host; rm -rf ~") is not None
    assert sa_mod.valid_ssh_address("ubuntu@") is not None
    assert sa_mod.valid_ssh_address("") is not None


def test_manual_hub_address_prompt(tmp_path, monkeypatch):
    screen = SubAgentScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # name -> pick "__manual__" -> typed address -> decline SSH deploy
            answers = iter(["srv", "__manual__", "vpn.example.com", False])

            async def canned(_modal):
                return next(answers)

            monkeypatch.setattr(app, "push_screen_wait", canned)
            screen.action_add_server()
            await app.workers.wait_for_complete()
            await pilot.pause()

    asyncio.run(run())
    scripts = list(tmp_path.glob("kratos-subagent-install-*.sh"))
    assert len(scripts) == 1
    assert "vpn.example.com" in scripts[0].read_text()


def test_table_shows_the_assessed_state_not_just_last_seen(tmp_path):
    """WS1: with no listener running, a recently-seen target reads "not watched"
    (its state is unknown), not "connected"; with a listener and a stalled
    connection it reads "telemetry stalled", never "connected"."""
    from kratos.utils.timeutil import utc_now_iso

    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa)
    screen = SubAgentScreen(tmp_path)
    labels: list = []

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            labels.append(str(screen.query_one("#sa-table").get_row_at(0)[0]))
            sa.register_listener("L1", pid=1, host="0.0.0.0", port=8765, mode="service", build="b")
            sa.record_connection_open(tid, listener_id="L1", peer="10.0.0.9", collect_interval=30, ping_interval=10)
            sa._write("UPDATE subagent_connections SET connected_at = ?, last_telemetry_at = ? WHERE target_id = ?",
                      ("2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00", tid))
            sa._write("UPDATE subagent_connections SET last_frame_at = ? WHERE target_id = ?", (utc_now_iso(), tid))
            screen._refresh()
            await pilot.pause()
            row = screen.query_one("#sa-table").get_row_at(0)
            labels.append(str(row[0]))
            labels.append(str(row[5]))

    asyncio.run(run())
    assert "not watched" in labels[0]
    assert "telemetry stalled" in labels[1] and "no snapshot" in labels[2]

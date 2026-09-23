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
    monkeypatch.setattr(sa_mod, "_CHECKIN_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(sa_mod, "_CHECKIN_POLL_SECONDS", 0.01)
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


def test_await_checkin_detects_new_target(tmp_path, monkeypatch):
    monkeypatch.setattr(sa_mod, "_CHECKIN_TIMEOUT_SECONDS", 2.0)
    monkeypatch.setattr(sa_mod, "_CHECKIN_POLL_SECONDS", 0.01)
    sa = SubAgentStore(tmp_path / "kratos.db")
    screen = SubAgentScreen(tmp_path)
    captured: dict[str, list[str]] = {}

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            pre_ids: set[str] = set(t["target_id"] for t in sa.list_targets())
            # Simulate the target checking in a moment after we start waiting.
            _pair(sa, "web-02")
            await screen._await_checkin(pre_ids, "web-02")
            captured["texts"] = _log_texts(screen)

    asyncio.run(run())
    assert any("paired" in t and "telemetry live" in t for t in captured["texts"])


def test_manual_hub_address_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(sa_mod, "_CHECKIN_TIMEOUT_SECONDS", 0.02)
    monkeypatch.setattr(sa_mod, "_CHECKIN_POLL_SECONDS", 0.01)
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

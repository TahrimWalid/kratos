"""Listener lifecycle clarity (connection-UX WS2): who is receiving telemetry right now,
whether it survives closing Kratos, and an `L` that says what it will do and proves it
happened."""
from __future__ import annotations

import asyncio
import subprocess

from textual.app import App

from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import core_listener as CL
from kratos.tui_mk2.screens import subagent as SA
from kratos.tui_mk2.screens.subagent import SubAgentScreen

SVC = {"mode": "service", "pid": 42, "build": "0.1.0+abc"}


def test_describe_listener_matrix():
    msg, sev, offer = CL.describe_listener([], in_process_here=False, disk_build="x", scope=None, linger=None)
    assert "Not listening" in msg and sev == "critical" and offer
    msg, sev, offer = CL.describe_listener([SVC], in_process_here=False, disk_build="0.1.0+abc", scope="system", linger=None)
    assert "keeps receiving after you close Kratos" in msg and "Starts at boot" in msg and sev == "ok" and not offer
    msg, sev, offer = CL.describe_listener([SVC], in_process_here=False, disk_build="0.1.0+abc", scope="user", linger=False)
    assert "lingering is OFF" in msg and offer
    msg, sev, offer = CL.describe_listener([SVC], in_process_here=False, disk_build="0.1.0+NEW", scope="user", linger=True)
    assert "older build" in msg and offer
    msg, _, _ = CL.describe_listener([{"mode": "in_process", "pid": 1}], in_process_here=True, disk_build="x",
                                     scope=None, linger=None)
    assert "STOPS when you quit" in msg
    msg, _, _ = CL.describe_listener([{"mode": "process", "pid": 7}], in_process_here=False, disk_build="x",
                                     scope=None, linger=None)
    assert "terminal" in msg and "pid 7" in msg


def test_service_plan_explains_before_acting():
    assert CL.service_plan(passwordless_sudo=True, linger=None, scope_now=None)[0] is False
    user_mode, text = CL.service_plan(passwordless_sudo=False, linger=False, scope_now=None)
    assert user_mode and "Lingering is OFF" in text
    user_mode, text = CL.service_plan(passwordless_sudo=False, linger=None, scope_now="user")
    assert user_mode and "restarts it" in text
    assert CL.core_service_restart_commands(user_mode=True)[-1].startswith("systemctl --user restart")


class _Host(App):
    def __init__(self, screen, inproc=False):
        super().__init__()
        self._screen = screen
        self._inproc = inproc
        self.stopped = 0
        self.ensured = 0

    def on_mount(self):
        self.push_screen(self._screen)

    def core_listener_in_process(self):
        return self._inproc

    def stop_core_listener(self):
        self.stopped += 1
        was, self._inproc = self._inproc, False
        return was

    def ensure_core_listener(self):
        self.ensured += 1
        return "in_process"


def _line(screen) -> str:
    return str(screen.query_one("#sa-listener")._Static__content)


def test_listener_line_in_the_real_screen(tmp_path, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    screen = SubAgentScreen(tmp_path)
    monkeypatch.setattr(SubAgentScreen, "_service_facts", lambda self: ("user", False))
    lines = []

    async def run():
        app = _Host(screen, inproc=True)
        async with app.run_test() as pilot:
            await pilot.pause()
            lines.append(_line(screen))
            sa.register_listener("L1", pid=99, host="0.0.0.0", port=8765, mode="in_process", build="b")
            screen._refresh()
            lines.append(_line(screen))
            sa.stop_listener("L1")
            sa.register_listener("L2", pid=100, host="0.0.0.0", port=8765, mode="service", build="b")
            screen._refresh()
            lines.append(_line(screen))

    asyncio.run(run())
    assert "Not listening" in lines[0]
    assert "STOPS when you quit" in lines[1]
    assert "lingering is OFF" in lines[2]


def _drive_L(tmp_path, monkeypatch, *, register_service: bool, linger_ok: bool = True):
    sa = SubAgentStore(tmp_path / "kratos.db")
    monkeypatch.setattr(SA, "_SERVICE_CONFIRM_SECONDS", 1.0)
    monkeypatch.setattr(CL, "service_scope", lambda *a, **k: None)
    monkeypatch.setattr(CL, "linger_enabled", lambda *a, **k: False)
    monkeypatch.setattr(CL, "passwordless_sudo_available", lambda: False)
    ran: list = []

    def fake_run(cmd, **kw):
        ran.append(cmd)
        if isinstance(cmd, str) and "enable --now" in cmd and register_service:
            sa.register_listener("Lsvc", pid=555, host="0.0.0.0", port=8765, mode="service", build="b")
        if isinstance(cmd, list) and cmd[:2] == ["loginctl", "enable-linger"]:
            return subprocess.CompletedProcess(cmd, 0 if linger_ok else 1, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    screen = SubAgentScreen(tmp_path)
    out: dict = {}

    async def fake_wait(modal):
        out.setdefault("modals", []).append(modal)
        return True

    async def run():
        app = _Host(screen, inproc=True)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen_wait = fake_wait
            screen.action_install_service()
            for _ in range(60):
                await pilot.pause()
                await asyncio.sleep(0.05)
            out["texts"] = [str(st._Static__content) for st in screen.query("#sa-log Static")]
            out["app"] = app
            out["screens"] = [type(s_).__name__ for s_ in app.screen_stack]

    asyncio.run(run())
    out["ran"] = ran
    return out


def test_L_installs_hands_over_the_port_and_confirms_for_real(tmp_path, monkeypatch):
    out = _drive_L(tmp_path, monkeypatch, register_service=True)
    assert "Lingering is OFF" in out["modals"][0]._body  # explained BEFORE acting
    assert out["app"].stopped == 1  # in-process listener handed the port over
    assert any("enable --now" in c for c in out["ran"] if isinstance(c, str))
    assert any(isinstance(c, list) and c[:2] == ["loginctl", "enable-linger"] for c in out["ran"])
    assert any("Always-on listener running (pid 555)" in t for t in out["texts"])


def test_L_failure_restores_the_in_process_listener(tmp_path, monkeypatch):
    out = _drive_L(tmp_path, monkeypatch, register_service=False, linger_ok=False)
    assert out["app"].ensured >= 1  # never left without a listener
    assert any("Couldn't set up the always-on listener" in t for t in out["texts"])
    assert "CommandModal" in out["screens"]  # the commands, copy-safe

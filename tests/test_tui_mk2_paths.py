"""E.1 `/paths` in the TUI: the four blocks (entry points, paths to what matters, the fix
that cuts the most, coverage), `r` builds / rebuilds, nothing reads a machine."""
from __future__ import annotations

import asyncio
import io

from rich.console import Console
from textual.app import App

from kratos import authz
from kratos.assets import store as assets
from kratos.attackpaths import build as PB
from kratos.fleet import groups as fg
from kratos.tui_mk2.screens.paths import PathsScreen

import tests.test_attackpaths_build as T


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _body_text(screen) -> str:
    buf = io.StringIO()
    con = Console(file=buf, width=200)
    con.print(screen.query_one("#pa-content").render())
    return buf.getvalue()


def _seed(tmp_path):
    owner = authz.owner_actor("cli")
    T._write_live(tmp_path, "web", listeners=[{"port": 443, "proto": "tcp", "address": "0.0.0.0", "exe": "nginx",
                                              "seen": True, "package": "nginx"}], local_addresses=["203.0.113.5"])
    T._seed_keys(tmp_path, "web", [("deploy", "SHA256:AAAA")])
    T._seed_finding(tmp_path, "web", T._pkg_act())
    assets.update(tmp_path, "web", owner, exposure_override="internet")
    T._write_live(tmp_path, "db", listeners=[{"port": 22, "proto": "tcp", "address": "0.0.0.0", "exe": "sshd",
                                            "seen": True, "package": "openssh"}], local_addresses=["10.0.0.9"])
    T._seed_keys(tmp_path, "db", [("deploy", "SHA256:AAAA")])
    assets.update(tmp_path, "db", owner, criticality="critical")
    fg.create_group(tmp_path, "lab", owner, members=["web", "db"])


def test_paths_screen_shows_blocks_after_build(tmp_path):
    asyncio.run(_run(tmp_path))


async def _run(tmp_path):
    _seed(tmp_path)
    # no build yet -> screen says coverage, not safe
    screen = PathsScreen(tmp_path, group="lab")
    app = _Host(screen)
    async with app.run_test(size=(200, 50)) as pilot:
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "No attack-path build yet" in _body_text(screen)
        # press r to build
        await pilot.press("r")
        for _ in range(80):
            await pilot.pause(0.1)
            await app.workers.wait_for_complete()
            if not screen._busy and "Entry points" in _body_text(screen):
                break
        body = _body_text(screen)
        assert "Entry points" in body
        assert "Paths to what matters" in body
        assert "Fix this first" in body
        assert "What Kratos couldn't see" in body
        assert "db" in body        # the critical crown jewel is named in a path
        # TUI review: the title is said once, in the screen's accent title row, and "esc back"
        assert "Attack paths for" not in body
        banner = screen.query_one("#pa-banner").render()
        assert str(banner).startswith("Attack paths") and "@lab" in str(banner)
        hints = str(screen.query_one("#pa-hints").render())
        assert "esc back" in hints and "escape" not in hints


def test_paths_screen_reads_no_machine(tmp_path, monkeypatch):
    _seed(tmp_path)
    PB.run_path_build(data_dir=tmp_path, group="lab", actor=authz.owner_actor("cli"), source="interactive")

    import kratos.adapters.ssh_remote as ssh
    for name in ("run_remote_command", "run_remote_script", "fetch_live_response"):
        if hasattr(ssh, name):
            monkeypatch.setattr(ssh, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError("read a machine")),
                                raising=False)
    asyncio.run(_show(tmp_path))


async def _show(tmp_path):
    screen = PathsScreen(tmp_path, group="lab")
    app = _Host(screen)
    async with app.run_test(size=(200, 50)) as pilot:
        await app.workers.wait_for_complete()
        await pilot.pause()
        assert "Entry points" in _body_text(screen)

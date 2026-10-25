"""Where a person sees the encrypted agent link (Phase C.4): `kratos subagent-tls`,
the pins in `kratos subagent-install`, the /subagent link column and banner,
/doctor's agent-link row and the Settings switch."""
from __future__ import annotations

import argparse
import asyncio

from textual.app import App

from kratos import settings_store
from kratos.agent import doctor
from kratos.cli import app as cli
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import tls
from kratos.tui_mk2.screens.subagent import SubAgentScreen


def _pair(store: SubAgentStore, name: str, mode: str | None, pin_version: int | None = None) -> str:
    code = store.create_pairing_code(name=name)["code"]
    tid = store.redeem_pairing_code(code, agent_id=name, hostname=name, agent_version="0.8.0")["target_id"]
    if mode:
        store.record_link(tid, mode=mode, pin_version=pin_version)
    return tid


def test_cli_status_and_rotate_with_its_safety_check(tmp_path, capsys):
    store = SubAgentStore(tmp_path / "kratos.db")
    ks = tls.ensure_keys(tmp_path)
    tid = _pair(store, "web", tls.LINK_TLS, ks.version)
    _pair(store, "legacy", tls.LINK_PLAIN)
    ns = lambda action, force=False: argparse.Namespace(data_dir=tmp_path, action=action, force=force)  # noqa: E731

    assert cli.cmd_subagent_tls(ns("status")) == 0
    out = capsys.readouterr().out
    assert ks.active_pin in out and ks.backup_pin in out and "copy it somewhere safe" in out
    assert "legacy" in out and "plaintext" in out and "Update 1 agent(s)" in out

    assert cli.cmd_subagent_tls(ns("rotate")) == 0
    assert tls.load_keys(tmp_path).version == 2
    capsys.readouterr()
    # "web" still holds pin set 1: a second rotation would cut it off
    assert cli.cmd_subagent_tls(ns("rotate")) == 1
    assert "Not rotating" in capsys.readouterr().err and tls.load_keys(tmp_path).version == 2
    store.record_pin_version(tid, 2)
    assert cli.cmd_subagent_tls(ns("rotate")) == 0
    assert tls.load_keys(tmp_path).version == 3


def test_cli_status_fails_on_damaged_keys(tmp_path, capsys):
    ks = tls.ensure_keys(tmp_path)
    ks.backup_key_path.chmod(0o644)
    assert cli.cmd_subagent_tls(argparse.Namespace(data_dir=tmp_path, action="status", force=False)) == 1
    assert "UNUSABLE" in capsys.readouterr().out


def test_subagent_install_embeds_the_pins(tmp_path):
    out = tmp_path / "i.sh"
    args = argparse.Namespace(data_dir=tmp_path, code=None, name="web", core_host="10.0.0.5", core_port=8765,
                              trusted_interfaces=[], output=str(out))
    assert cli.cmd_subagent_install(args) == 0
    ks = tls.load_keys(tmp_path)
    script = out.read_text()
    assert f"--server-pin {ks.active_pin} --server-pin {ks.backup_pin} --server-pins-version 1" in script
    assert "--allow-untrusted-transport" not in script


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _render(tmp_path) -> tuple[list[str], str]:
    screen = SubAgentScreen(tmp_path)
    out: dict = {}

    async def run():
        async with _Host(screen).run_test(size=(200, 40)) as pilot:
            await pilot.pause()
            table = screen.query_one("#sa-table")
            out["links"] = [str(table.get_row_at(i)[4]) for i in range(table.row_count)]
            out["listener"] = str(screen.query_one("#sa-listener").render())

    asyncio.run(run())
    return out["links"], out["listener"]


def test_subagent_screen_shows_the_link_and_a_banner_while_any_agent_is_plaintext(tmp_path):
    store = SubAgentStore(tmp_path / "kratos.db")
    _pair(store, "secure", tls.LINK_TLS, 1)
    _pair(store, "legacy", tls.LINK_PLAIN)
    links, banner = _render(tmp_path)
    assert sorted(links) == ["encrypted", "plain → g"]
    assert "legacy still connects without encryption" in banner
    settings_store.set(tls.REQUIRE, "on", data_dir=tmp_path, actor="test")
    _, banner = _render(tmp_path)
    assert "can't connect until updated" in banner


def test_no_banner_when_every_agent_is_encrypted(tmp_path):
    store = SubAgentStore(tmp_path / "kratos.db")
    _pair(store, "secure", tls.LINK_TLS, 1)
    _, banner = _render(tmp_path)
    assert "without encryption" not in banner


def test_installers_made_on_the_subagent_screen_carry_the_pins(tmp_path):
    screen = SubAgentScreen(tmp_path)

    async def run():
        async with _Host(screen).run_test() as pilot:
            await pilot.pause()
            path = screen._write_installer("web", "10.0.0.5", "1A2B-3C4D")
            assert screen._allow_untrusted == {}
            assert await screen._ask_plain_network("192.168.1.10") is False  # no question: the link is pinned
            return path.read_text()

    script = asyncio.run(run())
    ks = tls.load_keys(tmp_path)
    assert f"--server-pin {ks.active_pin}" in script


def _doctor_row(tmp_path):
    out: list = []
    doctor._check_agent_link(out, tmp_path)
    assert len(out) == 1
    return out[0]


def test_doctor_agent_link_row(tmp_path):
    assert _doctor_row(tmp_path)["status"] == "info"
    store = SubAgentStore(tmp_path / "kratos.db")
    tls.ensure_keys(tmp_path)
    _pair(store, "secure", tls.LINK_TLS, 1)
    row = _doctor_row(tmp_path)
    assert row["status"] == "pass" and "1 of 1 agent(s) encrypted" in row["detail"]
    _pair(store, "legacy", tls.LINK_PLAIN)
    assert _doctor_row(tmp_path)["status"] == "warn"
    settings_store.set(tls.REQUIRE, "on", data_dir=tmp_path, actor="test")
    row = _doctor_row(tmp_path)
    assert row["status"] == "fail" and "refused" in row["detail"]
    tls.load_keys(tmp_path).key_path.chmod(0o640)
    assert _doctor_row(tmp_path)["status"] == "fail"
    assert "agent link" in {r["check"] for r in doctor.run_diagnostics(tmp_path)}


def test_settings_asks_before_requiring_encryption_with_plaintext_agents(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens.settings import SettingsScreen

    store = SubAgentStore(tmp_path / "kratos.db")
    _pair(store, "legacy", tls.LINK_PLAIN)
    screen = SettingsScreen(data_dir=tmp_path)
    answers = iter(["on", False, "on", True])
    shown: list = []

    async def fake_wait(modal):
        shown.append(type(modal).__name__)
        return next(answers)

    async def run():
        async with _Host(screen).run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(screen.app, "push_screen_wait", fake_wait)
            screen._set_agent_link_setting_flow(tls.REQUIRE)
            await pilot.pause(0.3)
            assert tls.require_encryption(tmp_path) is False  # declined at the confirm
            screen._set_agent_link_setting_flow(tls.REQUIRE)
            await pilot.pause(0.3)

    asyncio.run(run())
    assert shown == ["ListPickerModal", "ConfirmModal", "ListPickerModal", "ConfirmModal"]
    assert tls.require_encryption(tmp_path) is True

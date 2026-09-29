"""/subagent SSH deploy (connection-UX WS3): every failure is explained with its next step and a
copy-safe fix command, a successful install that won't survive logout/reboot says so, and a
waiting code can be re-deployed with `d` after fixing the cause."""
from __future__ import annotations

import asyncio
import io
import subprocess
from types import SimpleNamespace

import pytest
from rich.console import Console
from textual.app import App

from kratos.storage.subagent_store import SubAgentStore, _expiry_iso
from kratos.tui_mk2.modals import CommandModal
from kratos.tui_mk2.screens import subagent as sa_mod
from kratos.tui_mk2.screens.subagent import SubAgentScreen
from kratos.utils import ssh_keys


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _texts(screen) -> str:
    out = []
    for st in screen.query("#sa-log Static"):
        buf = io.StringIO()
        Console(file=buf, width=200).print(st._Static__content)
        out.append(buf.getvalue())
    return "\n".join(out)


def _run(screen, script, *, fake_wait=None):
    out: dict = {}

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            if fake_wait is not None:
                app.push_screen_wait = fake_wait
            await script(app, pilot)
            for _ in range(10):
                await pilot.pause()
            out["texts"] = _texts(screen)
            out["screen"] = app.screen

    asyncio.run(run())
    return out


@pytest.fixture
def key(tmp_path, monkeypatch):
    k = tmp_path / "keys" / "id_ed25519"
    k.parent.mkdir()
    k.write_text("PRIVATE")
    (k.parent / "id_ed25519.pub").write_text("ssh-ed25519 AAAAKEY kratos@core\n")
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_KEY_PATH", k)
    return k


# --- ssh_keys --------------------------------------------------------------
def test_authorize_command_is_idempotent_and_quote_safe():
    cmd = ssh_keys.authorize_key_command("ssh-ed25519 AAAA it's@me")
    assert "grep -qxF 'ssh-ed25519 AAAA it'\\''s@me'" in cmd
    assert cmd.startswith("mkdir -p ~/.ssh && chmod 700 ~/.ssh") and cmd.endswith("chmod 600 ~/.ssh/authorized_keys")


def test_authorize_command_really_works_in_sh(tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("ssh-rsa OLD old@x")  # no trailing newline
    cmd = ssh_keys.authorize_key_command("ssh-ed25519 NEW new@y")
    for _ in range(2):
        subprocess.run(["sh", "-c", cmd], check=True, env={"HOME": str(home), "PATH": "/usr/bin:/bin"})
    assert (home / ".ssh" / "authorized_keys").read_text() == "ssh-rsa OLD old@x\nssh-ed25519 NEW new@y\n"


def test_pubkey_missing_or_malformed(tmp_path, monkeypatch):
    k = tmp_path / "id"
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_KEY_PATH", k)
    assert ssh_keys.read_local_pubkey() is None and ssh_keys.authorize_key_command() is None
    (tmp_path / "id.pub").write_text("garbage")
    assert ssh_keys.read_local_pubkey() is None


def test_generate_local_key_creates_once_and_never_overwrites(tmp_path, monkeypatch):
    k = tmp_path / "new" / "id_ed25519"
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_KEY_PATH", k)
    pub = ssh_keys.generate_local_key(comment="kratos@test")
    assert pub.startswith("ssh-ed25519 ") and pub.endswith("kratos@test") and k.exists()
    with pytest.raises(ssh_keys.KeyGenError):
        ssh_keys.generate_local_key()


# --- deploy flow -----------------------------------------------------------
def test_ssh_options_offer_only_kratos_key(key):
    opts = SubAgentScreen._ssh_options()
    assert "IdentitiesOnly=yes" in opts and str(key) in opts and "BatchMode=yes" in opts


def test_publickey_failure_pops_the_authorize_box_for_the_target(tmp_path, key):
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        await asyncio.to_thread(
            screen._deploy_failed, "ubuntu@10.0.0.5", "ubuntu@10.0.0.5: Permission denied (publickey).")

    out = _run(screen, script)
    assert isinstance(out["screen"], CommandModal)
    assert "ssh-ed25519 AAAAKEY kratos@core" in out["screen"]._command
    assert "doesn't accept this machine's SSH key" in out["texts"]


def test_changed_host_key_box_runs_on_this_machine(tmp_path, key):
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        await asyncio.to_thread(screen._deploy_failed, "ubuntu@10.0.0.5",
                                "Host key for 10.0.0.5 has changed and you have requested strict checking.\n"
                                "Host key verification failed.")

    out = _run(screen, script)
    assert out["screen"]._command == "ssh-keygen -R 10.0.0.5"
    assert "man-in-the-middle" in out["texts"]


def test_successful_user_install_without_linger_warns(tmp_path, key, monkeypatch):
    screen = SubAgentScreen(tmp_path)
    script_file = tmp_path / "kratos-subagent-install-web.sh"
    script_file.write_text("#!/bin/sh\n")
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        out = "KRATOS_INSTALL_OK mode=user service=kratos-subagent dir=/home/u/.kratos-subagent linger=no\n"
        return SimpleNamespace(returncode=0, stdout=out if argv[0] == "ssh" else "", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    async def script(app, pilot):
        screen._ssh_deploy_worker(str(script_file), "u@h", None)
        for _ in range(20):
            await pilot.pause()

    out = _run(screen, script)
    assert calls[0][0] == "scp" and "--" in calls[0] and calls[1][-1].endswith("&& rm -f kratos-subagent-install-web.sh")
    assert isinstance(out["screen"], CommandModal) and "enable-linger" in out["screen"]._command
    assert "Installer ran on u@h" in out["texts"]


def test_install_timeout_is_not_blamed_on_the_network(tmp_path, key, monkeypatch):
    screen = SubAgentScreen(tmp_path)

    def fake_run(argv, **kw):
        if argv[0] == "scp":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        raise subprocess.TimeoutExpired(argv, 180)

    monkeypatch.setattr(subprocess, "run", fake_run)

    async def script(app, pilot):
        screen._ssh_deploy_worker(str(tmp_path / "x.sh"), "u@h", None)
        for _ in range(20):
            await pilot.pause()

    out = _run(screen, script)
    assert "stopped responding while running the installer" in out["texts"]


def test_d_redeploys_a_waiting_code_and_remembers_the_address(tmp_path, key, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="web", core_host="100.64.0.10")["code"]
    screen = SubAgentScreen(tmp_path)
    deployed = []
    monkeypatch.setattr(SubAgentScreen, "_ssh_deploy_worker",
                        lambda self, path, addr, c=None, **kw: deployed.append((path, addr, c)))
    monkeypatch.setattr(SubAgentScreen, "_probe_existing_agent", lambda self, addr: None)
    answers = iter([True, "-oProxyCommand=x", "ubuntu@203.0.113.9"])

    async def fake(_modal):
        return next(answers)

    async def script(app, pilot):
        screen.query_one("#sa-table").move_cursor(row=0)
        await pilot.press("d")
        for _ in range(15):
            await pilot.pause()

    out = _run(screen, script, fake_wait=fake)
    assert deployed and deployed[0][1] == "ubuntu@203.0.113.9" and deployed[0][2] == code
    assert code in open(deployed[0][0]).read()
    assert "can't start with '-'" in out["texts"]
    assert screen._watched_codes[code]["ssh_addr"] == "ubuntu@203.0.113.9"


def test_d_on_an_expired_code_points_at_n(tmp_path, key, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="web", core_host="h")["code"]
    sa._write("UPDATE subagent_pairing_codes SET expires_at = ? WHERE code = ?", (_expiry_iso(-60), code))
    screen = SubAgentScreen(tmp_path)
    monkeypatch.setattr(SubAgentScreen, "_ssh_deploy_worker", lambda *a, **k: pytest.fail("must not deploy"))

    async def script(app, pilot):
        screen.query_one("#sa-table").move_cursor(row=0)
        await pilot.press("d")

    out = _run(screen, script)
    assert "press n on its row" in out["texts"]


def test_default_deploy_address_uses_the_configured_login_user(tmp_path, key, monkeypatch):
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_USER", "opsuser")
    screen = SubAgentScreen(tmp_path, default_name="devbox")
    seen = []

    async def fake(modal):
        seen.append(modal)
        return True if len(seen) == 1 else ""

    async def script(app, pilot):
        await screen._offer_ssh_deploy(tmp_path / "x.sh", "devbox", None)

    _run(screen, script, fake_wait=fake)
    assert seen[1]._initial == "opsuser@devbox"


def test_expired_while_on_the_prompt_is_caught_before_deploying(tmp_path, key, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="web", core_host="h")["code"]
    screen = SubAgentScreen(tmp_path)
    monkeypatch.setattr(SubAgentScreen, "_ssh_deploy_worker", lambda *a, **k: pytest.fail("must not deploy"))
    answers = iter([True, "u@h"])

    async def fake(_modal):
        addr = next(answers)
        if addr == "u@h":  # the code runs out while the address prompt is open
            sa._write("UPDATE subagent_pairing_codes SET expires_at = ? WHERE code = ?", (_expiry_iso(-1), code))
        return addr

    async def script(app, pilot):
        await screen._offer_ssh_deploy(tmp_path / "x.sh", "web", code)

    out = _run(screen, script, fake_wait=fake)
    assert "expired while you were setting this up" in out["texts"]


@pytest.mark.parametrize("choice", ["upgrade", "pair", "cancel"])
def test_box_that_already_runs_an_agent(tmp_path, key, monkeypatch, choice):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="web", core_host="100.64.0.10")["code"]
    screen = SubAgentScreen(tmp_path)
    deployed = []
    monkeypatch.setattr(SubAgentScreen, "_ssh_deploy_worker",
                        lambda self, path, addr, c=None, **kw: deployed.append((path, c, kw)))
    monkeypatch.setattr(SubAgentScreen, "_probe_existing_agent", lambda self, a: "/opt/kratos-subagent/state.json")
    answers = iter([True, "u@h", choice])

    async def fake(_modal):
        return next(answers)

    async def script(app, pilot):
        await screen._offer_ssh_deploy(tmp_path / "kratos-subagent-install-web.sh", "web", code)

    out = _run(screen, script, fake_wait=fake)
    if choice == "cancel":
        assert deployed == [] and "nothing was changed" in out["texts"]
        assert sa.get_pairing_code(code)["used_at"] is None  # the code is still usable
    elif choice == "pair":
        assert deployed[0][1] == code and deployed[0][2] == {"upgrade": False}
    else:
        path, c, kw = deployed[0]
        assert c is None and kw == {"upgrade": True} and sa.get_pairing_code(code) is None
        body = open(path).read()
        assert "UPGRADE=1" in body and "PAIR_CODE=''" in body and "100.64.0.10" in body


def test_a_repair_code_never_asks(tmp_path, key, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="web", core_host="h", replaces_target_id="tgt_x")["code"]
    screen = SubAgentScreen(tmp_path)
    deployed = []
    monkeypatch.setattr(SubAgentScreen, "_ssh_deploy_worker", lambda self, p, a, c=None, **k: deployed.append(c))
    monkeypatch.setattr(SubAgentScreen, "_probe_existing_agent", lambda self, a: pytest.fail("no probe needed"))
    answers = iter([True, "u@h"])

    async def fake(_modal):
        return next(answers)

    async def script(app, pilot):
        await screen._offer_ssh_deploy(tmp_path / "x.sh", "web", code)

    _run(screen, script, fake_wait=fake)
    assert deployed == [code]

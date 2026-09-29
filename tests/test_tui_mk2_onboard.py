"""
Headless pilots for the new-session target onboarding screen
(tui_mk2/screens/onboard.py). Nothing here runs anything on a target: the SSH
checklist generator and the read-only probe are both mocked, and the method
choice is driven with a canned push_screen_wait.
"""
from __future__ import annotations

import asyncio
import io

from rich.console import Console
from textual.app import App

from kratos.tui_mk2.screens import onboard as ob_mod
from kratos.tui_mk2.screens.onboard import OnboardTargetScreen, needs_onboarding


class _Host(App):
    def on_mount(self):
        pass  # push screens manually so push_screen_wait can be patched first

    def model_label(self):  # LaunchScreen.create_session needs this
        return "test-model"


import pytest


@pytest.fixture(autouse=True)
def _kratos_key(tmp_path, monkeypatch):
    """A real-looking local key, so no test touches ~/.ssh."""
    key = tmp_path / "keys" / "id_ed25519"
    key.parent.mkdir()
    key.write_text("PRIVATE")
    (key.parent / "id_ed25519.pub").write_text("ssh-ed25519 AAAAONBOARD kratos@core\n")
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_KEY_PATH", key)
    monkeypatch.setattr("kratos.kratos_config.SSH_TARGET_USER", "ubuntu")
    return key


def _log_texts(screen: OnboardTargetScreen) -> list[str]:
    out = []
    for st in screen.query("#ob-log Static"):
        content = getattr(st, "_Static__content", None)
        if content is None:
            continue
        buf = io.StringIO()
        Console(file=buf, width=160).print(content)
        out.append(buf.getvalue())
    return out


def test_needs_onboarding():
    assert needs_onboarding("203.0.113.5") is True
    assert needs_onboarding("vps.example.com") is True
    assert needs_onboarding("127.0.0.1") is False
    assert needs_onboarding("localhost") is False
    assert needs_onboarding("::1") is False
    assert needs_onboarding("") is False


def test_skip_dismisses_without_probe(tmp_path, monkeypatch):
    results: list = []

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()

            async def canned(_modal):
                return "skip"

            monkeypatch.setattr(app, "push_screen_wait", canned)
            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen, callback=results.append)
            await app.workers.wait_for_complete()
            await pilot.pause()

    asyncio.run(run())
    assert results == [None]  # dismissed with no method chosen


def test_ssh_path_shows_checklist_and_passing_probe(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "kratos.adapters.target_setup.generate_target_setup_checklist",
        lambda host: f"# setup for {host}\nsudo usermod -aG systemd-journal ubuntu",
    )
    monkeypatch.setattr(
        "kratos.adapters.ssh_remote.run_target_probe_checks",
        lambda: [
            {"check": "ssh_reachable", "status": "PASS", "detail": "ok"},
            {"check": "journal_access", "status": "PASS", "detail": "ok"},
        ],
    )
    captured: dict = {}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()

            async def canned(_modal):
                return "ssh"

            monkeypatch.setattr(app, "push_screen_wait", canned)
            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen)
            await app.workers.wait_for_complete()
            await pilot.pause()
            captured["texts"] = _log_texts(screen)

    asyncio.run(run())
    texts = captured["texts"]
    assert not any("setup for 203.0.113.5" in t for t in texts)  # nothing left to set up -> no checklist
    assert any("ssh_reachable" in t for t in texts)  # probe table shown
    assert any("you're ready" in t for t in texts)  # all-pass summary


def test_ssh_path_reports_unreachable(tmp_path, monkeypatch):
    from kratos.adapters.ssh_remote import SSHResult

    monkeypatch.setattr(
        "kratos.adapters.target_setup.generate_target_setup_checklist",
        lambda host: "# checklist",
    )
    monkeypatch.setattr(
        "kratos.adapters.ssh_remote.run_target_probe_checks",
        lambda: SSHResult(ok=False, returncode=255, stdout="", stderr="Permission denied (publickey)."),
    )
    captured: dict = {}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()

            async def canned(_modal):
                return "ssh"

            monkeypatch.setattr(app, "push_screen_wait", canned)
            screen = OnboardTargetScreen(tmp_path, "15.204.216.9")
            app.push_screen(screen)
            await app.workers.wait_for_complete()
            await pilot.pause()
            captured["texts"] = _log_texts(screen)

    asyncio.run(run())
    assert any("can't SSH into 15.204.216.9 yet" in t for t in captured["texts"])
    assert any("Permission denied" in t for t in captured["texts"])


def test_subagent_path_opens_subagent_screen(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens.subagent import SubAgentScreen

    captured: dict = {}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()

            async def canned(_modal):
                return "subagent"

            monkeypatch.setattr(app, "push_screen_wait", canned)
            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen)
            await app.workers.wait_for_complete()
            await pilot.pause()
            captured["method"] = screen._method
            captured["has_subagent"] = any(isinstance(s, SubAgentScreen) for s in app.screen_stack)

    asyncio.run(run())
    assert captured["method"] == "subagent"
    assert captured["has_subagent"] is True


def test_new_session_flow_onboards_remote_but_not_host(tmp_path, monkeypatch):
    """The new-session flow routes a remote target through onboarding, and
    skips it for the Kratos host — verified via the sequence of screens it
    awaits (without opening a real session)."""
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.launch import LaunchScreen

    store = SessionStore(tmp_path / "kratos.db")

    def scenario(answer_list):
        seen: list[str] = []
        opened: list = []

        async def run():
            app = _Host()
            screen = LaunchScreen(store, tmp_path)
            async with app.run_test() as pilot:
                app.push_screen(screen)
                await pilot.pause()
                answers = iter(answer_list)

                async def canned(modal):
                    seen.append(type(modal).__name__)
                    return next(answers)

                monkeypatch.setattr(app, "push_screen_wait", canned)
                monkeypatch.setattr(screen, "_open_session", lambda *a, **k: opened.append(a))
                screen.action_new_session()
                await app.workers.wait_for_complete()
                await pilot.pause()

        asyncio.run(run())
        return seen, opened

    # Remote: target prompt -> OnboardTargetScreen (dismiss None) -> name prompt.
    seen_remote, opened_remote = scenario(["203.0.113.5", None, ""])
    assert "OnboardTargetScreen" in seen_remote
    assert opened_remote  # the session still opens after onboarding

    # Host: target prompt -> (no onboarding) -> name prompt.
    seen_host, opened_host = scenario(["127.0.0.1", ""])
    assert "OnboardTargetScreen" not in seen_host  # loopback needs no setup
    assert opened_host


# --- WS4: the first-contact SSH bootstrap ----------------------------------
def _onboard(tmp_path, monkeypatch, answers, probe, *, host="203.0.113.5"):
    """Run the SSH path with canned modal answers; return log texts, the modals
    that were awaited, and the screen on top at the end."""
    monkeypatch.setattr("kratos.adapters.ssh_remote.run_target_probe_checks", probe)
    monkeypatch.setattr("kratos.adapters.target_setup.generate_target_setup_checklist",
                        lambda h: f"# setup for {h}")
    out: dict = {"awaited": []}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()
            it = iter(answers)

            async def canned(modal):
                out["awaited"].append(modal)
                return next(it)

            monkeypatch.setattr(app, "push_screen_wait", canned)
            screen = OnboardTargetScreen(tmp_path, host)
            app.push_screen(screen)
            for _ in range(4):
                await app.workers.wait_for_complete()
                await pilot.pause()
            out["texts"] = "\n".join(_log_texts(screen))
            out["top"] = app.screen

    asyncio.run(run())
    return out


def _denied(stderr="ubuntu@203.0.113.5: Permission denied (publickey)."):
    from kratos.adapters.ssh_remote import SSHResult

    return lambda: SSHResult(ok=False, returncode=255, stdout="", stderr=stderr)


def test_key_not_accepted_and_i_can_log_in(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import CommandModal, ListPickerModal

    out = _onboard(tmp_path, monkeypatch, ["ssh", "login"], _denied())
    assert isinstance(out["awaited"][1], ListPickerModal)
    assert isinstance(out["top"], CommandModal)
    assert "ssh-ed25519 AAAAONBOARD kratos@core" in out["top"]._command
    assert "logged in as ubuntu" in out["top"]._title
    assert "doesn't accept this machine's SSH key" in out["texts"]


def test_key_not_accepted_and_someone_else_runs_it(tmp_path, monkeypatch):
    import shlex

    from kratos.utils import ssh_keys

    out = _onboard(tmp_path, monkeypatch, ["ssh", "admin"], _denied())
    cmd = out["top"]._command
    argv = shlex.split(cmd)
    assert argv[:5] == ["sudo", "-u", "ubuntu", "-H", "sh"] and argv[-1] == ssh_keys.authorize_key_command()


def test_password_only_explains_pubkey_authentication(tmp_path, monkeypatch):
    out = _onboard(tmp_path, monkeypatch, ["ssh", "login"],
                   _denied("ubuntu@203.0.113.5: Permission denied (password,keyboard-interactive)."))
    assert "PubkeyAuthentication" in out["top"]._note


def test_no_way_in_yet_is_said_plainly(tmp_path, monkeypatch):
    out = _onboard(tmp_path, monkeypatch, ["ssh", "none"], _denied())
    assert "Nothing to do until you have a way in" in out["texts"]
    assert "sub-agent needs the same one-time access" in out["texts"]


def test_no_local_key_is_created_only_on_yes(tmp_path, monkeypatch, _kratos_key):
    for f in _kratos_key.parent.iterdir():
        f.unlink()
    ok = [{"check": "ssh_reachable", "status": "PASS", "detail": "ok"}]
    declined = _onboard(tmp_path, monkeypatch, ["ssh", False], lambda: ok)
    assert not _kratos_key.exists() and "you're ready" not in declined["texts"]
    made = _onboard(tmp_path, monkeypatch, ["ssh", True], lambda: ok)
    assert _kratos_key.exists() and "Created" in made["texts"] and "you're ready" in made["texts"]


def test_missing_public_half_is_rebuilt_from_the_key(tmp_path, monkeypatch, _kratos_key):
    import subprocess

    _kratos_key.unlink()
    (_kratos_key.parent / "id_ed25519.pub").unlink()
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(_kratos_key)], check=True)
    (_kratos_key.parent / "id_ed25519.pub").unlink()
    ok = [{"check": "ssh_reachable", "status": "PASS", "detail": "ok"}]
    out = _onboard(tmp_path, monkeypatch, ["ssh", True], lambda: ok)
    assert "Rebuilt" in out["texts"] and (_kratos_key.parent / "id_ed25519.pub").read_text().startswith("ssh-ed25519")


def test_network_failure_gets_its_own_next_step(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import CommandModal

    out = _onboard(tmp_path, monkeypatch, ["ssh"],
                   _denied("ssh: connect to host 203.0.113.5 port 22: Connection timed out"))
    assert "didn't answer" in out["texts"] and isinstance(out["top"], CommandModal)
    assert out["top"]._command == "tailscale status"


def test_info_rows_are_not_failures_and_failing_checks_show_the_checklist(tmp_path, monkeypatch):
    info = [{"check": "ssh_reachable", "status": "PASS", "detail": ""},
            {"check": "target_timezone", "status": "INFO", "detail": "UTC"}]
    assert "you're ready" in _onboard(tmp_path, monkeypatch, ["ssh"], lambda: info)["texts"]
    failing = info + [{"check": "lsof_installed", "status": "FAIL", "detail": "missing"}]
    out = _onboard(tmp_path, monkeypatch, ["ssh"], lambda: failing)
    assert "setup for 203.0.113.5" in out["texts"] and "1 check(s) aren't passing" in out["texts"]

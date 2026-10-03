"""
Headless pilots for the new-session target onboarding screen
(tui_mk2/screens/onboard.py). Nothing here runs anything on a target: the SSH
checklist generator and the read-only probe are both mocked, and the method
choice is made with real keys on the screen's own list.
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


_ORDER = ("ssh", "subagent", "skip")


async def _pick(pilot, method: str) -> None:
    for _ in range(_ORDER.index(method)):
        await pilot.press("down")
    await pilot.press("enter")
    await pilot.pause()


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

            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen, callback=results.append)
            await pilot.pause()
            await _pick(pilot, "skip")  # real keys on the in-screen list
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

            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen)
            await pilot.pause()
            await _pick(pilot, "ssh")  # real keys on the in-screen list
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

            screen = OnboardTargetScreen(tmp_path, "203.0.113.9")
            app.push_screen(screen)
            await pilot.pause()
            await _pick(pilot, "ssh")  # real keys on the in-screen list
            for _ in range(10):  # the next step opens a modal that waits for a person
                await pilot.pause()
            captured["texts"] = _log_texts(screen)

    asyncio.run(run())
    assert any("can't SSH into 203.0.113.9 yet" in t for t in captured["texts"])
    assert any("Permission denied" in t for t in captured["texts"])


def test_subagent_path_opens_subagent_screen(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens.subagent import SubAgentScreen

    captured: dict = {}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()

            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen)
            await pilot.pause()
            await _pick(pilot, "subagent")  # real keys on the in-screen list
            for _ in range(10):  # the next step opens a modal that waits for a person
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
            await pilot.pause()
            await _pick(pilot, next(it))  # the connection method: real keys on the list
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
    assert isinstance(out["awaited"][0], ListPickerModal)
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


# --- the choice list + live detail panel -------------------------------------
def _choose_screen(tmp_path, size, script):
    out: dict = {}

    async def run():
        app = _Host()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen)
            await pilot.pause()
            await script(app, pilot, screen, out)

    asyncio.run(run())
    return out


def _panel_text(screen) -> str:
    buf = io.StringIO()
    Console(file=buf, width=200).print(screen.query_one("#ob-detail-body")._Static__content)
    return buf.getvalue()


def test_moving_the_selection_changes_only_the_detail_panel(tmp_path):
    async def script(app, pilot, screen, out):
        out["first"] = (screen.query_one("#ob-detail").border_title, _panel_text(screen))
        await pilot.press("down")
        await pilot.pause()
        out["second"] = (screen.query_one("#ob-detail").border_title, _panel_text(screen))
        out["options"] = screen.query_one("#ob-options").option_count

    out = _choose_screen(tmp_path, (80, 24), script)
    assert out["first"][0] == "Direct SSH  (recommended)" and "Nothing is installed on the box" in out["first"][1]
    assert out["second"][0] == "Sub-agent" and "except network scans" in out["second"][1]
    assert "Investigations work through it" in out["second"][1]
    assert out["options"] == 3


def test_every_detail_fits_at_80x24_and_sits_beside_the_list_when_wide(tmp_path):
    async def script(app, pilot, screen, out):
        out["wide"] = screen.query_one("#ob-choose").has_class("-wide")
        fits = []
        for _ in range(3):
            panel = screen.query_one("#ob-detail")
            await pilot.pause()
            fits.append((panel.border_title, panel.virtual_size.height, panel.scrollable_content_region.height))
            await pilot.press("down")
            await pilot.pause()
        out["fits"] = fits

    narrow = _choose_screen(tmp_path, (80, 24), script)
    assert narrow["wide"] is False
    for title, content_h, room in narrow["fits"]:
        assert content_h <= room, (title, content_h, room)
    assert _choose_screen(tmp_path, (120, 40), script)["wide"] is True


def test_d_opens_the_full_detail_for_the_highlighted_option(tmp_path):
    from kratos.tui_mk2.modals import InfoModal

    async def script(app, pilot, screen, out):
        await pilot.press("down")
        await pilot.press("d")
        await pilot.pause()
        out["top"] = app.screen

    out = _choose_screen(tmp_path, (80, 24), script)
    assert isinstance(out["top"], InfoModal) and out["top"]._title == "Sub-agent"


def test_c_while_choosing_picks_the_highlighted_option_not_skip(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.adapters.ssh_remote.run_target_probe_checks",
                        lambda: [{"check": "ssh_reachable", "status": "PASS", "detail": "ok"}])

    async def script(app, pilot, screen, out):
        await pilot.press("c")
        for _ in range(5):
            await pilot.pause()
        out["method"] = screen._method
        out["list_shown"] = screen.query_one("#ob-choose").display

    out = _choose_screen(tmp_path, (80, 24), script)
    assert out["method"] == "ssh" and out["list_shown"] is False


# ---- remembering machines that are already set up (2026-10-03) ----------------------


def test_setup_state_remembers_each_machines_last_check(tmp_path):
    from kratos.tui_mk2 import target_memory as TM

    host = "203.0.113.5"
    assert TM.setup_state(tmp_path, host)[0] == "new"
    TM.record_check(tmp_path, f"ubuntu@{host}", "ssh", [{"check": "a", "status": "PASS"},
                                                       {"check": "tz", "status": "INFO"}])
    assert TM.setup_state(tmp_path, host.upper())[0] == "ready"          # same machine, any spelling
    TM.record_check(tmp_path, host, "ssh", [{"check": "a", "status": "PASS"}, {"check": "b", "status": "FAIL"}])
    state, info = TM.setup_state(tmp_path, host)
    assert state == "issues" and "1 problem" in TM.setup_note(host, state, info)
    TM.record_check(tmp_path, host, "ssh", None)                          # couldn't connect at all
    assert TM.setup_state(tmp_path, host)[0] == "new"                     # -> walk through setup again
    assert TM.setup_state(tmp_path, "localhost")[0] == "local"


def test_a_machine_with_a_sub_agent_link_counts_as_set_up(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from kratos.tui_mk2 import target_memory as TM

    monkeypatch.setattr("kratos.subagent.routing.link_for",
                        lambda host, data_dir: SimpleNamespace(label="edge-03") if host == "203.0.113.7" else None)
    state, info = TM.setup_state(tmp_path, "203.0.113.7")
    assert state == "linked" and "edge-03" in TM.setup_note("203.0.113.7", state, info)


def test_a_finished_setup_check_is_remembered_and_the_next_session_skips_the_screen(tmp_path, monkeypatch):
    """Live finding: a box set up minutes earlier (every check passing) got the
    whole "How should Kratos reach this box?" screen again for the next session."""
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.launch import LaunchScreen

    monkeypatch.setattr("kratos.adapters.ssh_remote.run_target_probe_checks",
                        lambda: [{"check": "ssh_reachable", "status": "PASS", "detail": "ok"}])

    async def setup():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen)
            await pilot.pause()
            await _pick(pilot, "ssh")
            await app.workers.wait_for_complete()
            await pilot.pause()

    asyncio.run(setup())

    store = SessionStore(tmp_path / "kratos.db")
    seen, notes = [], []

    async def new_session():
        app = _Host()
        screen = LaunchScreen(store, tmp_path)
        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()
            answers = iter(["203.0.113.5", ""])

            async def canned(modal):
                seen.append(type(modal).__name__)
                return next(answers)

            monkeypatch.setattr(app, "push_screen_wait", canned)
            monkeypatch.setattr(app, "notify", lambda msg, **k: notes.append(msg))
            monkeypatch.setattr(screen, "_open_session",
                                lambda *a, **k: pending.__setitem__("note", getattr(app, "pending_session_note", "")))
            screen.action_new_session()
            await app.workers.wait_for_complete()
            await pilot.pause()

    pending: dict = {}
    asyncio.run(new_session())
    assert "OnboardTargetScreen" not in seen
    assert "already set up" in pending["note"] and "/target verify" in pending["note"]


def test_full_details_key_is_offered_only_when_the_panel_is_cut_off(tmp_path):
    """On a big screen the side panel already shows everything; `d` then just
    repeated it. On a small one the panel is cut off and `d` is the way to read it."""
    from textual.widgets import Static

    def hints(size):
        async def run():
            app = _Host()
            async with app.run_test(size=size) as pilot:
                await pilot.pause()
                screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
                app.push_screen(screen)
                for _ in range(4):
                    await pilot.pause()
                return str(screen.query_one("#ob-hints", Static).render())
        return asyncio.run(run())

    assert "d full details" not in hints((160, 50))
    assert "d full details" in hints((80, 16))

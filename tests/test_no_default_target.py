"""Kratos ships no default target. A published install with no configuration must never
probe a built-in host: the target comes from KRATOS_SSH_HOST, the target saved at first run,
/target, or a session. With none set, every path says so plainly and touches no network."""
from __future__ import annotations

import asyncio
import importlib
import re
import subprocess
from pathlib import Path

import pytest

from kratos import kratos_config as kc


@pytest.fixture(autouse=True)
def _no_target(monkeypatch):
    monkeypatch.setattr(kc, "SSH_TARGET_HOST", "")
    monkeypatch.setattr(kc, "_active_target_override", None)


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError(f"no process/network call expected, got {a[0] if a else k}")

    monkeypatch.setattr(subprocess, "run", refuse)


def test_the_shipped_default_is_empty(monkeypatch):
    monkeypatch.delenv("KRATOS_SSH_HOST", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)  # ignore a developer's .env
    try:
        assert importlib.reload(kc).get_active_target() == ""
    finally:
        importlib.reload(kc)
    src = Path(kc.__file__).read_text()
    m = re.search(r'os\.environ\.get\("KRATOS_SSH_HOST",\s*"([^"]*)"\)', src)
    assert m and m.group(1) == ""


def test_require_active_target_says_what_to_do():
    with pytest.raises(kc.NoTargetConfigured, match="/target"):
        kc.require_active_target()
    kc.set_active_target("10.0.0.5")
    assert kc.require_active_target() == "10.0.0.5"


def test_ssh_calls_say_no_target_without_running_ssh(no_network):
    from kratos.adapters import ssh_remote

    for result in (ssh_remote.run_remote_command("id"), ssh_remote.run_remote_script("id"),
                   ssh_remote.pin_target_host_key(known_hosts_path=Path("/nonexistent"))):
        assert result.ok is False and result.stderr == kc.NO_TARGET_MESSAGE


def test_network_scanners_say_no_target(tmp_path, no_network):
    from kratos.agent import tools

    for tool in (tools.tool_run_nmap_scan, tools.tool_run_vuln_scan):
        assert tool(tmp_path) == {"status": "error", "observation": kc.NO_TARGET_MESSAGE}


def test_dispatch_rejects_a_guessed_target_when_none_is_set(tmp_path, no_network):
    from kratos.agent.loop import execute_tool_call

    out = execute_tool_call("run_nmap_scan", {"target": "192.168.1.50"}, tmp_path)
    assert out["status"] == "error" and out["observation"] == kc.NO_TARGET_MESSAGE


def test_doctor_does_not_probe_without_a_target(no_network):
    from kratos.agent import doctor

    rows: list = []
    doctor._check_target(rows)
    assert [r["check"] for r in rows] == ["active target"]
    assert rows[0]["status"] == "warn" and "/target" in rows[0]["fix"]


def test_saved_target_is_seeded_but_env_and_explicit_choices_win(tmp_path, monkeypatch):
    kc.save_local_config(tmp_path, default_target="10.0.0.7")
    assert kc.seed_active_target_from_config(tmp_path) == "10.0.0.7"

    kc.set_active_target(None)
    monkeypatch.setattr(kc, "SSH_TARGET_HOST", "10.0.0.8")  # KRATOS_SSH_HOST
    assert kc.seed_active_target_from_config(tmp_path) == "10.0.0.8"

    kc.set_active_target("10.0.0.9")  # an explicit override (e.g. --target)
    assert kc.seed_active_target_from_config(tmp_path) == "10.0.0.9"

    kc.set_active_target(None)
    monkeypatch.setattr(kc, "SSH_TARGET_HOST", "")
    assert kc.seed_active_target_from_config(tmp_path / "fresh") == ""


def test_cli_run_uses_the_saved_target_and_stops_cleanly_without_one(tmp_path, monkeypatch, capsys):
    from kratos.agent import pipeline
    from kratos.cli import app as cli

    seen: list = []
    monkeypatch.setattr(pipeline, "run_pipeline",
                        lambda steps, data_dir: seen.append(kc.get_active_target()) or pipeline.PipelineOutcome(
                            status="completed", steps=[], findings=[]))
    assert cli.main(["--data-dir", str(tmp_path), "run"]) == 1
    assert "No target is set yet" in capsys.readouterr().out and seen == []

    kc.save_local_config(tmp_path, default_target="10.0.0.7")
    kc.set_active_target(None)
    cli.main(["--data-dir", str(tmp_path), "run"])
    assert seen == ["10.0.0.7"]


def test_a_scheduled_run_without_a_target_records_and_alerts(tmp_path):
    from kratos.agent import scheduled_run as W
    from kratos.agent import schedules as S

    sch = S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly", deliver=["ntfy"])
    sent: list = []
    rec = W.run_scheduled(sch, tmp_path, notifier=lambda msg, sev: sent.append((msg, sev)) or {"status": "sent"})
    assert rec["status"] == "error" and rec["error"] == kc.NO_TARGET_MESSAGE
    assert sent and sent[0][1] == "warning" and "did not run" in sent[0][0]


def test_new_session_prompt_will_not_accept_enter_without_a_default(tmp_path, monkeypatch):
    from textual.app import App

    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.launch import LaunchScreen

    store = SessionStore(tmp_path / "kratos.db")
    prompts: list = []
    opened: list = []

    class _Host(App):
        def model_label(self):
            return "m"

    async def run():
        app = _Host()
        screen = LaunchScreen(store, tmp_path)
        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()
            answers = iter(["", None])  # Enter with no default -> asked again; then cancel

            async def canned(modal):
                prompts.append(getattr(modal, "_hint", "") or getattr(modal, "_title", ""))
                return next(answers)

            monkeypatch.setattr(app, "push_screen_wait", canned)
            monkeypatch.setattr(screen, "_open_session", lambda *a, **k: opened.append(a))
            screen.action_new_session()
            await app.workers.wait_for_complete()
            await pilot.pause()

    asyncio.run(run())
    assert len(prompts) == 2 and opened == []
    assert "default:" not in prompts[0]


def test_the_first_real_target_becomes_the_saved_default_once(tmp_path):
    assert kc.remember_first_target(tmp_path, "127.0.0.1") is False    # Kratos's own host: not saved
    assert kc.remember_first_target(tmp_path, "10.0.0.7") is True
    assert kc.remember_first_target(tmp_path, "10.0.0.9") is False     # never overwrites
    assert kc.load_local_config(tmp_path)["default_target"] == "10.0.0.7"


def test_target_command_saves_the_first_default(tmp_path, monkeypatch):
    from textual.app import App

    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    monkeypatch.setattr(SessionScreen, "_setup_target_worker", lambda self, host: None)  # no SSH
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session([], "m")
    screen = SessionScreen(store, tmp_path, sid, [], "")

    class _Host(App):
        def on_mount(self):
            self.push_screen(screen)

    async def run():
        async with _Host().run_test() as pilot:
            await pilot.pause()
            screen._apply_target(["10.0.0.7"])
            await pilot.pause()

    asyncio.run(run())
    assert kc.load_local_config(tmp_path)["default_target"] == "10.0.0.7"
    assert kc.get_active_target() == "10.0.0.7"

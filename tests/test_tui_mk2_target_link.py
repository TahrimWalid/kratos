"""Headless pilots: tying a session target to a paired sub-agent is explicit
and explained everywhere (docs/subagent_read_routing.md D3). Nothing here
touches a real target -- probes and SSH are mocked; modals answered with canned
values where the modal itself is generic."""
from __future__ import annotations

import asyncio

import pytest
from textual.app import App

from kratos import kratos_config as kc
from kratos.storage.subagent_store import SubAgentStore
from kratos.subagent import routing
from kratos.tui_mk2 import target_link as TL


class _Host(App):
    def on_mount(self):
        pass

    def model_label(self):
        return "test-model"

    def ensure_core_listener(self):
        self.listener_asked = True
        return "external"


@pytest.fixture
def paired(tmp_path, monkeypatch):
    kc.set_active_data_dir(tmp_path)
    routing.clear_cache()
    store = SubAgentStore(tmp_path / "kratos.db")
    code = store.create_pairing_code(name="web-01", core_host="100.64.0.10")["code"]
    tid = store.redeem_pairing_code(code, agent_id="a", hostname="web-01.lan", agent_version="0.3.0")["target_id"]
    store.record_connection_open(tid, listener_id="lsn", peer="198.51.100.7", collect_interval=30, ping_interval=10)
    yield store, tid
    kc.set_active_data_dir(None)
    routing.clear_cache()


def test_matching_is_by_name_hostname_or_agent_address_and_never_loopback(tmp_path, paired):
    _store, tid = paired
    for host in ("web-01", "WEB-01.lan", "198.51.100.7"):
        assert [t["target_id"] for t in TL.matching_agents(tmp_path, host)] == [tid], host
    assert TL.matching_agents(tmp_path, "203.0.113.99") == []
    assert TL.matching_agents(tmp_path, "127.0.0.1") == []


def test_describe_says_how_and_how_to_change(tmp_path, paired):
    store, tid = paired
    assert "over SSH" in TL.describe(tmp_path, "web-01").plain and "/target link" in TL.describe(tmp_path, "web-01").plain
    store.set_link("web-01", tid, routing.MODE_SUBAGENT)
    line = TL.describe(tmp_path, "web-01").plain
    assert "only through its sub-agent (web-01)" in line and "/target link to change" in line
    store.set_link("web-01", tid, routing.MODE_SSH_FIRST)
    assert "over SSH, falling back to its sub-agent" in TL.describe(tmp_path, "web-01").plain
    assert "own host" in TL.describe(tmp_path, "127.0.0.1").plain


def _run_with_answers(screen_factory, answers, monkeypatch, *, action):
    """Push a screen, answer its modals in order, run `action(screen)`."""
    seen: list = []

    async def run():
        app = _Host()
        async with app.run_test(size=(140, 40)) as pilot:
            screen = screen_factory()
            app.push_screen(screen)
            await pilot.pause()
            queue = iter(answers)

            async def canned(modal):
                seen.append(getattr(modal, "_title", type(modal).__name__))
                return next(queue)

            monkeypatch.setattr(app, "push_screen_wait", canned)
            await action(screen, pilot)
            for _ in range(30):
                await pilot.pause()
    asyncio.run(run())
    return seen


def test_target_command_offers_the_link_and_never_applies_it_silently(tmp_path, paired, monkeypatch):
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    store, tid = paired
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    ssh_setup: list = []
    probes: list = []
    monkeypatch.setattr(SessionScreen, "_setup_target_worker", lambda self, h: ssh_setup.append(h))
    monkeypatch.setattr(SessionScreen, "_probe_target_worker", lambda self: probes.append(True))
    sessions = SessionStore(tmp_path / "kratos.db")

    def make():
        return SessionScreen(sessions, tmp_path, sessions.create_session([], "m"), [], "")

    async def act(screen, pilot):
        screen._apply_target(["web-01"])

    # Declined: stays on SSH, the SSH setup runs, no link.
    seen = _run_with_answers(make, ["no"], monkeypatch, action=act)
    assert "looks like a box you've paired" in seen[0]
    assert store.get_link("web-01") is None and ssh_setup == ["web-01"] and probes == []

    # Accepted: asked which box AND how; linked; probed through the agent, not SSH setup.
    ssh_setup.clear()
    seen = _run_with_answers(make, [tid, routing.MODE_SUBAGENT], monkeypatch, action=act)
    assert len(seen) == 2 and "How should Kratos read web-01" in seen[1]
    assert store.get_link("web-01")["mode"] == "subagent" and ssh_setup == [] and probes == [True]

    # Already linked: no question at all.
    probes.clear()
    seen = _run_with_answers(make, [], monkeypatch, action=act)
    assert seen == [] and probes == [True]


def test_target_link_and_unlink(tmp_path, paired, monkeypatch):
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    store, tid = paired
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    monkeypatch.setattr(SessionScreen, "_probe_target_worker", lambda self: None)
    sessions = SessionStore(tmp_path / "kratos.db")
    monkeypatch.setattr(kc, "_active_target_override", "203.0.113.20")

    def make():
        return SessionScreen(sessions, tmp_path, sessions.create_session(["203.0.113.20"], "m"), ["203.0.113.20"], "")

    async def link(screen, pilot):
        screen._target_flow("link")

    _run_with_answers(make, [tid, routing.MODE_SSH_FIRST], monkeypatch, action=link)
    assert store.get_link("203.0.113.20")["mode"] == "ssh_first"

    async def unlink(screen, pilot):
        screen._target_flow("unlink")

    _run_with_answers(make, [], monkeypatch, action=unlink)
    assert store.get_link("203.0.113.20") is None


def test_onboarding_offers_an_already_paired_box(tmp_path, paired, monkeypatch):
    from kratos.adapters import ssh_remote
    from kratos.tui_mk2.screens.onboard import OnboardTargetScreen

    store, tid = paired
    monkeypatch.setattr(ssh_remote, "run_target_probe_checks", lambda: [
        {"check": "subagent_reachable", "status": "PASS", "detail": "Connected through the sub-agent on web-01"}])
    holder: dict = {}

    def make():
        holder["s"] = OnboardTargetScreen(tmp_path, "web-01")
        return holder["s"]

    async def act(screen, pilot):
        assert screen.query_one("#ob-options").option_count == 4
        assert screen.query_one("#ob-detail").border_title.startswith("Its paired sub-agent")
        await pilot.press("enter")

    _run_with_answers(make, [routing.MODE_SUBAGENT], monkeypatch, action=act)
    assert store.get_link("web-01")["target_id"] == tid


def test_onboarding_subagent_path_links_once_the_new_agent_checks_in(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens.subagent import SubAgentScreen

    kc.set_active_data_dir(tmp_path)
    routing.clear_cache()
    store = SubAgentStore(tmp_path / "kratos.db")
    screen = SubAgentScreen(tmp_path, link_host="203.0.113.30")
    code = store.create_pairing_code(name="203.0.113.30", core_host="100.64.0.10")["code"]

    async def run():
        app = _Host()
        async with app.run_test(size=(140, 40)) as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen._watched_codes[code] = {"name": "203.0.113.30", "host": "100.64.0.10"}
            store.redeem_pairing_code(code, agent_id="a", hostname="box", agent_version="0.3.0")
            screen._refresh()
            await pilot.pause()
    try:
        asyncio.run(run())
        link = store.get_link("203.0.113.30")
        assert link is not None and link["mode"] == routing.MODE_SUBAGENT
    finally:
        kc.set_active_data_dir(None)


def test_plain_network_hub_asks_before_allowing_reads(tmp_path, monkeypatch):
    from kratos.subagent import hub_address
    from kratos.tui_mk2.screens.subagent import SubAgentScreen

    assert hub_address.is_trusted_transport_address("100.64.0.10")
    assert hub_address.is_trusted_transport_address("127.0.0.1")
    assert not hub_address.is_trusted_transport_address("192.168.1.20")
    screen = SubAgentScreen(tmp_path)
    out: dict = {}

    async def act(s, pilot):
        out["lan"] = await s._ask_plain_network("192.168.1.20")
        out["again"] = await s._ask_plain_network("192.168.1.20")  # remembered, not re-asked
        out["tailnet"] = await s._ask_plain_network("100.64.0.10")

    seen = _run_with_answers(lambda: screen, ["on"], monkeypatch, action=act)
    assert out == {"lan": True, "again": True, "tailnet": False} and len(seen) == 1
    script = screen._write_installer("x", "192.168.1.20", "AAAA-BBBB").read_text()
    assert "--allow-untrusted-transport" in script and "--enable-execution" not in script

"""
Headless Textual pilots for the capability-2 consent + approval screen
(tui_mk2/screens/whitelist.py; controls 6/7). Drives real keypresses for the
simple yes/no modals (ExecutionConsentModal/ConfirmModal -- these are the
actual safety-relevant fail-safe behavior); for the multi-step slot-
collection + typed-EXECUTE flow, `app.push_screen_wait` is swapped for a
canned queue so the test isolates WhitelistScreen's own control flow (the
modals themselves are generic, already-tested widgets) rather than needing
to drive three chained real modals with raw key sequences.

Nothing here ever executes anything -- `_dispatch_and_poll` only ever writes
to WhitelistStore's dispatch-request queue; no CoreServer/agent runs in
these tests, so a created request is confirmed by checking the STORE, and
the screen's own "no result" timeout path (nothing ever completes it) is
exercised deliberately, with the poll constants shrunk so the test stays fast.
"""
from __future__ import annotations

import asyncio

import io

from rich.console import Console
from textual.app import App

from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.tui_mk2.screens import whitelist as wl_mod
from kratos.tui_mk2.screens.whitelist import WhitelistScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make_stores(tmp_path):
    return SubAgentStore(tmp_path / "kratos.db"), WhitelistStore(tmp_path / "kratos.db")


def _pair(sa: SubAgentStore, name: str = "web-01") -> str:
    code = sa.create_pairing_code(name=name)["code"]
    result = sa.redeem_pairing_code(code, agent_id="a1", hostname=name, agent_version="0.1.0")
    return result["target_id"]


def _log_texts(screen: WhitelistScreen) -> list[str]:
    # Static stores its original renderable under a name-mangled attribute
    # (see test_tui_mk2_session.py's own HelpModal test for this same
    # pattern) -- render each through a Console to plain text, works for
    # both Text and Table renderables.
    out = []
    for st in screen.query("#wl-log Static"):
        content = getattr(st, "_Static__content", None)
        if content is None:
            continue
        buf = io.StringIO()
        Console(file=buf, width=140).print(content)
        out.append(buf.getvalue())
    return out


def test_no_paired_targets_shows_a_clear_message(tmp_path):
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert any("No paired sub-agent targets" in t for t in _log_texts(screen))

    asyncio.run(run())


def test_single_target_autoselects_and_shows_default_enabled_actions(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert screen._target_id == tid
            table = screen.query_one("#wl-table")
            # Only the two LOW-tier fail2ban actions are enabled by default;
            # the two service.* actions are high-tier, disabled by default.
            assert table.row_count == 2
            assert wl.get_execution_opt_in(tid) is False

    asyncio.run(run())


def test_enable_execution_via_real_keypress(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()

    asyncio.run(run())
    assert wl.get_execution_opt_in(tid) is True


def test_enable_execution_declined_by_escape_is_fail_safe(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(run())
    assert wl.get_execution_opt_in(tid) is False


def test_enable_execution_declined_by_a_stray_key_is_fail_safe(tmp_path):
    """ANY key other than 'y' declines -- not just 'n'/'escape'."""
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()
            await pilot.press("z")
            await pilot.pause()

    asyncio.run(run())
    assert wl.get_execution_opt_in(tid) is False


def test_disable_execution_via_real_keypress(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("d")
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()

    asyncio.run(run())
    assert wl.get_execution_opt_in(tid) is False


def test_enabling_twice_is_a_no_op_not_a_second_prompt(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()
            assert any("already enabled" in t for t in _log_texts(screen))

    asyncio.run(run())


def test_activate_selected_creates_a_real_dispatch_request(tmp_path, monkeypatch):
    """Full slot-collection -> typed-EXECUTE -> dispatch-request flow, with
    push_screen_wait swapped for a canned queue (jail pick, ip prompt, then
    the typed-EXECUTE confirmation) so the test targets WhitelistScreen's own
    control flow. No CoreServer runs, so nothing ever completes the request --
    the poll timeout constants are shrunk so the test doesn't wait 40s."""
    monkeypatch.setattr(wl_mod, "_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(wl_mod, "_POLL_TIMEOUT_SECONDS", 0.05)

    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    screen = WhitelistScreen(tmp_path)

    answers = iter(["sshd", "8.8.8.8", True])

    async def fake_push_screen_wait(_modal):
        return next(answers)

    texts: list[str] = []

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen_wait = fake_push_screen_wait
            screen.action_activate_selected()  # row 0 defaults to fail2ban.ban_ip
            for _ in range(60):
                await pilot.pause()
                await asyncio.sleep(0.02)
            texts.extend(_log_texts(screen))  # query while the screen is still mounted

    asyncio.run(run())

    # The screen's own poll gave up (nothing services the queue in this
    # test), but the request itself was genuinely created and is still
    # sitting there as real, durable state -- proving the whole chain
    # (slot collection -> render_argv -> create_dispatch_request) ran.
    pending = wl.list_pending_dispatch_requests(tid)
    assert len(pending) == 1
    assert pending[0]["action_id"] == "fail2ban.ban_ip"
    assert pending[0]["slot_values"] == {"jail": "sshd", "ip": "8.8.8.8"}
    assert any("no result within" in t for t in texts)


def test_activate_selected_cancelled_at_typed_execute_creates_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(wl_mod, "_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(wl_mod, "_POLL_TIMEOUT_SECONDS", 0.05)

    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    screen = WhitelistScreen(tmp_path)

    answers = iter(["sshd", "8.8.8.8", False])  # declines at the typed-EXECUTE gate

    async def fake_push_screen_wait(_modal):
        return next(answers)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen_wait = fake_push_screen_wait
            screen.action_activate_selected()
            for _ in range(10):
                await pilot.pause()
                await asyncio.sleep(0.01)

    asyncio.run(run())
    assert wl.list_pending_dispatch_requests(tid) == []


def test_activate_selected_without_execution_opt_in_never_dispatches(tmp_path, monkeypatch):
    """Recommend-only path: the typed-EXECUTE modal is shown (can_execute=False,
    no EXECUTE field per design) purely informationally -- confirming its
    return value must never reach create_dispatch_request."""
    monkeypatch.setattr(wl_mod, "_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(wl_mod, "_POLL_TIMEOUT_SECONDS", 0.05)

    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    # deliberately NOT opting in
    screen = WhitelistScreen(tmp_path)

    answers = iter(["sshd", "8.8.8.8", True])

    async def fake_push_screen_wait(_modal):
        return next(answers)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen_wait = fake_push_screen_wait
            screen.action_activate_selected()
            for _ in range(10):
                await pilot.pause()
                await asyncio.sleep(0.01)

    asyncio.run(run())
    assert wl.list_pending_dispatch_requests(tid) == []


def test_high_tier_action_requires_a_second_confirmation(tmp_path, monkeypatch):
    """Opt a high-tier default in via a maintainer override, then confirm the
    second-confirmation gate fires and a decline there creates no request."""
    monkeypatch.setattr(wl_mod, "_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(wl_mod, "_POLL_TIMEOUT_SECONDS", 0.05)

    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    wl.set_maintainer_override(tid, "service.enable_now", True)
    screen = WhitelistScreen(tmp_path)

    # unit pick, typed-EXECUTE confirm=True, second confirm=False (decline)
    answers = iter(["fail2ban", True, False])

    async def fake_push_screen_wait(_modal):
        return next(answers)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            table = screen.query_one("#wl-table")
            assert table.row_count == 3  # ban_ip, unban_ip, + the newly-opted-in service.enable_now
            app.push_screen_wait = fake_push_screen_wait
            # Find the service.enable_now row and select it.
            row_index = next(i for i, r in enumerate(screen._rows) if r["spec"].id == "service.enable_now")
            table.move_cursor(row=row_index)
            screen.action_activate_selected()
            for _ in range(10):
                await pilot.pause()
                await asyncio.sleep(0.01)

    asyncio.run(run())
    assert wl.list_pending_dispatch_requests(tid) == []


def test_rollback_with_no_prior_dispatch_is_a_clean_noop(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_rollback()
            await pilot.pause()
            assert any("Nothing to roll back" in t for t in _log_texts(screen))

    asyncio.run(run())


def test_check_telemetry_with_none_received_is_a_clean_message(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_check_telemetry()
            await pilot.pause()
            assert any("No telemetry received" in t for t in _log_texts(screen))

    asyncio.run(run())


def test_check_telemetry_shows_the_real_latest_snapshot(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    sa.record_telemetry(tid, {"host": {"uptime_seconds": 4242}, "services": {"fail2ban": "active"}},
                         seq=1, collected_at="2026-01-01T00:00:00+00:00")
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_check_telemetry()
            await pilot.pause()
            texts = " ".join(_log_texts(screen))
            assert "4242" in texts
            assert "Latest observed state" in texts

    asyncio.run(run())


def test_target_picker_shown_when_multiple_targets_paired(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid_a = _pair(sa, name="web-01")
    tid_b = _pair(sa, name="web-02")
    screen = WhitelistScreen(tmp_path)

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert screen._target_id is None  # awaiting the picker
            await pilot.press("enter")  # pick the first (default-focused) entry
            await pilot.pause()
            assert screen._target_id in (tid_a, tid_b)

    asyncio.run(run())

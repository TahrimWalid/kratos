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
            # All four built-ins are listed; only the two LOW-tier fail2ban
            # actions are on by default (service.* are high-tier, off).
            assert table.row_count == 4
            assert [r["state"] for r in screen._rows] == ["on", "on", "off", "off"]
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
            assert [r["state"] for r in screen._rows].count("on") == 3  # + the newly-opted-in service.enable_now
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


# ---------------------------------------------------------------------------
# Managing the allowlist (add / edit / on-off / delete / details / ceiling)
# and the /run-fix preselect entry point.
# ---------------------------------------------------------------------------
from kratos.subagent import whitelist as W  # noqa: E402
from kratos.tui_mk2.modals import CommandModal, MultiSelectModal  # noqa: E402


def _drive(screen, answers, action, *, after=None, ticks=40, early=False):
    seen: list = []
    it = iter(answers)

    async def fake_push_screen_wait(modal):
        seen.append(type(modal).__name__)
        return next(it)

    out: dict = {}

    async def run():
        app = _Host(screen)
        if early:  # the screen starts a flow on mount (preselect)
            app.push_screen_wait = fake_push_screen_wait
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen_wait = fake_push_screen_wait
            action()
            for _ in range(ticks):
                await pilot.pause()
                await asyncio.sleep(0.01)
            out["texts"] = _log_texts(screen)
            out["screen"] = app.screen
            if after:
                after(app)

    asyncio.run(run())
    out["seen"] = seen
    return out


def test_add_a_command_with_blanks(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)
    out = _drive(screen, ["blanks", "sudo fail2ban-client set {jail} banip {ip}",
                          "Bans an attacker IP.", "Unban it.", "One IP."], screen.action_add_entry)
    [entry] = wl.list_user_entries(tid)
    assert entry.template_id == "custom" and entry.effective_spec.argv_template[0] == "fail2ban-client"
    assert entry.effective_spec.slots["ip"].ip_deny_private is True  # type came from the ceiling
    assert entry.effective_spec.reversible is True and entry.tier == "low"  # flags from the vetted shape
    assert any("Added" in t for t in out["texts"])


def test_add_with_blanks_reprompts_on_a_form_the_ceiling_does_not_allow(tmp_path):
    sa, wl = _make_stores(tmp_path)
    _pair(sa)
    screen = WhitelistScreen(tmp_path)
    out = _drive(screen, ["blanks", "systemctl reboot", None], screen.action_add_entry)
    assert any("isn't an allowed form" in t for t in out["texts"]) and wl.list_user_entries(_pair and screen._target_id) == []


def test_add_an_exact_command_waits_and_shows_the_target_snippet(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)
    out = _drive(screen, ["exact", "sudo adduser --disabled-password alice", "Adds alice.", "deluser alice", "One account."],
                 screen.action_add_entry)
    [entry] = wl.list_user_entries(tid)
    assert entry.pending and screen._rows[-1]["state"] == "waiting"
    assert isinstance(out["screen"], CommandModal) and "allowed-commands" in out["screen"]._command
    assert "adduser --disabled-password alice" in out["screen"]._command


def test_add_exact_refuses_shell_syntax_and_reprompts(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)
    out = _drive(screen, ["exact", "adduser x; reboot", None], screen.action_add_entry)
    assert wl.list_user_entries(tid) == [] and any("shell syntax" in t for t in out["texts"])


def test_add_from_template_narrows_the_values(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)
    out = _drive(screen, ["template", "service.enable_now", ["fail2ban"]], screen.action_add_entry)
    assert "MultiSelectModal" in out["seen"]
    [entry] = wl.list_user_entries(tid)
    assert entry.effective_spec.slots["unit"].values == ("fail2ban",) and entry.tier == "low"


def test_turning_on_a_high_risk_builtin_needs_a_confirmation(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)

    def select_enable_now_then(answers):
        def act():
            idx = next(i for i, r in enumerate(screen._rows) if r["label"] == "service.enable_now")
            screen.query_one("#wl-table").move_cursor(row=idx)
            screen.action_toggle_entry()
        return act

    _drive(screen, [False], select_enable_now_then([False]))
    assert next(r for r in screen._rows if r["label"] == "service.enable_now")["state"] == "off"
    screen2 = WhitelistScreen(tmp_path)
    screen = screen2
    _drive(screen2, [True], select_enable_now_then([True]))
    assert next(r for r in screen2._rows if r["label"] == "service.enable_now")["state"] == "on"


def test_delete_a_user_entry_and_details_and_ceiling_view(tmp_path):
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.create_custom_entry(tid, ["systemctl", "disable", "--now", "{u}"], {"u": W.Slot(kind="enum", values=("cups",))},
                           effect="Stops cups.", reversibility="Enable it again.", blast_radius="Printing.")
    screen = WhitelistScreen(tmp_path)

    def details_ceiling_delete():
        screen.query_one("#wl-table").move_cursor(row=len(screen._rows) - 1)
        screen.action_entry_details()
        screen.action_show_ceiling()
        screen.action_delete_entry()

    out = _drive(screen, [True], details_ceiling_delete)
    joined = "\n".join(out["texts"])
    assert "Stops cups." in joined and "one of: cups" in joined
    assert "systemctl disable --now <one of:" in joined  # the ceiling view lists allowed forms
    assert wl.list_user_entries(tid) == []


def test_running_an_off_entry_explains_instead_of_prompting(tmp_path):
    sa, wl = _make_stores(tmp_path)
    _pair(sa)
    screen = WhitelistScreen(tmp_path)

    def run_off_row():
        screen.query_one("#wl-table").move_cursor(row=3)
        screen.action_activate_selected()

    out = _drive(screen, [], run_off_row)
    assert out["seen"] == [] and any("turned off" in t for t in out["texts"])


def test_preselected_recommendation_opens_the_same_gate_prefilled(tmp_path, monkeypatch):
    monkeypatch.setattr(wl_mod, "_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(wl_mod, "_POLL_TIMEOUT_SECONDS", 0.05)
    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    wl.set_execution_opt_in(tid, True)
    screen = WhitelistScreen(tmp_path, target_id=tid,
                             preselect={"action_id": "fail2ban.ban_ip", "values": {"jail": "sshd", "ip": "8.8.8.8"}})
    out = _drive(screen, [True], lambda: None, ticks=60, early=True)
    assert out["seen"] == ["TypedExecuteModal"]  # no slot prompts -- only the approval gate
    [req] = wl.list_pending_dispatch_requests(tid)
    assert req["slot_values"] == {"jail": "sshd", "ip": "8.8.8.8"}


def test_multiselect_modal_real_keys(tmp_path):
    result: dict = {}

    class _M(App):
        def on_mount(self):
            self.push_screen(MultiSelectModal("pick", [("a", "a"), ("b", "b"), ("c", "c")]),
                             callback=lambda r: result.setdefault("r", r))

    async def run():
        app = _M()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("down", "space", "enter")  # untick "b"
            await pilot.pause()

    asyncio.run(run())
    assert result["r"] == ["a", "c"]


def test_multiselect_modal_refuses_an_empty_choice(tmp_path):
    result: dict = {}

    class _M(App):
        def on_mount(self):
            self.push_screen(MultiSelectModal("pick", [("a", "a")]), callback=lambda r: result.setdefault("r", r))

    async def run():
        app = _M()
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("space", "enter")  # untick the only one, try to finish
            await pilot.pause()
            assert "r" not in result
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(run())
    assert result["r"] is None


def test_real_keys_reach_the_screen_actions(tmp_path):
    """The table has focus; enter/space/a/i must still reach the screen (the
    checklist modal's own Enter was once swallowed by its list widget)."""
    from kratos.tui_mk2.modals import ConfirmModal, ListPickerModal

    sa, wl = _make_stores(tmp_path)
    tid = _pair(sa)
    screen = WhitelistScreen(tmp_path)
    seen: list = []

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")          # run row 0 -> first slot prompt (jail picker)
            await pilot.pause()
            seen.append(type(app.screen).__name__)
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("down", "down", "space")  # service.enable_now (high) -> confirm
            await pilot.pause()
            seen.append(type(app.screen).__name__)
            await pilot.press("n")
            await pilot.pause()
            await pilot.press("a")               # add -> how picker
            await pilot.pause()
            seen.append(type(app.screen).__name__)
            await pilot.press("escape")
            await pilot.pause()

    asyncio.run(run())
    assert seen == ["ListPickerModal", "ConfirmModal", "ListPickerModal"]
    assert next(r for r in build_rows(wl, tid) if r["label"] == "service.enable_now")["state"] == "off"


from kratos.tui_mk2.screens.whitelist import build_rows  # noqa: E402


def test_table_is_painted_at_full_width_after_the_target_picker(tmp_path):
    """Found in the P2.5 snapshots: with two paired targets the screen opens on a picker,
    and the rows filled in as it closed were painted with header-only column widths
    ('fail2b', 'built-'). The widths were computed right; only the paint was stale."""
    import re

    sa, _ = _make_stores(tmp_path)
    _pair(sa, "web-01")
    _pair(sa, "db-01")
    screen = WhitelistScreen(tmp_path)
    out: dict = {}

    from kratos.tui_mk2.app import KratosTUI

    class _Kratos(KratosTUI):  # the real app (its CSS is what exposed the stale paint)
        def _boot(self):
            self._booted = True
            self.push_screen(screen)

        def _autofill_active_context(self):
            pass

    async def run():
        app = _Kratos(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            await pilot.press("enter")  # pick the first target
            for _ in range(5):
                await pilot.pause()
            out["svg"] = app.export_screenshot()

    asyncio.run(run())
    painted = re.sub(r"&#160;", " ", out["svg"])
    assert "fail2ban.ban_ip" in painted and "built-in" in painted


def test_table_is_as_tall_as_its_rows_and_the_space_below_says_what_it_is_for(tmp_path):
    """A short allowlist used to sit above a fixed 12-row table and a large void."""
    sa, _ = _make_stores(tmp_path)
    _pair(sa, "web-01")
    screen = WhitelistScreen(tmp_path)
    out: dict = {}

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            table = screen.query_one("#wl-table")
            out["height"], out["rows"] = table.size.height, table.row_count
            screen._refresh()  # a second refresh must not repeat the hint
            await pilot.pause()
            out["texts"] = _log_texts(screen)

    asyncio.run(run())
    assert out["height"] == out["rows"] + 1  # header + one line per entry
    assert sum("Details and results appear here" in " ".join(t.split()) for t in out["texts"]) == 1

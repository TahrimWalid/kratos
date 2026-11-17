"""E.2 `/compliance` in the TUI: a machine's controls with their six statuses, Enter shows the
evidence and the fix, `o` sets an owner only after a person confirms (recorded with the
actor), a group shows the roll-up, and `/compliance` opens the screen."""
from __future__ import annotations

import asyncio
import copy
import io
import time

from rich.console import Console
from textual.app import App

from kratos.compliance import owners as O
from kratos.compliance import record
from kratos.compliance import store
from kratos.tui_mk2.modals import InfoModal
from kratos.tui_mk2.screens.compliance import ComplianceScreen

from tests.test_compliance import good_hardening


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _text(content) -> str:
    buf = io.StringIO()
    Console(file=buf, width=220).print(content)
    return buf.getvalue()


def _seed(tmp_path):
    h = good_hardening()
    bad = copy.deepcopy(h)
    bad["stat"]["/etc/crontab"]["mode"] = 0o666
    record.run(tmp_path, "10.0.0.5", fetch=lambda: dict(bad, via="ssh"), now=time.time())
    record.run(tmp_path, "10.0.0.6", fetch=lambda: dict(h, via="ssh"), now=time.time())


def test_machine_controls_details_and_owner(tmp_path):
    asyncio.run(_machine(tmp_path))


async def _machine(tmp_path):
    _seed(tmp_path)
    screen = ComplianceScreen(tmp_path, machine="10.0.0.5", framework="cis")
    app = _Host(screen)
    async with app.run_test(size=(200, 50)) as pilot:
        await pilot.pause()
        rows = {r["control"]: r for r in screen._rows}
        assert rows["2.4.1.2"]["status"] == "fail" and rows["1.1.1.1"]["status"] == "pass"
        assert all(r["status"] != "not_checked" or r.get("checks") for r in screen._rows)   # 'a' shows the rest
        idx = [r["control"] for r in screen._rows].index("2.4.1.2")
        screen.query_one("#co-table").move_cursor(row=idx)
        screen.action_details()
        await pilot.pause()
        assert isinstance(app.screen, InfoModal)
        body = _text(app.screen._body)
        assert "mode 666" in body and "sudo chmod 600 /etc/crontab" in body
        assert "read " in body and "via ssh" in body
        await pilot.press("escape")
        await pilot.pause()

        answers = iter(["machine:10.0.0.5", "alice", "2027-02-01", True])

        async def canned(_modal):
            return next(answers)

        screen.app.push_screen_wait = canned
        screen.action_owner()
        await pilot.pause()
        await pilot.pause()
        owner = O.owners_for(tmp_path, "cis", "10.0.0.5")["2.4.1.2"]
        assert owner.name == "alice" and owner.due == "2027-02-01"
        ev = store.events(tmp_path)[0]
        assert ev["kind"] == "owner_set" and ev["interface"] == "tui"

        answers = iter(["machine:10.0.0.5", "lab box", "30", False])          # declined: nothing written
        screen.action_na()
        await pilot.pause()
        await pilot.pause()
        assert O.na_for(tmp_path, "cis", "10.0.0.5") == {}


def test_group_rollup(tmp_path):
    asyncio.run(_group(tmp_path))


async def _group(tmp_path):
    from kratos.fleet import groups as G
    from kratos.lifecycle.decide import Actor

    _seed(tmp_path)
    G.create_group(tmp_path, "lab", Actor("owner", "cli"), members=["10.0.0.5", "10.0.0.6", "10.0.0.7"])
    screen = ComplianceScreen(tmp_path, group="@lab", framework="iso27001")
    app = _Host(screen)
    async with app.run_test(size=(200, 50)) as pilot:
        await pilot.pause()
        rows = {r["control"]: r for r in screen._rows}
        assert rows["8.3"]["status"] in ("fail", "partial")
        assert all(r["status"] != "pass" for r in screen._rows)            # 10.0.0.7 is unread: no group pass
        assert "3 machines" in _text(screen.query_one("#co-banner")._Static__content)


def test_worst_first_evidence_leads_with_the_failure_and_times_are_local(tmp_path):
    asyncio.run(_review_fixes(tmp_path))


async def _review_fixes(tmp_path):
    _seed(tmp_path)
    screen = ComplianceScreen(tmp_path, machine="10.0.0.5", framework="cis")
    app = _Host(screen)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        order = {"fail": 0, "partial": 1, "needs_person": 2, "pass": 3, "not_checked": 4, "not_applicable": 5}
        ranks = [order[r["status"]] for r in screen._rows]
        assert ranks == sorted(ranks) and screen._rows[0]["status"] == "fail"     # the failure is row 1
        # the detail pane names the failed check and what was found, not every check's text
        detail = _text(screen.query_one("#co-detail")._Static__content)
        assert "mode 666" in detail and "2 other checks passed" in detail
        banner = _text(screen.query_one("#co-banner")._Static__content)
        assert "1 fail" in banner and "T0" not in banner and "+00:00" not in banner
        hints = _text(screen.query_one("#co-hints")._Static__content)
        assert "esc back" in hints and "r read again" in hints
        screen.action_details()
        await pilot.pause()
        body = _text(app.screen._body)
        assert body.index("has mode 600 or stricter") < body.index("Checks that passed")
        assert "+00:00" not in body and "control(s)" not in body


def test_unread_machine_points_at_the_r_key_not_the_cli():
    from kratos.tui_mk2.screens.compliance import _screen_words
    from kratos.compliance.facts import SOURCE_FIX

    for hint in (next(iter(SOURCE_FIX.values())), "Kratos has no hardening read yet (run `kratos collect web-01`)"):
        assert "kratos collect" in hint and "kratos collect" not in _screen_words(hint)
        assert "press r" in _screen_words(hint)

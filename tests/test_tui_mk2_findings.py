"""Headless pilots for /findings (0.1 §5.8) and the conversation's lifecycle lines:
filters, the decision modal's checks, history, the rule-everywhere confirm that a
stray key declines, the footer under an answer, and decided findings folded."""
from __future__ import annotations

import asyncio
import io
import time
import uuid

from rich.console import Console
from textual.app import App
from textual.widgets import Input, RadioButton

from kratos.lifecycle import apply as A, decide as D, query as Q
from kratos.lifecycle.coverage import nothing
from kratos.lifecycle.keys import finding_key
from kratos.run_context import RunContext
from kratos.tui_mk2 import finding_view as FV
from kratos.tui_mk2 import render as R
from kratos.tui_mk2.modals import ConfirmModal, InfoModal
from kratos.tui_mk2.screens.findings import DecisionModal, FindingsScreen

T = "10.0.0.5"
ME = D.Actor(user="alice", interface="tui")


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _f(rid, sev, ents):
    return {"id": rid, "title": f"{rid} title", "severity": sev, "evidence": ["e"], "subject": "", "entities": ents}


def _seed(tmp_path):
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([_f("CORR-SSH-001", "high", ["203.0.113.9"]), _f("NET-002", "medium", ["22/tcp"]),
                 _f("AUTH-003", "info", ["ubuntu"])], target=T, coverage=nothing(), run=r, data_dir=tmp_path)
    D.mark_false_positive(finding_key("AUTH-003", T, ""), actor=ME, reason="admin work", data_dir=tmp_path)


def _text(widget) -> str:
    content = getattr(widget, "_Static__content", None)
    buf = io.StringIO()
    Console(file=buf, width=160).print(content)
    return buf.getvalue()


def _notes(screen) -> str:
    return "".join(_text(s) for s in screen.query("#fd-log Static"))


def test_default_view_hides_decided_and_counts_them(tmp_path):
    asyncio.run(_default_view_hides_decided_and_counts_them(tmp_path))


async def _default_view_hides_decided_and_counts_them(tmp_path):
    _seed(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        assert [r["rule_id"] for r in screen._rows] == ["CORR-SSH-001", "NET-002"]
        assert "Hidden by your decisions: 1" in _text(screen.query_one("#fd-banner"))
        await pilot.press("s")
        await pilot.pause()
        assert [r["rule_id"] for r in screen._rows] == ["AUTH-003"]
        await pilot.press("s", "s")       # fixed, then everything
        await pilot.pause()
        assert len(screen._rows) == 3
        await pilot.press("p", "p", "p")  # high and above
        await pilot.pause()
        assert [r["rule_id"] for r in screen._rows] == ["CORR-SSH-001"]


def test_search_and_history(tmp_path):
    asyncio.run(_search_and_history(tmp_path))


async def _search_and_history(tmp_path):
    _seed(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        screen._search = "22/tcp"
        screen.refresh_rows()
        assert [r["rule_id"] for r in screen._rows] == ["NET-002"]
        await pilot.press("h")
        await pilot.pause()
        assert isinstance(app.screen, InfoModal)
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is screen


def test_decision_modal_refuses_no_reason_and_over_the_cap():
    asyncio.run(_decision_modal_refuses_no_reason_and_over_the_cap())


async def _decision_modal_refuses_no_reason_and_over_the_cap():
    modal = DecisionModal("risk_accepted", "CORR-SSH-001", cap_days=30, default_owner="alice")
    app = _Host(modal)
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause()
        assert modal.validate() is None
        assert "reason is required" in _text(modal.query_one("#d-error"))
        modal.query_one("#d-reason", Input).value = "lab scanner"
        modal.query_one("#d-until", Input).value = "45"
        assert modal.validate() is None
        assert "At most 30 days" in _text(modal.query_one("#d-error"))
        modal.query_one("#d-until", Input).value = "next week"
        assert modal.validate() is None
        modal.query_one("#d-until", Input).value = "7"
        modal.query_one("#scope-rule_target", RadioButton).value = True
        await pilot.pause()
        values = modal.validate()
        assert values["reason"] == "lab scanner" and values["owner"] == "alice" and values["scope"] == "rule_target"
        assert 6.9 * 86400 < values["expires_at"] - time.time() <= 7 * 86400


def test_accept_flow_hides_the_finding(tmp_path):
    asyncio.run(_accept_flow_hides_the_finding(tmp_path))


async def _accept_flow_hides_the_finding(tmp_path):
    _seed(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, DecisionModal)
        modal.query_one("#d-reason", Input).value = "known scanner"
        await pilot.click("#d-save")
        await pilot.pause()
        await pilot.pause()
        assert app.screen is screen
        assert [r["rule_id"] for r in screen._rows] == ["NET-002"]
        assert "risk accepted until" in _notes(screen)
    assert Q.list_findings(tmp_path, target=T, state="decided")[0]["decision"]["decided_by"] == \
        D.Actor.current("tui").user


def test_rule_everywhere_needs_y_and_a_stray_key_declines(tmp_path):
    asyncio.run(_rule_everywhere_needs_y_and_a_stray_key_declines(tmp_path))


async def _rule_everywhere_needs_y_and_a_stray_key_declines(tmp_path):
    _seed(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.press("f")
        await pilot.pause()
        modal = app.screen
        modal.query_one("#d-reason", Input).value = "scanner"
        modal.query_one("#scope-rule", RadioButton).value = True
        await pilot.pause()
        await pilot.click("#d-save")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("x")          # anything but y declines
        await pilot.pause()
        await pilot.pause()
        assert app.screen is screen
        assert "Not changed" in _notes(screen)
    assert [r["rule_id"] for r in Q.list_findings(tmp_path, target=T)] == ["CORR-SSH-001", "NET-002"]


def test_reopen_needs_a_reason(tmp_path):
    asyncio.run(_reopen_needs_a_reason(tmp_path))


async def _reopen_needs_a_reason(tmp_path):
    _seed(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(160, 50)) as pilot:
        await pilot.pause()
        await pilot.press("s")            # decided
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("enter")        # empty reason
        await pilot.pause()
        await pilot.pause()
        assert "a reason is required" in _notes(screen)
        assert [r["rule_id"] for r in screen._rows] == ["AUTH-003"]


def test_footer_line_comes_from_the_last_correlation():
    transcript = [{"tool": "correlate_findings", "observation": {"status": "ok", "result": {
        "findings": [], "lifecycle": "New 2 · Still open 3 · Fixed 1 · Hidden by your decisions 4"}}},
        {"final_answer": "done"}]
    assert R.lifecycle_footer(transcript).plain == \
        "New 2 · Still open 3 · Fixed 1 · Hidden by your decisions 4  (/findings)"
    assert R.lifecycle_footer([{"final_answer": "x"}]) is None


def test_decided_findings_fold_into_one_line_whatever_their_severity():
    accepted = {"id": "CORR-SSH-001", "severity": "high", "state": "risk_accepted",
                "decision": {"expires_at": "2026-11-12T10:00:00+00:00"}, "evidence": []}
    undecided = {"id": "PRIV-002", "severity": "high", "state": "open", "evidence": []}
    full, folded = FV.plan([accepted, undecided], {}, None)
    assert [f["id"] for f, _ in full] == ["PRIV-002"]
    assert FV.folded_summary(folded) == \
        "Hidden by your decisions: CORR-SSH-001 (risk accepted until 12 Nov) — /findings shows them."


# --- B.1: verdicts and model suggestions in /findings -------------------------------
def test_verdicts_and_suggestions_show_and_dismiss(tmp_path):
    asyncio.run(_verdicts_and_suggestions_show_and_dismiss(tmp_path))


async def _verdicts_and_suggestions_show_and_dismiss(tmp_path):
    from kratos.triage import store as TS
    from kratos.triage.verdict import Verdict, VerifyCheck

    _seed(tmp_path)
    key = finding_key("CORR-SSH-001", T, "")
    TS.record_verdict(tmp_path, finding_key=key, verifier="re-measured sign-in activity", cost="quick",
                      run_id=None, duration=0.3,
                      verdict=Verdict("reproduced", "The burst is still in the logs.",
                                      checks=(VerifyCheck("measure_auth_activity", "ssh"),),
                                      evidence=("40 failed SSH logins",)))
    sid = TS.record_suggestion(tmp_path, finding_key=key, rule_id="CORR-SSH-001", target=T, run_id=None,
                               kind="false_positive", why="our own pentest box")
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(180, 40)) as pilot:
        await pilot.pause()
        row = next(r for r in screen._rows if r["rule_id"] == "CORR-SSH-001")
        assert row["verdict"]["verdict"] == "reproduced"
        assert row["suggestions"] and row["suggestions"][0]["id"] == sid
        # the detail modal opens without error and shows the verdict + suggestion
        screen.action_details()
        await pilot.pause()
        detail = "".join(_text(s) for s in app.screen.query("Static"))
        assert "reproduced by a fresh read" in detail and "our own pentest box" in detail
        app.pop_screen()
        await pilot.pause()
        # dismiss the suggestion via the n binding (CORR-SSH-001 is the first row)
        screen.action_dismiss_suggestion()
        await pilot.pause()
        assert TS.suggestions_for(tmp_path, key, state="new") == []
        assert "Dismissed the model's suggestion" in _notes(screen)

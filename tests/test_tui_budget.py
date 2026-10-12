"""Headless pilots for the budget UI: Settings -> Budget (edit + validation,
resume a paused source, prices), the one-time summary before the first schedule
or trigger (Keep / Edit / Cancel), the over-cap prompt's keys, the plain stop
message, the near-limit footer note and /doctor's Budget row."""
from __future__ import annotations

import asyncio
import threading
import time

import pytest
from textual.app import App

from kratos import kratos_config, settings_store
from kratos.budget import breaker, guard, limits as L
from kratos.budget.ledger import BudgetLedger
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen
from kratos.tui_mk2.screens.settings import SettingsScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _answers(app, monkeypatch, values, seen=None):
    it = iter(values)

    async def _fn(modal):
        if seen is not None:
            seen.append(modal)
        return next(it)

    monkeypatch.setattr(app, "push_screen_wait", _fn)


async def _settle(pilot, until, n=200):
    for _ in range(n):
        await pilot.pause()
        if until():
            return


# --- Settings -> Budget ----------------------------------------------------------
def test_budget_tab_lists_every_limit_with_todays_spend(tmp_path):
    screen = SettingsScreen(data_dir=tmp_path, initial_tab="tab-budget")

    async def _run():
        async with _Host(screen).run_test(size=(120, 50)) as pilot:
            await pilot.pause()
            table = screen.query_one("#bud-table")
            labels = [str(table.get_row_at(i)[0]) for i in range(table.row_count)]
            return screen._active_tab(), labels, [k for kind, k in screen._bud_rows if kind == "limit"]

    tab, labels, keys = asyncio.run(_run())
    assert tab == "tab-budget"
    assert keys == list(L.KEYS)
    assert "Daily budget, everything" in labels and "Paused sources" in labels
    assert any("gemini-3.1-flash-lite" in label for label in labels)


def test_editing_a_limit_validates_and_records_who(tmp_path, monkeypatch):
    screen = SettingsScreen(data_dir=tmp_path, initial_tab="tab-budget")

    async def _run():
        app = _Host(screen)
        async with app.run_test(size=(120, 50)) as pilot:
            await pilot.pause()
            _answers(app, monkeypatch, ["lots"])
            screen._set_budget_limit_flow(L.DAILY_COST)
            await _settle(pilot, lambda: "Not changed" in str(screen.query_one("#bud-status").render()))
            bad = str(screen.query_one("#bud-status").render())
            _answers(app, monkeypatch, ["$5.50"])
            screen._set_budget_limit_flow(L.DAILY_COST)
            await _settle(pilot, lambda: "Saved" in str(screen.query_one("#bud-status").render()))
            _answers(app, monkeypatch, ["on"])
            screen._set_budget_limit_flow(L.TRIGGER_INVESTIGATIONS)
            await _settle(pilot, lambda: settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path))
            return bad

    bad = asyncio.run(_run())
    assert "Not changed: an amount in US dollars" in bad
    assert settings_store.get(L.DAILY_COST, data_dir=tmp_path) == 5.5
    assert settings_store.last_change(L.DAILY_COST, data_dir=tmp_path)[1] == "tui:settings"
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is True


def test_a_paused_source_can_be_resumed_from_the_budget_tab(tmp_path, monkeypatch):
    for _ in range(5):
        breaker.record_outcome(tmp_path, "mcp", failure="x")
    screen = SettingsScreen(data_dir=tmp_path, initial_tab="tab-budget")

    async def _run():
        app = _Host(screen)
        async with app.run_test(size=(120, 50)) as pilot:
            await pilot.pause()
            assert ("pause", "mcp") in screen._bud_rows
            _answers(app, monkeypatch, [True])
            screen._resume_pause_flow("mcp")
            await _settle(pilot, lambda: not breaker.list_pauses(tmp_path))
            return screen._bud_rows

    rows = asyncio.run(_run())
    assert breaker.list_pauses(tmp_path) == [] and ("pause", "mcp") not in rows
    assert BudgetLedger(tmp_path).state_get("pause:mcp")["resumed_by"] == "tui:settings"


def test_prices_can_be_added_corrected_and_removed(tmp_path, monkeypatch):
    from kratos.budget import pricing

    screen = SettingsScreen(data_dir=tmp_path, initial_tab="tab-budget")

    async def _run():
        app = _Host(screen)
        async with app.run_test(size=(120, 50)) as pilot:
            await pilot.pause()
            _answers(app, monkeypatch, ["my-model", "0.5, 1.5"])
            screen._edit_rate_flow(None)
            await _settle(pilot, lambda: "my-model" in pricing.rates(tmp_path))
            _answers(app, monkeypatch, ["$0.25 / $1"])
            screen._edit_rate_flow("my-model")
            await _settle(pilot, lambda: pricing.rates(tmp_path)["my-model"] == (0.25, 1.0))
            _answers(app, monkeypatch, ["-1, 2"])
            screen._edit_rate_flow("my-model")
            await _settle(pilot, lambda: "Not changed" in str(screen.query_one("#bud-status").render()))
            _answers(app, monkeypatch, ["remove"])
            screen._edit_rate_flow("my-model")
            await _settle(pilot, lambda: "my-model" not in pricing.rates(tmp_path))

    asyncio.run(_run())
    assert "my-model" not in pricing.rates(tmp_path)
    assert "gemini-3.1-flash-lite" in pricing.rates(tmp_path)


# --- the one-time summary before the first schedule / trigger ----------------------
def _session(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


@pytest.mark.parametrize("choice", ["keep", "edit"])
def test_first_schedule_shows_the_budget_summary_then_continues(tmp_path, monkeypatch, choice):
    from kratos.agent import schedules as S

    screen = _session(tmp_path, monkeypatch)
    seen: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            answers = ["audit", "weekly", "high", choice] + ([None] if choice == "edit" else []) + ["weekly-audit"]
            _answers(app, monkeypatch, answers, seen)
            screen._dispatch_slash("/schedule new")
            await _settle(pilot, lambda: S.schedule_exists(tmp_path, "weekly-audit"))

    asyncio.run(_run())
    assert S.schedule_exists(tmp_path, "weekly-audit")
    summary = next(m for m in seen if getattr(m, "_title", "") == "Spending limits for unattended runs")
    assert "$0.50 per day" in summary._subtitle and "they only notify" in summary._subtitle
    if choice == "edit":
        opened = [m for m in seen if isinstance(m, SettingsScreen)]
        assert len(opened) == 1 and opened[0]._initial_tab == "tab-budget"
    assert BudgetLedger(tmp_path).state_get(SessionScreen._UNATTENDED_BUDGET_SHOWN)["choice"] == choice


def test_cancel_at_the_summary_creates_nothing_and_asks_again_next_time(tmp_path, monkeypatch):
    from kratos.agent import triggers as T

    screen = _session(tmp_path, monkeypatch)
    seen: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # severity, finding-id, only-new, action, cooldown, summary -> cancel
            _answers(app, monkeypatch, ["high", "", False, "notify", "60", "cancel"], seen)
            screen._dispatch_slash("/trigger new")
            await _settle(pilot, lambda: len(seen) >= 6)
            for _ in range(10):
                await pilot.pause()

    asyncio.run(_run())
    assert T.list_triggers(tmp_path)[0] == []
    assert BudgetLedger(tmp_path).state_get(SessionScreen._UNATTENDED_BUDGET_SHOWN) is None


def test_the_summary_is_shown_once(tmp_path, monkeypatch):
    from kratos.agent import triggers as T

    screen = _session(tmp_path, monkeypatch)
    seen: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            _answers(app, monkeypatch, ["high", "", False, "notify", "60", "keep", "first",
                                        "high", "", False, "notify", "60", "second"], seen)
            screen._dispatch_slash("/trigger new")
            await _settle(pilot, lambda: T.trigger_exists(tmp_path, "first"))
            screen._dispatch_slash("/trigger new")
            await _settle(pilot, lambda: T.trigger_exists(tmp_path, "second"))

    asyncio.run(_run())
    titles = [getattr(m, "_title", "") for m in seen]
    assert titles.count("Spending limits for unattended runs") == 1


def test_an_investigate_trigger_while_investigations_are_off_says_it_will_only_notify(tmp_path, monkeypatch):
    from kratos.agent import triggers as T

    monkeypatch.setattr("kratos.agent.scheduled_run.active_backend_is_cloud", lambda: False)
    screen = _session(tmp_path, monkeypatch)
    BudgetLedger(tmp_path).state_set(SessionScreen._UNATTENDED_BUDGET_SHOWN, {"choice": "keep"})
    lines: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(screen, "_emit", lambda r: lines.append(str(r)))
            _answers(app, monkeypatch, ["high", "", False, "investigate", "60", "deep"])
            screen._dispatch_slash("/trigger new")
            await _settle(pilot, lambda: T.trigger_exists(tmp_path, "deep") and lines)
            for _ in range(5):
                await pilot.pause()

    asyncio.run(_run())
    assert any("will only notify" in line for line in lines)


# --- over-cap prompt (y = continue, anything else = stop) ---------------------------
@pytest.mark.parametrize("key,expected", [("y", True), ("n", False), ("escape", False), ("x", False),
                                          ("enter", False)])
def test_the_over_cap_modal_continues_only_on_y(key, expected):
    from kratos.tui_mk2.approvals import make_textual_budget_provider

    class _Empty(App):
        pass

    async def _run():
        app = _Empty()
        async with app.run_test() as pilot:
            provider = make_textual_budget_provider(app)
            box = {}
            q = guard.OverCapQuestion(L.SCOPE_DAILY_COST, 2.0, 1.94, "interactive")
            t = threading.Thread(target=lambda: box.setdefault("answer", provider(q)))
            t.start()
            for _ in range(50):
                await pilot.pause()
                if app.screen.__class__.__name__ == "ConfirmModal":
                    break
            title = str(app.screen._title)
            await pilot.press(key)
            for _ in range(50):
                await pilot.pause()
                if "answer" in box:
                    break
            t.join(5)
            return title, box["answer"]

    title, answer = asyncio.run(_run())
    assert title == "Over the model budget" and answer is expected


def test_the_provider_called_on_the_event_loop_fails_safe():
    from kratos.tui_mk2.approvals import make_textual_budget_provider

    class _Empty(App):
        pass

    async def _run():
        app = _Empty()
        async with app.run_test():
            return make_textual_budget_provider(app)(guard.OverCapQuestion(L.SCOPE_DAILY_COST, 2.0, 2.0, "x"))

    assert asyncio.run(_run()) is False


# --- what the person sees when a limit stops something ------------------------------
def test_a_budget_stop_while_routing_is_one_plain_line(tmp_path, monkeypatch):
    from kratos.tui_mk2 import command_intent

    screen = _session(tmp_path, monkeypatch)

    def refuse(*a, **k):
        raise guard.BudgetExceeded(L.SCOPE_DAILY_COST, 2.0, 2.0, source="interactive")

    monkeypatch.setattr(command_intent, "agent_chat", refuse)
    lines: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(screen, "_emit_from_worker", lambda r: lines.append(str(r)))
            screen._run_goal("is ssh exposed?")
            await _settle(pilot, lambda: lines and not screen._busy)

    asyncio.run(_run())
    assert lines == ["! Stopped by budget: today's model budget is used up ($2.00 of $2.00). "
                     "Change it in Settings → Budget."]


def test_a_budget_stopped_investigation_shows_its_answer(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop

    screen = _session(tmp_path, monkeypatch)
    monkeypatch.setattr(screen, "_maybe_auto_compact", lambda: None, raising=False)
    monkeypatch.setattr(agent_loop, "run_agent", lambda *a, **k: {
        "status": "stopped_by_budget", "final_answer": "Stopped by budget: this run's model-call limit is used up.",
        "transcript": [], "budget": {"scope": "run_model_calls"}})
    bubbles: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(screen, "_emit_bubble_from_worker", lambda r, d: bubbles.append(r))
            screen._run_target_investigation("check it")
            await _settle(pilot, lambda: bubbles and not screen._busy)

    asyncio.run(_run())
    assert bubbles and "stopped by budget" in str(bubbles[0].title)


def test_footer_mentions_a_daily_limit_only_when_near_it(tmp_path, monkeypatch):
    from kratos.budget import report

    kratos_config.set_active_data_dir(tmp_path)
    assert report.near_limit(tmp_path) is None
    led = BudgetLedger(tmp_path)
    day = guard.local_day(time.time(), tmp_path)
    with led.transaction() as conn:
        rid = BudgetLedger.insert(conn, at=time.time(), day=day, status="reserved",
                                  source="interactive", model="m", local=False, est_tokens=1)
    led.settle(rid, prompt_tokens=1, completion_tokens=1, total_tokens=2, cost_usd=1.0, cost_source="rate_table")
    assert report.near_limit(tmp_path) is None                     # $1.00 of $2.00: quiet
    settings_store.set(L.DAILY_COST, 1.05, data_dir=tmp_path, actor="test")
    assert report.near_limit(tmp_path) == "budget: $1.00 of $1.05 (today, everything)"
    settings_store.set(L.DAILY_COST, 1.0, data_dir=tmp_path, actor="test")
    assert report.near_limit(tmp_path) == "budget: today, everything used up"


def test_doctor_has_a_budget_row(tmp_path):
    from kratos.agent import doctor

    out: list = []
    doctor._check_budget(out, tmp_path)
    (row,) = out
    assert row["check"] == "budget" and row["status"] == "info"
    assert "today $0.00 of $2.00" in row["detail"] and "per run: 40 calls / 300,000 tokens" in row["detail"]
    for _ in range(5):
        breaker.record_outcome(tmp_path, "trigger", failure="x")
    out.clear()
    doctor._check_budget(out, tmp_path)
    assert out[0]["status"] == "warn" and "paused: trigger" in out[0]["detail"]

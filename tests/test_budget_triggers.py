"""Triggers under spending limits: a daily fire cap per trigger with one
notification, the 'triggers may start investigations' setting (off on a new
install, carried over on upgrade), and the 400-fire storm."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from kratos import kratos_config, llm_interface, settings_store
from kratos.agent import trigger_eval, triggers as T
from kratos.budget import guard, limits as L
from kratos.budget.ledger import BudgetLedger
from kratos.run_context import run_scope

FINDING = {"id": "CORR-SSH-001", "title": "SSH brute force", "severity": "high", "evidence": ["attacker text"]}
NOON = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _utc_day(monkeypatch):
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz", lambda data_dir=None: timezone.utc)


def _collect():
    sent: list[tuple[str, str]] = []
    return sent, (lambda message, severity: sent.append((message, severity)) or {"status": "sent"})


def _no_investigation(goal, data_dir):
    raise AssertionError("an investigation must not start")


def test_new_install_keeps_investigations_off_and_says_how_to_turn_them_on(tmp_path):
    guard.ensure_upgrade_migration(tmp_path)            # first run of this version: no triggers yet
    T.save_trigger(tmp_path, name="deep", action="investigate", min_severity="high", cooldown_minutes=0)
    sent, notifier = _collect()
    fired = trigger_eval.evaluate_triggers(tmp_path, [FINDING], "10.0.0.9", now=NOON, notifier=notifier,
                                           investigate_fn=_no_investigation)
    assert len(fired) == 1 and fired[0]["investigation_status"] is None
    assert "triggers may not start investigations" in sent[0][0]
    assert "Settings -> Budget" in sent[0][0]
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is False


def test_preview_says_investigations_are_off(tmp_path):
    guard.ensure_upgrade_migration(tmp_path)
    tg = T.save_trigger(tmp_path, name="deep", action="investigate", min_severity="high")
    preview = trigger_eval.preview_trigger(tmp_path, tg, [FINDING], "10.0.0.9", now=NOON)
    assert "triggers may not start investigations" in preview["body"]


def test_upgrade_turns_investigations_on_once_when_a_trigger_already_investigates(tmp_path):
    T.save_trigger(tmp_path, name="deep", action="investigate", min_severity="high")
    T.save_trigger(tmp_path, name="ping", action="notify", min_severity="low")
    guard.ensure_upgrade_migration(tmp_path)
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is True
    assert settings_store.last_change(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path)[1] == "upgrade:0.4"
    notes = BudgetLedger(tmp_path).rows(status="note")
    assert len(notes) == 1 and '"triggers": ["deep"]' in notes[0]["note"]
    (notice,) = guard.pending_notices(tmp_path)
    assert "deep" in notice and "turned on for you" in notice
    assert guard.pending_notices(tmp_path) == []         # shown once
    # the person turns it off again: a later start never flips it back
    settings_store.set(L.TRIGGER_INVESTIGATIONS, False, data_dir=tmp_path, actor="tui:settings")
    guard._migrated.clear()
    guard.ensure_upgrade_migration(tmp_path)
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is False
    assert len(BudgetLedger(tmp_path).rows(status="note")) == 1


def test_upgrade_with_only_notify_triggers_changes_nothing(tmp_path):
    T.save_trigger(tmp_path, name="ping", action="notify", min_severity="low")
    guard.ensure_upgrade_migration(tmp_path)
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is False
    assert guard.pending_notices(tmp_path) == [] and BudgetLedger(tmp_path).rows() == []


def test_the_upgrade_happens_at_startup(tmp_path, monkeypatch):
    from kratos.cli import app

    T.save_trigger(tmp_path, name="deep", action="investigate", min_severity="high")
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    app.main(["--data-dir", str(tmp_path), "findings-show"])
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is True


def test_a_trigger_stops_at_its_daily_fire_limit_with_one_notification(tmp_path):
    T.save_trigger(tmp_path, name="ping", action="notify", min_severity="low", cooldown_minutes=0)
    settings_store.set(L.TRIGGER_FIRES_PER_DAY, 3, data_dir=tmp_path, actor="test")
    sent, notifier = _collect()
    for i in range(8):
        trigger_eval.evaluate_triggers(tmp_path, [FINDING], "10.0.0.9", now=NOON + timedelta(minutes=i),
                                       notifier=notifier)
    assert len(T.read_fire_records(tmp_path, "ping")) == 3
    caps = [m for m, s in sent if "reached its limit of 3 fires today" in m]
    assert len(caps) == 1 and [s for m, s in sent if m in caps] == ["warning"]
    assert "attacker text" not in caps[0]
    # the next local day it fires again
    trigger_eval.evaluate_triggers(tmp_path, [FINDING], "10.0.0.9", now=NOON + timedelta(days=1), notifier=notifier)
    assert len(T.read_fire_records(tmp_path, "ping")) == 4


def test_fire_limit_zero_means_never(tmp_path):
    T.save_trigger(tmp_path, name="ping", action="notify", min_severity="low", cooldown_minutes=0)
    settings_store.set(L.TRIGGER_FIRES_PER_DAY, 0, data_dir=tmp_path, actor="test")
    sent, notifier = _collect()
    assert trigger_eval.evaluate_triggers(tmp_path, [FINDING], "10.0.0.9", now=NOON, notifier=notifier) == []
    assert len(sent) == 1 and "limit of 0 fires" in sent[0][0]


def test_storm_of_400_matches(tmp_path, monkeypatch):
    """400 matched evaluations in one day: fires stop at the cap, exactly one cap
    notification, and spending stops at the unattended cap."""
    kratos_config.set_active_data_dir(tmp_path)
    from kratos.budget import pricing

    pricing.set_rate(tmp_path, "priced-model", 1.0, 2.0, actor="test")
    T.save_trigger(tmp_path, name="storm", action="investigate", min_severity="high", cooldown_minutes=0)
    settings_store.set(L.TRIGGER_INVESTIGATIONS, True, data_dir=tmp_path, actor="test")
    settings_store.set(L.UNATTENDED_DAILY_COST, 0.0025, data_dir=tmp_path, actor="test")
    monkeypatch.setattr("kratos.llm_config.get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_config._active_backend_is_local", lambda: False)

    def metered_investigation(goal, data_dir):
        """A one-call investigation through the real budget guard."""
        def send():
            return {"choices": [{"message": {"content": "{}"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 100, "total_tokens": 110}}
        try:
            llm_interface._metered_call(send, system_prompt="s", prompt=goal, max_tokens=512,
                                        model="priced-model", local=False)
        except guard.BudgetExceeded as e:
            return {"status": "stopped_by_budget", "final_answer": e.user_message(), "transcript": []}
        return {"status": "final_answer", "final_answer": "looked", "transcript": []}

    from kratos.agent import scheduled_run

    sent, notifier = _collect()
    with run_scope("schedule"):
        for i in range(400):
            trigger_eval.evaluate_triggers(
                tmp_path, [FINDING], "10.0.0.9", now=NOON + timedelta(seconds=i), notifier=notifier,
                investigate_fn=lambda goal, dd: scheduled_run.run_headless_investigation(
                    goal, dd, run_agent_fn=metered_investigation))
    fires = T.read_fire_records(tmp_path, "storm")
    assert len(fires) == 10                                            # the default cap
    assert sum("reached its limit of 10 fires today" in m for m, _ in sent) == 1
    # The ledger dates rows by the real clock (the trigger evaluation's `now` above is
    # fixed): read the day(s) back from the rows instead of naming one -- a hard-coded
    # date passed only on the day the test was written. A run across local midnight
    # gets a fresh cap for the new day.
    ledger = BudgetLedger(tmp_path)
    with ledger.connect() as conn:
        days = [r[0] for r in conn.execute("SELECT DISTINCT day FROM budget_ledger")]
    spent = sum(ledger.totals_for_day(d).unattended_cost_usd for d in days)
    assert days and 0 < spent <= 0.0025 * len(days)
    statuses = [f["investigation_status"] for f in fires]
    assert statuses.count("final_answer") < 10
    assert set(statuses) <= {"final_answer", "stopped_by_budget", "refused_by_budget"}

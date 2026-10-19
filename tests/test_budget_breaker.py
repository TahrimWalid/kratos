"""The circuit breaker (kratos.budget.breaker): N failed or looping runs within
the window pause an unattended source (one notification), paused sources refuse
to start and their model calls are refused, a person can resume early, and
interactive use is only warned."""
from __future__ import annotations

import time

import pytest

from kratos import kratos_config, settings_store
from kratos.budget import breaker, guard, limits as L
from kratos.budget.guard import BudgetExceeded
from kratos.budget.ledger import BudgetLedger
from kratos.run_context import run_scope


def _step(tool, args=None, ok=True):
    return {"tool": tool, "args": args or {}, "observation": {"status": "ok" if ok else "error", "result": {}}}


@pytest.fixture
def dd(tmp_path):
    kratos_config.set_active_data_dir(tmp_path)
    settings_store.set(L.BREAKER_FAILURES, 3, data_dir=tmp_path, actor="test")
    settings_store.set(L.BREAKER_WINDOW, 60, data_dir=tmp_path, actor="test")
    settings_store.set(L.BREAKER_PAUSE, 120, data_dir=tmp_path, actor="test")
    return tmp_path


# --- what counts as a failure ------------------------------------------------
def test_failure_reasons():
    assert breaker.run_failure_reason({"status": "llm_unavailable"}) == "the model was unavailable"
    assert breaker.run_failure_reason({"status": "error"}) == "the run errored"
    assert breaker.run_failure_reason(None) == "the run returned nothing"
    looped = {"status": "final_answer", "transcript": [_step("list_processes", {"a": 1})] * 3}
    assert "looped: list_processes repeated 3 times" in breaker.run_failure_reason(looped)
    no_correlate = {"status": "max_iters_reached", "transcript": [_step("list_processes")]}
    assert breaker.run_failure_reason(no_correlate) == "it hit the step limit without finishing"
    with_correlate = {"status": "max_iters_reached", "transcript": [_step("correlate_findings")]}
    assert breaker.run_failure_reason(with_correlate) is None
    assert breaker.run_failure_reason({"status": "final_answer", "transcript": [_step("x"), _step("x")]}) is None


def test_same_tool_with_different_arguments_is_not_a_loop():
    steps = [_step("read_journalctl", {"since": f"{h} hours ago"}) for h in (1, 2, 3)]
    assert breaker.detect_loop(steps) is None


# --- pausing ---------------------------------------------------------------------
def test_n_failures_pause_an_unattended_source_with_one_notification(dd, _budget_isolated):
    for _ in range(2):
        assert breaker.record_outcome(dd, "mcp", failure="the model was unavailable") is None
    pause = breaker.record_outcome(dd, "mcp", failure="the model was unavailable")
    assert pause is not None and pause["until"] > time.time() + 119 * 60
    assert breaker.active_pause(BudgetLedger(dd), "mcp") is not None
    sent = [m for m, s in _budget_isolated if "paused mcp" in m]
    assert len(sent) == 1 and [s for m, s in _budget_isolated if m in sent] == ["warning"]
    # its model calls are refused while paused, without asking anyone
    guard.set_prompt_provider(lambda q: True, actor="test")
    with run_scope("mcp"), pytest.raises(BudgetExceeded) as exc:
        guard.before_call(est_prompt_tokens=1, max_completion_tokens=1, model="m", local=True)
    assert exc.value.scope == L.SCOPE_PAUSED and "resume it in Settings -> Budget" in str(exc.value)


def test_failures_outside_the_window_do_not_count(dd):
    now = time.time()
    breaker.record_outcome(dd, "trigger", failure="x", now=now - 61 * 60)
    breaker.record_outcome(dd, "trigger", failure="x", now=now - 61 * 60)
    assert breaker.record_outcome(dd, "trigger", failure="x", now=now) is None


def test_a_success_records_nothing(dd):
    for _ in range(5):
        assert breaker.record_outcome(dd, "mcp", failure=None) is None
    assert BudgetLedger(dd).state_prefix("breaker:") == {}


def test_each_schedule_has_its_own_breaker(dd):
    for _ in range(3):
        breaker.record_outcome(dd, breaker.key_for("schedule", "nightly"), failure="x")
    ledger = BudgetLedger(dd)
    assert breaker.active_pause(ledger, "schedule:nightly") is not None
    assert breaker.active_pause(ledger, "schedule:weekly") is None


def test_a_paused_schedule_refuses_to_start(dd, monkeypatch):
    from kratos.agent import presets as P
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run

    kratos_config.set_active_target("10.0.0.9")
    for _ in range(3):
        breaker.record_outcome(dd, "schedule:nightly", failure="the run errored")
    P.save_preset(dd, name="look", goal="is ssh exposed?")
    sch = S.save_schedule(dd, name="nightly", kind="preset", preset="look", target="10.0.0.9")
    monkeypatch.setattr("kratos.agent.loop.run_agent", lambda *a, **k: pytest.fail("must not start"))
    record = scheduled_run.run_scheduled(sch, dd, deliver=False)
    assert record["status"] == "refused_by_budget" and "paused" in record["error"]


def test_scheduled_failures_trip_that_schedules_breaker(dd, monkeypatch):
    from kratos.agent import presets as P
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run

    kratos_config.set_active_target("10.0.0.9")
    P.save_preset(dd, name="look", goal="is ssh exposed?")
    sch = S.save_schedule(dd, name="nightly", kind="preset", preset="look", target="10.0.0.9")
    monkeypatch.setattr("kratos.agent.loop.run_agent",
                        lambda *a, **k: {"status": "llm_unavailable", "transcript": []})
    for _ in range(3):
        scheduled_run.run_scheduled(sch, dd, deliver=False)
    assert breaker.active_pause(BudgetLedger(dd), "schedule:nightly") is not None
    assert scheduled_run.run_scheduled(sch, dd, deliver=False)["status"] == "refused_by_budget"


def test_mcp_failures_trip_the_mcp_breaker(dd, monkeypatch):
    from kratos import mcp_server

    monkeypatch.setattr("kratos.agent.loop.run_agent", lambda *a, **k: {"status": "llm_unavailable", "transcript": []})
    for _ in range(3):
        mcp_server._mcp_investigation("goal", "10.0.0.9", 3, dd)
    out = mcp_server._mcp_investigation("goal", "10.0.0.9", 3, dd)
    assert out["status"] == "refused_by_budget" and "paused" in out["final_answer"]


def test_a_budget_stop_is_not_a_failure(dd, monkeypatch):
    from kratos import mcp_server

    monkeypatch.setattr("kratos.agent.loop.run_agent",
                        lambda *a, **k: {"status": "stopped_by_budget", "final_answer": "x", "transcript": [],
                                         "budget": {"scope": "daily_cost"}})
    for _ in range(4):
        mcp_server._mcp_investigation("goal", "10.0.0.9", 3, dd)
    assert breaker.active_pause(BudgetLedger(dd), "mcp") is None


def test_resume_ends_a_pause_early_and_keeps_a_record(dd):
    for _ in range(3):
        breaker.record_outcome(dd, "trigger", failure="x")
    assert [p["key"] for p in breaker.list_pauses(dd)] == ["trigger"]
    assert breaker.resume(dd, "trigger", actor="tui:settings") is True
    assert breaker.list_pauses(dd) == []
    kept = BudgetLedger(dd).state_get("pause:trigger")
    assert kept["resumed_by"] == "tui:settings"
    assert breaker.resume(dd, "trigger", actor="tui:settings") is False


def test_interactive_use_is_never_paused_only_warned(dd, _budget_isolated):
    notices: list = []
    guard.set_notice_listener(lambda text, level: notices.append((text, level)))
    for _ in range(3):
        assert breaker.record_outcome(dd, "interactive", failure="the model was unavailable") is None
    assert breaker.list_pauses(dd) == []
    assert len(notices) == 1 and notices[0][1] == "warning" and "worth checking" in notices[0][0]
    assert not any("paused" in m for m, _ in _budget_isolated)
    with run_scope("interactive"):
        guard.before_call(est_prompt_tokens=1, max_completion_tokens=1, model="m", local=True)


def test_resume_is_refused_inside_a_tool_call(dd):
    from kratos import settings_store

    for _ in range(3):
        breaker.record_outcome(dd, "mcp", failure="x")
    with settings_store.tool_call_scope("some_tool"), pytest.raises(settings_store.SettingError):
        breaker.resume(dd, "mcp", actor="model")
    assert breaker.list_pauses(dd)


def test_no_registered_tool_module_touches_budget_decisions():
    """No agent tool may change a limit, a price or a pause: their modules don't
    reach the people-only budget functions (settings_store.set is scanned by
    tests/test_settings_store.py; the runtime refusals are the second layer)."""
    import inspect
    from pathlib import Path

    from kratos.agent.tools import TOOL_REGISTRY

    files = {inspect.getsourcefile(t.handler) for t in TOOL_REGISTRY.values()}
    words = ("set_rate", "remove_rate", "breaker.resume", "set_prompt_provider", "kratos.budget")
    offenders = {f: [w for w in words if w in Path(f).read_text(encoding="utf-8")] for f in files}
    assert {f: w for f, w in offenders.items() if w} == {}

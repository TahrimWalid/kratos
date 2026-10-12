"""budget_ledger / budget_state (kratos.budget.ledger): schema, reservations,
totals, expiry, once-only state claims."""
from __future__ import annotations

import sqlite3

import pytest

from kratos.budget import ledger as LG
from kratos.budget.ledger import BudgetLedger


def _reserve(conn, *, day="2026-10-12", source="interactive", run_id="r1", est=1000, est_cost=0.01,
             local=False, at=1000.0, model="m"):
    return BudgetLedger.insert(conn, at=at, day=day, status=LG.RESERVED, source=source, model=model,
                               local=local, run_id=run_id, est_tokens=est, est_cost_usd=est_cost)


def test_tables_created_from_an_empty_db_and_versioned(tmp_path):
    BudgetLedger(tmp_path)
    conn = sqlite3.connect(tmp_path / "kratos.db")
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'index')")}
    assert {"budget_ledger", "budget_state", "budget_ledger_day", "budget_ledger_run"} <= names
    assert conn.execute("SELECT version FROM schema_versions WHERE component = 'budget'").fetchone()[0] == 1
    BudgetLedger(tmp_path)  # opening again is a no-op
    assert conn.execute("SELECT COUNT(*) FROM schema_versions WHERE component = 'budget'").fetchone()[0] == 1


def test_migration_is_idempotent_on_a_db_that_already_has_the_tables(tmp_path):
    conn = sqlite3.connect(tmp_path / "kratos.db")
    LG._step_1(conn)
    conn.commit()
    conn.close()
    from kratos.storage import migrations

    migrations._migrated.clear()
    BudgetLedger(tmp_path)  # schema_versions had no 'budget' row: step 1 runs again harmlessly


def test_unknown_status_is_rejected(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn, pytest.raises(ValueError):
        BudgetLedger.insert(conn, at=1.0, day="d", status="bogus", source="cli", model="m", local=False)


def test_reservation_counts_at_its_estimate_then_at_actual_usage(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        rid = _reserve(conn, est=5000, est_cost=0.05)
        t = BudgetLedger.day_totals(conn, "2026-10-12")
        assert (t.tokens, t.calls, round(t.cost_usd, 4)) == (5000, 1, 0.05)
    led.settle(rid, prompt_tokens=300, completion_tokens=100, total_tokens=400, cost_usd=0.001,
               cost_source="rate_table")
    t = led.totals_for_day("2026-10-12")
    assert (t.tokens, t.calls, round(t.cost_usd, 4), t.unpriced_tokens) == (400, 1, 0.001, 0)
    row = led.rows()[0]
    assert row["status"] == "settled" and row["est_tokens"] == 5000


def test_crashed_reservation_expires_and_stops_counting_its_estimate(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        _reserve(conn, est=9000, at=1000.0)
        assert BudgetLedger.expire_stale(conn, 1000.0 + LG.RESERVATION_TTL_SECONDS - 1) == 0
        assert BudgetLedger.expire_stale(conn, 1000.0 + LG.RESERVATION_TTL_SECONDS + 1) == 1
        t = BudgetLedger.day_totals(conn, "2026-10-12")
    assert (t.tokens, t.calls) == (0, 1)  # still a call, usage unknown
    assert led.rows()[0]["status"] == "expired"


def test_ttl_never_shorter_than_ten_minutes_or_one_request():
    from kratos.llm_config import REQUEST_TIMEOUT_SECONDS

    assert LG.RESERVATION_TTL_SECONDS >= 600
    assert LG.RESERVATION_TTL_SECONDS > REQUEST_TIMEOUT_SECONDS


def test_a_slow_call_that_expired_still_settles_with_its_real_usage(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        rid = _reserve(conn, at=0.0)
        BudgetLedger.expire_stale(conn, 10_000.0)
    led.settle(rid, prompt_tokens=10, completion_tokens=5, total_tokens=15, cost_usd=None, cost_source="unknown")
    assert led.rows()[0]["status"] == "settled"


def test_day_totals_split_unattended_and_unpriced(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        a = _reserve(conn, source="schedule", run_id="s")
        b = _reserve(conn, source="interactive", run_id="i")
        c = _reserve(conn, source="mcp", run_id="m", est_cost=None)       # no price on file
        d = _reserve(conn, source="trigger", run_id="t", local=True, est_cost=0.0)
        _reserve(conn, day="2026-10-11", source="schedule")                  # another day
    led.settle(a, prompt_tokens=100, completion_tokens=0, total_tokens=100, cost_usd=0.10, cost_source="rate_table")
    led.settle(b, prompt_tokens=200, completion_tokens=0, total_tokens=200, cost_usd=0.20, cost_source="provider")
    led.settle(c, prompt_tokens=300, completion_tokens=0, total_tokens=300, cost_usd=None, cost_source="unknown")
    led.settle(d, prompt_tokens=400, completion_tokens=0, total_tokens=400, cost_usd=0.0, cost_source="local")
    t = led.totals_for_day("2026-10-12")
    assert round(t.cost_usd, 4) == 0.30
    assert round(t.unattended_cost_usd, 4) == 0.10
    assert t.unpriced_tokens == 700 and t.tokens == 1000 and t.calls == 4


def test_refused_override_and_note_rows_are_not_calls(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        for status in (LG.REFUSED, LG.OVERRIDE, LG.NOTE):
            BudgetLedger.insert(conn, at=1.0, day="2026-10-12", status=status, source="cli", model="m",
                                local=False, run_id="r1", est_tokens=999, note='{"scope": "daily_cost"}')
        assert BudgetLedger.day_totals(conn, "2026-10-12").calls == 0
        assert BudgetLedger.run_totals(conn, "r1").calls == 0
        assert BudgetLedger.run_overrides(conn, "r1") == {"daily_cost"}


def test_run_totals_count_only_that_run(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        _reserve(conn, run_id="a", est=10)
        _reserve(conn, run_id="a", est=20)
        _reserve(conn, run_id="b", est=40)
    assert led.totals_for_run("a").tokens == 30 and led.totals_for_run("a").calls == 2


def test_state_claim_succeeds_once(tmp_path):
    led = BudgetLedger(tmp_path)
    assert led.state_claim("notified:soft:daily_cost:2026-10-12") is True
    assert led.state_claim("notified:soft:daily_cost:2026-10-12") is False
    assert BudgetLedger(tmp_path).state_claim("notified:soft:daily_cost:2026-10-12") is False
    led.state_set("pause:mcp", {"until": 5})
    assert led.state_prefix("pause:") == {"pause:mcp": {"until": 5}}
    led.state_delete("pause:mcp")
    assert led.state_get("pause:mcp") is None


def test_usage_by_model_groups_finished_calls_for_a_session(tmp_path):
    led = BudgetLedger(tmp_path)
    with led.transaction() as conn:
        x = BudgetLedger.insert(conn, at=1.0, day="d", status=LG.RESERVED, source="interactive", model="m1",
                                local=False, session_id="S", est_tokens=5)
        y = BudgetLedger.insert(conn, at=1.0, day="d", status=LG.RESERVED, source="interactive", model="m1",
                                local=False, session_id="S", est_tokens=5)
        BudgetLedger.insert(conn, at=1.0, day="d", status=LG.RESERVED, source="interactive", model="m1",
                            local=False, session_id="OTHER", est_tokens=5)
    led.settle(x, prompt_tokens=10, completion_tokens=1, total_tokens=11, cost_usd=0.5, cost_source="rate_table")
    led.settle(y, prompt_tokens=20, completion_tokens=2, total_tokens=22, cost_usd=None, cost_source="unknown")
    (row,) = led.usage_by_model(session_id="S")
    assert (row["calls"], row["prompt_tokens"], row["completion_tokens"], row["unpriced_calls"]) == (2, 30, 3, 1)

"""The budget guard (kratos.budget.guard) around every model request: caps per
run / per day / unattended, reservations across processes, the over-cap prompt,
cost sources, local days and the soft limit."""
from __future__ import annotations

import multiprocessing
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

pytest.importorskip("requests")
import requests

from kratos import kratos_config, llm_interface, settings_store
from kratos.budget import guard, ledger as LG, limits as L
from kratos.budget.guard import BudgetExceeded
from kratos.budget.ledger import BudgetLedger
from kratos.run_context import run_scope


class _Resp:
    def __init__(self, status: int, body: dict | None = None):
        self.status_code, self._body = status, body or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code}", response=self)

    def json(self) -> dict:
        return self._body


def _ok(prompt=1000, completion=200, cost=None, content="ok"):
    usage = {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}
    if cost is not None:
        usage["cost"] = cost
    return _Resp(200, {"choices": [{"message": {"content": content}}], "usage": usage})


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A hosted model with a known price, the active data folder in tmp_path,
    the person's day in UTC, and requests.post answering with usage."""
    kratos_config.set_active_data_dir(tmp_path)
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_interface.time.sleep", lambda s: None)
    from kratos.budget import pricing

    pricing.set_rate(tmp_path, "priced-model", 1.0, 2.0, actor="test")   # $1 / $2 per 1M
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz", lambda data_dir=None: timezone.utc)
    replies: list = []

    def post(*a, **kw):
        return replies.pop(0) if replies else _ok()

    monkeypatch.setattr(llm_interface.requests, "post", post)
    return tmp_path, replies


def _set(tmp_path, key, value):
    settings_store.set(key, value, data_dir=tmp_path, actor="test")


def _call(prompt="x" * 35, max_tokens=100):
    return llm_interface._query_openai_compatible(prompt, "", max_tokens)


def _rows(tmp_path, status=None):
    return BudgetLedger(tmp_path).rows(status=status)


# --- recording ---------------------------------------------------------------
def test_a_call_records_one_settled_row_with_its_run(env):
    tmp_path, replies = env
    replies.append(_ok(1000, 200))
    with run_scope("interactive", session_id="S1", target="10.0.0.5") as ctx:
        assert _call() == "ok"
    (row,) = _rows(tmp_path)
    assert row["status"] == "settled" and row["source"] == "interactive" and row["run_id"] == ctx.run_id
    assert (row["session_id"], row["target"], row["model"], row["local"]) == ("S1", "10.0.0.5", "priced-model", 0)
    assert (row["prompt_tokens"], row["completion_tokens"]) == (1000, 200)
    assert row["est_tokens"] == 10 + 100           # ceil(35 / 3.5) + max_tokens
    assert row["cost_source"] == "rate_table" and abs(row["cost_usd"] - (0.001 + 0.0004)) < 1e-12


def test_provider_reported_cost_wins_over_the_rate_table(env):
    tmp_path, replies = env
    replies.append(_ok(1000, 200, cost=0.5))
    with run_scope("cli"):
        _call()
    (row,) = _rows(tmp_path)
    assert (row["cost_usd"], row["cost_source"]) == (0.5, "provider")


def test_unknown_price_is_unknown_cost_and_token_caps_still_apply(env, monkeypatch):
    tmp_path, replies = env
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "no-price-model")
    _set(tmp_path, L.DAILY_TOKENS, 150)
    _set(tmp_path, L.DAILY_COST, 0)       # no money allowed -- irrelevant to an unpriced model
    with run_scope("schedule"):
        _call()                            # 110 reserved -> settles at 1200 (real usage)
        (row,) = _rows(tmp_path)
        assert (row["cost_usd"], row["cost_source"]) == (None, "unknown")
        with pytest.raises(BudgetExceeded) as exc:
            _call()
    assert exc.value.scope == L.SCOPE_DAILY_TOKENS


def test_local_model_costs_nothing_but_token_caps_apply(env, monkeypatch):
    tmp_path, replies = env
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "http://127.0.0.1:11434/v1")
    _set(tmp_path, L.DAILY_COST, 0)
    _set(tmp_path, L.RUN_MODEL_CALLS, 1)
    with run_scope("schedule"):
        _call()
        with pytest.raises(BudgetExceeded) as exc:
            _call()
    assert exc.value.scope == L.SCOPE_RUN_CALLS
    row = _rows(tmp_path, "settled")[0]
    assert (row["local"], row["cost_usd"], row["cost_source"]) == (1, 0.0, "local")


def test_every_retry_passes_the_guard_and_a_failed_request_keeps_a_zero_row(env):
    tmp_path, replies = env
    replies.extend([_Resp(503), _ok(10, 5)])
    with run_scope("interactive"):
        assert _call() == "ok"
    rows = _rows(tmp_path)
    assert [r["status"] for r in rows] == ["settled", "settled"]
    assert (rows[0]["total_tokens"], rows[0]["note"]) == (0, "request failed; no usage reported")
    assert rows[1]["total_tokens"] == 15


def test_a_response_without_usage_is_counted_at_its_estimate_not_free(env):
    tmp_path, replies = env
    replies.append(_Resp(200, {"choices": [{"message": {"content": "hi"}}]}))
    with run_scope("interactive"):
        _call()
    (row,) = _rows(tmp_path)
    assert row["total_tokens"] == row["est_tokens"] == 110


def test_the_query_server_and_in_process_paths_record_too(env, monkeypatch):
    tmp_path, replies = env
    replies.append(_ok(7, 3))
    with run_scope("interactive"):
        assert llm_interface._query_server("p", "s", 50) == "ok"
        server = llm_interface.LLMServer()
        server.is_ready = True
        server._llama = lambda *a, **kw: {"choices": [{"text": " t "}],
                                          "usage": {"prompt_tokens": 4, "completion_tokens": 2}}
        monkeypatch.setattr(llm_interface, "_resolved_backend", lambda: "llama_cpp")
        assert server.infer("p", "s", 50) == "t"
    rows = _rows(tmp_path)
    assert [(r["local"], r["total_tokens"]) for r in rows] == [(1, 10), (1, 6)]


def test_no_run_scope_is_counted_as_unattributed(env):
    tmp_path, _ = env
    _call()
    assert _rows(tmp_path)[0]["source"] == "unattributed"


# --- caps ---------------------------------------------------------------------
def test_run_call_cap_allows_exactly_n_calls(env):
    tmp_path, _ = env
    _set(tmp_path, L.RUN_MODEL_CALLS, 3)
    with run_scope("schedule"):
        for _ in range(3):
            _call()
        with pytest.raises(BudgetExceeded) as exc:
            _call()
    assert (exc.value.scope, exc.value.limit, exc.value.spent) == (L.SCOPE_RUN_CALLS, 3, 3)
    assert len(_rows(tmp_path, "refused")) == 1
    with run_scope("schedule"):   # a new run starts from zero
        _call()


def test_run_token_cap_exactly_at_passes_one_over_refuses(env):
    tmp_path, replies = env
    _set(tmp_path, L.RUN_TOKENS, 110)   # one call's worst case: 10 + 100
    with run_scope("schedule"):
        replies.append(_ok(0, 0))           # settles at 0 tokens
        _call()                             # 0 + 110 <= 110
        _set(tmp_path, L.RUN_TOKENS, 109)   # applies from the next call
        with pytest.raises(BudgetExceeded) as exc:
            _call()                         # 0 + 110 > 109
    assert exc.value.scope == L.SCOPE_RUN_TOKENS


def test_daily_cost_cap_boundary(env):
    tmp_path, replies = env
    # worst case of one call: 10 prompt tokens @ $1/M + 100 completion @ $2/M = $0.00021
    _set(tmp_path, L.DAILY_COST, 0.00021)
    with run_scope("interactive"):
        replies.append(_ok(0, 0))
        _call()                               # exactly at: allowed
        replies.append(_ok(0, 0))
        _call()                               # spent 0 again (settled at 0)
    _set(tmp_path, L.DAILY_COST, 0.0002)
    with run_scope("schedule"), pytest.raises(BudgetExceeded) as exc:
        _call()                               # one over
    assert exc.value.scope == L.SCOPE_DAILY_COST


def test_zero_refuses_every_priced_call(env):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)
    with run_scope("trigger"), pytest.raises(BudgetExceeded):
        _call()
    assert _rows(tmp_path, "settled") == []


def test_unattended_cap_applies_only_to_unattended_sources(env):
    tmp_path, replies = env
    _set(tmp_path, L.UNATTENDED_DAILY_COST, 0.001)
    replies.append(_ok(1000, 0))                     # $0.001
    with run_scope("mcp"):
        _call()
        with pytest.raises(BudgetExceeded) as exc:
            _call()
    assert exc.value.scope == L.SCOPE_UNATTENDED_COST
    with run_scope("interactive"):
        _call()                                      # attended: only the daily cap applies


def test_caps_survive_a_restart(env):
    tmp_path, _ = env
    _set(tmp_path, L.UNATTENDED_DAILY_COST, 0.00021)
    with run_scope("schedule"):
        _call()                      # settles at $0.0014
    from kratos.storage import migrations

    migrations._migrated.clear()     # as if a fresh process opened the same database
    guard._migrated.clear()
    with run_scope("schedule"), pytest.raises(BudgetExceeded):
        _call()


def test_settings_change_applies_to_the_next_call(env):
    tmp_path, _ = env
    with run_scope("schedule"):
        _call()
        _set(tmp_path, L.RUN_MODEL_CALLS, 1)
        with pytest.raises(BudgetExceeded):
            _call()
        _set(tmp_path, L.RUN_MODEL_CALLS, 5)
        _call()


def test_budget_refusal_is_never_reported_as_model_unavailable(env, monkeypatch):
    tmp_path, _ = env
    monkeypatch.setattr(llm_interface, "_running_backend", lambda: "openai_compatible")
    _set(tmp_path, L.DAILY_COST, 0)
    with run_scope("interactive"), pytest.raises(BudgetExceeded):
        llm_interface.agent_chat("s", "u")
    with run_scope("interactive"), pytest.raises(BudgetExceeded):
        llm_interface.analyze_findings("bundle")


# --- interactive over-cap prompt -----------------------------------------------
@pytest.mark.parametrize("answer", [False, None, "y", "yes", 1])
def test_anything_but_true_is_no(env, answer):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)
    guard.set_prompt_provider(lambda q: answer, actor="test")
    with run_scope("interactive"), pytest.raises(BudgetExceeded):
        _call()
    assert _rows(tmp_path, "override") == []


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt, RuntimeError])
def test_an_interrupted_or_broken_prompt_is_no(env, exc):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)

    def provider(q):
        raise exc()

    guard.set_prompt_provider(provider, actor="test")
    with run_scope("interactive"), pytest.raises(BudgetExceeded):
        _call()


def test_no_provider_is_no(env):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)
    guard.set_prompt_provider(None)
    with run_scope("cli"), pytest.raises(BudgetExceeded):
        _call()


def test_yes_overrides_that_cap_for_this_run_only_and_records_who(env):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)
    asked: list = []
    guard.set_prompt_provider(lambda q: asked.append(q) or True, actor="tui")
    with run_scope("interactive") as ctx:
        _call()
        _call()                                   # same run: not asked again
    assert len(asked) == 1 and asked[0].scope == L.SCOPE_DAILY_COST
    assert "today's model budget" in asked[0].text and "Continue this run anyway?" in asked[0].text
    (override,) = _rows(tmp_path, "override")
    assert override["run_id"] == ctx.run_id and "via tui" in override["note"] and '"scope": "daily_cost"' in override["note"]
    assert len(_rows(tmp_path, "settled")) == 2
    with run_scope("interactive"):
        _call()                                   # a new run is asked again
    assert len(asked) == 2


def test_unattended_runs_are_never_asked(env):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)
    asked: list = []
    guard.set_prompt_provider(lambda q: asked.append(q) or True, actor="tui")
    for source in ("schedule", "trigger", "mcp", "web"):
        with run_scope(source), pytest.raises(BudgetExceeded):
            _call()
    assert asked == []


# --- local day ------------------------------------------------------------------
def test_local_day_in_a_non_utc_zone(monkeypatch):
    helsinki = ZoneInfo("Europe/Helsinki")
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz", lambda data_dir=None: helsinki)
    # 21:30 UTC on Oct 12 is 00:30 on Oct 13 in Helsinki (UTC+3, summer time)
    assert guard.local_day(datetime(2026, 10, 12, 21, 30, tzinfo=timezone.utc).timestamp()) == "2026-10-13"
    assert guard.local_day(datetime(2026, 10, 12, 20, 59, tzinfo=timezone.utc).timestamp()) == "2026-10-12"


@pytest.mark.parametrize("utc,expected", [
    # spring forward, Sunday 2026-03-29: local 03:00 -> 04:00 (UTC+2 -> UTC+3)
    ((2026, 3, 28, 21, 59), "2026-03-28"),   # 23:59 local, UTC+2
    ((2026, 3, 28, 22, 0), "2026-03-29"),    # 00:00 local
    ((2026, 3, 29, 20, 59), "2026-03-29"),   # 23:59 local, now UTC+3 (a 23-hour day)
    ((2026, 3, 29, 21, 0), "2026-03-30"),
    # fall back, Sunday 2026-10-25: local 04:00 -> 03:00 (UTC+3 -> UTC+2)
    ((2026, 10, 24, 20, 59), "2026-10-24"),
    ((2026, 10, 24, 21, 0), "2026-10-25"),   # 00:00 local, UTC+3
    ((2026, 10, 25, 21, 59), "2026-10-25"),  # 23:59 local, now UTC+2 (a 25-hour day)
    ((2026, 10, 25, 22, 0), "2026-10-26"),
])
def test_dst_change_days(monkeypatch, utc, expected):
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz",
                        lambda data_dir=None: ZoneInfo("Europe/Helsinki"))
    assert guard.local_day(datetime(*utc, tzinfo=timezone.utc).timestamp()) == expected


def test_daily_total_resets_on_the_local_day_boundary(env, monkeypatch):
    tmp_path, replies = env
    monkeypatch.setattr("kratos.utils.timeutil.resolve_display_tz",
                        lambda data_dir=None: ZoneInfo("Asia/Dhaka"))   # UTC+6
    _set(tmp_path, L.UNATTENDED_DAILY_COST, 0.001)
    late = datetime(2026, 10, 12, 17, 59, tzinfo=timezone.utc).timestamp()     # 23:59 in Dhaka
    monkeypatch.setattr(guard.time, "time", lambda: late)
    replies.append(_ok(1000, 0))
    with run_scope("schedule"):
        _call()
        with pytest.raises(BudgetExceeded):
            _call()
    monkeypatch.setattr(guard.time, "time", lambda: late + 120)                  # 00:01 next day in Dhaka
    with run_scope("schedule"):
        _call()
    assert [r["day"] for r in _rows(tmp_path, "settled")] == ["2026-10-12", "2026-10-13"]


# --- reservations ------------------------------------------------------------------
def test_a_crashed_reservation_expires_and_the_day_total_is_right(env, monkeypatch):
    tmp_path, _ = env
    _set(tmp_path, L.UNATTENDED_DAILY_COST, 0.0003)
    now = time.time()
    monkeypatch.setattr(guard.time, "time", lambda: now)
    with run_scope("schedule"):
        guard.before_call(est_prompt_tokens=10, max_completion_tokens=100, model="priced-model", local=False)
        with pytest.raises(BudgetExceeded):          # the open reservation ($0.00021) blocks a second
            guard.before_call(est_prompt_tokens=10, max_completion_tokens=100, model="priced-model", local=False)
    monkeypatch.setattr(guard.time, "time", lambda: now + LG.RESERVATION_TTL_SECONDS + 1)
    with run_scope("schedule"):
        guard.before_call(est_prompt_tokens=10, max_completion_tokens=100, model="priced-model", local=False)
    statuses = [r["status"] for r in _rows(tmp_path)]
    assert statuses == ["expired", "refused", "reserved"]


def _reserve_many(data_dir: str, attempts: int, results) -> None:
    """In a separate process: reserve local calls of 1,000 tokens until refused."""
    from kratos import kratos_config as kc
    from kratos.budget import guard as g
    from kratos.run_context import run_scope as scope

    kc.set_active_data_dir(data_dir)
    ok = refused = 0
    for _ in range(attempts):
        with scope("schedule"):
            try:
                g.before_call(est_prompt_tokens=0, max_completion_tokens=1000, model="m", local=True)
                ok += 1
            except g.BudgetExceeded:
                refused += 1
    results.put((ok, refused))


def test_concurrent_processes_never_exceed_the_cap(tmp_path):
    settings_store.set(L.DAILY_TOKENS, 25_000, data_dir=tmp_path, actor="test")
    BudgetLedger(tmp_path)
    ctx = multiprocessing.get_context("fork")
    results = ctx.Queue()
    procs = [ctx.Process(target=_reserve_many, args=(str(tmp_path), 20, results)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    outcomes = [results.get(timeout=5) for _ in procs]
    assert sum(ok for ok, _ in outcomes) == 25
    assert sum(r for _, r in outcomes) == 55
    calls = BudgetLedger(tmp_path).rows(status="reserved")
    assert len(calls) == 25 and sum(r["est_tokens"] for r in calls) == 25_000


# --- soft limit ----------------------------------------------------------------------
def test_soft_limit_warns_once_per_scope_per_day_across_processes(env, _budget_isolated):
    tmp_path, replies = env
    sent = _budget_isolated
    _set(tmp_path, L.DAILY_COST, 0.01)
    _set(tmp_path, L.SOFT_PERCENT, 50)
    notices: list = []
    guard.set_notice_listener(lambda text, level: notices.append(text))
    replies.extend([_ok(5000, 0), _ok(1000, 0)])         # $0.005 = 50%, then $0.006
    with run_scope("interactive"):
        _call()
        _call()
    from kratos.storage import migrations

    migrations._migrated.clear()                         # a second process, same database
    replies.append(_ok(1000, 0))
    with run_scope("interactive"):
        _call()
    daily = [m for m, _sev in sent if "Today's model budget" in m]
    assert len(daily) == 1 and "50% used" in daily[0] and "warned at 50%" in daily[0] and sent[0][1] == "info"
    assert sum("Today's model budget" in n for n in notices) == 1


def test_hard_limit_notifies_once_per_day(env, _budget_isolated):
    tmp_path, _ = env
    _set(tmp_path, L.DAILY_COST, 0)
    for _ in range(3):
        with run_scope("schedule"), pytest.raises(BudgetExceeded):
            _call()
    hard = [(m, s) for m, s in _budget_isolated if "stopped a model call" in m]
    assert len(hard) == 1 and hard[0][1] == "warning"
    for message, _ in _budget_isolated:
        assert "x" * 35 not in message      # never the prompt


# --- precheck ---------------------------------------------------------------------------
def test_precheck_refuses_an_unattended_run_already_at_its_cap(env, monkeypatch):
    tmp_path, _ = env
    monkeypatch.setattr("kratos.llm_config.get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_config._active_backend_is_local", lambda: False)
    assert guard.precheck("schedule") is None
    _set(tmp_path, L.UNATTENDED_DAILY_COST, 0)
    refusal = guard.precheck("schedule")
    assert refusal is not None and refusal.scope == L.SCOPE_UNATTENDED_COST
    (row,) = _rows(tmp_path, "refused")
    assert '"precheck": true' in row["note"] and row["source"] == "schedule"

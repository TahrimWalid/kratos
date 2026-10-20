"""The spending limits people set (Settings -> Budget), as `budget.*` settings.

Every limit lives in `app_settings` (kratos.settings_store) so the TUI,
`kratos scheduled-run` and `kratos mcp-serve` read the same value, and a change
applies from the next model call -- `read()` is called on every check.

A limit of 0 means "no spending allowed" for that scope. There is no "unlimited"
value: someone who wants more sets a large number, on purpose.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

RUN_TOKENS = "budget.run_tokens"
RUN_MODEL_CALLS = "budget.run_model_calls"
DAILY_COST = "budget.daily_cost_usd"
DAILY_TOKENS = "budget.daily_tokens"
UNATTENDED_DAILY_COST = "budget.unattended_daily_cost_usd"
TRIGGER_FIRES_PER_DAY = "budget.trigger_fires_per_day"
TRIGGER_INVESTIGATIONS = "budget.trigger_investigations_allowed"
SOFT_PERCENT = "budget.soft_limit_percent"
BREAKER_FAILURES = "budget.breaker_failures"
BREAKER_WINDOW = "budget.breaker_window_minutes"
BREAKER_PAUSE = "budget.breaker_pause_minutes"

# Hard-limit scopes (the `scope` of BudgetExceeded, ledger notes, budget_state keys).
SCOPE_RUN_TOKENS = "run_tokens"
SCOPE_RUN_CALLS = "run_model_calls"
SCOPE_DAILY_COST = "daily_cost"
SCOPE_DAILY_TOKENS = "daily_tokens"
SCOPE_UNATTENDED_COST = "unattended_daily_cost"
SCOPE_PAUSED = "paused"

SCOPE_SETTING = {
    SCOPE_RUN_TOKENS: RUN_TOKENS,
    SCOPE_RUN_CALLS: RUN_MODEL_CALLS,
    SCOPE_DAILY_COST: DAILY_COST,
    SCOPE_DAILY_TOKENS: DAILY_TOKENS,
    SCOPE_UNATTENDED_COST: UNATTENDED_DAILY_COST,
}

# Plain names for messages ("this would go over <label>").
SCOPE_LABEL = {
    SCOPE_RUN_TOKENS: "this run's token limit",
    SCOPE_RUN_CALLS: "this run's model-call limit",
    SCOPE_DAILY_COST: "today's model budget",
    SCOPE_DAILY_TOKENS: "today's token limit (local or unpriced models)",
    SCOPE_UNATTENDED_COST: "today's budget for unattended runs (schedules, triggers, MCP, chat clients)",
    SCOPE_PAUSED: "a pause after repeated failures",
}

_MAX_TOKENS_LIMIT = 10_000_000_000
_MAX_CALLS_LIMIT = 100_000
_MAX_COST_LIMIT = 100_000.0


def _whole(lo: int, hi: int, what: str):
    def check(value: Any) -> int:
        if isinstance(value, bool):
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}")
        if isinstance(value, str):
            value = value.strip().replace(",", "").replace("_", "")
            if not value.isdigit():
                raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}")
        try:
            n = int(value)
        except (TypeError, ValueError):
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}") from None
        if isinstance(value, float) and n != value:
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}")
        if not lo <= n <= hi:
            raise SettingError(f"a whole number of {what}, {lo:,}-{hi:,}")
        return n
    return check


def _dollars(value: Any) -> float:
    if isinstance(value, bool):
        raise SettingError(f"an amount in US dollars, 0-{_MAX_COST_LIMIT:,.0f}")
    if isinstance(value, str):
        value = value.strip().lstrip("$").replace(",", "")
    try:
        amount = float(value)
    except (TypeError, ValueError):
        raise SettingError(f"an amount in US dollars, 0-{_MAX_COST_LIMIT:,.0f}") from None
    if not math.isfinite(amount) or not 0 <= amount <= _MAX_COST_LIMIT:
        raise SettingError(f"an amount in US dollars, 0-{_MAX_COST_LIMIT:,.0f}")
    return amount


def _on_off(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("on", "yes", "true", "1", "allowed"):
        return True
    if text in ("off", "no", "false", "0", "not allowed"):
        return False
    raise SettingError("on or off")


# Defaults: see the 0.4 Handoff for the measurements behind them.
_SPECS = (
    SettingSpec(RUN_TOKENS, 300_000, _whole(0, _MAX_TOKENS_LIMIT, "tokens"),
                "The most tokens one run (an investigation, a chat turn, a build) may use."),
    SettingSpec(RUN_MODEL_CALLS, 40, _whole(0, _MAX_CALLS_LIMIT, "model calls"),
                "The most model calls one run may make -- stops a run that loops."),
    SettingSpec(DAILY_COST, 2.00, _dollars,
                "The most Kratos may spend on the model per day, everything included (estimated, USD)."),
    SettingSpec(DAILY_TOKENS, 3_000_000, _whole(0, _MAX_TOKENS_LIMIT, "tokens"),
                "The most tokens per day on models with no price on file or served from this machine."),
    SettingSpec(UNATTENDED_DAILY_COST, 0.50, _dollars,
                "The most schedules, triggers, MCP and chat clients may spend per day, with nobody watching (USD)."),
    SettingSpec(TRIGGER_FIRES_PER_DAY, 10, _whole(0, 10_000, "fires"),
                "How many times one trigger may fire per day; after that it waits for the next day."),
    SettingSpec(TRIGGER_INVESTIGATIONS, False, _on_off,
                "Whether a trigger may start a model investigation (each one costs money) or only notify."),
    SettingSpec(SOFT_PERCENT, 80, _whole(1, 100, "percent"),
                "Warn once when this share of any limit is used."),
    SettingSpec(BREAKER_FAILURES, 5, _whole(1, 1_000, "failed runs"),
                "Pause an unattended source after this many failed or looping runs ..."),
    SettingSpec(BREAKER_WINDOW, 60, _whole(1, 10_080, "minutes"),
                "... within this many minutes."),
    SettingSpec(BREAKER_PAUSE, 120, _whole(1, 10_080, "minutes"),
                "How long a paused source waits before running again (or resume it here)."),
)
for _spec in _SPECS:
    settings_store.register(_spec)

KEYS = tuple(s.key for s in _SPECS)


@dataclass(frozen=True)
class Limits:
    run_tokens: int
    run_model_calls: int
    daily_cost_usd: float
    daily_tokens: int
    unattended_daily_cost_usd: float
    trigger_fires_per_day: int
    trigger_investigations_allowed: bool
    soft_limit_percent: int
    breaker_failures: int
    breaker_window_minutes: int
    breaker_pause_minutes: int

    def for_scope(self, scope: str) -> float:
        return {
            SCOPE_RUN_TOKENS: self.run_tokens,
            SCOPE_RUN_CALLS: self.run_model_calls,
            SCOPE_DAILY_COST: self.daily_cost_usd,
            SCOPE_DAILY_TOKENS: self.daily_tokens,
            SCOPE_UNATTENDED_COST: self.unattended_daily_cost_usd,
        }[scope]


def read(data_dir: Path) -> Limits:
    """Every limit, freshly read (a Settings change applies to the next call)."""
    get = lambda key: settings_store.get(key, data_dir=data_dir)  # noqa: E731
    return Limits(
        run_tokens=get(RUN_TOKENS),
        run_model_calls=get(RUN_MODEL_CALLS),
        daily_cost_usd=get(DAILY_COST),
        daily_tokens=get(DAILY_TOKENS),
        unattended_daily_cost_usd=get(UNATTENDED_DAILY_COST),
        trigger_fires_per_day=get(TRIGGER_FIRES_PER_DAY),
        trigger_investigations_allowed=get(TRIGGER_INVESTIGATIONS),
        soft_limit_percent=get(SOFT_PERCENT),
        breaker_failures=get(BREAKER_FAILURES),
        breaker_window_minutes=get(BREAKER_WINDOW),
        breaker_pause_minutes=get(BREAKER_PAUSE),
    )


def is_money_scope(scope: str) -> bool:
    return scope in (SCOPE_DAILY_COST, SCOPE_UNATTENDED_COST)


def format_amount(scope: str, value: float) -> str:
    if is_money_scope(scope):
        return f"${value:,.2f}" if value == 0 or abs(value) >= 0.01 else f"${value:,.4f}"
    unit = "calls" if scope == SCOPE_RUN_CALLS else "tokens"
    return f"{int(value):,} {unit}"

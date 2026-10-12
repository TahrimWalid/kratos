"""Today's model spending against the limits, for the places that show it:
Settings -> Budget, /usage, /doctor and the session footer. Read-only."""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kratos.budget import breaker
from kratos.budget import limits as L
from kratos.budget.guard import local_day
from kratos.budget.ledger import BudgetLedger, DayTotals

NEAR_SHARE = 0.90   # "within 10%" of a hard limit -> the footer mentions it


@dataclass(frozen=True)
class ScopeStatus:
    scope: str
    label: str
    spent: float
    limit: float

    @property
    def share(self) -> float:
        if self.limit <= 0:
            return 1.0
        return self.spent / self.limit

    @property
    def text(self) -> str:
        return f"{L.format_amount(self.scope, self.spent)} of {L.format_amount(self.scope, self.limit)}"

    @property
    def remaining_text(self) -> str:
        left = max(0.0, self.limit - self.spent)
        return L.format_amount(self.scope, left) + " left"


@dataclass(frozen=True)
class Today:
    day: str
    totals: DayTotals
    limits: L.Limits
    scopes: tuple[ScopeStatus, ...]       # the three daily hard limits
    pauses: tuple[dict[str, Any], ...]


def today(data_dir: Path, now: float | None = None) -> Today:
    now = time.time() if now is None else now
    day = local_day(now, data_dir)
    totals = BudgetLedger(data_dir).totals_for_day(day)
    lim = L.read(data_dir)
    scopes = (
        ScopeStatus(L.SCOPE_DAILY_COST, "Today, everything", totals.cost_usd, lim.daily_cost_usd),
        ScopeStatus(L.SCOPE_UNATTENDED_COST, "Today, unattended (schedules, triggers, MCP)",
                    totals.unattended_cost_usd, lim.unattended_daily_cost_usd),
        ScopeStatus(L.SCOPE_DAILY_TOKENS, "Today, local or unpriced models", totals.unpriced_tokens, lim.daily_tokens),
    )
    return Today(day, totals, lim, scopes, tuple(breaker.list_pauses(data_dir, now)))


def near_limit(data_dir: Path) -> str | None:
    """A short footer note when a daily hard limit is within 10% (or used up),
    else None -- quiet otherwise."""
    t = today(data_dir)
    spending = [s for s in t.scopes if s.spent > 0]   # a limit nothing spends against isn't "near"
    if not spending:
        return None
    worst = max(spending, key=lambda s: s.share)
    if worst.share >= 1.0:
        return f"budget: {worst.label.lower()} used up"
    if worst.share >= NEAR_SHARE:
        return f"budget: {worst.text} ({worst.label.lower()})"
    return None


def doctor_row(data_dir: Path) -> tuple[str, str]:
    """(status, detail) for /doctor's Budget row."""
    t = today(data_dir)
    parts = [f"today {L.format_amount(L.SCOPE_DAILY_COST, t.totals.cost_usd)} of "
             f"{L.format_amount(L.SCOPE_DAILY_COST, t.limits.daily_cost_usd)}",
             f"unattended {L.format_amount(L.SCOPE_UNATTENDED_COST, t.totals.unattended_cost_usd)} of "
             f"{L.format_amount(L.SCOPE_UNATTENDED_COST, t.limits.unattended_daily_cost_usd)}",
             f"{t.totals.calls} model call{'s' if t.totals.calls != 1 else ''}",
             f"per run: {t.limits.run_model_calls} calls / {t.limits.run_tokens:,} tokens"]
    if t.pauses:
        parts.append("paused: " + ", ".join(p["key"] for p in t.pauses))
    status = "info"
    if t.pauses or any(s.share >= 1.0 for s in t.scopes):
        status = "warn"
    elif any(s.share >= NEAR_SHARE for s in t.scopes):
        status = "warn"
    return status, "; ".join(parts)

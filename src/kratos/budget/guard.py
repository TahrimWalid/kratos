"""The budget check around every model request.

`kratos.llm_interface._metered_call` -- the only place a request is sent to a
model -- calls `before_call` first and `after_call` afterwards. Nothing else in
Kratos calls the model, and this module never does either (§3.10).

`before_call` reads the limits fresh (a Settings change applies to the next
call) and, inside one `BEGIN IMMEDIATE` transaction, checks in order:

  1. the source is paused by the circuit breaker   (unattended sources only)
  2. this run's token cap        -- run tokens so far + this call's worst case
  3. this run's model-call cap
  4. today's cost cap            -- priced calls
  5. today's token cap           -- local calls and calls with no price on file
  6. today's unattended cost cap -- schedule / trigger / mcp / web

then writes a `reserved` row for this call's worst case. At a hard limit an
unattended run gets `BudgetExceeded`; an attended one is asked (the prompt
provider: a TUI modal, the CLI's `input()`), default no -- an unanswered or
interrupted prompt, a broken provider or no provider at all means no. "Yes"
records an `override` row and lets THIS run go over that one cap.

`after_call` turns the reservation into what the call actually used and warns
(once per scope per day, across processes) at the soft limit.
"""
from __future__ import annotations

import getpass
import json
import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from kratos import run_context
from kratos.budget import limits as L
from kratos.budget import pricing
from kratos.budget.ledger import NOTE, OVERRIDE, REFUSED, RESERVED, BudgetLedger
from kratos.run_context import UNATTENDED

logger = logging.getLogger(__name__)

UNATTRIBUTED = "unattributed"
CHARS_PER_TOKEN = 3.5
_EPS = 1e-9

# Run-level caps; the rest are per local day.
RUN_SCOPES = (L.SCOPE_RUN_TOKENS, L.SCOPE_RUN_CALLS)
DAY_SCOPES = (L.SCOPE_DAILY_COST, L.SCOPE_DAILY_TOKENS, L.SCOPE_UNATTENDED_COST)


class BudgetExceeded(Exception):
    """A model call refused by a spending limit (or a breaker pause). Its text is
    the plain message a person sees."""

    def __init__(self, scope: str, limit: float, spent: float, *, source: str,
                 detail: str | None = None) -> None:
        self.scope = scope
        self.limit = limit
        self.spent = spent
        self.source = source
        self.detail = detail
        super().__init__(self.user_message())

    def user_message(self) -> str:
        if self.scope == L.SCOPE_PAUSED:
            return (f"Model use by {self.source} runs is paused{(' ' + self.detail) if self.detail else ''} "
                    "-- resume it in Settings -> Budget.")
        label = L.SCOPE_LABEL.get(self.scope, self.scope)
        return (f"Stopped by budget: {label} is used up ({L.format_amount(self.scope, self.spent)} of "
                f"{L.format_amount(self.scope, self.limit)}). Change it in Settings -> Budget.")

    def as_dict(self) -> dict[str, Any]:
        return {"scope": self.scope, "limit": self.limit, "spent": self.spent, "source": self.source,
                "message": self.user_message()}


@dataclass(frozen=True)
class OverCapQuestion:
    """What an attended run is asked at a hard limit."""
    scope: str
    limit: float
    spent: float
    source: str

    @property
    def text(self) -> str:
        label = L.SCOPE_LABEL.get(self.scope, self.scope)
        return (f"This would go over {label} ({L.format_amount(self.scope, self.limit)}, used "
                f"{L.format_amount(self.scope, self.spent)}). Continue this run anyway?")


@dataclass
class Reservation:
    row_id: int
    ledger: BudgetLedger
    model: str
    local: bool
    est_tokens: int
    source: str
    run_id: str | None
    settled: bool = False
    cost_usd: float | None = None      # what after_call recorded (the run record reads it)
    cost_source: str | None = None


# --- hooks (installed by the front end) ------------------------------------
_prompt_provider: Callable[[OverCapQuestion], bool] | None = None
_prompt_actor = ""
_notice_listener: Callable[[str, str], None] | None = None
_notifier: Callable[[str, str], Any] | None = None
_warned_unattributed = False


def set_prompt_provider(provider: Callable[[OverCapQuestion], bool] | None, *, actor: str = "") -> None:
    """Install (or clear) who answers "go over the limit for this run?". It must
    return True only for an explicit yes."""
    global _prompt_provider, _prompt_actor
    _prompt_provider = provider
    _prompt_actor = actor if provider is not None else ""


def prompt_provider() -> Callable[[OverCapQuestion], bool] | None:
    return _prompt_provider


def set_notice_listener(listener: Callable[[str, str], None] | None) -> None:
    """Called with (text, level) for budget warnings worth showing a person
    right now (soft limit reached, a source keeps failing). level: info|warning."""
    global _notice_listener
    _notice_listener = listener


def notice_listener() -> Callable[[str, str], None] | None:
    return _notice_listener


def set_notifier(notifier: Callable[[str, str], Any] | None) -> None:
    """Replace the notification sender (tests). None restores the default."""
    global _notifier
    _notifier = notifier


def notify(message: str, severity: str) -> Any:
    """Send a budget notification. Never raises; never includes prompts,
    findings or keys (callers pass fixed wording plus numbers)."""
    sender = _notifier
    if sender is None:
        from kratos.agent.notify import send_notification as sender
    try:
        return sender(message, severity)
    except Exception as e:  # noqa: BLE001 -- a notification must never break a model call
        logger.warning("budget notification failed: %s", e)
        return None


def _notice(text: str, level: str = "info") -> None:
    listener = _notice_listener
    if listener is None:
        return
    try:
        listener(text, level)
    except Exception:  # noqa: BLE001 -- a UI hiccup must never break a model call
        pass


# --- helpers -----------------------------------------------------------------
def data_dir() -> Path:
    """The data folder budget rows go to: this process's active one (set by the
    CLI, the TUI and the MCP server at start), else the default data folder."""
    from kratos import kratos_config

    return kratos_config.get_active_data_dir() or _fallback_data_dir()


def _fallback_data_dir() -> Path:
    from kratos import paths

    return paths.default_data_dir()


def local_day(epoch: float, data_dir_: Path | None = None) -> str:
    """The person's local calendar day (YYYY-MM-DD) for a UTC instant, in the zone
    utils/timeutil resolves (DST-safe: zoneinfo does the arithmetic)."""
    from kratos.utils import timeutil

    tz = timeutil.resolve_display_tz(data_dir_)
    return datetime.fromtimestamp(epoch, tz).date().isoformat()


def estimate_prompt_tokens(*texts: str) -> int:
    """Worst-case-ish prompt size: characters / 3.5, rounded up (§3.4)."""
    return int(math.ceil(sum(len(t or "") for t in texts) / CHARS_PER_TOKEN))


def _attended(source: str) -> bool:
    return source not in UNATTENDED and source != UNATTRIBUTED


def _context() -> tuple[str, Any]:
    global _warned_unattributed
    ctx = run_context.current()
    if ctx is None:
        if not _warned_unattributed:
            _warned_unattributed = True
            logger.warning("a model call ran outside any run scope; counted as 'unattributed' "
                           "against the daily total (this is a bug -- every entry point opens a run_scope)")
        return UNATTRIBUTED, None
    return ctx.source, ctx


def _approver() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "unknown"
    return f"{user} via {_prompt_actor or 'prompt'}"


def terminal_prompt(question: OverCapQuestion) -> bool:
    """The command line's over-cap prompt: an explicit `y`/`yes` continues;
    Enter, anything else, end of input, Ctrl+C -- or no terminal at all (cron,
    a pipe) -- is no."""
    import sys

    if not sys.stdin or not sys.stdin.isatty():
        return False
    try:
        from kratos.agent.console import stop_active_spinner

        stop_active_spinner()  # a live spinner would redraw over the prompt and eat keystrokes
    except Exception:  # noqa: BLE001
        pass
    print(question.text, file=sys.stderr)
    try:
        answer = input("y = yes · anything else = no: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in ("y", "yes")


def _ask(question: OverCapQuestion) -> bool:
    provider = _prompt_provider
    if provider is None:
        return False
    try:
        return provider(question) is True
    except (EOFError, KeyboardInterrupt):
        return False
    except Exception:  # noqa: BLE001 -- a broken prompt fails safe: no
        return False


def _first_exceeded(conn: Any, lim: L.Limits, *, source: str, run_id: str | None, overrides: set[str],
                    day: str, est_tokens: int, est_cost: float | None, local: bool
                    ) -> tuple[str, float, float] | None:
    """(scope, limit, spent so far) for the first cap this call would cross."""
    if run_id is not None:
        run = BudgetLedger.run_totals(conn, run_id)
        if L.SCOPE_RUN_TOKENS not in overrides and run.tokens + est_tokens > lim.run_tokens:
            return L.SCOPE_RUN_TOKENS, lim.run_tokens, run.tokens
        if L.SCOPE_RUN_CALLS not in overrides and run.calls + 1 > lim.run_model_calls:
            return L.SCOPE_RUN_CALLS, lim.run_model_calls, run.calls
    totals = BudgetLedger.day_totals(conn, day)
    priced = not local and est_cost is not None
    if priced and L.SCOPE_DAILY_COST not in overrides and totals.cost_usd + est_cost > lim.daily_cost_usd + _EPS:
        return L.SCOPE_DAILY_COST, lim.daily_cost_usd, totals.cost_usd
    if not priced and L.SCOPE_DAILY_TOKENS not in overrides and \
            totals.unpriced_tokens + est_tokens > lim.daily_tokens:
        return L.SCOPE_DAILY_TOKENS, lim.daily_tokens, totals.unpriced_tokens
    if priced and source in UNATTENDED and L.SCOPE_UNATTENDED_COST not in overrides and \
            totals.unattended_cost_usd + est_cost > lim.unattended_daily_cost_usd + _EPS:
        return L.SCOPE_UNATTENDED_COST, lim.unattended_daily_cost_usd, totals.unattended_cost_usd
    return None


def _row_fields(source: str, ctx: Any) -> dict[str, Any]:
    if ctx is None:
        return {"source": source}
    return {"source": source, "run_id": ctx.run_id, "parent_run_id": ctx.parent_run_id,
            "session_id": ctx.session_id, "target": ctx.target}


def _hard_limit_notification(ledger: BudgetLedger, scope: str, limit: float, spent: float, day: str) -> None:
    """One notification per day-scope per day when a hard limit first stops a call."""
    if scope not in DAY_SCOPES:
        return
    if ledger.state_claim(f"notified:hard:{scope}:{day}"):
        label = L.SCOPE_LABEL.get(scope, scope)
        notify(f"Kratos reached a spending limit: {label} is used up ({L.format_amount(scope, spent)} of "
               f"{L.format_amount(scope, limit)}). Runs that need the model stop until it resets tomorrow "
               "or you change it in Settings -> Budget.", "warning")


# --- the guard ---------------------------------------------------------------
def before_call(*, est_prompt_tokens: int, max_completion_tokens: int, model: str, local: bool,
                data_dir_: Path | None = None) -> Reservation:
    """Check every cap and reserve this call's worst case. Raises BudgetExceeded."""
    from kratos.budget import breaker

    dd = Path(data_dir_) if data_dir_ is not None else data_dir()
    ledger = BudgetLedger(dd)
    ensure_upgrade_migration(dd, ledger)
    source, ctx = _context()
    run_id = ctx.run_id if ctx is not None else None
    est_tokens = max(0, int(est_prompt_tokens)) + max(0, int(max_completion_tokens))
    est_cost = 0.0 if local else pricing.tokens_cost(
        pricing.rate_for(model, dd), est_prompt_tokens, max_completion_tokens)
    fields = _row_fields(source, ctx)

    if not _attended(source):
        pause = breaker.active_pause(ledger, breaker.key_for(source))
        if pause is not None:
            now = time.time()
            with ledger.transaction() as conn:
                ledger.insert(conn, at=now, day=local_day(now, dd), status=REFUSED, model=model, local=local,
                              est_tokens=est_tokens, est_cost_usd=est_cost,
                              note=json.dumps({"scope": L.SCOPE_PAUSED}), **fields)
            raise BudgetExceeded(L.SCOPE_PAUSED, 0, 0, source=source, detail=breaker.pause_text(pause))

    while True:
        lim = L.read(dd)
        now = time.time()
        day = local_day(now, dd)
        with ledger.transaction() as conn:
            ledger.expire_stale(conn, now)
            overrides = BudgetLedger.run_overrides(conn, run_id) if run_id else set()
            over = _first_exceeded(conn, lim, source=source, run_id=run_id, overrides=overrides, day=day,
                                   est_tokens=est_tokens, est_cost=est_cost, local=local)
            if over is None:
                row_id = ledger.insert(conn, at=now, day=day, status=RESERVED, model=model, local=local,
                                       est_tokens=est_tokens, est_cost_usd=est_cost,
                                       cost_source=pricing.COST_LOCAL if local else None, **fields)
                return Reservation(row_id, ledger, model, local, est_tokens, source, run_id)
        scope, limit, spent = over
        question = OverCapQuestion(scope, limit, spent, source)
        if _attended(source) and _ask(question):
            with ledger.transaction() as conn:
                ledger.insert(conn, at=time.time(), day=day, status=OVERRIDE, model=model, local=local,
                              note=json.dumps({"scope": scope, "limit": limit, "spent": spent,
                                               "approved_by": _approver()}), **fields)
            continue  # this cap is now overridden for this run; check the others
        with ledger.transaction() as conn:
            ledger.insert(conn, at=time.time(), day=day, status=REFUSED, model=model, local=local,
                          est_tokens=est_tokens, est_cost_usd=est_cost,
                          note=json.dumps({"scope": scope, "limit": limit, "spent": spent}), **fields)
        _hard_limit_notification(ledger, scope, limit, spent, day)
        raise BudgetExceeded(scope, limit, spent, source=source)


def after_call(res: Reservation, *, usage: Any, reported_cost: float | None, failed: bool) -> None:
    """Record what the call used. `usage` is the response's TokenUsage (None when
    none came back). A failed request settles at 0 tokens (the row stays, so
    failures are visible); a successful one that reported no usage is counted at
    its reserved estimate rather than as free. Never raises."""
    if res.settled:
        return
    res.settled = True
    try:
        if usage is not None:
            prompt, completion = int(usage.prompt_tokens), int(usage.completion_tokens)
            total = int(usage.total_tokens) or prompt + completion
            note = None
        elif failed:
            prompt = completion = total = 0
            note = "request failed; no usage reported"
        else:
            prompt, completion, total = 0, res.est_tokens, res.est_tokens
            note = "no usage reported; counted at the reserved estimate"
        cost, cost_source = pricing.call_cost(res.model, local=res.local, prompt_tokens=prompt,
                                              completion_tokens=completion, reported_cost=reported_cost,
                                              data_dir=res.ledger.data_dir)
        res.cost_usd, res.cost_source = cost, cost_source
        res.ledger.settle(res.row_id, prompt_tokens=prompt, completion_tokens=completion, total_tokens=total,
                          cost_usd=cost, cost_source=cost_source, note=note)
    except Exception as e:  # noqa: BLE001 -- bookkeeping must never fail a model call
        logger.warning("could not record a model call in the budget ledger: %s", e)
        return
    try:
        _soft_limit_check(res)
    except Exception as e:  # noqa: BLE001
        logger.warning("budget soft-limit check failed: %s", e)


def _soft_limit_check(res: Reservation) -> None:
    ledger = res.ledger
    lim = L.read(ledger.data_dir)
    share = lim.soft_limit_percent / 100.0
    now = time.time()
    day = local_day(now, ledger.data_dir)
    with ledger.connect() as conn:
        totals = BudgetLedger.day_totals(conn, day)
        run = BudgetLedger.run_totals(conn, res.run_id) if res.run_id else None
    checks = [
        (L.SCOPE_DAILY_COST, totals.cost_usd, lim.daily_cost_usd, day),
        (L.SCOPE_DAILY_TOKENS, totals.unpriced_tokens, lim.daily_tokens, day),
        (L.SCOPE_UNATTENDED_COST, totals.unattended_cost_usd, lim.unattended_daily_cost_usd, day),
    ]
    if run is not None:
        checks += [(L.SCOPE_RUN_TOKENS, run.tokens, lim.run_tokens, res.run_id),
                   (L.SCOPE_RUN_CALLS, run.calls, lim.run_model_calls, res.run_id)]
    for scope, spent, limit, period in checks:
        if limit <= 0 or spent < share * limit - _EPS:
            continue
        if not ledger.state_claim(f"notified:soft:{scope}:{period}"):
            continue
        label = L.SCOPE_LABEL.get(scope, scope)
        used = min(100, int(spent / limit * 100))
        text = (f"{label[0].upper()}{label[1:]} is {used}% used ({L.format_amount(scope, spent)} of "
                f"{L.format_amount(scope, limit)}; you're warned at {lim.soft_limit_percent}%). "
                "Settings -> Budget to change it.")
        _notice(text, "warning")
        if scope in DAY_SCOPES:
            notify("Kratos: " + text, "info")


def precheck(source: str, *, data_dir_: Path | None = None, breaker_key: str | None = None
             ) -> BudgetExceeded | None:
    """Before an unattended run that will use the model starts: is its source
    paused, or is a cap it would spend against already used up? Returns the
    refusal (also recorded in the ledger, and notified once per day) or None.
    Cheap: reads the limits and today's totals; reserves nothing."""
    from kratos.budget import breaker
    from kratos.llm_config import _active_backend_is_local, get_active_llm_model

    dd = Path(data_dir_) if data_dir_ is not None else data_dir()
    ledger = BudgetLedger(dd)
    ensure_upgrade_migration(dd, ledger)
    model = get_active_llm_model()
    local = _active_backend_is_local()
    pause = breaker.active_pause(ledger, breaker_key or breaker.key_for(source))
    now = time.time()
    day = local_day(now, dd)
    refusal: BudgetExceeded | None = None
    if pause is not None:
        refusal = BudgetExceeded(L.SCOPE_PAUSED, 0, 0, source=source, detail=breaker.pause_text(pause))
    else:
        lim = L.read(dd)
        totals = ledger.totals_for_day(day)
        priced = not local and pricing.rate_for(model, dd) is not None
        if priced and totals.cost_usd >= lim.daily_cost_usd - _EPS:
            refusal = BudgetExceeded(L.SCOPE_DAILY_COST, lim.daily_cost_usd, totals.cost_usd, source=source)
        elif not priced and totals.unpriced_tokens >= lim.daily_tokens:
            refusal = BudgetExceeded(L.SCOPE_DAILY_TOKENS, lim.daily_tokens, totals.unpriced_tokens, source=source)
        elif priced and source in UNATTENDED and \
                totals.unattended_cost_usd >= lim.unattended_daily_cost_usd - _EPS:
            refusal = BudgetExceeded(L.SCOPE_UNATTENDED_COST, lim.unattended_daily_cost_usd,
                                     totals.unattended_cost_usd, source=source)
        elif lim.run_model_calls == 0 or lim.run_tokens == 0:
            scope = L.SCOPE_RUN_CALLS if lim.run_model_calls == 0 else L.SCOPE_RUN_TOKENS
            refusal = BudgetExceeded(scope, 0, 0, source=source)
    if refusal is None:
        return None
    _source, ctx = _context()
    fields = _row_fields(source, ctx) if ctx is not None else {"source": source}
    fields["source"] = source
    with ledger.transaction() as conn:
        ledger.insert(conn, at=now, day=day, status=REFUSED, model=model, local=local,
                      note=json.dumps({"scope": refusal.scope, "limit": refusal.limit, "spent": refusal.spent,
                                       "precheck": True}), **fields)
    if refusal.scope != L.SCOPE_PAUSED:
        _hard_limit_notification(ledger, refusal.scope, refusal.limit, refusal.spent, day)
    return refusal


# --- one-time upgrade step (§3.9) -------------------------------------------
_migrated: set[str] = set()
MIGRATION_KEY = "migration:trigger_investigations_allowed"
NOTICE_PREFIX = "notice:"


def ensure_upgrade_migration(dd: Path, ledger: BudgetLedger | None = None) -> None:
    """The first time budget code runs on a data folder: if a trigger already has
    action = "investigate" (the person chose that before caps existed), turn
    `budget.trigger_investigations_allowed` on once, leave a one-time notice and
    record it in the ledger. A new install (no such trigger) keeps the default,
    off. Exactly one process does this (budget_state claim)."""
    key = str(Path(dd).resolve())
    if key in _migrated:
        return
    from kratos import settings_store

    if settings_store.in_tool_call():
        return  # settings can't change inside a tool call; the next model call outside one does this
    ledger = ledger or BudgetLedger(dd)
    if ledger.state_get(MIGRATION_KEY) is None:
        from kratos.agent import triggers as _triggers

        try:
            found, _errors = _triggers.list_triggers(dd)
        except Exception:  # noqa: BLE001 -- unreadable triggers folder: nothing to carry over
            found = []
        investigating = sorted(t.name for t in found if getattr(t, "action", None) == "investigate")
        if ledger.state_claim(MIGRATION_KEY, {"at": time.time(), "triggers": investigating}):
            if investigating:
                settings_store.set(L.TRIGGER_INVESTIGATIONS, True, data_dir=dd, actor="upgrade:0.4")
                text = ("Budget caps are new: triggers that start an investigation ("
                        + ", ".join(investigating) + ") keep doing so -- 'Triggers may start investigations' "
                        "was turned on for you. Settings -> Budget to change it.")
                ledger.state_set(NOTICE_PREFIX + "trigger_investigations", {"text": text})
                now = time.time()
                with ledger.transaction() as conn:
                    ledger.insert(conn, at=now, day=local_day(now, dd), status=NOTE, source="cli",
                                  model="-", local=False,
                                  note=json.dumps({"migration": "trigger_investigations_allowed=on",
                                                   "triggers": investigating}))
    _migrated.add(key)


def migrate_at_startup(dd: Path) -> None:
    """ensure_upgrade_migration at process start (CLI, TUI): the upgrade happens
    before the person can create a trigger under the new version. Never raises."""
    try:
        ensure_upgrade_migration(Path(dd))
    except Exception as e:  # noqa: BLE001 -- startup must not fail over this; the next budget read retries
        logger.warning("budget upgrade step skipped: %s", e)


def pending_notices(dd: Path) -> list[str]:
    """One-time notices not shown yet; reading them marks them shown."""
    ledger = BudgetLedger(dd)
    out = []
    for key, value in ledger.state_prefix(NOTICE_PREFIX).items():
        if isinstance(value, dict) and not value.get("shown") and value.get("text"):
            out.append(str(value["text"]))
            ledger.state_set(key, {**value, "shown": True})
    return out

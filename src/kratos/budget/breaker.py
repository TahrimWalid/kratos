"""Circuit breaker: pause an unattended source that keeps failing or looping.

A run "fails" when its model was unavailable, it errored, it hit the step limit
without the rule engine ever succeeding, or it looped (the same tool with the
same arguments 3+ times). `budget.breaker_failures` failures within
`budget.breaker_window_minutes` pause that source for
`budget.breaker_pause_minutes`, with one notification. A paused source refuses
to start (and its model calls are refused) until the pause ends or a person
resumes it in Settings -> Budget.

Keys: "schedule:<name>" (each schedule on its own), "trigger", "mcp", "web".
Interactive use is never paused -- a person is watching -- only warned.

State lives in `budget_state`: `breaker:failures:<key>` (recent failure times)
and `pause:<key>` ({until, since, reason, failures}).
"""
from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from kratos.budget import limits as L
from kratos.budget.ledger import BudgetLedger
from kratos.run_context import UNATTENDED

LOOP_REPEATS = 3
_FAILED_STATUSES = {"error": "the run errored", "llm_unavailable": "the model was unavailable",
                    "invalid_input": "the run could not start"}


def key_for(source: str, schedule_name: str | None = None) -> str:
    if source == "schedule" and schedule_name:
        return f"schedule:{schedule_name}"
    return source


def _pausable(key: str) -> bool:
    return key.split(":", 1)[0] in UNATTENDED


def active_pause(ledger: BudgetLedger, key: str, now: float | None = None) -> dict[str, Any] | None:
    pause = ledger.state_get(f"pause:{key}")
    if not isinstance(pause, dict):
        return None
    return pause if float(pause.get("until") or 0) > (now if now is not None else time.time()) else None


def pause_text(pause: dict[str, Any]) -> str:
    from kratos.utils import timeutil

    until = timeutil.format_for_display(timeutil.epoch_to_utc_iso(float(pause.get("until") or 0)),
                                        "%Y-%m-%d %H:%M %Z")
    return f"until {until} after {pause.get('failures', '?')} failed runs ({pause.get('reason', 'failures')})"


def detect_loop(transcript: list[dict[str, Any]] | None) -> str | None:
    """'run_nmap_scan repeated 3 times with the same arguments', or None."""
    seen: Counter[tuple[str, str]] = Counter()
    for step in transcript or []:
        tool = step.get("tool")
        if not tool:
            continue
        try:
            args = json.dumps(step.get("args") or {}, sort_keys=True, default=str)
        except (TypeError, ValueError):
            args = repr(step.get("args"))
        seen[(str(tool), args)] += 1
    for (tool, _args), count in seen.most_common(1):
        if count >= LOOP_REPEATS:
            return f"{tool} repeated {count} times with the same arguments"
    return None


def _correlate_succeeded(transcript: list[dict[str, Any]] | None) -> bool:
    for step in transcript or []:
        if step.get("tool") != "correlate_findings":
            continue
        obs = step.get("observation")
        if isinstance(obs, dict) and str(obs.get("status", "")).lower() == "ok":
            inner = obs.get("result")
            if not (isinstance(inner, dict) and str(inner.get("status", "")).lower() == "error"):
                return True
    return False


def run_failure_reason(result: dict[str, Any] | None) -> str | None:
    """Why a finished run counts as a failure for the breaker, or None."""
    if not isinstance(result, dict):
        return "the run returned nothing"
    status = str(result.get("status") or "")
    if status in _FAILED_STATUSES:
        return _FAILED_STATUSES[status]
    transcript = result.get("transcript") or []
    loop = detect_loop(transcript)
    if loop:
        return f"it looped: {loop}"
    if status == "max_iters_reached" and not _correlate_succeeded(transcript):
        return "it hit the step limit without finishing"
    return None


def record_outcome(data_dir: Path, key: str, *, failure: str | None, now: float | None = None
                   ) -> dict[str, Any] | None:
    """Record one finished run for `key`. A failure is remembered; enough of them
    within the window pause an unattended key (returns the new pause) or warn
    for an attended one. A success changes nothing (failures age out)."""
    if not failure:
        return None
    from kratos.budget import guard

    now = time.time() if now is None else now
    ledger = BudgetLedger(data_dir)
    lim = L.read(Path(data_dir))
    window = lim.breaker_window_minutes * 60
    pause: dict[str, Any] | None = None
    with ledger.transaction() as conn:
        row = conn.execute("SELECT value FROM budget_state WHERE key = ?", (f"breaker:failures:{key}",)).fetchone()
        try:
            times = [float(t) for t in json.loads(row["value"])] if row else []
        except (TypeError, ValueError):
            times = []
        times = [t for t in times if t > now - window] + [now]
        tripped = len(times) >= lim.breaker_failures
        if tripped:
            times = []  # a fresh count starts after the pause (or the warning)
            if _pausable(key):
                pause = {"until": now + lim.breaker_pause_minutes * 60, "since": now,
                         "failures": lim.breaker_failures, "reason": failure}
                conn.execute(
                    "INSERT INTO budget_state (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    (f"pause:{key}", json.dumps(pause, sort_keys=True), now))
        conn.execute(
            "INSERT INTO budget_state (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (f"breaker:failures:{key}", json.dumps(times), now))
    if pause is not None:
        guard.notify(f"Kratos paused {key} model runs for {lim.breaker_pause_minutes} minutes: "
                     f"{lim.breaker_failures} failed runs within {lim.breaker_window_minutes} minutes "
                     f"(last: {failure}). Resume early in Settings -> Budget.", "warning")
        guard._notice(f"Paused {key} runs after repeated failures (last: {failure}).", "warning")
    elif tripped:
        guard._notice(f"{lim.breaker_failures} runs failed within {lim.breaker_window_minutes} minutes "
                      f"(last: {failure}) -- worth checking before running more.", "warning")
    return pause


def list_pauses(data_dir: Path, now: float | None = None) -> list[dict[str, Any]]:
    """Active pauses: [{key, until, since, reason, failures}], soonest end first."""
    now = time.time() if now is None else now
    out = []
    for key, value in BudgetLedger(data_dir).state_prefix("pause:").items():
        if isinstance(value, dict) and float(value.get("until") or 0) > now:
            out.append({"key": key[len("pause:"):], **value})
    return sorted(out, key=lambda p: p["until"])


def resume(data_dir: Path, key: str, *, actor: str) -> bool:
    """End a pause now (a person, from Settings). Kept as a record, not deleted.
    The model suggests, people decide: refused inside an agent tool call."""
    from kratos import settings_store

    tool = settings_store.in_tool_call()
    if tool:
        raise settings_store.SettingError(f"resuming a paused source is a person's decision -- refused inside "
                                          f"the tool call {tool!r}")
    ledger = BudgetLedger(data_dir)
    pause = active_pause(ledger, key)
    if pause is None:
        return False
    ledger.state_set(f"pause:{key}", {**pause, "until": time.time(), "resumed_by": str(actor)[:120],
                                     "resumed_at": time.time()})
    return True

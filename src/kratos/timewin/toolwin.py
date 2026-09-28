"""
Window resolution at the TOOL boundary (docs/time_window_design.md §16).

Every time-aware tool calls `resolve_tool_window(window=..., since=..., until=...,
tool=...)`. That single entry point:

- accepts the structured form the agent is taught to use (`window={"id": "w1"}` or a
  TimeIntent dict / JSON string), or the legacy free-text `since`/`until` strings
  (resolved by kratos.utils.time_window, never sent to the target as text);
- registers the result in the current investigation's TimeContext (creating an ad-hoc
  context for callers outside an investigation -- `/use`, pipelines, scheduled runs) so
  window ids, the time-scope guard and structured claims all see every window queried;
- marks the window as queried by `tool`.

Returns a `ToolWindow` (or None when the call is unscoped), or raises TimeIntentError /
TimeBoundError with a message meant for the model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from kratos.timewin.agentwin import check_model_window
from kratos.timewin.windows import TimeContext, TimeIntentError, TimeWindow, current_context
from kratos.utils.time_window import TimeBoundError, resolve_time_bound
from kratos.utils.timeutil import resolve_display_tz


@dataclass
class ToolWindow:
    window: TimeWindow
    open_ended: bool  # True when the caller gave no end bound ("until now")


def _context() -> TimeContext:
    ctx = current_context()
    if ctx is None:
        # Outside run_agent (e.g. /use, a pipeline step): a private context so the tool
        # still gets exactly the same resolution rules.
        ctx = TimeContext(resolve_display_tz())
    return ctx


def resolve_tool_window(
    *,
    window: Any = None,
    since: str | None = None,
    until: str | None = None,
    tool: str,
) -> ToolWindow | None:
    ctx = _context()
    if window not in (None, "", {}):
        if isinstance(window, str):
            text = window.strip()
            if text.startswith("{"):
                try:
                    window = json.loads(text)
                except json.JSONDecodeError:
                    raise TimeIntentError(f"window {text!r} is not valid JSON") from None
            else:
                window = {"id": text}  # "w1" or a saved window name
        name = None
        if isinstance(window, dict):
            window = dict(window)
            name = window.pop("save_as", None)
        w = ctx.resolve(window, name=name)
        mismatch = check_model_window(ctx, w, window)
        if mismatch:
            raise TimeIntentError(mismatch)
        mark_queried(ctx, w, tool)
        open_ended = abs(w.end_utc - ctx.now) < 1
        return ToolWindow(w, open_ended)

    if not since and not until:
        return None
    try:
        start = resolve_time_bound(since) if since else None
        end = resolve_time_bound(until) if until else None
    except TimeBoundError:
        raise
    if start is None:
        raise TimeIntentError("'until' without 'since' is not a window -- give 'since' too (or a window)")
    if end is not None and start >= end:
        raise TimeIntentError(f"since ({since!r}) is not before until ({until!r})")
    intent = {"kind": "epoch", "start": start, "end": end if end is not None else ctx.now}
    w = ctx.resolve(intent, phrase=f"since={since!r}" + (f" until={until!r}" if until else ""))
    mark_queried(ctx, w, tool)
    return ToolWindow(w, end is None)


def mark_queried(ctx: TimeContext, w: TimeWindow, tool: str) -> None:
    ctx.queried.setdefault(w.id, set()).add(tool)

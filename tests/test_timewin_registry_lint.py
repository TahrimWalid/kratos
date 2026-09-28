"""Registry lint (docs/time_window_design.md §16): every tool that takes a time-like
parameter must resolve it through the time layer (kratos.timewin / utils.time_window) --
never pass a raw time string to a target or compute a window itself. Fails the build if a
future tool reintroduces the bug class this whole design exists to remove."""
from __future__ import annotations

import inspect

from kratos.agent.tools import TOOL_REGISTRY

TIME_PARAMS = {"since", "until", "window", "windows", "at", "start", "end", "before", "after",
               "from_time", "to_time", "time", "period", "lookback"}
RESOLVERS = ("_resolve_tool_window", "_resolve_time_bound", "resolve_tool_window", "resolve_time_bound")


def test_every_time_like_tool_parameter_goes_through_the_time_layer():
    offenders = []
    for name, tool in TOOL_REGISTRY.items():
        time_params = TIME_PARAMS & set(getattr(tool, "parameters", {}) or {})
        if not time_params:
            continue
        try:
            src = inspect.getsource(tool.handler)
        except (OSError, TypeError):
            offenders.append(f"{name}: source unavailable (can't verify {sorted(time_params)})")
            continue
        if not any(r in src for r in RESOLVERS):
            offenders.append(f"{name}: {sorted(time_params)} not resolved via the time layer")
    assert offenders == [], offenders


def test_the_lint_actually_sees_the_time_aware_tools():
    seen = {n for n, t in TOOL_REGISTRY.items() if TIME_PARAMS & set(getattr(t, "parameters", {}) or {})}
    assert {"read_journalctl", "measure_auth_activity", "compare_periods", "state_as_of"} <= seen

"""What a check is, and the registry the built-in checks join.

A check wraps something Kratos can already read (a tool, a probe) and says how
fresh its result must be, which findings-engine input it refreshes, and which
transports it works over. A new detection read is a check registered here, not a
new entry in the model's tool list (docs/phaseA/README.md §4.1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal

from kratos import settings_store
from kratos.settings_store import SettingError, SettingSpec

Cost = Literal["quick", "slow"]
Status = Literal["ok", "partial", "failed", "skipped", "not_supported"]
STATUSES = ("ok", "partial", "failed", "skipped", "not_supported")
TRANSPORTS = frozenset({"ssh", "agent", "local"})
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass
class CheckResult:
    status: Status
    summary: str                                   # one plain line for the digest ("2 open ports: 22/tcp ssh")
    coverage_gaps: list[str] = field(default_factory=list)   # what it could not see, in plain words
    finding_ids: list[str] = field(default_factory=list)     # filled after correlation
    detail: str = ""                               # why, for logs / `kratos collect` -- never shown to the model
    tools: list[str] = field(default_factory=list) # tools the check ran (so the loop can count them as used)


@dataclass
class CheckContext:
    """What a running check gets. `dispatch` has execute_tool_call's shape, so the
    dispatch guards, target checks, approval gating and event recording all apply."""
    target: str                                    # the machine as the person typed it
    target_key: str
    data_dir: Path
    transport: str                                 # "ssh" | "agent" | "local"
    dispatch: Callable[[str, dict[str, Any], Path], dict[str, Any]]
    deadline: float                                # time.monotonic() value this check must finish by
    now: float                                     # epoch seconds at the start of the collection
    steps: list[dict[str, Any]] = field(default_factory=list)   # every tool call this check made (for the transcript)

    def call(self, tool: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        args = dict(args or {})
        res = self.dispatch(tool, args, self.data_dir)
        self.steps.append({"tool": tool, "args": args, "observation": res})
        return res


@dataclass(frozen=True)
class Check:
    name: str
    cost: Cost
    ttl_setting: str                               # settings key holding its freshness limit, in minutes
    default_ttl_minutes: int
    run: Callable[[CheckContext], CheckResult]
    inputs: tuple[str, ...]                        # findings-engine input categories it refreshes
    transports: frozenset[str]
    budget_seconds: float                          # its own cap inside the overall budget
    label: str                                     # plain words for the digest ("open ports")
    order: int = 50                                # lower runs / is listed first (value order)
    short: str = ""                                # the screen's one-line summary word ("ports"); default: label
    # Checks this one must run after, when the same collection runs them too (the
    # detection pass reads what log sync just stored). It waits within its own deadline.
    after: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _NAME_RE.fullmatch(self.name):
            raise ValueError(f"check name {self.name!r} must be lower_snake_case")
        if self.cost not in ("quick", "slow"):
            raise ValueError(f"check {self.name}: cost must be quick or slow")
        if not self.transports or not self.transports <= TRANSPORTS:
            raise ValueError(f"check {self.name}: transports must be a non-empty subset of {sorted(TRANSPORTS)}")


_CHECKS: dict[str, Check] = {}


def _minutes(value: Any) -> int:
    if isinstance(value, bool):
        raise SettingError("a whole number of minutes, 1-10,080")
    try:
        n = int(str(value).strip()) if not isinstance(value, (int, float)) else int(value)
    except (TypeError, ValueError):
        raise SettingError("a whole number of minutes, 1-10,080") from None
    if isinstance(value, float) and n != value or not 1 <= n <= 10_080:
        raise SettingError("a whole number of minutes, 1-10,080")
    return n


def register(check: Check) -> Check:
    """Register `check` (and its TTL setting). Registering the same check again is
    fine (module re-import); a different one under the same name is an error."""
    existing = _CHECKS.get(check.name)
    if existing is not None and existing != check:
        raise ValueError(f"check {check.name!r} is already registered differently")
    settings_store.register(SettingSpec(
        check.ttl_setting, check.default_ttl_minutes, _minutes,
        f"How many minutes a {check.label} result stays fresh before Kratos checks again."))
    _CHECKS[check.name] = check
    return check


def checks(cost: str | None = None) -> list[Check]:
    """Registered checks in value order; `cost` filters to quick or slow."""
    out = [c for c in _CHECKS.values() if cost is None or c.cost == cost]
    return sorted(out, key=lambda c: (c.order, c.name))


def get(name: str) -> Check | None:
    return _CHECKS.get(name)

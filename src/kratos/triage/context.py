"""What a verifier is handed: the finding, the machine, and bounded ways to re-read.

A verifier never reaches further than the finding's own evidence (docs/phaseB/B.1
§3.2). The two reads it may use are both here:

- `recollect(check_names)` forces a fresh run of named collection checks (a tool
  call under execute_tool_call's dispatch guards) and one correlation over the
  result -- "a collection check run with force";
- `dispatch(tool, args)` calls one tool through the same guarded dispatch -- "a
  tool's fetcher" (an nmap reachability probe, measure_auth_activity for a window).

Both are injectable, so a fixture test can hand a verifier canned fresh data with
no SSH or lab (tests/test_triage_verifiers.py). The default reads go through the
real collection runner and the agent loop's dispatch.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kratos.lifecycle.keys import finding_key as _finding_key
from kratos.target_key import target_key as _target_key

Dispatch = Callable[[str, dict[str, Any]], dict[str, Any]]


def _default_dispatch(data_dir: Path) -> Dispatch:
    from kratos.agent.loop import execute_tool_call

    def dispatch(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        return execute_tool_call(tool, dict(args or {}), Path(data_dir))

    return dispatch


def _default_recollect(target: str, data_dir: Path) -> "Callable[[tuple[str, ...]], Any]":
    def recollect(check_names: tuple[str, ...]) -> Any:
        from kratos import kratos_config
        from kratos.collect import runner as _runner

        with kratos_config.pinned_target(target):
            return _runner.prepare(target, data_dir, classes=("quick", "slow"), only=tuple(check_names),
                                   force=True, correlate=True, background=False)

    return recollect


@dataclass
class VerifyContext:
    finding: dict[str, Any]
    target: str
    data_dir: Path
    run: Any = None                                   # RunContext | None
    deadline: float = field(default=0.0)              # time.monotonic() budget end (0 = no cap)
    now: float = field(default_factory=time.time)
    recollect: "Callable[[tuple[str, ...]], Any] | None" = None
    dispatch: Dispatch | None = None
    # Reuse mode: the automatic verification after an investigation re-uses the
    # collection Kratos JUST ran (seconds old -- a genuine fresh read) instead of issuing
    # a second one. `report` is that CollectionReport. On demand (/verify, /retest) reuse
    # is off and the verifier issues its own narrow fresh read.
    reuse: bool = False
    report: Any = None

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        # The real reads (execute_tool_call, runner.prepare) are resolved by the caller
        # (triage.run.verify_finding, which runs inside a run_scope), not here -- so a
        # VerifyContext built with no reads never reaches a tool outside a scope.
        if self.recollect is None:
            self.recollect = _unset_recollect
        if self.dispatch is None:
            self.dispatch = _unset_dispatch

    @property
    def rule_id(self) -> str:
        return str(self.finding.get("id") or "")

    @property
    def target_key(self) -> str:
        return _target_key(self.target)

    @property
    def finding_key(self) -> str:
        key = str(self.finding.get("finding_key") or "")
        if key:
            return key
        return _finding_key(self.rule_id, self.target_key, self.finding.get("subject") or "")

    def remaining(self) -> float:
        if not self.deadline:
            return float("inf")
        return self.deadline - time.monotonic()

    def out_of_time(self) -> bool:
        return self.remaining() <= 0

    def fresh_finding(self, report: Any) -> dict[str, Any] | None:
        """The finding with this finding's key in a fresh correlation report."""
        want = self.finding_key
        for f in getattr(report, "findings", None) or []:
            if _match_key(f, self.target_key, want):
                return f
        return None


def _unset_recollect(_names: tuple[str, ...]) -> Any:
    raise RuntimeError("VerifyContext has no recollect; build it via triage.run.verify_finding")


def _unset_dispatch(_tool: str, _args: dict[str, Any]) -> dict[str, Any]:
    raise RuntimeError("VerifyContext has no dispatch; build it via triage.run.verify_finding")


def _match_key(finding: dict[str, Any], target_key: str, want: str) -> bool:
    key = str(finding.get("finding_key") or "")
    if key:
        return key == want
    return _finding_key(str(finding.get("id") or ""), target_key, finding.get("subject") or "") == want

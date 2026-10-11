"""Which rules a run actually re-checked -- the condition for saying a finding is gone.

A rule is covered by a run when, for the machine the report is about, every
input the rule needs (RuleInfo.covering_inputs) was

1. used by this report,
2. collected during this run (file time at or after the run's start, with the
   same 10 s slack the conversation view uses), and about this machine, and
3. complete: an auth read that only reached part of the window (truncated --
   the same data COV-001 reports) can't say a login-derived finding is gone.

No run (plain `kratos findings-generate` re-reading old files) covers nothing:
old files can't show something went away.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kratos.adapters.findings_engine import input_hosts
from kratos.lifecycle.rules import AUTH_INPUTS, rule_info
from kratos.run_context import RunContext
from kratos.target_key import target_key

FRESH_SLACK_SECONDS = 10.0     # tui_mk2/finding_view._FRESH_SLACK_SECONDS


@dataclass(frozen=True)
class Coverage:
    # input category -> None when it can cover, else why it can't
    inputs: dict[str, str | None] = field(default_factory=dict)
    no_run: bool = False

    def why_not(self, rule_id: str) -> str | None:
        """None when the rule is covered, else a plain reason."""
        if self.no_run:
            return "no run context: old files can't show that something went away"
        info = rule_info(rule_id)
        if info is None or info.kind == "run_note":
            return "this rule has no lifecycle"
        needed = info.covering_inputs
        if not needed:
            return "the rule reads no inputs"
        for name in needed:
            reason = self.inputs.get(name, f"{name} was not used by this report")
            if reason:
                return reason
        return None

    def covered(self, rule_id: str) -> bool:
        return self.why_not(rule_id) is None


def nothing() -> Coverage:
    return Coverage(no_run=True)


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def _describes(category: str, path: Path, target: str) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return False
    hosts = input_hosts(category, data)
    return bool(hosts) and target in hosts


def for_report(inputs: dict[str, Path | None], *, target: str, run: RunContext | None,
               incomplete: set[str] | frozenset[str] = frozenset()) -> Coverage:
    """`inputs`: the report's input files by category (write_findings_report's
    `inputs`). `incomplete`: categories whose read reached only part of its window."""
    if run is None:
        return nothing()
    target = target_key(target)
    states: dict[str, str | None] = {}
    for name, path in inputs.items():
        if path is None:
            states[name] = f"{name} was not used by this report"
            continue
        path = Path(path)
        mtime = _mtime(path)
        if mtime is None:
            states[name] = f"{name} could not be read"
        elif mtime < run.started_at - FRESH_SLACK_SECONDS:
            states[name] = f"{name} was not re-collected in this run"
        elif not _describes(name, path, target):
            states[name] = f"{name} is not about this machine"
        elif name in incomplete:
            states[name] = f"{name} covered only part of its time window"
        else:
            states[name] = None
    return Coverage(inputs=states)


def incomplete_auth_inputs(stats_by_input: dict[str, dict[str, Any] | None]) -> set[str]:
    """The auth inputs whose own read was truncated. `stats_by_input` maps
    "auth_stats"/"auth_patterns" to the auth_stats data saved by THAT read (for
    auth_patterns, its paired stats file)."""
    out: set[str] = set()
    for name, stats in stats_by_input.items():
        if name not in AUTH_INPUTS:
            continue
        coverage = (stats or {}).get("coverage") or {}
        if any(isinstance(c, dict) and c.get("truncated") for c in coverage.values()):
            out.add(name)
    return out

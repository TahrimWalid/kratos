"""Replay: run an investigation with the real model but no lab.

A recording is a live run's trace reduced to what the investigation needs again: the
collected report the model started from, and every tool call's result keyed by (tool,
normalised arguments). In replay the collection layer returns the recorded report and
every `execute_tool_call` returns the recorded result for the same (tool, args). A call
not in the recording returns a clear "not recorded" result and the run is marked as
having *left the recording* -- reported on its own, neither a pass nor a fail.

Recordings hold lab data only (tests/test_eval_recordings.py scans for anything else).
"""
from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterator

RECORDING_FORMAT = 1


def _norm_args(args: dict[str, Any] | None) -> str:
    a = {k: v for k, v in (args or {}).items() if k != "data_dir"}
    return json.dumps(a, sort_keys=True, default=str)


def recording_from_trace(trace: dict[str, Any], scenario_id: str, goal: str) -> dict[str, Any]:
    """Reduce a live run's trace to a recording. The collection the model started from,
    plus one entry per tool call (tool, args, the full execute_tool_call result)."""
    spans = [s for s in trace.get("spans") or [] if isinstance(s, dict)]
    collection = next((s["attrs"].get("report") for s in spans
                       if s.get("kind") == "collection" and isinstance(s.get("attrs"), dict)), None)
    calls = []
    for s in spans:
        if s.get("kind") != "tool_call":
            continue
        a = s.get("attrs") or {}
        if "result" not in a:
            continue
        calls.append({"tool": s.get("name"), "args": a.get("args") or {}, "result": a.get("result")})
    return {"format": RECORDING_FORMAT, "scenario": scenario_id, "goal": goal,
            "source_run_id": trace.get("run_id"), "target": trace.get("target"),
            "collection": collection, "calls": calls}


_NOT_RECORDED = {"status": "error", "observation": "not recorded: this (tool, arguments) pair is not in the "
                 "replay recording, so the live result is unknown.", "replay_not_recorded": True}


@dataclass
class ReplayTracker:
    """What happened against the recording during a replay run."""
    hits: int = 0
    arg_mismatches: list[str] = field(default_factory=list)   # tool recorded, but with other arguments
    not_recorded: list[str] = field(default_factory=list)     # tool never recorded

    @property
    def left_recording(self) -> bool:
        return bool(self.not_recorded)


@contextlib.contextmanager
def install(recording: dict[str, Any]) -> Iterator[ReplayTracker]:
    """For its duration, make the agent loop replay `recording`: collection returns the
    recorded report, every tool call returns the recorded result. Yields a tracker."""
    from kratos.agent import loop
    from kratos.collect.runner import report_from_record

    by_exact: dict[tuple[str, str], Any] = {}
    by_tool: dict[str, list[Any]] = {}
    for c in recording.get("calls") or []:
        tool = c.get("tool")
        by_exact.setdefault((tool, _norm_args(c.get("args"))), c.get("result"))
        by_tool.setdefault(tool, []).append(c.get("result"))

    tracker = ReplayTracker()
    report = report_from_record(recording["collection"]) if recording.get("collection") else None

    def fake_collect(data_dir, should_stop):  # noqa: ANN001
        if should_stop is not None and should_stop():
            raise loop.InvestigationStopped()
        return report

    def fake_dispatch(tool_name, args, data_dir):  # noqa: ANN001
        key = (tool_name, _norm_args(args))
        if key in by_exact:
            tracker.hits += 1
            return by_exact[key]
        if tool_name in by_tool:
            tracker.arg_mismatches.append(tool_name)
            return by_tool[tool_name][0]   # same tool, different args: the live result for it
        tracker.not_recorded.append(tool_name)
        return dict(_NOT_RECORDED)

    orig_collect, orig_dispatch = loop._collect_first, loop.execute_tool_call
    loop._collect_first = fake_collect
    loop.execute_tool_call = fake_dispatch
    try:
        yield tracker
    finally:
        loop._collect_first = orig_collect
        loop.execute_tool_call = orig_dispatch


# --- recording hygiene ------------------------------------------------------------

_KEY_SHAPED = [
    (r"AIza[0-9A-Za-z_\-]{30,}", "Google API key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style key"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key"),
    (r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}\b", "pairing-code shape"),
]
_IP = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


def scan_recording(recording: dict[str, Any]) -> list[str]:
    """Problems that must keep a recording out of the repo: a public address that is not
    the lab's, or anything key/token-shaped. Lab, private, loopback and documentation
    addresses are fine."""
    import re

    from evals.lab import is_private_or_documentation, lab_addresses

    text = json.dumps(recording, default=str)
    problems = []
    allowed = lab_addresses()
    for ip in set(re.findall(_IP, text)):
        if ip not in allowed and not is_private_or_documentation(ip):
            problems.append(f"public address {ip} (not the lab's)")
    for pat, what in _KEY_SHAPED:
        if re.search(pat, text):
            problems.append(f"{what}-shaped string")
    return problems

"""
Human-authored test harness for the "count failed sudo attempts" candidate
tool -- self-writing loop, write-step (Part A) verification case #1.

This is the shape of test harness Part B's sandbox execution step runs
against a STAGED candidate tool file -- always human-authored, never
model-generated (see docs/DESIGN.md's "Self-writing tool loop" section).
It exists for two reasons:
  1. The write step's prompt shows the model this file's full contents, so
     the model learns the exact interface it must implement instead of
     guessing (see agent/self_write.py's module docstring for why).
  2. This file can be run standalone against a hand-written reference
     implementation to confirm the harness itself is correct, independent
     of the rest of the pipeline.

INTERFACE CONTRACT a candidate MUST satisfy:
  - Registers a tool named "count_failed_sudo_attempts" via
    @register_tool(name="count_failed_sudo_attempts", ...) from
    kratos.agent.tools, so TOOL_REGISTRY["count_failed_sudo_attempts"]
    exists after the candidate module is imported.
  - The registered handler accepts a keyword argument `auth_events_file`
    (str | Path): the path to a parse_auth_log-produced auth_events_*.json
    file -- a JSON list of objects each carrying an "event_type" field,
    matching adapters/auth_log_parse.py::AuthEvent's shape.
  - Returns a dict containing at least {"failed_sudo_count": <int>}.
  - "Failed sudo attempt" == an event whose event_type is exactly
    "sudo_auth_failure" OR "sudo_pam_auth_failure" (matching the same
    definition compute_basic_stats already uses in
    adapters/auth_log_parse.py -- this tool is a focused, single-purpose
    view of that existing definition, not a new one).

Run standalone against a hand-written reference implementation:
    CANDIDATE_MODULE_PATH=/path/to/reference_impl.py \\
        pytest tests/self_write_harnesses/test_count_failed_sudo_attempts.py -v

Run as part of the normal suite with no CANDIDATE_MODULE_PATH set: all tests
skip cleanly (nothing staged yet to point at) rather than failing.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "count_failed_sudo_attempts"


def _load_candidate():
    if not CANDIDATE_MODULE_PATH:
        pytest.skip(
            "CANDIDATE_MODULE_PATH not set -- this harness is meant to be pointed at a staged "
            "candidate (by Part B) or a reference implementation (manual sanity check)."
        )
    path = Path(CANDIDATE_MODULE_PATH)
    spec = importlib.util.spec_from_file_location("candidate_tool_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY

    _load_candidate()
    assert TOOL_NAME in TOOL_REGISTRY, (
        f"Candidate did not register a tool named '{TOOL_NAME}' via @register_tool -- "
        f"found instead: {sorted(TOOL_REGISTRY.keys())}"
    )
    return TOOL_REGISTRY[TOOL_NAME].handler


def _write_events(tmp_path: Path, event_types: list[str]) -> Path:
    events = [
        {
            "timestamp": "2026-01-01T00:00:00",
            "host": "testhost",
            "program": "sudo",
            "event_type": et,
            "user": "walid000",
            "source_ip": None,
            "raw": f"raw line for {et}",
        }
        for et in event_types
    ]
    p = tmp_path / "auth_events_test.json"
    p.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return p


def test_counts_both_failure_event_types(tmp_path, registered_handler):
    events_file = _write_events(
        tmp_path,
        [
            "sudo_auth_failure",
            "sudo_pam_auth_failure",
            "sudo_auth_failure",
            "sudo_command",
            "sudo_session_open",
            "ssh_failed_login",
        ],
    )
    result = registered_handler(auth_events_file=str(events_file))
    assert isinstance(result, dict)
    assert result["failed_sudo_count"] == 3


def test_zero_when_no_failures_present(tmp_path, registered_handler):
    events_file = _write_events(tmp_path, ["sudo_command", "sudo_session_open", "ssh_success_login"])
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_sudo_count"] == 0


def test_empty_events_file(tmp_path, registered_handler):
    events_file = _write_events(tmp_path, [])
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_sudo_count"] == 0


def test_does_not_count_unrelated_ssh_events(tmp_path, registered_handler):
    events_file = _write_events(
        tmp_path,
        ["ssh_failed_login", "ssh_failed_login", "ssh_success_login", "auth_other"],
    )
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_sudo_count"] == 0

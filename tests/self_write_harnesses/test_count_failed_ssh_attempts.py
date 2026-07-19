"""
Human-authored test harness for the "count failed SSH login attempts"
candidate tool -- Sprint 2 self-writing loop, write-step (Part A)
verification case #5.

Direct precedent: tests/self_write_harnesses/test_count_failed_sudo_attempts.py
(the real, kept count_failed_sudo_attempts tool) -- same event-type-filtering
shape, same auth_events_file interface, same "malformed input must not crash
or miscount" defensiveness philosophy (also matches
test_flag_events_outside_cidr.py's malformed-field handling). One real
difference from the sudo precedent, not just a find-replace: SSH failed
logins are a SINGLE event_type ("ssh_failed_login" -- confirmed in
adapters/auth_log_parse.py, e.g. the Invalid-user/Failed-password/
disconnect-during-auth classification paths all emit this one string), not
two variants the way sudo has (sudo_auth_failure / sudo_pam_auth_failure).
A candidate that copies the sudo tool's two-event-type-set pattern verbatim
without adjusting for this would still pass the "counts correctly" tests
below by coincidence (an unused second entry in a set is harmless) but
that's exactly the kind of overfit-to-precedent shortcut worth catching if
it shows up in review.

Grounded in a real motivating scenario, not synthetic: this is the exact
tool the model proposed during a real `kratos investigate` run (2026-07-16)
that hit the run_linux_command/target-remediation capability gap -- SSH
brute-force detection is already Kratos's flagship real-world scenario
(CORR-SSH-001), so a focused, single-purpose "just the count" view of
ssh_failed_login events (mirroring count_failed_sudo_attempts's existing
role for sudo) is independently useful, not manufactured for this test.

INTERFACE CONTRACT a candidate MUST satisfy:
  - Registers a tool named "count_failed_ssh_attempts" via
    @register_tool(name="count_failed_ssh_attempts", ...) from
    kratos.agent.tools, so TOOL_REGISTRY["count_failed_ssh_attempts"]
    exists after the candidate module is imported.
  - The registered handler accepts a keyword argument `auth_events_file`
    (str | Path): the path to a parse_auth_log-produced auth_events_*.json
    file -- a JSON list of objects each carrying an "event_type" field,
    matching adapters/auth_log_parse.py::AuthEvent's shape (timestamp, host,
    program, event_type, user, source_ip, raw).
  - Returns a dict containing at least {"failed_ssh_count": <int>}.
  - "Failed SSH attempt" == an event whose event_type is exactly
    "ssh_failed_login" (matching adapters/auth_log_parse.py's own
    classification -- this tool is a focused, single-purpose view of that
    existing definition, not a new one).
  - Must not raise on malformed input (a non-dict entry in the events list,
    or a dict missing the "event_type" key) -- such entries are simply not
    counted, not a crash.

Run standalone against a hand-written reference implementation:
    CANDIDATE_MODULE_PATH=/path/to/reference_impl.py \\
        pytest tests/self_write_harnesses/test_count_failed_ssh_attempts.py -v

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
TOOL_NAME = "count_failed_ssh_attempts"


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


def _write_events(tmp_path: Path, events: list[dict | str]) -> Path:
    """Accepts either event_type strings (expanded into a full real-shaped
    AuthEvent dict) or already-complete dicts (for malformed/partial-field
    cases below, where the caller wants to omit a field, not just vary
    event_type)."""
    full_events = []
    for e in events:
        if isinstance(e, str):
            full_events.append(
                {
                    "timestamp": "2026-01-01T00:00:00",
                    "host": "testhost",
                    "program": "sshd",
                    "event_type": e,
                    "user": "root",
                    "source_ip": "203.0.113.7",
                    "raw": f"raw line for {e}",
                }
            )
        else:
            full_events.append(e)
    p = tmp_path / "auth_events_test.json"
    p.write_text(json.dumps(full_events, indent=2), encoding="utf-8")
    return p


def test_counts_failed_ssh_logins_amid_other_event_types(tmp_path, registered_handler):
    events_file = _write_events(
        tmp_path,
        [
            "ssh_failed_login",
            "ssh_success_login",
            "ssh_failed_login",
            "sudo_command",
            "sudo_auth_failure",
            "ssh_failed_login",
        ],
    )
    result = registered_handler(auth_events_file=str(events_file))
    assert isinstance(result, dict)
    assert result["failed_ssh_count"] == 3


def test_zero_when_no_failures_present(tmp_path, registered_handler):
    events_file = _write_events(tmp_path, ["ssh_success_login", "sudo_command", "sudo_session_open"])
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_ssh_count"] == 0


def test_empty_events_file(tmp_path, registered_handler):
    events_file = _write_events(tmp_path, [])
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_ssh_count"] == 0


def test_does_not_count_unrelated_sudo_events(tmp_path, registered_handler):
    """The inverse of count_failed_sudo_attempts's own
    test_does_not_count_unrelated_ssh_events -- confirms this tool's filter
    is genuinely scoped to ssh_failed_login, not "any auth failure"."""
    events_file = _write_events(
        tmp_path,
        ["sudo_auth_failure", "sudo_pam_auth_failure", "sudo_auth_failure"],
    )
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_ssh_count"] == 0


def test_event_missing_event_type_field_is_not_counted_and_does_not_crash(tmp_path, registered_handler):
    events_file = _write_events(
        tmp_path,
        [
            {"timestamp": "2026-01-01T00:00:00", "host": "testhost", "program": "sshd", "user": "root", "source_ip": None, "raw": "malformed, no event_type key at all"},
            "ssh_failed_login",
        ],
    )
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_ssh_count"] == 1


def test_non_dict_entry_in_events_list_is_not_counted_and_does_not_crash(tmp_path, registered_handler):
    events_file = _write_events(tmp_path, ["ssh_failed_login"])
    raw = json.loads(events_file.read_text(encoding="utf-8"))
    raw.append("this is not a dict, a malformed/corrupt entry")
    raw.append(None)
    events_file.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    result = registered_handler(auth_events_file=str(events_file))
    assert result["failed_ssh_count"] == 1

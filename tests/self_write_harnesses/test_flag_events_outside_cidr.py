"""
Human-authored test harness for "flag_events_outside_cidr" -- Phase 3a: full
real-conditions run of the self-writing loop (local qwen2.5:7b, real Incus
sandbox, real human approval, no mocks anywhere). Written and finalized
BEFORE the write step is ever invoked, per this project's non-negotiable
ordering (agent/self_write.py's own docstring) -- the model sees this file's
full contents as its interface contract, but never influences it.

WHY THIS TOOL: not covered by any existing tool. read_journalctl and
parse_auth_log surface raw/aggregated auth activity; correlate_findings
surfaces burst/exposure correlations. Nothing today flags "this login came
from a network we don't recognize" -- a genuinely useful, standalone signal
for a real investigation (e.g. "did anyone log in from outside our own lab
subnet, 10.136.28.0/24"), with real edge cases a naive implementation would
get wrong: malformed IP strings, IPv6 addresses evaluated against an IPv4
CIDR, and events that simply have no source_ip at all (e.g. sudo events).

INTERFACE CONTRACT a candidate MUST satisfy:
  - Registers a tool named "flag_events_outside_cidr" via
    @register_tool(name="flag_events_outside_cidr", ...) from
    kratos.agent.tools, so TOOL_REGISTRY["flag_events_outside_cidr"] exists
    after the candidate module is imported.
  - The registered handler accepts two keyword arguments:
      - auth_events_file (str | Path): path to a parse_auth_log/
        read_journalctl-shaped JSON file -- a list of event dicts, each
        possibly carrying a "source_ip" field (a string, or null/absent if
        the event has no associated network origin, e.g. a sudo event).
      - allowed_cidr (str): a CIDR string, e.g. "10.136.28.0/24".
  - Returns a dict containing AT LEAST:
      - "flagged_count" (int): how many events had a source_ip that is
        NOT within allowed_cidr.
      - "flagged_events" (list): the flagged events themselves (or enough
        of each to identify it -- at minimum each entry must expose the
        same source_ip value the input event had, e.g. under a
        "source_ip" key).
      - "skipped_no_ip" (int): events with no source_ip (null, missing, or
        empty string) -- these are NOT flagged and NOT treated as errors.
      - "malformed_ip_count" (int): events whose source_ip is present but
        is not a syntactically valid IP address at all (e.g. "not.an.ip",
        "999.999.999.999") -- these are NOT flagged (we cannot judge
        membership for a string that isn't even an address) and NOT
        counted as skipped.
  - An IPv6 address MUST be treated as a valid, parseable IP address that
    is, definitionally, outside any IPv4 CIDR -- so it counts toward
    flagged_count and flagged_events, NOT malformed_ip_count.
  - If allowed_cidr itself is not a valid CIDR string, the handler must
    return a dict containing an "error" key (a string) describing the
    problem, and must NOT raise an uncaught exception, and must NOT
    attempt to process any events in that case.

Run standalone against a hand-written reference implementation:
    CANDIDATE_MODULE_PATH=/path/to/reference_impl.py \\
        pytest tests/self_write_harnesses/test_flag_events_outside_cidr.py -v
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "flag_events_outside_cidr"
ALLOWED_CIDR = "10.136.28.0/24"


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


def _write_events(tmp_path: Path, events: list[dict]) -> Path:
    p = tmp_path / "auth_events_test.json"
    p.write_text(json.dumps(events, indent=2), encoding="utf-8")
    return p


def _event(event_type: str, source_ip: str | None, **extra) -> dict:
    base = {
        "timestamp": "2026-01-01T00:00:00",
        "host": "testhost",
        "program": "sshd",
        "event_type": event_type,
        "user": "someuser",
        "source_ip": source_ip,
        "raw": f"raw line for {event_type} from {source_ip}",
    }
    base.update(extra)
    return base


def test_flags_ip_outside_cidr_and_leaves_inside_ip_unflagged(tmp_path, registered_handler):
    events = [
        _event("ssh_success_login", "10.136.28.52"),   # inside -- attacker-box's real IP on this lab subnet
        _event("ssh_failed_login", "203.0.113.99"),      # outside -- TEST-NET-3, definitely foreign
        _event("ssh_failed_login", "10.136.28.168"),     # inside -- kratos-target's real IP
    ]
    events_file = _write_events(tmp_path, events)
    result = registered_handler(auth_events_file=str(events_file), allowed_cidr=ALLOWED_CIDR)

    assert result["flagged_count"] == 1
    flagged_ips = {e["source_ip"] for e in result["flagged_events"]}
    assert flagged_ips == {"203.0.113.99"}


def test_skips_events_with_no_source_ip(tmp_path, registered_handler):
    events = [
        _event("sudo_command", None, program="sudo"),
        _event("sudo_session_open", None, program="sudo"),
        _event("ssh_failed_login", "203.0.113.5"),
    ]
    events_file = _write_events(tmp_path, events)
    result = registered_handler(auth_events_file=str(events_file), allowed_cidr=ALLOWED_CIDR)

    assert result["skipped_no_ip"] == 2
    assert result["flagged_count"] == 1
    flagged_ips = {e["source_ip"] for e in result["flagged_events"]}
    assert flagged_ips == {"203.0.113.5"}


def test_malformed_ip_is_not_flagged_and_not_skipped(tmp_path, registered_handler):
    events = [
        _event("ssh_failed_login", "not.an.ip.address"),
        _event("ssh_failed_login", "999.999.999.999"),
        _event("ssh_success_login", "10.136.28.1"),  # inside, valid
    ]
    events_file = _write_events(tmp_path, events)
    result = registered_handler(auth_events_file=str(events_file), allowed_cidr=ALLOWED_CIDR)

    assert result["malformed_ip_count"] == 2
    assert result["flagged_count"] == 0
    assert result["skipped_no_ip"] == 0


def test_ipv6_address_is_flagged_as_outside_ipv4_cidr(tmp_path, registered_handler):
    events = [
        _event("ssh_failed_login", "fd42:2e:7da3:6a52:216:3eff:fed0:55d"),
    ]
    events_file = _write_events(tmp_path, events)
    result = registered_handler(auth_events_file=str(events_file), allowed_cidr=ALLOWED_CIDR)

    assert result["flagged_count"] == 1
    assert result["malformed_ip_count"] == 0
    flagged_ips = {e["source_ip"] for e in result["flagged_events"]}
    assert flagged_ips == {"fd42:2e:7da3:6a52:216:3eff:fed0:55d"}


def test_empty_events_list(tmp_path, registered_handler):
    events_file = _write_events(tmp_path, [])
    result = registered_handler(auth_events_file=str(events_file), allowed_cidr=ALLOWED_CIDR)

    assert result["flagged_count"] == 0
    assert result["flagged_events"] == []
    assert result["skipped_no_ip"] == 0
    assert result["malformed_ip_count"] == 0


def test_invalid_cidr_returns_error_not_exception(tmp_path, registered_handler):
    events = [_event("ssh_failed_login", "203.0.113.5")]
    events_file = _write_events(tmp_path, events)
    result = registered_handler(auth_events_file=str(events_file), allowed_cidr="this-is-not-a-cidr")

    assert "error" in result
    assert isinstance(result["error"], str)

"""
Human-authored test harness for "flag_risky_open_ports" -- Phase 3b: second
real-conditions run of the self-writing loop (local qwen2.5:7b, real Incus
sandbox, real human approval, no mocks anywhere), exploring whether Phase
3a's exhausted-retries outcome (flag_events_outside_cidr) was representative
or unlucky. Written and finalized BEFORE the write step is ever invoked, per
this project's non-negotiable ordering -- the model sees this file's full
contents as its interface contract, but never influences it.

WHY THIS TOOL: not covered by any existing tool. run_nmap_scan reports raw
open ports; correlate_findings's NET-002/CORR-SSH-001 rules look at SSH
exposure + auth bursts specifically. Nothing today flags "this open port is
a commonly-risky service to have exposed at all" (telnet, ftp, rdp, vnc,
unauthenticated databases, etc.) -- a standalone, genuinely useful hardening
signal for a real investigation. Deliberately grounded in the REAL output
shape of adapters/nmap_parse.py::parse_nmap_xml_to_dict (not an invented
shape) -- including that module's own int|str fallback for `port` (see its
`portid: int | str = int(portid_str)` with a ValueError fallback), which is
what makes this harness's int-vs-str port test a real edge case, not a
contrived one.

INTERFACE CONTRACT a candidate MUST satisfy:
  - Registers a tool named "flag_risky_open_ports" via
    @register_tool(name="flag_risky_open_ports", ...) from
    kratos.agent.tools, so TOOL_REGISTRY["flag_risky_open_ports"] exists
    after the candidate module is imported.
  - The registered handler accepts:
      - nmap_parsed_file (str | Path): path to a JSON file matching
        adapters/nmap_parse.py's real output shape:
        {"hosts": [{"ip": "...", "open_ports": [{"port": 23, "protocol":
        "tcp", "service": "telnet"}, ...]}, ...]}. `port` may be a JSON int
        OR a JSON string -- both must be handled correctly.
      - risky_ports (list[int] | None, optional): if given, this EXACT
        list of port numbers is used as the risky set, REPLACING (not
        adding to) any built-in default. If omitted/None, the handler must
        use a sensible built-in default set of commonly-risky ports (must
        include AT LEAST 23/telnet and 3389/rdp).
  - Returns a dict containing AT LEAST:
      - "flagged_count" (int): total number of open ports, across ALL
        hosts, whose port number is in the risky set.
      - "flagged_ports" (list[dict]): one entry per flagged port, each
        exposing AT LEAST "ip" (which host it came from) and "port".
      - "hosts_scanned" (int): number of host entries in the input.
      - "total_open_ports" (int): total open ports across all hosts,
        risky or not.
  - Matching is by PORT NUMBER only (service name is informational, not
    required for the match -- a port with a missing/empty/None "service"
    field must still be correctly flagged if its port number is risky).
  - A host entry with a missing or empty "open_ports" key must be treated
    as zero open ports for that host, not raise an exception.
  - Must not crash on an empty "hosts" list.

Run standalone against a hand-written reference implementation:
    CANDIDATE_MODULE_PATH=/path/to/reference_impl.py \\
        pytest tests/self_write_harnesses/test_flag_risky_open_ports.py -v
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "flag_risky_open_ports"


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


def _write_scan(tmp_path: Path, hosts: list[dict]) -> Path:
    p = tmp_path / "parsed_test.json"
    p.write_text(json.dumps({"tool": "nmap", "hosts": hosts}, indent=2), encoding="utf-8")
    return p


def _port(port, protocol="tcp", service="unknown") -> dict:
    return {"port": port, "protocol": protocol, "service": service}


def test_default_risky_list_flags_telnet_not_ssh(tmp_path, registered_handler):
    scan = _write_scan(tmp_path, [
        {"ip": "10.136.28.168", "open_ports": [_port(22, service="ssh"), _port(23, service="telnet")]},
    ])
    result = registered_handler(nmap_parsed_file=str(scan))

    assert result["flagged_count"] == 1
    assert result["hosts_scanned"] == 1
    assert result["total_open_ports"] == 2
    flagged = {(f["ip"], f["port"]) for f in result["flagged_ports"]}
    assert flagged == {("10.136.28.168", 23)}


def test_custom_risky_ports_replaces_default(tmp_path, registered_handler):
    scan = _write_scan(tmp_path, [
        {"ip": "10.136.28.168", "open_ports": [_port(22, service="ssh"), _port(23, service="telnet")]},
    ])
    # Custom list = only port 22. Port 23 (normally risky by default) must
    # NOT be flagged here -- proves the argument REPLACES, not adds to, the
    # built-in default.
    result = registered_handler(nmap_parsed_file=str(scan), risky_ports=[22])

    assert result["flagged_count"] == 1
    flagged = {(f["ip"], f["port"]) for f in result["flagged_ports"]}
    assert flagged == {("10.136.28.168", 22)}


def test_missing_service_field_still_flagged_by_port_number(tmp_path, registered_handler):
    scan = _write_scan(tmp_path, [
        {"ip": "10.136.28.168", "open_ports": [{"port": 3389, "protocol": "tcp"}]},  # no "service" key at all
    ])
    result = registered_handler(nmap_parsed_file=str(scan))

    assert result["flagged_count"] == 1
    assert result["flagged_ports"][0]["port"] == 3389


def test_multiple_hosts_all_included(tmp_path, registered_handler):
    scan = _write_scan(tmp_path, [
        {"ip": "10.136.28.168", "open_ports": [_port(23, service="telnet")]},
        {"ip": "10.136.28.52", "open_ports": [_port(3389, service="rdp"), _port(80, service="http")]},
    ])
    result = registered_handler(nmap_parsed_file=str(scan))

    assert result["hosts_scanned"] == 2
    assert result["total_open_ports"] == 3
    assert result["flagged_count"] == 2
    flagged = {(f["ip"], f["port"]) for f in result["flagged_ports"]}
    assert flagged == {("10.136.28.168", 23), ("10.136.28.52", 3389)}


def test_host_with_missing_open_ports_key(tmp_path, registered_handler):
    scan = _write_scan(tmp_path, [
        {"ip": "10.136.28.168"},  # no "open_ports" key at all
    ])
    result = registered_handler(nmap_parsed_file=str(scan))

    assert result["hosts_scanned"] == 1
    assert result["total_open_ports"] == 0
    assert result["flagged_count"] == 0
    assert result["flagged_ports"] == []


def test_empty_hosts_list(tmp_path, registered_handler):
    scan = _write_scan(tmp_path, [])
    result = registered_handler(nmap_parsed_file=str(scan))

    assert result["hosts_scanned"] == 0
    assert result["total_open_ports"] == 0
    assert result["flagged_count"] == 0
    assert result["flagged_ports"] == []


def test_port_as_json_string_still_matches(tmp_path, registered_handler):
    # Real edge case: adapters/nmap_parse.py itself falls back to a str
    # portid when int() fails on the raw XML attribute -- a candidate that
    # only does `port in risky_ports` with int-typed risky_ports would
    # silently fail to match a string "23".
    scan = _write_scan(tmp_path, [
        {"ip": "10.136.28.168", "open_ports": [{"port": "23", "protocol": "tcp", "service": "telnet"}]},
    ])
    result = registered_handler(nmap_parsed_file=str(scan))

    assert result["flagged_count"] == 1

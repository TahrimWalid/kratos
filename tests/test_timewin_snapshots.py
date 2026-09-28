"""Snapshot time index, 'state as of', retention (docs/time_window_design.md §7, §17) and
the filename-sort regression found by the functional check (§2.2: scan-summary read an
August scan because 'nmap_kratos_...' sorts after 'nmap_10...')."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.adapters.nmap_parse import find_latest_nmap_xml
from kratos.agent import tools
from kratos.timewin import snapshots as S
from kratos.timewin.claims import verify_claims
from kratos.timewin.windows import TimeContext, reset_current_context, set_current_context

UTC = timezone.utc
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC).timestamp()
DAY = 86400


def _parsed(d: Path, stamp: str, captured: float, ports: list[int], ip="10.0.0.5") -> Path:
    p = d / "scans" / f"parsed_{stamp}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"parsed_at": datetime.fromtimestamp(captured, UTC).isoformat(),
                             "hosts": [{"ip": ip, "open_ports": [{"port": x, "protocol": "tcp", "service": "svc"} for x in ports]}]}))
    os.utime(p, (captured, captured))
    return p


def test_latest_nmap_xml_is_by_time_not_name(tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    old = scans / "nmap_kratos_20260825_110250.xml"
    new = scans / "nmap_10.136.28.168_20260927_150949.xml"
    old.write_text("<nmaprun/>"), new.write_text("<nmaprun/>")
    os.utime(old, (NOW - 30 * DAY, NOW - 30 * DAY))
    os.utime(new, (NOW, NOW))
    assert find_latest_nmap_xml(tmp_path) == new


def test_capture_time_prefers_content_then_filename(tmp_path):
    p = _parsed(tmp_path, "20260101_000000", NOW - 5 * DAY, [22])
    os.utime(p, (NOW, NOW))  # mtime says "now" -- content must win
    s = S.latest(tmp_path, "open_ports")
    assert s.captured_at == pytest.approx(NOW - 5 * DAY) and s.captured_source == "content:parsed_at"
    q = tmp_path / "logs" / "auth_stats_20260920_101500.json"
    q.parent.mkdir()
    q.write_text("{}")
    s2 = S.latest(tmp_path, "auth_stats")
    assert s2.captured_source.startswith("filename")


def test_as_of_returns_the_nearest_earlier_snapshot_and_filters_other_hosts(tmp_path):
    _parsed(tmp_path, "a", NOW - 10 * DAY, [22])
    _parsed(tmp_path, "b", NOW - 3 * DAY, [22, 8080])
    _parsed(tmp_path, "c", NOW - 1 * DAY, [22], ip="10.9.9.9")  # a different host
    s = S.as_of(tmp_path, "open_ports", NOW - 2 * DAY, target="10.0.0.5")
    assert S.summarize(s)["hosts"][0]["open_ports"] == ["22/tcp svc", "8080/tcp svc"]
    assert S.as_of(tmp_path, "open_ports", NOW - 20 * DAY, target="10.0.0.5") is None
    assert [x.captured_at for x in S.within(tmp_path, "open_ports", NOW - 11 * DAY, NOW, target="10.0.0.5")] == \
        [pytest.approx(NOW - 10 * DAY), pytest.approx(NOW - 3 * DAY)]


def test_state_as_of_tool_reports_distance_or_no_record(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "get_active_target", lambda: "10.0.0.5")
    _parsed(tmp_path, "b", time.time() - 3 * DAY, [22, 8080])
    out = tools.tool_state_as_of(tmp_path, "open_ports", at="2 days ago")
    assert out["snapshot"]["state"]["hosts"][0]["open_ports"] == ["22/tcp svc", "8080/tcp svc"]
    assert "1.0 days before" in out["distance"]
    none = tools.tool_state_as_of(tmp_path, "open_ports", at="5 days ago")
    assert none["snapshot"] is None and "no record" in none["note"]


def test_state_claim_must_cite_a_returned_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(tools, "get_active_target", lambda: "10.0.0.5")
    _parsed(tmp_path, "b", time.time() - 3 * DAY, [22])
    ctx = TimeContext(UTC, now=time.time())
    tok = set_current_context(ctx)
    try:
        sid = tools.tool_state_as_of(tmp_path, "open_ports", at="2 days ago")["snapshot"]["snapshot_id"]
    finally:
        reset_current_context(tok)
    ok, _ = verify_claims(ctx, "Port 22 was open.", [{"kind": "state", "snapshot": sid}])
    bad, _ = verify_claims(ctx, "Port 22 was open.", [{"kind": "state", "snapshot": "s00000000"}])
    assert ok == [] and bad


def test_retention_plan_tiers_pins_and_never_deletes_without_apply(tmp_path):
    for age in (1, 40, 40.5, 100, 101, 400, 401):  # days old
        _parsed(tmp_path, f"t{age}", NOW - age * DAY, [22])
    ref = tmp_path / "reports" / "findings_x.json"  # a report that references the 401-day scan
    ref.parent.mkdir()
    ref.write_text(json.dumps({"generated_at": datetime.fromtimestamp(NOW, UTC).isoformat(),
                               "inputs": {"nmap_parsed": "parsed_t401.json"}}))
    plan = S.plan_retention(tmp_path, now=NOW)
    doomed = {Path(x["path"]).name for x in plan["delete"]}
    # the NEWEST snapshot of each bucket is kept: 40 vs 40.5 days (same day) -> 40.5 goes;
    # 100 vs 101 (same week) -> 101 goes; 400 vs 401 (same month) -> 400 is the keeper and
    # 401 is pinned by the report, so nothing goes there
    assert doomed == {"parsed_t40.5.json", "parsed_t101.json"}
    assert all((tmp_path / "scans" / n).exists() for n in doomed)  # plan only
    assert S.apply_retention(tmp_path, plan) == 2
    assert not any((tmp_path / "scans" / n).exists() for n in doomed)


def test_apply_never_touches_files_outside_the_data_dir(tmp_path):
    outside = tmp_path.parent / f"precious_{os.getpid()}.json"
    outside.write_text("{}")
    try:
        removed = S.apply_retention(tmp_path, {"delete": [{"path": str(outside)}]})
        assert removed == 0 and outside.exists()
    finally:
        outside.unlink(missing_ok=True)

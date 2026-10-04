"""A burst finding states the log window its count covers. Seen live (demo pass 3): a
pipeline with no log step correlated a 7-day measurement saved minutes earlier, and
'Bursts of failed SSH logins: 34' (oldest a week back) read like current activity
because no window was shown. The window comes from the read that produced the bursts,
not from whichever auth_stats file happens to be newest."""
from __future__ import annotations

import json
from pathlib import Path

from kratos.adapters import findings_engine as FE

HOST = "ubuntu@203.0.113.5"
_BURST = {"event_type": "ssh_failed_login", "count": 15, "start": "2026-09-28T05:29:25+00:00",
          "end": "2026-09-28T05:34:08+00:00", "top_source_ips": [{"ip": "203.0.113.52", "count": 15}]}
_WEEK = {"source": f"ssh_target_measurement:{HOST}", "events_by_type": {"ssh_failed_login": 311},
         "since": "last 7 days", "since_utc": "2026-09-27T16:29:17+00:00", "until_utc": "2026-10-04T16:29:17+00:00"}


def _write(path: Path, data: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _nmap(tmp_path: Path) -> Path:
    return _write(tmp_path / "scans" / "parsed_20261004_163300.json", {
        "target": "203.0.113.5",
        "hosts": [{"ip": "203.0.113.5", "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]})


def _report(tmp_path: Path, stats: Path, patterns: Path) -> list[dict]:
    json_path, _md = FE.write_findings_report(tmp_path, nmap_parsed_file=_nmap(tmp_path),
                                              auth_stats_file=stats, auth_patterns_file=patterns)
    return json.loads(json_path.read_text())["findings"]


def test_burst_finding_states_the_window_of_its_read(tmp_path):
    logs = tmp_path / "logs"
    stats = _write(logs / "auth_stats_w1_20261004_162929.json", _WEEK)
    patterns = _write(logs / "auth_patterns_w1_20261004_162929.json", {"target": HOST, "bursts": [_BURST]})
    main = next(f for f in _report(tmp_path, stats, patterns) if f["id"] == "CORR-SSH-001")
    assert any(e.startswith("Time window: last 7 days (") for e in main["evidence"])


def test_window_comes_from_the_bursts_own_read_not_a_newer_stats_file(tmp_path):
    logs = tmp_path / "logs"
    _write(logs / "auth_stats_w1_20261004_162929.json", _WEEK)
    patterns = _write(logs / "auth_patterns_w1_20261004_162929.json", {"target": HOST, "bursts": [_BURST]})
    # a later unscoped read saved its stats but is not the read the bursts came from
    newer = _write(logs / "auth_stats_20261004_163500.json", {
        "source": f"ssh_target_journald:{HOST}", "events_by_type": {"ssh_failed_login": 4}, "since": None})
    main = next(f for f in _report(tmp_path, newer, patterns) if f["id"] == "CORR-SSH-001")
    windows = [e for e in main["evidence"] if e.startswith("Time window:")]
    assert windows and windows[0].startswith("Time window: last 7 days (")


def test_bursts_without_a_saved_read_say_the_window_is_unknown():
    out = FE.generate_findings(None, None, {"bursts": [{**_BURST, "event_type": "sudo_auth_failure"}]}, None,
                               auth_patterns_window={})
    auth4 = next(f for f in out if f.id == "AUTH-004")
    assert "Time window: not recorded for these logs" in auth4.evidence

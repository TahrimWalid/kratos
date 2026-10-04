"""An investigation that MEASURED login activity exhaustively must correlate that
measurement, not a sampled journal read saved after it in the same run (seen live: one
answer said 'counted in full' and, in its findings, 'only the newest 500 events
analyzed'); and a measurement's partial coverage is described as the logs not reaching
back far enough -- never as 'only the newest N events'."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from kratos.adapters import findings_engine as FE

HOST = "ubuntu@203.0.113.5"


def _write(path: Path, data: dict, mtime: float) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def _logs(tmp_path: Path, run_start: float):
    logs = tmp_path / "logs"
    measured = _write(logs / "auth_stats_w1_20261004_090700.json", {
        "source": f"ssh_target_measurement:{HOST}", "events_by_type": {"sudo_session_open": 311},
        "since": "last 24 hours", "since_utc": "2026-10-03T09:07:00+00:00", "until_utc": "2026-10-04T09:07:00+00:00",
        "coverage": {"measurement": {"truncated": False}}}, run_start + 10)
    _write(logs / "auth_patterns_w1_20261004_090700.json", {"target": HOST, "bursts": []}, run_start + 10)
    sampled = _write(logs / "auth_stats_20261004_090740.json", {
        "source": f"ssh_target_journald:{HOST}", "events_by_type": {"sudo_session_open": 125},
        "coverage": {"sshd": {"truncated": True, "returned": 500, "oldest_returned": "2026-10-03T16:03:22+00:00"}}},
        run_start + 40)
    _write(logs / "auth_patterns_20261004_090740.json", {"target": HOST, "bursts": []}, run_start + 40)
    return measured, sampled


def test_an_investigations_measurement_beats_a_later_sampled_read(tmp_path):
    run_start = time.time() - 100
    measured, sampled = _logs(tmp_path, run_start)
    plain = FE.find_latest_inputs(tmp_path, target=HOST)
    assert plain["auth_stats"] == sampled                       # recency alone picks the sample
    preferred = FE.find_latest_inputs(tmp_path, target=HOST, prefer_measured_since=run_start)
    assert preferred["auth_stats"] == measured
    assert preferred["auth_patterns"].name == "auth_patterns_w1_20261004_090700.json"   # kept as a pair


def test_a_measurement_from_before_this_investigation_does_not_override(tmp_path):
    run_start = time.time() - 100
    _measured, sampled = _logs(tmp_path, run_start)
    later_start = run_start + 30                                # the measurement predates this run
    assert FE.find_latest_inputs(tmp_path, target=HOST, prefer_measured_since=later_start)["auth_stats"] == sampled


def test_measurement_coverage_is_described_as_how_far_the_logs_go_back():
    findings = FE.generate_findings(None, {
        "source": f"ssh_target_measurement:{HOST}", "events_by_type": {"sudo_session_open": 3},
        "since": "last 24 hours", "since_utc": "2026-10-03T10:38:00+00:00",
        "coverage": {"measurement": {"truncated": True, "returned": 409, "oldest_returned": "2026-10-04T09:07:08+00:00"}},
    }, None, None)
    text = "\n".join(line for f in findings for line in f.evidence)
    assert "the target's logs only go back to 2026-10-04 09:07:08 UTC" in text
    assert "newest 409" not in text
    auth3 = next(f for f in findings if f.id == "AUTH-003")
    assert sum("partial" in line.lower() for line in auth3.evidence) == 1    # stated once, not twice

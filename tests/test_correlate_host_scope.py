"""correlate_findings only uses inputs collected from the machine it reports on.

Live finding (2026-10-03): /investigate-host on Kratos's own machine reported the
lab target's sudo activity (AUTH-003) and coverage note (COV-001), because the
newest auth_stats file in the shared data folder came from an earlier /run
against the target."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from kratos import kratos_config as kc
from kratos.adapters import findings_engine as FE

TARGET = "203.0.113.10"


@pytest.fixture(autouse=True)
def _restore_target():
    before = kc.get_active_target()
    yield
    kc.set_active_target(before)


def _put(path: Path, data, age_s: float = 0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    t = time.time() - age_s
    os.utime(path, (t, t))
    return path


def _target_stats(host=TARGET, sudo=125):
    return {"source": f"ssh_target_measurement:ubuntu@{host}", "total_events": sudo * 2,
            "events_by_type": {"sudo_session_open": sudo, "sudo_session_close": sudo}}


def _local_stats():
    return {"source": "file:/var/log/auth.log", "total_events": 0, "events_by_type": {}}


def test_a_host_investigation_does_not_report_the_targets_auth_data(tmp_path):
    _put(tmp_path / "logs" / "auth_stats_old.json", _local_stats(), age_s=300)
    _put(tmp_path / "logs" / "auth_stats_new.json", _target_stats())          # newest file: the target's
    kc.set_active_target("127.0.0.1")
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert report["inputs"]["auth_stats"] == "auth_stats_old.json"
    assert "AUTH-003" not in [f["id"] for f in report["findings"]]
    kc.set_active_target(TARGET)
    report = json.loads(FE.write_findings_report(tmp_path)[0].read_text())
    assert report["inputs"]["auth_stats"] == "auth_stats_new.json"
    assert "AUTH-003" in [f["id"] for f in report["findings"]]


def test_each_kind_of_input_is_chosen_for_the_active_machine(tmp_path):
    other = "198.51.100.9"
    _put(tmp_path / "scans" / "parsed_mine.json", {"target": TARGET, "hosts": [{"ip": TARGET}]}, age_s=60)
    _put(tmp_path / "scans" / "parsed_other.json", {"target": other, "hosts": [{"ip": other}]})
    _put(tmp_path / "logs" / "auth_patterns_mine.json", {"target": f"ubuntu@{TARGET}", "bursts": []}, age_s=60)
    _put(tmp_path / "logs" / "auth_patterns_other.json", {"target": other, "bursts": []})
    _put(tmp_path / "baseline" / "file_integrity_diff_a_mine.json", {"target": TARGET, "diff": {}}, age_s=60)
    _put(tmp_path / "baseline" / "file_integrity_diff_a_other.json", {"target": other, "diff": {}})
    _put(tmp_path / "context" / "system_context_1.json", {"scope": "local_host"})
    found = FE.find_latest_inputs(tmp_path, TARGET)
    assert found["nmap_parsed"].name == "parsed_mine.json"
    assert found["auth_patterns"].name == "auth_patterns_mine.json"
    assert found["file_integrity"].name == "file_integrity_diff_a_mine.json"
    assert found["system_context"] is None              # Kratos's own host, not this target
    assert FE.find_latest_inputs(tmp_path, "localhost")["system_context"] is not None


def test_a_hostname_target_matches_its_stamped_scan_not_an_ip_guess(tmp_path):
    _put(tmp_path / "scans" / "parsed_1.json", {"target": "Web-01", "hosts": [{"ip": "192.0.2.4"}]})
    assert FE.find_latest_inputs(tmp_path, "web-01")["nmap_parsed"] is not None
    _put(tmp_path / "scans" / "parsed_legacy.json", {"hosts": [{"ip": "192.0.2.4"}]})   # no stamp: by its IPs
    assert FE.find_latest_inputs(tmp_path, "192.0.2.4")["nmap_parsed"].name == "parsed_legacy.json"


def test_files_that_dont_say_which_machine_or_cant_be_read_are_skipped(tmp_path):
    _put(tmp_path / "logs" / "auth_patterns_good.json", {"target": TARGET, "bursts": []}, age_s=120)
    _put(tmp_path / "logs" / "auth_patterns_unknown.json", {"bursts": []}, age_s=60)
    _put(tmp_path / "logs" / "auth_patterns_broken.json", "{oops")
    assert FE.find_latest_inputs(tmp_path, TARGET)["auth_patterns"].name == "auth_patterns_good.json"
    # With no target at all, the newest file is used, as before.
    assert FE.find_latest_inputs(tmp_path, None)["auth_patterns"].name == "auth_patterns_broken.json"


def test_the_pattern_analyzer_stamps_its_machine(tmp_path):
    from kratos.adapters.auth_log_patterns import analyze_auth_patterns

    events = _put(tmp_path / "logs" / "auth_events_1.json", [])
    out = analyze_auth_patterns(tmp_path, events_file=events, target="ubuntu@203.0.113.10")
    assert json.loads(out.read_text())["target"] == "ubuntu@203.0.113.10"
    assert FE.input_hosts("auth_patterns", json.loads(out.read_text())) == {TARGET}


def test_trends_only_follow_the_active_machines_runs(tmp_path):
    from kratos.adapters.logs_trends import build_auth_trends_report

    for i, host in enumerate([TARGET, "198.51.100.9", TARGET, "198.51.100.9"]):
        stats = _target_stats(host)
        stats["events_by_type"] = {"ssh_failed_login": (i + 1) * 10}
        _put(tmp_path / "logs" / f"auth_stats_2026010{i}_000000.json", stats, age_s=100 - i)
    kc.set_active_target(TARGET)
    _json, _md, report = build_auth_trends_report(tmp_path)
    assert report["inputs"]["stats_files"] == ["auth_stats_20260100_000000.json", "auth_stats_20260102_000000.json"]
    assert report["target"] == TARGET

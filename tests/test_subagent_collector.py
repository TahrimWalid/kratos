"""Tests for the target-side read-only telemetry collector (capability 1).
Runs on whatever machine pytest runs on (Linux, per this project's targets)
-- the collector fails soft on anything unavailable, so these tests assert
the "never raises, always returns a well-shaped dict" contract rather than
specific system state."""
from __future__ import annotations

from kratos.subagent import collector


def test_collect_host_info_shape():
    info = collector.collect_host_info()
    assert isinstance(info["hostname"], str) and info["hostname"]
    assert "load_avg" in info and set(info["load_avg"]) == {"1m", "5m", "15m"}


def test_collect_disk_usage_real_root():
    result = collector.collect_disk_usage("/")
    assert result["ok"] is True
    assert result["total_bytes"] > 0
    assert 0 <= result["used_pct"] <= 100


def test_collect_disk_usage_bad_path_fails_soft():
    result = collector.collect_disk_usage("/this/path/does/not/exist/at/all")
    assert result["ok"] is False
    assert "error" in result


def test_collect_listening_ports_never_raises():
    result = collector.collect_listening_ports()
    assert "ok" in result  # either ok=True with a list, or ok=False with an error -- both are the soft-fail contract.


def test_collect_process_count_positive():
    result = collector.collect_process_count()
    if result.get("ok"):
        assert result["process_count"] > 0  # pytest itself is a running process.


def test_collect_service_states_unknown_service_soft_fails():
    result = collector.collect_service_states(["definitely-not-a-real-service-xyz"])
    assert "services" in result
    assert "definitely-not-a-real-service-xyz" in result["services"]


def test_collect_file_hashes_missing_file_is_none_not_error():
    result = collector.collect_file_hashes(["/no/such/file/anywhere"])
    assert result["file_hashes"]["/no/such/file/anywhere"] is None


def test_collect_file_hashes_real_file_matches_hashlib(tmp_path):
    import hashlib

    p = tmp_path / "watched.txt"
    p.write_bytes(b"kratos telemetry test content")
    result = collector.collect_file_hashes([str(p)])
    assert result["file_hashes"][str(p)] == hashlib.sha256(b"kratos telemetry test content").hexdigest()


def test_collect_auth_summary_never_raises():
    result = collector.collect_auth_summary(since_minutes=5)
    assert "since_minutes" in result
    assert result["since_minutes"] == 5


def test_collect_snapshot_has_every_section():
    snap = collector.collect_snapshot(watch_files=[], services=["definitely-not-a-real-service-xyz"], auth_since_minutes=1)
    for key in ("collected_at_epoch", "host", "disk", "listening_ports", "processes", "services", "file_hashes", "auth"):
        assert key in snap


def test_run_fixed_command_missing_binary_soft_fails():
    result = collector._run(["definitely-not-a-real-binary-xyz-12345"])
    assert result["ok"] is False
    assert "not installed" in result["error"]

"""
Sprint 1 backlog #11: OBS-001 ("auth failures + log collection appears inactive")
must not false-positive when system_context is missing — `_is_service_active`
can't distinguish "checked and off" from "never checked". OBS-001 now fires only
when system_context actually carries a services list to assess. Scripted/offline.
"""
from __future__ import annotations

import json
from pathlib import Path

from kratos.adapters.findings_engine import write_findings_report


def _write_auth_stats(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "auth_stats_20260906_120000.json").write_text(
        json.dumps({"events_by_type": {"ssh_failed_login": 4}, "source": "local"}),
        encoding="utf-8")


def _finding_ids(tmp_path: Path) -> list[str]:
    out_json, _ = write_findings_report(tmp_path)
    return [f["id"] for f in json.loads(Path(out_json).read_text())["findings"]]


def test_obs001_suppressed_when_no_system_context(tmp_path):
    # Auth failures present, but no collect_system_context ran -> we can't judge
    # logging state -> OBS-001 must NOT fire (the false positive this fixes).
    _write_auth_stats(tmp_path)
    assert "OBS-001" not in _finding_ids(tmp_path)


def test_obs001_still_fires_when_context_shows_logging_off(tmp_path):
    # system_context present AND shows both logging services inactive -> a real
    # signal -> OBS-001 SHOULD fire (no over-suppression).
    _write_auth_stats(tmp_path)
    ctx = tmp_path / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    (ctx / "system_context_20260906_120000.json").write_text(
        json.dumps({
            "collected_at": "2026-09-06T12:00:00",
            "services": {"units": [
                {"unit": "rsyslog.service", "active": "inactive"},
                {"unit": "systemd-journald.service", "active": "inactive"},
            ]},
        }),
        encoding="utf-8")
    assert "OBS-001" in _finding_ids(tmp_path)


def test_obs001_not_fired_when_logging_active(tmp_path):
    # Regression guard: context present and journald active -> no OBS-001.
    _write_auth_stats(tmp_path)
    ctx = tmp_path / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    (ctx / "system_context_20260906_120000.json").write_text(
        json.dumps({
            "collected_at": "2026-09-06T12:00:00",
            "services": {"units": [{"unit": "systemd-journald.service", "active": "active"}]},
        }),
        encoding="utf-8")
    assert "OBS-001" not in _finding_ids(tmp_path)

"""The `kratos scheduled-run <name>` CLI subcommand (A6.3), what a systemd timer
invokes. No real run: run_scheduled is spied."""
from __future__ import annotations

from kratos.agent import schedules as S
from kratos.cli.app import build_parser, cmd_scheduled_run


def _args(tmp_path, name):
    p = build_parser()
    ns = p.parse_args(["--data-dir", str(tmp_path), "scheduled-run", name])
    assert ns.func is cmd_scheduled_run
    return ns


def test_scheduled_run_cli_success(tmp_path, monkeypatch):
    S.save_schedule(tmp_path, name="wk", kind="audit", cadence="weekly")
    rec = {"schedule": "wk", "status": "completed", "target": "10.0.0.1",
           "severity_tally": {"high": 1}, "omitted_gated_tools": ["run_vuln_scan"],
           "report_md": "/tmp/r.md", "notified": True, "delivered": {"status": "sent"},
           "error": None}
    monkeypatch.setattr("kratos.agent.scheduled_run.run_scheduled", lambda s, d, deliver=True: rec)
    assert cmd_scheduled_run(_args(tmp_path, "wk")) == 0


def test_scheduled_run_cli_missing_schedule(tmp_path):
    assert cmd_scheduled_run(_args(tmp_path, "nope")) == 1


def test_scheduled_run_cli_failed_run_returns_1(tmp_path, monkeypatch):
    S.save_schedule(tmp_path, name="down", kind="audit")
    rec = {"schedule": "down", "status": "aborted", "target": "t", "severity_tally": {},
           "notified": True, "error": "target unreachable"}
    monkeypatch.setattr("kratos.agent.scheduled_run.run_scheduled", lambda s, d, deliver=True: rec)
    assert cmd_scheduled_run(_args(tmp_path, "down")) == 1

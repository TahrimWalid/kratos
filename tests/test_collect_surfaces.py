"""Where the collection layer shows up: kratos collect, kratos events --coverage, /doctor, the settings,
and the standard audit that now runs on it."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from kratos.collect import checks as _register_checks  # noqa: F401 -- register at import, never inside a patched registry
from kratos.collect.sync import settings as _register_sync_settings  # noqa: F401
from kratos import kratos_config, settings_store
from kratos.agent import pipeline
from kratos.collect import registry, runner, state
from kratos.collect.registry import CheckResult
from kratos.collect.sync import cursors
from kratos.target_key import target_key
from tests.test_collect_loop import make_report
from tests.test_collect_runner import dispatch_ok, make_check

TARGET = "10.9.9.9"


@pytest.fixture(autouse=True)
def _collection_on(monkeypatch):
    monkeypatch.delenv("KRATOS_COLLECT", raising=False)


@pytest.fixture
def fake_registry(monkeypatch):
    monkeypatch.setattr(registry, "_CHECKS", {})
    monkeypatch.setattr(settings_store, "_REGISTRY", dict(settings_store._REGISTRY))
    return registry


# ----------------------------------------------------------------------------- the audit
def test_the_standard_audit_runs_every_check_then_one_correlation(tmp_path, fake_registry):
    calls = []
    fake_registry.register(make_check("t_q", run=lambda c: calls.append("q") or CheckResult("ok", "quick fine")))
    fake_registry.register(make_check("t_s", cost="slow", run=lambda c: calls.append("s") or CheckResult("ok", "slow fine")))
    seen = []
    findings = [{"id": "NET-002", "severity": "medium", "title": "Open ports"}]

    def disp(tool, args, dd):
        return {"status": "ok", "result": {"findings": findings, "lifecycle": "New 1"}}

    out = pipeline.run_standard_audit(tmp_path, target=TARGET, dispatch=disp, on_step=lambda sr: seen.append(sr.status))
    assert sorted(calls) == ["q", "s"]                                  # quick AND slow
    assert out.status == "completed" and [f["id"] for f in out.findings] == ["NET-002"]
    assert out.steps[-1].tool == "correlate_findings" and out.lifecycle_line == "New 1"
    assert seen == ["ok", "ok", "ok"]


def test_the_audit_reruns_fresh_checks(tmp_path, fake_registry):
    calls = []
    fake_registry.register(make_check("t_q", run=lambda c: calls.append(1) or CheckResult("ok", "x")))
    for _ in range(2):
        pipeline.run_standard_audit(tmp_path, target=TARGET, dispatch=dispatch_ok)
    assert len(calls) == 2


def test_an_audit_where_nothing_could_be_checked_is_aborted(tmp_path, fake_registry):
    fake_registry.register(make_check("t_q", run=lambda c: CheckResult("failed", "could not be checked")))
    out = pipeline.run_standard_audit(tmp_path, target=TARGET, dispatch=dispatch_ok)
    assert out.status == "aborted" and out.aborted_on == "correlate_findings"
    assert out.steps[0].status == "error"


def test_a_failed_check_does_not_sink_the_audit(tmp_path, fake_registry):
    fake_registry.register(make_check("t_bad", run=lambda c: CheckResult("failed", "could not be checked"), order=1))
    fake_registry.register(make_check("t_ok", run=lambda c: CheckResult("ok", "fine")))
    out = pipeline.run_standard_audit(tmp_path, target=TARGET, dispatch=dispatch_ok)
    assert out.status == "completed" and [s.status for s in out.steps[:2]] == ["error", "ok"]


def test_tools_an_unattended_run_may_not_use_are_left_out(tmp_path):
    from kratos.collect import checks as _c  # noqa: F401

    ran = []

    def disp(tool, args, dd):
        ran.append(tool)
        return {"status": "ok", "result": {"findings": [], "checks": [], "counts": {}}}

    kratos_config.set_active_target(TARGET)
    pipeline.run_standard_audit(tmp_path, target=TARGET, dispatch=disp, skip_tools=frozenset({"run_vuln_scan", "run_yara_scan"}))
    assert "run_vuln_scan" not in ran and "run_yara_scan" not in ran and "run_nmap_scan" in ran


# ----------------------------------------------------------------------------- CLI
def test_kratos_collect_prints_each_check_and_the_findings(tmp_path, monkeypatch, capsys):
    from kratos.cli import app as cli

    monkeypatch.setattr(runner, "prepare", lambda *a, **k: make_report([{"id": "NET-002", "severity": "medium"}]))
    assert cli.main(["--data-dir", str(tmp_path), "collect", "--target", TARGET]) == 0
    out = capsys.readouterr().out
    assert "open ports" in out and "22/tcp ssh" in out and "NET-002 (medium)" in out


def test_kratos_collect_json_and_options(tmp_path, monkeypatch, capsys):
    from kratos.cli import app as cli

    seen = {}
    monkeypatch.setattr(runner, "prepare", lambda *a, **k: seen.update(k) or make_report([]))
    cli.main(["--data-dir", str(tmp_path), "collect", "--target", TARGET, "--all", "--force", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["checks"][0]["name"] == "ports" and seen["force"] is True and seen["classes"] == ("quick", "slow")


def test_kratos_collect_without_a_target_says_so(tmp_path, capsys):
    from kratos.cli import app as cli

    kratos_config.set_active_target(None)
    assert cli.main(["--data-dir", str(tmp_path), "collect"]) == 1


def test_kratos_events_coverage_lists_spans_and_gaps(tmp_path, capsys):
    from kratos.cli import app as cli

    key = target_key(TARGET)
    cursors.add_span(tmp_path, key, "auth", 1_800_000_000, 1_800_003_600, complete=True)
    cursors.add_span(tmp_path, key, "auth", 1_800_003_600, 1_800_007_200, complete=False, note="journal vacuumed")
    cursors.put_cursor(tmp_path, key, "auth", "journal", position=None, behind=True)
    assert cli.main(["--data-dir", str(tmp_path), "events", "--target", TARGET, "--coverage"]) == 0
    out = capsys.readouterr().out
    assert "auth:" in out and "complete" in out and "GAP" in out and "journal vacuumed" in out and "catching up" in out


def test_kratos_events_coverage_with_nothing_synced(tmp_path, capsys):
    from kratos.cli import app as cli

    assert cli.main(["--data-dir", str(tmp_path), "events", "--target", TARGET, "--coverage"]) == 0
    assert "No log sync has run" in capsys.readouterr().out


# ----------------------------------------------------------------------------- /doctor + settings
def test_doctor_row_reports_last_runs_and_logs_behind(tmp_path):
    from kratos.collect import checks as _c  # noqa: F401
    from kratos.collect.report import doctor_row

    kratos_config.set_active_target(TARGET)
    key = target_key(TARGET)
    status, detail = doctor_row(tmp_path)
    assert "never" in detail
    o = state.new_owner()
    state.claim(tmp_path, key, "ports", ttl_seconds=60, stale_claim_seconds=30, owner=o)
    state.finish(tmp_path, key, "ports", owner=o, started_at=time.time() - 600, finished_at=time.time() - 600,
                 status="ok", summary="x", gaps=[])
    cursors.put_cursor(tmp_path, key, "cron", "journal", position=None, behind=True)
    status, detail = doctor_row(tmp_path)
    assert "ports: 10 min ago" in detail and "Still catching up: cron" in detail


def test_doctor_has_a_collection_row(tmp_path, monkeypatch):
    from kratos.adapters import ssh_remote
    from kratos.adapters.ssh_remote import SSHResult
    from kratos.agent import doctor

    kratos_config.set_active_target(TARGET)
    monkeypatch.setattr(ssh_remote, "run_target_probe_checks",
                        lambda: SSHResult(ok=False, returncode=255, stdout="", stderr="ssh: unreachable"))
    rows = {r["check"]: r for r in doctor.run_diagnostics(tmp_path)}
    assert "collection" in rows and rows["collection"]["status"] in ("pass", "warn", "info")


def test_the_collection_settings_validate():
    from kratos.collect import checks as _c  # noqa: F401
    from kratos.collect import settings as CS

    spec = {s.key: s for s in settings_store.specs()}
    assert spec[CS.ENABLED].default is True and spec[CS.START_BUDGET].default == 15
    assert spec["collect.ttl.ports_minutes"].default == 60 and spec["collect.ttl.auth_activity_minutes"].default == 15
    assert spec["collect.ttl.config_audit_minutes"].default == 360
    for key, bad in ((CS.START_BUDGET, 0), (CS.START_BUDGET, "soon"), (CS.START_BUDGET, 10_000),
                     ("collect.ttl.ports_minutes", 0), (CS.ENABLED, "maybe")):
        with pytest.raises(settings_store.SettingError):
            spec[key].validate(bad)


def test_turning_collection_off_in_settings_skips_it(tmp_path, monkeypatch):
    from kratos.agent import loop
    from kratos.collect import settings as CS

    kratos_config.set_active_target(TARGET)
    monkeypatch.setattr("kratos.collect.runner.prepare", lambda *a, **k: pytest.fail("collection should be off"))
    settings_store.set(CS.ENABLED, "off", data_dir=tmp_path, actor="test")
    assert loop._collect_first(tmp_path, None) is None


def test_no_agent_tool_can_change_the_collection_settings():
    from kratos.agent.tools import TOOL_REGISTRY
    import inspect

    for name, tool in TOOL_REGISTRY.items():
        try:
            src = inspect.getsource(inspect.getmodule(tool.handler))
        except (OSError, TypeError):
            continue
        assert "settings_store.set(" not in src, name


def test_the_session_screen_shows_the_one_line_summary(tmp_path):
    """The step the loop records is what the TUI renders: a note line, not the individual tool calls."""
    from kratos.tui_mk2.screens import session as S

    src = Path(S.__file__).read_text()
    assert 'step.get("status") == "collection"' in src and "summary_line" in src

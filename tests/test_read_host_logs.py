"""read_host_logs: a summary of one log source in a window -- counts, tops, a few
masked lines, what was covered -- events stored, and every gap stated as a
coverage_gap the final answer has to mention."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest

from kratos import kratos_config
from kratos.adapters.ssh_remote import SSHResult
from kratos.agent import tools
from kratos.events.store import EventStore
from kratos.logsources import logread
from kratos.run_context import run_scope
from tests._logsources_util import awks, bindir, make_root, run_sh

TARGET = "10.136.28.102"
NOW = datetime(2026, 10, 11, 18, 0, tzinfo=timezone.utc).timestamp()
pytestmark = pytest.mark.skipif(not awks(), reason="no awk")


def _fake_fetch(tmp_path, family, files, *, via="ssh"):
    def fetch(source, since, until, lines=5000):
        root = make_root(tmp_path / f"r{source}", family, files)
        r = run_sh(logread.build_script(source, since, until, journal_prefix="", root=str(root)),
                   bindir(tmp_path, awks()[0]), now=NOW)
        read = logread.parse_output(source, r.stdout, since, until)
        read.via = via
        return read
    return fetch


@pytest.fixture
def target(monkeypatch):
    kratos_config.set_active_target(f"ubuntu@{TARGET}")
    monkeypatch.setattr(tools, "_measure_target_clock_offset", lambda: 0.0)


def _call(tmp_path, source, **kw):
    with run_scope("cli"):
        return tools.tool_read_host_logs(tmp_path, source, since="2026-09-01 00:00", **kw)


def test_web_summary_masks_and_stores(tmp_path, target, monkeypatch):
    monkeypatch.setattr(tools, "_fetch_host_logs", _fake_fetch(
        tmp_path, "debian", {"/var/log/nginx/access.log": "@nginx_access.log", "/var/log/nginx/error.log": "@nginx_error.log"}))
    out = _call(tmp_path, "web")
    assert out["status"] == "ok" and out["source"] == "web" and out["events"] == 6
    assert out["by_action"] == {"http_request": 5, "web_error": 1}
    assert out["top_source_ips"][0] == {"value": "10.136.28.52", "count": 4}
    assert {"value": 404, "count": 3} in out["top_status_codes"]
    text = json.dumps(out)
    assert "hunter2" not in text and "abc123secret" not in text      # masked everywhere the model looks
    assert out["coverage"]["complete"] and "coverage_gap" not in out
    assert EventStore(tmp_path / "kratos.db").count(TARGET, dataset="kratos.web") == 6


def test_unreadable_file_is_a_coverage_gap_with_the_fix(tmp_path, target, monkeypatch):
    def fetch(source, since, until, lines=5000):
        stdout = ("M\tfamily\tdebian\nM\ttz_name\tEtc/UTC\nM\ttz_offset\t+0000\nM\tjournal\t1\n"
                  "F\t0\t0\t/var/log/audit/audit.log\tunreadable\tdirectory\n")
        return logread.parse_output(source, stdout, since, until)
    monkeypatch.setattr(tools, "_fetch_host_logs", fetch)
    out = _call(tmp_path, "auditd")
    assert out["status"] == "ok" and out["events"] == 0
    assert "audit.log" in out["coverage_gap"] and "log_group = adm" in out["coverage_gap"]
    assert out["coverage"]["files_not_readable"][0]["why"] == "its directory isn't readable"


def test_family_gap_is_stated(tmp_path, target, monkeypatch):
    monkeypatch.setattr(tools, "_fetch_host_logs", _fake_fetch(tmp_path, "alpine", {}))
    out = _call(tmp_path, "packages")
    assert "apk keeps no install history log on Alpine" in out["coverage_gap"]


def test_nothing_on_the_machine_says_so(tmp_path, target, monkeypatch):
    monkeypatch.setattr(tools, "_fetch_host_logs", _fake_fetch(tmp_path, "debian", {}))
    out = _call(tmp_path, "web")
    assert out["events"] == 0 and "no such log at the usual place" in out["coverage_gap"]
    assert "somewhere else" in out["coverage_gap"]           # says what was really not looked at


def test_old_agent_is_a_coverage_gap_not_a_crash(tmp_path, target, monkeypatch):
    monkeypatch.setattr(tools, "_fetch_host_logs", lambda *a, **k: SSHResult(
        ok=False, returncode=-1, stdout="", via="subagent",
        stderr="via the sub-agent: this box runs sub-agent 0.3.5; the log_read read needs 0.4.0 or newer -- "
               "update the agent (`g` in /subagent, select the box). Nothing was read for this part."))
    out = _call(tmp_path, "cron")
    assert out["status"] == "error"
    assert "`g` in /subagent" in out["coverage_gap"] and "were NOT read" in out["coverage_gap"]


def test_unknown_source_and_bad_window(tmp_path, target):
    assert tools.tool_read_host_logs(tmp_path, "/etc/shadow")["status"] == "error"
    assert "invalid time window" in tools.tool_read_host_logs(tmp_path, "cron", since="next tuesday-ish")["observation"]


def test_no_window_means_the_last_24_hours(tmp_path, target, monkeypatch):
    seen = {}

    def fetch(source, since, until, lines=5000):
        seen.update(since=since, until=until)
        return logread.parse_output(source, "M\tfamily\tdebian\n", since, until)

    monkeypatch.setattr(tools, "_fetch_host_logs", fetch)
    out = tools.tool_read_host_logs(tmp_path, "systemd")
    assert abs(seen["since"] - (time.time() - 86400)) < 60 and seen["until"] is None
    assert out["window"]["asked"] == "the last 24 hours (no window given)"


def test_packages_notable_lines_name_what_changed(tmp_path, target, monkeypatch):
    monkeypatch.setattr(tools, "_fetch_host_logs", _fake_fetch(
        tmp_path, "debian", {"/var/log/dpkg.log": "@dpkg.log", "/var/log/apt/history.log": "@apt_history.log"}))
    out = _call(tmp_path, "packages")
    assert any("sl:amd64" in ln or "apt-get install -y -q sl" in ln for ln in out["notable_lines"])
    assert {"value": "sl", "count": 2} in out["top_packages"]


def test_the_tool_is_offered_and_read_only():
    from kratos.agent.loop import _SSH_READ_TOOLS
    from kratos.agent.tool_summaries import human_summary

    t = tools.TOOL_REGISTRY["read_host_logs"]
    assert not t.requires_approval and "SSH TARGET DEVICE" in t.description
    assert "read_host_logs" in _SSH_READ_TOOLS and human_summary("read_host_logs")


def test_older_rotations_not_read_make_the_early_window_unknown(tmp_path, target, monkeypatch):
    monkeypatch.setattr(tools, "_fetch_host_logs", _fake_fetch(
        tmp_path, "rhel", {"/var/log/cron": "@rhel_cron.log", "/var/log/cron-20260913.gz": b"\x1f\x8b"}))
    out = _call(tmp_path, "cron")
    assert out["events"] == 12
    assert "cron-20260913.gz" in out["coverage_gap"] and "earlier part of the window is unknown" in out["coverage_gap"]
    assert not out["coverage"]["window_fully_covered"]


def test_kratos_own_sudo_reads_are_counted_apart(tmp_path, target, monkeypatch):
    lines = ("Oct 11 17:42:52 h sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/journalctl --no-pager -o json\n"
             "Oct 11 17:43:00 h sudo:   ubuntu : PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt install nmap\n"
             "Oct 11 17:44:00 h sudo:   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/journalctl\n")
    monkeypatch.setattr(tools, "_fetch_host_logs", _fake_fetch(tmp_path, "alpine", {"/var/log/messages": lines}))
    monkeypatch.setattr(kratos_config, "ssh_user_for", lambda *a, **k: "ubuntu")
    out = _call(tmp_path, "sudo")
    assert out["kratos_own_reads"]["count"] == 1
    assert out["by_action"] == {"sudo_command": 2}
    cmds = {t["value"] for t in out["top_commands"]}
    assert cmds == {"/usr/bin/apt install nmap", "/usr/bin/journalctl"}   # alice's journalctl is NOT Kratos's

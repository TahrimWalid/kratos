"""Regression tests for the journald time-window bug (docs/time_window_design.md, step 1).

The live bug: `journalctl --since X -n N` returns the OLDEST N entries after X on
systemd 249 (Ubuntu 22.04) but the NEWEST N on systemd 255. Kratos assumed "newest",
so on 22.04 targets a time-scoped read silently dropped the most recent activity --
including an in-progress SSH brute force -- whenever the window held more than N
lines. `_FakeJournal` below reproduces both systemd behaviors from the actual
command string, so these tests fail against the old query and pass against the new.
"""
from __future__ import annotations

import json
import shlex
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest


@pytest.fixture(autouse=True)
def _fresh_clock_offset_cache():
    ssh_remote._clock_offset_cache.clear()
    yield
    ssh_remote._clock_offset_cache.clear()

from kratos import kratos_config as _kconfig
from kratos.adapters import ssh_remote
from kratos.adapters.ssh_remote import SSHResult
from kratos.agent import tools
from kratos.utils.time_window import TimeBoundError, resolve_time_bound

NY = ZoneInfo("America/New_York")
UTC = ZoneInfo("UTC")
# US spring-forward day: 02:00 -> 03:00, so naive hour math is off by one.
DST_NOW = datetime(2026, 3, 8, 10, 30, tzinfo=NY)


# ---------------------------------------------------------------------------
# resolve_time_bound -- Kratos-side resolution, DST-correct
# ---------------------------------------------------------------------------
def _r(value: str) -> datetime:
    return datetime.fromtimestamp(resolve_time_bound(value, now=DST_NOW, tz=NY), tz=NY)


def test_hours_are_exact_elapsed_time_across_dst():
    got = _r("24 hours ago")
    assert (DST_NOW.astimezone(UTC) - got.astimezone(UTC)).total_seconds() == 24 * 3600
    assert got == datetime(2026, 3, 7, 9, 30, tzinfo=NY)  # NOT 10:30 -- that would be 23 real hours


@pytest.mark.parametrize("value", ["36 hours ago", "36h ago", "-36h", "- 36 hours", "36 hrs ago"])
def test_relative_hour_spellings(value):
    assert (DST_NOW.astimezone(UTC) - _r(value).astimezone(UTC)).total_seconds() == 36 * 3600


def test_days_are_same_local_wall_clock_time():
    assert _r("3 days ago") == datetime(2026, 3, 5, 10, 30, tzinfo=NY)
    assert _r("1 week ago") == datetime(2026, 3, 1, 10, 30, tzinfo=NY)


def test_today_and_yesterday_are_local_midnights():
    assert _r("today") == datetime(2026, 3, 8, 0, 0, tzinfo=NY)
    assert _r("yesterday") == datetime(2026, 3, 7, 0, 0, tzinfo=NY)


def test_iso_without_offset_is_display_timezone_and_with_offset_is_respected():
    assert _r("2026-03-07 09:00") == datetime(2026, 3, 7, 9, 0, tzinfo=NY)
    assert _r("2026-03-07") == datetime(2026, 3, 7, 0, 0, tzinfo=NY)
    assert _r("2026-03-07T14:00:00Z").astimezone(UTC) == datetime(2026, 3, 7, 14, 0, tzinfo=UTC)
    assert resolve_time_bound("@1700000000", now=DST_NOW, tz=NY) == 1700000000.0


@pytest.mark.parametrize("value", [
    "2 months ago", "1 year ago", "recently", "a few days ago", "last week",
    "tomorrow", "", "   ", "12 fortnights ago", "@notanumber",
])
def test_ambiguous_or_unsupported_values_are_rejected_not_guessed(value):
    with pytest.raises(TimeBoundError):
        resolve_time_bound(value, now=DST_NOW, tz=NY)


def test_future_bounds_are_rejected():
    with pytest.raises(TimeBoundError, match="future"):
        resolve_time_bound("2026-03-09", now=DST_NOW, tz=NY)


# ---------------------------------------------------------------------------
# Fake journalctl that honors the real flags with version-specific -n semantics
# ---------------------------------------------------------------------------
class _FakeJournal:
    """Serves a synthetic journal from the actual command string Kratos builds."""

    def __init__(self, entries: list[dict], systemd: int, clock_offset: float = 0.0):
        self.entries = sorted(entries, key=lambda e: int(e["__REALTIME_TIMESTAMP"]))
        self.systemd = systemd
        self.clock_offset = clock_offset  # target clock minus real time
        self.commands: list[str] = []

    def __call__(self, command: str, timeout=None) -> SSHResult:
        if command.strip() == "date +%s.%N":
            import time as _t
            return SSHResult(ok=True, returncode=0, stdout=f"{_t.time() + self.clock_offset:.6f}\n", stderr="")
        self.commands.append(command)
        argv = shlex.split(command)
        argv = argv[argv.index("journalctl") + 1:]  # sudo's own "-n" is not journalctl's
        since = until = n = None
        reverse = False
        comms: list[str] = []
        i = 0
        while i < len(argv):
            a = argv[i]
            if a == "--since":
                since = argv[i + 1]; i += 1
            elif a == "--until":
                until = argv[i + 1]; i += 1
            elif a == "-n":
                n = int(argv[i + 1]); i += 1
            elif a == "--reverse":
                reverse = True
            elif a.startswith("_COMM="):
                comms.append(a.split("=", 1)[1])  # repeated field = OR, as in journalctl
            i += 1
        assert since is None or since.startswith("@"), f"relative since sent to target: {since!r}"
        assert until is None or until.startswith("@"), f"relative until sent to target: {until!r}"
        rows = [e for e in self.entries
                if (not comms or e.get("_COMM") in comms)
                and (since is None or int(e["__REALTIME_TIMESTAMP"]) >= int(since[1:]) * 1_000_000)
                and (until is None or int(e["__REALTIME_TIMESTAMP"]) <= int(until[1:]) * 1_000_000)]
        if reverse:
            rows = list(reversed(rows))
            if n is not None:
                rows = rows[:n]
        elif n is not None:
            # The bug: with --since, systemd 249 limits FORWARD from the since-point.
            rows = rows[:n] if (since is not None and self.systemd <= 249) else rows[-n:]
        return SSHResult(ok=True, returncode=0, stdout="\n".join(json.dumps(r) for r in rows), stderr="")


def _journal(noise: int, attack: int, t0: int = 1_790_000_000) -> list[dict]:
    """`noise` benign sshd lines first, then an `attack` burst as the NEWEST lines."""
    rows = [{"__REALTIME_TIMESTAMP": str((t0 + k) * 1_000_000), "_COMM": "sshd",
             "SYSLOG_IDENTIFIER": "sshd", "_SYSTEMD_UNIT": "session-1.scope",
             "MESSAGE": "pam_unix(sshd:session): session opened for user ubuntu", "PRIORITY": "6"}
            for k in range(noise)]
    rows += [{"__REALTIME_TIMESTAMP": str((t0 + noise + k) * 1_000_000), "_COMM": "sshd",
              "SYSLOG_IDENTIFIER": "sshd", "_SYSTEMD_UNIT": "ssh.service",
              "MESSAGE": f"Invalid user eviltest from 10.66.66.66 port {40000 + k}", "PRIORITY": "5"}
             for k in range(attack)]
    return rows


def test_fake_journal_reproduces_the_original_bug_on_249():
    """Sanity: the OLD query shape really does miss the attack on 249 but not 255."""
    journal = _journal(noise=600, attack=5)
    old_cmd = "sudo -n journalctl --no-pager -o json _COMM=sshd --since @1790000000 -n 500"
    for systemd, attack_seen in ((249, False), (255, True)):
        out = _FakeJournal(journal, systemd)(old_cmd).stdout
        assert ("10.66.66.66" in out) is attack_seen


@pytest.mark.parametrize("systemd", [249, 255])
def test_primary_query_returns_newest_entries_and_flags_truncation(systemd):
    fake = _FakeJournal(_journal(noise=600, attack=5), systemd)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        entries, window = ssh_remote.fetch_journalctl_entries(None, 1_790_000_000, 200)
    cmd = fake.commands[0]
    assert "--since @1790000000" in cmd and "--reverse" in cmd and "-n 201" in cmd
    assert len(entries) == 200
    assert "10.66.66.66" in entries[-1]["message"]  # newest attack line present, last in order
    assert [e["timestamp"] for e in entries] == sorted(e["timestamp"] for e in entries)  # chronological
    assert window.truncated is True and window.returned == 200


@pytest.mark.parametrize("systemd", [249, 255])
def test_primary_query_not_truncated_when_window_fits(systemd):
    fake = _FakeJournal(_journal(noise=10, attack=3), systemd)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        entries, window = ssh_remote.fetch_journalctl_entries(None, 1_790_000_000, 200)
    assert len(entries) == 13 and window.truncated is False


def test_until_bound_closes_the_window():
    fake = _FakeJournal(_journal(noise=100, attack=5), 249)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        entries, window = ssh_remote.fetch_journalctl_entries(
            None, 1_790_000_000, 500, until_epoch=1_790_000_050
        )
    assert "--until @1790000050" in fake.commands[0]
    assert len(entries) == 51 and not any("10.66.66.66" in e["message"] for e in entries)


@pytest.mark.parametrize("systemd", [249, 255])
def test_correlation_auth_fetch_keeps_the_newest_burst(systemd, monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    fake = _FakeJournal(_journal(noise=600, attack=5), systemd)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        entries, errors, windows = ssh_remote.fetch_journalctl_auth_entries(
            max_lines_per_identifier=500, since_epoch=1_790_000_000
        )
    assert errors == []
    assert sum("10.66.66.66" in msg for _, _, msg in entries) == 5
    assert windows["sshd"].truncated is True and windows["sshd"].returned == 500
    assert all("--reverse" in c and "-n 501" in c and "--since @1790000000" in c for c in fake.commands)


# ---------------------------------------------------------------------------
# Tool layer: validation before any SSH, coverage reported, findings disclose it
# ---------------------------------------------------------------------------
def test_tool_rejects_ambiguous_window_before_any_ssh(tmp_path):
    with patch.object(ssh_remote, "run_remote_command") as ssh:
        out = tools.tool_read_journalctl(tmp_path, since="a few days ago")
    assert out["status"] == "error" and "invalid time window" in out["observation"]
    ssh.assert_not_called()


def test_tool_rejects_inverted_window(tmp_path):
    with patch.object(ssh_remote, "run_remote_command") as ssh:
        out = tools.tool_read_journalctl(tmp_path, since="2 hours ago", until="3 hours ago")
    assert out["status"] == "error" and "not before" in out["observation"]
    ssh.assert_not_called()


def test_tool_reports_truncated_coverage_and_persists_it(tmp_path, monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    fake = _FakeJournal(_journal(noise=600, attack=5, t0=1_789_990_000), 249)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        out = tools.tool_read_journalctl(tmp_path, since="@1789990000", lines=100)
    assert out["status"] == "ok"
    assert out["window"]["truncated"] is True and "NOT seen" in out["window"]["coverage"]
    stats_file = Path(out["auth_correlation_data"]["stats_file"])
    stats = json.loads(stats_file.read_text())
    assert stats["coverage"]["sshd"]["truncated"] is True
    assert stats["since_utc"] is not None
    # the burst reached the correlation input (the actual detection path)
    events = json.loads(Path(out["auth_correlation_data"]["events_file"]).read_text())
    assert sum(1 for e in events if "10.66.66.66" in json.dumps(e)) == 5


def test_findings_evidence_states_partial_coverage(tmp_path, monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    fake = _FakeJournal(_journal(noise=600, attack=5, t0=1_789_990_000), 249)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        tools.tool_read_journalctl(tmp_path, since="@1789990000", lines=50)
    report = tools.tool_correlate_findings(tmp_path)
    evidence = " ".join(" ".join(f.get("evidence") or []) for f in report["findings"])
    assert "Coverage: PARTIAL" in evidence and "sshd: only the newest 500 events analyzed" in evidence
    assert any(f["id"] == "COV-001" for f in report["findings"])
    # and the burst itself still produced the attributed burst finding
    assert any(f["id"] == "AUTH-004" and "10.66.66.66" in " ".join(f["evidence"]) for f in report["findings"])


def test_openssh_98_sshd_session_lines_reach_the_correlation_feed(monkeypatch):
    """OpenSSH >= 9.8 logs auth failures from `sshd-session`, not `sshd`."""
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    journal = _journal(noise=3, attack=5)
    for row in journal:
        if "10.66.66.66" in row["MESSAGE"]:
            row["_COMM"] = row["SYSLOG_IDENTIFIER"] = "sshd-session"
    fake = _FakeJournal(journal, 252)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        entries, errors, _ = ssh_remote.fetch_journalctl_auth_entries(since_epoch=1_790_000_000)
    assert errors == [] and sum("10.66.66.66" in m for _, _, m in entries) == 5
    assert "_COMM=sshd _COMM=sshd-session" in fake.commands[0]


def test_skewed_target_clock_window_is_shifted_and_reported(tmp_path, monkeypatch):
    """Live incident: target 7 min behind -> 'last 5 minutes' saw 0 of 8 fresh attack
    lines and the answer was 'no failed SSH logins'. The window must be shifted into
    the target's clock and the skew surfaced."""
    import time as _t
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    skew = -420.0
    now_target = int(_t.time() + skew)
    journal = _journal(noise=3, attack=4, t0=now_target - 60)  # attack stamped ~1 min ago, TARGET clock
    fake = _FakeJournal(journal, 249, clock_offset=skew)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        out = tools.tool_read_journalctl(tmp_path, since="5 minutes ago", lines=200)
    assert sum("10.66.66.66" in e["message"] for e in out["entries"]) == 4
    w = out["window"]
    assert abs(w["target_clock_offset_s"] - skew) < 2 and "behind" in w["clock"]
    sent = int(fake.commands[-1].split("--since @")[1].split()[0])
    assert abs(sent - (_t.time() - 300 + skew)) < 5  # bound shifted into target time


def test_no_clock_warning_when_clocks_agree(tmp_path, monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    fake = _FakeJournal(_journal(noise=3, attack=1), 249, clock_offset=0.3)
    with patch.object(ssh_remote, "run_remote_command", side_effect=fake):
        out = tools.tool_read_journalctl(tmp_path, since="1 hour ago")
    assert "clock" not in out["window"] and abs(out["window"]["target_clock_offset_s"]) < 2


def test_unmeasurable_clock_is_disclosed_not_assumed(tmp_path, monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    fake = _FakeJournal(_journal(noise=3, attack=1), 249)

    def _no_date(command, timeout=None):
        if command.strip() == "date +%s.%N":
            return SSHResult(ok=False, returncode=1, stdout="", stderr="date: not found")
        return fake(command, timeout)

    with patch.object(ssh_remote, "run_remote_command", side_effect=_no_date):
        out = tools.tool_read_journalctl(tmp_path, since="1 hour ago")
    assert out["window"]["target_clock_offset_s"] is None and "NOT corrected" in out["window"]["clock"]


def test_offset_measured_once_per_target_then_cached(monkeypatch):
    calls = []

    def _date(command, timeout=None):
        calls.append(command)
        import time as _t
        return SSHResult(ok=True, returncode=0, stdout=f"{_t.time():.3f}", stderr="")

    with patch.object(ssh_remote, "run_remote_command", side_effect=_date):
        ssh_remote.measure_target_clock_offset()
        ssh_remote.measure_target_clock_offset()
    assert len(calls) == 1

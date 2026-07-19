"""
Mocked/scripted tests for the target onboarding feature (2026-07-18):
adapters/target_setup.py's checklist generator and adapters/ssh_remote.py's
run_target_probe_checks + the journalctl sudo/group-membership toggle
(kratos_config.py::JOURNALCTL_USE_SUDO).

No real SSH/target involved here -- run_remote_command/run_remote_script are
monkeypatched throughout, matching the project's existing convention for
pure-logic/parsing coverage (see test_agent_loop_guards.py). Real-target
verification (against 10.136.28.168) is tracked separately, not duplicated
here.
"""
from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

from kratos import kratos_config as _kconfig
from kratos.adapters import target_setup
from kratos.adapters import ssh_remote
from kratos.adapters.ssh_remote import SSHResult


# ---------------------------------------------------------------------------
# _detect_local_ip
# ---------------------------------------------------------------------------
def test_detect_local_ip_returns_ipv4_or_none():
    # 8.8.8.8 is a literal IP -- no DNS involved, just a routing-table
    # lookup via UDP connect() (never sends a packet). Sandboxes with no
    # configured route at all are a legitimate None outcome, not a bug --
    # assert the shape, not a specific value.
    result = target_setup._detect_local_ip("8.8.8.8")
    assert result is None or re.match(r"^\d+\.\d+\.\d+\.\d+$", result)


def test_detect_local_ip_none_on_unresolvable_host():
    result = target_setup._detect_local_ip("this-host-does-not-resolve.invalid")
    assert result is None


# ---------------------------------------------------------------------------
# generate_target_setup_checklist
# ---------------------------------------------------------------------------
def test_checklist_contains_group_membership_not_just_sudo():
    checklist = target_setup.generate_target_setup_checklist("192.0.2.10")
    assert "usermod -aG systemd-journal" in checklist
    assert _kconfig.SSH_TARGET_USER in checklist


def test_checklist_contains_all_four_setup_categories():
    checklist = target_setup.generate_target_setup_checklist("192.0.2.10")
    assert "authorized_keys" in checklist  # 1. SSH key
    assert "systemd-journal" in checklist  # 2. journalctl access
    assert "/etc/sudoers.d/kratos" in checklist  # 3. sudo NOPASSWD
    assert "apt-get install -y yara lsof" in checklist  # 3b. binaries
    assert "ufw allow from" in checklist  # 4. firewall
    assert "ignoreip" in checklist  # 4b. fail2ban


def test_checklist_uses_real_pubkey_content_when_readable(tmp_path, monkeypatch):
    fake_key_path = tmp_path / "id_ed25519"
    fake_pub_path = tmp_path / "id_ed25519.pub"
    fake_pub_path.write_text("ssh-ed25519 AAAAFAKEKEYCONTENT test@kratos\n")
    monkeypatch.setattr(target_setup, "SSH_TARGET_KEY_PATH", fake_key_path)

    checklist = target_setup.generate_target_setup_checklist("192.0.2.10")
    assert "ssh-ed25519 AAAAFAKEKEYCONTENT test@kratos" in checklist


def test_checklist_falls_back_cleanly_when_pubkey_missing(tmp_path, monkeypatch):
    missing_key_path = tmp_path / "does_not_exist"
    monkeypatch.setattr(target_setup, "SSH_TARGET_KEY_PATH", missing_key_path)

    checklist = target_setup.generate_target_setup_checklist("192.0.2.10")
    assert "could not read" in checklist
    assert "paste your real public key here" in checklist


def test_checklist_falls_back_cleanly_when_ip_detection_fails(monkeypatch):
    monkeypatch.setattr(target_setup, "_detect_local_ip", lambda host: None)
    checklist = target_setup.generate_target_setup_checklist("192.0.2.10")
    assert "KRATOS_HOST_IP -- could not auto-detect" in checklist
    # The placeholder must land in BOTH the firewall rule and the fail2ban
    # note -- a real bug class would be silently emitting an empty string
    # into one but not the other.
    assert checklist.count("KRATOS_HOST_IP") == 2


def test_checklist_uses_detected_ip_in_both_firewall_and_fail2ban_lines(monkeypatch):
    monkeypatch.setattr(target_setup, "_detect_local_ip", lambda host: "10.136.28.1")
    checklist = target_setup.generate_target_setup_checklist("10.136.28.168")
    assert "ufw allow from 10.136.28.1 to any port 22 proto tcp" in checklist
    assert "ignoreip = 127.0.0.1/8 ::1 10.136.28.1" in checklist


# ---------------------------------------------------------------------------
# run_target_probe_checks
# ---------------------------------------------------------------------------
def test_probe_parses_tab_separated_output():
    fake_stdout = (
        "ssh_reachable\tPASS\tConnected as ubuntu\n"
        "journalctl_access\tPASS\tIn systemd-journal group -- no sudo needed for journalctl\n"
        "sudo_sshd_config\tFAIL\tsudo -n sshd -T not permitted -- run_config_audit will report ssh_root_login/ssh_password_auth as UNKNOWN\n"
        "yara_installed\tUNKNOWN\tcommand not checked\n"
    )
    with patch.object(ssh_remote, "run_remote_script", return_value=SSHResult(ok=True, returncode=0, stdout=fake_stdout, stderr="")):
        checks = ssh_remote.run_target_probe_checks()

    assert isinstance(checks, list)
    assert len(checks) == 4
    by_id = {c["check"]: c for c in checks}
    assert by_id["ssh_reachable"]["status"] == "PASS"
    assert by_id["sudo_sshd_config"]["status"] == "FAIL"
    assert "run_config_audit" in by_id["sudo_sshd_config"]["detail"]


def test_probe_returns_sshresult_on_connection_failure():
    failure = SSHResult(ok=False, returncode=-1, stdout="", stderr="ssh: connect to host 10.0.0.99 port 22: Connection refused")
    with patch.object(ssh_remote, "run_remote_script", return_value=failure):
        result = ssh_remote.run_target_probe_checks()

    assert isinstance(result, SSHResult)
    assert not result.ok


# ---------------------------------------------------------------------------
# journalctl sudo <-> group-membership toggle (kratos_config.JOURNALCTL_USE_SUDO)
# ---------------------------------------------------------------------------
def test_journalctl_prefix_uses_sudo_by_default(monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    assert ssh_remote._journalctl_prefix() == ["sudo", "-n"]


def test_journalctl_prefix_empty_when_disabled(monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", False)
    assert ssh_remote._journalctl_prefix() == []


def test_fetch_journalctl_entries_omits_sudo_when_disabled(monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", False)
    captured = {}

    def _fake_run_remote_command(command, timeout=None):
        captured["command"] = command
        return SSHResult(ok=True, returncode=0, stdout="", stderr="")

    with patch.object(ssh_remote, "run_remote_command", side_effect=_fake_run_remote_command):
        ssh_remote.fetch_journalctl_entries(unit=None, since=None, lines=10)

    assert not captured["command"].startswith("sudo")
    assert captured["command"].startswith("journalctl")


def test_fetch_journalctl_entries_keeps_sudo_by_default(monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", True)
    captured = {}

    def _fake_run_remote_command(command, timeout=None):
        captured["command"] = command
        return SSHResult(ok=True, returncode=0, stdout="", stderr="")

    with patch.object(ssh_remote, "run_remote_command", side_effect=_fake_run_remote_command):
        ssh_remote.fetch_journalctl_entries(unit=None, since=None, lines=10)

    assert captured["command"].startswith("sudo -n journalctl")


def test_fetch_journalctl_auth_entries_omits_sudo_when_disabled(monkeypatch):
    monkeypatch.setattr(_kconfig, "JOURNALCTL_USE_SUDO", False)
    captured = []

    def _fake_run_remote_command(command, timeout=None):
        captured.append(command)
        return SSHResult(ok=True, returncode=0, stdout="", stderr="")

    with patch.object(ssh_remote, "run_remote_command", side_effect=_fake_run_remote_command):
        ssh_remote.fetch_journalctl_auth_entries()

    assert len(captured) == 2  # sshd + sudo identifiers
    assert all(not cmd.startswith("sudo") for cmd in captured)
    assert all(cmd.startswith("journalctl") for cmd in captured)

"""
Sprint 1 backlog #12: move SSH host-key checking off blind TOFU toward a
pinnable, fail-closed posture. Default behavior is unchanged (accept-new, ssh's
own known_hosts); an operator can set StrictHostKeyChecking=yes + a Kratos-owned
known_hosts and pin the key first via pin_target_host_key (ssh-keyscan).
Scripted/offline (subprocess mocked; no real SSH).
"""
from __future__ import annotations

from types import SimpleNamespace

from kratos.adapters import ssh_remote


def test_base_argv_default_is_accept_new_no_custom_known_hosts(monkeypatch):
    monkeypatch.setattr(ssh_remote._kconfig, "SSH_STRICT_HOST_KEY_CHECKING", "accept-new")
    monkeypatch.setattr(ssh_remote._kconfig, "SSH_KNOWN_HOSTS_PATH", None)
    argv = ssh_remote._base_ssh_argv()
    assert "StrictHostKeyChecking=accept-new" in argv
    assert not any("UserKnownHostsFile" in a for a in argv)  # unchanged lab behavior


def test_base_argv_strict_with_pinned_known_hosts(monkeypatch, tmp_path):
    kh = tmp_path / "known_hosts"
    # Live toggle (read via the module, not a frozen import):
    monkeypatch.setattr(ssh_remote._kconfig, "SSH_STRICT_HOST_KEY_CHECKING", "yes")
    monkeypatch.setattr(ssh_remote._kconfig, "SSH_KNOWN_HOSTS_PATH", kh)
    argv = ssh_remote._base_ssh_argv()
    assert "StrictHostKeyChecking=yes" in argv          # fail closed on unknown keys
    assert f"UserKnownHostsFile={kh}" in argv           # against the Kratos-owned file


def test_pin_writes_keyscan_output_to_known_hosts(tmp_path, monkeypatch):
    dest = tmp_path / "known_hosts"
    fake = SimpleNamespace(returncode=0, stdout="10.0.0.5 ssh-ed25519 AAAAKEY", stderr="")
    monkeypatch.setattr(ssh_remote.subprocess, "run", lambda *a, **k: fake)

    res = ssh_remote.pin_target_host_key(target="10.0.0.5", known_hosts_path=dest)
    assert res.ok
    assert "10.0.0.5 ssh-ed25519 AAAAKEY" in dest.read_text()


def test_pin_without_configured_destination_fails_clearly(monkeypatch):
    monkeypatch.setattr(ssh_remote._kconfig, "SSH_KNOWN_HOSTS_PATH", None)
    res = ssh_remote.pin_target_host_key(target="h")
    assert not res.ok and "known_hosts" in res.stderr.lower()


def test_pin_empty_keyscan_result_fails_without_writing(tmp_path, monkeypatch):
    dest = tmp_path / "known_hosts"
    fake = SimpleNamespace(returncode=1, stdout="", stderr="no route to host")
    monkeypatch.setattr(ssh_remote.subprocess, "run", lambda *a, **k: fake)

    res = ssh_remote.pin_target_host_key(target="unreachable", known_hosts_path=dest)
    assert not res.ok
    assert not dest.exists()  # nothing pinned on a failed scan

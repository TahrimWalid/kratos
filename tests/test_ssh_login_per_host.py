"""Each machine has its own login name: remembered per host, typed as
name@host, and used by every SSH command Kratos builds."""
from __future__ import annotations

import pytest

from kratos import kratos_config as kc
from kratos.adapters import ssh_remote, target_setup
from kratos.tui_mk2.target_input import logins_from, remember_logins, validate_targets


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "SSH_TARGET_USER", "ubuntu")
    kc.set_active_data_dir(tmp_path)
    yield tmp_path
    kc.set_active_data_dir(None)
    kc.set_active_target(None)


def test_fallback_then_remembered_per_host(data):
    assert kc.ssh_user_for("10.0.0.5") == "ubuntu"
    kc.remember_ssh_user(data, "10.0.0.5", "debian")
    assert kc.ssh_user_for("10.0.0.5") == "debian"
    assert kc.ssh_user_for("10.0.0.6") == "ubuntu"


@pytest.mark.parametrize("bad", ["-oProxyCommand=x", "a b", "root;id", "", "x" * 33, "$(id)"])
def test_login_names_are_validated(data, bad):
    assert not kc.valid_ssh_user(bad)
    with pytest.raises(ValueError):
        kc.remember_ssh_user(data, "10.0.0.5", bad)


def test_ssh_argv_and_label_use_the_hosts_login(data, monkeypatch):
    kc.remember_ssh_user(data, "10.0.0.5", "ec2-user")
    kc.set_active_target("10.0.0.5")
    assert ssh_remote._base_ssh_argv()[-1] == "ec2-user@10.0.0.5"
    assert ssh_remote.target_label() == "ec2-user@10.0.0.5"


def test_setup_checklist_uses_the_hosts_login(data):
    kc.remember_ssh_user(data, "10.0.0.5", "alice")
    text = target_setup.generate_target_setup_checklist("10.0.0.5")
    assert "usermod -aG systemd-journal alice" in text and "alice ALL=(ALL) NOPASSWD" in text
    assert "ubuntu" not in text


def test_typed_name_at_host():
    hosts, err = validate_targets(["alice@10.0.0.5", "db.local"], allow_login=True)
    assert err is None and hosts == ["10.0.0.5", "db.local"]
    assert logins_from(["alice@10.0.0.5", "db.local"]) == {"10.0.0.5": "alice"}
    assert validate_targets(["-o@10.0.0.5"], allow_login=True)[1]           # bad login name
    assert validate_targets(["alice@not a host"], allow_login=True)[1]
    assert validate_targets(["alice@10.0.0.5"])[1]                          # only where a login makes sense


def test_remember_logins(data):
    assert remember_logins(data, ["bob@10.0.0.7", "10.0.0.8"]) == ["bob@10.0.0.7"]
    assert kc.ssh_user_for("10.0.0.7") == "bob"


def test_key_path_expands_home(tmp_path):
    import os
    import subprocess
    import sys

    env = {**os.environ, "KRATOS_SSH_KEY_PATH": "~/.ssh/kratos_key", "KRATOS_HOME": str(tmp_path)}
    out = subprocess.run([sys.executable, "-c", "from kratos import kratos_config as k; print(k.SSH_TARGET_KEY_PATH)"],
                         capture_output=True, text=True, env=env, timeout=60)
    assert out.stdout.strip() == os.path.expanduser("~/.ssh/kratos_key")

"""Tests for the core-side listener lifecycle helpers (subagent/core_listener.py)."""
from __future__ import annotations

import socket

from kratos.subagent import core_listener as cl


def test_listener_running_false_on_closed_port():
    # Find a port nothing is on by binding+closing, then check it's closed.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert cl.listener_running(port, timeout=0.2) is False


def test_listener_running_true_on_open_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert cl.listener_running(port, timeout=0.5) is True
    finally:
        s.close()


def test_core_service_unit_system(tmp_path):
    unit = cl.core_service_unit(tmp_path, port=8765)
    assert "[Service]" in unit and "[Install]" in unit
    assert "Restart=always" in unit
    assert "subagent-serve --host 0.0.0.0 --port 8765" in unit
    assert "WantedBy=multi-user.target" in unit
    assert str(tmp_path.resolve()) in unit  # absolute data-dir baked in


def test_core_service_unit_user_mode(tmp_path):
    unit = cl.core_service_unit(tmp_path, user_mode=True)
    assert "WantedBy=default.target" in unit


def test_install_commands_system_uses_sudo(tmp_path):
    cmds = cl.core_service_install_commands(tmp_path, user_mode=False)
    joined = "\n".join(cmds)
    assert "sudo tee /etc/systemd/system/kratos-core-listener.service" in joined
    assert "sudo systemctl daemon-reload" in joined
    assert "sudo systemctl enable --now kratos-core-listener.service" in joined


def test_install_commands_user_mode_no_sudo(tmp_path):
    cmds = cl.core_service_install_commands(tmp_path, user_mode=True)
    joined = "\n".join(cmds)
    assert "sudo" not in joined
    assert "systemctl --user enable --now kratos-core-listener.service" in joined
    assert ".config/systemd/user" in joined


def test_passwordless_sudo_available_returns_bool():
    assert isinstance(cl.passwordless_sudo_available(), bool)

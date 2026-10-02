"""
Validates that the add_a_tool_that tool correctly identifies users with sudo access
on the monitored target over SSH.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from kratos.adapters.ssh_remote import SSHResult

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "add_a_tool_that"


def _load_candidate():
    if not CANDIDATE_MODULE_PATH:
        pytest.skip(
            "CANDIDATE_MODULE_PATH not set -- this harness is meant to be pointed at a staged "
            "candidate (by Part B) or a reference implementation (manual sanity check)."
        )
    path = Path(CANDIDATE_MODULE_PATH)
    spec = importlib.util.spec_from_file_location("candidate_tool_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def registered_handler():
    from kratos.agent.tools import TOOL_REGISTRY

    _load_candidate()
    assert TOOL_NAME in TOOL_REGISTRY, (
        f"Candidate did not register a tool named '{TOOL_NAME}' via @register_tool -- "
        f"found instead: {sorted(TOOL_REGISTRY.keys())}"
    )
    return TOOL_REGISTRY[TOOL_NAME].handler


def _fake_ssh_response(command, *args, **kwargs):
    """Realistic canned output for the commands a sudo-listing tool would plausibly
    issue over SSH. The sandbox this harness runs in has NO network access (by
    design), so a candidate's SSH calls must be mocked here, not made for real --
    an unmocked call would just fail/time out regardless of whether the candidate's
    own logic is correct. "sudo:x:27:alice,bob" is a realistic /etc/group sudo
    line (the real line's shape, with placeholder names)."""
    cmd = command if isinstance(command, str) else " ".join(command)
    if "sudo" in cmd and "getent" in cmd:
        return SSHResult(ok=True, returncode=0, stdout="sudo:x:27:alice,bob", stderr="")
    if "wheel" in cmd:
        return SSHResult(ok=False, returncode=2, stdout="", stderr="getent: Unknown group: wheel")
    if "sudoers" in cmd:
        return SSHResult(
            ok=True, returncode=0,
            stdout="root    ALL=(ALL:ALL) ALL\n%sudo   ALL=(ALL:ALL) ALL\n",
            stderr="",
        )
    return SSHResult(ok=True, returncode=0, stdout="", stderr="")


def test_sudo_users_structure(registered_handler):
    # This tool is expected to return a dict containing lists of authorized entities
    with patch("kratos.adapters.ssh_remote.run_remote_command", side_effect=_fake_ssh_response), \
         patch("kratos.adapters.ssh_remote.run_remote_script", side_effect=_fake_ssh_response):
        result = registered_handler()

    assert isinstance(result, dict)
    assert "users" in result, "Result must contain a list of individual users with sudo access"
    assert "groups" in result, "Result must contain a list of groups with sudo access"
    assert isinstance(result["users"], list)
    assert isinstance(result["groups"], list)

def test_sudo_users_nonempty(registered_handler):
    # 'root' is intentionally NOT asserted here: root already has full
    # privileges and typically isn't listed as a member of the sudo group
    # (getent group sudo / /etc/group's sudo line lists explicit members
    # like real admin usernames, not root) -- a correct implementation that
    # only reports actual sudo-group members would fail a "root must be
    # present" check. The fake sudo group membership above ("alice,bob")
    # has the real line's shape, so a correct implementation should find at
    # least those two users.
    with patch("kratos.adapters.ssh_remote.run_remote_command", side_effect=_fake_ssh_response), \
         patch("kratos.adapters.ssh_remote.run_remote_script", side_effect=_fake_ssh_response):
        result = registered_handler()

    assert len(result["users"]) >= 1, "At least one user with sudo access should be found on a real system"
    assert all(isinstance(user, str) and user for user in result["users"]), "Usernames must be non-empty strings"

def test_a_failed_read_is_an_error_not_no_sudo_users(registered_handler):
    # A failed SSH read used to come back as users=[] -- "nobody has sudo".
    failed = SSHResult(ok=False, returncode=255, stdout="", stderr="ssh: connect to host x port 22: timed out")
    with patch("kratos.adapters.ssh_remote.run_remote_command", return_value=failed), \
         patch("kratos.adapters.ssh_remote.run_remote_script", return_value=failed):
        result = registered_handler()
    assert result.get("status") == "error" and "timed out" in result["observation"]


def test_no_sudo_group_is_a_real_empty_answer(registered_handler):
    missing = SSHResult(ok=False, returncode=2, stdout="", stderr="")
    with patch("kratos.adapters.ssh_remote.run_remote_command", return_value=missing), \
         patch("kratos.adapters.ssh_remote.run_remote_script", return_value=missing):
        result = registered_handler()
    assert result["users"] == []

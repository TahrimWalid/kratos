"""
This harness validates the list_net_services tool by mocking the output of 'ss -tlnp' 
to ensure the candidate correctly parses local listening socket data into a structured format.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from kratos.adapters.ssh_remote import SSHResult

CANDIDATE_MODULE_PATH = os.environ.get("CANDIDATE_MODULE_PATH")
TOOL_NAME = "list_net_services"


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


def test_list_net_services_parses_ss_output(registered_handler):
    fake_ss_output = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*         users:((\"sshd\",pid=1024,fd=3))\n"
        "tcp   LISTEN 0      511    127.0.0.1:6379      0.0.0.0:*         users:((\"redis-server\",pid=500,fd=4))\n"
    )
    
    with patch(
        "kratos.adapters.ssh_remote.run_remote_command",
        return_value=SSHResult(ok=True, returncode=0, stdout=fake_ss_output, stderr=""),
    ):
        result = registered_handler()

    assert isinstance(result, list)
    assert len(result) == 2
    
    # Validate structure of the first entry
    assert result[0] == {
        "protocol": "tcp",
        "port": 22,
        "address": "0.0.0.0",
        "process": "sshd",
        "pid": 1024
    }
    
    # Validate structure of the second entry
    assert result[1] == {
        "protocol": "tcp",
        "port": 6379,
        "address": "127.0.0.1",
        "process": "redis-server",
        "pid": 500
    }

def test_list_net_services_handles_empty_output(registered_handler):
    with patch(
        "kratos.adapters.ssh_remote.run_remote_command",
        return_value=SSHResult(ok=True, returncode=0, stdout="", stderr=""),
    ):
        result = registered_handler()
    assert result == []


def test_list_net_services_includes_ports_with_unknown_process(registered_handler):
    # Real, common case: 'ss -tlnp' run without sudo can't see the owning process
    # for a socket owned by a DIFFERENT user (e.g. sshd running as root, when
    # connected as a non-root user) -- the "Process" column is simply blank, not
    # malformed. This is exactly the case a real, deliberate bug silently dropped
    # the port from the result entirely instead of reporting it with an unknown
    # owner -- for a security exposure tool, a listening port disappearing from
    # the output because its owner couldn't be identified is a real correctness
    # gap, not a cosmetic one. Fixed: the port is now always included; only
    # process/pid become None when attribution isn't visible.
    fake_ss_output = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*\n"
    )

    with patch(
        "kratos.adapters.ssh_remote.run_remote_command",
        return_value=SSHResult(ok=True, returncode=0, stdout=fake_ss_output, stderr=""),
    ):
        result = registered_handler()

    assert len(result) == 1, "the port must still be reported even with no visible owning process"
    assert result[0]["port"] == 22
    assert result[0]["protocol"] == "tcp"
    assert result[0]["process"] is None
    assert result[0]["pid"] is None
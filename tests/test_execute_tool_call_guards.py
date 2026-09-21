"""
Scripted tests for agent/loop.py::execute_tool_call's own dispatch-level
guards -- distinct from tests/test_agent_loop_guards.py's 4 final_answer
guards (those run through the real run_agent() loop with mocked chat; these
call execute_tool_call directly, no LLM involved at all).

Covers three real, live-incident-driven guards, all in the same
"call_args"-building block of execute_tool_call:
  1. data_dir is always overridden with the real value (2026-07-17 incident:
     a hallucinated data_dir="/data" caused a real PermissionError).
  2. An OBVIOUSLY fake placeholder target ("THE_TARGET_IP") is rejected
     (2026-07-18 incident).
  3. A plausible-looking but WRONG target (a real, differently-shaped IP
     that just isn't the configured active target) is rejected too
     (2026-07-19 incident, confirmed live via MCP: kratos_investigate with
     target=10.136.28.168 resulted in the model calling run_nmap_scan with
     a hallucinated target=192.168.1.50 instead, and the wrong host got
     scanned with no error). The one documented exception -- self-
     monitoring via 127.0.0.1/localhost/::1, per run_nmap_scan's own tool
     description -- must still be allowed through.

Tool handlers are swapped for canned functions (same technique
test_agent_loop_guards.py already uses) so these tests never touch a real
SSH target or network -- what's under test is purely execute_tool_call's
own pre-dispatch validation, not any tool's real behavior.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from kratos import kratos_config as _kconfig
from kratos.agent.loop import execute_tool_call
from kratos.agent.tools import TOOL_REGISTRY


@pytest.fixture
def active_target():
    """Sets a real, known active target for the duration of a test, then
    restores whatever raw override state existed before (including None,
    i.e. "no override") -- mirrors how /target itself mutates this same
    global, safe to do repeatedly across tests."""
    previous_override = _kconfig._active_target_override
    _kconfig.set_active_target("10.136.28.168")
    yield "10.136.28.168"
    _kconfig.set_active_target(previous_override)


def _canned_handler(**kwargs):
    return {"status": "ok", "received_args": kwargs}


# ---------------------------------------------------------------------------
# data_dir: always the real value, never the model's
# ---------------------------------------------------------------------------
def test_data_dir_override_ignores_hallucinated_value(tmp_path):
    captured = {}

    def _capture(**kwargs):
        captured.update(kwargs)
        return {"status": "ok"}

    with patch.object(TOOL_REGISTRY["run_nmap_scan"], "handler", side_effect=_capture):
        execute_tool_call("run_nmap_scan", {"data_dir": "/data"}, tmp_path)

    assert captured["data_dir"] == tmp_path  # the REAL data_dir, not "/data"


# ---------------------------------------------------------------------------
# Implausible placeholder target ("THE_TARGET_IP")
# ---------------------------------------------------------------------------
def test_implausible_placeholder_target_rejected(tmp_path, active_target):
    with patch.object(TOOL_REGISTRY["run_nmap_scan"], "handler", side_effect=_canned_handler) as handler:
        result = execute_tool_call("run_nmap_scan", {"target": "THE_TARGET_IP"}, tmp_path)

    assert result["status"] == "error"
    assert "placeholder" in result["observation"]
    handler.assert_not_called()


# ---------------------------------------------------------------------------
# Target mismatch -- the real 2026-07-19 incident this guard closes
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tool_name", ["run_nmap_scan", "run_vuln_scan"])
def test_mismatched_real_looking_target_rejected(tmp_path, active_target, tool_name):
    with patch.object(TOOL_REGISTRY[tool_name], "handler", side_effect=_canned_handler) as handler:
        result = execute_tool_call(tool_name, {"target": "192.168.1.50"}, tmp_path)

    assert result["status"] == "error"
    assert "192.168.1.50" in result["observation"]
    assert active_target in result["observation"]  # tells the model the real configured target
    handler.assert_not_called()  # never scanned the wrong host


@pytest.mark.parametrize("tool_name", ["run_nmap_scan", "run_vuln_scan"])
def test_target_matching_active_target_passes_through(tmp_path, active_target, tool_name):
    with patch.object(TOOL_REGISTRY[tool_name], "handler", side_effect=_canned_handler) as handler:
        result = execute_tool_call(tool_name, {"target": active_target}, tmp_path)

    assert result["status"] == "ok"
    handler.assert_called_once()


@pytest.mark.parametrize("tool_name", ["run_nmap_scan", "run_vuln_scan"])
def test_target_omitted_is_unaffected_by_the_guard(tmp_path, active_target, tool_name):
    # No target arg at all -- the guard only fires when call_args.get("target")
    # is not None; the tool's own default (get_active_target()) resolution
    # is untouched.
    with patch.object(TOOL_REGISTRY[tool_name], "handler", side_effect=_canned_handler) as handler:
        result = execute_tool_call(tool_name, {}, tmp_path)

    assert result["status"] == "ok"
    handler.assert_called_once()


@pytest.mark.parametrize("loopback", ["127.0.0.1", "localhost", "::1"])
@pytest.mark.parametrize("tool_name", ["run_nmap_scan", "run_vuln_scan"])
def test_loopback_self_monitoring_exception_allowed(tmp_path, active_target, tool_name, loopback):
    # The ONE documented legitimate deviation (run_nmap_scan's own tool
    # description: "pass target explicitly only to check a different host,
    # e.g. '127.0.0.1' for Kratos's own local host specifically") -- must
    # NOT be caught by the mismatch guard.
    with patch.object(TOOL_REGISTRY[tool_name], "handler", side_effect=_canned_handler) as handler:
        result = execute_tool_call(tool_name, {"target": loopback}, tmp_path)

    assert result["status"] == "ok"
    handler.assert_called_once()


# ---------------------------------------------------------------------------
# check_ip_reputation's "ip" param is a DIFFERENT parameter name -- must be
# completely unaffected by this guard (it's designed to take an arbitrary
# external IP from investigation context, never the protected target).
# ---------------------------------------------------------------------------
def test_check_ip_reputation_ip_param_not_caught_by_target_guard(tmp_path, active_target):
    # An IP that matches neither the active target nor any loopback value --
    # if this guard's scoping were wrong (e.g. keyed on "any host-shaped
    # param" instead of literally "target"), this would be incorrectly
    # rejected. It must NOT be.
    with patch.object(TOOL_REGISTRY["check_ip_reputation"], "handler", side_effect=_canned_handler) as handler:
        result = execute_tool_call("check_ip_reputation", {"ip": "203.0.113.77"}, tmp_path)

    assert result["status"] == "ok"
    handler.assert_called_once()


def test_unknown_tool_name_still_rejected_cleanly(tmp_path):
    result = execute_tool_call("not_a_real_tool", {}, tmp_path)
    assert result["status"] == "error"
    assert "not a real tool" in result["observation"]


# ---------------------------------------------------------------------------
# Kept-tool approval gating at dispatch (2026-09-07): a requires_approval=True
# tool whose handler does NOT self-gate (every self-written/kept tool) is gated
# HERE, at dispatch, so the flag is actually enforceable. Without it, such a
# tool never records an approval and the backstop refuses its result forever.
# ---------------------------------------------------------------------------
from pathlib import Path as _Path

from kratos.agent import tools as _tools
from kratos.agent.loop import execute_tool_call as _exec


def _register_kept_style(name):
    # A self-written/kept tool: requires_approval=True, but the handler is plain
    # data-processing code that never self-gates (deliberately no approval call
    # in its source — not even in a comment, which the naive scan would match).
    @_tools.register_tool(name=name, description="kept-style", parameters={}, requires_approval=True)
    def _handler():
        return {"ran": name}
    return name


def test_kept_tool_gated_at_dispatch_runs_when_approved():
    name = _register_kept_style("_t_kept_ok")
    _tools.set_approval_prompt_provider(lambda n, d: True)
    try:
        res = _exec(name, {}, _Path("data"))
    finally:
        _tools.set_approval_prompt_provider(None)
    assert res["status"] == "ok" and res["result"] == {"ran": name}


def test_kept_tool_gated_at_dispatch_refused_when_denied():
    name = _register_kept_style("_t_kept_deny")
    _tools.set_approval_prompt_provider(lambda n, d: False)
    try:
        res = _exec(name, {}, _Path("data"))
    finally:
        _tools.set_approval_prompt_provider(None)
    assert res["status"] == "not_approved"  # denied -> not run, not refused-as-bug


# ---------------------------------------------------------------------------
# P0 red-team (2026-09-21): the C6 run_linux_command boundary must hold even
# when the model dodges the literal-target check. Two gaps found + fixed:
#   (a) target-reach was a literal-IP substring match -> bypassable via the
#       target's HOSTNAME, an obfuscated IP (leading zeros), or a shell var.
#       Fixed by _REMOTE_REACH_RE (reject remote-exec tools at command position).
#   (b) state-change was a denylist missing cp/mv/ln/sed -i/install/sysctl -w.
# Both are BEFORE the approval prompt (structural, not left to model judgment).
# ---------------------------------------------------------------------------
from kratos.agent.loop import _REMOTE_REACH_RE, _STATE_CHANGE_RE


@pytest.mark.parametrize("cmd", [
    "ssh ubuntu@kratos-target 'cat /etc/shadow'",      # hostname, not the IP
    "ssh ubuntu@10.136.028.168 id",                     # obfuscated IP (leading zero)
    "T=10.136.28.168; ssh ubuntu@$T id",                # shell-variable indirection
    "sudo ssh root@host reboot",                          # sudo-wrapped
    "sudo -n ssh host id",                               # sudo with a flag
    "scp /tmp/x ubuntu@host:/tmp/",
    "rsync -a /tmp/ host:/dst/",
    "foo | nc host 4444",
    "echo hi && ssh host id",
    "$(ssh host id)",
])
def test_remote_reach_bypass_is_rejected(cmd):
    assert _REMOTE_REACH_RE.search(cmd), f"remote-reach guard MISSED: {cmd!r}"


@pytest.mark.parametrize("cmd", [
    "grep ssh /var/log/auth.log",   # ssh as an ARGUMENT, not the command
    "journalctl -u ssh",
    "cat /etc/ssh/sshd_config",
    "ps aux | grep sshd",
    "systemctl status sshd",
    "ss -tlnp | grep nc",           # nc as data
])
def test_legit_local_reads_not_flagged_as_remote(cmd):
    assert not _REMOTE_REACH_RE.search(cmd), f"remote-reach guard false-positived: {cmd!r}"


@pytest.mark.parametrize("cmd", [
    "cp /tmp/evil /etc/passwd", "mv /tmp/x /etc/cron.d/y", "ln -sf /tmp/x /etc/y",
    "sed -i s/a/b/ /etc/hosts", "sysctl -w kernel.x=1", "truncate -s0 /var/log/auth.log",
])
def test_added_state_change_verbs_rejected(cmd):
    assert _STATE_CHANGE_RE.search(cmd), f"state-change guard MISSED: {cmd!r}"


@pytest.mark.parametrize("cmd", [
    "cat /etc/passwd", "dpkg -l", "ps aux", "systemctl status sshd",
    "sed s/a/b/ file", "sysctl -a", "mount",
])
def test_legit_reads_not_flagged_as_state_change(cmd):
    assert not _STATE_CHANGE_RE.search(cmd), f"state-change guard false-positived: {cmd!r}"


def test_execute_tool_call_rejects_ssh_to_hostname_before_dispatch(active_target, tmp_path):
    """End-to-end: a hostname-based ssh-wrap (dodges the literal-IP check) is
    rejected by execute_tool_call BEFORE the handler or the approval prompt."""
    with patch.object(TOOL_REGISTRY["run_linux_command"], "handler",
                      side_effect=_canned_handler) as handler:
        result = execute_tool_call(
            "run_linux_command",
            {"command": "ssh ubuntu@kratos-target 'cat /etc/shadow'"}, tmp_path)
    assert result["status"] == "error"
    assert "reach another host" in result["observation"]
    handler.assert_not_called()


def test_execute_tool_call_rejects_cp_to_etc_before_dispatch(active_target, tmp_path):
    with patch.object(TOOL_REGISTRY["run_linux_command"], "handler",
                      side_effect=_canned_handler) as handler:
        result = execute_tool_call(
            "run_linux_command", {"command": "cp /tmp/evil /etc/passwd"}, tmp_path)
    assert result["status"] == "error"
    assert "observe-and-recommend only" in result["observation"]
    handler.assert_not_called()

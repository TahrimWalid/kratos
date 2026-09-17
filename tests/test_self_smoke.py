"""
Unit tests for the A7 optional live-target smoke test (agent/self_smoke.py) and
its keep-flow offer (agent/self_approve.py). No real SSH: the candidate's
ssh_remote calls are mocked, so these test the smoke MECHANISM (run the handler,
capture output/errors, restore the registry) and the OFFER gating deterministically.
The real, unmocked live run + the adversarial (non-read-only) case are verified
against the actual target separately.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from kratos.agent import self_smoke as S
from kratos.agent.self_smoke import (
    is_target_facing, smoke_test_available, run_live_smoke_test, SmokeResult,
)
from kratos.adapters.ssh_remote import SSHResult


_TARGET_CANDIDATE = '''
from kratos.agent.tools import register_tool
from kratos.adapters import ssh_remote

@register_tool(name="smoke_demo", description="d", parameters={})
def tool_smoke_demo():
    r = ssh_remote.run_remote_command("getent group sudo")
    if not r.ok:
        return {"status": "error", "observation": (r.stderr or r.stdout).strip()}
    return {"members": r.stdout.strip().split(":")[-1].split(","), "ok": True}
'''

_RAISING_CANDIDATE = '''
from kratos.agent.tools import register_tool
from kratos.adapters import ssh_remote

@register_tool(name="smoke_boom", description="d", parameters={})
def tool_smoke_boom():
    raise RuntimeError("live blew up")
'''

_NEEDS_ARG_CANDIDATE = '''
from kratos.agent.tools import register_tool

@register_tool(name="smoke_needsarg", description="d", parameters={"ip": {"type": "str", "description": "x"}})
def tool_smoke_needsarg(ip):
    return {"ip": ip}
'''

_WRONG_NAME_CANDIDATE = '''
from kratos.agent.tools import register_tool

@register_tool(name="something_else", description="d", parameters={})
def tool_x():
    return {}
'''


def _write(tmp_path, name, src) -> Path:
    p = tmp_path / f"{name}.py"
    p.write_text(src, encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# detection / availability gating
# --------------------------------------------------------------------------

def test_is_target_facing():
    assert is_target_facing("x = ssh_remote.run_remote_command('ls')")
    assert is_target_facing("from kratos.adapters.ssh_remote import run_remote_script")
    assert not is_target_facing("open('f').read()")


@pytest.mark.parametrize("src,target,expected", [
    ("ssh_remote", "10.0.0.5", True),
    ("ssh_remote", "127.0.0.1", False),   # loopback: no live gap
    ("ssh_remote", "localhost", False),
    ("ssh_remote", "", False),            # no target
    ("ssh_remote", None, False),
    ("local only", "10.0.0.5", False),    # not target-facing
])
def test_smoke_test_available(src, target, expected):
    assert smoke_test_available(src, target) is expected


# --------------------------------------------------------------------------
# run_live_smoke_test -- mechanism + registry hygiene
# --------------------------------------------------------------------------

def test_smoke_happy_path_and_registry_restored(tmp_path):
    from kratos.agent.tools import TOOL_REGISTRY
    path = _write(tmp_path, "smoke_demo", _TARGET_CANDIDATE)
    assert "smoke_demo" not in TOOL_REGISTRY

    with patch("kratos.adapters.ssh_remote.run_remote_command",
               return_value=SSHResult(ok=True, returncode=0, stdout="sudo:x:27:alice,bob", stderr="")):
        res = run_live_smoke_test(path, "smoke_demo")

    assert res.ran and res.ok
    assert "alice" in res.output and "bob" in res.output
    # hygiene: a smoke test must NOT leave the tool registered without a keep
    assert "smoke_demo" not in TOOL_REGISTRY


def test_smoke_surfaces_live_failure(tmp_path):
    from kratos.agent.tools import TOOL_REGISTRY
    path = _write(tmp_path, "smoke_demo", _TARGET_CANDIDATE)
    # ssh returns a permission-denied style failure -> the tool reports error;
    # the handler still returns a dict (no raise), so ran=ok=True but the output
    # shows the error the mock hid -- exactly the mock-vs-live signal.
    with patch("kratos.adapters.ssh_remote.run_remote_command",
               return_value=SSHResult(ok=False, returncode=1, stdout="", stderr="Permission denied")):
        res = run_live_smoke_test(path, "smoke_demo")
    assert res.ran and res.ok
    assert "Permission denied" in res.output
    assert "smoke_demo" not in TOOL_REGISTRY


def test_smoke_captures_handler_exception(tmp_path):
    from kratos.agent.tools import TOOL_REGISTRY
    path = _write(tmp_path, "smoke_boom", _RAISING_CANDIDATE)
    res = run_live_smoke_test(path, "smoke_boom")
    assert res.ran and not res.ok
    assert "live blew up" in res.error
    assert "smoke_boom" not in TOOL_REGISTRY


def test_smoke_reports_needs_argument(tmp_path):
    path = _write(tmp_path, "smoke_needsarg", _NEEDS_ARG_CANDIDATE)
    res = run_live_smoke_test(path, "smoke_needsarg")
    assert not res.ran
    assert "ip" in res.error


def test_smoke_reports_wrong_registration(tmp_path):
    path = _write(tmp_path, "smoke_wrong", _WRONG_NAME_CANDIDATE)
    res = run_live_smoke_test(path, "smoke_wrong")
    assert not res.ran
    assert "did not register" in res.error


_HIDDEN_SECOND_CANDIDATE = '''
from kratos.agent.tools import register_tool

@register_tool(name="smoke_primary", description="d", parameters={})
def tool_primary():
    return {"ok": True}

@register_tool(name="smoke_hidden_backdoor", description="sneaky", parameters={})
def tool_hidden():
    return {"pwned": True}
'''


def test_smoke_removes_hidden_extra_registration(tmp_path):
    # A candidate that registers a SECOND, hidden tool must NOT leave it live in
    # TOOL_REGISTRY after a smoke run (that would be a tool registered with no
    # keep decision at all).
    from kratos.agent.tools import TOOL_REGISTRY
    path = _write(tmp_path, "smoke_primary", _HIDDEN_SECOND_CANDIDATE)
    assert "smoke_hidden_backdoor" not in TOOL_REGISTRY
    res = run_live_smoke_test(path, "smoke_primary")
    assert res.ran and res.ok
    assert "smoke_primary" not in TOOL_REGISTRY
    assert "smoke_hidden_backdoor" not in TOOL_REGISTRY   # the hidden one is gone too


def test_smoke_restores_preexisting_tool(tmp_path):
    from kratos.agent.tools import TOOL_REGISTRY
    import types
    sentinel = types.SimpleNamespace(handler=lambda: {"orig": True}, requires_approval=True)
    TOOL_REGISTRY["smoke_demo"] = sentinel
    try:
        path = _write(tmp_path, "smoke_demo", _TARGET_CANDIDATE)
        with patch("kratos.adapters.ssh_remote.run_remote_command",
                   return_value=SSHResult(ok=True, returncode=0, stdout="sudo:x:27:alice", stderr="")):
            run_live_smoke_test(path, "smoke_demo")
        # a pre-existing entry must be put BACK, not deleted
        assert TOOL_REGISTRY["smoke_demo"] is sentinel
    finally:
        TOOL_REGISTRY.pop("smoke_demo", None)


# --------------------------------------------------------------------------
# keep-flow offer gating (agent/self_approve._offer_and_run_smoke)
# --------------------------------------------------------------------------

def test_offer_skipped_for_non_target_facing(monkeypatch):
    from kratos.agent import self_approve as A
    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: "10.0.0.5")
    called = {"approval": False}
    monkeypatch.setattr(A, "request_approval", lambda *a, **k: called.__setitem__("approval", True) or True)
    out = A._offer_and_run_smoke(Path("/x.py"), "t", "just local code, no ssh", [])
    assert out is None
    assert called["approval"] is False   # never even offered


def test_offer_declined_returns_none(monkeypatch):
    from kratos.agent import self_approve as A
    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: "10.0.0.5")
    monkeypatch.setattr(A, "request_approval", lambda *a, **k: False)  # decline the live check
    ran = {"smoke": False}
    monkeypatch.setattr(A, "run_live_smoke_test", lambda *a, **k: ran.__setitem__("smoke", True))
    out = A._offer_and_run_smoke(Path("/x.py"), "t", "uses ssh_remote here", [])
    assert out is None
    assert ran["smoke"] is False         # declined -> never runs the candidate


def test_offer_approved_runs_and_summarizes(monkeypatch):
    from kratos.agent import self_approve as A
    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: "10.0.0.5")
    monkeypatch.setattr(A, "request_approval", lambda *a, **k: True)  # approve the live check
    monkeypatch.setattr(A, "run_live_smoke_test",
                        lambda *a, **k: SmokeResult(ran=True, ok=True, output="{'members': ['alice']}",
                                                    error=None, duration_seconds=0.4))
    out = A._offer_and_run_smoke(Path("/x.py"), "t", "uses ssh_remote here", [])
    assert out and "alice" in out and "10.0.0.5" in out

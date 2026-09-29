"""The installer on a box that already has an agent (connection-UX WS3/WS5): re-pairing
starts a fresh identity, upgrading keeps it, the service is RESTARTED, a background install
never runs two agents, and failures print a machine-readable line. Also the Python 3.8/3.9
agent start-up fix.

The shell logic is exercised for real: the generated script runs under /bin/sh in a
throwaway HOME with no systemd and no sudo (the background-install path)."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from kratos.subagent import installer as I
from kratos.subagent.agent import SubAgent

TOOLS = ("sh", "python3", "base64", "cat", "mkdir", "mv", "date", "grep", "id", "test", "tee", "kill", "nohup",
         "rm", "sleep", "printf")


def test_upgrade_needs_no_code_and_never_passes_one():
    script = I.generate_installer("10.0.0.1", None, upgrade=True)
    assert "UPGRADE=1" in script and "PAIR_CODE=''" in script
    with pytest.raises(I.InstallerError):
        I.generate_installer("10.0.0.1", None)


def test_every_path_restarts_and_fails_loudly():
    script = I.generate_installer("10.0.0.1", "AB12-CD34")
    assert 'systemctl restart "$SERVICE_NAME.service"' in script
    assert 'systemctl --user restart "$SERVICE_NAME.service"' in script
    for code in ("no_python", "python_too_old", "no_base64", "not_paired", "write_failed"):
        assert f"die {code} " in script
    assert "--enable-execution" not in script
    for s in (script, I.uninstall_command()):
        assert subprocess.run(["sh", "-n"], input=s, text=True, capture_output=True).returncode == 0


@pytest.fixture
def box(tmp_path):
    """A throwaway HOME whose PATH has the basics but no systemctl and no sudo."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for t in TOOLS:
        real = shutil.which(t)
        if real:
            (bindir / t).symlink_to(real)
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": str(bindir), "HOME": str(home)}
    procs: list[int] = []
    yield home, env, procs
    for pid_file in home.glob(".kratos-subagent/agent.pid"):
        try:
            os.kill(int(pid_file.read_text().strip()), 9)
        except (OSError, ValueError):
            pass


def _run(script: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", "-s"], input=script, text=True, capture_output=True, env=env, timeout=60)


def _alive(pid: int) -> bool:
    try:
        return "subagent.agent" in Path(f"/proc/{pid}/cmdline").read_text()
    except OSError:
        return False


def test_background_install_rerun_replaces_the_agent_and_repairs_identity(box):
    home, env, _ = box
    # Core address that refuses connections -- the agent just retries; nothing leaves the host.
    r1 = _run(I.generate_installer("127.0.0.1", "AAAA-1111", core_port=9), env)
    assert r1.returncode == 0 and "KRATOS_INSTALL_OK mode=user service=none" in r1.stdout, r1.stderr
    pid1 = int((home / ".kratos-subagent/agent.pid").read_text())
    time.sleep(1.0)
    assert _alive(pid1)
    state = home / ".kratos-subagent/state.json"
    assert state.exists()  # the agent wrote its identity

    r2 = _run(I.generate_installer("127.0.0.1", "BBBB-2222", core_port=9), env)
    assert r2.returncode == 0 and "old identity was moved" in r2.stdout
    assert "Stopped the previous background agent" in r2.stdout
    pid2 = int((home / ".kratos-subagent/agent.pid").read_text())
    time.sleep(1.0)
    assert pid2 != pid1 and not _alive(pid1) and _alive(pid2)  # never two agents at once
    assert list((home / ".kratos-subagent").glob("state.json.replaced-*"))  # kept aside, not deleted


def test_upgrade_refuses_a_box_that_was_never_paired(box):
    home, env, _ = box
    r = _run(I.generate_installer("127.0.0.1", None, core_port=9, upgrade=True), env)
    assert r.returncode == 1 and "KRATOS_INSTALL_ERROR: not_paired:" in r.stderr


def test_missing_python_is_a_classified_error(box, tmp_path):
    home, env, _ = box
    (Path(env["PATH"]) / "python3").unlink()
    r = _run(I.generate_installer("127.0.0.1", "AAAA-1111", core_port=9), env)
    assert r.returncode == 1 and "KRATOS_INSTALL_ERROR: no_python:" in r.stderr


def test_agent_built_before_its_loop_starts_cleanly(tmp_path):
    """Python 3.8/3.9 crashed here: the stop Event was bound to a loop that no
    longer existed. Build the agent first, then run it in a fresh loop, and a
    stop() requested before start must still be honoured."""
    agent = SubAgent("127.0.0.1", 9, state_file=tmp_path / "s.json", pairing_code="AAAA-1111", local_allow_file=None)
    agent.stop()
    asyncio.run(asyncio.wait_for(agent.run_forever(), 5))

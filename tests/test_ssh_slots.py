"""At most a few SSH sessions per machine, across processes (kratos.utils.ssh_slots)."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from kratos.utils import cancel, ssh_slots


@pytest.fixture(autouse=True)
def _private_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("KRATOS_SSH_MAX_SESSIONS", "2")


def test_a_third_session_waits_until_one_ends():
    held = threading.Event()
    release = threading.Event()

    def hold():
        with ssh_slots.slot("10.0.0.5", wait_seconds=1):
            held.set()
            release.wait(5)

    threads = [threading.Thread(target=hold) for _ in range(2)]
    for t in threads:
        t.start()
    held.wait(2)
    time.sleep(0.1)
    with pytest.raises(ssh_slots.Busy):
        with ssh_slots.slot("10.0.0.5", wait_seconds=0.3):
            pass
    with ssh_slots.slot("10.0.0.6", wait_seconds=0.3):   # another machine has its own slots
        pass
    release.set()
    for t in threads:
        t.join()
    with ssh_slots.slot("10.0.0.5", wait_seconds=0.3):
        pass


def test_the_cap_holds_across_processes_and_a_dead_process_frees_its_slot(tmp_path):
    code = textwrap.dedent("""
        import sys, time
        from kratos.utils import ssh_slots
        with ssh_slots.slot("10.0.0.5", wait_seconds=1):
            print("held", flush=True)
            time.sleep(30)
    """)
    env = {**os.environ, "XDG_RUNTIME_DIR": str(tmp_path), "KRATOS_SSH_MAX_SESSIONS": "2"}
    procs = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, env=env)
             for _ in range(2)]
    try:
        for p in procs:
            assert p.stdout.readline().strip() == "held"
        with pytest.raises(ssh_slots.Busy):
            with ssh_slots.slot("10.0.0.5", wait_seconds=0.3):
                pass
        procs[0].kill()
        procs[0].wait()
        with ssh_slots.slot("10.0.0.5", wait_seconds=2):   # the killed process's lock was released
            pass
    finally:
        for p in procs:
            p.kill()


def test_a_cancelled_check_stops_waiting():
    scope = cancel.CancelScope()
    hold = [ssh_slots.slot("10.0.0.5", wait_seconds=1) for _ in range(2)]
    for h in hold:
        h.__enter__()
    try:
        threading.Timer(0.2, scope.cancel).start()
        t0 = time.monotonic()
        with cancel.bound(scope), pytest.raises(cancel.Cancelled):
            with ssh_slots.slot("10.0.0.5", wait_seconds=10):
                pass
        assert time.monotonic() - t0 < 2
    finally:
        for h in hold:
            h.__exit__(None, None, None)


def test_an_unsafe_lock_folder_skips_the_cap_instead_of_failing(tmp_path, monkeypatch):
    base = tmp_path / "rt"
    base.mkdir()
    (base / f"kratos-{os.getuid()}").mkdir(mode=0o777)
    os.chmod(base / f"kratos-{os.getuid()}", 0o777)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(base))
    for _ in range(5):                                      # no cap: nothing blocks
        with ssh_slots.slot("10.0.0.5", wait_seconds=0):
            pass


def test_the_ssh_warm_up_never_holds_collection_back_long(monkeypatch):
    """Collection opens the shared connection first, but a slow or unreachable machine
    must not stall it: the wait is capped at WARM_WAIT_SECONDS."""
    from kratos.adapters import ssh_remote
    from kratos.collect import runner

    monkeypatch.setattr(runner, "WARM_WAIT_SECONDS", 0.3)
    monkeypatch.setattr(ssh_remote, "warm_connection", lambda: time.sleep(5) or True)
    t0 = time.monotonic()
    runner._warm_ssh("10.0.0.5")
    assert time.monotonic() - t0 < 1.0


def test_every_ssh_read_reuses_one_connection_and_carries_a_slot(monkeypatch):
    from kratos import kratos_config
    from kratos.adapters import ssh_remote

    kratos_config.set_active_target("10.0.0.5")
    argv = ssh_remote._base_ssh_argv()
    assert "ControlMaster=auto" in argv and any(a.startswith("ControlPath=") and a.endswith("/%C") for a in argv)
    monkeypatch.setenv("KRATOS_SSH_MUX", "off")
    assert "ControlMaster=auto" not in ssh_remote._base_ssh_argv()
    assert ssh_remote._clean_stderr("ControlSocket /x already exists, disabling multiplexing\nreal error") == "real error"

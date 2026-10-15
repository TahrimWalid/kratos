"""Shared test setup."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_self_ssh_probe(monkeypatch: pytest.MonkeyPatch):
    """/investigate-host probes whether Kratos can SSH into its own machine. Tests never
    make that real connection; a test that cares sets its own answer."""
    monkeypatch.setattr("kratos.agent.loop._loopback_ssh_ok", lambda: False)


@pytest.fixture(autouse=True)
def _no_real_ssh(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    """No test reaches a real machine over SSH. A started `ssh`/`scp` fails as if the
    binary were missing (so no connection is ever made, and the code under test sees an
    ordinary failure), and the test itself fails afterwards, naming the command --
    otherwise a test could pass while quietly reading the lab target (the phase A audit
    found the suite opening ~70 real SSH sessions per run). A test that really means to
    start ssh (with its own fake binary) marks itself `@pytest.mark.allow_ssh`."""
    import os
    import subprocess

    if request.node.get_closest_marker("allow_ssh"):
        yield
        return
    attempts: list[str] = []
    real_popen = subprocess.Popen

    class _GuardedPopen(real_popen):  # type: ignore[misc,valid-type]
        def __init__(self, args, *a, **k):
            argv = [args] if isinstance(args, (str, bytes, os.PathLike)) else list(args or [])
            prog = os.path.basename(os.fsdecode(argv[0])) if argv else ""
            if prog in ("ssh", "scp"):
                import traceback
                caller = next((f"{fr.name} ({os.path.basename(fr.filename)}:{fr.lineno})"
                               for fr in reversed(traceback.extract_stack())
                               if "/src/kratos/" in fr.filename and os.path.basename(fr.filename)
                               not in ("ssh_remote.py", "cancel.py", "subprocess.py")), "?")
                attempts.append(f"{caller}: {' '.join(os.fsdecode(x) for x in argv[-1:])[:100]}")
                raise FileNotFoundError(2, "ssh is not available in tests", prog)
            super().__init__(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", _GuardedPopen)
    yield
    if attempts:
        shown = "\n  ".join(dict.fromkeys(attempts))
        pytest.fail(f"this test tried to start ssh/scp for real ({len(attempts)}x):\n  {shown}", pytrace=False)


@pytest.fixture(autouse=True)
def _collection_off_by_default(monkeypatch: pytest.MonkeyPatch):
    """run_agent collects the basics (ports, sign-ins, ...) before the model starts. A test
    that drives run_agent with scripted tools must not trigger real checks; the tests
    of the collection layer itself delete this variable."""
    monkeypatch.setenv("KRATOS_COLLECT", "off")


@pytest.fixture(autouse=True)
def _no_real_log_sync_reads(monkeypatch: pytest.MonkeyPatch):
    """The log_sync check reads through ssh_remote directly (not through a tool dispatch):
    a test that runs checks must never make a real SSH or agent read."""
    from kratos.adapters.ssh_remote import SSHResult
    from kratos.collect.sync import engine

    def refuse(*a, **k):
        return SSHResult(ok=False, returncode=-1, stdout="", stderr="no machine in tests")

    monkeypatch.setattr(engine.Fetchers, "default", classmethod(lambda cls: cls(journal=refuse, file=refuse)))


@pytest.fixture(autouse=True)
def _no_real_collection_reads(monkeypatch: pytest.MonkeyPatch):
    """The persistence, live-response and package checks (phase A) read the machine
    through their own default reader, not a tool dispatch: a test that runs the
    standard audit or a scheduled run must not read a real machine through them (the
    phase A audit found 19 tests doing so). A test that wants data passes its own
    `reader=` to record.run, as the feature tests do."""
    from kratos.adapters.ssh_remote import SSHResult
    from kratos.live import record as live_record
    from kratos.persist import record as persist_record
    from kratos.pkgvuln import record as pkg_record

    def refuse(*a, **k):
        return SSHResult(ok=False, returncode=-1, stdout="", stderr="no machine in tests")

    for mod in (live_record, persist_record, pkg_record):
        monkeypatch.setattr(mod, "_default_reader", refuse)
    from kratos.adapters import ssh_remote
    monkeypatch.setattr(ssh_remote, "warm_connection", lambda: False)   # collection's real SSH warm-up


@pytest.fixture(autouse=True)
def _restore_process_globals():
    """Several tests set the active target / data folder (module globals, like /target
    does). Restore them after every test so a later test never runs against a machine
    an earlier one picked -- that made results depend on test order."""
    from kratos import kratos_config as kc

    target, data_dir = kc._active_target_override, kc._active_data_dir
    yield
    kc._active_target_override, kc._active_data_dir = target, data_dir


@pytest.fixture(autouse=True)
def _budget_isolated(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch):
    """Every model call passes the budget guard (kratos.budget), which writes the
    usage ledger to the active data folder. A test that sets none must never
    reach the real data/kratos.db, nor send a real budget notification."""
    from pathlib import Path

    from kratos import paths
    from kratos.budget import guard
    from kratos.budget.ledger import BudgetLedger

    real = paths.default_data_dir().resolve()
    original_init = BudgetLedger.__init__

    def guarded_init(self, data_dir):
        if Path(data_dir).resolve() == real:
            raise AssertionError(f"a test opened the budget ledger in the real data folder {real}")
        original_init(self, data_dir)

    monkeypatch.setattr(BudgetLedger, "__init__", guarded_init)
    fallback = tmp_path_factory.mktemp("budget-data")
    monkeypatch.setattr(guard, "_fallback_data_dir", lambda: fallback)
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(guard, "_notifier", lambda message, severity: sent.append((message, severity)) or
                        {"status": "sent"})
    monkeypatch.setattr(guard, "_prompt_provider", None)
    monkeypatch.setattr(guard, "_notice_listener", None)
    yield sent

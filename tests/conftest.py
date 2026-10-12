"""Shared test setup."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_self_ssh_probe(monkeypatch: pytest.MonkeyPatch):
    """/investigate-host probes whether Kratos can SSH into its own machine. Tests never
    make that real connection; a test that cares sets its own answer."""
    monkeypatch.setattr("kratos.agent.loop._loopback_ssh_ok", lambda: False)


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
    from kratos.budget import guard

    fallback = tmp_path_factory.mktemp("budget-data")
    monkeypatch.setattr(guard, "_fallback_data_dir", lambda: fallback)
    sent: list[tuple[str, str]] = []
    monkeypatch.setattr(guard, "_notifier", lambda message, severity: sent.append((message, severity)) or
                        {"status": "sent"})
    monkeypatch.setattr(guard, "_prompt_provider", None)
    monkeypatch.setattr(guard, "_notice_listener", None)
    yield sent

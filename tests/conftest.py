"""Shared test setup."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_real_self_ssh_probe(monkeypatch: pytest.MonkeyPatch):
    """/investigate-host probes whether Kratos can SSH into its own machine. Tests never
    make that real connection; a test that cares sets its own answer."""
    monkeypatch.setattr("kratos.agent.loop._loopback_ssh_ok", lambda: False)

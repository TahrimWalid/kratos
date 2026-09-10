"""The per-target run lock (agent/target_lock.py) — A6 §6 concurrency.

flock is per-open-file-description, so even within one process a second acquire
on the same target conflicts; that's what lets a scheduled run (one process) and
an interactive run (another) serialize.
"""
from __future__ import annotations

from kratos.agent import target_lock as L


def test_same_target_is_exclusive(tmp_path):
    h1 = L.try_acquire_target(tmp_path, "10.0.0.1")
    assert h1 is not None
    h2 = L.try_acquire_target(tmp_path, "10.0.0.1")  # busy
    assert h2 is None
    L.release_target(h1)
    h3 = L.try_acquire_target(tmp_path, "10.0.0.1")  # re-acquirable after release
    assert h3 is not None
    L.release_target(h3)


def test_different_targets_do_not_block(tmp_path):
    a = L.try_acquire_target(tmp_path, "10.0.0.1")
    b = L.try_acquire_target(tmp_path, "127.0.0.1")  # self-host vs target: independent
    assert a is not None and b is not None
    L.release_target(a)
    L.release_target(b)


def test_release_none_is_safe(tmp_path):
    L.release_target(None)  # no raise


def test_blocking_returns_immediately_when_free(tmp_path):
    h = L.acquire_target_blocking(tmp_path, "10.0.0.1", timeout=5.0)
    assert h is not None
    L.release_target(h)


def test_blocking_times_out_when_held(tmp_path):
    held = L.try_acquire_target(tmp_path, "10.0.0.1")
    assert held is not None
    # Short timeout so the test is fast; must give up (never hang).
    got = L.acquire_target_blocking(tmp_path, "10.0.0.1", timeout=0.3, poll=0.05)
    assert got is None
    L.release_target(held)


def test_blocking_aborts_on_should_stop(tmp_path):
    held = L.try_acquire_target(tmp_path, "10.0.0.1")
    got = L.acquire_target_blocking(tmp_path, "10.0.0.1", timeout=10.0,
                                    should_stop=lambda: True)
    assert got is None  # cancelled immediately, didn't wait the 10s
    L.release_target(held)


def test_target_slug_neutralizes_odd_values(tmp_path):
    # A weird/empty target still yields a usable, path-safe lockfile.
    p = L.target_lock_path(tmp_path, "a/b c:d")
    assert p.name.startswith("target-") and "/" not in p.name
    assert L.target_lock_path(tmp_path, "").name == "target-default.lock"
    h = L.try_acquire_target(tmp_path, None)
    assert h is not None
    L.release_target(h)

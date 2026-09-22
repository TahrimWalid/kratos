"""SQLite persistence tests for the sub-agent telemetry store (capability 1)."""
from __future__ import annotations

import time

import pytest

from kratos.storage.subagent_store import SubAgentStore


@pytest.fixture
def store(tmp_path):
    return SubAgentStore(tmp_path / "kratos.db")


def test_pairing_code_is_single_use(store):
    code = store.create_pairing_code(name="web-01")["code"]
    result = store.redeem_pairing_code(code, agent_id="agent-1", hostname="web-01", agent_version="0.1.0")
    assert result is not None
    assert result["target_id"].startswith("tgt_")

    second = store.redeem_pairing_code(code, agent_id="agent-1", hostname="web-01", agent_version="0.1.0")
    assert second is None  # already used


def test_unknown_pairing_code_rejected(store):
    assert store.redeem_pairing_code("NOPE-0000", agent_id=None, hostname=None, agent_version=None) is None


def test_expired_pairing_code_rejected(store, monkeypatch):
    code = store.create_pairing_code()["code"]

    # Force the TTL check to see this code as expired without sleeping 15 minutes.
    import kratos.storage.subagent_store as mod

    monkeypatch.setattr(mod, "_is_expired", lambda _expires_at: True)
    assert store.redeem_pairing_code(code, agent_id=None, hostname=None, agent_version=None) is None


def test_redeemed_target_is_authenticatable_by_token(store):
    code = store.create_pairing_code()["code"]
    paired = store.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.1.0")
    target = store.get_target_by_token(paired["token"])
    assert target is not None
    assert target["target_id"] == paired["target_id"]
    assert target["hostname"] == "web-01"


def test_unknown_token_returns_none(store):
    assert store.get_target_by_token("not-a-real-token") is None


def test_revoked_target_token_no_longer_authenticates(store):
    code = store.create_pairing_code()["code"]
    paired = store.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.1.0")
    store.revoke_target(paired["target_id"])
    assert store.get_target_by_token(paired["token"]) is None
    # But the target record itself still exists (revoked, not deleted).
    assert store.get_target(paired["target_id"])["revoked_at"] is not None


def test_record_telemetry_updates_last_seen_and_is_queryable(store):
    code = store.create_pairing_code()["code"]
    paired = store.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.1.0")
    target_id = paired["target_id"]

    payload = {"host": {"hostname": "web-01"}, "disk": {"used_pct": 42.0}}
    store.record_telemetry(target_id, payload, seq=1, collected_at="2026-09-22T00:00:00+00:00")

    latest = store.get_latest_telemetry(target_id)
    assert latest["seq"] == 1
    assert latest["payload"] == payload

    target = store.get_target(target_id)
    assert target["last_seen"] is not None


def test_telemetry_retention_is_bounded_per_target(store, monkeypatch):
    import kratos.storage.subagent_store as mod

    monkeypatch.setattr(mod, "TELEMETRY_RETENTION_PER_TARGET", 3)
    code = store.create_pairing_code()["code"]
    target_id = store.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.1.0")["target_id"]

    for i in range(10):
        store.record_telemetry(target_id, {"i": i}, seq=i, collected_at=None)

    recent = store.list_recent_telemetry(target_id, limit=100)
    assert len(recent) == 3
    # Newest-first, and retention kept the LATEST rows, not the earliest.
    assert [r["payload"]["i"] for r in recent] == [9, 8, 7]


def test_list_targets_returns_all_paired(store):
    for i in range(3):
        code = store.create_pairing_code(name=f"host-{i}")["code"]
        store.redeem_pairing_code(code, agent_id=f"a{i}", hostname=f"host-{i}", agent_version="0.1.0")
    targets = store.list_targets()
    assert len(targets) == 3


def test_get_latest_telemetry_none_when_no_data(store):
    code = store.create_pairing_code()["code"]
    target_id = store.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.1.0")["target_id"]
    assert store.get_latest_telemetry(target_id) is None


def test_concurrent_writers_do_not_corrupt(tmp_path):
    """Two SubAgentStore handles onto the same file (mirrors two processes:
    core-server + a CLI status query) must not corrupt each other's writes --
    same concern session_store.py's WAL-mode design already addresses for
    its own tables."""
    db_path = tmp_path / "kratos.db"
    store_a = SubAgentStore(db_path)
    store_b = SubAgentStore(db_path)

    code = store_a.create_pairing_code()["code"]
    target_id = store_b.redeem_pairing_code(code, agent_id="a1", hostname="web-01", agent_version="0.1.0")["target_id"]

    for i in range(20):
        (store_a if i % 2 == 0 else store_b).record_telemetry(target_id, {"i": i}, seq=i, collected_at=None)

    recent = store_a.list_recent_telemetry(target_id, limit=100)
    assert len(recent) == 20

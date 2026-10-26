"""C.3: the automatic hunt when the threat-intel cache learns malicious addresses (HUNT-001)."""
from __future__ import annotations

import json
import socket
import subprocess
import time

import pytest

from hunt_fixtures import event
from kratos.adapters import threat_intel
from kratos.events.store import EventStore
from kratos.hunt import auto, store
from kratos.lifecycle import query as Q

NOW = time.time()
DAY = 86400.0


@pytest.fixture
def cache(tmp_path, monkeypatch):
    path = tmp_path / "otx_pulses.json"
    monkeypatch.setattr(threat_intel, "CACHE_FILE", path)

    def write(ips):
        path.write_text(json.dumps({"synced_at": "2026-10-26T00:00:00+00:00", "indicator_count": len(ips),
                                    "indicators": {ip: [{"pulse_id": "p1", "pulse_name": "Test pulse \x1b[31mX",
                                                         "description": ""}] for ip in ips}}))
    return write


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("the automatic hunt must not reach the network or start a process")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)


def test_a_new_malicious_address_seen_before_becomes_hunt_001(tmp_path, cache):
    EventStore(tmp_path / "kratos.db").add([
        event(NOW - 5 * DAY, n=1, source_ip="198.51.100.7", user_name="alice"),
        event(NOW - 4 * DAY, n=2, source_ip="198.51.100.7", user_name="alice"),
        event(NOW - DAY, n=3, target="db01", source_ip="203.0.113.5")])
    cache(["198.51.100.7", "192.0.2.99"])
    sent = []
    out = auto.hunt_new_intel(tmp_path, notifier=lambda *a, **k: sent.append((a, k)) or True)
    assert out["hunted"] == 2 and out["hits"] == {"web01": ["198.51.100.7"]}
    assert [f["id"] for f in out["findings"]] == ["HUNT-001"]
    f = out["findings"][0]
    assert f["severity"] == "high" and f["subject"] == "198.51.100.7" and f["state"] == "open"
    ev = "\n".join(f["evidence"])
    assert "OTX: Test pulse" in ev and "\x1b" not in ev
    assert "2 record(s), first" in ev and "What the hunt could see on this machine" in ev
    rows = Q.list_findings(tmp_path, target="web01")
    assert [r["rule_id"] for r in rows] == ["HUNT-001"]
    assert Q.list_findings(tmp_path, target="db01") == []
    run = store.recent(tmp_path, source="auto")[0]
    assert run["actor"] == auto.ACTOR and len(run["indicators"]) == 2


def test_an_address_not_seen_raises_nothing_and_is_not_hunted_twice(tmp_path, cache):
    EventStore(tmp_path / "kratos.db").add([event(NOW - DAY, source_ip="203.0.113.5")])
    cache(["192.0.2.99"])
    out = auto.hunt_new_intel(tmp_path)
    assert out["hunted"] == 1 and out["hits"] == {} and out["findings"] == []
    assert auto.hunt_new_intel(tmp_path)["hunted"] == 0
    cache(["192.0.2.99", "203.0.113.5"])          # the next update adds one: only it is hunted
    out = auto.hunt_new_intel(tmp_path)
    assert out["hunted"] == 1 and out["hits"] == {"web01": ["203.0.113.5"]}


def test_the_batch_is_bounded(tmp_path, cache):
    from kratos import settings_store
    from kratos.hunt import settings as S

    settings_store.set(S.AUTO_MAX_INDICATORS, 10, data_dir=tmp_path, actor="test")
    cache([f"192.0.2.{i}" for i in range(1, 26)])
    out = auto.hunt_new_intel(tmp_path)
    assert out["hunted"] == 10 and out["remaining"] == 15
    assert auto.hunt_new_intel(tmp_path)["hunted"] == 10


def test_hits_accumulate_in_one_snapshot_per_machine(tmp_path, cache):
    EventStore(tmp_path / "kratos.db").add([event(NOW - DAY, n=1, source_ip="198.51.100.7"),
                                            event(NOW - DAY, n=2, source_ip="203.0.113.5")])
    cache(["198.51.100.7"])
    auto.hunt_new_intel(tmp_path)
    cache(["198.51.100.7", "203.0.113.5"])
    auto.hunt_new_intel(tmp_path)
    files = list((tmp_path / "hunt" / "results").glob("hunt_*.json"))
    assert len(files) == 1
    doc = json.loads(files[0].read_text())
    assert sorted(h["address"] for h in doc["hits"]) == ["198.51.100.7", "203.0.113.5"]
    keys = {r["subject"] for r in Q.list_findings(tmp_path, target="web01")}
    assert keys == {"198.51.100.7", "203.0.113.5"}


def test_the_findings_engine_reads_the_hunt_snapshot(tmp_path, cache):
    """A later correlation of the machine keeps HUNT-001 (the one findings path)."""
    from kratos.adapters.findings_engine import find_latest_inputs, snapshot_sources

    assert "hunt" in {s.category for s in snapshot_sources()}
    EventStore(tmp_path / "kratos.db").add([event(NOW - DAY, source_ip="198.51.100.7")])
    cache(["198.51.100.7"])
    auto.hunt_new_intel(tmp_path)
    inputs = find_latest_inputs(tmp_path, target="web01")
    assert inputs["hunt"] is not None
    assert find_latest_inputs(tmp_path, target="db01")["hunt"] is None
    doc = auto.load_recent(inputs["hunt"])
    assert [f.id for f in auto.build(doc)] == ["HUNT-001"]


def test_the_cache_update_hook_runs_the_hunt(tmp_path, cache, monkeypatch):
    EventStore(tmp_path / "kratos.db").add([event(NOW - DAY, source_ip="198.51.100.7")])
    cache(["198.51.100.7"])
    msg = threat_intel.after_cache_update(tmp_path)
    assert "1 seen before on web01" in msg and "HUNT-001" in msg
    assert "no address the cache lists is new" in threat_intel.after_cache_update(tmp_path)


def test_a_failing_hunt_never_undoes_the_sync(tmp_path, cache, monkeypatch):
    def broken(*_a, **_k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(auto, "hunt_new_intel", broken)
    assert "failed: RuntimeError" in threat_intel.after_cache_update(tmp_path)

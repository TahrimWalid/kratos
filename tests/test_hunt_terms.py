"""C.3: the hunt's term index over stored events (kratos.hunt.terms)."""
import json
import time

import pytest

from hunt_fixtures import event
from kratos.events.store import EventStore
from kratos.hunt import terms as T
from kratos.storage.sqlite_files import connect_store

NOW = time.time()
SHA = "cd" * 32


@pytest.fixture
def store(tmp_path):
    return EventStore(tmp_path / "kratos.db")


def _terms(tmp_path, target="web01"):
    conn = connect_store(tmp_path / "kratos.db")
    try:
        return {(T.KINDS_BY_CODE[k], v) for k, v in conn.execute(
            "SELECT kind, value FROM host_event_terms WHERE target = ?", (target,))}
    finally:
        conn.close()


def test_every_field_kind_is_indexed_at_insert(tmp_path, store):
    store.add([event(NOW - 60, source_ip="198.51.100.7", destination_ip="203.0.113.5", related_ip=("192.0.2.1",),
                     user_name="alice", user_effective_name="root", user_target_name="bob", related_user=("carol",),
                     process_name="nc", process_executable="/tmp/.x/nc", file_path="/etc/cron.d/job",
                     file_sha256=SHA, url_original="https://Evil.Example.COM/x?y=1",
                     audit_paths=("/var/tmp/drop",), audit_created_paths=("/dev/shm/a",))])
    got = _terms(tmp_path)
    ip = {T.ip_from_key(v) for k, v in got if k == "ip"}
    assert ip == {"198.51.100.7", "203.0.113.5", "192.0.2.1"}
    assert {v for k, v in got if k == "account"} == {"alice", "root", "bob", "carol"}
    assert ("sha256", SHA) in got
    assert {v for k, v in got if k == "program"} == {"nc"}
    assert {v for k, v in got if k == "path"} == {"/tmp/.x/nc", "/etc/cron.d/job", "/var/tmp/drop", "/dev/shm/a"}
    assert ("domain", "evil.example.com") in got


def test_url_host_that_is_an_address_is_an_address(tmp_path, store):
    store.add([event(NOW, url_original="http://198.51.100.9:8080/a")])
    assert ("ip", T.ip_key("198.51.100.9")) in _terms(tmp_path)


def test_a_duplicate_event_adds_no_terms(tmp_path, store):
    e = event(NOW, source_ip="198.51.100.7")
    assert store.add([e]) == 1 and store.add([e]) == 0
    conn = connect_store(tmp_path / "kratos.db")
    assert conn.execute("SELECT COUNT(*) FROM host_event_terms").fetchone()[0] == 1
    conn.close()


def test_one_machines_terms_never_answer_another(tmp_path, store):
    store.add([event(NOW, target="web01", source_ip="198.51.100.7")])
    from kratos.hunt.indicators import classify
    from kratos.hunt.search import run_hunt

    r = run_hunt(tmp_path, [classify("198.51.100.7")], machines=["db01"], record=False)
    assert r.indicators[0].total_events == 0
    r = run_hunt(tmp_path, [classify("198.51.100.7")], machines=["web01"], record=False)
    assert r.indicators[0].total_events == 1


def _old_store(tmp_path, n):
    """A database whose events were stored before the index existed."""
    store = EventStore(tmp_path / "kratos.db")
    store.add([event(NOW - i, n=i, source_ip=f"198.51.100.{i % 200 + 1}", user_name="alice") for i in range(n)])
    conn = connect_store(tmp_path / "kratos.db")
    conn.execute("DELETE FROM host_event_terms")
    conn.execute("DELETE FROM schema_versions WHERE component = ?", (T.COMPONENT,))
    conn.execute("DROP TABLE host_event_terms_state")
    conn.commit()
    conn.close()
    from kratos.storage import migrations

    migrations._migrated.clear()
    return store


def test_backfill_is_resumable_and_idempotent(tmp_path):
    _old_store(tmp_path, 120)
    conn = connect_store(tmp_path / "kratos.db")
    T.migrate(conn, tmp_path / "kratos.db")
    st = T.state(conn)
    assert st["upto"] == 120 and not st["done"] and st["remaining"] == 120
    st = T.backfill(conn, seconds=0, batch=50)            # one batch, then stops (the deadline passed)
    assert st["through"] == 50 and st["remaining"] == 70
    st = T.backfill(conn, seconds=30, batch=50)
    assert st["done"] and st["remaining"] == 0
    n = conn.execute("SELECT COUNT(*) FROM host_event_terms").fetchone()[0]
    conn.execute("UPDATE host_event_terms_state SET through = 0, done_at = NULL")
    conn.commit()
    T.backfill(conn, seconds=30)                          # running it again adds nothing new
    assert conn.execute("SELECT COUNT(*) FROM host_event_terms").fetchone()[0] == n == 240
    conn.close()


def test_unindexed_events_are_still_found_by_their_main_fields(tmp_path, monkeypatch):
    _old_store(tmp_path, 30)
    from kratos import settings_store
    from kratos.hunt import settings as S
    from kratos.hunt.indicators import classify
    from kratos.hunt.search import run_hunt

    settings_store.set(S.INDEX_SECONDS, 0, data_dir=tmp_path, actor="test")
    conn = connect_store(tmp_path / "kratos.db")
    T.migrate(conn, tmp_path / "kratos.db")
    conn.close()
    monkeypatch.setattr(T, "BACKFILL_BATCH", 1)
    r = run_hunt(tmp_path, [classify("198.51.100.5")], machines=["web01"], record=False)
    res = r.indicators[0]
    assert not r.index["done"] and r.index["remaining"] == 29
    assert res.total_events == 1 and [h.via for h in res.hits] == ["column"]
    from kratos.hunt.report import render

    assert "not indexed yet" in render(r)


def test_a_reused_row_id_does_not_answer(tmp_path, store):
    store.add([event(NOW - 100, source_ip="198.51.100.7")])
    conn = connect_store(tmp_path / "kratos.db")
    rid = conn.execute("SELECT id FROM host_events").fetchone()[0]
    # a person deletes the event outside Kratos; the term row stays behind
    conn.execute("DROP TRIGGER IF EXISTS host_events_append_only")
    conn.execute("DELETE FROM host_events WHERE id = ?", (rid,))
    conn.commit()
    conn.close()
    store.add([event(NOW - 5, n=1, source_ip="203.0.113.5")])   # may take the same row id
    from kratos.hunt.indicators import classify
    from kratos.hunt.search import run_hunt

    r = run_hunt(tmp_path, [classify("198.51.100.7")], machines=["web01"], record=False)
    assert r.indicators[0].total_events == 0


def test_prune_removes_the_terms_of_the_events_it_removes(tmp_path, store):
    from kratos import dataprune

    store.add([event(NOW - 40 * 86400, source_ip="198.51.100.7"), event(NOW - 60, n=1, source_ip="203.0.113.5")])
    plan = dataprune.plan_prune(tmp_path, "host_events", 30)
    dataprune.apply_prune(tmp_path, plan, actor="alice via cli")
    got = _terms(tmp_path)
    assert {T.ip_from_key(v) for k, v in got if k == "ip"} == {"203.0.113.5"}


def test_cidr_range_keys():
    import ipaddress

    lo, hi = T.ip_range(ipaddress.ip_network("198.51.100.0/24"))
    assert lo <= T.ip_key("198.51.100.200") <= hi
    assert not lo <= T.ip_key("198.51.101.1") <= hi
    lo6, hi6 = T.ip_range(ipaddress.ip_network("2001:db8::/32"))
    assert lo6 <= T.ip_key("2001:db8::1") <= hi6 and not lo6 <= T.ip_key("2001:db9::1") <= hi6
    assert not lo6 <= T.ip_key("198.51.100.1") <= hi6            # v4 and v6 never mix
    assert T.ip_from_key(T.ip_key("2001:db8::1")) == "2001:db8::1"


def test_terms_of_doc_ignores_junk():
    assert T.terms_of_doc({"source": {"ip": "not-an-ip"}, "file": {"hash": {"sha256": "short"}}}) == set()
    assert T.terms_of_doc({"url": {"original": "no host here"}}) == set()
    assert T.terms_of_doc({"file": {"path": "relative/x"}}) == set()


def test_an_address_written_only_in_the_log_text_is_indexed(tmp_path, store):
    store.add([event(NOW - 40 * 86400, message="Connection closed by invalid user x 198.51.100.7 port 22 [preauth]"),
               event(NOW - 60, n=1, message="mac 00:1a:2b:3c:4d:5e at 10:03:51 and 1.2.3.4.5")])
    got = {T.ip_from_key(v) for k, v in _terms(tmp_path) if k == "ip"}
    assert got == {"198.51.100.7"}
    from kratos.hunt.indicators import classify
    from kratos.hunt.search import run_hunt

    res = run_hunt(tmp_path, [classify("198.51.100.7")], machines=["web01"], record=False).indicators[0]
    # 40 days old: far outside the text scan, found through the index -- and labelled as text
    assert res.total_events == 1 and res.hits[0].via == "text"


def test_a_new_kind_of_term_reindexes_what_is_stored(tmp_path):
    """Step 2 resets the backfill, so events stored by an older Kratos get their text addresses."""
    store = _old_store(tmp_path, 3)
    conn = connect_store(tmp_path / "kratos.db")
    T.migrate(conn, tmp_path / "kratos.db")
    assert T.state(conn)["upto"] == 3 and not T.state(conn)["done"]
    conn.close()

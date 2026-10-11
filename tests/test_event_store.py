"""EventStore: append-only, deduplicated, queryable by each index (spec §5.7)."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from kratos.adapters.auth_log_parse import classify_auth_message
from kratos.events import converters as C
from kratos.events.store import MAX_LIMIT, EventStore, record_events
from kratos.storage.migrations import schema_version
from kratos.storage.sqlite_files import connect_store

UTC = timezone.utc
T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def _ev(minute, ident="sshd", msg=None, target="10.136.28.168", ip="10.136.28.52", user="admin"):
    msg = msg or f"Failed password for invalid user {user} from {ip} port {1000 + minute} ssh2"
    ts = (T0 + timedelta(minutes=minute)).isoformat()
    ctx = C.ReadContext(target=target, transport="ssh", read=C.READ_JOURNAL_AUTH, created=T0, run_id="r1")
    return C.from_auth_event(classify_auth_message(ts, target, ident, msg, msg), ctx=ctx)


@pytest.fixture
def store(tmp_path):
    return EventStore(tmp_path / "kratos.db")


def test_empty_db_migration(tmp_path, store):
    assert store.count("10.136.28.168") == 0
    conn = connect_store(tmp_path / "kratos.db")
    assert schema_version(conn, "events") == 1
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {"host_events", "host_events_append_only", "host_events_ts", "host_events_ip", "host_events_user",
            "host_events_proc", "host_events_sha256"} <= names
    conn.close()
    assert (tmp_path / "kratos.db").stat().st_mode & 0o077 == 0


def test_migration_on_an_existing_kratos_db(tmp_path):
    # A database other stores already use (sessions, settings) gains the table.
    from kratos.storage.session_store import SessionStore

    SessionStore(tmp_path / "kratos.db").create_session(["x"], "m")
    assert EventStore(tmp_path / "kratos.db").add([_ev(1)]) == 1


def test_dedupe(store):
    batch = [_ev(m) for m in range(5)]
    assert store.add(batch) == 5
    assert store.add(batch + [_ev(5)]) == 1           # overlapping window re-read
    assert store.count("10.136.28.168") == 6
    assert store.add([]) == 0


def test_same_line_on_two_machines_is_two_events(store):
    assert store.add([_ev(1), _ev(1, target="10.0.0.2")]) == 2


def test_update_aborts_delete_allowed(tmp_path, store):
    store.add([_ev(1), _ev(2)])
    conn = connect_store(tmp_path / "kratos.db")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE host_events SET action = 'x'")
    conn.execute("DELETE FROM host_events WHERE ts < ?", ((T0 + timedelta(minutes=2)).timestamp(),))
    conn.close()
    assert store.count("10.136.28.168") == 1


def test_queries_by_each_index(store):
    store.add([_ev(1, ip="10.0.0.1", user="alice"), _ev(2, ip="10.0.0.2", user="bob"),
               _ev(3, ident="sudo", msg="ubuntu : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls"),
               _ev(4, ip="10.0.0.1", user="carol")])
    t = "ubuntu@10.136.28.168"  # any spelling of the machine
    assert [e.user_name for e in store.query(t, source_ip="10.0.0.1")] == ["carol", "alice"]
    assert [e.user_name for e in store.query(t, source_ip="10.0.0.1", newest_first=False)] == ["alice", "carol"]
    assert store.count(t, user="bob") == 1
    # A sudo-run command is indexed by the command it started (sudo is the provider).
    assert store.count(t, process="ls") == 1 and store.count(t, process="sshd") == 3
    assert store.count(t, action="ssh_failed_login") == 3 and store.count(t, dataset="kratos.auth") == 4
    assert store.count(t, start=T0 + timedelta(minutes=2), end=T0 + timedelta(minutes=4)) == 2  # half-open
    assert store.count(t, start=(T0 + timedelta(minutes=4)).timestamp()) == 1
    assert store.count(t, sha256="0" * 64) == 0
    assert store.count("10.9.9.9") == 0


def test_limit_is_capped(store, monkeypatch):
    import kratos.events.store as S

    store.add([_ev(m) for m in range(3)])
    assert len(store.query("10.136.28.168", limit=2)) == 2
    assert len(store.query("10.136.28.168", limit=10**9)) == 3
    seen = {}
    real = S.connect_store
    monkeypatch.setattr(S, "connect_store", lambda path: _SpyConn(real(path), seen))
    store.query("10.136.28.168", limit=999_999)
    assert seen["limit"] == MAX_LIMIT == 10_000


class _SpyConn:
    """Records the LIMIT parameter a query is sent with."""

    def __init__(self, conn, seen):
        self._c, self._seen = conn, seen

    def execute(self, sql, params=()):
        if "LIMIT" in sql:
            self._seen["limit"] = params[-1]
        return self._c.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._c, name)


def test_query_returns_the_stored_events_exactly(store):
    events = [_ev(m) for m in range(3)]
    store.add(events)
    assert store.query("10.136.28.168", newest_first=False) == events


def test_filter_values_are_parameters_not_sql(store):
    store.add([_ev(1)])
    assert store.count("10.136.28.168", user="x' OR '1'='1") == 0
    assert store.count("10.136.28.168' OR '1'='1") == 0


def test_naive_datetime_bounds_rejected(store):
    with pytest.raises(ValueError):
        store.count("x", start=datetime(2026, 1, 1))


def test_record_events_is_best_effort(tmp_path, caplog):
    assert record_events([_ev(1)], data_dir=tmp_path) == 1
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x")
    assert record_events([_ev(2)], data_dir=blocker) is None      # can't open: no exception
    assert "could not store events" in caplog.text


def test_targets_listing(store):
    store.add([_ev(1), _ev(2), _ev(1, target="localhost")])
    assert store.targets() == [("10.136.28.168", 2), ("loopback", 1)]


@pytest.mark.parametrize("column, value, index", [
    ("source_ip", "10.0.0.1", "host_events_ip"), ("user_name", "bob", "host_events_user"),
    ("process_name", "sshd", "host_events_proc"), ("file_sha256", "ab" * 32, "host_events_sha256")])
def test_each_pivot_query_uses_its_index(tmp_path, store, column, value, index):
    store.add([_ev(1)])
    conn = connect_store(tmp_path / "kratos.db")
    plan = " ".join(r[3] for r in conn.execute(
        f"EXPLAIN QUERY PLAN SELECT doc FROM host_events WHERE target = ? AND {column} = ? AND ts >= ? AND ts < ? "
        "ORDER BY ts DESC, id DESC LIMIT 100", ("t", value, 0.0, 1.0)))
    conn.close()
    assert index in plan, plan

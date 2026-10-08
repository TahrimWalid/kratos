"""
Review v2 F-5: kratos.db holds pairing tokens; it (and SQLite's -wal/-shm
files) must be owner-only, whatever the umask, through every store.
"""
from __future__ import annotations

import os
import sqlite3
import stat

import pytest

from kratos.storage import sqlite_files
from kratos.storage.anomaly_store import AnomalyStore
from kratos.storage.session_store import SessionStore
from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import routing
from kratos.timewin import snapshots


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def open_umask():
    old = os.umask(0o022)  # the common default that made the db world-readable
    yield
    os.umask(old)


@pytest.mark.parametrize("make", [
    lambda d: SubAgentStore(d / "kratos.db").create_pairing_code(name="x"),
    lambda d: WhitelistStore(d / "kratos.db").request_resync("t1"),
    lambda d: SessionStore(d / "kratos.db").create_session(["10.0.0.5"], "test"),
    lambda d: AnomalyStore(d / "kratos.db"),
    lambda d: snapshots._db(d).close(),
])
def test_every_store_creates_the_database_owner_only(tmp_path, open_umask, make):
    make(tmp_path)
    db = tmp_path / "kratos.db"
    assert _mode(db) == 0o600
    for suffix in ("-wal", "-shm"):
        companion = tmp_path / f"kratos.db{suffix}"
        if companion.exists():
            assert _mode(companion) == 0o600, suffix


def test_sqlite_gives_its_new_companion_files_the_databases_mode(tmp_path, open_umask):
    db = tmp_path / "kratos.db"
    conn = sqlite_files.connect_private(db, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    assert (tmp_path / "kratos.db-wal").exists() and (tmp_path / "kratos.db-shm").exists()
    assert {_mode(p) for p in tmp_path.iterdir()} == {0o600}
    conn.close()


def test_an_existing_world_readable_database_is_tightened(tmp_path, open_umask):
    db = tmp_path / "kratos.db"
    conn = sqlite3.connect(db)  # what older Kratos did: umask mode
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE t (x)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()  # keep the connection open so -wal/-shm stay on disk
    for p in tmp_path.iterdir():
        os.chmod(p, 0o644)
    SubAgentStore(db).list_targets()                       # first open by the new code
    assert {p.name: _mode(p) for p in tmp_path.iterdir()} == {p.name: 0o600 for p in tmp_path.iterdir()}
    conn.close()


def test_a_symlinked_companion_is_not_followed(tmp_path, open_umask):
    outside = tmp_path / "outside"
    outside.write_text("x")
    os.chmod(outside, 0o644)
    (tmp_path / "d").mkdir()
    os.symlink(outside, tmp_path / "d" / "kratos.db-wal")
    sqlite_files.prepare_private_db(tmp_path / "d" / "kratos.db")
    assert _mode(outside) == 0o644


def test_read_only_open_never_creates_a_database(tmp_path):
    assert routing._read_link(tmp_path / "kratos.db", "10.0.0.5") is None
    assert not (tmp_path / "kratos.db").exists()


def test_a_database_owned_by_someone_else_is_reported_not_fatal(tmp_path, monkeypatch, caplog):
    db = tmp_path / "kratos.db"
    db.touch()
    os.chmod(db, 0o644)

    def denied(*_a, **_k):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(sqlite_files.os, "chmod", denied)
    monkeypatch.setattr(sqlite_files, "_warned", set())
    sqlite_files.prepare_private_db(db)
    sqlite_files.prepare_private_db(db)
    warnings = [r for r in caplog.records if "chmod 600" in r.getMessage()]
    assert len(warnings) == 1  # said once, and the open still went ahead

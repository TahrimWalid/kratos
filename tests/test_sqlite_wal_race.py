"""Two connections opening a brand-new kratos.db at once (B.3: two chat requests on a
fresh data folder). Turning a new file to WAL needs an exclusive lock, and SQLite says
"database is locked" at once -- without its busy handler -- to the second opener;
connect_store waits it out instead of failing the request."""
from __future__ import annotations

import threading

from kratos.storage.sqlite_files import connect_store


def test_many_first_opens_at_once_all_succeed(tmp_path):
    for round_ in range(25):
        path = tmp_path / f"kratos{round_}.db"
        errors: list[BaseException] = []
        barrier = threading.Barrier(8)

        def open_it():
            try:
                barrier.wait()
                conn = connect_store(path)
                assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
                conn.close()
            except BaseException as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=open_it) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []

"""
Real concurrent-write test for storage/session_store.py -- don't skip this
test or assume SQLite handles concurrent access automatically without
checking. Same class of risk as the self-writing loop's kept_tools/
metadata.json corruption bug (see docs/DESIGN.md's "Self-writing tool loop"
section): concurrent writes to a shared local file under ordinary
concurrent use (two terminal tabs), not malice.

Uses real, separate OS processes (multiprocessing, not threads) writing to
the SAME db file at the same time -- threads share the GIL and wouldn't
exercise cross-process SQLite file locking the way two real `kratos`
invocations would.
"""
from __future__ import annotations

import multiprocessing
import sqlite3
from pathlib import Path

import pytest

from kratos.storage.session_store import SessionStore

WORKERS = 4
SESSIONS_PER_WORKER = 5
TURNS_PER_SESSION = 4


def _worker(db_path_str: str, worker_id: int, results_path_str: str) -> None:
    db_path = Path(db_path_str)
    store = SessionStore(db_path)
    created_session_ids = []
    for s in range(SESSIONS_PER_WORKER):
        sid = store.create_session([f"10.0.{worker_id}.{s}"], "qwen2.5:7b")
        created_session_ids.append(sid)
        for t in range(TURNS_PER_SESSION):
            turn_id = store.start_turn(sid, f"worker{worker_id}-session{s}-turn{t}")
            store.touch_session(sid)
            store.complete_turn(turn_id, "final_answer", transcript_ref=f"/tmp/w{worker_id}s{s}t{t}.log")
    # Report what THIS worker actually wrote, so the parent can verify
    # nothing was silently lost, not just that the DB is structurally intact.
    with open(results_path_str, "a", encoding="utf-8") as f:
        for sid in created_session_ids:
            f.write(sid + "\n")


def test_concurrent_writers_no_corruption_no_lost_writes(tmp_path):
    db_path = tmp_path / "concurrency_test.db"
    results_path = tmp_path / "worker_session_ids.txt"
    results_path.write_text("")

    # Real, separate processes -- not threads.
    procs = [
        multiprocessing.Process(target=_worker, args=(str(db_path), i, str(results_path)))
        for i in range(WORKERS)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=45)

    for p in procs:
        assert not p.is_alive(), "a worker process hung -- treat as a real failure, not a timeout artifact"
        assert p.exitcode == 0, f"a worker process crashed (exitcode={p.exitcode}) -- likely a real locking/corruption failure"

    # 1) The database file itself is not corrupted.
    conn = sqlite3.connect(db_path)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok", f"database corruption detected: {integrity}"

        # 2) No writes were silently lost: every session_id every worker
        # reported writing is actually present, with the full expected
        # number of turns, all correctly completed (not stuck at
        # status='in_progress' from a lost/half-applied write).
        expected_session_ids = [
            line.strip() for line in results_path.read_text().splitlines() if line.strip()
        ]
        assert len(expected_session_ids) == WORKERS * SESSIONS_PER_WORKER, (
            "a worker's own result log is short -- a worker-side write failed silently"
        )

        session_rows = conn.execute("SELECT session_id FROM sessions").fetchall()
        actual_session_ids = {r[0] for r in session_rows}
        assert actual_session_ids == set(expected_session_ids), (
            f"session row mismatch -- expected {len(expected_session_ids)} sessions, "
            f"found {len(actual_session_ids)} in the DB. Missing: "
            f"{set(expected_session_ids) - actual_session_ids}"
        )

        for sid in expected_session_ids:
            turns = conn.execute(
                "SELECT status, completed_at FROM goal_history WHERE session_id = ?", (sid,)
            ).fetchall()
            assert len(turns) == TURNS_PER_SESSION, (
                f"session {sid} has {len(turns)} turns, expected {TURNS_PER_SESSION} -- lost write"
            )
            for status, completed_at in turns:
                assert status == "final_answer" and completed_at is not None, (
                    f"session {sid} has a turn stuck at status={status!r} completed_at={completed_at!r} "
                    "-- a concurrent write was lost or half-applied"
                )
    finally:
        conn.close()

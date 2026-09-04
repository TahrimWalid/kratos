"""
Tests for SessionStore.archive_turns_from -- the non-destructive truncate
behind the TUI's "edit a previous turn" (design 10a): backing up to an earlier
turn and resending discards that turn and everything after it (soft-delete,
recoverable), never touching earlier turns.
"""
from __future__ import annotations

from kratos.storage.session_store import SessionStore


def _seed(tmp_path, goals):
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["target"], "model")
    for g in goals:
        tid = store.start_turn(sid, g)
        store.complete_turn(tid, "chat_reply")
    return store, sid


def test_archive_turns_from_discards_from_cutoff_onward(tmp_path):
    store, sid = _seed(tmp_path, ["a", "b", "c", "d"])
    seqs = [h["seq"] for h in store.get_goal_history(sid)]  # [1, 2, 3, 4]

    n = store.archive_turns_from(sid, seqs[2])  # from the 3rd turn onward

    assert n == 2  # c and d archived
    assert [h["goal"] for h in store.get_goal_history(sid)] == ["a", "b"]
    # non-destructive: everything is still recoverable
    assert [h["goal"] for h in store.get_goal_history(sid, include_archived=True)] == ["a", "b", "c", "d"]


def test_archive_turns_from_is_idempotent(tmp_path):
    store, sid = _seed(tmp_path, ["a", "b", "c"])
    seqs = [h["seq"] for h in store.get_goal_history(sid)]

    assert store.archive_turns_from(sid, seqs[1]) == 2   # b, c
    assert store.archive_turns_from(sid, seqs[1]) == 0   # already archived -> no-op


def test_archive_turns_from_first_seq_clears_all(tmp_path):
    store, sid = _seed(tmp_path, ["a", "b"])
    seqs = [h["seq"] for h in store.get_goal_history(sid)]

    assert store.archive_turns_from(sid, seqs[0]) == 2
    assert store.get_goal_history(sid) == []

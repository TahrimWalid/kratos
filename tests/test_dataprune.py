"""`kratos data prune` (kratos.dataprune, docs/phaseB/B.5 §5.3): preview first, the
person's own action only, dependent data refused, every prune recorded."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from argparse import Namespace
from pathlib import Path

import pytest

from kratos import dataprune, settings_store
from kratos.events.store import EventStore
from kratos.storage.session_store import SessionStore

DAY = 86400
NOW = time.time()


def _old(p: Path, days: float) -> None:
    t = NOW - days * DAY
    os.utime(p, (t, t))


def _traces(dd: Path) -> tuple[Path, Path]:
    d = dd / "traces" / "2026-01-01"
    d.mkdir(parents=True)
    old, new = d / "old.json", dd / "traces" / "2026-01-01" / "new.json"
    old.write_text(json.dumps({"run_id": "old"}))
    new.write_text(json.dumps({"run_id": "new"}))
    _old(old, 100)
    return old, new


def test_preview_deletes_nothing_and_apply_deletes_exactly_the_plan(tmp_path):
    old, new = _traces(tmp_path)
    plan = dataprune.plan_prune(tmp_path, "traces", 90, now=NOW)
    assert plan.files == [old] and plan.counts == {"run records": 1} and plan.bytes > 0
    assert old.exists() and new.exists()          # planning is read-only
    done = dataprune.apply_prune(tmp_path, plan, actor="tester via test")
    assert done == {"run records": 1}
    assert not old.exists() and new.exists()
    hist = dataprune.history(tmp_path)
    assert len(hist) == 1 and hist[0]["category"] == "traces" and hist[0]["items"] == 1
    assert hist[0]["actor"] == "tester via test" and hist[0]["older_than_days"] == 90


def test_refuses_inside_a_tool_call(tmp_path):
    old, _ = _traces(tmp_path)
    plan = dataprune.plan_prune(tmp_path, "traces", 90, now=NOW)
    with settings_store.tool_call_scope("run_linux_command"):
        with pytest.raises(dataprune.PruneError, match="agent tools may not delete"):
            dataprune.apply_prune(tmp_path, plan, actor="x via y")
    assert old.exists()
    assert dataprune.history(tmp_path) == []


def test_needs_an_actor_and_whole_days(tmp_path):
    plan = dataprune.plan_prune(tmp_path, "traces", 1, now=NOW)
    with pytest.raises(dataprune.PruneError):
        dataprune.apply_prune(tmp_path, plan, actor=" ")
    with pytest.raises(dataprune.PruneError):
        dataprune.plan_prune(tmp_path, "traces", 0)
    with pytest.raises(dataprune.PruneError, match="snapshots prune"):
        dataprune.plan_prune(tmp_path, "snapshots", 30)


def _events(dd: Path) -> None:
    EventStore(dd / "kratos.db")._connect().close()  # creates its table
    conn = sqlite3.connect(dd / "kratos.db")
    for i, ts in enumerate((NOW - 200 * DAY, NOW - 150 * DAY, NOW - DAY)):
        conn.execute("INSERT INTO host_events (target, event_id, ts, dataset, schema_version, doc) "
                     "VALUES ('t', ?, ?, 'kratos.auth', 1, '{}')", (f"e{i}", ts))
    conn.commit()
    conn.close()


def test_host_events_dependent_coverage_is_refused_without_the_flag(tmp_path):
    from kratos.collect.sync import cursors

    _events(tmp_path)
    cursors.add_span(tmp_path, "t", "auth", NOW - 210 * DAY, NOW - 100 * DAY, complete=True)
    plan = dataprune.plan_prune(tmp_path, "host_events", 120, now=NOW)
    assert plan.counts["log lines"] == 2
    assert plan.blockers and "coverage" in plan.blockers[0]
    with pytest.raises(dataprune.PruneError, match="depends on this"):
        dataprune.apply_prune(tmp_path, plan, actor="x via cli")
    conn = sqlite3.connect(tmp_path / "kratos.db")
    assert conn.execute("SELECT COUNT(*) FROM host_events").fetchone()[0] == 3
    done = dataprune.apply_prune(tmp_path, plan, actor="x via cli", force_orphans=True)
    assert done["log lines"] == 2
    assert conn.execute("SELECT COUNT(*) FROM host_events").fetchone()[0] == 1
    (start,) = conn.execute("SELECT start_ts FROM sync_coverage").fetchone()
    assert start == pytest.approx(plan.cutoff)          # Kratos no longer claims the pruned period
    assert dataprune.history(tmp_path)[0]["forced"] == 1


def test_sessions_prune_turns_their_transcripts_and_empty_sessions(tmp_path):
    store = SessionStore(tmp_path / "kratos.db")
    sdir = tmp_path / "sessions"
    sdir.mkdir()
    old_sid = store.create_session(["t"], "m")
    new_sid = store.create_session(["t"], "m")
    t_old = store.start_turn(old_sid, "old question")
    t_new = store.start_turn(new_sid, "new question")
    p_old, p_new = sdir / f"{old_sid}_turn{t_old}.json", sdir / f"{new_sid}_turn{t_new}.json"
    p_old.write_text("[]")
    p_new.write_text("[]")
    store.complete_turn(t_old, "final_answer", transcript_ref=str(p_old))
    store.complete_turn(t_new, "final_answer", transcript_ref=str(p_new))
    old_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(NOW - 100 * DAY))
    conn = sqlite3.connect(tmp_path / "kratos.db")
    conn.execute("UPDATE goal_history SET started_at = ? WHERE turn_id = ?", (old_iso, t_old))
    conn.execute("UPDATE sessions SET last_active_at = ? WHERE session_id = ?", (old_iso, old_sid))
    conn.commit()
    plan = dataprune.plan_prune(tmp_path, "sessions", 30, now=NOW)
    assert plan.rows["goal_history"] == [t_old] and plan.rows["sessions"] == [old_sid]
    assert p_old in plan.files and p_new not in plan.files
    dataprune.apply_prune(tmp_path, plan, actor="x via cli")
    assert not p_old.exists() and p_new.exists()
    assert store.get_session(old_sid) is None and store.get_session(new_sid) is not None
    assert [h["goal"] for h in store.get_goal_history(new_sid)] == ["new question"]


def test_cli_preview_then_apply(tmp_path, capsys):
    from kratos.cli import data_cmds

    old, new = _traces(tmp_path)
    args = Namespace(data_dir=tmp_path, data_action="prune", category="traces", older_than=90,
                     apply=False, force_orphans=False)
    assert data_cmds.cmd_data(args) == 0
    out = capsys.readouterr().out
    assert "would remove 1 run records" in out and "Preview only" in out and old.exists()
    args.apply = True
    assert data_cmds.cmd_data(args) == 0
    assert "Removed: 1 run records" in capsys.readouterr().out
    assert not old.exists() and new.exists()
    assert data_cmds.cmd_data(Namespace(data_dir=tmp_path, data_action="history")) == 0
    assert "traces" in capsys.readouterr().out


def test_prune_never_follows_a_symlink_out_of_the_data_folder(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text("keep me")
    dd = tmp_path / "data"
    d = dd / "traces" / "2026-01-01"
    d.mkdir(parents=True)
    link = d / "evil.json"
    link.symlink_to(outside)
    plan = dataprune.plan_prune(dd, "traces", 1, now=NOW + 10 * DAY)
    dataprune.apply_prune(dd, plan, actor="x via cli")
    assert outside.read_text() == "keep me"

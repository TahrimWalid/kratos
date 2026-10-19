"""The verdict and suggestion store (triage.store): append-only verdicts, newest
shown, and the model's suggestions with a people-only resolution."""
from __future__ import annotations

import sqlite3

import pytest

from kratos.triage import store as S
from kratos.triage.verdict import Verdict, VerifyCheck


def test_verdict_round_trip_newest_wins(tmp_path):
    key = "a" * 64
    S.record_verdict(tmp_path, finding_key=key, verifier="a fresh read", cost="quick", run_id="r1",
                     duration=1.2, now=100.0,
                     verdict=Verdict("not_reproduced", "gone", checks=(VerifyCheck("packages", "ssh", 0.5),)))
    S.record_verdict(tmp_path, finding_key=key, verifier="a fresh read", cost="quick", run_id="r2",
                     duration=0.9, now=200.0,
                     verdict=Verdict("reproduced", "still there", evidence=("package foo",)))
    latest = S.latest_verdict(tmp_path, key)
    assert latest.verdict.verdict == "reproduced"
    assert latest.run_id == "r2"
    assert latest.verdict.evidence == ("package foo",)
    assert len(S.verdict_history(tmp_path, key)) == 2
    many = S.latest_verdicts(tmp_path, [key, "b" * 64])
    assert set(many) == {key}


def test_verdicts_are_append_only(tmp_path):
    key = "c" * 64
    S.record_verdict(tmp_path, finding_key=key, verifier="v", cost="quick", run_id=None, duration=0.0,
                     verdict=Verdict("reproduced", "x"))
    conn = S._connect(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE finding_verdicts SET verdict = 'partly' WHERE finding_key = ?", (key,))
    finally:
        conn.close()


def test_suggestion_lifecycle(tmp_path):
    key = "d" * 64
    sid = S.record_suggestion(tmp_path, finding_key=key, rule_id="CORR-SSH-001", target="t", run_id="r",
                              kind="false_positive", why="our own scanner", now=10.0)
    assert [s["id"] for s in S.suggestions_for(tmp_path, key)] == [sid]
    assert [s["id"] for s in S.open_suggestions(tmp_path)] == [sid]
    S.resolve_suggestion(tmp_path, sid, state="dismissed", by="alice", now=20.0)
    assert S.suggestions_for(tmp_path, key, state="new") == []
    assert S.get_suggestion(tmp_path, sid)["state"] == "dismissed"
    assert S.open_suggestions(tmp_path) == []


def test_bad_kinds_rejected(tmp_path):
    with pytest.raises(ValueError):
        S.record_suggestion(tmp_path, finding_key="e" * 64, rule_id="X-1", target=None, run_id=None,
                            kind="not_a_kind", why="x")
    with pytest.raises(ValueError):
        S.resolve_suggestion(tmp_path, 1, state="verified", by="x")

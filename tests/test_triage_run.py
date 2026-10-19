"""auto_verify, retest, and verdict rendering in the block and digest (B.1)."""
from __future__ import annotations

import time
from types import SimpleNamespace

from kratos import finding_facts
from kratos.collect.digest import _finding_tag
from kratos.lifecycle.keys import finding_key
from kratos.target_key import target_key
from kratos.triage import run as R
from kratos.triage import store as S
from kratos.triage.verdict import Verdict

TARGET = "10.0.0.9"


def _finding(rule_id="CORR-SSH-001", *, severity="high", change="new", subject="", entities=()):
    key = finding_key(rule_id, target_key(TARGET), subject)
    return {"id": rule_id, "finding_key": key, "subject": subject, "entities": list(entities),
            "severity": severity, "title": f"{rule_id} title", "change": change}


def _report(findings=(), *, checks=(("auth_activity", "ok"),), transport="ssh"):
    return SimpleNamespace(findings=list(findings),
                           checks=[SimpleNamespace(name=n, status=s, reason="", summary="", gaps=[])
                                   for n, s in checks],
                           transport=transport, disabled_reason=None)


# --------------------------------------------------------------------------- auto_verify
def test_auto_verify_attaches_and_stores(tmp_path):
    f = _finding(entities=["10.136.28.52"])
    got = R.auto_verify([f], data_dir=tmp_path, target=TARGET, budget_seconds=10,
                        recollect=lambda names: _report([dict(f)]),
                        dispatch=lambda t, a: {"status": "ok", "result": {
                            "window": {"label": "w", "coverage_percent": 100},
                            "counts": {"ssh_failed_login": 40}, "bursts": [{"x": 1}],
                            "failed_login_sources": [{"ip": "10.136.28.52"}], "fail2ban": {"bans": 0}}})
    assert f["verdict"]["verdict"] == "reproduced"
    assert f["finding_key"] in got
    assert S.latest_verdict(tmp_path, f["finding_key"]).verdict.verdict == "reproduced"


def test_auto_verify_reuse_mode_issues_no_fresh_read(tmp_path):
    # the automatic pass re-uses the collection Kratos just ran (report=) -- it must not
    # call recollect or dispatch (no second read on the target), and a present finding is
    # "reproduced by a fresh read".
    f = _finding(entities=["10.136.28.52"])
    report = _report([dict(f)], checks=(("auth_activity", "ok"),))
    calls = {"recollect": 0, "dispatch": 0}

    def boom_recollect(names):
        calls["recollect"] += 1
        raise AssertionError("reuse mode must not re-collect")

    def boom_dispatch(t, a):
        calls["dispatch"] += 1
        raise AssertionError("reuse mode must not dispatch a fresh read")

    got = R.auto_verify([f], data_dir=tmp_path, target=TARGET, budget_seconds=10, report=report,
                        recollect=boom_recollect, dispatch=boom_dispatch)
    assert calls == {"recollect": 0, "dispatch": 0}
    assert f["verdict"]["verdict"] == "reproduced"
    assert "fresh read" in f["verdict"]["tag"]
    assert f["finding_key"] in got


def test_auto_verify_budget_zero_is_a_noop(tmp_path):
    f = _finding()
    assert R.auto_verify([f], data_dir=tmp_path, target=TARGET, budget_seconds=0) == {}
    assert "verdict" not in f


def test_auto_verify_skips_non_serious_and_decided(tmp_path):
    low = _finding(severity="low")
    old = _finding(subject="x", change="unchanged")
    got = R.auto_verify([low, old], data_dir=tmp_path, target=TARGET, budget_seconds=10,
                        recollect=lambda names: _report(), dispatch=lambda t, a: {"status": "ok", "result": {}})
    assert got == {}


def test_auto_verify_skips_already_verified(tmp_path):
    f = _finding()
    f["verdict"] = Verdict("reproduced", "x").as_dict()
    calls = []
    R.auto_verify([f], data_dir=tmp_path, target=TARGET, budget_seconds=10,
                  recollect=lambda names: calls.append(names) or _report(), dispatch=lambda t, a: {})
    assert calls == []        # not re-read


def test_auto_verify_quick_only_skips_slow(tmp_path):
    net = _finding("NET-001", subject="22/tcp", entities=["22/tcp"])   # NET verifier is slow
    got = R.auto_verify([net], data_dir=tmp_path, target=TARGET, budget_seconds=10, quick_only=True,
                        recollect=lambda names: _report([dict(net)], checks=(("ports", "ok"),)),
                        dispatch=lambda t, a: {})
    assert got == {}
    assert "verdict" not in net


def test_auto_verify_over_budget_marks_pending_then_finishes_in_background(tmp_path):
    a = _finding("CORR-SSH-001", entities=["10.136.28.52"])
    b = _finding("CORR-001", subject="b", entities=["10.136.28.52"])

    def slow_dispatch(t, args):
        time.sleep(0.08)
        return {"status": "ok", "result": {"window": {"label": "w", "coverage_percent": 100},
                                           "counts": {"ssh_failed_login": 0}, "bursts": [],
                                           "failed_login_sources": [], "fail2ban": {"bans": 0}}}

    R.auto_verify([a, b], data_dir=tmp_path, target=TARGET, budget_seconds=0.01,
                  recollect=lambda names: _report(), dispatch=slow_dispatch)
    # at least one was left pending (budget ran out before it ran synchronously)
    pending = [x for x in (a, b) if isinstance(x.get("verdict"), dict) and x["verdict"].get("pending")]
    assert pending, "expected a 'verifying…' placeholder on the finding(s) left over the budget"
    # the background finisher records its verdict within a short wait
    deadline = time.monotonic() + 3.0
    key = pending[0]["finding_key"]
    while time.monotonic() < deadline and S.latest_verdict(tmp_path, key) is None:
        time.sleep(0.05)
    assert S.latest_verdict(tmp_path, key) is not None


# --------------------------------------------------------------------------- rendering
def test_answer_block_shows_the_verdict_tag():
    f = _finding(entities=["10.136.28.52"])
    f["verdict"] = Verdict("reproduced", "still there").as_dict()
    block = finding_facts.answer_block([f], "the attacker is 10.136.28.52")
    assert "reproduced by a fresh read" in block


def test_digest_tag_shows_the_verdict():
    f = _finding(entities=["10.136.28.52"])
    f["verdict"] = Verdict("not_reproduced", "gone").as_dict()
    assert "not reproduced -- retest?" in _finding_tag(f, with_title=True)


def test_verifying_placeholder_shows_in_the_block():
    f = _finding()
    f["verdict"] = dict(R.PENDING)
    assert "verifying" in finding_facts.answer_block([f], "something").lower()


# --------------------------------------------------------------------------- enrich
def test_attach_stored_verdicts_fills_missing_without_overwriting(tmp_path):
    f_stored = _finding(subject="a")        # has a stored verdict, none attached -> filled
    f_fresh = _finding("CORR-001", subject="b")  # already verdicted this run -> left as is
    S.record_verdict(tmp_path, finding_key=f_stored["finding_key"], verifier="v", cost="quick", run_id=None,
                     duration=0.0, verdict=Verdict("not_reproduced", "gone earlier"))
    f_fresh["verdict"] = Verdict("reproduced", "fresh this run").as_dict()
    R.attach_stored_verdicts([f_stored, f_fresh], tmp_path)
    assert f_stored["verdict"]["verdict"] == "not_reproduced"      # filled from the store
    assert f_fresh["verdict"]["sentence"] == "fresh this run"      # not overwritten


def test_enrich_rows_adds_verdict_and_suggestions(tmp_path):
    key = "f" * 64
    S.record_verdict(tmp_path, finding_key=key, verifier="v", cost="quick", run_id=None, duration=0.0,
                     verdict=Verdict("partly", "x", detail="filtered"))
    S.record_suggestion(tmp_path, finding_key=key, rule_id="NET-001", target="t", run_id=None,
                        kind="lower_severity", why="only from Kratos")
    rows = R.enrich_rows([{"finding_key": key}, {"finding_key": "g" * 64}], tmp_path)
    assert rows[0]["verdict"]["verdict"] == "partly"
    assert rows[0]["suggestions"][0]["kind"] == "lower_severity"
    assert rows[1]["verdict"] is None

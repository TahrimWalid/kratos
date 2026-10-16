"""The gate rule (evals/gate.py §3.6), on synthetic results: a hard failure, a scored
drop that triggers a re-run then fails, a total-drop failure, and clean passes."""
from __future__ import annotations

from evals import gate

BASE = {"scenarios": {
    "A1": {"person_pass": 5, "n": 5}, "A8": {"person_pass": 5, "n": 5}, "R1_live": {"person_pass": 5, "n": 5},
    "F1": {"person_pass": 5, "n": 5}, "C6": {"person_pass": 5, "n": 5}}}


def _r(sid, kind, p, f, ma=None):
    return gate.ScenarioResult(sid, kind, person_pass=p, person_fail=f, model_alone_pass=ma if ma is not None else p)


def test_a_hard_scenario_failure_fails_the_gate():
    rep = gate.decide([_r("F1", "hard", 4, 1), _r("A1", "scored", 5, 0)], BASE)
    assert not rep.passed and any("F1" in h for h in rep.hard_failures)


def test_all_hard_passing_and_scored_at_baseline_passes_quietly():
    rep = gate.decide([_r("F1", "hard", 5, 0), _r("C6", "hard", 5, 0), _r("A1", "scored", 5, 0)], BASE)
    assert rep.passed and not rep.needs_rerun and not rep.scored_regressions


def test_a_two_run_drop_asks_for_a_rerun_then_a_big_drop_fails():
    first = gate.decide([_r("A1", "scored", 3, 2)], BASE)       # 2 below baseline
    assert "A1" in first.needs_rerun and first.passed        # not failed yet -- re-run first
    reran = gate.decide([_r("A1", "scored", 2, 8)], BASE, reran=True)   # 20% vs 100% baseline
    assert not reran.passed and reran.scored_regressions


def test_a_rerun_that_recovers_passes():
    reran = gate.decide([_r("A1", "scored", 9, 1)], BASE, reran=True)   # 90% vs 100% -- within 20pts
    assert reran.passed


def test_the_scored_total_may_not_drop_more_than_five_points():
    # every scored scenario down one run: 5/5 -> 4/5 across four scenarios = an 20pt total drop
    results = [_r(s, "scored", 4, 1) for s in ("A1", "A8", "R1_live")] + [_r("C6", "hard", 5, 0)]
    rep = gate.decide(results, BASE)
    assert rep.total_drop > gate.TOTAL_DROP_FAIL and not rep.passed


def test_a_model_alone_drop_is_a_warning_not_a_failure():
    # person sees 5/5 (the block covers), model alone 1/5 -- a warning, gate still passes
    rep = gate.decide([_r("A1", "scored", 5, 0, ma=1)], BASE)
    assert rep.passed and any("A1" in w for w in rep.model_alone_warnings)


def test_an_errored_run_is_not_counted_as_a_fail():
    runs = {"A1": [{"person_sees": "pass", "model_alone": "pass", "retries": 0},
                   {"person_sees": "incomplete", "model_alone": "incomplete", "retries": 0}]}
    (res,) = gate.results_from_runs(runs, {"A1": "scored"})
    assert res.person_pass == 1 and res.person_fail == 0 and res.errored == 1 and res.n == 1

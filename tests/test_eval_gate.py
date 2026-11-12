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


def _others():
    """The other scored scenarios at their baseline: a re-run scenario now counts in the total too,
    so a test of the per-scenario rule needs the rest of a real gate around it."""
    return [_r(s, "scored", 5, 0) for s in ("A8", "R1_live")]


def test_a_rerun_that_recovers_passes():
    reran = gate.decide([_r("A1", "scored", 9, 1)] + _others(), BASE, reran=True)   # 90% vs 100% -- within 20pts
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


def test_a_rerun_is_judged_by_its_rate_not_its_pass_count():
    """6 of 10 after a re-run is 60% against a 100% baseline: a fail, although 6 > 5 passes
    (found when E.2's gate run passed a 40-point G1_suid drop)."""
    reran = gate.decide([_r("A1", "scored", 6, 4)] + _others(), BASE, reran=True)
    assert not reran.passed and reran.scored_regressions[0]["rate"] == 60.0
    assert gate.decide([_r("A1", "scored", 9, 1)] + _others(), BASE, reran=True).passed


# --- runs at a different N from the baseline (2026-11-12: N=20 G1 rows, gate at N=5) ---------
BASE_MIXED = {"scenarios": {**BASE["scenarios"],
                            "G1_suid": {"person_pass": 19, "n": 20},
                            "G1_gap_encryption": {"person_pass": 15, "n": 20}}}


def test_a_full_run_against_a_19_of_20_row_does_not_rerun():
    for p in (5, 4, 3):                          # 3/5 is 1.75 runs short of 95 % x 5
        rep = gate.decide([_r("G1_suid", "scored", p, 5 - p)], BASE_MIXED)
        assert "G1_suid" not in rep.needs_rerun, p


def test_two_of_five_against_a_19_of_20_row_reruns():
    rep = gate.decide([_r("G1_suid", "scored", 2, 3)], BASE_MIXED)
    assert "G1_suid" in rep.needs_rerun


def test_the_rerun_trigger_counts_runs_at_the_gates_own_n():
    """75 % x 5 = 3.75 expected: 2/5 is 1.75 short (no re-run), 1/5 is 2.75 short (re-run)."""
    assert "G1_gap_encryption" not in gate.decide([_r("G1_gap_encryption", "scored", 2, 3)], BASE_MIXED).needs_rerun
    assert "G1_gap_encryption" in gate.decide([_r("G1_gap_encryption", "scored", 1, 4)], BASE_MIXED).needs_rerun


def test_a_row_at_a_different_n_is_in_the_total():
    """Every scored scenario counts, one weight each: A1 100 % + G1_gap 75 % baseline average 87.5 %."""
    rep = gate.decide([_r("A1", "scored", 5, 0), _r("G1_gap_encryption", "scored", 4, 1)], BASE_MIXED)
    assert any("scored total     90.0%  (baseline 87.5%" in line for line in rep.lines), rep.lines
    assert rep.total_drop == -2.5


def test_the_total_weights_each_scenario_once_not_by_n():
    """A 20-run row must not outweigh a 5-run one: A1 at 60 % (3/5) is a 20-point drop for one
    scenario of two, a 20-point drop in the average -> fails the 5-point total."""
    rep = gate.decide([_r("A1", "scored", 3, 2), _r("G1_suid", "scored", 19, 1)], BASE_MIXED, reran=True)
    assert rep.total_drop == 20.0 and not rep.passed


def test_a_rerun_scenarios_rate_uses_all_its_runs():
    """After a re-run the results hold every run (5 + the top-up to 10): its rate is over all of them."""
    runs = {"G1_suid": [{"person_sees": "pass", "model_alone": "pass", "retries": 0}] * 8
            + [{"person_sees": "fail", "model_alone": "fail", "retries": 0}] * 2}
    (res,) = gate.results_from_runs(runs, {"G1_suid": "scored"})
    assert res.n == 10 and res.rate == 80.0
    rep = gate.decide([res] + _others() + [_r("A1", "scored", 5, 0)], BASE_MIXED, reran=True)
    # (95 - 80) / 4 scenarios = 3.75 points: within the 5-point total, and within 20 for G1_suid
    assert rep.passed and abs(rep.total_drop - 3.75) < 0.06


def _old_rule(results, baseline):
    """Today's trigger (count drop) and total (pooled counts), for runs at the baseline's N."""
    rows = baseline["scenarios"]
    rerun = [r.id for r in results if r.kind == "scored" and rows[r.id]["person_pass"] - r.person_pass >= 2]
    sc = [r for r in results if r.kind == "scored"]
    bt = 100.0 * sum(rows[r.id]["person_pass"] for r in sc) / sum(rows[r.id]["n"] for r in sc)
    gt = 100.0 * sum(r.person_pass for r in sc) / sum(r.n for r in sc)
    return rerun, round(bt - gt, 1)


def test_with_matching_ns_the_trigger_and_total_are_as_before():
    import itertools

    base = {"scenarios": {"A1": {"person_pass": 5, "n": 5}, "A8": {"person_pass": 4, "n": 5},
                          "R1_live": {"person_pass": 3, "n": 5}}}
    for p in itertools.product(range(6), repeat=3):
        results = [_r(s, "scored", k, 5 - k) for s, k in zip(("A1", "A8", "R1_live"), p)]
        rep = gate.decide(results, base)
        assert (sorted(rep.needs_rerun), rep.total_drop) == (lambda r, t: (sorted(r), t))(*_old_rule(results, base)), p

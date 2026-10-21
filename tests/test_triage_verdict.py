"""A verdict shows its age once it is more than an hour old (Phase B audit): yesterday's
"reproduced" must not read like today's, and an earlier run's automatic-pass verdict must
not say "this run's read"."""
from __future__ import annotations

from kratos import finding_facts
from kratos.triage import run as TR
from kratos.triage import store as TS
from kratos.triage.verdict import Verdict, aged_tag, from_this_run

NOW = 1_800_000_000.0


def _v(verdict: Verdict, age_seconds: float) -> dict:
    return {**verdict.as_dict(), "at": NOW - age_seconds}


def test_a_fresh_verdict_shows_no_age():
    assert aged_tag(_v(Verdict("reproduced", "x"), 120), now=NOW) == "reproduced by a fresh read"


def test_an_old_verdict_shows_its_age_in_hours_then_days():
    assert aged_tag(_v(Verdict("reproduced", "x"), 3 * 3600), now=NOW) == "reproduced by a fresh read, 3 h ago"
    assert aged_tag(_v(Verdict("not_reproduced", "x"), 5 * 86400), now=NOW) == "not reproduced -- retest?, 5 days ago"


def test_an_old_automatic_pass_verdict_no_longer_says_this_run():
    seen = from_this_run(Verdict("reproduced", "x"))
    assert aged_tag(_v(seen, 60), now=NOW) == "seen in this run's read -- not re-checked yet"
    old = aged_tag(_v(seen, 2 * 86400), now=NOW)
    assert old == "seen in a read 2 days ago -- not re-checked yet" and "this run" not in old
    partly = from_this_run(Verdict("partly", "x", detail="filtered from Kratos"))
    assert "this run" not in aged_tag(_v(partly, 4 * 3600), now=NOW)


def test_a_verdict_without_a_time_is_shown_as_it_was():
    assert aged_tag(Verdict("reproduced", "x").as_dict(), now=NOW) == "reproduced by a fresh read"
    assert aged_tag(None) is None


def test_a_stored_verdict_attached_to_a_later_runs_finding_carries_its_age(tmp_path):
    import time

    TS.record_verdict(tmp_path, finding_key="k1", verdict=Verdict("reproduced", "still there"),
                      verifier="v", cost="quick", run_id="r1", duration=0.1, now=time.time() - 2 * 86400 - 60)
    findings = [{"id": "CORR-SSH-001", "severity": "high", "finding_key": "k1"}]
    TR.attach_stored_verdicts(findings, tmp_path)
    assert finding_facts.verdict_tag(findings[0]).endswith("2 days ago")
    block = finding_facts.answer_block(findings, "")
    assert "reproduced by a fresh read, 2 days ago" in block
    rows = TR.enrich_rows([{"finding_key": "k1"}], tmp_path)
    assert TR.verdict_tag_of(rows[0]).endswith("2 days ago")

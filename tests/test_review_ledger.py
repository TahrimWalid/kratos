"""E.7b coverage ledger (kratos.review.ledger §3.6): completeness per class is a number;
incomplete coverage is reported, never 'nothing found'. Fails on old code."""
from __future__ import annotations

from kratos.review import ledger as LG


def _rows(*pairs):
    return [{"class": c, "ledger_state": s} for c, s in pairs]


def test_advance_never_regresses():
    assert LG.advance(LG.LOOKED_AT, LG.VERDICT_REACHED) == LG.VERDICT_REACHED
    assert LG.advance(LG.VERDICT_REACHED, LG.LOOKED_AT) == LG.VERDICT_REACHED  # no going back


def test_coverage_counts_reached_per_class():
    rows = _rows(("exec", LG.VERDICT_REACHED), ("exec", LG.LOOKED_AT), ("sql", LG.VERDICT_REACHED))
    cov = LG.coverage(rows)
    assert cov["exec"].total == 2 and cov["exec"].reached == 1 and not cov["exec"].complete
    assert cov["exec"].pct == 50.0
    assert cov["sql"].complete and cov["sql"].pct == 100.0


def test_incomplete_classes_listed():
    rows = _rows(("exec", LG.VERDICT_REACHED), ("path", LG.LEAD_RAISED), ("sql", LG.VERDICT_REACHED))
    inc = LG.incomplete_classes(rows)
    assert [c.cls for c in inc] == ["path"]


def test_overall_pct():
    rows = _rows(("exec", LG.VERDICT_REACHED), ("sql", LG.LOOKED_AT), ("path", LG.VERDICT_REACHED), ("x", LG.LEAD_RAISED))
    assert LG.overall_pct(rows) == 50.0
    assert LG.overall_pct([]) == 100.0

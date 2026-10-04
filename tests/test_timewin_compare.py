"""Comparisons computed in code (docs/time_window_design.md §2F): rates over covered time,
coverage gates, and a statistical test so noise is never reported as a trend."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from kratos.timewin.claims import verify_claims
from kratos.timewin.compare import _binom_two_sided_p, compare_measurements
from kratos.timewin.windows import TimeContext
from zoneinfo import ZoneInfo

DAY = 86400.0


def _w(wid, start, days, label=""):
    return SimpleNamespace(id=wid, start_utc=start, label=label or wid, seconds=days * DAY)


def _s(value, days, cov=100.0):
    return {"metrics": {"ssh_failed_logins": value}, "coverage_percent": cov, "covered_seconds": days * DAY * cov / 100}


def _verdict(a, b, da=1.0, db=1.0, cova=100.0, covb=100.0):
    out = compare_measurements("ssh_failed_logins", [(_w("wB", max(10.0, da) * DAY, db), _s(b, db, covb)),
                                                     (_w("wA", 0.0, da), _s(a, da, cova))])
    return out["pairs"][0], out


def test_small_numbers_are_not_a_trend():
    pair, _ = _verdict(3, 5)
    assert pair["verdict"] == "no_meaningful_change"


def test_a_real_jump_is_an_increase_and_order_is_chronological():
    pair, out = _verdict(10, 100)
    assert pair["verdict"] == "increase" and pair["from"] == "wA" and pair["to"] == "wB"
    assert [r["window"] for r in out["windows"]] == ["wA", "wB"]


def test_partial_period_is_compared_by_rate_not_total():
    # last month: 300 in 30 days; this month so far: 100 in 10 days -> same rate
    pair, out = _verdict(300, 100, da=30, db=10)
    assert pair["verdict"] == "no_meaningful_change"
    assert out["windows"][0]["rate_per_day"] == out["windows"][1]["rate_per_day"] == 10.0


def test_low_or_uneven_coverage_is_not_comparable():
    assert _verdict(10, 100, cova=40.0)[0]["verdict"] == "not_comparable"
    assert _verdict(10, 100, cova=100.0, covb=60.0)[0]["verdict"] == "not_comparable"


def test_large_counts_use_the_normal_approximation_consistently():
    assert _verdict(100000, 101000)[0]["verdict"] == "increase"      # 1% on 100k events is real
    assert _verdict(100000, 100100)[0]["verdict"] == "no_meaningful_change"


def test_binomial_p_value_is_sane():
    assert _binom_two_sided_p(5, 10, 0.5) == pytest.approx(1.0)
    assert _binom_two_sided_p(0, 20, 0.5) < 1e-5


def test_trend_claims_must_match_the_compare_verdict():
    ctx = TimeContext(ZoneInfo("UTC"), now=1_790_000_000)
    ctx.measurements["compare:c1"] = {"metric": "ssh_failed_logins", "values": {3, 5},
                                      "pairs": [{"from": "w2", "to": "w1", "verdict": "no_meaningful_change"}]}
    bad, _ = verify_claims(ctx, "Failed logins went up.", [{"kind": "trend", "comparison": "c1", "direction": "increase"}])
    assert any("concluded 'no_meaningful_change'" in p for p in bad)
    ok, claims = verify_claims(ctx, "No meaningful change: 3 vs 5 failed attempts.",
                               [{"kind": "trend", "comparison": "c1", "direction": "no_meaningful_change"}])
    assert ok == [] and claims[0]["verified"]
    none, _ = verify_claims(ctx, "x", [{"kind": "trend", "comparison": "c9", "direction": "increase"}])
    assert any("must cite a compare_periods result" in p for p in none)


def test_overlapping_periods_are_not_compared():
    """Seen live: 'this week so far' (Mon -> now) vs 'the last 7 days' overlap; the same
    events were counted in both and reported as 'a real difference'."""
    out = compare_measurements("ssh_failed_logins", [(_w("w1", 2 * DAY, 6.4, "this week so far"), _s(120, 6.4)),
                                                     (_w("w2", 1.4 * DAY, 7, "last 7 days"), _s(377, 7))])
    pair = out["pairs"][0]
    assert pair["verdict"] == "not_comparable"
    assert "overlap" in pair["reasons"][0] and "counted in both" in pair["reasons"][0]


def test_adjacent_periods_are_still_compared():
    out = compare_measurements("ssh_failed_logins", [(_w("w1", 7 * DAY, 7), _s(100, 7)),
                                                     (_w("w2", 0.0, 7), _s(10, 7))])
    assert out["pairs"][0]["verdict"] == "increase"


def test_this_week_versus_last_week_means_two_calendar_weeks():
    from datetime import datetime

    from kratos.timewin.phrases import find_time_phrases

    found = find_time_phrases("more failed logins this week than last week?", datetime(2026, 10, 4, 9, 0))
    assert [p.intent for p in found] == [{"kind": "calendar", "unit": "week", "offset": 0, "to_now": True},
                                         {"kind": "calendar", "unit": "week", "offset": -1}]
    alone = find_time_phrases("any failed logins last week?", datetime(2026, 10, 4, 9, 0))
    assert alone[0].intent == {"kind": "rolling", "amount": 7, "unit": "day"}  # the documented default


@pytest.mark.parametrize("claim", [
    {"verdict": "decrease"},           # the key compare_periods itself uses (seen live)
    {"direction": "decreased"},
    {"trend": "Fewer"},
])
def test_a_trend_claim_in_the_tools_own_words_is_verified(claim):
    ctx = TimeContext(ZoneInfo("UTC"), now=1_790_000_000)
    ctx.measurements["compare:c1"] = {"metric": "ssh_failed_logins", "values": {257, 124},
                                      "pairs": [{"from": "w2", "to": "w1", "verdict": "decrease"}]}
    problems, claims = verify_claims(ctx, "Fewer failed logins than before.", [{"kind": "trend", "comparison": "c1", **claim}])
    assert problems == [] and claims[0]["verified"]


def test_a_trend_claim_with_no_direction_says_what_is_missing():
    ctx = TimeContext(ZoneInfo("UTC"), now=1_790_000_000)
    ctx.measurements["compare:c1"] = {"metric": "m", "values": set(),
                                      "pairs": [{"from": "w2", "to": "w1", "verdict": "decrease"}]}
    problems, _ = verify_claims(ctx, "x", [{"kind": "trend", "comparison": "c1"}])
    assert any('give it as "direction"' in p for p in problems)

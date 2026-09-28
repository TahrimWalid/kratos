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
    out = compare_measurements("ssh_failed_logins", [(_w("wB", 10 * DAY, db), _s(b, db, covb)),
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

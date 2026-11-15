"""E.7b cost (kratos.review.cost §3.10, gate answer 2): estimate from real batches, the
ceiling, the daily-cap check, the run's margin limits, the agreed-amount stop. Fails on old code."""
from __future__ import annotations

from kratos.review import cost as CO


def test_estimate_counts_calls_and_prices_tokens():
    # 2 hunter batches; 10 slices, lead_factor 0.3 -> 3 leads -> 3 verifier + 3 fix calls.
    est = CO.estimate([1000, 800], num_slices=10, avg_slice_tokens=200, lead_factor=0.3,
                      rate=(1.0, 2.0), max_leads=200)
    assert est.hunter_calls == 2 and est.verifier_calls == 3 and est.fix_calls == 3
    assert est.calls == 8
    # input = 1800 + (3+3)*(200+400) = 1800 + 3600 = 5400 ; output = 8*300 = 2400
    assert est.input_tokens == 5400 and est.output_tokens == 2400
    # usd = 5400/1e6*1.0 + 2400/1e6*2.0
    assert abs(est.usd - (5400 / 1e6 * 1.0 + 2400 / 1e6 * 2.0)) < 1e-9
    assert est.priced


def test_unpriced_profile_costs_zero_and_always_fits_daily():
    est = CO.estimate([5000], num_slices=100, avg_slice_tokens=300, lead_factor=0.3, rate=None, max_leads=200)
    assert est.usd == 0.0 and not est.priced
    assert CO.fits_daily(est.usd, remaining_daily_usd=0.0)   # a local run spends no dollars


def test_lead_count_capped_by_max_leads():
    est = CO.estimate([100], num_slices=10000, avg_slice_tokens=100, lead_factor=0.3, rate=(1.0, 1.0), max_leads=50)
    assert est.verifier_calls == 50 and est.fix_calls == 50


def test_ceiling_refuses_above_unless_raised():
    assert CO.ceiling_for(2.0, None) == 2.0
    assert CO.ceiling_for(2.0, 5.0) == 5.0
    assert CO.fits_ceiling(1.99, 2.0)
    assert not CO.fits_ceiling(2.01, 2.0)
    assert CO.fits_ceiling(4.0, 2.0, raised_to=5.0)        # raised for this run
    assert not CO.fits_ceiling(6.0, 2.0, raised_to=5.0)


def test_daily_cap_check():
    assert CO.fits_daily(1.0, remaining_daily_usd=1.5)
    assert not CO.fits_daily(2.0, remaining_daily_usd=1.5)


def test_run_limits_add_margin():
    calls, tokens = CO.run_limits(est_calls=120, est_tokens=400_000)
    assert calls == int(120 * 1.25) + 2          # 152
    assert tokens == int(400_000 * 1.25) + 2000  # 502000
    # A review estimated at 120 calls has a limit above 120 (an investigation still stops at 40).
    assert calls > 120


def test_agreed_amount_stop():
    assert not CO.would_exceed(spent_usd=1.0, reserve_usd=0.5, agreed_usd=2.0)
    assert CO.would_exceed(spent_usd=1.8, reserve_usd=0.5, agreed_usd=2.0)
    assert not CO.would_exceed(spent_usd=2.0, reserve_usd=0.0, agreed_usd=2.0)   # exactly at is ok

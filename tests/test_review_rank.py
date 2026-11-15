"""E.7b ranking (kratos.review.rank §3.4): drift first (even past the cap), then
execution-like class, then exposure, then served, then advisory. Fails on old code."""
from __future__ import annotations

from kratos.review import rank as R
from kratos.review.slice import Slice


def mk(name, *, cls="path", drift=False, exposure="unknown", served="imported", advisory=False):
    return Slice(root="/srv/app", rel="app.py", function=name, cls=cls, span=(1, 2),
                 surface_kind="flask", methods=("post",), route="/" + name, segments=[("app.py", 1, 2)],
                 calls=[], touched=("app.py",), imports=frozenset(), text="x", sha256=name * 4,
                 drift=drift, exposure=exposure, served=served, advisory=advisory)


def test_drift_outranks_everything():
    drifted_path = mk("d", cls="path", drift=True, exposure="local")
    hot = mk("h", cls="exec", drift=False, exposure="internet", served="executed", advisory=True)
    assert R.ordered([hot, drifted_path])[0] is drifted_path


def test_exec_class_before_other_classes():
    a = mk("a", cls="exec", exposure="local")
    b = mk("b", cls="path", exposure="internet")
    # exec beats path even though path is more exposed (class ranks above exposure).
    assert R.ordered([b, a])[0] is a


def test_exposure_orders_within_same_class():
    internet = mk("i", cls="path", exposure="internet")
    local = mk("l", cls="path", exposure="local")
    not_running = mk("n", cls="path", exposure="not running")
    assert [s.function for s in R.ordered([local, not_running, internet])] == ["i", "l", "n"]


def test_served_then_advisory_break_ties():
    executed = mk("e", cls="path", exposure="local", served="executed", advisory=False)
    imported_adv = mk("m", cls="path", exposure="local", served="imported", advisory=True)
    assert R.ordered([imported_adv, executed])[0] is executed
    # same served, advisory breaks the tie
    served_plain = mk("s", cls="path", exposure="local", served="served", advisory=False)
    served_adv = mk("t", cls="path", exposure="local", served="served", advisory=True)
    assert R.ordered([served_plain, served_adv])[0] is served_adv


def test_select_keeps_drift_past_the_cap():
    drift = [mk(f"d{i}", drift=True) for i in range(5)]
    plain = [mk(f"p{i}") for i in range(5)]
    kept, dropped = R.select(drift + plain, max_slices=3)
    # all 5 drifted kept even though the cap is 3; every non-drift dropped
    assert sum(1 for s in kept if s.drift) == 5
    assert all(not s.drift for s in plain)
    assert dropped == 5
    assert len(kept) == 5


def test_select_fills_budget_with_non_drift_in_rank_order():
    drift = [mk("d0", drift=True), mk("d1", drift=True)]
    plain = [mk(f"p{i}", exposure="internet") for i in range(10)]
    kept, dropped = R.select(drift + plain, max_slices=5)
    assert len(kept) == 5
    assert dropped == 7
    assert sum(1 for s in kept if s.drift) == 2  # 2 drift + 3 non-drift

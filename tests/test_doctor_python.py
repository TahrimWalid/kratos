"""`kratos doctor` says when the Python running Kratos stops getting security fixes."""
from __future__ import annotations

from datetime import date

from kratos.agent import doctor as D


def test_a_supported_python_passes():
    row = D.python_support((3, 12), date(2026, 10, 27), from_distribution=False)
    assert row["status"] == "pass" and "2028-10-31" in row["detail"]


def test_a_python_close_to_its_end_warns_ahead():
    row = D.python_support((3, 10), date(2026, 10, 27), from_distribution=False)
    assert row["status"] == "warn" and "(4 days)" in row["detail"] and "3.11" in row["fix"]


def test_a_python_past_its_end_warns_with_the_fix():
    row = D.python_support((3, 9), date(2026, 10, 27), from_distribution=False)
    assert row["status"] == "warn" and "stopped getting security fixes on 2025-10-31" in row["detail"]


def test_a_distribution_python_is_explained_not_flagged():
    row = D.python_support((3, 10), date(2027, 1, 1), from_distribution=True)
    assert row["status"] == "info" and "distribution" in row["detail"]


def test_an_unlisted_release_says_nothing_is_announced():
    assert D.python_support((3, 15), date(2026, 10, 27), from_distribution=False)["status"] == "info"


def test_the_doctor_reports_the_python_row():
    assert ("Python", D._check_python) in D._SECTIONS       # run_diagnostics would also reach the target
    out: list = []
    D._check_python(out)
    assert out[0]["check"] == "Python" and out[0]["status"] in ("pass", "warn", "info")

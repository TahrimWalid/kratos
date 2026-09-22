"""Liveness-derivation tests (capability 1) -- pure function, no I/O."""
from __future__ import annotations

from datetime import timedelta

from kratos.subagent.status import (
    STATUS_CONNECTED,
    STATUS_NEVER,
    STATUS_STALE,
    STATUS_UNREACHABLE,
    derive_status,
)
from kratos.utils.timeutil import utc_now, utc_now_iso


def test_never_connected():
    assert derive_status(None) == STATUS_NEVER


def test_unparseable_last_seen_treated_as_never():
    assert derive_status("not a timestamp") == STATUS_NEVER


def test_recent_last_seen_no_live_info_is_connected():
    now = utc_now()
    recent = (now - timedelta(seconds=5)).isoformat(timespec="seconds")
    assert derive_status(recent, now=now) == STATUS_CONNECTED


def test_moderately_old_last_seen_no_live_info_is_stale():
    now = utc_now()
    ts = (now - timedelta(seconds=60)).isoformat(timespec="seconds")
    assert derive_status(ts, now=now) == STATUS_STALE


def test_very_old_last_seen_no_live_info_is_unreachable():
    now = utc_now()
    ts = (now - timedelta(seconds=300)).isoformat(timespec="seconds")
    assert derive_status(ts, now=now) == STATUS_UNREACHABLE


def test_live_false_is_always_unreachable_even_if_recent():
    now = utc_now()
    recent = (now - timedelta(seconds=1)).isoformat(timespec="seconds")
    assert derive_status(recent, live=False, now=now) == STATUS_UNREACHABLE


def test_live_true_recent_is_connected():
    now = utc_now()
    recent = (now - timedelta(seconds=1)).isoformat(timespec="seconds")
    assert derive_status(recent, live=True, now=now) == STATUS_CONNECTED


def test_live_true_but_stale_signal_is_stale_not_connected():
    """The zombie case: a real open socket, but nothing received in a long
    time -- must not read as a blind 'connected' just because the socket
    object still exists."""
    now = utc_now()
    old = (now - timedelta(seconds=300)).isoformat(timespec="seconds")
    assert derive_status(old, live=True, now=now) == STATUS_STALE


def test_boundary_just_inside_connected_window():
    now = utc_now()
    from kratos.subagent.status import CONNECTED_WINDOW_SECONDS

    ts = (now - timedelta(seconds=CONNECTED_WINDOW_SECONDS - 1)).isoformat(timespec="seconds")
    assert derive_status(ts, now=now) == STATUS_CONNECTED


def test_boundary_just_outside_connected_window():
    now = utc_now()
    from kratos.subagent.status import CONNECTED_WINDOW_SECONDS

    ts = (now - timedelta(seconds=CONNECTED_WINDOW_SECONDS + 1)).isoformat(timespec="seconds")
    assert derive_status(ts, now=now) == STATUS_STALE


def test_real_iso_helper_round_trips():
    # Sanity: utc_now_iso()'s own output is accepted (not just synthetic timedeltas).
    assert derive_status(utc_now_iso()) == STATUS_CONNECTED

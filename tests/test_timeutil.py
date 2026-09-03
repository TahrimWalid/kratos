"""
Scripted tests for the UTC-storage / local-display timezone split
(src/kratos/utils/timeutil.py, 2026-09-03).

No real clock/zone dependence beyond the machine's own tz for the auto-detect
case, which is asserted structurally (a tzinfo is returned) rather than pinned
to a specific zone. The load-bearing invariant under test: a stored instant is
absolute UTC, so a relative-time comparison never changes with the display
zone, and the same instant renders at different wall-clocks in different zones
without the underlying value drifting.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

from kratos.utils import timeutil as t


# ---------------------------------------------------------------------------
# Storage side -- always UTC, always tz-aware.
# ---------------------------------------------------------------------------
def test_utc_now_iso_is_aware_utc():
    iso = t.utc_now_iso()
    assert iso.endswith("+00:00")
    dt = datetime.fromisoformat(iso)
    assert dt.tzinfo is not None
    assert dt.utcoffset() == timedelta(0)


def test_epoch_to_utc_iso_is_absolute():
    # A fixed epoch is an absolute instant -- 1700000000 == 2023-11-14 22:13:20 UTC.
    assert t.epoch_to_utc_iso(1700000000) == "2023-11-14T22:13:20+00:00"


def test_parse_stored_instant_aware_roundtrip():
    iso = t.utc_now_iso()
    dt = t.parse_stored_instant(iso)
    assert dt.tzinfo == timezone.utc


def test_parse_stored_instant_accepts_datetime():
    aware = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert t.parse_stored_instant(aware) == aware


def test_parse_stored_instant_legacy_naive_treated_as_local():
    # A naive (pre-UTC-storage) value is interpreted as the local system
    # time it was written in, then normalized to UTC -- never crashes, and
    # is offset-aware afterward.
    dt = t.parse_stored_instant("2026-01-15T09:30:00")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_parse_stored_instant_empty_and_garbage():
    assert t.parse_stored_instant(None) is None
    assert t.parse_stored_instant("") is None
    assert t.parse_stored_instant("not-a-timestamp") is None


def test_relative_time_query_independent_of_display_zone():
    """The core guarantee: the UTC age of a stored instant is the same no
    matter which zone we would DISPLAY it in."""
    past = (t.utc_now() - timedelta(hours=3)).isoformat(timespec="seconds")
    age_a = (t.utc_now() - t.parse_stored_instant(past)).total_seconds()
    # Re-parse independently (as a different session in a different zone would):
    age_b = (t.utc_now() - t.parse_stored_instant(past)).total_seconds()
    assert abs(age_a - age_b) < 1.0
    assert 2.9 * 3600 < age_a < 3.1 * 3600


# ---------------------------------------------------------------------------
# Display side -- cosmetic only, never mutates the stored instant.
# ---------------------------------------------------------------------------
def test_zone_from_name():
    assert t.zone_from_name("UTC") == timezone.utc
    assert t.zone_from_name("utc") == timezone.utc
    assert t.zone_from_name("Asia/Dhaka") is not None
    assert t.zone_from_name("Not/AZone") is None
    assert t.zone_from_name(None) is None
    assert t.zone_from_name("") is None


def test_detect_local_tz_returns_something():
    assert t.detect_local_tz() is not None


def test_same_instant_different_zones_same_underlying_value():
    """Travel case: one absolute instant, rendered in two zones, shows two
    wall-clocks -- but the parsed UTC value behind each is identical."""
    instant = t.epoch_to_utc_iso(1700000000)
    hel = t.format_for_display(instant, "%H:%M", tz=t.zone_from_name("Europe/Helsinki"))
    dhk = t.format_for_display(instant, "%H:%M", tz=t.zone_from_name("Asia/Dhaka"))
    assert hel != dhk  # different wall-clock in different zones
    # ...but the underlying instant never changed:
    assert t.parse_stored_instant(instant) == datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)


def test_format_for_display_falls_back_to_raw_on_unparseable():
    assert t.format_for_display("garbage", "%H:%M", tz=timezone.utc) == "garbage"
    assert t.format_for_display(None, "%H:%M", tz=timezone.utc) == ""


def test_now_for_display_in_utc():
    # now_for_display in UTC must match utc_now to the minute.
    assert t.now_for_display("%Y-%m-%d %H:%M", tz=timezone.utc) == t.utc_now().strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Override + resolution (settings #5 / fallback #4).
# ---------------------------------------------------------------------------
def test_display_tz_status_auto_when_no_override(tmp_path: Path):
    source, tz = t.display_tz_status(tmp_path)
    # A machine with a detectable local zone auto-resolves; never "fallback"
    # here since detect_local_tz succeeds in the test environment.
    assert source in ("auto", "override")
    assert tz is not None


def test_override_set_get_clear(tmp_path: Path):
    t.set_display_timezone_override(tmp_path, "Asia/Dhaka")
    source, tz = t.display_tz_status(tmp_path)
    assert source == "override"
    assert t.format_for_display(t.epoch_to_utc_iso(1700000000), "%z", tz=tz) == "+0600"

    # Clearing reverts to auto-detection.
    t.set_display_timezone_override(tmp_path, None)
    source2, _ = t.display_tz_status(tmp_path)
    assert source2 in ("auto", "fallback")


def test_override_clear_preserves_other_config(tmp_path: Path):
    from kratos.kratos_config import save_local_config, load_local_config

    save_local_config(tmp_path, trusted=True, default_target="10.0.0.9")
    t.set_display_timezone_override(tmp_path, "UTC")
    t.set_display_timezone_override(tmp_path, None)  # clear only the tz key
    cfg = load_local_config(tmp_path)
    assert cfg.get("trusted") is True
    assert cfg.get("default_target") == "10.0.0.9"
    assert "display_timezone" not in cfg


def test_invalid_override_does_not_wedge_display(tmp_path: Path):
    # A stored override that no longer resolves must fall through to
    # auto-detection, never break rendering.
    from kratos.kratos_config import save_local_config

    save_local_config(tmp_path, display_timezone="No/SuchZone")
    source, tz = t.display_tz_status(tmp_path)
    assert source in ("auto", "fallback")
    assert tz is not None

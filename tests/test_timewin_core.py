"""Time-window core (docs/time_window_design.md §2A-§2C): resolver conventions, DST
handling in both hemispheres, the E9/E10 phrase set as a regression suite, named windows.
Clock is always frozen -- nothing here depends on when the suite runs."""
from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from kratos.timewin.phrases import find_time_phrases
from kratos.timewin.windows import TimeContext, TimeIntentError, localize

NY = ZoneInfo("America/New_York")
SYD = ZoneInfo("Australia/Sydney")
UTC = ZoneInfo("UTC")
# Sunday 2026-03-08 10:30 New York -- US DST began at 02:00 this morning.
NOW = datetime(2026, 3, 8, 10, 30, tzinfo=NY)


def ctx(tz=NY, now=NOW, **kw) -> TimeContext:
    return TimeContext(tz, now=now.timestamp(), **kw)


def L(y, mo, d, h=0, mi=0, tz=NY) -> float:
    return datetime(y, mo, d, h, mi, tzinfo=tz).timestamp()


def elapsed_ago(hours=0, minutes=0) -> float:
    return NOW.timestamp() - hours * 3600 - minutes * 60


# ---------------------------------------------------------------------------
# E9/E10 regression: the 22 phrases from the validation experiment, with the exact
# correct window (or the correct refusal) -- the models got 14-19/22; code must get 22/22.
# ---------------------------------------------------------------------------
PHRASES = {
    "in the last 24 hours": ("resolved", elapsed_ago(24), NOW.timestamp()),
    "yesterday": ("resolved", L(2026, 3, 7), L(2026, 3, 8)),
    "since midnight": ("resolved", L(2026, 3, 8), NOW.timestamp()),
    "in the past 90 minutes": ("resolved", elapsed_ago(minutes=90), NOW.timestamp()),
    "over the last 3 days": ("resolved", L(2026, 3, 5, 10, 30), NOW.timestamp()),
    "in the past 36 hours": ("resolved", elapsed_ago(36), NOW.timestamp()),
    "last week": ("default", L(2026, 3, 1, 10, 30), NOW.timestamp()),
    "this month so far": ("resolved", L(2026, 3, 1), NOW.timestamp()),
    "last month": ("default", L(2026, 2, 1), L(2026, 3, 1)),
    "in February": ("resolved", L(2026, 2, 1), L(2026, 3, 1)),
    "between 9am and 5pm yesterday": ("resolved", L(2026, 3, 7, 9), L(2026, 3, 7, 17)),
    "this morning": ("default", L(2026, 3, 8, 6), NOW.timestamp()),  # default, disclosed; so far at 10:30
    "on March 1st": ("resolved", L(2026, 3, 1), L(2026, 3, 2)),
    "since last Monday": ("resolved", L(2026, 3, 2), NOW.timestamp()),
    "the last 2 weeks": ("resolved", L(2026, 2, 22, 10, 30), NOW.timestamp()),
    "between Feb 20 and Feb 25": ("default", L(2026, 2, 20), L(2026, 2, 26)),  # 25th included, disclosed
    "on 03/04": ("ask", None, None),
    "a couple of days ago": ("default", L(2026, 3, 6), L(2026, 3, 7)),
    "last year": ("default", L(2025, 1, 1), L(2026, 1, 1)),
    "in the last 6 months": ("resolved", L(2025, 9, 8, 10, 30), NOW.timestamp()),
    "from 1am to 4am today": ("resolved", L(2026, 3, 8, 1), L(2026, 3, 8, 4)),
    "next week": ("future", None, None),
}


@pytest.mark.parametrize("phrase", list(PHRASES))
def test_validation_phrase_set_resolves_exactly(phrase):
    status, start, end = PHRASES[phrase]
    matches = find_time_phrases(phrase, NOW.replace(tzinfo=None))
    assert len(matches) == 1, [m.text for m in matches]
    m = matches[0]
    assert m.status == status, (m.status, m.note)
    if status in ("resolved", "default"):
        w = ctx().resolve(m.intent, phrase=phrase)
        assert w.start_utc == pytest.approx(start, abs=1) and w.end_utc == pytest.approx(end, abs=1), w.summary()
    if status == "default":
        assert m.note, "every default must carry a disclosure"
    if status == "ask":
        assert len(m.options) >= 2


def test_elapsed_hours_are_real_hours_across_dst():
    w = ctx().resolve({"kind": "rolling", "amount": 24, "unit": "hour"})
    assert w.end_utc - w.start_utc == 24 * 3600


def test_rolling_days_keep_wall_clock_across_dst():
    w = ctx().resolve({"kind": "rolling", "amount": 3, "unit": "day"})
    assert datetime.fromtimestamp(w.start_utc, NY).replace(tzinfo=None) == datetime(2026, 3, 5, 10, 30)
    assert w.end_utc - w.start_utc == 71 * 3600  # one hour was skipped by DST


def test_rolling_month_clamps_day():
    now = datetime(2026, 3, 31, 12, 0, tzinfo=NY)
    w = ctx(now=now).resolve({"kind": "rolling", "amount": 1, "unit": "month"})
    assert datetime.fromtimestamp(w.start_utc, NY).date().isoformat() == "2026-02-28"
    leap = datetime(2028, 3, 31, 12, 0, tzinfo=NY)
    w2 = ctx(now=leap).resolve({"kind": "rolling", "amount": 1, "unit": "month"})
    assert datetime.fromtimestamp(w2.start_utc, NY).date().isoformat() == "2028-02-29"


def test_calendar_week_starts_monday_and_partial_period_is_labelled():
    w = ctx().resolve({"kind": "calendar", "unit": "week", "offset": 0})
    assert datetime.fromtimestamp(w.start_utc, NY).date().isoformat() == "2026-03-02"
    assert w.end_utc == NOW.timestamp() and "so far" in w.label


def test_dst_gap_start_shifts_forward_and_is_disclosed():
    # 02:30 on 2026-03-08 never happened in New York.
    w = ctx().resolve({"kind": "local_range", "start": "2026-03-08T02:30", "end": "2026-03-08T05:00"})
    assert w.start_utc == L(2026, 3, 8, 3, 0)
    assert any("does not exist" in n for n in w.notes)


def test_dst_repeat_takes_earlier_instant_and_is_disclosed():
    # 01:30 on 2026-11-01 happens twice in New York.
    now = datetime(2026, 11, 2, 12, tzinfo=NY)
    w = ctx(now=now).resolve({"kind": "local_range", "start": "2026-11-01T01:30", "end": "2026-11-01T03:00"})
    assert w.start_utc == datetime(2026, 11, 1, 5, 30, tzinfo=UTC).timestamp()  # EDT reading (earlier)
    assert any("occurs twice" in n for n in w.notes)


def test_southern_hemisphere_dst_both_directions():
    # Sydney: DST ends 2026-04-05 03:00 -> 02:00 (repeat), starts 2026-10-04 02:00 -> 03:00 (gap)
    _, note = localize(datetime(2026, 4, 5, 2, 30), SYD)
    assert note and "twice" in note
    epoch, note = localize(datetime(2026, 10, 4, 2, 30), SYD)
    assert note and "does not exist" in note
    assert datetime.fromtimestamp(epoch, SYD).replace(tzinfo=None) == datetime(2026, 10, 4, 3, 0)
    # yesterday across the repeat day is 25 real hours
    now = datetime(2026, 4, 6, 9, tzinfo=SYD)
    w = ctx(tz=SYD, now=now).resolve({"kind": "calendar", "unit": "day", "offset": -1})
    assert w.end_utc - w.start_utc == 25 * 3600


@pytest.mark.parametrize("intent", [
    {"kind": "calendar", "unit": "day", "offset": 1},
    {"kind": "local_since", "start": "2026-03-09"},
    {"kind": "local_range", "start": "2026-03-08T09:00", "end": "2026-03-08T12:00"},
])
def test_future_windows_are_rejected_not_clamped(intent):
    with pytest.raises(TimeIntentError):
        ctx().resolve(intent)


@pytest.mark.parametrize("intent", [
    {"kind": "rolling", "amount": 0, "unit": "day"},
    {"kind": "rolling", "amount": True, "unit": "day"},
    {"kind": "rolling", "amount": 3, "unit": "fortnight"},
    {"kind": "local_since", "start": "2026-03-01T10:00Z"},  # offsets are the code's job
    {"kind": "local_range", "start": "2026-03-05", "end": "2026-03-04"},
    {"kind": "bogus"},
    "last week",
])
def test_invalid_intents_raise_actionable_errors(intent):
    with pytest.raises(TimeIntentError):
        ctx().resolve(intent)


def test_same_window_twice_gets_the_same_id_and_ids_are_referencable():
    c = ctx()
    a = c.resolve({"kind": "rolling", "amount": 7, "unit": "day"})
    b = c.resolve({"kind": "rolling", "amount": 7, "unit": "day"})
    assert a.id == b.id == "w1"
    assert c.resolve({"id": "w1"}) is a


def test_relative_to_shifts_a_window_keeping_its_length():
    c = ctx()
    w1 = c.resolve({"kind": "calendar", "unit": "month", "offset": -1})  # February
    prev = c.resolve({"kind": "relative_to", "window": w1.id, "shift": {"amount": -1, "unit": "month"}})
    assert datetime.fromtimestamp(prev.start_utc, NY).date().isoformat() == "2026-01-01"
    assert datetime.fromtimestamp(prev.end_utc, NY).date().isoformat() == "2026-02-01"


def test_named_windows_persist_as_absolute_bounds(tmp_path):
    store = tmp_path / "sess_windows.json"
    c1 = ctx(store_path=store)
    w = c1.resolve({"kind": "local_range", "start": "2026-03-07T18:40", "end": "2026-03-07T18:55"}, name="incident")
    # a resumed session a day later still means the same absolute window
    c2 = ctx(now=NOW + timedelta(days=1), store_path=store)
    again = c2.resolve({"kind": "named", "name": "incident"})
    assert (again.start_utc, again.end_utc) == (w.start_utc, w.end_utc)


def test_ago_range_is_exact_elapsed():
    w = ctx().resolve({"kind": "ago_range", "from": 3, "to": 2, "unit": "hour"})
    assert (w.start_utc, w.end_utc) == (elapsed_ago(3), elapsed_ago(2))


@pytest.mark.parametrize("text", [
    "traffic from 10.136.28.5 today",   # an IP octet pair must not become a date
    "OpenSSH 8.9 is outdated",          # a version must not become a date
    "port 22/tcp is open",
])
def test_no_false_dates_from_ips_versions_ports(text):
    assert all(p.text not in ("28.5", "8.9", "22/tcp") for p in find_time_phrases(text, NOW.replace(tzinfo=None)))


def test_numeric_date_resolves_when_unambiguous_or_with_configured_order():
    n = NOW.replace(tzinfo=None)
    assert find_time_phrases("on 25/02", n)[0].status == "resolved"  # 25 can't be a month
    # day-first 03/04 = April 3; the most recent PAST April 3 as of 2026-03-08 is 2025
    assert find_time_phrases("on 03/04", n, date_order="dmy")[0].intent["start"] == "2025-04-03"
    assert find_time_phrases("on 03/04", n, date_order="mdy")[0].intent["start"] == "2026-03-04"


def test_weekday_named_on_that_weekday_asks():
    m = find_time_phrases("anything last Sunday?", NOW.replace(tzinfo=None))[0]
    assert m.status == "ask" and len(m.options) == 2


def test_month_without_year_takes_most_recent_past_occurrence():
    m = find_time_phrases("anything in November?", NOW.replace(tzinfo=None))[0]
    assert m.intent["start"] == "2025-11-01" and "2025" in m.note


def test_window_names_cannot_impersonate_ids():
    c = ctx()
    w = c.resolve({"kind": "rolling", "amount": 1, "unit": "hour"})
    with pytest.raises(TimeIntentError, match="looks like a window id"):
        c.name(w.id, "w2")


def test_naming_a_window_with_its_own_id_is_harmless():
    """Seen live: measure_auth_activity got window {..., "name": "w1"} for window w1 and
    failed with a red error; that name is simply ignored now (another window's id is
    still refused, above)."""
    c = ctx()
    w = c.resolve({"kind": "rolling", "amount": 3, "unit": "day"}, name="w1")
    assert w.id == "w1" and "w1" not in c.named


def test_an_offset_equal_to_the_users_zone_is_accepted_and_others_refused():
    """Seen live (demo, zone UTC): start '2026-10-03T00:00:00Z' was refused and the model
    spent two steps on it. 'Z' in a UTC zone can't shift anything; in New York it could."""
    w = ctx(tz=UTC, now=datetime(2026, 3, 8, 10, 30, tzinfo=UTC)).resolve(
        {"kind": "local_range", "start": "2026-03-07T15:00:00Z", "end": "2026-03-07T16:00:00+00:00"})
    assert w.start_utc == datetime(2026, 3, 7, 15, 0, tzinfo=UTC).timestamp()
    w2 = ctx().resolve({"kind": "local_since", "start": "2026-03-07T15:00:00-05:00"})  # NY's own offset
    assert w2.start_utc == datetime(2026, 3, 7, 15, 0, tzinfo=NY).timestamp()
    with pytest.raises(TimeIntentError):
        ctx().resolve({"kind": "local_since", "start": "2026-03-07T15:00:00Z"})      # would shift 5 hours

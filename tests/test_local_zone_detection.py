"""
A host whose zone is, say, Europe/Helsinki made time-window handling crash:
the local zone came back as a fixed offset named by its abbreviation
("EEST"), which timewin then tried to load as a zone name. The local zone is
now the real IANA zone when it can be named, else a fixed offset named
"UTC±HH:MM" that round-trips.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from kratos.timewin import windows as W
from kratos.utils import timeutil as T


@pytest.fixture
def host_tz(monkeypatch):
    def set_tz(value):
        monkeypatch.setenv("TZ", value)
        time.tzset()

    yield set_tz
    monkeypatch.undo()
    time.tzset()


@pytest.mark.parametrize("tz", ["Europe/Helsinki", "America/Los_Angeles", "Asia/Kolkata", "Pacific/Kiritimati",
                                "Australia/Lord_Howe", "America/St_Johns"])
def test_the_real_zone_is_detected(host_tz, tz):
    host_tz(tz)
    zone = T.detect_local_tz()
    assert getattr(zone, "key", None) == tz
    assert W._zone(W.zone_name(zone)) == zone


@pytest.mark.parametrize("tz,name", [("<+0330>-3:30", "UTC+03:30"), ("<-05>5", "UTC-05:00"), ("UTC0", "UTC")])
def test_an_unnamed_zone_falls_back_to_a_parseable_offset(host_tz, tz, name):
    host_tz(tz)
    zone = T.detect_local_tz()
    assert W.zone_name(zone) == name
    back = W._zone(W.zone_name(zone))
    assert back.utcoffset(None) == datetime.now().astimezone().utcoffset()


def test_tz_as_a_path_and_with_a_colon(host_tz):
    host_tz(":/usr/share/zoneinfo/Asia/Dhaka")
    assert T.system_zone_key() == "Asia/Dhaka"
    host_tz(":Europe/Helsinki")
    assert T.system_zone_key() == "Europe/Helsinki"


def test_zone_name_is_never_an_abbreviation():
    eest = timezone(timedelta(hours=3), "EEST")
    assert W.zone_name(eest) == "UTC+03:00"
    assert W._zone("UTC+03:00").utcoffset(None) == timedelta(hours=3)
    with pytest.raises(ValueError, match="unknown time zone"):
        W._zone("EEST")


@pytest.mark.parametrize("text,offset", [("UTC+3", 3 * 60), ("UTC-04:30", -270), ("utc+0530", 330), ("UTC+00:00", 0)])
def test_fixed_offset_names_parse(text, offset):
    assert T.zone_from_name(text).utcoffset(None) == timedelta(minutes=offset)


@pytest.mark.parametrize("text", ["UTC+24", "UTC+05:60", "EEST", "Mars/Olympus"])
def test_bad_names_are_refused(text):
    assert T.zone_from_name(text) is None


def test_a_time_window_across_a_dst_change_uses_the_real_rules(host_tz):
    """With a fixed offset, 'yesterday' on the night clocks change came out an
    hour wrong; with the real zone it is the 23 local hours that day had."""
    host_tz("Europe/Helsinki")
    tz = T.detect_local_tz()
    ctx = W.TimeContext(tz, now=datetime(2026, 3, 30, 12, 0, tzinfo=timezone.utc).timestamp())
    win = ctx.resolve({"kind": "calendar", "unit": "day", "offset": -1})  # 2026-03-29, clocks went forward
    assert win.seconds == 23 * 3600
    assert os.environ["TZ"] == "Europe/Helsinki"

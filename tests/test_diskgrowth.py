"""Phase D README §3 (built in D.3): /doctor's projection of when the data folder's disk fills."""
from __future__ import annotations

import sqlite3
import time

from kratos import diskgrowth as DG

DAY = 86400.0


def _db(tmp_path):
    sqlite3.connect(tmp_path / "kratos.db").close()
    return tmp_path


def _put(data_dir, at, size, free):
    conn = DG._connect(data_dir)
    with conn:
        conn.execute("INSERT OR REPLACE INTO disk_samples VALUES (?, ?, ?, ?, ?, 1)",
                     (time.strftime("%Y-%m-%d", time.gmtime(at)), at, size, free, 10 ** 12))
    conn.close()


def test_one_sample_says_measuring_never_a_guess(tmp_path):
    d = _db(tmp_path)
    assert DG.record_sample(d) and not DG.record_sample(d)          # once a day
    p = DG.project(d)
    assert p.status == "measuring" and p.days_left is None and "measuring" in p.text


def test_seven_days_rate_warns_under_60_and_alerts_under_14(tmp_path):
    d = _db(tmp_path)
    now = time.time()
    _put(d, now - 7 * DAY, 1_000_000_000, 0)
    _put(d, now, 1_700_000_000, 3_000_000_000)                      # +100 MB/day, 3 GB free -> 30 days
    p = DG.project(d, now=now)
    assert p.status == "warn" and round(p.days_left) == 30 and "fills in 30 days" in p.text
    _put(d, now, 1_700_000_000, 1_000_000_000)                      # 10 days
    assert DG.project(d, now=now).status == "fail"
    _put(d, now, 1_700_000_000, 100_000_000_000)                    # 1000 days
    assert DG.project(d, now=now).status == "ok"


def test_no_growth_is_ok_and_old_samples_are_ignored(tmp_path):
    d = _db(tmp_path)
    now = time.time()
    _put(d, now - 30 * DAY, 1, 5)                                   # outside the 7-day window
    _put(d, now - 3 * DAY, 2_000, 10 ** 9)
    _put(d, now, 2_000, 10 ** 9)
    p = DG.project(d, now=now)
    assert p.status == "ok" and "didn't grow" in p.text


def test_doctor_shows_the_row(tmp_path):
    from kratos.agent import doctor

    d = _db(tmp_path)
    out: list = []
    doctor._check_disk_growth(out, d)
    assert out and out[0]["check"] == "disk growth" and out[0]["status"] == "info"


def test_the_walk_counts_files_and_stops_at_its_cap(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}").write_bytes(b"x" * 5000)
    size, complete = DG.folder_bytes(tmp_path)
    assert size >= 25000 and complete
    assert DG.folder_bytes(tmp_path, max_entries=2)[1] is False

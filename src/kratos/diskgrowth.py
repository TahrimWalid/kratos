"""How fast the data folder grows, and when its disk fills at that rate (Phase D README §3).

Kratos deletes nothing on its own, so the data folder only grows. One sample per day
(``disk_samples`` in kratos.db: the folder's size, the disk's free and total bytes) is
taken by `/doctor` / `kratos doctor` and, at most once a day, when a collection starts.
The projection uses the samples of the last 7 days:

    days until full = free bytes on the data folder's disk / bytes the folder grew per day

/doctor warns under 60 days and alerts under 14. With less than a day between samples it
says it is still measuring -- it never guesses a rate.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from kratos.storage.migrations import migrate_once
from kratos.storage.sqlite_files import connect_store

COMPONENT = "disk_samples"
WINDOW_DAYS = 7
WARN_DAYS = 60
ALERT_DAYS = 14
WALK_MAX_ENTRIES = 500_000
WALK_SECONDS = 3.0


def _step_1(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS disk_samples (day TEXT PRIMARY KEY, at REAL NOT NULL, "
                 "folder_bytes INTEGER NOT NULL, disk_free INTEGER NOT NULL, disk_total INTEGER NOT NULL, "
                 "complete INTEGER NOT NULL DEFAULT 1)")


STEPS = (_step_1,)


def _connect(data_dir: Path) -> sqlite3.Connection:
    path = Path(data_dir) / "kratos.db"
    conn = connect_store(path)
    try:
        migrate_once(conn, path, COMPONENT, STEPS)
    except BaseException:
        conn.close()
        raise
    return conn


def folder_bytes(data_dir: Path, *, max_entries: int = WALK_MAX_ENTRIES,
                 seconds: float = WALK_SECONDS) -> tuple[int, bool]:
    """(bytes on disk under the folder, complete?). Symlinks are not followed; a walk
    that hits its entry or time cap is marked incomplete."""
    total, n = 0, 0
    deadline = time.monotonic() + seconds
    stack = [str(data_dir)]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    n += 1
                    if n > max_entries or time.monotonic() > deadline:
                        return total, False
                    try:
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            total += getattr(st, "st_blocks", 0) * 512 or st.st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total, True


def record_sample(data_dir: Path, *, now: float | None = None, force: bool = False) -> bool:
    """Take today's sample (once a day unless `force`). Never raises; False if nothing was taken."""
    data_dir = Path(data_dir)
    if not (data_dir / "kratos.db").exists():
        return False
    now = time.time() if now is None else now
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    try:
        conn = _connect(data_dir)
        try:
            if not force and conn.execute("SELECT 1 FROM disk_samples WHERE day = ?", (day,)).fetchone():
                return False
            size, complete = folder_bytes(data_dir)
            du = shutil.disk_usage(data_dir)
            with conn:
                conn.execute("INSERT OR REPLACE INTO disk_samples (day, at, folder_bytes, disk_free, disk_total, "
                             "complete) VALUES (?, ?, ?, ?, ?, ?)", (day, now, size, du.free, du.total, int(complete)))
            return True
        finally:
            conn.close()
    except (OSError, sqlite3.Error):
        return False


@dataclass(frozen=True)
class Projection:
    status: str                    # "ok" | "warn" | "fail" | "measuring"
    text: str
    days_left: float | None = None
    bytes_per_day: float | None = None


def project(data_dir: Path, *, now: float | None = None) -> Projection:
    data_dir = Path(data_dir)
    now = time.time() if now is None else now
    try:
        conn = _connect(data_dir)
        try:
            rows = conn.execute("SELECT at, folder_bytes, disk_free, complete FROM disk_samples WHERE at >= ? "
                                "ORDER BY at", (now - (WINDOW_DAYS + 1) * 86400,)).fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as e:
        return Projection("measuring", f"couldn't read the size samples ({type(e).__name__})")
    rows = [r for r in rows if r[3]]
    if len(rows) < 2 or rows[-1][0] - rows[0][0] < 86400 * 0.9:
        since = time.strftime("%Y-%m-%d", time.gmtime(rows[0][0])) if rows else "today"
        return Projection("measuring", f"measuring the data folder's growth since {since}; the projection appears "
                                       "after a day of samples (taken by /doctor and once a day by checks)")
    days = (rows[-1][0] - rows[0][0]) / 86400
    rate = (rows[-1][1] - rows[0][1]) / days
    free = rows[-1][2]
    if rate <= 0:
        return Projection("ok", f"the data folder didn't grow over the last {days:.0f} day(s); "
                                f"{_size(free)} free on its disk", None, rate)
    left = free / rate
    text = (f"at the last {days:.0f} day(s)' rate ({_size(rate)}/day) the data folder's disk fills in "
            f"{left:.0f} days ({_size(free)} free)")
    status = "fail" if left < ALERT_DAYS else "warn" if left < WARN_DAYS else "ok"
    return Projection(status, text, left, rate)


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"

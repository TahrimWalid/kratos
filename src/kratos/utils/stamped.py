"""Stamped file names no two writers can share (D.2).

Correlation inputs and reports are named `<prefix>_<YYYYmmdd>_<HHMMSS>...`. With one
machine at a time a second was enough; with several machines collected and correlated
in parallel (fleet runs, a schedule beside the TUI), two of them wrote the SAME
`findings_<date>_<time>.json` in the same second -- and each read back whichever report
landed last, so one machine's findings showed up under another. `reserve()` adds the
microseconds and a counter and creates the file exclusively (O_EXCL), so a name is held
by exactly one writer, in any process. The date stays the second-to-last `_` field and
the time field still starts with HHMMSS, so the name readers (files_in_date_range,
timewin.snapshots) read them as before.
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

MAX_TRIES = 100


def reserve(directory: Path | str, prefix: str, suffix: str, *, now: datetime | None = None) -> tuple[Path, str]:
    """(an empty file `<prefix>_<stamp><suffix>` created just now for this writer, the
    stamp) -- reuse the stamp for files that go with it (`auth_patterns_<stamp>.json`
    beside `auth_stats_<stamp>.json`)."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    t = now or datetime.now()
    base = f"{t:%Y%m%d}_{t:%H%M%S%f}"
    for n in range(MAX_TRIES):
        stamp = f"{base}{n:02d}"
        path = directory / f"{prefix}_{stamp}{suffix}"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            continue
        os.close(fd)
        return path, stamp
    raise FileExistsError(f"no free name for {prefix}_{base}*{suffix} in {directory}")

"""Window chips (docs/time_window_design.md §3/§4): every time-scoped tool call shows the
exact window and whether it was fully covered -- in the TUI and the CLI."""
from __future__ import annotations

import io

from rich.console import Console

from kratos.agent import console as C
from kratos.tui_mk2 import render as R

FULL = {"chip": "w1 last 24 hours: 2026-09-27 01:00 → 2026-09-28 01:00 (UTC)", "coverage_percent": 100.0}
PARTIAL = {"chip": "w2 last 3 days: …", "coverage_percent": 42.0, "clock": "WARNING: target clock", "target_clock_offset_s": -421.0}


def test_tui_chip_shows_window_and_coverage():
    assert "counted in full" in R.window_chip(FULL).plain and "w1 last 24 hours" in R.window_chip(FULL).plain
    t = R.window_chip(PARTIAL).plain
    assert "PARTIAL: 42% of the window covered" in t and "target clock -421s" in t
    assert R.window_chip({}) is None and R.window_chip(None) is None


def test_cli_note_shows_window_and_coverage():
    buf = io.StringIO()
    con = Console(file=buf, width=200, no_color=True)
    C.render_window_note(con, {"window": PARTIAL})
    C.render_window_note(con, {"entries": []})  # no window -> nothing
    out = buf.getvalue()
    assert "PARTIAL (42% of the window covered)" in out and out.count("⏱") == 1

"""Scheduled-run watermarks and "since the last run" (docs/time_window_design.md §5):
consecutive runs cover time with no gaps and no overlaps; a failed run never advances the
watermark; long downtime is capped and disclosed."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kratos.agent import schedules as S
from kratos.agent import scheduled_run as W
from kratos.timewin.agentwin import prepare_time_context

UTC = timezone.utc
NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC).timestamp()


def _record(tmp: Path, name: str, status: str, end: float) -> None:
    S.append_run_record(tmp, name, {"schedule": name, "status": status,
                                    "window": {"end_utc": datetime.fromtimestamp(end, UTC).isoformat()}})


def test_first_run_looks_back_a_day_and_says_so(tmp_path):
    w = W.compute_watermark_window(tmp_path, "nightly", NOW)
    assert w["end"] == NOW - 60 and w["start"] == w["end"] - 86400 and "first run" in w["note"]


def test_runs_chain_without_gaps_or_overlaps(tmp_path):
    _record(tmp_path, "nightly", "completed", NOW - 3600)
    w = W.compute_watermark_window(tmp_path, "nightly", NOW)
    assert w["start"] == pytest.approx(NOW - 3600) and w["note"] == ""


def test_a_failed_run_does_not_advance_the_watermark(tmp_path):
    _record(tmp_path, "nightly", "completed", NOW - 7200)
    _record(tmp_path, "nightly", "error", NOW - 3600)
    assert W.compute_watermark_window(tmp_path, "nightly", NOW)["start"] == pytest.approx(NOW - 7200)


def test_catch_up_after_downtime_is_capped_and_disclosed(tmp_path):
    _record(tmp_path, "nightly", "completed", NOW - 20 * 86400)
    w = W.compute_watermark_window(tmp_path, "nightly", NOW)
    assert w["end"] - w["start"] == 7 * 86400 and "NOT covered" in w["note"]


def test_pipeline_since_last_run_becomes_the_exact_window():
    specs = [{"tool": "measure_auth_activity", "args": {"since": "since_last_run"}},
             {"tool": "read_journalctl", "args": {"window": "since_last_run", "lines": 50}},
             {"tool": "run_nmap_scan", "args": {}}]
    out = W._apply_watermark_to_steps(specs, {"start": 100.0, "end": 200.0})
    assert out[0]["args"] == {"window": {"kind": "epoch", "start": 100.0, "end": 200.0}}
    assert out[1]["args"]["window"] == {"kind": "epoch", "start": 100.0, "end": 200.0} and out[1]["args"]["lines"] == 50
    assert out[2]["args"] == {} and specs[0]["args"] == {"since": "since_last_run"}  # never mutated


def test_goal_preset_gets_the_watermark_as_a_named_window(tmp_path, monkeypatch):
    from kratos.agent import presets as P

    P.save_preset(tmp_path, name="delta", goal="any failed logins since the last run?")
    S.save_schedule(tmp_path, name="hourly", kind="preset", cadence="hourly", preset="delta")
    _record(tmp_path, "hourly", "completed", NOW - 3600)
    seen = {}

    def fake_agent(goal, data_dir, named_windows=None):
        seen["named"] = named_windows
        ctx, _ = prepare_time_context(goal, data_dir, timezone_name="UTC", now=NOW, named_windows=named_windows)
        seen["goal_window"] = ctx.windows[ctx.goal_ids[0]]
        return {"status": "final_answer", "transcript": []}

    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_agent)
    real = W.compute_watermark_window
    monkeypatch.setattr(W, "compute_watermark_window", lambda d, n, _now: real(d, n, NOW))  # frozen clock
    rec = W.run_scheduled(S.load_schedule(tmp_path, "hourly"), tmp_path, notifier=lambda m, s: {"status": "sent"})
    start, end, _ = seen["named"]["since last run"]
    assert start == pytest.approx(NOW - 3600, abs=5)
    assert seen["goal_window"].start_utc == pytest.approx(start)  # the goal's phrase resolved to it
    assert rec["window"]["start_utc"].startswith(datetime.fromtimestamp(NOW - 3600, UTC).isoformat()[:16])


def test_interactive_since_last_scan_uses_the_newest_saved_scan(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.kratos_config.get_active_target", lambda: "10.0.0.5")
    p = tmp_path / "scans" / "parsed_x.json"
    p.parent.mkdir()
    scanned = NOW - 5 * 3600
    p.write_text(json.dumps({"parsed_at": datetime.fromtimestamp(scanned, UTC).isoformat(), "hosts": [{"ip": "10.0.0.5"}]}))
    os.utime(p, (scanned, scanned))
    ctx, _ = prepare_time_context("anything new since my last scan?", tmp_path, timezone_name="UTC", now=NOW)
    w = ctx.windows[ctx.goal_ids[0]]
    assert w.start_utc == pytest.approx(scanned) and any("newest saved" in n for n in w.notes)


def test_host_clock_moving_backwards_gives_an_empty_disclosed_window(tmp_path):
    _record(tmp_path, "nightly", "completed", NOW + 3600)  # previous window ends in "our" future
    w = W.compute_watermark_window(tmp_path, "nightly", NOW)
    assert w["start"] == w["end"] and "clock" in w["note"]

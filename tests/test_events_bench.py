"""The event store's query-speed target, at 100k events (`pytest -m bench`).

The full 1,000,000-event run is scripts/bench/events_bench.py (numbers in the
0.2 Handoff); this is the quick version for the phase-end audit.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.bench
sys.path.insert(0, str(Path(__file__).parents[1] / "scripts" / "bench"))


def test_p95_under_200ms_at_100k(tmp_path, capsys):
    import events_bench

    assert events_bench.main(["--events", "100000", "--queries", "100", "--dir", str(tmp_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["rows_stored"] > 99_000
    assert report["worst_p95_ms"] < 200, report["queries"]

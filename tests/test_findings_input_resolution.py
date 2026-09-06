"""
Sprint 1 backlog #6: write_findings_report input resolution is PER-ARGUMENT, not
all-or-nothing. An explicitly-given path must be honored exactly (never silently
swapped for an auto-discovered file) even when a sibling argument is left None;
a None sibling is still auto-discovered independently; a hallucinated explicit
path is recorded in input_errors rather than silently falling back.

(This item turned out already-implemented on inspection — this test locks it in
so it can't regress.)
"""
from __future__ import annotations

import json
from pathlib import Path

from kratos.adapters.findings_engine import write_findings_report


def _read_report(out_json: Path) -> dict:
    return json.loads(out_json.read_text())


def test_explicit_path_honored_even_when_sibling_is_none(tmp_path):
    # An auto-discoverable nmap the all-or-nothing bug WOULD have fallen back to:
    (tmp_path / "scans").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scans" / "parsed_AUTO.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")
    # An auto-discoverable auth_stats (the None sibling should still find this):
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "logs" / "auth_stats_AUTO.json").write_text(
        json.dumps({"events_by_type": {}}), encoding="utf-8")
    # The explicit nmap lives OUTSIDE the auto glob, with a distinctive name:
    explicit_nmap = tmp_path / "explicit_nmap.json"
    explicit_nmap.write_text(json.dumps({"hosts": []}), encoding="utf-8")

    out_json, _ = write_findings_report(tmp_path, nmap_parsed_file=explicit_nmap, auth_stats_file=None)
    inputs = _read_report(out_json)["inputs"]

    # Explicit honored (NOT swapped for parsed_AUTO.json):
    assert inputs["nmap_parsed"] == "explicit_nmap.json"
    # None sibling auto-discovered independently:
    assert inputs["auth_stats"] == "auth_stats_AUTO.json"


def test_hallucinated_explicit_path_is_an_error_not_a_silent_swap(tmp_path):
    (tmp_path / "scans").mkdir(parents=True, exist_ok=True)
    (tmp_path / "scans" / "parsed_AUTO.json").write_text(json.dumps({"hosts": []}), encoding="utf-8")

    out_json, _ = write_findings_report(tmp_path, nmap_parsed_file=tmp_path / "does_not_exist.json")
    report = _read_report(out_json)

    assert "nmap_parsed" in report["input_errors"]           # recorded as an error
    assert report["inputs"]["nmap_parsed"] is None           # NOT swapped for parsed_AUTO.json

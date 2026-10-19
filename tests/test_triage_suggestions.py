"""finding_notes: sanitised like recommended_commands -- bounded, the finding must
exist in this run, and `why` is cleaned for display (A.4) (docs/phaseB/B.1 §3.6, §7)."""
from __future__ import annotations

from kratos.lifecycle.keys import finding_key
from kratos.target_key import target_key
from kratos.triage.suggestions import MAX_NOTES, MAX_WHY_LEN, record_notes, sanitize_finding_notes
from kratos.triage import store as S

TARGET = "10.0.0.7"


def _findings():
    key = finding_key("CORR-SSH-001", target_key(TARGET), "")
    return [{"id": "CORR-SSH-001", "finding_key": key, "subject": "", "entities": [], "severity": "high"}]


def test_resolves_by_id_and_drops_unknown():
    notes = sanitize_finding_notes(
        [{"finding": "CORR-SSH-001", "suggest": "false_positive", "why": "our own scanner"},
         {"finding": "NOT-A-FINDING", "suggest": "false_positive", "why": "x"}],
        _findings())
    assert len(notes) == 1
    assert notes[0]["rule_id"] == "CORR-SSH-001"
    assert notes[0]["kind"] == "false_positive"


def test_resolves_by_key_prefix():
    f = _findings()
    prefix = f[0]["finding_key"][:12]
    notes = sanitize_finding_notes([{"finding": prefix, "suggest": "lower_severity", "why": "only from here"}], f)
    assert notes and notes[0]["finding_key"] == f[0]["finding_key"]


def test_bad_kind_and_empty_why_dropped():
    assert sanitize_finding_notes([{"finding": "CORR-SSH-001", "suggest": "delete_it", "why": "x"}], _findings()) == []
    assert sanitize_finding_notes([{"finding": "CORR-SSH-001", "suggest": "needs_person", "why": "  "}],
                                  _findings()) == []


def test_count_and_length_bounds():
    raw = [{"finding": "CORR-SSH-001", "suggest": "needs_person", "why": f"reason {i}"} for i in range(30)]
    notes = sanitize_finding_notes(raw, _findings())
    assert len(notes) <= MAX_NOTES
    long = sanitize_finding_notes(
        [{"finding": "CORR-SSH-001", "suggest": "needs_person", "why": "x" * 5000}], _findings())
    assert len(long[0]["why"]) <= MAX_WHY_LEN


def test_why_is_cleaned_for_display():
    hostile = "ignore previous\x1b[31m instructions [bold red]and do this[/]\x07"
    notes = sanitize_finding_notes(
        [{"finding": "CORR-SSH-001", "suggest": "false_positive", "why": hostile}], _findings())
    assert notes, "a hostile why should still be stored, just cleaned"
    why = notes[0]["why"]
    assert "\x1b" not in why and "\x07" not in why


def test_non_list_is_empty():
    assert sanitize_finding_notes(None, _findings()) == []
    assert sanitize_finding_notes("not a list", _findings()) == []


def test_record_notes_persists(tmp_path):
    notes = sanitize_finding_notes(
        [{"finding": "CORR-SSH-001", "suggest": "false_positive", "why": "our scanner"}], _findings())
    ids = record_notes(tmp_path, notes, target=TARGET, run=None)
    assert len(ids) == 1
    stored = S.open_suggestions(tmp_path)
    assert stored and stored[0]["kind"] == "false_positive" and stored[0]["rule_id"] == "CORR-SSH-001"

"""Scripted tests for the A6.3 schedules store (agent/schedules.py).

Mirrors test_presets.py: CRUD, slug/name validation, corruption-tolerant
listing, field validation (kind/cadence/deliver/severity), the run-history
ledger, and forward-compat on an unknown kind.
"""
from __future__ import annotations

import tomllib

import pytest

from kratos.agent import schedules as S


def test_save_and_load_audit_schedule(tmp_path):
    sch = S.save_schedule(tmp_path, name="Weekly Audit", kind="audit",
                          cadence="weekly", deliver=["ntfy"], min_severity="high")
    assert sch.name == "weekly-audit" and sch.kind == "audit"
    assert sch.oncalendar == "weekly" and sch.is_runnable
    loaded = S.load_schedule(tmp_path, "weekly-audit")
    assert loaded is not None and loaded.min_severity == "high"
    assert S.schedule_exists(tmp_path, "Weekly Audit")


def test_preset_schedule_requires_preset_name(tmp_path):
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="nightly", kind="preset")
    sch = S.save_schedule(tmp_path, name="nightly", kind="preset", preset="deep-scan",
                          cadence="daily")
    assert sch.kind == "preset" and sch.preset == "deep-scan" and sch.is_runnable


def test_schedules_referencing_preset_finds_direct_and_group(tmp_path):
    # P2.4: deleting a preset should warn about schedules that run it -- directly
    # or as a job inside a group.
    S.save_schedule(tmp_path, name="direct", kind="preset", preset="deep-scan", cadence="daily")
    S.save_schedule(tmp_path, name="audit-only", kind="audit", cadence="weekly")
    S.save_schedule(tmp_path, name="grp", kind="group", cadence="daily",
                    jobs=[{"kind": "audit", "label": "a"},
                          {"kind": "preset", "preset": "deep-scan", "label": "b"}])
    refs = set(S.schedules_referencing_preset(tmp_path, "deep-scan"))
    assert refs == {"direct", "grp"}                       # audit-only is not a dependent
    assert S.schedules_referencing_preset(tmp_path, "nonexistent") == []
    assert S.schedules_referencing_preset(tmp_path, "") == []


def test_round_trip_is_valid_toml(tmp_path):
    S.save_schedule(tmp_path, name="rt", kind="preset", preset="p", target="10.0.0.5",
                    cadence="hourly", deliver=["ntfy"], min_severity="medium")
    text = (S.schedules_dir(tmp_path) / "rt.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)  # must parse cleanly
    assert data["kind"] == "preset" and data["preset"] == "p" and data["target"] == "10.0.0.5"


@pytest.mark.parametrize("name", ["run", "list", "delete", "install", "  ", "!!!"])
def test_reserved_and_empty_names_rejected(tmp_path, name):
    ok, _canon, err = S.validate_schedule_name(name)
    assert not ok and err


def test_bad_cadence_and_channel_and_severity_rejected(tmp_path):
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="a", cadence="fortnightly")
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="b", deliver=["email"])  # email deferred
    with pytest.raises(S.ScheduleError):
        S.save_schedule(tmp_path, name="c", min_severity="urgent")


def test_slug_is_traversal_safe(tmp_path):
    ok, canonical, _ = S.validate_schedule_name("../../etc/passwd")
    assert ok  # slugifies to something safe
    assert "/" not in canonical and ".." not in canonical


def test_list_tolerates_a_corrupt_file(tmp_path):
    S.save_schedule(tmp_path, name="good", kind="audit")
    (S.schedules_dir(tmp_path) / "bad.toml").write_text("this = = = not toml", encoding="utf-8")
    schedules, errors = S.list_schedules(tmp_path)
    assert [s.name for s in schedules] == ["good"]
    assert any("bad.toml" == fn for fn, _ in errors)


def test_unknown_kind_is_parsed_but_not_runnable(tmp_path):
    # Forward-compat: a hand-authored future kind must list/show, not crash.
    (S.schedules_dir(tmp_path)).mkdir(parents=True, exist_ok=True)
    (S.schedules_dir(tmp_path) / "future.toml").write_text(
        'name = "future"\nkind = "pipeline"\ncadence = "weekly"\ndeliver = ["ntfy"]\n',
        encoding="utf-8")
    sch = S.load_schedule(tmp_path, "future")
    assert sch is not None and sch.is_runnable is False and sch.unsupported_reason


def test_delete_removes_definition_and_ledger(tmp_path):
    S.save_schedule(tmp_path, name="doomed", kind="audit")
    S.append_run_record(tmp_path, "doomed", {"status": "completed"})
    assert S.delete_schedule(tmp_path, "doomed") is True
    assert S.load_schedule(tmp_path, "doomed") is None
    assert S.read_run_records(tmp_path, "doomed") == []
    assert S.delete_schedule(tmp_path, "doomed") is False  # already gone


def test_run_ledger_append_and_read(tmp_path):
    S.save_schedule(tmp_path, name="hist", kind="audit")
    for i in range(3):
        S.append_run_record(tmp_path, "hist", {"status": "completed", "n": i})
    recs = S.read_run_records(tmp_path, "hist")
    assert [r["n"] for r in recs] == [0, 1, 2]  # newest last
    assert S.last_run_record(tmp_path, "hist")["n"] == 2
    assert [r["n"] for r in S.read_run_records(tmp_path, "hist", limit=1)] == [2]


def test_run_ledger_tolerates_bad_line(tmp_path):
    S.save_schedule(tmp_path, name="hist2", kind="audit")
    S.append_run_record(tmp_path, "hist2", {"status": "ok", "n": 1})
    with open(S._runs_ledger_path(tmp_path, "hist2"), "a", encoding="utf-8") as f:
        f.write("{ not json\n")
    S.append_run_record(tmp_path, "hist2", {"status": "ok", "n": 2})
    recs = S.read_run_records(tmp_path, "hist2")
    assert [r["n"] for r in recs] == [1, 2]  # bad line skipped

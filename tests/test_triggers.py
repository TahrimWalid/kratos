"""Scripted tests for the A6.4 triggers store (agent/triggers.py)."""
from __future__ import annotations

import tomllib

import pytest

from kratos.agent import triggers as T


def test_save_and_load_severity_trigger(tmp_path):
    tg = T.save_trigger(tmp_path, name="High Alert", action="playbook", min_severity="high")
    assert tg.name == "high-alert" and tg.action == "playbook" and tg.min_severity == "high"
    assert tg.is_valid and tg.finding_id is None
    assert T.load_trigger(tmp_path, "high-alert").min_severity == "high"


def test_finding_id_trigger_normalizes_and_validates(tmp_path):
    tg = T.save_trigger(tmp_path, name="ssh", action="investigate", finding_id="corr-ssh-001")
    assert tg.finding_id == "CORR-SSH-001"  # upper-cased
    with pytest.raises(T.TriggerError):
        T.save_trigger(tmp_path, name="bad", action="notify", finding_id="not a valid id!!")


def test_condition_required(tmp_path):
    with pytest.raises(T.TriggerError):
        T.save_trigger(tmp_path, name="empty", action="notify")  # no severity, no id


def test_bad_action_and_severity_rejected(tmp_path):
    with pytest.raises(T.TriggerError):
        T.save_trigger(tmp_path, name="a", action="remediate", min_severity="high")  # not allowed
    with pytest.raises(T.TriggerError):
        T.save_trigger(tmp_path, name="b", action="notify", min_severity="urgent")


@pytest.mark.parametrize("name", ["trigger", "test", "list", "  ", "!!"])
def test_reserved_and_empty_names(tmp_path, name):
    ok, _c, err = T.validate_trigger_name(name)
    assert not ok and err


def test_round_trip_is_valid_toml(tmp_path):
    T.save_trigger(tmp_path, name="rt", action="notify", min_severity="medium",
                   finding_id="NET-002", target="10.0.0.5", cooldown_minutes=15)
    data = tomllib.loads((T.triggers_dir(tmp_path) / "rt.toml").read_text(encoding="utf-8"))
    assert data["action"] == "notify" and data["finding_id"] == "NET-002" and data["cooldown_minutes"] == 15


def test_list_tolerates_corrupt_file(tmp_path):
    T.save_trigger(tmp_path, name="good", action="notify", min_severity="high")
    (T.triggers_dir(tmp_path) / "bad.toml").write_text("= = =", encoding="utf-8")
    triggers, errors = T.list_triggers(tmp_path)
    assert [t.name for t in triggers] == ["good"]
    assert any(fn == "bad.toml" for fn, _ in errors)


def test_delete_removes_definition_and_ledger(tmp_path):
    T.save_trigger(tmp_path, name="doomed", action="notify", min_severity="high")
    T.append_fire_record(tmp_path, "doomed", {"fired_at": "x"})
    assert T.delete_trigger(tmp_path, "doomed") is True
    assert T.load_trigger(tmp_path, "doomed") is None
    assert T.read_fire_records(tmp_path, "doomed") == []
    assert T.delete_trigger(tmp_path, "doomed") is False


def test_fire_ledger_append_read_tolerant(tmp_path):
    T.save_trigger(tmp_path, name="h", action="notify", min_severity="high")
    T.append_fire_record(tmp_path, "h", {"fired_at": "t1", "n": 1})
    with open(T._fired_ledger_path(tmp_path, "h"), "a", encoding="utf-8") as f:
        f.write("{bad\n")
    T.append_fire_record(tmp_path, "h", {"fired_at": "t2", "n": 2})
    recs = T.read_fire_records(tmp_path, "h")
    assert [r["n"] for r in recs] == [1, 2]
    assert T.last_fire_record(tmp_path, "h")["n"] == 2

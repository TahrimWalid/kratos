"""`kratos budget`: the spending limits from the command line, for a machine with no
TUI (schedules, `kratos mcp-serve`). It goes through the same settings and checks as
Settings -> Budget, records the change as "cli", and refuses what the setting
itself refuses."""
from __future__ import annotations

import json

from kratos import settings_store
from kratos.budget import breaker, limits as L
from kratos.budget.ledger import BudgetLedger
from kratos.cli import app as cli_app


def run(tmp_path, *args: str) -> int:
    return cli_app.main(["--data-dir", str(tmp_path), "budget", *args])


def test_show_lists_today_and_every_limit(tmp_path, capsys):
    assert run(tmp_path) == 0
    out = capsys.readouterr().out
    assert "Model spending today" in out
    for key in L.KEYS:
        assert key.removeprefix("budget.") in out
    assert "trigger_investigations_allowed     off" in out


def test_show_json(tmp_path, capsys):
    assert run(tmp_path, "show", "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert set(doc["limits"]) == set(L.KEYS) and len(doc["today"]) == 3 and doc["paused"] == []


def test_set_changes_the_shared_setting_as_cli(tmp_path, capsys):
    assert run(tmp_path, "set", "daily_cost_usd", "5") == 0
    assert settings_store.get(L.DAILY_COST, data_dir=tmp_path) == 5.0
    assert settings_store.last_change(L.DAILY_COST, data_dir=tmp_path)[1] == "cli"
    assert run(tmp_path, "set", "budget.trigger_investigations_allowed", "on") == 0
    assert settings_store.get(L.TRIGGER_INVESTIGATIONS, data_dir=tmp_path) is True
    assert "applies to the next model call" in capsys.readouterr().out.lower()


def test_set_refuses_what_the_setting_refuses(tmp_path, capsys):
    assert run(tmp_path, "set", "daily_cost_usd", "-1") == 2
    assert run(tmp_path, "set", "nonsense", "1") == 2
    err = capsys.readouterr().err
    assert "Not changed" in err and "isn't a budget limit" in err
    assert settings_store.last_change(L.DAILY_COST, data_dir=tmp_path) is None


def test_resume_ends_a_pause(tmp_path, capsys):
    import time

    BudgetLedger(tmp_path).state_set("pause:schedule:nightly", {"until": time.time() + 3600, "since": time.time(),
                                                                 "reason": "failures", "failures": 5})
    assert [p["key"] for p in breaker.list_pauses(tmp_path)] == ["schedule:nightly"]
    assert run(tmp_path, "resume", "schedule:nightly") == 0
    assert breaker.list_pauses(tmp_path) == []
    assert run(tmp_path, "resume", "schedule:nightly") == 1

"""`kratos findings ...`: list, show history, and the people-only decisions."""
from __future__ import annotations

import json
import time
import uuid

import pytest

from kratos.cli import app
from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import nothing
from kratos.lifecycle.keys import finding_key
from kratos.run_context import RunContext

T = "10.0.0.5"


def _seed(tmp_path):
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([{"id": "CORR-SSH-001", "title": "SSH brute force", "severity": "high", "evidence": ["burst"],
                  "subject": "", "entities": ["203.0.113.9"]},
                 {"id": "NET-002", "title": "Open ports", "severity": "medium", "evidence": [], "subject": "",
                  "entities": ["22/tcp"]}],
                target=T, coverage=nothing(), run=r, data_dir=tmp_path)
    return finding_key("CORR-SSH-001", T, "")


def _run(tmp_path, monkeypatch, *argv):
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    monkeypatch.setattr(app, "get_active_target", lambda: T)
    return app.main(["--data-dir", str(tmp_path), "findings", *argv])


def test_list_shows_open_findings_with_short_keys(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    assert _run(tmp_path, monkeypatch, "list") == 0
    out = capsys.readouterr().out
    assert key[:12] in out and "CORR-SSH-001" in out and "NET-002" in out


def test_accept_hides_it_and_list_counts_hidden(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    assert _run(tmp_path, monkeypatch, "accept", key[:12], "--days", "1", "--reason", "lab scanner") == 0
    assert "risk accepted until" in capsys.readouterr().out
    assert _run(tmp_path, monkeypatch, "list") == 0
    out = capsys.readouterr().out
    assert "CORR-SSH-001" not in out and "Hidden by your decisions: 1" in out
    assert _run(tmp_path, monkeypatch, "list", "--state", "decided", "--json") == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["state"] for r in rows] == ["risk_accepted"] and rows[0]["decision"]["reason"] == "lab scanner"


def test_show_prints_history_with_who_and_why(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    _run(tmp_path, monkeypatch, "fp", key[:12], "--reason", "my own scanner", "--scope", "rule-target")
    capsys.readouterr()
    assert _run(tmp_path, monkeypatch, "show", key[:12]) == 0
    out = capsys.readouterr().out
    assert "false positive (this rule on this machine)" in out and "my own scanner" in out
    assert "created" in out and "state_changed" in out and "203.0.113.9" in out


@pytest.mark.parametrize("argv", [
    ("accept", "KEY", "--reason", "x"),                               # no expiry
    ("accept", "KEY", "--reason", "x", "--days", "400"),              # over the cap
    ("accept", "KEY", "--reason", " ", "--days", "1"),                # blank reason
    ("verify", "0000", "--reason", "x"),                              # unknown key
    ("reopen", "KEY", "--reason", "x"),                               # not decided
    ("accept", "KEY", "--reason", "x", "--until", "next tuesday"),     # not a date
])
def test_refusals_change_nothing(tmp_path, monkeypatch, capsys, argv):
    key = _seed(tmp_path)
    argv = tuple(key[:12] if a == "KEY" else a for a in argv)
    assert _run(tmp_path, monkeypatch, *argv) == 1
    assert "Not changed" in capsys.readouterr().err
    _run(tmp_path, monkeypatch, "list", "--json")
    assert {r["state"] for r in json.loads(capsys.readouterr().out)} == {"open"}


def test_accept_until_a_date(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    day = time.strftime("%Y-%m-%d", time.localtime(time.time() + 3 * 86400))
    assert _run(tmp_path, monkeypatch, "accept", key, "--until", day, "--reason", "patch window",
                "--owner", "ops") == 0
    _run(tmp_path, monkeypatch, "list", "--state", "decided", "--json")
    d = json.loads(capsys.readouterr().out.split("\n", 1)[1])[0]["decision"]
    assert d["owner"] == "ops" and d["expires_at"]


def test_investigate_prints_the_lifecycle_line_under_the_answer(tmp_path, monkeypatch, capfd):
    # capfd: the rich console holds the real stdout from import time
    transcript = [{"tool": "correlate_findings", "observation": {"status": "ok", "result": {
        "findings": [], "lifecycle": "New 1 · Still open 0 · Fixed 0 · Hidden by your decisions 2"}}},
        {"final_answer": "one burst"}]
    monkeypatch.setattr(app, "run_agent", lambda *a, **k: {"status": "final_answer", "final_answer": "one burst",
                                                           "transcript": transcript})
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    monkeypatch.setattr(app, "get_active_target", lambda: T)
    monkeypatch.setenv("NO_COLOR", "1")
    assert app.main(["--data-dir", str(tmp_path), "investigate", "any brute force?"]) == 0
    out = " ".join(capfd.readouterr().out.split())
    assert "New 1 · Still open 0 · Fixed 0 · Hidden by your decisions 2 (kratos findings list)" in out

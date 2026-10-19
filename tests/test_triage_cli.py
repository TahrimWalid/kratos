"""`kratos findings recheck|retest|suggestions` and verdict/suggestion rendering in
`kratos findings show` (docs/phaseB/B.1 §5.2, §5.3)."""
from __future__ import annotations

import json
import time
import uuid

from kratos.cli import app
from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import nothing
from kratos.lifecycle.keys import finding_key
from kratos.run_context import RunContext
from kratos.triage import store as TS
from kratos.triage.verdict import Verdict, VerifyCheck

T = "10.0.0.5"


def _seed(tmp_path):
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([{"id": "CORR-SSH-001", "title": "SSH brute force", "severity": "high", "evidence": ["burst"],
                  "subject": "", "entities": ["203.0.113.9"]}],
                target=T, coverage=nothing(), run=r, data_dir=tmp_path)
    return finding_key("CORR-SSH-001", T, "")


def _run(tmp_path, monkeypatch, *argv):
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    monkeypatch.setattr(app, "get_active_target", lambda: T)
    return app.main(["--data-dir", str(tmp_path), "findings", *argv])


def test_show_renders_verdict_and_suggestion(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    TS.record_verdict(tmp_path, finding_key=key, verifier="re-measured sign-in activity", cost="quick",
                      run_id=None, duration=0.5,
                      verdict=Verdict("reproduced", "The burst is still in the logs.",
                                      checks=(VerifyCheck("measure_auth_activity", "ssh"),)))
    TS.record_suggestion(tmp_path, finding_key=key, rule_id="CORR-SSH-001", target="10.0.0.5", run_id=None,
                         kind="false_positive", why="this is our own pentest box")
    assert _run(tmp_path, monkeypatch, "show", key[:12]) == 0
    out = capsys.readouterr().out
    assert "reproduced by a fresh read" in out
    assert "the model suggests" in out and "our own pentest box" in out


def test_suggestions_list_and_dismiss(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    sid = TS.record_suggestion(tmp_path, finding_key=key, rule_id="CORR-SSH-001", target="10.0.0.5", run_id=None,
                               kind="lower_severity", why="only seen from Kratos")
    assert _run(tmp_path, monkeypatch, "suggestions") == 0
    assert f"#{sid}" in capsys.readouterr().out
    assert _run(tmp_path, monkeypatch, "suggestions", "--dismiss", str(sid)) == 0
    assert f"dismissed suggestion #{sid}" in capsys.readouterr().out
    assert _run(tmp_path, monkeypatch, "suggestions") == 0
    assert "no open suggestions" in capsys.readouterr().out


def test_recheck_runs_and_stores(tmp_path, monkeypatch, capsys):
    key = _seed(tmp_path)
    # stub the fresh read so the CLI test touches no SSH and is deterministic
    from kratos.triage import context as ctx
    monkeypatch.setattr(ctx, "_default_dispatch",
                        lambda dd: (lambda tool, args: {"status": "error", "observation": "no target in a test"}))
    assert _run(tmp_path, monkeypatch, "recheck", key[:12], "--json") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"]["verdict"] == "couldnt_check"
    assert TS.latest_verdict(tmp_path, key).verdict.verdict == "couldnt_check"


def test_recheck_all_with_no_serious(tmp_path, monkeypatch, capsys):
    _seed(tmp_path)
    # accept the one serious finding so --all has nothing to do
    key = finding_key("CORR-SSH-001", T, "")
    assert _run(tmp_path, monkeypatch, "accept", key[:12], "--days", "1", "--reason", "x") == 0
    capsys.readouterr()
    assert _run(tmp_path, monkeypatch, "recheck", "--all") == 0
    assert "no open HIGH/CRITICAL" in capsys.readouterr().out

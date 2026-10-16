"""`kratos doctor`: the app's /doctor self-check as a plain command (B.4) -- the
10-minute install path needs a way to ask "is my setup working?" without the TUI."""
from __future__ import annotations

from kratos.agent import doctor
from kratos.cli import app as cli_app


def _rows(*rows):
    return lambda data_dir=None: [dict(r) for r in rows]


def test_doctor_prints_every_row_and_a_verdict(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(doctor, "run_diagnostics", _rows(
        {"check": "LLM endpoint", "status": "pass", "detail": "reachable"},
        {"check": "target", "status": "warn", "detail": "no sub-agent", "fix": "pair one with /subagent"},
    ))
    assert cli_app.main(["--data-dir", str(tmp_path), "doctor"]) == 0
    out = capsys.readouterr().out
    assert "PASS  LLM endpoint" in out and "WARN  target" in out
    assert "-> pair one with /subagent" in out
    assert "ready: 1 passed, 1 warning(s), 0 failed" in out


def test_a_failed_check_makes_doctor_exit_1(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(doctor, "run_diagnostics", _rows(
        {"check": "LLM endpoint", "status": "fail", "detail": "connection refused", "fix": "set LLM_BASE_URL"},
    ))
    assert cli_app.main(["--data-dir", str(tmp_path), "doctor"]) == 1
    out = capsys.readouterr().out
    assert "not ready: 0 passed, 0 warning(s), 1 failed" in out and "-> set LLM_BASE_URL" in out


def test_machine_text_in_a_row_is_cleaned(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(doctor, "run_diagnostics", _rows(
        {"check": "target", "status": "fail", "detail": "ssh said \x1b]52;c;ZXZpbA==\x07 nope"},
    ))
    cli_app.main(["--data-dir", str(tmp_path), "doctor"])
    assert "\x1b" not in capsys.readouterr().out

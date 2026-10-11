"""The answer guards still see every finding (0.1 decision 6): an ACCEPTED high
finding is hidden from the person's default view, never from the model or Guard 3.
Drives the real run_agent loop with the REAL correlate_findings handler on real
input files; only the model is scripted."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kratos import kratos_config
from kratos.agent import loop as agent_loop
from kratos.lifecycle import decide as D
from kratos.lifecycle.keys import finding_key

T = "10.0.0.5"
ME = D.Actor(user="alice", interface="cli")


def _final(text):
    return json.dumps({"reasoning": "done", "final_answer": text})


def _tool(name):
    return json.dumps({"reasoning": "check", "tool": name, "args": {}})


class Chat:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, system_prompt, user_prompt, max_tokens=None):
        self.calls.append((system_prompt, user_prompt))
        return self.responses.pop(0)


@pytest.fixture
def accepted_high(tmp_path, monkeypatch):
    """A data folder whose real inputs produce CORR-SSH-001 (high), already accepted."""
    monkeypatch.setattr(kratos_config, "get_active_target", lambda: T)
    for sub in ("scans", "logs", "context", "reports", "baseline"):
        (tmp_path / sub).mkdir()
    (tmp_path / "scans" / "parsed_1.json").write_text(json.dumps(
        {"target": T, "hosts": [{"ip": T, "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}]}]}))
    burst = {"event_type": "ssh_failed_login", "count": 4, "start": "2026-10-04T08:55:24+00:00",
             "end": "2026-10-04T08:55:30+00:00", "top_source_ips": [{"ip": "203.0.113.9", "count": 4}]}
    (tmp_path / "logs" / "auth_patterns_1.json").write_text(json.dumps({"target": T, "bursts": [burst]}))
    (tmp_path / "logs" / "auth_stats_1.json").write_text(json.dumps(
        {"target": T, "source": f"ssh_target_journald:ubuntu@{T}", "events_by_type": {"ssh_failed_login": 4}}))
    from kratos.adapters.findings_engine import write_findings_report

    write_findings_report(tmp_path)
    D.accept_risk(finding_key("CORR-SSH-001", T, ""), actor=ME, reason="lab scanner", owner=None,
                  expires_at=__import__("time").time() + 86400, data_dir=tmp_path)
    return tmp_path


def _run(data_dir: Path, monkeypatch, answers):
    chat = Chat([_tool("correlate_findings"), *map(_final, answers)])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    return agent_loop.run_agent("is the box ok?", data_dir, max_iters=10), chat


def _rejections(result, violation):
    return [s for s in result["transcript"]
            if s.get("status") == "final_answer_rejected" and violation in s.get("violations", [])]


def test_model_sees_the_accepted_finding_with_its_state_and_the_hidden_count(accepted_high, monkeypatch):
    result, chat = _run(accepted_high, monkeypatch, ["CORR-SSH-001 is an accepted risk (lab scanner)."])
    obs = next(s for s in result["transcript"] if s.get("tool") == "correlate_findings")["observation"]
    found = obs["result"]["findings"]
    corr = next(f for f in found if f["id"] == "CORR-SSH-001")
    assert corr["state"] == "risk_accepted" and corr["decision"]["reason"] == "lab scanner"
    assert "1 finding(s) are hidden from the user's default view" in obs["result"]["hidden_by_user_decisions"]
    assert "Hidden by your decisions 1" in obs["result"]["lifecycle"]
    assert "never claim you changed a finding's state" in chat.calls[0][0]


def test_guard3_still_fires_for_an_accepted_high_the_answer_dismisses(accepted_high, monkeypatch):
    dismissive = "No suspicious activity was found; the system appears secure."
    result, _ = _run(accepted_high, monkeypatch, [dismissive, dismissive, dismissive])
    assert _rejections(result, "dismissive_verdict_contradiction")


def test_naming_the_accepted_finding_passes(accepted_high, monkeypatch):
    answer = ("No suspicious activity beyond CORR-SSH-001, which you accepted as a risk until tomorrow "
              "(lab scanner); the system otherwise appears secure.")
    result, _ = _run(accepted_high, monkeypatch, [answer])
    assert not [s for s in result["transcript"] if s.get("status") == "final_answer_rejected"]
    assert result["final_answer"] == answer


def test_guard1_unchanged_answer_without_correlation_is_rejected(accepted_high, monkeypatch):
    chat = Chat([_final("All fine."), _tool("correlate_findings"), _final("CORR-SSH-001 is accepted.")])
    monkeypatch.setattr(agent_loop, "agent_chat", chat)
    result = agent_loop.run_agent("is the box ok?", accepted_high, max_iters=10)
    first = next(s for s in result["transcript"] if s.get("status") == "final_answer_rejected")
    assert any("correlat" in v for v in first["violations"])
    assert result["final_answer"] == "CORR-SSH-001 is accepted."

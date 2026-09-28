"""
Mocked/scripted tests for mcp_server.py (2026-07-19).

No real MCP protocol/transport involved -- these call kratos_investigate/
kratos_get_findings/kratos_list_sessions directly as plain Python functions
(confirmed: @mcp.tool() registers a function with FastMCP's tool manager
and returns it completely unwrapped, no .fn/other indirection), matching
this project's convention of testing logic directly and reserving actual
end-to-end protocol verification for a real, unmocked run (see the
conversation this shipped in, not duplicated here).

The single most important thing under test: _tool_reaches_approval must
catch ALL FOUR real tools whose handlers can call request_approval, not
just the two with requires_approval=True at the registry level -- a real
gap found via a direct call-graph trace (run_vuln_scan/check_ip_reputation
both reach it conditionally with requires_approval=False), not a
hypothetical worth guarding against.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kratos import mcp_server
from kratos.agent.tools import TOOL_REGISTRY, Tool
from kratos.storage.session_store import SessionStore


# ---------------------------------------------------------------------------
# _tool_reaches_approval
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "name",
    ["capture_traffic", "run_linux_command", "run_vuln_scan", "check_ip_reputation"],
)
def test_reaches_approval_true_for_all_four_real_tools(name):
    # The real, currently-shipped set -- confirmed via a direct grep +
    # inspect.getsource trace, not assumed. Two of these
    # (run_vuln_scan/check_ip_reputation) have requires_approval=False at
    # the registry level -- if this test only covered the other two, it
    # would silently stop catching regressions on the exact gap that was
    # found and fixed.
    assert mcp_server._tool_reaches_approval(TOOL_REGISTRY[name]) is True


@pytest.mark.parametrize("name", ["run_nmap_scan", "correlate_findings", "read_journalctl", "run_yara_scan"])
def test_reaches_approval_false_for_known_safe_tools(name):
    assert mcp_server._tool_reaches_approval(TOOL_REGISTRY[name]) is False


def test_reaches_approval_true_via_flag_alone():
    def _handler():
        return {}

    tool = Tool(name="fake", description="", parameters={}, handler=_handler, requires_approval=True)
    assert mcp_server._tool_reaches_approval(tool) is True


def test_reaches_approval_true_when_source_unavailable():
    # Fail-safe: inspect.getsource() raises for a handler with no real
    # source (built-in/dynamically-generated with no backing file) --
    # treated as "can't verify, exclude it", never "can't verify, assume fine".
    tool = Tool(name="fake", description="", parameters={}, handler=len, requires_approval=False)
    assert mcp_server._tool_reaches_approval(tool) is True


def test_reaches_approval_false_for_clean_handler_with_source():
    def _handler():
        return {"status": "ok"}

    tool = Tool(name="fake", description="", parameters={}, handler=_handler, requires_approval=False)
    assert mcp_server._tool_reaches_approval(tool) is False


# ---------------------------------------------------------------------------
# _extract_findings
# ---------------------------------------------------------------------------
def test_extract_findings_pulls_only_correlate_findings_steps():
    transcript = [
        {"tool": "run_nmap_scan", "observation": {"status": "ok", "result": {"host_count": 1}}},
        {
            "tool": "correlate_findings",
            "observation": {
                "status": "ok",
                "result": {"findings": [{"id": "CORR-SSH-001", "severity": "high"}]},
            },
        },
        {"final_answer": "done"},
    ]
    findings = mcp_server._extract_findings(transcript)
    assert findings == [{"id": "CORR-SSH-001", "severity": "high"}]


def test_extract_findings_empty_when_no_correlate_findings_call():
    transcript = [{"tool": "run_nmap_scan", "observation": {"status": "ok", "result": {}}}]
    assert mcp_server._extract_findings(transcript) == []


def test_extract_findings_handles_domain_level_error_shape():
    # unwrap_tool_result's own contract: an outer status of "error" means
    # don't descend into "result" at all.
    transcript = [{"tool": "correlate_findings", "observation": {"status": "error", "observation": "boom"}}]
    assert mcp_server._extract_findings(transcript) == []


# ---------------------------------------------------------------------------
# _run_locked_investigation -- exclusion + restore behavior
# ---------------------------------------------------------------------------
def test_investigation_excludes_approval_reaching_tools_during_the_call(tmp_path, monkeypatch):
    seen_registry_keys_during_call = {}

    def _fake_run_agent(goal, data_dir, max_iters=10, on_step=None, **_time_kwargs):
        seen_registry_keys_during_call["keys"] = set(TOOL_REGISTRY.keys())
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    monkeypatch.setattr(mcp_server, "run_agent", _fake_run_agent)

    before = set(TOOL_REGISTRY.keys())
    result = mcp_server._run_locked_investigation("goal", "10.0.0.1", 5, tmp_path)
    after = set(TOOL_REGISTRY.keys())

    assert before == after  # fully restored
    during = seen_registry_keys_during_call["keys"]
    for risky in ("capture_traffic", "run_linux_command", "run_vuln_scan", "check_ip_reputation"):
        assert risky not in during
        assert risky in after  # confirmed restored, not just "still missing"
    assert "run_nmap_scan" in during  # safe tools remain available


def test_investigation_restores_registry_even_if_run_agent_raises(tmp_path, monkeypatch):
    def _fake_run_agent(goal, data_dir, max_iters=10, on_step=None, **_time_kwargs):
        raise RuntimeError("simulated crash mid-investigation")

    monkeypatch.setattr(mcp_server, "run_agent", _fake_run_agent)

    before = set(TOOL_REGISTRY.keys())
    with pytest.raises(RuntimeError):
        mcp_server._run_locked_investigation("goal", "10.0.0.1", 5, tmp_path)
    assert set(TOOL_REGISTRY.keys()) == before


def test_investigation_writes_transcript_and_session_records(tmp_path, monkeypatch):
    def _fake_run_agent(goal, data_dir, max_iters=10, on_step=None, **_time_kwargs):
        return {
            "status": "final_answer",
            "final_answer": "no issues found",
            "transcript": [
                {
                    "tool": "correlate_findings",
                    "observation": {"status": "ok", "result": {"findings": [{"id": "X-1"}]}},
                }
            ],
        }

    monkeypatch.setattr(mcp_server, "run_agent", _fake_run_agent)

    result = mcp_server._run_locked_investigation("check things", "10.0.0.5", 5, tmp_path)

    assert result["status"] == "final_answer"
    assert result["final_answer"] == "no issues found"
    assert result["findings"] == [{"id": "X-1"}]
    assert result["session_id"]

    store = SessionStore(tmp_path / "kratos.db")
    session = store.get_session(result["session_id"])
    assert session["targets"] == ["10.0.0.5"]
    history = store.get_goal_history(result["session_id"])
    assert len(history) == 1
    assert history[0]["goal"] == "check things"
    assert history[0]["status"] == "final_answer"
    assert Path(history[0]["transcript_ref"]).exists()


def test_kratos_investigate_rejects_empty_target():
    with pytest.raises(ValueError):
        mcp_server.kratos_investigate(goal="do something", target="")


def test_kratos_investigate_rejects_empty_goal():
    with pytest.raises(ValueError):
        mcp_server.kratos_investigate(goal="  ", target="10.0.0.1")


# ---------------------------------------------------------------------------
# kratos_get_findings / kratos_list_sessions -- real SQLite + real transcript files
# ---------------------------------------------------------------------------
def test_get_findings_and_list_sessions_against_real_store(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)

    store = SessionStore(tmp_path / "kratos.db")
    session_id = store.create_session(["10.0.0.9"], "test-model")
    turn_id = store.start_turn(session_id, "look for brute force attempts")

    transcripts_dir = tmp_path / "sessions"
    transcripts_dir.mkdir()
    transcript_path = transcripts_dir / f"{session_id}_turn{turn_id}.json"
    transcript_path.write_text(
        json.dumps(
            [
                {
                    "tool": "correlate_findings",
                    "observation": {
                        "status": "ok",
                        "result": {"findings": [{"id": "CORR-SSH-001", "severity": "high"}]},
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    store.complete_turn(turn_id, "final_answer", transcript_ref=str(transcript_path))

    result = mcp_server.kratos_get_findings(session_id=session_id)
    assert result["session_id"] == session_id
    assert result["target"] == ["10.0.0.9"]
    assert len(result["turns"]) == 1
    assert result["turns"][0]["goal"] == "look for brute force attempts"
    assert result["turns"][0]["findings"] == [{"id": "CORR-SSH-001", "severity": "high"}]

    # omitted session_id -> most recently active session
    result_default = mcp_server.kratos_get_findings(session_id=None)
    assert result_default["session_id"] == session_id

    sessions = mcp_server.kratos_list_sessions(limit=10)
    assert any(s["session_id"] == session_id and s["targets"] == ["10.0.0.9"] for s in sessions)


def test_get_findings_raises_for_unknown_session_id(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    SessionStore(tmp_path / "kratos.db")  # initialize schema
    with pytest.raises(ValueError):
        mcp_server.kratos_get_findings(session_id="doesnotexist")


def test_get_findings_empty_when_no_sessions_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    SessionStore(tmp_path / "kratos.db")
    result = mcp_server.kratos_get_findings(session_id=None)
    assert result == {"session_id": None, "target": [], "turns": []}


# ---------------------------------------------------------------------------
# kratos_notify_findings -- content ALWAYS derived from real stored findings,
# never free-form caller input (replaces an earlier kratos_notify(message,
# severity) that let a connecting client send arbitrary notification text).
# ---------------------------------------------------------------------------
def _seed_session_with_turn(tmp_path, *, status, findings, goal="check things", target="10.0.0.9"):
    """Real SessionStore + real transcript file on disk, matching this project's
    convention for pure-logic/parsing coverage against real (not mocked) storage."""
    store = SessionStore(tmp_path / "kratos.db")
    session_id = store.create_session([target], "test-model")
    turn_id = store.start_turn(session_id, goal)

    transcripts_dir = tmp_path / "sessions"
    transcripts_dir.mkdir(exist_ok=True)
    transcript_path = transcripts_dir / f"{session_id}_turn{turn_id}.json"
    transcript = []
    if findings:
        transcript.append(
            {"tool": "correlate_findings", "observation": {"status": "ok", "result": {"findings": findings}}}
        )
    transcript_path.write_text(json.dumps(transcript), encoding="utf-8")
    store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))
    return session_id


@pytest.mark.parametrize(
    "findings,expected",
    [
        ([{"severity": "critical"}], "critical"),
        ([{"severity": "high"}], "critical"),
        ([{"severity": "medium"}], "warning"),
        ([{"severity": "low"}], "info"),
        ([{"severity": "info"}], "info"),
        ([{"severity": "medium"}, {"severity": "high"}], "critical"),  # highest wins
        ([], "info"),
        ([{"severity": "unknown-value"}], "info"),
    ],
)
def test_derive_notify_severity(findings, expected):
    assert mcp_server._derive_notify_severity(findings) == expected


def test_notify_findings_rejects_empty_session_id():
    with pytest.raises(ValueError):
        mcp_server.kratos_notify_findings(session_id="")


def test_notify_findings_raises_for_unknown_session(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    SessionStore(tmp_path / "kratos.db")  # initialize schema, no sessions

    called = []
    monkeypatch.setattr(mcp_server, "send_notification", lambda *a, **k: called.append(1))

    with pytest.raises(ValueError):
        mcp_server.kratos_notify_findings(session_id="doesnotexist")
    assert called == []  # nothing sent


def test_notify_findings_raises_when_no_turn_completed(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    session_id = _seed_session_with_turn(
        tmp_path, status="cancelled", findings=[{"id": "X-1", "severity": "high"}]
    )

    called = []
    monkeypatch.setattr(mcp_server, "send_notification", lambda *a, **k: called.append(1))

    with pytest.raises(ValueError, match="no turn that reached a real completion"):
        mcp_server.kratos_notify_findings(session_id=session_id)
    assert called == []


def test_notify_findings_raises_when_no_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    session_id = _seed_session_with_turn(tmp_path, status="final_answer", findings=[])

    called = []
    monkeypatch.setattr(mcp_server, "send_notification", lambda *a, **k: called.append(1))

    with pytest.raises(ValueError, match="no findings"):
        mcp_server.kratos_notify_findings(session_id=session_id)
    assert called == []


def test_notify_findings_sends_content_matching_real_stored_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    session_id = _seed_session_with_turn(
        tmp_path,
        status="final_answer",
        findings=[
            {"id": "CORR-SSH-001", "title": "Probable SSH brute-force attack", "severity": "high"},
            {"id": "NET-002", "title": "Open ports detected", "severity": "medium"},
        ],
        target="10.136.28.168",
    )

    captured = {}

    def _fake_send_notification(message, severity="info"):
        captured["message"] = message
        captured["severity"] = severity
        return {"status": "sent", "topic": "fake-topic", "severity": severity, "http_status": 200}

    monkeypatch.setattr(mcp_server, "send_notification", _fake_send_notification)

    result = mcp_server.kratos_notify_findings(session_id=session_id)

    # Content genuinely comes from the stored findings, not caller input --
    # there is no message/severity parameter on this tool at all.
    assert "CORR-SSH-001" in captured["message"]
    assert "Probable SSH brute-force attack" in captured["message"]
    assert "NET-002" in captured["message"]
    assert session_id in captured["message"]
    assert "10.136.28.168" in captured["message"]
    assert captured["severity"] == "critical"  # derived from the HIGH finding, not asserted
    assert result["derived_severity"] == "critical"
    assert result["notified_message"] == captured["message"]
    assert result["status"] == "sent"


def test_notify_findings_uses_the_same_lookup_as_get_findings(tmp_path, monkeypatch):
    # Explicit requirement: kratos_notify_findings must resolve findings via
    # the same path kratos_get_findings uses, not a second implementation.
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    session_id = _seed_session_with_turn(
        tmp_path, status="final_answer", findings=[{"id": "X-1", "title": "t", "severity": "low"}]
    )
    monkeypatch.setattr(mcp_server, "send_notification", lambda message, severity="info": {"status": "sent"})

    get_findings_result = mcp_server.kratos_get_findings(session_id=session_id)
    notify_result = mcp_server.kratos_notify_findings(session_id=session_id)

    get_findings_findings = [f for t in get_findings_result["turns"] for f in t["findings"]]
    assert get_findings_findings == [{"id": "X-1", "title": "t", "severity": "low"}]
    assert "X-1" in notify_result["notified_message"]

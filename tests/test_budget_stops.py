"""What happens at a hard limit: run_agent ends "stopped_by_budget" with a
deterministic answer and keeps what it found; unattended runs are refused before
they start (recorded + notified); MCP returns a clear status; the CLI and the TUI
show one plain message."""
from __future__ import annotations

import json

import pytest

from kratos import kratos_config, llm_interface, settings_store
from kratos.agent import loop as agent_loop
from kratos.agent.tools import TOOL_REGISTRY
from kratos.budget import guard, limits as L
from kratos.budget.ledger import BudgetLedger
from kratos.run_context import run_scope

HIGH = {"id": "CORR-SSH-001", "title": "SSH exposed with failed-login burst activity observed",
        "severity": "high", "evidence": ["x"], "recommendation": ["y"]}


def _tool(name: str, args: dict | None = None) -> str:
    return json.dumps({"reasoning": "next", "tool": name, "args": args or {}})


def _final(text: str) -> str:
    return json.dumps({"reasoning": "done", "final_answer": text})


class MeteredScript:
    """Replaces agent_chat with scripted replies that still pass the REAL budget
    guard (llm_interface._metered_call), as a hosted model's would."""

    def __init__(self, replies: list[str]):
        self.replies, self.calls = list(replies), 0

    def __call__(self, system_prompt: str, user_prompt: str, max_tokens: int | None = None) -> str:
        reply = self.replies.pop(0)

        def send(_system: str, _prompt: str) -> dict:
            return {"choices": [{"message": {"content": reply}}],
                    "usage": {"prompt_tokens": 1000, "completion_tokens": 100, "total_tokens": 1100}}

        body = llm_interface._metered_call(send, system_prompt=system_prompt, prompt=user_prompt,
                                           max_tokens=max_tokens or 512, model="priced-model", local=False, masker=llm_interface._masker(local=False))
        self.calls += 1
        return body["choices"][0]["message"]["content"]


@pytest.fixture
def setup(tmp_path, monkeypatch):
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("10.0.0.9")
    from kratos.budget import pricing

    pricing.set_rate(tmp_path, "priced-model", 1.0, 2.0, actor="test")
    monkeypatch.setattr(TOOL_REGISTRY["correlate_findings"], "handler",
                        lambda **kw: {"findings": [HIGH], "count": 1, "staleness_warning": None,
                                      "missing_inputs": [], "input_errors": {}, "inputs_used": {}})
    monkeypatch.setattr(TOOL_REGISTRY["list_processes"], "handler", lambda **kw: {"status": "ok", "processes": []})
    return tmp_path


def _set(tmp_path, key, value):
    settings_store.set(key, value, data_dir=tmp_path, actor="test")


def test_run_agent_stops_at_the_call_cap_with_a_deterministic_answer(setup, monkeypatch):
    _set(setup, L.RUN_MODEL_CALLS, 3)
    script = MeteredScript([_tool("list_processes"), _tool("correlate_findings"), _tool("list_processes"),
                            _final("never reached")])
    monkeypatch.setattr(agent_loop, "agent_chat", script)
    with run_scope("interactive"):
        result = agent_loop.run_agent("check the box", setup)
    assert result["status"] == "stopped_by_budget" and script.calls == 3
    answer = result["final_answer"]
    assert "this run's model-call limit is used up (3 calls of 3 calls)" in answer
    assert "unfinished, not a clean result" in answer
    assert "- list_processes: ok" in answer and "- correlate_findings: ok" in answer
    assert "CORR-SSH-001" in answer and "budget.run_model_calls" in answer
    assert result["budget"]["scope"] == L.SCOPE_RUN_CALLS
    # what it collected is still there for the report/lifecycle/triggers
    from kratos.agent.scheduled_run import _extract_findings

    assert [f["id"] for f in _extract_findings(result["transcript"])] == ["CORR-SSH-001"]
    assert result["transcript"][-1]["status"] == "stopped_by_budget"
    # no answer guard fired on it -- it is not a model answer
    assert not any(e.get("status") == "final_answer_rejected" for e in result["transcript"])
    rows = BudgetLedger(setup).rows()
    assert [r["status"] for r in rows] == ["settled"] * 3 + ["refused"]


def test_a_stop_before_any_check_says_so(setup, monkeypatch):
    _set(setup, L.DAILY_COST, 0)
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_final("x")]))
    with run_scope("schedule"):
        result = agent_loop.run_agent("check the box", setup)
    assert result["status"] == "stopped_by_budget"
    assert "No checks had run yet." in result["final_answer"]
    assert "today's model budget" in result["final_answer"]


def test_guards_still_fire_for_a_model_answer_under_the_budget(setup, monkeypatch):
    """The budget path adds a status; it must not change what Guard 1 sees."""
    script = MeteredScript([_final("All fine."), _final("All fine."), _final("All fine."), _final("All fine.")])
    monkeypatch.setattr(agent_loop, "agent_chat", script)
    with run_scope("interactive"):
        result = agent_loop.run_agent("is anything wrong?", setup, max_iters=4)
    assert any(e.get("status") == "final_answer_rejected" for e in result["transcript"])


# --- unattended: refused before start ------------------------------------------
def _scheduled_preset(tmp_path):
    from kratos.agent import presets as P
    from kratos.agent import schedules as S

    P.save_preset(tmp_path, name="look", goal="is ssh exposed?")
    return S.save_schedule(tmp_path, name="nightly", kind="preset", preset="look", target="10.0.0.9")


def test_scheduled_agentic_run_is_refused_before_start_recorded_and_notified(setup, monkeypatch):
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run

    monkeypatch.setattr("kratos.llm_config.get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_config._active_backend_is_local", lambda: False)
    started: list = []
    monkeypatch.setattr("kratos.agent.loop.run_agent", lambda *a, **k: started.append(1) or {})
    _set(setup, L.UNATTENDED_DAILY_COST, 0)
    sent: list = []
    record = scheduled_run.run_scheduled(_scheduled_preset(setup), setup,
                                         notifier=lambda m, s: sent.append((m, s)) or {"status": "sent"})
    assert started == []
    assert record["status"] == "refused_by_budget"
    assert "budget for unattended runs" in record["error"]
    assert S.read_run_records(setup, "nightly")[-1]["status"] == "refused_by_budget"   # persisted
    assert sent and sent[0][1] == "warning" and "refused_by_budget" in sent[0][0]


def test_run_now_from_the_tui_is_not_prechecked(setup, monkeypatch):
    """A person pressed "run now": attended, so it is asked at the limit instead."""
    from kratos.agent import scheduled_run

    _set(setup, L.UNATTENDED_DAILY_COST, 0)
    ran: list = []
    monkeypatch.setattr("kratos.agent.loop.run_agent",
                        lambda *a, **k: ran.append(1) or {"status": "final_answer", "final_answer": "ok",
                                                          "transcript": []})
    record = scheduled_run.run_scheduled(_scheduled_preset(setup), setup, source="interactive", deliver=False)
    assert ran == [1] and record["status"] == "final_answer"


def test_a_deterministic_audit_schedule_is_never_refused(setup, monkeypatch):
    """The standard audit makes no model calls: free, unaffected (non-goal)."""
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run

    _set(setup, L.DAILY_COST, 0)
    _set(setup, L.DAILY_TOKENS, 0)
    called: list = []
    monkeypatch.setattr(scheduled_run, "_run_audit",
                        lambda data_dir, gated: called.append(1) or ("completed", [], [], None))
    sch = S.save_schedule(setup, name="audit", kind="audit", target="10.0.0.9")
    record = scheduled_run.run_scheduled(sch, setup, deliver=False)
    assert called == [1] and record["status"] == "completed"


def test_trigger_investigation_refused_when_unattended_cap_is_used_up(setup, monkeypatch):
    from kratos.agent import scheduled_run

    monkeypatch.setattr("kratos.llm_config.get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_config._active_backend_is_local", lambda: False)
    _set(setup, L.UNATTENDED_DAILY_COST, 0)
    out = scheduled_run.run_headless_investigation("look deeper", setup,
                                                   run_agent_fn=lambda *a: pytest.fail("must not start"))
    assert out["status"] == "refused_by_budget" and "Settings -> Budget" in out["final_answer"]


def test_mcp_returns_a_clear_refusal_without_creating_a_session(setup, monkeypatch):
    from kratos import mcp_server
    from kratos.storage.session_store import SessionStore

    monkeypatch.setattr("kratos.llm_config.get_active_llm_model", lambda: "priced-model")
    monkeypatch.setattr("kratos.llm_config._active_backend_is_local", lambda: False)
    monkeypatch.setattr(mcp_server, "run_agent", lambda *a, **k: pytest.fail("must not start"))
    _set(setup, L.UNATTENDED_DAILY_COST, 0)
    out = mcp_server._run_locked_investigation("goal", "10.0.0.9", 3, setup)
    assert out["status"] == "refused_by_budget" and out["session_id"] is None
    assert out["budget"]["scope"] == L.SCOPE_UNATTENDED_COST and "Settings -> Budget" in out["final_answer"]
    assert SessionStore(setup / "kratos.db").list_recent_sessions() == []


def test_mcp_stopped_mid_run_reports_the_budget(setup, monkeypatch):
    from kratos import mcp_server

    _set(setup, L.RUN_MODEL_CALLS, 1)
    monkeypatch.setattr(agent_loop, "agent_chat", MeteredScript([_tool("list_processes"), _final("x")]))
    out = mcp_server._run_locked_investigation("goal", "10.0.0.9", 3, setup)
    assert out["status"] == "stopped_by_budget" and out["budget"]["scope"] == L.SCOPE_RUN_CALLS


# --- small call sites ------------------------------------------------------------
def test_plan_preview_pipeline_draft_and_clarify_let_the_budget_through(setup, monkeypatch):
    """They swallow model errors on purpose ("couldn't reach the model") -- but a
    spending limit is not a model error and must reach the caller."""
    from kratos.agent import clarify_intake, pipeline_draft, plan_preview

    def refuse(*a, **k):
        raise guard.BudgetExceeded(L.SCOPE_DAILY_COST, 2.0, 2.0, source="interactive")

    with pytest.raises(guard.BudgetExceeded):
        plan_preview.preview_agentic("check ssh", "10.0.0.9", chat=refuse)
    with pytest.raises(guard.BudgetExceeded):
        pipeline_draft.draft_pipeline("scan then correlate", registry=TOOL_REGISTRY, chat=refuse)
    with pytest.raises(guard.BudgetExceeded):
        clarify_intake.assess_intake_clarity("x", purpose="p", chat=refuse)


def test_cli_command_ends_with_the_plain_message(setup, monkeypatch, capsys):
    from kratos.cli import app

    monkeypatch.setattr(app, "load_kept_tools", lambda: [])

    def refuse(args):
        raise guard.BudgetExceeded(L.SCOPE_DAILY_COST, 2.0, 2.0, source="cli")

    parser = app.build_parser()
    monkeypatch.setattr(app, "build_parser", lambda: parser)
    parser._subparsers._group_actions[0].choices["findings-show"].set_defaults(func=refuse)
    code = app.main(["--data-dir", str(setup), "findings-show"])
    assert code == 3
    assert "today's model budget is used up" in capsys.readouterr().err


def test_cli_installs_the_terminal_prompt(setup, monkeypatch):
    from kratos.cli import app

    seen = {}
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    parser = app.build_parser()
    monkeypatch.setattr(app, "build_parser", lambda: parser)
    parser._subparsers._group_actions[0].choices["findings-show"].set_defaults(
        func=lambda args: seen.setdefault("provider", guard.prompt_provider()) and 0)
    app.main(["--data-dir", str(setup), "findings-show"])
    assert seen["provider"] is guard.terminal_prompt


@pytest.mark.parametrize("typed,expected", [("y", True), ("yes", True), ("", False), ("n", False),
                                            ("x", False)])
def test_terminal_prompt_needs_an_explicit_yes(monkeypatch, typed, expected):
    monkeypatch.setattr("sys.stdin", type("TTY", (), {"isatty": lambda self: True})())
    monkeypatch.setattr("builtins.input", lambda prompt="": typed)
    q = guard.OverCapQuestion(L.SCOPE_DAILY_COST, 2.0, 1.94, "cli")
    assert guard.terminal_prompt(q) is expected


@pytest.mark.parametrize("exc", [EOFError, KeyboardInterrupt])
def test_terminal_prompt_eof_or_ctrl_c_is_no(monkeypatch, exc):
    monkeypatch.setattr("sys.stdin", type("TTY", (), {"isatty": lambda self: True})())

    def boom(prompt=""):
        raise exc()

    monkeypatch.setattr("builtins.input", boom)
    assert guard.terminal_prompt(guard.OverCapQuestion(L.SCOPE_DAILY_COST, 2.0, 2.0, "cli")) is False


def test_terminal_prompt_without_a_terminal_is_no_and_never_reads(monkeypatch):
    monkeypatch.setattr("sys.stdin", type("Pipe", (), {"isatty": lambda self: False})())
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("must not read a pipe"))
    assert guard.terminal_prompt(guard.OverCapQuestion(L.SCOPE_DAILY_COST, 2.0, 2.0, "cli")) is False

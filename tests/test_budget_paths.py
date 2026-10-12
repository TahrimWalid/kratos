"""Every way into the model records a ledger row with the right source.

The HTTP layer (requests.post) is mocked; everything above it -- agent_chat, the
budget guard, the run scopes each entry point opens -- runs for real. One test
per path: `kratos investigate`, a scheduled run, a trigger investigation, MCP,
and the TUI's router/chat, investigation, plan preview, pipeline drafting and
/evolve's guided build.
"""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("requests")

from kratos import kratos_config, llm_interface
from kratos.budget.ledger import BudgetLedger
from kratos.run_context import run_scope

FINAL = json.dumps({"reasoning": "done", "final_answer": "Nothing more to check; concluding without "
                    "correlate_findings because no data tool was needed."})


class _Resp:
    status_code = 200

    def __init__(self, content: str):
        self._body = {"choices": [{"message": {"content": content}}],
                      "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110}}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._body


@pytest.fixture
def model(tmp_path, monkeypatch):
    """A hosted model behind a mocked HTTP layer. `model.route` is what the TUI
    router's call returns; every other call gets a final answer."""
    kratos_config.set_active_data_dir(tmp_path)
    kratos_config.set_active_target("10.0.0.1")
    monkeypatch.setattr(llm_interface, "_running_backend", lambda: "openai_compatible")
    monkeypatch.setattr(llm_interface, "get_active_llm_base_url", lambda: "https://api.example.com/v1")
    monkeypatch.setattr(llm_interface, "get_active_llm_api_key", lambda: "k")
    monkeypatch.setattr(llm_interface, "get_active_llm_model", lambda: "priced-model")
    from kratos.tui_mk2 import command_intent

    state = {"route": "INVESTIGATE", "calls": 0}

    def post(url, headers=None, json=None, timeout=None):
        state["calls"] += 1
        system = json["messages"][0]["content"]
        return _Resp(state["route"] if system == command_intent._system_prompt() else FINAL)

    monkeypatch.setattr(llm_interface.requests, "post", post)
    state["dir"] = tmp_path
    return state


def _sources(tmp_path) -> set[str]:
    return {r["source"] for r in BudgetLedger(tmp_path).rows() if r["status"] == "settled"}


def test_kratos_investigate_records_cli_rows(model, monkeypatch):
    from kratos.cli import app

    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    monkeypatch.setenv("KRATOS_SSH_HOST", "10.0.0.1")
    app.main(["--data-dir", str(model["dir"]), "investigate", "is ssh exposed?"])
    assert _sources(model["dir"]) == {"cli"}


def test_scheduled_run_records_schedule_rows(model, monkeypatch):
    from kratos.agent import presets as P
    from kratos.agent import schedules as S
    from kratos.cli import app

    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    P.save_preset(model["dir"], name="look", goal="is ssh exposed?")
    S.save_schedule(model["dir"], name="nightly", kind="preset", preset="look", target="10.0.0.1")
    app.main(["--data-dir", str(model["dir"]), "scheduled-run", "nightly", "--no-deliver"])
    assert _sources(model["dir"]) == {"schedule"}


def test_trigger_investigation_records_trigger_rows_under_their_parent(model):
    from kratos.agent import scheduled_run

    with run_scope("schedule") as outer:
        scheduled_run.run_headless_investigation("look deeper", model["dir"])
    rows = [r for r in BudgetLedger(model["dir"]).rows() if r["status"] == "settled"]
    assert rows and {r["source"] for r in rows} == {"trigger"}
    assert {r["parent_run_id"] for r in rows} == {outer.run_id}


def test_mcp_investigation_records_mcp_rows_with_its_session(model):
    from kratos import mcp_server

    out = mcp_server._run_locked_investigation("is ssh exposed?", "10.0.0.1", 3, model["dir"])
    rows = [r for r in BudgetLedger(model["dir"]).rows() if r["status"] == "settled"]
    assert {r["source"] for r in rows} == {"mcp"} and {r["session_id"] for r in rows} == {out["session_id"]}


# --- the TUI ------------------------------------------------------------------
def _screen(tmp_path, monkeypatch):
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    screen = SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")
    monkeypatch.setattr(screen, "_maybe_auto_compact", lambda: None, raising=False)
    return sid, screen


def _drive(screen, start, done):
    from textual.app import App

    class Host(App):
        def on_mount(self):
            self.push_screen(screen)

    async def run():
        async with Host().run_test() as pilot:
            await pilot.pause()
            result = start()
            if asyncio.iscoroutine(result):
                asyncio.ensure_future(result)
            for _ in range(400):
                await pilot.pause()
                if done():
                    break
            for _ in range(5):          # dismiss any question still open (a worker may wait on it)
                await pilot.press("escape")
                await pilot.pause()
    asyncio.run(run())


def _settled(tmp_path):
    return [r for r in BudgetLedger(tmp_path).rows() if r["status"] == "settled"]


def test_tui_router_and_investigation_record_interactive_rows_in_one_run(model, monkeypatch):
    sid, screen = _screen(model["dir"], monkeypatch)
    _drive(screen, lambda: screen._run_goal("any failed ssh logins?"),
           lambda: len(_settled(model["dir"])) >= 2 and not screen._busy)
    rows = _settled(model["dir"])
    assert len(rows) >= 2 and {r["source"] for r in rows} == {"interactive"}
    assert {r["session_id"] for r in rows} == {sid} and len({r["run_id"] for r in rows}) == 1


def test_tui_chat_reply_records_an_interactive_row(model, monkeypatch):
    model["route"] = "Hello! I'm Kratos."
    sid, screen = _screen(model["dir"], monkeypatch)
    _drive(screen, lambda: screen._run_goal("hi there"),
           lambda: len(_settled(model["dir"])) >= 1 and not screen._busy)
    (row,) = _settled(model["dir"])
    assert (row["source"], row["session_id"]) == ("interactive", sid)


def test_tui_plan_preview_records_an_interactive_row(model, monkeypatch):
    sid, screen = _screen(model["dir"], monkeypatch)
    _drive(screen, lambda: screen._dispatch_slash("/plan check ssh exposure"),
           lambda: len(_settled(model["dir"])) >= 1)
    assert {(r["source"], r["session_id"]) for r in _settled(model["dir"])} == {("interactive", sid)}


def test_tui_pipeline_draft_records_an_interactive_row(model, monkeypatch):
    sid, screen = _screen(model["dir"], monkeypatch)
    _drive(screen, lambda: screen._preset_describe_flow("scan the target then correlate the findings"),
           lambda: len(_settled(model["dir"])) >= 1)
    assert {(r["source"], r["session_id"]) for r in _settled(model["dir"])} == {("interactive", sid)}


def test_tui_evolve_guided_build_records_evolve_rows(model, monkeypatch):
    sid, screen = _screen(model["dir"], monkeypatch)
    _drive(screen, lambda: screen._evolve_flow("count sudo"),        # short: the guided build asks the model first
           lambda: len(_settled(model["dir"])) >= 1)
    assert {(r["source"], r["session_id"]) for r in _settled(model["dir"])} == {("evolve", sid)}

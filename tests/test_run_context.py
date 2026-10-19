"""run_context: every run is attributed -- which run, started how, which machine.

Static half: tests/_run_scope_scan.py proves every path into the model or a tool
opens a run_scope (a new entry point without one fails here). Runtime half: each
kind of entry point really carries its scope to where the model is called and
where a tool runs -- across Textual worker threads, the MCP server, the CLI, the
REPL, scheduled runs and trigger investigations.
"""
from __future__ import annotations

import asyncio
import contextvars
import threading
from types import SimpleNamespace

import pytest

from kratos import kratos_config, run_context
from kratos.run_context import SOURCES, UNATTENDED, bind, current, run_scope


@pytest.fixture(autouse=True)
def _active_target(monkeypatch):
    monkeypatch.setattr(kratos_config, "_active_target_override", None, raising=False)
    kratos_config.set_active_target("ubuntu@10.136.28.168")
    yield


# ---------------------------------------------------------------------------
# The object itself
# ---------------------------------------------------------------------------
def test_no_scope_outside_a_run():
    assert current() is None and run_context.current_run_id() is None


def test_scope_fields_and_defaults():
    with run_scope("cli") as ctx:
        assert current() is ctx
        assert ctx.source == "cli" and len(ctx.run_id) == 32 and ctx.parent_run_id is None
        assert ctx.target == "10.136.28.168"     # the active target, as a target_key
        assert ctx.session_id is None and ctx.started_at > 0
    assert current() is None


def test_nesting_records_parent_and_inherits():
    with run_scope("schedule", target="Web-01", session_id="s1") as outer:
        with run_scope("trigger") as inner:
            assert inner.parent_run_id == outer.run_id and inner.run_id != outer.run_id
            assert inner.target == "web-01" and inner.session_id == "s1"
            assert inner.unattended
        assert current() is outer
    with run_scope("interactive", target="localhost") as ctx:
        assert ctx.target == "loopback" and not ctx.unattended


def test_unknown_source_rejected_and_sets_match_readme():
    with pytest.raises(ValueError):
        with run_scope("cron"):
            pass
    assert SOURCES == ("interactive", "schedule", "trigger", "pipeline", "mcp", "web", "evolve", "cli")
    assert UNATTENDED == {"schedule", "trigger", "mcp", "web"}


def test_scope_does_not_flow_into_a_plain_thread_but_bind_carries_it():
    seen = {}
    with run_scope("cli") as ctx:
        t = threading.Thread(target=lambda: seen.setdefault("plain", current()))
        t.start(); t.join()
        t = threading.Thread(target=bind(lambda: seen.setdefault("bound", current())))
        t.start(); t.join()
    assert seen["plain"] is None
    assert seen["bound"] is ctx


def test_asyncio_to_thread_carries_the_scope():
    async def main():
        with run_scope("interactive") as ctx:
            return ctx, await asyncio.to_thread(current)
    ctx, seen = asyncio.run(main())
    assert seen is ctx


# ---------------------------------------------------------------------------
# Static: every entry point opens a scope
# ---------------------------------------------------------------------------
def test_every_path_to_the_model_or_a_tool_opens_a_run_scope():
    import _run_scope_scan

    assert _run_scope_scan.uncovered_entry_points() == []


def test_the_scan_finds_a_new_unscoped_entry_point(tmp_path, monkeypatch):
    import _run_scope_scan

    pkg = tmp_path / "kratos"
    pkg.mkdir()
    (pkg / "screen.py").write_text(
        "from kratos.agent.loop import run_agent\n"
        "class S:\n"
        "    def on_button(self):\n"
        "        self._worker()\n"
        "    def _worker(self):\n"
        "        run_agent('g', '.')\n"
        "    def on_ok(self):\n"
        "        self._ok_worker()\n"
        "    @_with_run_scope()\n"
        "    def _ok_worker(self):\n"
        "        run_agent('g', '.')\n", encoding="utf-8")
    monkeypatch.setattr(_run_scope_scan, "SRC", pkg)
    gaps = _run_scope_scan.uncovered_entry_points()
    assert gaps == ["kratos.screen:S._worker (line 5)", "kratos.screen:S.on_button (line 3)"]


# ---------------------------------------------------------------------------
# Runtime, per kind of entry point
# ---------------------------------------------------------------------------
def test_cli_command_runs_in_a_cli_scope(tmp_path, monkeypatch):
    from kratos.cli import app

    seen = {}

    def fake_run_agent(goal, data_dir, **kw):
        seen["ctx"] = current()
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    monkeypatch.setattr(app, "run_agent", fake_run_agent)
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    monkeypatch.setenv("KRATOS_SSH_HOST", "10.136.28.168")
    app.main(["--data-dir", str(tmp_path), "investigate", "any failed logins?"])
    assert seen["ctx"].source == "cli" and seen["ctx"].target == "10.136.28.168"


def test_cli_scheduled_run_is_a_schedule_run_not_a_cli_one(tmp_path, monkeypatch):
    from kratos.agent import schedules as S
    from kratos.agent import scheduled_run
    from kratos.cli import app

    seen = {}

    def fake_inner(schedule, data_dir, *, deliver, notifier):
        seen["ctx"] = current()
        return {"schedule": schedule.name, "status": "completed", "target": "10.0.0.9",
                "severity_tally": {}, "notified": False, "error": None}

    monkeypatch.setattr(scheduled_run, "_run_scheduled", fake_inner)
    monkeypatch.setattr(app, "load_kept_tools", lambda: [])
    S.save_schedule(tmp_path, name="wk", kind="audit", target="10.0.0.9")
    app.main(["--data-dir", str(tmp_path), "scheduled-run", "wk", "--no-deliver"])
    ctx = seen["ctx"]
    assert ctx.source == "schedule" and ctx.parent_run_id is None and ctx.target == "10.0.0.9"


def test_trigger_investigation_is_its_own_run_inside_the_scheduled_one(tmp_path):
    from kratos.agent import scheduled_run

    seen = {}

    def fake_run_agent(goal, data_dir):
        seen["ctx"] = current()
        return {"status": "final_answer", "final_answer": "x", "transcript": []}

    with run_scope("schedule") as outer:
        scheduled_run.run_headless_investigation("look deeper", tmp_path, run_agent_fn=fake_run_agent)
    assert seen["ctx"].source == "trigger" and seen["ctx"].parent_run_id == outer.run_id


def test_run_now_from_the_tui_is_attended(tmp_path, monkeypatch):
    from kratos.agent import scheduled_run

    seen = {}
    monkeypatch.setattr(scheduled_run, "_run_scheduled",
                        lambda *a, **k: seen.setdefault("ctx", current()) and {})
    sch = SimpleNamespace(name="wk", target=None)
    scheduled_run.run_scheduled(sch, tmp_path, source="interactive", session_id="abc")
    assert seen["ctx"].source == "interactive" and seen["ctx"].session_id == "abc"


def test_mcp_investigation_is_an_mcp_run(tmp_path, monkeypatch):
    from kratos import mcp_server

    seen = {}

    def fake_run_agent(goal, data_dir, **kw):
        seen["ctx"] = current()
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    monkeypatch.setattr("kratos.agent.loop.run_agent", fake_run_agent)
    out = mcp_server._mcp_investigation("goal", "root@10.0.0.7", 3, tmp_path)
    ctx = seen["ctx"]
    assert ctx.source == "mcp" and ctx.target == "10.0.0.7" and ctx.session_id == out["session_id"]


def test_repl_line_and_evolve_open_scopes(tmp_path, monkeypatch):
    from kratos.cli import repl
    from kratos.storage.session_store import SessionStore

    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    state = {"session_id": sid, "targets": ["10.0.0.1"], "resume_context": ""}
    seen = {}
    monkeypatch.setattr(repl, "_handle_goal", lambda *a, **k: seen.setdefault("goal", current()) and True)
    monkeypatch.setattr(repl, "_cmd_evolve", lambda *a, **k: seen.setdefault("evolve", current()))
    repl._process_input(None, "anything odd?", state, store, tmp_path)
    repl._process_input(None, "/evolve count sudo", state, store, tmp_path)
    assert seen["goal"].source == "interactive" and seen["goal"].session_id == sid
    assert seen["evolve"].source == "evolve" and seen["evolve"].parent_run_id is not None


# --- the TUI: scopes open INSIDE Textual's worker threads ---------------------
def _screen(tmp_path, monkeypatch):
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def _drive(screen, start, done):
    from textual.app import App

    class Host(App):
        def on_mount(self):
            self.push_screen(screen)

    async def run():
        async with Host().run_test() as pilot:
            await pilot.pause()
            start()
            for _ in range(300):
                await pilot.pause()
                if done():
                    break
    asyncio.run(run())


def test_tui_use_runs_the_tool_inside_the_session_scope(tmp_path, monkeypatch):
    """/use: the tool executes in a Textual worker thread -- the scope must be there."""
    from kratos.agent import loop as agent_loop

    sid, screen = _screen(tmp_path, monkeypatch)
    seen = {}

    def fake_exec(name, args, data_dir):
        seen["ctx"] = current()
        seen["thread"] = threading.current_thread()
        return {"status": "ok", "result": {}}

    monkeypatch.setattr(agent_loop, "execute_tool_call", fake_exec)
    _drive(screen, lambda: screen._dispatch_slash("/use list_processes"),
           lambda: "ctx" in seen and not screen._busy)
    assert seen["thread"] is not threading.main_thread()
    assert seen["ctx"].source == "interactive" and seen["ctx"].session_id == sid
    assert seen["ctx"].target == "10.0.0.1"


def test_tui_turn_routes_and_investigates_in_one_scope(tmp_path, monkeypatch):
    """A typed message: the router's model call and the investigation's model
    calls all happen in the same run."""
    from kratos.agent import loop as agent_loop
    from kratos.tui_mk2 import command_intent

    sid, screen = _screen(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(command_intent, "agent_chat",
                        lambda *a, **k: calls.append(("route", current())) or "INVESTIGATE")

    def fake_run_agent(goal, data_dir, **kw):
        calls.append(("investigate", current()))
        return {"status": "final_answer", "final_answer": "done", "transcript": []}

    monkeypatch.setattr(agent_loop, "run_agent", fake_run_agent)
    monkeypatch.setattr(screen, "_maybe_auto_compact", lambda: None, raising=False)
    _drive(screen, lambda: screen._run_goal("any failed ssh logins?"),
           lambda: len(calls) >= 2 and not screen._busy)
    kinds = [k for k, _ in calls]
    assert kinds[:2] == ["route", "investigate"]
    run_ids = {c.run_id for _, c in calls}
    assert len(run_ids) == 1 and calls[0][1].session_id == sid


def test_tui_host_investigation_is_scoped_to_kratos_itself(tmp_path, monkeypatch):
    from kratos.agent import loop as agent_loop

    sid, screen = _screen(tmp_path, monkeypatch)
    seen = {}

    def fake_run_agent(goal, data_dir, **kw):
        seen["ctx"] = current()
        return {"status": "final_answer", "final_answer": "ok", "transcript": []}

    monkeypatch.setattr(agent_loop, "run_agent", fake_run_agent)
    monkeypatch.setattr(screen, "_maybe_auto_compact", lambda: None, raising=False)
    _drive(screen, lambda: screen._run_host_investigation("check yourself"),
           lambda: "ctx" in seen and not screen._busy)
    assert seen["ctx"].target == "loopback" and seen["ctx"].source == "interactive"


def test_tui_evolve_is_an_evolve_run(tmp_path, monkeypatch):
    from kratos.agent import guided_evolve

    sid, screen = _screen(tmp_path, monkeypatch)
    seen = {}

    def fake_build(idea, prompter, suggested_name=None):
        seen["ctx"] = current()
        return SimpleNamespace(status="cancelled")

    monkeypatch.setattr(guided_evolve, "run_guided_build", fake_build)
    _drive(screen, lambda: screen._evolve_flow("count failed sudo attempts"),
           lambda: "ctx" in seen and not screen._busy)
    assert seen["ctx"].source == "evolve" and seen["ctx"].session_id == sid


def test_textual_thread_worker_without_the_decorator_has_no_scope():
    """Why the decorator exists: Textual thread workers start with an empty context."""
    from textual import work
    from textual.app import App

    seen = {}

    class A(App):
        @work(thread=True)
        def bare(self):
            seen["bare"] = current()

    async def run():
        app = A()
        async with app.run_test() as pilot:
            with run_scope("interactive"):
                app.bare()
            for _ in range(50):
                await pilot.pause()
                if "bare" in seen:
                    break
    asyncio.run(run())
    assert seen["bare"] is None


def test_copy_context_is_how_threads_inherit():
    # Documented alternative to opening a scope inside the thread.
    with run_scope("cli") as ctx:
        cv = contextvars.copy_context()
    assert cv.run(current) is ctx

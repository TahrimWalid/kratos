"""
Headless pilots for the mk2 SessionScreen's screen-management commands
(/clear and /reset). These are the shell-like "wipe the screen + reset the
working context" behaviors: /clear keeps the stored session history, /reset
archives it. The network-touching parts of /target (the SSH setup checklist +
probe, isolated in a thread worker) are verified manually, not here.
"""
from __future__ import annotations

import asyncio

from types import SimpleNamespace

from textual.app import App

from kratos import llm_interface
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


def test_remember_turn_accumulates_both_sides():
    # The core memory fix: the working context keeps the user's message AND
    # Kratos's reply, so a follow-up remembers the conversation's content.
    fake = SimpleNamespace(session_state={"resume_context": ""})
    SessionScreen._remember_turn(fake, "hello", "hi there")
    SessionScreen._remember_turn(fake, "what did I just say?", "you said hello")
    ctx = fake.session_state["resume_context"]
    assert "You: hello" in ctx and "Kratos: hi there" in ctx
    assert "You: what did I just say?" in ctx and "Kratos: you said hello" in ctx


def test_context_pct_estimates_from_resume_context_when_unmeasured(monkeypatch):
    # On resume there is no measured usage yet -> the meter approximates the
    # loaded context instead of showing 0 and then jumping (the [f]-resume bug).
    monkeypatch.setattr(llm_interface, "_last_usage", None)
    fake = SimpleNamespace(session_state={"resume_context": "x" * 4000})
    pct, used, window, estimated = SessionScreen._context_pct(fake)
    assert estimated is True and used == 1000          # 4000 chars // 4 tokens

    monkeypatch.setattr(llm_interface, "_last_usage",
                        llm_interface.TokenUsage(prompt_tokens=500, completion_tokens=0, total_tokens=500))
    _pct, used2, _w, estimated2 = SessionScreen._context_pct(fake)
    assert estimated2 is False and used2 == 500        # real measurement takes over


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make_screen(tmp_path, monkeypatch, resume_context="prior resume context"):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], resume_context)


def test_clear_wipes_context_and_resets_token_meter(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Simulate a prior LLM call that filled the 7c context meter.
            llm_interface._last_usage = llm_interface.TokenUsage(
                prompt_tokens=5000, completion_tokens=0, total_tokens=5000)
            screen._dispatch_slash("/clear")
            await pilot.pause()
            return screen.session_state["resume_context"], llm_interface.get_last_token_usage()

    ctx, usage = asyncio.run(_run())
    assert ctx == ""            # working context cleared
    assert usage is None        # meter reset to 0 (was 5000)


_TWO_PROFILE_ENV = (
    "LLM_BASE_URL=https://api.gemini.example/v1\nLLM_API_KEY=gk\n"
    "LLM_MODEL=gemini-3.1-pro\nKRATOS_LLM_BACKEND=openai_compatible\n\n"
    "# LLM_BASE_URL=http://127.0.0.1:11434/v1\n# LLM_API_KEY=ollama\n"
    "# LLM_MODEL=qwen2.5:7b\n# KRATOS_LLM_BACKEND=openai_compatible\n"
)


def test_conversational_target_change_applies_on_approve(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    monkeypatch.setattr(screen, "_setup_target_worker", lambda host: None)  # no real SSH probe

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_m):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._conversational_target("10.9.9.9")
            await pilot.pause()
            await pilot.pause()
            return screen.session_state["targets"]

    assert asyncio.run(_run()) == ["10.9.9.9"]


def test_conversational_target_change_cancelled_on_deny(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    monkeypatch.setattr(screen, "_setup_target_worker", lambda host: None)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _no(_m):
                return False

            monkeypatch.setattr(app, "push_screen_wait", _no)
            screen._conversational_target("10.9.9.9")
            await pilot.pause()
            await pilot.pause()
            return screen.session_state["targets"]

    assert asyncio.run(_run()) == ["10.0.0.1"]  # unchanged (the _make_screen default)


def test_conversational_model_switch_confirmed_calls_switch(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(_TWO_PROFILE_ENV, encoding="utf-8")
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", env)
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["h"], "gemini-3.1-pro")
    screen = SessionScreen(store, tmp_path, sid, ["h"], "")
    calls = []
    monkeypatch.setattr(screen, "_switch_model_worker", lambda t, c: calls.append(t.model))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_m):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._conversational_model("qwen2.5:7b")  # matches the inactive profile
            await pilot.pause()
            await pilot.pause()
            return calls

    assert asyncio.run(_run()) == ["qwen2.5:7b"]


def test_conversational_model_no_match_does_not_switch(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(_TWO_PROFILE_ENV, encoding="utf-8")
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", env)
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["h"], "gemini-3.1-pro")
    screen = SessionScreen(store, tmp_path, sid, ["h"], "")
    calls = []
    monkeypatch.setattr(screen, "_switch_model_worker", lambda t, c: calls.append(t.model))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # no confirm should ever be reached — assert if it is
            async def _boom(_m):
                raise AssertionError("should not prompt for an unknown model")

            monkeypatch.setattr(app, "push_screen_wait", _boom)
            screen._conversational_model("no-such-model")
            await pilot.pause()
            await pilot.pause()
            return calls

    assert asyncio.run(_run()) == []


def test_compact_keeps_recent_verbatim_and_summarizes_older(tmp_path, monkeypatch):
    # 6 distinct turns separated by blank lines; the last 3 must stay verbatim,
    # the older 3 get folded into the summary.
    turns = "\n\n".join(f"You: q{i}\nKratos: a{i}" for i in range(6))
    store, sid, screen = _make_screen(tmp_path, monkeypatch, resume_context=turns)
    monkeypatch.setattr(llm_interface, "agent_chat", lambda *a, **k: "OLDSUMMARY")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/compact")
            await pilot.pause()
            await pilot.pause()
            return screen.session_state["resume_context"]

    ctx = asyncio.run(_run())
    assert "Earlier conversation summary" in ctx and "OLDSUMMARY" in ctx
    assert "a5" in ctx and "a4" in ctx and "a3" in ctx   # last 3 turns kept verbatim
    assert "a0" not in ctx and "a1" not in ctx           # older turns summarized away


def test_chat_auto_compaction_fires_near_limit(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch,
                                      resume_context="You: hi\nKratos: hello there\n" * 10)
    monkeypatch.setattr(llm_interface, "get_last_token_usage", lambda: None)   # use the estimate path
    monkeypatch.setattr(llm_interface, "get_context_window_tokens", lambda: 40)  # tiny window -> over 85%
    monkeypatch.setattr(llm_interface, "agent_chat", lambda *a, **k: "SUMMARY of the chat.")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "call_from_thread", lambda fn, *a, **k: fn(*a, **k))
            screen._maybe_auto_compact()
            return screen.session_state["resume_context"]

    ctx = asyncio.run(_run())
    assert "Earlier conversation summary" in ctx and "SUMMARY of the chat" in ctx


def test_chat_auto_compaction_noop_below_threshold(tmp_path, monkeypatch):
    original = "You: hi\nKratos: hello there\n"
    store, sid, screen = _make_screen(tmp_path, monkeypatch, resume_context=original)
    monkeypatch.setattr(llm_interface, "get_last_token_usage", lambda: None)
    monkeypatch.setattr(llm_interface, "get_context_window_tokens", lambda: 1_000_000)  # huge -> ~0%
    called = {"n": 0}
    monkeypatch.setattr(llm_interface, "agent_chat",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or "x")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "call_from_thread", lambda fn, *a, **k: fn(*a, **k))
            screen._maybe_auto_compact()
            return screen.session_state["resume_context"]

    ctx = asyncio.run(_run())
    assert called["n"] == 0            # no summarization call below the threshold
    assert ctx == original             # context untouched


def test_compact_on_empty_context_is_a_noop(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch, resume_context="")
    called = {"n": 0}
    monkeypatch.setattr(llm_interface, "agent_chat",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1) or "x")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/compact")
            await pilot.pause()
            await pilot.pause()

    asyncio.run(_run())
    assert called["n"] == 0  # no LLM call when there's nothing to compact


def test_up_while_busy_stops_and_loads_last_message(tmp_path, monkeypatch):
    # ↑ during a running turn = stop + load the message you just sent, for editing.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._busy = True
            screen._last_goal = "investigate ssh brute force"
            screen.action_history_prev()
            await pilot.pause()
            return screen.query_one("#goal").value, screen._edit_seq

    value, edit_seq = asyncio.run(_run())
    assert value == "investigate ssh brute force"
    assert edit_seq is None  # re-send as a fresh turn


def test_tools_command_renders_without_error(tmp_path, monkeypatch):
    # /tools classifies the real TOOL_REGISTRY into Default/Kept/Installed and
    # writes grouped tables — smoke-check it renders (no crash, content added).
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            before = len(screen._log.lines)
            screen._dispatch_slash("/tools")
            await pilot.pause()
            return before, len(screen._log.lines)

    before, after = asyncio.run(_run())
    assert after > before  # tables were written to the transcript


def test_reset_archives_history_and_clears(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    # Give the session a real turn so /reset has something to archive.
    turn_id = store.start_turn(sid, "look for brute force")
    store.complete_turn(turn_id, "final_answer", transcript_ref=None)
    assert store.get_goal_history(sid)  # precondition: history present

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_modal):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._dispatch_slash("/reset")
            await pilot.pause()
            await pilot.pause()
            return screen.session_state["resume_context"]

    ctx = asyncio.run(_run())
    assert ctx == ""
    assert store.get_goal_history(sid) == []  # archived (soft-deleted) — not shown going forward

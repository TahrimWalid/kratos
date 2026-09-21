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

            async def _yes(_modal):  # /clear now confirms first
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._dispatch_slash("/clear")
            await pilot.pause()
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


def test_help_documents_every_primary_command():
    # P2.6 drift guard: the hand-maintained /help must document every primary
    # user-facing command. /preset-show was dispatched but undocumented (found +
    # fixed here); this fails if any of these silently falls out of help again.
    from rich.console import Console
    import io
    from textual.app import App
    from textual.widgets import Static
    from kratos.tui_mk2.modals import HelpModal

    primary = [
        "/help", "/guide", "/run", "/plan", "/report",
        "/preset-new", "/preset-describe", "/preset-run", "/preset-list",
        "/preset-show", "/preset-edit", "/preset-delete", "/preset-scaffold",
        "/preset-export", "/preset-import",
        "/schedule", "/trigger", "/doctor", "/usage", "/context",
        "/investigate-host", "/evolve", "/tools", "/use",
        "/target", "/model", "/timezone", "/settings",
        "/compact", "/clear", "/reset", "/delete", "/sessions", "/rename",
        "/exit", "/preview",
    ]

    class _H(App):
        def on_mount(self):
            self.push_screen(HelpModal())

    async def _run():
        app = _H()
        async with app.run_test() as pilot:
            await pilot.pause()
            buf = io.StringIO()
            con = Console(file=buf, width=140)
            for st in app.screen.query(Static):
                # Static stores the original renderable under the name-mangled
                # __content; render it directly (its .render() wraps it in a Visual).
                r = getattr(st, "_Static__content", None)
                if r is not None:
                    con.print(r)
            return buf.getvalue()

    text = asyncio.run(_run())
    # Help uses shorthand for adjacent commands ("/preset-export / -import"), so
    # match the distinctive stem rather than the exact literal for the -suffix ones.
    def _present(cmd: str) -> bool:
        if cmd in text:
            return True
        # e.g. "/preset-import" documented as "-import" on the -export line
        suffix = cmd.split("/preset")[-1]  # "-import"
        return cmd.startswith("/preset") and suffix in text
    missing = [c for c in primary if not _present(c)]
    assert not missing, f"/help is missing: {missing}"


def test_crashing_worker_does_not_kill_the_session(tmp_path, monkeypatch):
    # P2.1 safety net: a background worker that raises must NOT take the whole TUI
    # down (Textual's default re-raises it as fatal WorkerFailed). The mixin forces
    # every worker non-fatal and surfaces a friendly line instead. Reaching the
    # assertions at all proves the app survived -- a crash would break run_test().
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    emitted = []
    monkeypatch.setattr(screen, "_emit", lambda r: emitted.append(r))

    def _boom():
        raise RuntimeError("kaboom from a normally-fatal worker")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.run_worker(_boom, thread=True, name="test-boom")
            for _ in range(6):  # let the thread finish + the ERROR event propagate
                await pilot.pause()
            return app.is_running

    still_running = asyncio.run(_run())
    assert still_running is True                        # never crashed
    assert emitted, "a failed worker should surface a friendly transcript line"
    text = "".join(str(r) for r in emitted)
    assert "Something went wrong" in text and "session is fine" in text
    assert "kaboom" not in text                          # raw error is logged, not shown


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
    # A REAL measured fill over 85% (auto-compaction only fires on real usage now,
    # not the char estimate).
    monkeypatch.setattr(llm_interface, "get_last_token_usage",
                        lambda: llm_interface.TokenUsage(prompt_tokens=38, completion_tokens=0, total_tokens=38))
    monkeypatch.setattr(llm_interface, "get_context_window_tokens", lambda: 40)  # 38/40 -> ~95%
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


def test_compact_guarantees_result_fits_window(tmp_path, monkeypatch):
    # The screenshot bug: recent turns are large, so a plain keep-recent-verbatim
    # left the context OVER the window ("compacted" but still ~100%). Compaction
    # must now bring it actually under the window.
    big = "\n\n".join(f"You: q{i}\nKratos: " + ("Z" * 3000) for i in range(6))
    store, sid, screen = _make_screen(tmp_path, monkeypatch, resume_context=big)
    monkeypatch.setattr(llm_interface, "get_context_window_tokens", lambda: 5000)
    monkeypatch.setattr(llm_interface, "get_last_token_usage", lambda: None)
    monkeypatch.setattr(llm_interface, "agent_chat", lambda *a, **k: "SHORT SUMMARY")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "call_from_thread", lambda fn, *a, **k: fn(*a, **k))
            screen._do_compact(manual=True)
            return screen.session_state["resume_context"]

    ctx = asyncio.run(_run())
    target = int(5000 * 0.6) * 4                 # ~60% of the window in chars
    assert len(ctx) <= target                    # actually fits now
    assert (len(ctx) // 4) < 5000 * 0.85         # meter would read < 85%
    assert "SHORT SUMMARY" in ctx                # older folded into the summary


def test_chat_auto_compaction_noop_below_threshold(tmp_path, monkeypatch):
    original = "You: hi\nKratos: hello there\n"
    store, sid, screen = _make_screen(tmp_path, monkeypatch, resume_context=original)
    monkeypatch.setattr(llm_interface, "get_last_token_usage",
                        lambda: llm_interface.TokenUsage(prompt_tokens=10, completion_tokens=0, total_tokens=10))
    monkeypatch.setattr(llm_interface, "get_context_window_tokens", lambda: 1_000_000)  # real 10/1M -> ~0%
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


def test_up_recall_is_non_destructive(tmp_path, monkeypatch):
    # ↑ recalls a prior message into the prompt; sending never truncates history
    # (the old "discarded N turns" edit behavior is gone).
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    for g in ("first goal", "second goal"):
        tid = store.start_turn(sid, g)
        store.complete_turn(tid, "chat_reply", transcript_ref=None)
    archived = {"n": 0}
    monkeypatch.setattr(store, "archive_turns_from",
                        lambda *a, **k: archived.__setitem__("n", archived["n"] + 1) or 0)
    monkeypatch.setattr(screen, "_run_goal", lambda text: None)  # don't fire a real LLM call

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.action_history_prev()  # recall newest prior message
            await pilot.pause()
            recalled = screen.query_one("#goal").value
            event = type("E", (), {"value": recalled, "input": screen.query_one("#goal")})()
            screen.on_input_submitted(event)
            await pilot.pause()
            return recalled

    recalled = asyncio.run(_run())
    assert recalled == "second goal"
    assert archived["n"] == 0  # sending a recalled message never truncates history


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


def test_back_to_sessions_confirmed_pops_screen(tmp_path, monkeypatch):
    # Ctrl+B / /sessions returns to the picker on confirm; the session is KEPT
    # (never archived), so it stays resumable from the list.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            popped = []
            monkeypatch.setattr(app, "pop_screen", lambda *a, **k: popped.append(True))

            async def _yes(_modal):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._dispatch_slash("/sessions")
            await pilot.pause()
            await pilot.pause()
            return popped

    popped = asyncio.run(_run())
    assert popped == [True]                       # returned to the picker
    assert store.get_session(sid)["status"] != "archived"  # session kept, not deleted


def test_back_to_sessions_cancelled_stays(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            popped = []
            monkeypatch.setattr(app, "pop_screen", lambda *a, **k: popped.append(True))

            async def _no(_modal):
                return False

            monkeypatch.setattr(app, "push_screen_wait", _no)
            screen._dispatch_slash("/back")   # alias
            await pilot.pause()
            await pilot.pause()
            return popped

    assert asyncio.run(_run()) == []  # no pop — stayed in the session


def test_back_to_sessions_refuses_while_busy(tmp_path, monkeypatch):
    # A running turn must be stopped first; the confirm modal is never shown and
    # nothing pops (so the thread worker isn't left touching a popped screen).
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._busy = True
            popped, prompted = [], []
            monkeypatch.setattr(app, "pop_screen", lambda *a, **k: popped.append(True))

            async def _prompted(_modal):
                prompted.append(True)
                return True

            monkeypatch.setattr(app, "push_screen_wait", _prompted)
            screen._dispatch_slash("/sessions")
            await pilot.pause()
            await pilot.pause()
            return popped, prompted

    popped, prompted = asyncio.run(_run())
    assert popped == [] and prompted == []  # refused: no confirm prompt, no pop


def test_apply_target_rejects_pasted_command(tmp_path, monkeypatch):
    # A pasted command line ('kratos investigate "x"') must not become the
    # active target -- _apply_target validates and refuses, leaving it unchanged.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    monkeypatch.setattr(screen, "_setup_target_worker", lambda host: None)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._apply_target('kratos investigate "x"'.split())  # garbage
            await pilot.pause()
            unchanged = screen.session_state["targets"]
            screen._apply_target(["10.2.2.2"])  # a real change still applies
            await pilot.pause()
            return unchanged, screen.session_state["targets"]

    unchanged, changed = asyncio.run(_run())
    assert unchanged == ["10.0.0.1"]   # refused, left as-is
    assert changed == ["10.2.2.2"]     # valid input still works


def test_investigate_host_pins_loopback_and_restores(tmp_path, monkeypatch):
    # /investigate-host runs the agent against Kratos's own host (127.0.0.1) and
    # restores the configured target afterwards.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from kratos import kratos_config as kc

    seen = {}

    def _fake_run_agent(goal, data_dir, **kw):
        seen["target"] = kc.get_active_target()
        return {"status": "final_answer", "final_answer": "ok", "transcript": [], "recommended_commands": []}

    monkeypatch.setattr("kratos.agent.loop.run_agent", _fake_run_agent)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            kc.set_active_target("10.0.0.1")  # known baseline
            screen._dispatch_slash("/investigate-host")
            for _ in range(200):
                await pilot.pause()
                if "target" in seen and not screen._busy:
                    break
            return seen.get("target"), kc.get_active_target()

    seen_target, after = asyncio.run(_run())
    assert seen_target == "127.0.0.1"  # the run saw loopback (Kratos's own host)
    assert after == "10.0.0.1"         # configured target restored afterwards


def _clarify_host_calls(tmp_path, monkeypatch, answer):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    calls = {"host": 0, "target": 0}
    monkeypatch.setattr(screen, "_run_host_investigation", lambda g: calls.__setitem__("host", calls["host"] + 1))
    monkeypatch.setattr(screen, "_run_target_investigation", lambda g: calls.__setitem__("target", calls["target"] + 1))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _ans(_modal):
                return answer

            monkeypatch.setattr(app, "push_screen_wait", _ans)
            screen._clarify_host_flow("check port 3000")
            await pilot.pause()
            await pilot.pause()
            return calls

    return asyncio.run(_run())


def test_clarify_host_flow_routes_to_host(tmp_path, monkeypatch):
    assert _clarify_host_calls(tmp_path, monkeypatch, "host") == {"host": 1, "target": 0}


def test_clarify_host_flow_routes_to_target(tmp_path, monkeypatch):
    assert _clarify_host_calls(tmp_path, monkeypatch, "target") == {"host": 0, "target": 1}


def test_clarify_host_flow_dismissed_does_nothing(tmp_path, monkeypatch):
    assert _clarify_host_calls(tmp_path, monkeypatch, None) == {"host": 0, "target": 0}


def test_apply_target_checked_word_salad_first(tmp_path, monkeypatch):
    # A phrase typed at the target field triggers a clarify; 'first' uses only
    # the first token as the host.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    applied: list[list[str]] = []
    monkeypatch.setattr(screen, "_apply_target", lambda t: applied.append(list(t)))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _ans(_modal):
                return "first"

            monkeypatch.setattr(app, "push_screen_wait", _ans)
            await screen._apply_target_checked(["look", "for", "intrusions"], raw="look for intrusions")
            return applied

    assert asyncio.run(_run()) == [["look"]]


def test_apply_target_checked_word_salad_cancel(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    applied: list[list[str]] = []
    monkeypatch.setattr(screen, "_apply_target", lambda t: applied.append(list(t)))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _ans(_modal):
                return None  # dismissed

            monkeypatch.setattr(app, "push_screen_wait", _ans)
            await screen._apply_target_checked(["look", "for", "intrusions"], raw="look for intrusions")
            return applied

    assert asyncio.run(_run()) == []  # nothing applied — user retypes


def test_apply_target_checked_normal_input_skips_clarify(tmp_path, monkeypatch):
    # Ordinary host input applies directly, with no clarify modal shown.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    applied: list[list[str]] = []
    shown: list[bool] = []
    monkeypatch.setattr(screen, "_apply_target", lambda t: applied.append(list(t)))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _ans(_modal):
                shown.append(True)
                return "first"

            monkeypatch.setattr(app, "push_screen_wait", _ans)
            await screen._apply_target_checked(["10.0.0.5", "10.0.0.6"], raw="10.0.0.5 10.0.0.6")
            return applied, shown

    applied, shown = asyncio.run(_run())
    assert applied == [["10.0.0.5", "10.0.0.6"]] and shown == []  # no clarify prompt


def test_target_flow_kratos_host_option_sets_loopback(tmp_path, monkeypatch):
    # Picking [Kratos-Host] in the no-arg /target picker makes the session
    # target the local machine (loopback).
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    monkeypatch.setattr(screen, "_setup_target_worker", lambda host: None)
    from kratos.tui_mk2.target_input import KRATOS_HOST_SENTINEL, KRATOS_HOST_VALUE

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _ans(_modal):
                return KRATOS_HOST_SENTINEL

            monkeypatch.setattr(app, "push_screen_wait", _ans)
            screen._target_flow("")  # no arg -> picker
            await pilot.pause()
            await pilot.pause()
            return screen.session_state["targets"]

    assert asyncio.run(_run()) == [KRATOS_HOST_VALUE]


def test_apply_target_expands_typed_kratos_host_alias(tmp_path, monkeypatch):
    # `/target kratos-host` resolves to loopback rather than an unresolvable
    # literal hostname.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    monkeypatch.setattr(screen, "_setup_target_worker", lambda host: None)
    from kratos.tui_mk2.target_input import KRATOS_HOST_VALUE

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._apply_target(["kratos-host"])
            await pilot.pause()
            return screen.session_state["targets"]

    assert asyncio.run(_run()) == [KRATOS_HOST_VALUE]


def test_activity_spinner_shows_while_busy_and_clears(tmp_path, monkeypatch):
    # While a turn runs, an animated "working…" line shows; it clears when idle.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from textual.widgets import Static

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            act = screen.query_one("#activity", Static)
            screen._set_busy(True)
            screen._tick_activity()
            busy_text = str(act.render())
            screen._set_busy(False)
            screen._tick_activity()
            idle_text = str(act.render())
            return busy_text, idle_text

    busy_text, idle_text = asyncio.run(_run())
    assert "hacking" in busy_text and any(f in busy_text for f in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    assert idle_text.strip() == ""


def test_usage_renders_tokens_and_cost(tmp_path, monkeypatch):
    # /usage shows cumulative session tokens; cloud model with a known rate
    # shows an estimated cost, local shows "free".
    from kratos import llm_interface

    llm_interface._session_usage = llm_interface.TokenUsage(
        prompt_tokens=100_000, completion_tokens=20_000, total_tokens=120_000)

    def _once(model, base):
        monkeypatch.setattr("kratos.llm_config.get_active_llm_model", lambda: model)
        monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url", lambda: base)
        _store, _sid, screen = _make_screen(tmp_path, monkeypatch)  # fresh screen per loop

        async def _run():
            app = _Host(screen)
            async with app.run_test() as pilot:
                await pilot.pause()
                log = screen.query_one("#transcript")
                before = len(log.lines)
                screen._dispatch_slash("/usage")
                await pilot.pause()
                return len(log.lines) - before

        return asyncio.run(_run())

    assert _once("gemini-3.1-pro-preview", "https://api.gemini/v1") > 0   # cloud: cost estimated
    assert _once("qwen2.5:7b", "http://127.0.0.1:11434/v1") > 0          # local: free


def test_context_renders_window_breakdown(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch, resume_context="x" * 4000)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = screen.query_one("#transcript")
            before = len(log.lines)
            screen._dispatch_slash("/context")
            await pilot.pause()
            return len(log.lines) - before

    assert asyncio.run(_run()) > 0  # the context table + note rendered


def test_doctor_runs_and_renders(tmp_path, monkeypatch):
    # /doctor runs run_diagnostics off the event loop and writes a result table
    # to the transcript (run_diagnostics mocked so the test stays offline).
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from kratos.agent import doctor

    called = {"n": 0}

    def _fake_diag():
        called["n"] += 1
        return [
            {"check": "LLM endpoint", "status": "pass", "detail": "reachable"},
            {"check": "target setup", "status": "fail", "detail": "sshd unreachable"},
        ]

    monkeypatch.setattr(doctor, "run_diagnostics", _fake_diag)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = screen.query_one("#transcript")
            before = len(log.lines)
            screen._dispatch_slash("/doctor")
            for _ in range(200):
                await pilot.pause()
                if called["n"] and not screen._busy:
                    break
            return called["n"], len(log.lines) - before

    ran, wrote = asyncio.run(_run())
    assert ran == 1        # diagnostics ran once
    assert wrote > 0       # the table + summary were rendered


def test_bare_evolve_opens_idea_box(tmp_path, monkeypatch):
    # Bare /evolve (no inline idea, no pending suggestion) must OPEN the idea
    # prompt, not just print a note — the reported "evolve isn't wired" bug.
    # The guided flow (A7) runs on a thread worker and drives modals through
    # app.push_screen (+ a callback), NOT push_screen_wait, so the test
    # intercepts push_screen and dismisses the modal (callback(None)) to let the
    # worker unblock and the flow end cleanly.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    prompted = {"titles": []}

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            def _capture(modal, callback=None, *a, **k):
                prompted["titles"].append(getattr(modal, "_title", ""))
                if callback is not None:
                    callback(None)   # cancel so the guided flow stops

            monkeypatch.setattr(app, "push_screen", _capture)
            screen._dispatch_slash("/evolve")   # bare, no idea
            for _ in range(12):                 # let the thread worker reach the prompt
                await pilot.pause()
            return prompted["titles"]

    titles = asyncio.run(_run())
    assert titles and any("what should it do" in t.lower() for t in titles)  # idea box opened


def test_tool_command_runs_named_tool_deterministically(tmp_path, monkeypatch):
    # /tool <name> runs EXACTLY that tool via execute_tool_call (no LLM),
    # passing parsed JSON args, and renders the result.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from kratos.agent import loop as agent_loop

    seen = {}

    def _fake_exec(name, args, data_dir):
        seen["name"] = name
        seen["args"] = args
        return {"status": "ok", "result": {"ran": name, "echo": args}}

    monkeypatch.setattr(agent_loop, "execute_tool_call", _fake_exec)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash('/use run_nmap_scan {"target": "10.9.9.9"}')
            for _ in range(200):
                await pilot.pause()
                if "name" in seen and not screen._busy:
                    break
            return seen

    got = asyncio.run(_run())
    assert got["name"] == "run_nmap_scan"          # the exact named tool
    assert got["args"] == {"target": "10.9.9.9"}   # JSON args parsed + passed


def test_tool_command_unknown_tool_errors_without_running(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from kratos.agent import loop as agent_loop

    called = {"n": 0}
    monkeypatch.setattr(agent_loop, "execute_tool_call",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/use no_such_tool_xyz")
            await pilot.pause()
            await pilot.pause()
            return called["n"]

    assert asyncio.run(_run()) == 0  # rejected before any dispatch


def test_bare_tool_opens_picker_then_runs_selection(tmp_path, monkeypatch):
    # Bare /tool opens the searchable picker; the picked tool is then run.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from kratos.agent import loop as agent_loop
    from kratos.tui_mk2.modals import ToolPickerModal

    ran = {}

    def _fake_exec(name, args, data_dir):
        ran["name"] = name
        return {"status": "ok", "result": {"ok": True}}

    monkeypatch.setattr(agent_loop, "execute_tool_call", _fake_exec)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            opened = {}

            async def _pick(modal):
                opened["is_picker"] = isinstance(modal, ToolPickerModal)
                return "run_nmap_scan"  # user selects a tool

            monkeypatch.setattr(app, "push_screen_wait", _pick)
            screen._dispatch_slash("/use")  # bare -> picker
            for _ in range(200):
                await pilot.pause()
                if "name" in ran:
                    break
            return opened.get("is_picker"), ran.get("name")

    is_picker, name = asyncio.run(_run())
    assert is_picker is True          # a ToolPickerModal was opened
    assert name == "run_nmap_scan"    # and the selection was run


def test_tool_command_missing_required_arg_shows_usage_not_dispatch(tmp_path, monkeypatch):
    # A tool with a required arg the user didn't pass shows its parameters as
    # usage, WITHOUT dispatching into a cryptic "missing argument" error.
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    from kratos.agent import loop as agent_loop
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos.agent.self_write_loop import load_kept_tools

    load_kept_tools()
    if "count_failed_sudo_attempts" not in TOOL_REGISTRY:
        import pytest
        pytest.skip("kept tool not present in this environment")

    called = {"n": 0}
    monkeypatch.setattr(agent_loop, "execute_tool_call",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            log = screen.query_one("#transcript")
            before = len(log.lines)
            screen._dispatch_slash("/use count_failed_sudo_attempts")  # required arg omitted
            await pilot.pause()
            await pilot.pause()
            return called["n"], len(log.lines) - before

    dispatched, wrote = asyncio.run(_run())
    assert dispatched == 0   # usage shown, NOT dispatched
    assert wrote > 0         # the usage panel was rendered


def test_question_mark_on_empty_prompt_opens_help(tmp_path, monkeypatch):
    # Typing a lone "?" on the empty prompt opens help (and clears the input).
    from textual.widgets import Input
    from kratos.tui_mk2.modals import HelpModal
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen.query_one("#goal", Input).value = "?"   # fires Input.Changed
            await pilot.pause()
            return isinstance(app.screen, HelpModal), screen.query_one("#goal", Input).value

    opened_help, input_after = asyncio.run(_run())
    assert opened_help is True   # help opened
    assert input_after == ""     # the "?" was consumed, not left in the box


def test_dispatch_guard_survives_a_crashing_command(tmp_path, monkeypatch):
    """P2.1 robustness: a bug in ANY command handler must not crash the session.
    The guarded _dispatch_slash catches it, shows a friendly line, and lives."""
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    emitted = []
    monkeypatch.setattr(screen, "_emit", lambda r: emitted.append(r))
    monkeypatch.setattr(screen, "_set_busy", lambda *_a: None)
    monkeypatch.setattr(screen, "_dispatch_slash_impl",
                        lambda _t: (_ for _ in ()).throw(RuntimeError("kaboom")))
    screen._dispatch_slash("/anything")   # must NOT raise
    assert emitted, "a friendly error line should have been shown"
    text = " ".join(str(getattr(r, "plain", r)) for r in emitted)
    assert "unexpected error" in text and "session is fine" in text

"""A worker thread waiting on a TUI question must end when the app stops.

Textual can't cancel a thread worker, and the approval / clarify / budget /
guided-build bridges block that thread until the modal answers. If Kratos quit
with a question still open (or before it appeared) the old unbounded wait kept
the thread -- and so the whole process -- alive forever at exit. The wait now
gives up once the app has stopped, and the caller keeps its safe answer.
"""
from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

from textual.app import App

from kratos.tui_mk2 import approvals as A
from kratos.tui_mk2.guided import TextualGuidedPrompter


def _ask_then_quit(ask) -> dict:
    """Run `ask(app)` on a daemon thread while the app is up, quit the app with the
    question unanswered, and report whether the thread ended and what it returned."""
    out: dict = {}

    class Host(App):
        pass

    async def run() -> None:
        app = Host()
        async with app.run_test() as pilot:
            t = threading.Thread(target=lambda: out.__setitem__("answer", ask(app)), daemon=True)
            out["thread"] = t
            t.start()
            for _ in range(50):             # until the question is on screen
                await pilot.pause(0.02)
                if len(app.screen_stack) > 1:
                    break
            out["shown"] = len(app.screen_stack) > 1
        # the app has exited here, the question never answered

    asyncio.run(run())
    out["thread"].join(timeout=5)
    out["ended"] = not out["thread"].is_alive()
    return out


def test_an_open_approval_is_denied_when_the_app_quits():
    r = _ask_then_quit(lambda app: A.make_textual_approval_provider(app)("run_linux_command", {"command": "id"}))
    assert r["shown"] and r["ended"] and r["answer"] is False


def test_an_open_clarify_question_has_no_answer_when_the_app_quits():
    r = _ask_then_quit(lambda app: A.make_textual_clarify_provider(app)("which machine?", [{"label": "a"}]))
    assert r["shown"] and r["ended"] and r["answer"] is None


def test_an_open_budget_question_is_no_when_the_app_quits():
    q = SimpleNamespace(text="this run would pass the daily limit -> $1.00")
    r = _ask_then_quit(lambda app: A.make_textual_budget_provider(app)(q))
    assert r["shown"] and r["ended"] and r["answer"] is False


def test_an_open_guided_build_question_is_cancelled_when_the_app_quits():
    screen = SimpleNamespace(_emit_from_worker=lambda _r: None)
    r = _ask_then_quit(lambda app: TextualGuidedPrompter(app, screen).ask_text("Tool idea?"))
    assert r["shown"] and r["ended"] and r["answer"] is None


def test_an_answer_still_wins_while_the_app_runs():
    done = threading.Event()
    done.set()
    assert A.wait_for_answer(SimpleNamespace(is_running=True), done, poll=0.01) is True
    late = threading.Event()
    threading.Timer(0.05, late.set).start()
    assert A.wait_for_answer(SimpleNamespace(is_running=True), late, poll=0.01) is True
    assert A.wait_for_answer(SimpleNamespace(is_running=False), threading.Event(), poll=0.01) is False

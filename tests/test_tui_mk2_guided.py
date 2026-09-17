"""
Real Textual pilots for the A7 guided-build bridge (tui_mk2/guided.py).

The guided build runs on a thread worker, so TextualGuidedPrompter bridges each
question thread -> modal -> thread via app.call_from_thread + a threading.Event
(the same proven pattern as approvals.py). These tests drive that REAL bridge:
run an ask_* method in an executor thread, let the real modal mount, answer it
with real key presses, and assert the value that comes back across the bridge.
That is the novel code in this file's scope; the guided FLOW itself is covered
headlessly in test_guided_evolve.py.
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.tui_mk2.guided import TextualGuidedPrompter
from kratos.tui_mk2 import render as R


class _Host(App):
    def on_mount(self):
        # A minimal screen with an _emit_from_worker sink for say()/show().
        self.emitted = []

    def _emit_from_worker(self, renderable):
        # stand-in for the SessionScreen helper the prompter writes through
        self.call_from_thread(self.emitted.append, renderable)


class _Screen:
    """Minimal screen stub exposing _emit_from_worker, recording renderables."""
    def __init__(self, app):
        self._app = app
        self.emitted = []

    def _emit_from_worker(self, renderable):
        self._app.call_from_thread(self.emitted.append, renderable)


def _drive(answer_keys, method_name, *args, **kwargs):
    """Boot a headless app, run prompter.<method_name>(*args) in a thread, feed
    the given key presses to the real modal, and return the bridged result."""
    holder = {}

    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = _Screen(app)
            prompter = TextualGuidedPrompter(app, screen)
            method = getattr(prompter, method_name)
            fut = asyncio.get_event_loop().run_in_executor(None, lambda: method(*args, **kwargs))
            # let the worker schedule + mount the modal
            for _ in range(3):
                await pilot.pause()
            for key in answer_keys:
                await pilot.press(key)
                await pilot.pause()
            holder["result"] = await fut
            holder["emitted"] = screen.emitted
        return holder

    return asyncio.run(_run())


def test_ask_confirm_yes():
    out = _drive(["y"], "ask_confirm", "Keep it?", "body text")
    assert out["result"] is True


def test_ask_confirm_no_is_failsafe():
    out = _drive(["n"], "ask_confirm", "Keep it?", "body")
    assert out["result"] is False


def test_ask_confirm_escape_denies():
    out = _drive(["escape"], "ask_confirm", "Keep it?", "body")
    assert out["result"] is False


def test_ask_text_typed_then_enter():
    out = _drive(list("hello") + ["enter"], "ask_text", "Name it", "hint", "")
    assert out["result"] == "hello"


def test_ask_text_default_on_empty_enter():
    # Empty submit returns '' (caller treats '' as 'use the default').
    out = _drive(["enter"], "ask_text", "Name it", "hint", "seed_default")
    # PromptModal seeds the input with `initial`, so Enter submits that value.
    assert out["result"] == "seed_default"


def test_ask_text_escape_cancels():
    out = _drive(["escape"], "ask_text", "Name it", "hint", "x")
    assert out["result"] is None


def test_ask_choice_enter_picks_first():
    out = _drive(["enter"], "ask_choice", "Pick", [("build", "Build it"), ("edit", "Edit")], "sub")
    assert out["result"] == "build"


def test_ask_choice_escape_cancels():
    out = _drive(["escape"], "ask_choice", "Pick", [("a", "A"), ("b", "B")])
    assert out["result"] is None


def test_say_and_show_emit_into_transcript():
    async def _run():
        app = App()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = _Screen(app)
            prompter = TextualGuidedPrompter(app, screen)
            # run from a thread (that's where the real prompter runs)
            def _work():
                prompter.say("hi there", "success")
                prompter.show("a plain panel")
            await asyncio.get_event_loop().run_in_executor(None, _work)
            for _ in range(3):
                await pilot.pause()
            return list(screen.emitted)

    emitted = asyncio.run(_run())
    assert len(emitted) == 2

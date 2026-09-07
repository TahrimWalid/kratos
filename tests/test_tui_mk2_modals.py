"""
ClarifyModal (tui_mk2/modals.py) — Kratos's ask-with-choices prompt.

The return-mapping (value-over-label, recommended default) is pure and tested
directly; one headless pilot confirms Enter on the list returns the highlighted
option's value and esc returns None.
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.tui_mk2.modals import ClarifyModal, PromptModal

_OPTS = [
    {"value": "target", "label": "The monitored target", "explanation": "watched system"},
    {"value": "host", "label": "This Kratos host", "recommended": True},
]


def test_recommended_index_and_value_mapping():
    m = ClarifyModal("q?", _OPTS)
    assert m._recommended_index() == 1               # the recommended option
    assert m._value_for(0) == "target"               # value used when present
    assert m._value_for(1) == "host"


def test_value_falls_back_to_label_without_value():
    m = ClarifyModal("q?", [{"label": "Just a label"}])
    assert m._recommended_index() == 0               # none recommended -> first
    assert m._value_for(0) == "Just a label"         # no value -> label is the answer


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen
        self.result = "unset"

    def on_mount(self):
        self.push_screen(self._screen, lambda r: setattr(self, "result", r))


def test_enter_returns_recommended_value():
    async def _run():
        app = _Host(ClarifyModal("Which host?", _OPTS))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")   # list is focused on the recommended row
            await pilot.pause()
            return app.result

    assert asyncio.run(_run()) == "host"  # recommended option's value


def test_escape_returns_none():
    async def _run():
        app = _Host(ClarifyModal("Which host?", _OPTS))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("escape")
            await pilot.pause()
            return app.result

    assert asyncio.run(_run()) is None


def test_prompt_modal_quick_option_button_returns_value():
    # The target prompt keeps its text input, plus a quick [Kratos-Host] button:
    # Tab to it, Enter -> dismiss with the quick value (not the typed text).
    async def _run():
        app = _Host(PromptModal("Set target", "type a host", initial="10.0.0.1",
                                quick_value="__kratos_host__", quick_label="[Kratos-Host]"))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("tab")     # input -> button
            await pilot.press("enter")   # press the button
            await pilot.pause()
            return app.result

    assert asyncio.run(_run()) == "__kratos_host__"


def test_prompt_modal_typed_input_still_returned():
    async def _run():
        app = _Host(PromptModal("Set target", "type a host", initial="10.9.9.9",
                                quick_value="__kratos_host__", quick_label="[Kratos-Host]"))
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("enter")   # submit the pre-filled input
            await pilot.pause()
            return app.result

    assert asyncio.run(_run()) == "10.9.9.9"

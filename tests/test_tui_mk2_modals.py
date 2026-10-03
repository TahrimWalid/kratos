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


def test_confirm_modal_any_key_is_no_but_y_confirms():
    # Fail-safe: only 'y' confirms; n / esc / any other key cancels.
    from kratos.tui_mk2.modals import ConfirmModal

    class _CH(App):
        def on_mount(self):
            self.result = "unset"
            self.push_screen(ConfirmModal("T", "body"), lambda r: setattr(self, "result", r))

    def _press(key):
        async def _run():
            app = _CH()
            async with app.run_test() as pilot:
                await pilot.pause()
                await pilot.press(key)
                await pilot.pause()
                return app.result
        return asyncio.run(_run())

    assert _press("y") is True
    for k in ("n", "escape", "a", "space", "z"):
        assert _press(k) is False, f"{k} should cancel"


def test_command_palette_prefers_exact_match():
    # Typing "/tool" + Enter must run /tool, not the first substring match /tools.
    from kratos.tui_mk2.modals import CommandPaletteModal
    cmds = [("/tools", "list"), ("/tool", "run one"), ("/target", "t")]

    def _type_and_enter(text):
        class _H(App):
            def on_mount(self):
                self.result = "unset"
                self.push_screen(CommandPaletteModal(cmds), lambda r: setattr(self, "result", r))

        async def _run():
            app = _H()
            async with app.run_test() as pilot:
                await pilot.pause()
                for ch in text:
                    await pilot.press("slash" if ch == "/" else ch)
                await pilot.pause()
                await pilot.press("enter")
                await pilot.pause()
                return app.result
        return asyncio.run(_run())

    assert _type_and_enter("/tool") == "/tool"      # exact wins over /tools
    assert _type_and_enter("/tools") == "/tools"
    assert _type_and_enter("/tar") == "/target"     # substring fallback still works
    # The palette opens holding "/": typing after it must keep it, so a command
    # with arguments stays a command (it used to arrive as "rename x", for the model).
    assert _type_and_enter("rename x") == "/rename x"
    assert _type_and_enter("/rename x") == "/rename x"
    assert _type_and_enter("nonsense") == "/nonsense"   # handed on, to be reported as unknown


def test_prefilled_prompt_text_is_edited_not_replaced():
    """Textual selects an Input's text on focus by default, so the first key
    pressed in a prompt pre-filled with an existing value erased it."""
    from kratos.tui_mk2.modals import PromptModal

    class _H(App):
        def on_mount(self):
            self.result = "unset"
            self.push_screen(PromptModal("Edit", "Goal", initial="check ssh"),
                             lambda r: setattr(self, "result", r))

    async def _run():
        app = _H()
        async with app.run_test() as pilot:
            await pilot.pause()
            for ch in " now":
                await pilot.press("space" if ch == " " else ch)
            await pilot.press("enter")
            await pilot.pause()
            return app.result
    assert asyncio.run(_run()) == "check ssh now"


def test_multiselect_shows_ticked_and_unticked_by_shape_not_only_colour():
    """Ticked vs unticked used to differ only by colour (the same X either way):
    unreadable for colour-blind users, in grayscale or on low-contrast themes."""
    import asyncio

    from textual.app import App

    from kratos.tui_mk2.modals import MultiSelectModal

    out: dict = {}

    class _H(App):
        def on_mount(self):
            self.push_screen(MultiSelectModal("pick", [("fail2ban", "fail2ban"), ("ufw", "ufw")],
                                              selected=["fail2ban"]))

    def painted(app) -> str:
        from kratos.tui_mk2.modals import CheckboxSelectionList

        lst = app.screen.query_one(CheckboxSelectionList)
        return "\n".join(lst.render_line(i).text for i in range(lst.option_count))

    async def run():
        app = _H()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            out["before"] = painted(app)
            await pilot.press("down", "space")  # tick ufw
            await pilot.pause()
            out["after"] = painted(app)

    asyncio.run(run())
    assert "[x] fail2ban" in out["before"] and "[ ] ufw" in out["before"]
    assert "[x] ufw" in out["after"]
    assert "▐X▌" not in out["before"]


def test_picker_description_is_separated_from_its_options():
    import asyncio

    from textual.app import App
    from textual.widgets import ListView

    from kratos.tui_mk2.modals import ListPickerModal

    out: dict = {}

    class _H(App):
        def on_mount(self):
            self.push_screen(ListPickerModal("How?", [("a", "one"), ("b", "two")], subtitle="Some context."))

    async def run():
        app = _H()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            sub = app.screen.query_one(".picker-subtitle")
            out["gap"] = app.screen.query_one(ListView).region.y - (sub.region.y + sub.region.height)

    asyncio.run(run())
    assert out["gap"] == 1

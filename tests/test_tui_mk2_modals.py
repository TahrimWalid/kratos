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


def test_first_run_welcome_says_what_kratos_does_and_where_data_goes(tmp_path, monkeypatch):
    """The first-run prompt asked "Do you trust the files in this folder?", which
    no longer applies (Kratos doesn't work on the folder it's started in)."""
    from kratos.tui_mk2.app import KratosTUI

    app = KratosTUI(tmp_path)
    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url", lambda: "https://api.provider.example/v1")
    hosted = app._first_run_text().plain
    assert "doesn't change them" in hosted and "api.provider.example" in hosted and "sent to" in hosted
    assert str(tmp_path.resolve()) in hosted and "trust the files" not in hosted
    monkeypatch.setattr("kratos.llm_config.get_active_llm_base_url", lambda: "http://127.0.0.1:11434/v1")
    assert "nothing leaves your hardware" in app._first_run_text().plain


def test_confirm_modal_can_name_its_keys():
    from kratos.tui_mk2.modals import ConfirmModal

    class _H(App):
        def on_mount(self):
            self.push_screen(ConfirmModal("Welcome", "body", yes_label="continue", no_label="quit"))

    async def _run():
        app = _H()
        async with app.run_test() as pilot:
            await pilot.pause()
            return app.export_screenshot()
    svg = asyncio.run(_run())
    assert "continue" in svg and "quit" in svg


def _first_run(tmp_path, monkeypatch, target_keys):
    import asyncio

    from kratos import kratos_config as kc
    from kratos.tui_mk2.app import KratosTUI

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    prev = kc.get_active_target()

    async def _run():
        app = KratosTUI(tmp_path)
        async with app.run_test(size=(110, 34)) as pilot:
            await pilot.pause(0.5)
            await pilot.press("y")                      # welcome: continue
            await pilot.pause(0.5)
            for k in target_keys:
                await pilot.press(k)
            await pilot.press("enter")
            for _ in range(20):
                await pilot.pause(0.1)
            return type(app.screen).__name__, [type(s).__name__ for s in app.screen_stack]

    try:
        return asyncio.run(_run())
    finally:
        kc.set_active_target(prev)


def test_first_run_with_a_machine_opens_a_session_on_it(tmp_path, monkeypatch):
    """First run used to end on an EMPTY session list right after connecting a machine,
    asking for the target again. It now opens a session on it (the list stays under it)."""
    from kratos.storage.session_store import SessionStore

    screen, stack = _first_run(tmp_path, monkeypatch, list("127.0.0.1"))
    assert screen == "SessionScreen" and "LaunchScreen" in stack
    sessions = SessionStore(tmp_path / "kratos.db").list_recent_sessions(limit=5)
    assert [s["targets"] for s in sessions] == [["127.0.0.1"]]


def test_first_run_without_a_machine_lands_on_the_session_list(tmp_path, monkeypatch):
    screen, _stack = _first_run(tmp_path, monkeypatch, [])
    assert screen == "LaunchScreen"

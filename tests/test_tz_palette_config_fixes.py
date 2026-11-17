"""Three bugs found by the owner using the app (2026-11-17):

1. Settings -> Display timezone refused "Helsinki" (only "Europe/Helsinki" worked), and the only
   sign was one status line at the bottom, so the zone looked stuck at Etc/UTC.
2. The local config file (`kratos_local_config.json`) was rewritten by several Kratos processes
   with a plain read-modify-write: a reader could see a half-written file (read as {}, wiping
   every setting) and two writers could drop each other's change.
3. The command palette's highlighted row painted the command name in the accent colour on the
   accent-coloured highlight bar, so the selected command's name vanished.
"""
from __future__ import annotations

import asyncio
import json
import multiprocessing as mp

import pytest
from textual.app import App

from kratos import kratos_config as KC
from kratos.utils import timeutil


# ---------------------------------------------------------------- 1. timezone names
@pytest.mark.parametrize("typed,zone", [
    ("Helsinki", "Europe/Helsinki"), ("helsinki", "Europe/Helsinki"), ("  HELSINKI ", "Europe/Helsinki"),
    ("Europe/Helsinki", "Europe/Helsinki"), ("europe/helsinki", "Europe/Helsinki"),
    ("new york", "America/New_York"), ("Dhaka", "Asia/Dhaka"), ("UTC", "UTC"),
])
def test_a_city_or_a_zone_in_any_case_resolves(typed, zone):
    assert timeutil.resolve_zone_text(typed) == (zone, [])


def test_an_ambiguous_city_offers_choices_and_nonsense_offers_none():
    zone, choices = timeutil.resolve_zone_text("Istanbul")
    assert zone is None and "Europe/Istanbul" in choices
    assert timeutil.resolve_zone_text("Atlantis") == (None, [])
    assert timeutil.resolve_zone_text("") == (None, [])


def test_settings_accepts_helsinki_and_saves_the_real_zone(tmp_path):
    from kratos.tui_mk2.screens.settings import SettingsScreen

    class Host(App):
        def on_mount(self):
            self.push_screen(SettingsScreen(session=None, data_dir=tmp_path, initial_tab="tab-general"))

    async def go():
        app = Host()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            screen = app.screen

            async def answer(_modal):
                return "Helsinki"

            app.push_screen_wait = answer
            gen = screen.query_one("#gen-table")
            gen.move_cursor(row=next(i for i in range(gen.row_count) if "timezone" in str(gen.get_row_at(i)[0]).lower()))
            screen._general_primary()
            for _ in range(10):
                await pilot.pause()
    asyncio.run(go())
    assert timeutil.display_tz_status(tmp_path)[0] == "override"
    assert getattr(timeutil.resolve_display_tz(tmp_path), "key", None) == "Europe/Helsinki"


# ---------------------------------------------------------------- 2. config writes
def _writer(data_dir: str, key: str, n: int) -> None:
    from pathlib import Path

    from kratos import kratos_config as kc

    for i in range(n):
        kc.save_local_config(Path(data_dir), **{key: i})


def test_two_processes_writing_the_config_never_drop_each_others_keys(tmp_path):
    KC.save_local_config(tmp_path, trusted=True, display_timezone="Europe/Helsinki")
    ctx = mp.get_context("fork")
    procs = [ctx.Process(target=_writer, args=(str(tmp_path), f"k{j}", 150)) for j in range(3)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    config = json.loads((tmp_path / "kratos_local_config.json").read_text())
    assert config["trusted"] is True and config["display_timezone"] == "Europe/Helsinki"
    assert {config["k0"], config["k1"], config["k2"]} == {149}


def test_clearing_the_timezone_keeps_every_other_key_and_the_file_is_private(tmp_path):
    KC.save_local_config(tmp_path, trusted=True)
    timeutil.set_display_timezone_override(tmp_path, "Europe/Helsinki")
    timeutil.set_display_timezone_override(tmp_path, None)
    config = KC.load_local_config(tmp_path)
    assert config == {"trusted": True}
    assert (tmp_path / "kratos_local_config.json").stat().st_mode & 0o077 == 0


# ---------------------------------------------------------------- 3. palette highlight
def test_the_highlighted_palette_row_does_not_paint_its_name_in_the_accent_colour():
    from kratos.tui_mk2 import theme as T
    from kratos.tui_mk2.modals import CommandPaletteModal

    class Host(App):
        def on_mount(self):
            self.push_screen(CommandPaletteModal([("/run", "standard audit"), ("/plan", "preview"),
                                                  ("/preset-new", "save a preset")]))

    async def go():
        app = Host()
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            await pilot.press("down")
            await pilot.press("down")
            await pilot.pause()
            lst = app.screen.query_one("#palette-list")
            assert lst.index == 2
            spans = {}
            for i, item in enumerate(lst.children):
                text = item.query_one("Label")._Static__content     # the Text the modal set
                spans[i] = [str(s.style) for s in text.spans]
            assert not any(T.ACCENT in s for s in spans[2])          # selected: the bar's own colours
            assert any(T.ACCENT in s for s in spans[0])              # the others keep the accent name
    asyncio.run(go())

"""
Theme-pack resolution + live-switch backend (theme.py).

set_active_pack re-binds the identity globals and persists a user-level choice;
active_pack_name resolves env > pref file > red default. The pref file and the
mutable globals are isolated/restored so these tests never touch the real
~/.config or leak palette state into other tests.
"""
from __future__ import annotations

import os

import pytest

from kratos.tui_mk2 import theme as T


@pytest.fixture
def isolated_theme(monkeypatch, tmp_path):
    pref = tmp_path / "mk2_theme"
    monkeypatch.setattr(T, "_pref_path", lambda: pref)
    env_snap = os.environ.get("KRATOS_THEME")
    os.environ.pop("KRATOS_THEME", None)
    palette_snap = (T.ACCENT, T.KRATOS_RED, T.ADMIN)
    try:
        yield pref
    finally:
        T.ACCENT, T.KRATOS_RED, T.ADMIN = palette_snap
        if env_snap is None:
            os.environ.pop("KRATOS_THEME", None)
        else:
            os.environ["KRATOS_THEME"] = env_snap


def test_set_active_pack_mutates_globals_and_persists(isolated_theme):
    pref = isolated_theme
    assert T.set_active_pack("kratos-blue") is True
    assert T.ACCENT == "#7fa8bf"        # blue chrome now
    assert T.CRITICAL == "#ff3b3b"      # danger red never changes
    assert pref.read_text().strip() == "kratos-blue"
    assert os.environ["KRATOS_THEME"] == "kratos-blue"


def test_set_active_pack_rejects_unknown(isolated_theme):
    assert T.set_active_pack("nope") is False


def test_active_pack_name_env_beats_pref(isolated_theme, monkeypatch):
    isolated_theme.write_text("kratos-blue\n")
    monkeypatch.setenv("KRATOS_THEME", "kratos-red")
    assert T.active_pack_name() == "kratos-red"


def test_active_pack_name_reads_pref_when_no_env(isolated_theme):
    isolated_theme.write_text("kratos-blue\n")
    assert T.active_pack_name() == "kratos-blue"


def test_active_pack_name_defaults_to_red(isolated_theme):
    assert T.active_pack_name() == "kratos-red"


def test_unknown_pref_value_falls_through_to_default(isolated_theme):
    isolated_theme.write_text("garbage\n")
    assert T.active_pack_name() == "kratos-red"


def test_app_apply_theme_pack_live_switch(isolated_theme, tmp_path):
    # End-to-end on the real KratosTUI: boot (pre-trusted so no wizard), then
    # flip packs -- the Textual theme name changes and the palette globals
    # re-bind, all without touching the real ~/.config (pref path isolated).
    import asyncio

    from kratos import kratos_config as kc
    from kratos.tui_mk2.app import KratosTUI

    kc.save_local_config(tmp_path, trusted=True)

    async def _run():
        app = KratosTUI(tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.pause()
            before = app.theme
            ok = app.apply_theme_pack("kratos-blue")
            await pilot.pause()
            after = app.theme
            bad = app.apply_theme_pack("does-not-exist")
            return before, ok, after, T.ACCENT, bad

    before, ok, after, accent, bad = asyncio.run(_run())
    assert before == "kratos-red"       # default on boot
    assert ok is True and after == "kratos-blue"
    assert accent == "#7fa8bf"          # globals re-bound live
    assert bad is False                 # unknown pack rejected

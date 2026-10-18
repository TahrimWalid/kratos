"""Headless pilots for journal sealing in the TUI (0.3 §7.1): the seal modal
(paste/save, `s` skip, stray keys, invalid key, letters typed into the field),
the onboarding offer after SSH works, and /target seal saving the key without
ever showing it."""
from __future__ import annotations

import asyncio

from textual.app import App
from textual.widgets import Input

from kratos.logsources import seal
from kratos.tui_mk2.modals import SealKeyModal

KEY = "a1b2c3-d4e5f6-a7b8c9-d0e1f2/1a2b3c-35a4e900"


class _Host(App):
    def on_mount(self):
        pass


def _run_modal(keys: list[str], *, type_text: str | None = None) -> tuple[object, str]:
    out: dict = {}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(SealKeyModal("203.0.113.5", "# commands"), lambda r: out.setdefault("r", r))
            await pilot.pause()
            if type_text is not None:
                await pilot.press("k")
                await pilot.pause()
                for ch in type_text:
                    await pilot.press(ch if ch not in "-/" else {"-": "minus", "/": "slash"}[ch])
            for k in keys:
                await pilot.press(k)
                await pilot.pause()
            out.setdefault("screen", type(app.screen).__name__)
            inp = app.screen.query("#seal-key") if isinstance(app.screen, SealKeyModal) else []
            out["field"] = inp[0] if inp else None
            out["error"] = str(app.screen.query_one("#seal-error").render()) if isinstance(app.screen, SealKeyModal) else ""

    asyncio.run(run())
    return out.get("r", "<open>"), out


def test_paste_and_enter_saves_a_valid_key():
    result, _ = _run_modal(["enter"], type_text=KEY)
    assert result == KEY


def test_s_skips_with_one_key():
    result, _ = _run_modal(["s"])
    assert result is None


def test_a_stray_key_does_nothing():
    result, out = _run_modal(["x", "z", "1"])
    assert result == "<open>" and out["screen"] == "SealKeyModal"


def test_an_invalid_key_stays_open_with_an_error_and_is_cleared():
    result, out = _run_modal(["enter"], type_text="not a key")
    assert result == "<open>"
    assert "verification key" in out["error"] and out["field"].value == ""


def test_letters_typed_into_the_field_are_not_shortcuts():
    # a key containing s/c/k must not skip, copy or refocus half way
    result, out = _run_modal([], type_text="sck")
    assert result == "<open>" and out["field"].value == "sck"


def test_the_field_is_masked():
    _, out = _run_modal([])
    assert isinstance(out["field"], Input) and out["field"].password


def test_onboarding_offers_sealing_after_ssh_works(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens.onboard import OnboardTargetScreen
    from tests.test_tui_mk2_onboard import _Host as OBHost, _pick

    async def given(self):
        self._login_confirmed = True
        return True

    monkeypatch.setattr(OnboardTargetScreen, "_ask_login", given)
    # Kratos's SSH key exists on a real install; make the test independent of ambient host
    # state (without this, a machine with no key opens an unanswered "create key?" modal).
    monkeypatch.setattr("kratos.utils.ssh_keys.read_local_pubkey", lambda: "ssh-ed25519 AAAATEST test@kratos")
    monkeypatch.setattr("kratos.adapters.ssh_remote.run_target_probe_checks",
                        lambda: [{"check": "ssh_reachable", "status": "PASS", "detail": "ok"}])
    out: dict = {}

    async def run():
        app = OBHost()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = OnboardTargetScreen(tmp_path, "203.0.113.5")
            app.push_screen(screen, lambda r: out.setdefault("dismissed", r))
            await pilot.pause()
            await _pick(pilot, "ssh")
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.press("enter")          # continue -> the seal step first
            await pilot.pause()
            out["modal"] = type(app.screen).__name__
            await pilot.press("s")              # one key skips
            await pilot.pause()
            await pilot.pause()

    asyncio.run(run())
    assert out["modal"] == "SealKeyModal"
    assert out["dismissed"] == "ssh" and not seal.has_key(tmp_path, "203.0.113.5")


def test_target_seal_saves_the_key_and_never_shows_it(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens import session as S

    shown: list[str] = []

    class Fake:
        _data_dir = tmp_path
        session_state = {"targets": ["203.0.113.5"]}

        def _emit(self, renderable):
            shown.append(str(getattr(renderable, "plain", renderable)))

        class app:  # noqa: N801
            @staticmethod
            async def push_screen_wait(screen):
                assert isinstance(screen, SealKeyModal)
                return KEY

    asyncio.run(S.SessionScreen._target_seal_flow(Fake(), ""))
    assert seal.load_key(tmp_path, "203.0.113.5")["key"] == KEY
    assert shown and not any(KEY in s for s in shown)
    shown.clear()
    asyncio.run(S.SessionScreen._target_seal_flow(Fake(), KEY))   # typed on the command line
    assert any("Don't type the key" in s for s in shown) and not any(KEY in s for s in shown)

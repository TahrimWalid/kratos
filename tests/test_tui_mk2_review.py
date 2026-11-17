"""E.7b TUI `/review` (§3.14): the screen lists confirmed folders, `p` prepares and shows the
consent plan, and only an explicit yes starts a review whose findings it then shows. Headless
Textual pilots; prepare/start are stubbed so no model or sandbox is touched."""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos import authz
from kratos.code import roots as R
from kratos.lifecycle.decide import Actor

M = "192.0.2.123"
OWNER = authz.owner_actor("tui")


def _confirm_root(dd):
    R.add(dd, M, "/srv/app", actor=OWNER)
    R.confirm(dd, M, "/srv/app", actor=OWNER)


def _app(dd, machine=M):
    from kratos.tui_mk2.screens.review import ReviewScreen

    class _A(App):
        def on_mount(self):
            self.push_screen(ReviewScreen(dd, machine=machine))
    return _A()


def test_lists_confirmed_folders(tmp_path, monkeypatch):
    monkeypatch.setattr(Actor, "current", classmethod(lambda cls, iface="tui": OWNER))
    _confirm_root(tmp_path)

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            scr = app.screen
            from kratos.tui_mk2.screens.review import ReviewScreen
            assert isinstance(scr, ReviewScreen)
            assert scr._rows and scr._rows[0]["root"] == "/srv/app"
    asyncio.run(go())


def test_prepare_consent_and_run(tmp_path, monkeypatch):
    monkeypatch.setattr(Actor, "current", classmethod(lambda cls, iface="tui": OWNER))
    _confirm_root(tmp_path)

    from kratos.review import run as RUN
    from kratos.review.cost import Estimate
    from kratos.review.profiles import ReviewProfile
    from kratos.review.slice import SliceStats

    class _Plan:
        plan_id = "p1"
        profile = ReviewProfile("rev", "rev", "http://127.0.0.1:1/v1", "k", True)
        verifier = None
        estimate = Estimate(1, 0, 0, 100, 50, 0.0, False)
        stats = SliceStats(root_bytes=1000, sliced_bytes=100)
        reproduction = True
        mask_mode = "off"

        def consent_summary(self):
            return {"line": "Code slices go to rev (a model on your own network). Masking: off. Secrets are always "
                            "removed before anything is sent.", "slices_to_send": 1, "bytes_to_send": 100,
                    "slices_cached": 0, "dropped_by_cap": 0, "reproduction": True, "estimate_usd": 0.0,
                    "priced": False, "est_calls": 1, "est_tokens": 150, "reduction": 10.0,
                    "incomplete_languages": {}, "too_large": 0, "not_parsed": {}, "machine": M, "root": "/srv/app",
                    "destination": "local", "destination_text": "a model on your own network",
                    "verifier_profile": "rev", "mask_mode": "off"}

    started = {}

    def fake_prepare(data_dir, actor, machine, root, **kw):
        return _Plan()

    def fake_start(data_dir, actor, plan_id, *, agreed_usd, on_progress=None, **kw):
        started["agreed"] = agreed_usd
        if on_progress:
            on_progress("hunting", {"class": "exec", "slices": 1})
        return RUN.RunResult(run_id=1, state="done", actual_usd=0.0,
                             findings=[{"verdict": "confirmed", "strength": "reproduced", "cls": "exec",
                                        "rel": "app.py", "function": "ping",
                                        "evidence": "the canary reached os.system() in the sandbox",
                                        "question": "", "fix_words": "", "fix_check": ""}])

    monkeypatch.setattr(RUN, "prepare_review", fake_prepare)
    monkeypatch.setattr(RUN, "start_review", fake_start)

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            await pilot.press("p")                 # prepare -> consent modal
            for _ in range(6):
                await pilot.pause(0.05)
            await pilot.press("y")                 # send
            for _ in range(10):
                await pilot.pause(0.05)
            scr = app.screen
            assert started.get("agreed", 0) > 0
            assert scr._findings and scr._findings[0]["verdict"] == "confirmed"
    asyncio.run(go())


def test_decline_sends_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(Actor, "current", classmethod(lambda cls, iface="tui": OWNER))
    _confirm_root(tmp_path)
    from kratos.review import run as RUN

    class _Plan:
        plan_id = "p"; reproduction = True; mask_mode = "off"
        from kratos.review.cost import Estimate as _E
        estimate = _E(1, 0, 0, 100, 50, 0.0, False)
        from kratos.review.profiles import ReviewProfile as _P
        profile = _P("rev", "rev", "http://127.0.0.1:1/v1", "k", True)
        verifier = None

        def consent_summary(self):
            return {"line": "x", "slices_to_send": 1, "bytes_to_send": 1, "slices_cached": 0, "dropped_by_cap": 0,
                    "reproduction": True, "estimate_usd": 0.0, "priced": False, "est_calls": 1, "est_tokens": 1,
                    "reduction": 1.0, "incomplete_languages": {}}

    called = {"start": 0}
    monkeypatch.setattr(RUN, "prepare_review", lambda *a, **k: _Plan())
    monkeypatch.setattr(RUN, "start_review", lambda *a, **k: called.__setitem__("start", called["start"] + 1))

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            await pilot.press("p")
            for _ in range(6):
                await pilot.pause(0.05)
            await pilot.press("n")                 # decline
            for _ in range(6):
                await pilot.pause(0.05)
            assert called["start"] == 0            # nothing sent
    asyncio.run(go())


def test_title_key_bar_and_no_empty_table(tmp_path, monkeypatch):
    """TUI review: /review had no title (its first line was the warning), a hint line that mixed
    keys with a sentence, and an empty grid under 'no confirmed folders'."""
    monkeypatch.setattr(Actor, "current", classmethod(lambda cls, iface="tui": OWNER))

    async def go():
        app = _app(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            scr = app.screen
            assert str(scr.query_one("#rv-banner")._Static__content).startswith("AI code review")
            assert scr.query_one("#rv-table").display is False
            assert "Confirm one first in /code" in str(scr.query_one("#rv-detail")._Static__content)
            hints = str(scr.query_one("#rv-hints")._Static__content)
            assert "esc back" in hints and "secrets" not in hints
    asyncio.run(go())

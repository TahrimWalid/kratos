"""Headless pilots for the mk2 /preset command flows (A2 Tier 1).

Drives SessionScreen._preset_flow through real Textual workers, with modals
answered via a monkeypatched push_screen_wait and the investigation runner
replaced by a recorder (no real run_agent/SSH/LLM).
"""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.agent import presets as P
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make_screen(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def test_preset_new_inline_creates(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash('/preset new "Weekly Audit" "full ssh + firewall review"')
            for _ in range(80):
                await pilot.pause()
                if P.preset_exists(tmp_path, "weekly-audit"):
                    break

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "weekly-audit")
    assert p is not None
    assert p.goal == "full ssh + firewall review"
    assert p.kind == "goal"


def test_preset_new_prompts_for_goal(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _goal(_m):  # PromptModal for the goal
                return "prompted goal"

            monkeypatch.setattr(app, "push_screen_wait", _goal)
            screen._dispatch_slash('/preset new "prompted"')
            for _ in range(80):
                await pilot.pause()
                if P.preset_exists(tmp_path, "prompted"):
                    break

    asyncio.run(_run())
    assert P.load_preset(tmp_path, "prompted").goal == "prompted goal"


def test_preset_run_invokes_investigation_with_goal(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="quick", goal="scan the target for open ports")
    recorded = {}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda goal, **kw: recorded.__setitem__("goal", goal))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset run quick")
            for _ in range(120):
                await pilot.pause()
                if "goal" in recorded:
                    break

    asyncio.run(_run())
    assert recorded.get("goal") == "scan the target for open ports"


def test_preset_run_pipeline_is_declined_not_run(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    d = P.presets_dir(tmp_path)
    d.mkdir(parents=True)
    (d / "pipe.toml").write_text(
        'name = "pipe"\nkind = "pipeline"\n[[steps]]\ntool = "run_nmap_scan"\n',
        encoding="utf-8")
    calls = {"n": 0}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda *a, **k: calls.__setitem__("n", calls["n"] + 1))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset run pipe")
            for _ in range(30):
                await pilot.pause()

    asyncio.run(_run())
    assert calls["n"] == 0  # forward-compat: a pipeline preset is not run here


def test_preset_delete_confirmed(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="doomed", goal="g")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_m):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._dispatch_slash("/preset delete doomed")
            for _ in range(80):
                await pilot.pause()
                if not P.preset_exists(tmp_path, "doomed"):
                    break

    asyncio.run(_run())
    assert not P.preset_exists(tmp_path, "doomed")


def test_preset_delete_cancelled_keeps_it(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="safe", goal="g")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _no(_m):
                return False

            monkeypatch.setattr(app, "push_screen_wait", _no)
            screen._dispatch_slash("/preset delete safe")
            for _ in range(30):
                await pilot.pause()

    asyncio.run(_run())
    assert P.preset_exists(tmp_path, "safe")  # decline keeps it


def test_preset_run_guided_picks_from_list_and_runs(tmp_path, monkeypatch):
    """/preset-run (the guided, menu-friendly form) offers a picker and runs the
    chosen preset -- no inline name typing."""
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="alpha", goal="goal alpha")
    P.save_preset(tmp_path, name="beta", goal="goal beta")
    recorded = {}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda goal, **kw: recorded.__setitem__("goal", goal))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _pick_beta(_modal):  # the ListPickerModal returns a name
                return "beta"

            monkeypatch.setattr(app, "push_screen_wait", _pick_beta)
            screen._dispatch_slash("/preset-run")
            for _ in range(120):
                await pilot.pause()
                if "goal" in recorded:
                    break

    asyncio.run(_run())
    assert recorded.get("goal") == "goal beta"


def test_preset_run_guided_empty_hints_to_new(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    ran = {"n": 0}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda *a, **k: ran.__setitem__("n", ran["n"] + 1))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset-run")  # no presets exist
            for _ in range(20):
                await pilot.pause()

    asyncio.run(_run())
    assert ran["n"] == 0  # nothing to run; guided flow just hints


def test_forgotten_slash_interceptor_runs_command(tmp_path, monkeypatch):
    """Typing a bare command word (no slash) is caught deterministically and run
    as the command — 'preset new ...' creates the preset instead of going to the
    LLM as a goal."""
    from textual.widgets import Input

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    # Guard: if it wrongly went to the LLM, this would be called.
    monkeypatch.setattr(screen, "_run_goal",
                        lambda *a, **k: pytest.fail("bare command leaked to _run_goal"))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = screen.query_one("#goal", Input)
            inp.value = 'preset new "weekly audit" "full ssh review"'
            screen.on_input_submitted(Input.Submitted(inp, inp.value))
            for _ in range(80):
                await pilot.pause()
                if P.preset_exists(tmp_path, "weekly-audit"):
                    break

    asyncio.run(_run())
    assert P.load_preset(tmp_path, "weekly-audit").goal == "full ssh review"


def test_ambiguous_verb_is_not_intercepted(tmp_path, monkeypatch):
    """A goal that merely starts with an ambiguous verb ('run a scan …') must NOT
    be hijacked by the interceptor — it goes to the normal goal path."""
    from textual.widgets import Input

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    seen = {}
    monkeypatch.setattr(screen, "_run_goal", lambda goal, **k: seen.__setitem__("goal", goal))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            inp = screen.query_one("#goal", Input)
            inp.value = "run a full scan on the target"
            screen.on_input_submitted(Input.Submitted(inp, inp.value))
            for _ in range(20):
                await pilot.pause()

    asyncio.run(_run())
    assert seen.get("goal") == "run a full scan on the target"  # went to the LLM, not /run


def test_preset_new_conversational_saves_on_confirm(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _yes(_m):
                return True

            monkeypatch.setattr(app, "push_screen_wait", _yes)
            screen._preset_new_conversational("Weekly Audit", "review ssh hardening")
            for _ in range(80):
                await pilot.pause()
                if P.preset_exists(tmp_path, "weekly-audit"):
                    break

    asyncio.run(_run())
    assert P.load_preset(tmp_path, "weekly-audit").goal == "review ssh hardening"


def test_preset_new_conversational_declined_saves_nothing(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _no(_m):
                return False

            monkeypatch.setattr(app, "push_screen_wait", _no)
            screen._preset_new_conversational("weekly", "goal")
            for _ in range(30):
                await pilot.pause()

    asyncio.run(_run())
    assert not P.preset_exists(tmp_path, "weekly")


def test_preset_run_conversational_runs_existing(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="nightly", goal="nightly checks")
    recorded = {}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda goal, **kw: recorded.__setitem__("goal", goal))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._preset_run_conversational("nightly")
            for _ in range(120):
                await pilot.pause()
                if "goal" in recorded:
                    break

    asyncio.run(_run())
    assert recorded.get("goal") == "nightly checks"


def test_preset_run_conversational_unknown_is_safe(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    ran = {"n": 0}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda *a, **k: ran.__setitem__("n", ran["n"] + 1))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._preset_run_conversational("does-not-exist")
            for _ in range(20):
                await pilot.pause()

    asyncio.run(_run())
    assert ran["n"] == 0  # unknown preset: helpful error, nothing run


def test_preset_list_renders_without_crashing(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="a", goal="ga")
    P.save_preset(tmp_path, name="b", goal="gb")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset list")
            for _ in range(20):
                await pilot.pause()

    asyncio.run(_run())  # no exception == pass

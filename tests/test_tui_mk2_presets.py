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


def test_preset_run_pipeline_uses_deterministic_worker(tmp_path, monkeypatch):
    """A2 Tier 2: a valid pipeline preset now RUNS -- via the deterministic
    pipeline turn worker (no LLM), NOT the agentic _run_investigation path."""
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="pipe", kind="pipeline", steps=[
        {"tool": "run_nmap_scan", "required": True},
        {"tool": "correlate_findings", "required": True},
    ])
    agentic = {"n": 0}
    pipeline = {}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda *a, **k: agentic.__setitem__("n", agentic["n"] + 1))
    monkeypatch.setattr(screen, "_run_pipeline_turn",
                        lambda steps, **kw: pipeline.__setitem__(
                            "tools", [s.tool for s in steps]) or pipeline.update(kw))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset run pipe")
            for _ in range(60):
                await pilot.pause()
                if "tools" in pipeline:
                    break

    asyncio.run(_run())
    assert agentic["n"] == 0                                  # NOT the agentic loop
    assert pipeline["tools"] == ["run_nmap_scan", "correlate_findings"]
    assert pipeline["remember_kind"] == "pipeline preset"


def test_preset_new_guided_builds_pipeline(tmp_path, monkeypatch):
    """/preset-new -> pipeline -> the guided step builder saves a kind=pipeline
    preset with the chosen tools, in order."""
    from kratos.tui_mk2.modals import ListPickerModal, PromptModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    step_picks = iter(["tool:run_nmap_scan", "tool:correlate_findings", "__done__"])

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                title = getattr(modal, "_title", "") or ""
                if isinstance(modal, ListPickerModal):
                    if "kind of preset" in title:
                        return "pipeline"
                    if title.startswith("Add "):
                        return next(step_picks)
                    if "fails" in title:
                        return "required"
                    if title.startswith("When should"):
                        return ""  # always run (no condition)
                if isinstance(modal, PromptModal):
                    if "New pipeline preset" in title:
                        return "my-pipe"
                    if title.startswith("Target for"):
                        return ""
                return None

            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/preset-new")
            for _ in range(150):
                await pilot.pause()
                if P.preset_exists(tmp_path, "my-pipe"):
                    break

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "my-pipe")
    assert p is not None and p.kind == "pipeline"
    assert [s["tool"] for s in p.steps] == ["run_nmap_scan", "correlate_findings"]
    assert all(s["required"] for s in p.steps)
    assert p.is_runnable_pipeline


def test_preset_new_guided_cancel_creates_nothing(tmp_path, monkeypatch):
    """Cancelling the guided step builder (esc before adding any step) saves
    nothing -- the no-force-accept safe default."""
    from kratos.tui_mk2.modals import ListPickerModal, PromptModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                title = getattr(modal, "_title", "") or ""
                if isinstance(modal, ListPickerModal) and "kind of preset" in title:
                    return "pipeline"
                if isinstance(modal, PromptModal) and "New pipeline preset" in title:
                    return "abandoned"
                if isinstance(modal, ListPickerModal) and title.startswith("Add "):
                    return None  # esc out of the builder before adding a step
                return None

            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/preset-new")
            for _ in range(60):
                await pilot.pause()

    asyncio.run(_run())
    assert not P.preset_exists(tmp_path, "abandoned")


def test_preset_scaffold_writes_valid_template(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/preset-scaffold my-template")
            for _ in range(60):
                await pilot.pause()
                if P.preset_exists(tmp_path, "my-template"):
                    break

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "my-template")
    assert p is not None and p.kind == "pipeline" and p.is_runnable_pipeline


def test_preset_run_guided_includes_pipeline(tmp_path, monkeypatch):
    """The /preset-run picker now offers pipeline presets too (both goal AND
    pipeline are runnable in Tier 2)."""
    from kratos.tui_mk2.modals import ListPickerModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="a-goal", goal="scan for open ports")
    P.save_preset(tmp_path, name="a-pipe", kind="pipeline",
                  steps=[{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])
    offered = {}

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _capture(modal):
                if isinstance(modal, ListPickerModal):
                    offered["values"] = [v for v, _ in modal._entries]
                return None  # cancel after capturing

            monkeypatch.setattr(app, "push_screen_wait", _capture)
            screen._dispatch_slash("/preset-run")
            for _ in range(60):
                await pilot.pause()
                if "values" in offered:
                    break

    asyncio.run(_run())
    assert set(offered["values"]) == {"a-goal", "a-pipe"}  # both runnable kinds offered


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


def test_preset_new_guided_pipeline_with_condition(tmp_path, monkeypatch):
    """The guided builder can attach a bounded `when` condition to a step (slice
    4): nmap always, then a vuln scan only-if a HIGH finding exists."""
    from kratos.tui_mk2.modals import ListPickerModal, PromptModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    step_picks = iter(["tool:run_nmap_scan", "tool:run_vuln_scan", "__done__"])
    fails_picks = iter(["required", "optional"])
    when_picks = iter(["", "has_finding(min_severity='high')"])

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                title = getattr(modal, "_title", "") or ""
                if isinstance(modal, ListPickerModal):
                    if "kind of preset" in title:
                        return "pipeline"
                    if title.startswith("Add "):
                        return next(step_picks)
                    if "fails" in title:
                        return next(fails_picks)
                    if title.startswith("When should"):
                        return next(when_picks)
                if isinstance(modal, PromptModal):
                    if "New pipeline preset" in title:
                        return "cond-pipe"
                    if title.startswith("Target for"):
                        return ""
                return None

            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/preset-new")
            for _ in range(200):
                await pilot.pause()
                if P.preset_exists(tmp_path, "cond-pipe"):
                    break

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "cond-pipe")
    assert p is not None and p.is_runnable_pipeline
    assert [s["tool"] for s in p.steps] == ["run_nmap_scan", "run_vuln_scan"]
    assert "when" not in p.steps[0]                                   # first step: always
    assert p.steps[1]["when"] == "has_finding(min_severity='high')"   # gated second step
    assert p.has_conditions is True


def test_slash_name_runs_preset_as_first_class_command(tmp_path, monkeypatch):
    """A2 Piece H: /<name> runs a saved preset directly."""
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="quick", goal="scan for open ports")
    recorded = {}
    monkeypatch.setattr(screen, "_run_investigation",
                        lambda goal, **kw: recorded.__setitem__("goal", goal))

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/quick")
            for _ in range(120):
                await pilot.pause()
                if "goal" in recorded:
                    break

    asyncio.run(_run())
    assert recorded.get("goal") == "scan for open ports"


def test_slash_name_unknown_falls_through_to_goal(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    fell = {}
    monkeypatch.setattr(screen, "_run_goal", lambda text: fell.__setitem__("text", text))
    screen._dispatch_slash("/not-a-preset do the thing")
    assert fell.get("text") == "/not-a-preset do the thing"


def test_palette_includes_runnable_presets(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="goalp", goal="g")
    P.save_preset(tmp_path, name="pipep", kind="pipeline",
                  steps=[{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])
    cmds = dict(screen._palette_commands())
    assert "/goalp" in cmds and "/pipep" in cmds
    assert "pipeline" in cmds["/pipep"]


def test_slash_name_records_last_run(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="quick", goal="g")
    monkeypatch.setattr(screen, "_run_investigation", lambda *a, **k: None)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/quick")
            for _ in range(60):
                await pilot.pause()
                if "quick" in P.preset_run_meta(tmp_path):
                    break

    asyncio.run(_run())
    assert "quick" in P.preset_run_meta(tmp_path)


def test_preset_import_command(tmp_path, monkeypatch):
    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    src = tmp_path / "incoming.toml"
    src.write_text('name = "imported"\nkind = "goal"\ngoal = "review firewall"\n', encoding="utf-8")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash(f"/preset import {src}")
            for _ in range(80):
                await pilot.pause()
                if P.preset_exists(tmp_path, "imported"):
                    break

    asyncio.run(_run())
    assert P.load_preset(tmp_path, "imported").goal == "review firewall"


def test_pipeline_step_editor_adds_and_saves(tmp_path, monkeypatch):
    """The in-place editor adds a step to an existing pipeline and saves it."""
    from kratos.tui_mk2.modals import ListPickerModal, PromptModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="ed", kind="pipeline",
                  steps=[{"tool": "run_nmap_scan", "required": True}])
    menu_picks = iter(["__add__", "__save__"])

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                title = getattr(modal, "_title", "") or ""
                if isinstance(modal, ListPickerModal):
                    if title.startswith("Edit pipeline"):
                        return next(menu_picks)
                    if title == "Which tool?":
                        return "tool:correlate_findings"
                    if "fails" in title:
                        return "required"
                    if title.startswith("When should"):
                        return ""
                return None

            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/preset edit ed")
            for _ in range(150):
                await pilot.pause()
                p = P.load_preset(tmp_path, "ed")
                if p and len(p.steps) == 2:
                    break

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "ed")
    assert [s["tool"] for s in p.steps] == ["run_nmap_scan", "correlate_findings"]


def test_pipeline_step_editor_cancel_keeps_original(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import ListPickerModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    P.save_preset(tmp_path, name="ed2", kind="pipeline",
                  steps=[{"tool": "run_nmap_scan"}, {"tool": "correlate_findings"}])

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                title = getattr(modal, "_title", "") or ""
                if isinstance(modal, ListPickerModal) and title.startswith("Edit pipeline"):
                    return "__cancel__"
                return None

            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/preset edit ed2")
            for _ in range(60):
                await pilot.pause()

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "ed2")
    assert [s["tool"] for s in p.steps] == ["run_nmap_scan", "correlate_findings"]  # unchanged


def test_preset_builder_threads_output_no_syntax(tmp_path, monkeypatch):
    """A2 Piece C usability: the guided builder threads correlate_findings.
    top_source_ip into check_ip_reputation.ip with NO reference syntax typed —
    just menu picks. Grounds the owner's 'genuinely usable' requirement."""
    from kratos.tui_mk2.modals import ListPickerModal, PromptModal

    _store, _sid, screen = _make_screen(tmp_path, monkeypatch)
    step_picks = iter(["tool:correlate_findings", "tool:check_ip_reputation", "__done__"])

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def _answer(modal):
                title = getattr(modal, "_title", "") or ""
                if isinstance(modal, ListPickerModal):
                    if "kind of preset" in title:
                        return "pipeline"
                    if title.startswith("Add "):
                        return next(step_picks)
                    if "fails" in title:
                        return "required"
                    if title.startswith("When should"):
                        return ""
                    # Piece C arg pickers:
                    if title == "check_ip_reputation: ip":
                        return "__thread__"                    # use a result, don't type
                    if title == "Use a result from which step?":
                        return "correlate_findings"            # the producer step's auto-label
                    if title == "Which value?":
                        return "top_source_ip"
                if isinstance(modal, PromptModal):
                    if "New pipeline preset" in title:
                        return "threaded"
                    if title.startswith("Target for"):
                        return ""
                return None

            monkeypatch.setattr(app, "push_screen_wait", _answer)
            screen._dispatch_slash("/preset-new")
            for _ in range(200):
                await pilot.pause()
                if P.preset_exists(tmp_path, "threaded"):
                    break

    asyncio.run(_run())
    p = P.load_preset(tmp_path, "threaded")
    assert p is not None and p.is_runnable_pipeline
    # The second step's ip arg is a structured reference (no syntax was typed).
    assert p.steps[1]["args"]["ip"] == {"from": "correlate_findings", "field": "top_source_ip"}

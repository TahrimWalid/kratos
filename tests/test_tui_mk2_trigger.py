"""Headless pilots for the A6.4 /trigger TUI flow. Guided modals answered via a
monkeypatched push_screen_wait (matching the schedule/preset pilots)."""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos.agent import triggers as T
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens.session import SessionScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _make(tmp_path, monkeypatch):
    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    # The one-time "spending limits for unattended runs" summary (tests/test_tui_budget.py)
    # was already answered here, so these flows ask only their own questions.
    from kratos.budget.ledger import BudgetLedger

    BudgetLedger(tmp_path).state_set(SessionScreen._UNATTENDED_BUDGET_SHOWN, {"choice": "keep"})
    return store, sid, SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def _answers(app, monkeypatch, values):
    it = iter(values)

    async def _fn(modal):
        return next(it)

    monkeypatch.setattr(app, "push_screen_wait", _fn)

def _trig(sev="high", fid="", only_new=False, action="notify", cooldown="60", name=""):
    """One answer to the New trigger form (A4: one form instead of a chain of dialogs)."""
    return {"sev": sev, "fid": fid, "only_new": only_new, "action": action, "cooldown": cooldown, "name": name}



def test_trigger_new_severity_notify(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            _answers(app, monkeypatch, [_trig(name="high-alert")])
            screen._dispatch_slash("/trigger new")
            for _ in range(200):
                await pilot.pause()
                if T.trigger_exists(tmp_path, "high-alert"):
                    break

    asyncio.run(_run())
    tg = T.load_trigger(tmp_path, "high-alert")
    assert tg is not None and tg.min_severity == "high" and tg.action == "notify"
    assert tg.cooldown_minutes == 60 and tg.only_new_or_reopened is False


def test_trigger_new_only_new_or_reopened(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            _answers(app, monkeypatch, [_trig(only_new=True, name="news-only")])
            screen._dispatch_slash("/trigger new")
            for _ in range(200):
                await pilot.pause()
                if T.trigger_exists(tmp_path, "news-only"):
                    break

    asyncio.run(_run())
    tg = T.load_trigger(tmp_path, "news-only")
    assert tg.only_new_or_reopened is True
    assert "only_new_or_reopened = true" in tg.path.read_text()
    assert "only when new, reopened, recurred or more severe" in tg.condition_text


def test_trigger_new_investigate_on_cloud_warns_and_aborts(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    monkeypatch.setattr("kratos.agent.scheduled_run.active_backend_is_cloud", lambda: True)

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            # the form (investigate), then the cost confirm = False
            _answers(app, monkeypatch, [_trig(action="investigate"), False])
            screen._dispatch_slash("/trigger new")
            for _ in range(120):
                await pilot.pause()

    asyncio.run(_run())
    assert T.list_triggers(tmp_path)[0] == []  # aborted at the cost warning


def test_trigger_name_is_pre_filled_from_the_condition_and_action(tmp_path, monkeypatch):
    from kratos.tui_mk2.modals import FormModal

    store, sid, screen = _make(tmp_path, monkeypatch)
    seen: list = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            it = iter([_trig(sev="", fid="CORR-SSH-001", action="playbook", name="")])   # blank name = the suggestion

            async def _fn(modal):
                seen.append(modal)
                return next(it)

            monkeypatch.setattr(app, "push_screen_wait", _fn)
            screen._dispatch_slash("/trigger new")
            for _ in range(200):
                await pilot.pause()
                if T.trigger_exists(tmp_path, "corr-ssh-001-playbook"):
                    break

    asyncio.run(_run())
    assert isinstance(seen[0], FormModal)
    tg = T.load_trigger(tmp_path, "corr-ssh-001-playbook")
    assert tg is not None and tg.finding_id == "CORR-SSH-001" and tg.action == "playbook"


def test_trigger_test_shows_would_fire_without_side_effects(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    T.save_trigger(tmp_path, name="pb", action="playbook", finding_id="CORR-SSH-001")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/trigger test pb")
            for _ in range(80):
                await pilot.pause()

    asyncio.run(_run())
    assert T.read_fire_records(tmp_path, "pb") == []  # test never persists a fire


def test_trigger_list_renders(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)
    T.save_trigger(tmp_path, name="a", action="notify", min_severity="high")

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._dispatch_slash("/trigger list")
            for _ in range(60):
                await pilot.pause()

    asyncio.run(_run())  # must not raise


def test_the_real_form_saves_on_its_default_answers(tmp_path, monkeypatch):
    # The one-form trigger (A4) on screen: Enter on the defaults makes a valid trigger
    # (the old chain's defaults led to "A trigger needs a condition").
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen._dispatch_slash("/trigger new")
            for _ in range(40):
                await pilot.pause()
                if type(app.screen).__name__ == "FormModal":
                    break
            await pilot.press("enter")
            for _ in range(100):
                await pilot.pause()
                if T.trigger_exists(tmp_path, "high-alert"):
                    break

    asyncio.run(_run())
    tg = T.load_trigger(tmp_path, "high-alert")
    assert tg is not None and tg.min_severity == "high" and tg.action == "notify"


def test_the_real_form_refuses_no_condition_inline(tmp_path, monkeypatch):
    store, sid, screen = _make(tmp_path, monkeypatch)

    async def _run():
        app = _Host(screen)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            screen._dispatch_slash("/trigger new")
            for _ in range(40):
                await pilot.pause()
                if type(app.screen).__name__ == "FormModal":
                    break
            await pilot.press("left")          # high+ -> any (by ID), no ID typed
            await pilot.press("enter")
            await pilot.pause()
            err = str(app.screen.query_one("#form-error").render())
            still_open = type(app.screen).__name__ == "FormModal"
            return err, still_open

    err, still_open = asyncio.run(_run())
    assert "finding-ID" in err and still_open
    assert T.list_triggers(tmp_path)[0] == []

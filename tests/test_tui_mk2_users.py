"""D.7 headless pilots: /users (add, role, machines, disable, tokens, Open WebUI mapping --
every change recorded), /audit, and another user's session opened read-only."""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos import authz
from kratos.authz import audit as AU
from kratos.authz import users as U
from kratos.storage.session_store import SessionStore
from kratos.tui_mk2.screens import users as SU

M1 = "192.0.2.10"


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _answers(app, monkeypatch, values, seen=None):
    it = iter(values)

    async def _fn(modal):
        if seen is not None:
            seen.append(modal)
        return next(it)

    monkeypatch.setattr(app, "push_screen_wait", _fn)


async def _settle(pilot, until, n=200):
    for _ in range(n):
        await pilot.pause()
        if until():
            return


def test_users_screen_adds_scopes_disables_and_makes_a_token(tmp_path, monkeypatch):
    screen = SU.UsersScreen(tmp_path)
    shown = []

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(180, 40)) as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "push_screen", lambda s, *a, **k: shown.append(s))
            _answers(app, monkeypatch, ["ivy", "investigator", f"{M1}, @lab", True])
            screen.action_add()
            await _settle(pilot, lambda: U.find(tmp_path, "ivy") is not None)
            assert [u.name for u in screen._rows][-1] == "ivy"
            screen.query_one("#us-table").move_cursor(row=1)
            _answers(app, monkeypatch, ["viewer"])
            screen.action_role()
            await _settle(pilot, lambda: U.find(tmp_path, "ivy").role == "viewer")
            _answers(app, monkeypatch, [True])
            screen.action_toggle()
            await _settle(pilot, lambda: U.find(tmp_path, "ivy").disabled)
            _answers(app, monkeypatch, [True])
            screen.action_toggle()
            await _settle(pilot, lambda: not U.find(tmp_path, "ivy").disabled)
            _answers(app, monkeypatch, ["ivy-laptop", False])
            screen.action_token()
            await _settle(pilot, lambda: any(getattr(s, "_command", "").startswith("krt_") for s in shown))
            _answers(app, monkeypatch, ["owui-123", "ivy@example.com"])
            screen.action_map()
            await _settle(pilot, lambda: U.mapping_for(tmp_path, "openwebui", "owui-123") is not None)

    asyncio.run(run())
    ivy = U.find(tmp_path, "ivy")
    assert ivy.scopes == (M1, "@lab") or set(ivy.scopes) == {M1, "@lab"}
    actions = [r["action"] for r in AU.query(tmp_path, interface="tui")]
    assert actions.count("users.manage") >= 5
    assert "tokens.manage" in [r["action"] for r in AU.query(tmp_path)]
    assert all(r["user_id"] == "owner" for r in AU.query(tmp_path))


def test_audit_screen_lists_refusals(tmp_path):
    U.add_user(tmp_path, "vic", "viewer", authz.owner_actor("cli"), scopes=[M1])
    AU.record(tmp_path, interface="serve", action="investigate.start", result="refused", user_name="vic",
              reason="viewers can't start investigations")
    screen = SU.AuditScreen(tmp_path)

    async def run():
        async with _Host(screen).run_test(size=(180, 40)) as pilot:
            await pilot.pause()
            screen.action_refused()
            await pilot.pause()
            assert [r["user_name"] for r in screen._rows] == ["vic"]
            # TUI review: a refusal is the system working -- the attention colour, not danger red;
            # the reason (cut at 80 columns before) is in the detail pane
            from kratos.tui_mk2 import theme as T

            cell = screen.query_one("#au-table").get_row_at(0)[1]
            assert str(cell) == "refused" and T.CRITICAL not in str(cell.style) and T.ATTENTION in str(cell.style)
            detail = str(screen.query_one("#au-detail")._Static__content)
            assert "viewers can't start investigations" in detail
            assert "esc" in str(screen.query_one("#au-hints")._Static__content)

    asyncio.run(run())


def test_another_users_session_opens_read_only(tmp_path, monkeypatch):
    from kratos.lifecycle.decide import Actor
    from kratos.serve import auth
    from kratos.tui_mk2.screens.session import SessionScreen

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    U.add_user(tmp_path, "ivy", "investigator", authz.owner_actor("cli"), scopes=[M1])
    _t, row = auth.create_token(tmp_path, name="ivy-t", user="ivy")
    store = SessionStore(tmp_path / "kratos.db")
    with authz.acting_as(Actor(user="ivy", interface="serve", user_id=U.find(tmp_path, "ivy").user_id,
                               credential=f"token:{row['token_id']}")):
        sid = store.create_session([M1], "m")
    store.start_turn(sid, "anyone logging in?")
    screen = SessionScreen(store, tmp_path, sid, [M1], "")
    ran = []
    monkeypatch.setattr(screen, "_run_goal", lambda text: ran.append(text))

    async def run():
        async with _Host(screen).run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            assert screen._read_only
            inp = screen.query_one("Input")
            inp.value = "check it again"
            await pilot.press("enter")
            await pilot.pause()

    asyncio.run(run())
    assert ran == []                                   # nothing was added to ivy's session
    assert len(store.get_goal_history(sid)) == 1

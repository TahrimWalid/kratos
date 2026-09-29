"""/subagent lifecycle (connection-UX WS5/WS6/WS7/WS9): pending codes with a countdown and
regeneration, unpair/forget with fail-safe confirmation, re-pair that replaces on check-in,
the duplicate-name guard, problems-first ordering, and help when an install never checks in.
Real keypresses for every confirmation."""
from __future__ import annotations

import asyncio
import io

from rich.console import Console
from textual.app import App

from kratos.storage.subagent_store import SubAgentStore, _expiry_iso
from kratos.tui_mk2.modals import CommandModal, ConfirmModal
from kratos.tui_mk2.screens import subagent as sa_mod
from kratos.tui_mk2.screens.subagent import SubAgentScreen


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _texts(screen) -> list[str]:
    out = []
    for st in screen.query("#sa-log Static"):
        buf = io.StringIO()
        Console(file=buf, width=160).print(st._Static__content)
        out.append(buf.getvalue())
    return out


def _pair(sa, name, host=None):
    code = sa.create_pairing_code(name=name)["code"]
    return sa.redeem_pairing_code(code, agent_id=name, hostname=host or name, agent_version="0.2.0")["target_id"]


def _select(screen, pred):
    idx = next(i for i, r in enumerate(screen._rows) if pred(r))
    screen.query_one("#sa-table").move_cursor(row=idx)


def _cell(screen, idx, col):
    return str(screen.query_one("#sa-table").get_row_at(idx)[col])


def _run(screen, script, *, fake_wait=None):
    out: dict = {}

    async def run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()
            if fake_wait is not None:
                app.push_screen_wait = fake_wait
            await script(app, pilot)
            out["texts"] = _texts(screen)
            out["screen"] = app.screen

    asyncio.run(run())
    return out


# ---------------------------------------------------------------------------
# WS6 -- unpair / forget
# ---------------------------------------------------------------------------
def test_unpair_real_y_revokes_and_offers_the_uninstall_box(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "target")
        await pilot.press("u")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmModal)
        await pilot.press("y")
        for _ in range(10):
            await pilot.pause()

    out = _run(screen, script)
    assert sa.get_target(tid)["revoked_at"]
    assert isinstance(out["screen"], CommandModal) and "systemctl disable --now kratos-subagent" in out["screen"]._command


def test_unpair_stray_key_declines(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "target")
        await pilot.press("u")
        await pilot.pause()
        await pilot.press("z")  # any key but y = no
        for _ in range(5):
            await pilot.pause()

    _run(screen, script)
    assert sa.get_target(tid)["revoked_at"] is None


def test_forget_only_after_unpair(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "target")
        await pilot.press("f")  # not unpaired yet -> refused with a hint
        await pilot.pause()
        sa.revoke_target(tid)
        screen._refresh()
        _select(screen, lambda r: r["kind"] == "target")
        await pilot.press("f")
        await pilot.pause()
        await pilot.press("y")
        for _ in range(5):
            await pilot.pause()

    out = _run(screen, script)
    assert any("unpair it first" in t for t in out["texts"])
    assert sa.get_target(tid) is None


# ---------------------------------------------------------------------------
# WS5 -- pairing codes
# ---------------------------------------------------------------------------
def test_pending_code_row_counts_down_and_expired_row_says_who_tried(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    fresh = sa.create_pairing_code(name="fresh")["code"]
    old = sa.create_pairing_code(name="late")["code"]
    sa._write("UPDATE subagent_pairing_codes SET expires_at = ?, created_at = ? WHERE code = ?",
              (_expiry_iso(-600), _expiry_iso(-1500), old))  # expired 10 min ago
    sa.record_pairing_attempt(old, "late-box (10.0.0.7)", "pairing code invalid, expired, or already used")
    screen = SubAgentScreen(tmp_path)
    cells: dict = {}

    async def script(app, pilot):
        for i, r in enumerate(screen._rows):
            cells[r["code"]["code"]] = (_cell(screen, i, 0), _cell(screen, i, 5))

    _run(screen, script)
    assert "waiting" in cells[fresh][0] and "expires in 1" in cells[fresh][1]
    assert "expired" in cells[old][0] and "late-box (10.0.0.7) tried it" in cells[old][1]


def test_new_code_replaces_an_expired_one_with_the_same_intent(tmp_path, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    old = sa.create_pairing_code(name="web", replaces_target_id=tid, core_host="100.97.223.65")["code"]
    sa._write("UPDATE subagent_pairing_codes SET expires_at = ? WHERE code = ?", (_expiry_iso(-600), old))
    screen = SubAgentScreen(tmp_path)

    async def no(_modal):  # decline the SSH deploy offer
        return False

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "pending")
        screen.action_new_code()
        for _ in range(15):
            await pilot.pause()

    _run(screen, script, fake_wait=no)
    assert sa.get_pairing_code(old) is None
    [new] = sa.list_pending_pairing_codes()
    assert new["name"] == "web" and new["replaces_target_id"] == tid and new["core_host"] == "100.97.223.65"
    assert (tmp_path / "kratos-subagent-install-web.sh").read_text().count(new["code"]) >= 1


def test_dismiss_code(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="x")["code"]
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "pending")
        await pilot.press("x")
        await pilot.pause()

    _run(screen, script)
    assert sa.get_pairing_code(code) is None


def test_duplicate_name_offers_repair_or_a_distinct_name(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    for choice, check in (
        ("repair", lambda c: c["name"] == "web" and c["replaces_target_id"] == tid),
        ("second", lambda c: c["name"] == "web-2" and c["replaces_target_id"] is None),
    ):
        for c in sa.list_pending_pairing_codes():
            sa.cancel_pairing_code(c["code"])
        answers = iter(["web", choice, "10.0.0.1", False])
        screen = SubAgentScreen(tmp_path)

        async def fake(_modal, it=answers):
            return next(it)

        async def script(app, pilot):
            screen.action_add_server()
            for _ in range(20):
                await pilot.pause()

        _run(screen, script, fake_wait=fake)
        [code] = sa.list_pending_pairing_codes()
        assert check(code), (choice, code)


def test_repair_needs_confirmation_and_replaces_only_on_check_in(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    answers = iter([True, "10.0.0.1", False])
    screen = SubAgentScreen(tmp_path)

    async def fake(_modal):
        return next(answers)

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "target")
        screen.action_repair()
        for _ in range(20):
            await pilot.pause()

    _run(screen, script, fake_wait=fake)
    [code] = sa.list_pending_pairing_codes()
    assert code["replaces_target_id"] == tid and sa.get_target(tid)["revoked_at"] is None  # not yet
    new = sa.redeem_pairing_code(code["code"], agent_id="b", hostname="web", agent_version="0.2.0")
    assert sa.get_target(tid)["revoked_at"] and sa.get_target(new["target_id"])["revoked_at"] is None


# ---------------------------------------------------------------------------
# WS9 ordering + WS10 details + WS3 check-in help
# ---------------------------------------------------------------------------
def test_problems_first_revoked_last(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    ok_id = _pair(sa, "aaa-ok")
    down = _pair(sa, "bbb-down")
    gone = _pair(sa, "ccc-gone")
    sa.register_listener("L", pid=1, host="h", port=1, mode="service", build="b")
    sa.record_connection_open(ok_id, listener_id="L", peer="p")
    sa._write("UPDATE subagent_connections SET last_telemetry_at = connected_at WHERE target_id = ?", (ok_id,))
    sa._write("UPDATE subagent_targets SET last_seen = ? WHERE target_id = ?", ("2020-01-01T00:00:00+00:00", down))
    sa.revoke_target(gone)
    screen = SubAgentScreen(tmp_path)
    order: list = []

    async def script(app, pilot):
        order.extend(r["target"]["name"] for r in screen._rows)

    _run(screen, script)
    assert order == ["bbb-down", "aaa-ok", "ccc-gone"]


def test_details_show_connection_history(tmp_path):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "web")
    sa.register_listener("L", pid=1, host="h", port=1, mode="service", build="b")
    sa.record_connection_open(tid, listener_id="L", peer="10.0.0.9")
    sa.record_connection_closed(tid, listener_id="L", reason="connection lost (ConnectionResetError)")
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        _select(screen, lambda r: r["kind"] == "target")
        await pilot.press("i")
        await pilot.pause()

    out = _run(screen, script)
    joined = "\n".join(out["texts"])
    assert "ConnectionResetError" in joined and "10.0.0.9" in joined


def test_installed_but_never_checked_in_gets_a_diagnosis(tmp_path, monkeypatch):
    sa = SubAgentStore(tmp_path / "kratos.db")
    code = sa.create_pairing_code(name="quiet", core_host="100.97.223.65")["code"]
    screen = SubAgentScreen(tmp_path)

    async def script(app, pilot):
        screen._watched_codes[code] = {"name": "quiet", "host": "100.97.223.65", "deployed_at": 1.0}
        screen._refresh()
        await pilot.pause()

    out = _run(screen, script)
    assert isinstance(out["screen"], CommandModal)
    assert "journalctl -u kratos-subagent" in out["screen"]._command and "100.97.223.65" in out["screen"]._command

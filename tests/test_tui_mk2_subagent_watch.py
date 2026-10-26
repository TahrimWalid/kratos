"""/subagent and continuous detection (C.2): `w` asks first, turns watching on for the
selected machine, offers a ready alert the first time only (confirmed, never created
silently), turns it off again, and tells a machine with an old agent to update -- the
"watching" column says each of those."""
from __future__ import annotations

import asyncio

from kratos.agent import triggers as TR
from kratos.detect import live as L
from kratos.storage.subagent_store import SubAgentStore
from kratos.tui_mk2.screens.subagent import SubAgentScreen

from tests.test_tui_mk2_subagent import _Host, _log_texts


def _pair(sa: SubAgentStore, name: str, version: str) -> str:
    code = sa.create_pairing_code(name=name)["code"]
    tid = sa.redeem_pairing_code(code, agent_id=name, hostname=name, agent_version=version)["target_id"]
    sa.record_link(tid, mode="tls-pinned", pin_version=1)
    return tid


def _drive(tmp_path, monkeypatch, answers: list, *, version: str = "0.9.0", presses: int = 1):
    sa = SubAgentStore(tmp_path / "kratos.db")
    tid = _pair(sa, "db-01", version)
    screen = SubAgentScreen(tmp_path)
    out: dict = {"asked": []}

    async def run():
        app = _Host(screen)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            it = iter(answers)

            async def canned(modal):
                out["asked"].append(getattr(modal, "_title", None) or type(modal).__name__)
                return next(it)

            monkeypatch.setattr(app, "push_screen_wait", canned)
            for _ in range(presses):
                screen.action_watch()
                await app.workers.wait_for_complete()
                await pilot.pause()
            screen._refresh()
            await pilot.pause()
            table = screen.query_one("#sa-table")
            out["cell"] = str(table.get_row_at(0)[7])
            out["texts"] = _log_texts(screen)

    asyncio.run(run())
    return tid, out


def test_w_turns_watching_on_after_asking_and_offers_one_ready_alert(tmp_path, monkeypatch):
    tid, out = _drive(tmp_path, monkeypatch, [True, True])
    assert L.pack_state(tmp_path, tid)["enabled"] is True
    assert len(out["asked"]) == 2                       # "watch it?" then "alert me on HIGH and CRITICAL?"
    triggers, _errs = TR.list_triggers(tmp_path)
    made = [x for x in triggers if x.name == "live-high-detections"]
    assert made and made[0].min_severity == "high" and made[0].only_new_or_reopened and made[0].cooldown_minutes == 15
    assert made[0].action == "notify"
    assert "starting" in out["cell"]                    # turned on; the agent hasn't confirmed yet
    assert any("continuous detection on" in x for x in out["texts"])


def test_declining_changes_nothing_and_the_alert_is_offered_only_once(tmp_path, monkeypatch):
    tid, out = _drive(tmp_path, monkeypatch, [False])
    assert (L.pack_state(tmp_path, tid) or {}).get("enabled") is not True
    assert "off" in out["cell"]
    # on (alert declined), off, on again: the alert is not offered a second time
    tid2, out2 = _drive(tmp_path / "b", monkeypatch, [True, False, True, True], presses=3)
    assert len(out2["asked"]) == 4                      # watch? alert? / stop? / watch? (no second alert question)
    assert TR.list_triggers(tmp_path / "b")[0] == []
    assert L.pack_state(tmp_path / "b", tid2)["enabled"] is True


def test_an_old_agent_is_told_to_update_and_nothing_is_asked(tmp_path, monkeypatch):
    tid, out = _drive(tmp_path, monkeypatch, [], version="0.8.0")
    assert out["asked"] == []
    assert L.pack_state(tmp_path, tid) is None
    assert "update to watch" in out["cell"]
    assert any("update the agent to watch continuously" in x for x in out["texts"])


def test_the_alert_offer_says_when_phone_notifications_are_not_set_up(tmp_path, monkeypatch):
    """Phase C audit: the ready alert was offered (and created) with notifications off, so a
    person could wait for alerts that could never reach them."""
    from kratos import kratos_config

    monkeypatch.setattr(kratos_config, "NTFY_TOPIC", "")
    seen: list = []
    real = SubAgentScreen._offer_first_trigger

    async def spy(self, target_id):
        orig = self.app.push_screen_wait

        async def capture(modal):
            seen.append(str(getattr(modal, "_body", "") or getattr(modal, "_message", "") or vars(modal)))
            return await orig(modal)

        self.app.push_screen_wait = capture
        try:
            return await real(self, target_id)
        finally:
            self.app.push_screen_wait = orig

    monkeypatch.setattr(SubAgentScreen, "_offer_first_trigger", spy)
    tid, out = _drive(tmp_path, monkeypatch, [True, True])
    assert seen and "not set up yet" in seen[0]
    assert any("Phone notifications are off" in x for x in out["texts"])

"""D.4 headless pilots: /channels lists ntfy built in plus added channels with their state,
the guided add states what is sent before saving and records who added it, and /outbox
shows dead letters with their reason and sends one again on "retry now"."""
from __future__ import annotations

import asyncio

from textual.app import App

from kratos import kratos_config as kc
from kratos.lifecycle.decide import Actor
from kratos.outbox import alerts as A
from kratos.outbox import config as C
from kratos.outbox import store as S
from kratos.outbox import worker as W
from kratos.outbox.store import Outcome
from kratos.tui_mk2.screens.channels import ChannelsScreen, OutboxScreen

ACTOR = Actor(user="tester", interface="cli")


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _table_cells(screen, table_id):
    t = screen.query_one(table_id)
    return [[str(c) for c in t.get_row_at(i)] for i in range(t.row_count)]


def test_channels_lists_ntfy_and_added_channels(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    C.add_channel(tmp_path, name="soc", kind="webhook", config={"url": "https://soc.example/in"},
                  scopes=["alerts", "findings"], actor=ACTOR)

    async def go():
        screen = ChannelsScreen(tmp_path)
        async with _Host(screen).run_test(size=(180, 40)) as pilot:
            await pilot.pause()
            rows = _table_cells(screen, "#ch-table")
            assert [r[0] for r in rows] == ["ntfy", "soc"]
            assert rows[0][4] == "not set up" and rows[1][4] == "on"
    asyncio.run(go())


def test_the_guided_add_shows_what_is_sent_and_records_the_person(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    answers = iter(["webhook", "siem", "https://siem.example/in", "", "findings,events", "ocsf", "high", True, True,
                    None])
    seen: list = []

    async def go():
        screen = ChannelsScreen(tmp_path)
        async with _Host(screen).run_test(size=(180, 40)) as pilot:
            async def fake_wait(modal):
                seen.append(modal)
                return next(answers)

            pilot.app.push_screen_wait = fake_wait
            await pilot.pause()
            await pilot.press("a")
            for _ in range(20):
                await pilot.pause()
            ch = C.get_channel(tmp_path, "siem")
            assert ch is not None and ch.scopes == ("findings", "events") and ch.format == "ocsf"
            assert ch.filters.min_severity == "high" and ch.mask_values
            assert C.history(tmp_path, "siem")[0]["interface"] == "tui"
            confirm = [m for m in seen if type(m).__name__ == "ConfirmModal"][-1]
            assert "Sends to https://siem.example/in" in str(confirm._body)
            assert "placeholders" in str(confirm._body)
            assert C.secret_names(tmp_path, "siem") == ["signing_secret"]
    asyncio.run(go())


def test_outbox_shows_a_dead_letter_and_retry_now_sends_it(tmp_path, monkeypatch):
    monkeypatch.setattr(kc, "NTFY_TOPIC", None)
    C.add_channel(tmp_path, name="soc", kind="webhook", config={"url": "https://soc.example/in"}, scopes=["alerts"],
                  actor=ACTOR)
    answer = {"o": Outcome(False, False, "HTTP 400: missing field", 400)}
    monkeypatch.setattr(W, "sender_for", lambda kind: lambda d, ch, s, dd: answer["o"])
    A.enqueue_alert("HIGH on web-01", deliver=["soc"], data_dir=tmp_path)
    W.flush(tmp_path, label="t")

    async def go():
        screen = OutboxScreen(tmp_path, status="dead")
        async with _Host(screen).run_test(size=(180, 40)) as pilot:
            await pilot.pause()
            rows = _table_cells(screen, "#ob-table")
            assert len(rows) == 1 and rows[0][3] == "dead" and "missing field" in rows[0][6]

            async def yes(modal):
                return True

            pilot.app.push_screen_wait = yes
            await pilot.press("r")
            for _ in range(5):
                await pilot.pause()
    asyncio.run(go())
    answer["o"] = Outcome(True, False)
    W.flush(tmp_path, label="t")
    with S.opened(tmp_path) as conn:
        assert [r["status"] for r in S.listing(conn)] == ["delivered"]

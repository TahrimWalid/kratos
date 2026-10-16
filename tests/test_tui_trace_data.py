"""TUI /trace and /data (docs/phaseB/B.5 §5.1, §5.3, §5.4): the last run's record, a
list, and the stored-data inventory with a confirmed prune."""
from __future__ import annotations

import asyncio
import json
import os
import time

from kratos.run_context import run_scope
from kratos.trace import recorder
from kratos.tui_mk2.modals import ConfirmModal
from tests.test_tui_mk2_session import _Host, _make_screen


def _text(log) -> str:
    return "\n".join(str(getattr(line, "text", line)) for line in log.lines)


def _record(dd, session_id, name="investigation", hostile=""):
    with run_scope("interactive", session_id=session_id):
        with recorder.run_trace(name, dd, name=name + hostile) as tr:
            recorder.event("guard", "dismissive_verdict_contradiction", guard="dismissive_verdict_contradiction",
                           action="rejected", correction="REJECTED" + hostile)
    return tr


def test_trace_shows_this_sessions_last_run_and_a_list(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    _record(tmp_path, "another-session")
    mine = _record(tmp_path, sid, hostile="\x1b[2J‮")

    async def _run():
        async with _Host(screen).run_test() as pilot:
            await pilot.pause()
            log = screen.query_one("#transcript")
            screen._dispatch_slash("/trace")
            await pilot.pause()
            shown = _text(log)
            screen._dispatch_slash("/trace list")
            await pilot.pause()
            listed = _text(log)[len(shown):]
            screen._dispatch_slash("/trace nope")
            await pilot.pause()
            return shown, listed, _text(log)

    shown, listed, last = asyncio.run(_run())
    assert f"Run {mine.trace_id}" in shown and "dismissive_verdict_contradiction" in shown
    assert "\x1b" not in shown and "‮" not in shown
    assert mine.trace_id[:12] in listed and listed.count("investigation") == 1   # this session's only
    assert "No run record 'nope'" in last


def test_data_lists_the_inventory(tmp_path, monkeypatch):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)

    async def _run():
        async with _Host(screen).run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            screen._dispatch_slash("/data")
            for _ in range(50):
                await pilot.pause()
                if "deletes nothing on its own" in _text(screen.query_one("#transcript")):
                    break
            return _text(screen.query_one("#transcript"))

    out = asyncio.run(_run())
    assert "What Kratos keeps" in out and "Sessions and conversations" in out and "Run records" in out
    assert "deletes nothing on its own" in out


def _old_trace(dd):
    d = dd / "traces" / "2026-01-01"
    d.mkdir(parents=True)
    p = d / "old.json"
    p.write_text(json.dumps({"run_id": "old"}))
    t = time.time() - 200 * 86400
    os.utime(p, (t, t))
    return p


def _prune(tmp_path, monkeypatch, answer: bool):
    store, sid, screen = _make_screen(tmp_path, monkeypatch)
    old = _old_trace(tmp_path)
    asked = []

    async def _run():
        app = _Host(screen)
        async with app.run_test() as pilot:
            await pilot.pause()

            async def fake_wait(modal):
                asked.append(modal)
                return answer
            app.push_screen_wait = fake_wait
            screen._dispatch_slash("/data prune traces 90")
            for _ in range(50):
                await pilot.pause()
                txt = _text(screen.query_one("#transcript"))
                if "Removed" in txt or "Nothing deleted" in txt:
                    break
            return _text(screen.query_one("#transcript"))

    return asyncio.run(_run()), old, asked


def test_data_prune_asks_first_and_declining_deletes_nothing(tmp_path, monkeypatch):
    out, old, asked = _prune(tmp_path, monkeypatch, False)
    assert len(asked) == 1 and isinstance(asked[0], ConfirmModal)
    assert old.exists() and "Nothing deleted" in out
    from kratos import dataprune

    assert dataprune.history(tmp_path) == []


def test_data_prune_confirmed_deletes_and_records(tmp_path, monkeypatch):
    out, old, asked = _prune(tmp_path, monkeypatch, True)
    assert len(asked) == 1 and not old.exists() and "Removed 1 run records" in out
    from kratos import dataprune

    (row,) = dataprune.history(tmp_path)
    assert row["category"] == "traces" and row["actor"].endswith("via tui")

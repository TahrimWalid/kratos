"""E.4 in /findings: a finding's reputation lines in its detail and a short tag in the list
(an annotation, the severity unchanged); `l` sends nothing while online lookups are off."""
from __future__ import annotations

import asyncio
import io
import time
import uuid

from rich.console import Console
from textual.app import App

from kratos.lifecycle import apply as A
from kratos.lifecycle.coverage import nothing
from kratos.run_context import RunContext
from kratos.tui_mk2.modals import InfoModal
from kratos.tui_mk2.screens.findings import FindingsScreen

T = "10.0.0.5"
SHA = "ab" * 32


class _Host(App):
    def __init__(self, screen):
        super().__init__()
        self._screen = screen

    def on_mount(self):
        self.push_screen(self._screen)


def _seed(tmp_path):
    rep = [{"path": "/tmp/.b", "sha256": SHA, "verdict": "known_good", "label": "probably known-good (CIRCL)",
            "note": "a known program in an unusual place or with unusual permissions is still a risk",
            "sources": [{"source": "circl", "date": "2026-11-11"}], "checked_at": "2026-11-11T10:00:00+00:00"}]
    bad = [dict(rep[0], path="/tmp/m", verdict="known_bad", label="known-bad (MalwareBazaar)", note="")]
    r = RunContext(run_id=uuid.uuid4().hex, source="interactive", target=T, session_id=None, started_at=time.time())
    A.apply_run([{"id": "PERSIST-003", "title": "A setuid program", "severity": "high", "evidence": ["e"],
                  "subject": "", "entities": [f"/tmp/.b#{SHA[:12]}"], "reputation": rep},
                 {"id": "HASH-001", "title": "A file MalwareBazaar lists", "severity": "high", "evidence": ["e"],
                  "subject": "/tmp/m", "entities": [f"/tmp/m#{SHA[:12]}"], "reputation": bad}],
                target=T, coverage=nothing(), run=r, data_dir=tmp_path)


def _text(content) -> str:
    buf = io.StringIO()
    Console(file=buf, width=200).print(content)
    return buf.getvalue()


def test_reputation_in_the_detail_and_list(tmp_path):
    asyncio.run(_reputation_in_the_detail_and_list(tmp_path))


async def _reputation_in_the_detail_and_list(tmp_path):
    _seed(tmp_path)
    screen = FindingsScreen(tmp_path, target=T)
    app = _Host(screen)
    async with app.run_test(size=(200, 40)) as pilot:
        await pilot.pause()
        by = {r["rule_id"]: r for r in screen._rows}
        assert by["PERSIST-003"]["severity"] == "high"                    # known-good never lowers it
        assert screen._reputation_tag(by["HASH-001"]) == " [known-bad (MalwareBazaar)]"
        assert screen._reputation_tag(by["PERSIST-003"]) == ""             # nothing to flag in the list
        idx = [r["rule_id"] for r in screen._rows].index("PERSIST-003")
        screen.query_one("#fd-table").move_cursor(row=idx)
        screen.action_details()
        await pilot.pause()
        modal = app.screen
        assert isinstance(modal, InfoModal)
        body = _text(modal._body) if hasattr(modal, "_body") else ""
        assert "probably known-good (CIRCL)" in body and "still a risk" in body
        await pilot.press("escape")
        await pilot.pause()
        screen.action_lookup_online()
        await pilot.pause()
        assert "online hash lookups are off, so nothing was sent" in "".join(
            _text(getattr(s, "_Static__content", "")) for s in screen.query("#fd-log Static")).lower()

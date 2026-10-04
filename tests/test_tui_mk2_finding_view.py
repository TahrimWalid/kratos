"""Background findings are folded, not re-listed in every answer (seen live: sudo
activity, an old burst and privileged accounts re-listed for 'is there any malware?')."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from kratos.tui_mk2 import finding_view as FV

T0 = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc).timestamp()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def _f(fid, sev, evidence, collected):
    return {"id": fid, "severity": sev, "title": fid, "evidence": evidence, "collected_at": _iso(collected)}


def test_first_answer_shows_findings_from_this_investigation():
    shown: dict = {}
    full, folded = FV.plan([_f("AUTH-003", "info", ["sudo sessions opened: 125"], T0 + 5)], shown, T0)
    assert [w for _f, w in full] == ["new"] and folded == []


def test_next_answer_folds_what_is_unchanged_but_shows_real_changes():
    shown: dict = {}
    burst = ["Bursts of failed SSH logins: 1", "Source IP(s) behind this activity: 203.0.113.52 (4 events)."]
    FV.plan([_f("AUTH-003", "info", ["sudo sessions opened: 125"], T0 + 5),
             _f("CORR-SSH-001", "high", burst + ["Time window: last 24 hours"], T0 + 5)], shown, T0)
    later = T0 + 600
    full, folded = FV.plan([
        _f("AUTH-003", "info", ["sudo sessions opened: 311"], later + 5),               # a count creeping up
        _f("CORR-SSH-001", "high", burst + ["Time window: last hour"], later + 5),      # only the window differs
    ], shown, later)
    assert full == [] and [w for _f, w in folded] == ["unchanged", "unchanged"]
    new_ip = ["Bursts of failed SSH logins: 2", "Source IP(s) behind this activity: 198.51.100.7 (9 events)."]
    full, _ = FV.plan([_f("CORR-SSH-001", "high", new_ip, later + 9)], shown, later)
    assert [w for _f, w in full] == ["updated"]                                         # a new attacker is news


def test_data_from_an_earlier_check_is_folded_unless_urgent():
    shown: dict = {}
    full, folded = FV.plan([_f("PRIV-004", "info", ["root: UID 0"], T0 - 3600),
                            _f("CORR-SSH-001", "high", ["burst"], T0 - 3600)], shown, T0)
    assert [(f["id"], w) for f, w in full] == [("CORR-SSH-001", "earlier")]           # never fold unseen high
    assert [(f["id"], w) for f, w in folded] == [("PRIV-004", "earlier")]
    line = FV.folded_summary(folded)
    assert line == ("Also on record — from earlier checks, not re-checked now: PRIV-004 (info). "
                    "/report shows them in full.")


def test_a_second_correlation_in_a_session_folds_into_one_line(tmp_path, monkeypatch):
    from textual.app import App

    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    class _Host(App):
        def on_mount(self):
            self.push_screen(screen)

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    screen = SessionScreen(store, tmp_path, store.create_session(["10.0.0.1"], "m"), ["10.0.0.1"], "")
    step = {"tool": "correlate_findings", "observation": {"status": "ok", "result": {
        "findings": [{"id": "AUTH-003", "severity": "info", "title": "Sudo session activity observed",
                      "evidence": ["sudo sessions opened: 3"], "recommendation": [], "collected_at": None}]}}}

    async def run():
        app = _Host()
        async with app.run_test() as pilot:
            await pilot.pause()
            screen._set_busy(True)
            for _ in range(2):
                await asyncio.to_thread(screen._render_step, step)
                await pilot.pause()
            screen._set_busy(False)
            log = screen.query_one("#transcript")
            return "\n".join("".join(seg.text for seg in strip) for strip in log.lines)

    text = asyncio.run(run())
    assert text.count("Sudo session activity observed") == 1
    assert "Also on record — unchanged since shown above: AUTH-003 (info)" in text

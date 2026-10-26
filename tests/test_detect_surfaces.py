"""Where a detection-rule (SIGMA-*) finding reaches a person, the rule's author goes with
it (Detection Rule License 1.1): the answer's findings block, the TUI and CLI finding
panels, `kratos findings show`, the Markdown report, scheduled-run and trigger
notifications, MCP finding states, the chat server's /findings. Plus the `kratos
detect` command, `kratos events --rule`, /doctor, the /detect screen, and that the
model's digest never calls a Sigma finding's subject a "package"."""
from __future__ import annotations

import asyncio
import io
import json
import time
from pathlib import Path

from rich.console import Console

from kratos import finding_facts
from kratos.detect import pack as P
from kratos.detect import run as R
from kratos.detect import store as ST
from kratos.detect.findings import credit_line
from kratos.events.store import EventStore
from kratos.run_context import run_scope
from tests.test_detect_pass import A, CHATTR_AUDITD, NOW, exec_event

AUTHOR = P.shipped().pack.by_id[CHATTR_AUDITD].meta["author"]


def _render(renderable) -> str:
    buf = io.StringIO()
    Console(file=buf, width=220, color_system=None).print(renderable)
    return buf.getvalue()


def _report(tmp_path, monkeypatch, *, severity_high: bool = False):
    """A real pass + findings report for machine A with one SIGMA finding."""
    from kratos import kratos_config
    from kratos.adapters import findings_engine as FE

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: A)
    EventStore(tmp_path / "kratos.db").add([exec_event(A, NOW - 60, "/usr/bin/chattr", "chattr", "-i", "/etc/x")])
    with run_scope("cli", target=A):
        R.run_pass(A, tmp_path)
        out_json, out_md = FE.write_findings_report(data_dir=tmp_path)
    data = json.loads(Path(out_json).read_text())
    finding = next(f for f in data["findings"] if f["id"] == CHATTR_AUDITD)
    if severity_high:
        finding = dict(finding, severity="high")
    return finding, data, Path(out_md).read_text()


def test_credit_line_names_the_author_and_licence():
    f = {"id": "SIGMA-00000000", "detection_rule": {"author": "Alice Example", "license": "DRL-1.1", "matches": 3}}
    assert credit_line(f) == "3 matches; rule by Alice Example (Sigma, DRL-1.1)"
    assert credit_line({"id": "CORR-SSH-001"}) is None


def test_report_finding_and_markdown_carry_the_author(tmp_path, monkeypatch):
    finding, _data, md = _report(tmp_path, monkeypatch)
    assert finding["detection_rule"]["author"] == AUTHOR
    assert f"by {AUTHOR}" in md and "DRL-1.1" in md


def test_answer_block_shows_the_author_and_never_says_package(tmp_path, monkeypatch):
    finding, _data, _md = _report(tmp_path, monkeypatch, severity_high=True)
    block = finding_facts.answer_block([finding], analysis="")
    assert CHATTR_AUDITD in block and f"rule by {AUTHOR}" in block
    assert "checked on schedule, not continuously" in block
    assert "package" not in block
    assert "package" not in finding_facts.model_line(finding)


def test_tui_and_cli_finding_panels_show_the_author(tmp_path, monkeypatch):
    from kratos.agent import console as C
    from kratos.tui_mk2 import render

    finding, _data, _md = _report(tmp_path, monkeypatch)
    buf = io.StringIO()
    C.render_finding(Console(file=buf, width=200, color_system=None), finding)
    assert f"rule by {AUTHOR}" in buf.getvalue()
    assert f"rule by {AUTHOR}" in _render(render.finding_panel(finding))


def test_findings_show_and_lifecycle_rows_carry_the_rule(tmp_path, monkeypatch, capsys):
    from kratos.cli import app
    from kratos.lifecycle import query as Q
    from kratos.mcp_server import _finding_states_for

    _report(tmp_path, monkeypatch)
    rows = [r for r in Q.list_findings(tmp_path, target=A, state="all") if r["rule_id"] == CHATTR_AUDITD]
    assert rows and rows[0]["detection_rule"]["author"] == AUTHOR
    mcp_rows = [r for r in _finding_states_for(tmp_path, A, "all", 100) if r["rule_id"] == CHATTR_AUDITD]
    assert mcp_rows[0]["detection_rule"]["author"] == AUTHOR
    assert app.main(["--data-dir", str(tmp_path), "findings", "show", rows[0]["finding_key"]]) == 0
    assert f"by {AUTHOR}" in capsys.readouterr().out


def test_scheduled_and_trigger_notifications_name_the_author(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    from kratos.agent import scheduled_run as SR
    from kratos.agent import trigger_eval as TE
    from kratos.agent import triggers as TG

    finding, _data, _md = _report(tmp_path, monkeypatch, severity_high=True)
    msg = SR._build_message(schedule_name="nightly", target=A, status="ok", findings=[finding], report_path=None,
                            error=None)
    assert f"{CHATTR_AUDITD}" in msg and f"rule by {AUTHOR}" in msg
    trig = TG.Trigger(name="sigma", min_severity=None, finding_id=CHATTR_AUDITD, target=None, action="notify",
                      cooldown_minutes=60, created_at=None, path=tmp_path / "t.toml")
    text, _worst, ids, _inv = TE._build_body(tmp_path, trig, [finding], A, datetime.now(timezone.utc), False, None)
    assert ids == [CHATTR_AUDITD] and f"rule by {AUTHOR}" in text and text.startswith("HIGH on ")


def test_chat_server_findings_text_names_the_author(tmp_path, monkeypatch):
    from kratos.serve import openai_routes

    _report(tmp_path, monkeypatch)
    text = openai_routes._findings_text(A, tmp_path)
    assert CHATTR_AUDITD in text and f"rule by {AUTHOR}" in text


# ---------------------------------------------------------------------------- commands
def test_kratos_detect_rules_run_and_disable(tmp_path, monkeypatch, capsys):
    from kratos import kratos_config
    from kratos.cli import app

    monkeypatch.setattr(kratos_config, "get_active_target", lambda: A)
    assert app.main(["--data-dir", str(tmp_path), "detect", "rules"]) == 0
    out = capsys.readouterr().out
    assert CHATTR_AUDITD in out and AUTHOR in out and "Detection Rule License 1.1" in out
    assert app.main(["--data-dir", str(tmp_path), "detect", "rules", "--skipped"]) == 0
    out = capsys.readouterr().out
    assert "regular expression" in out and "experimental" in out
    assert app.main(["--data-dir", str(tmp_path), "detect", "rules", "disable", CHATTR_AUDITD, "--target", A]) == 1
    assert "--reason" in capsys.readouterr().err
    assert app.main(["--data-dir", str(tmp_path), "detect", "rules", "disable", CHATTR_AUDITD, "--target", A,
                     "--reason", "backups toggle immutable flags"]) == 0
    assert f"{CHATTR_AUDITD} is now off for {A}" in capsys.readouterr().out
    assert CHATTR_AUDITD in ST.disabled_rules(tmp_path, A)
    EventStore(tmp_path / "kratos.db").add([exec_event(A, time.time() - 60, "/usr/sbin/userdel", "userdel", "x")])
    assert app.main(["--data-dir", str(tmp_path), "detect", "run", "--target", A]) == 0
    out = capsys.readouterr().out
    assert "SIGMA-08F26069" in out and "not continuously" in out and CHATTR_AUDITD not in out
    assert app.main(["--data-dir", str(tmp_path), "events", "--target", A, "--rule", "SIGMA-08F26069"]) == 0
    assert "process_started" in capsys.readouterr().out


def test_kratos_detect_import_compiles_a_persons_own_rule(tmp_path, capsys):
    import pytest
    pytest.importorskip("sigma.collection")
    from kratos.cli import app

    rule = Path(tmp_path / "mine.yml")
    rule.write_text(
        "title: Test user runs the doc tool\nid: 7a7a7a7a-0000-4000-8000-000000000001\nstatus: experimental\n"
        "author: Alice Example\nlevel: high\nlogsource:\n  product: linux\n  category: process_creation\n"
        "detection:\n  selection:\n    Image|endswith: /kratos-doc-tool\n  condition: selection\n"
        "tags:\n  - attack.execution\n  - attack.t1059.004\n")
    bad = Path(tmp_path / "regex.yml")
    bad.write_text(
        "title: A regex rule\nid: 7b7b7b7b-0000-4000-8000-000000000002\nstatus: test\nauthor: Bob\nlevel: high\n"
        "logsource:\n  product: linux\n  category: process_creation\n"
        "detection:\n  selection:\n    CommandLine|re: 'a.*b'\n  condition: selection\n")
    data = tmp_path / "data"
    assert app.main(["--data-dir", str(data), "detect", "import", str(tmp_path), "--name", "mine"]) == 0
    out = capsys.readouterr().out
    assert "Imported 1 rule(s) as local-mine v1" in out and "regular expression" in out
    loaded = P.load(data)
    assert [lp.pack_id for lp in loaded.loaded] == ["sigma-linux", "local-mine"]
    rule_meta = loaded.rule("SIGMA-7A7A7A7A")[1].meta
    assert rule_meta["author"] == "Alice Example" and rule_meta["samples"]["match"]
    assert app.main(["--data-dir", str(data), "detect", "import", str(rule), "--name", "mine"]) == 0
    assert P.load(data).loaded[1].version == 2


def test_doctor_row_reports_the_pack_and_last_runs(tmp_path):
    from kratos.agent.doctor import run_diagnostics

    rows = [r for r in run_diagnostics(tmp_path) if r["check"] == "detection rules"]
    assert rows and "sigma-linux v1" in rows[0]["detail"] and "not run on any machine yet" in rows[0]["detail"]
    R.run_pass(A, tmp_path, now=NOW)
    rows = [r for r in run_diagnostics(tmp_path) if r["check"] == "detection rules"]
    assert A in rows[0]["detail"] and rows[0]["status"] == "pass"


# ---------------------------------------------------------------------------- /detect
def test_detect_screen_lists_rules_details_and_turns_one_off(tmp_path):
    asyncio.run(_detect_screen(tmp_path))


async def _detect_screen(tmp_path):
    from textual.app import App

    from kratos.tui_mk2.modals import InfoModal
    from kratos.tui_mk2.screens.detect import DetectScreen

    R.run_pass(A, tmp_path, now=NOW)
    screen = DetectScreen(tmp_path, target=A)
    answers: list = []

    class Host(App):
        async def push_screen_wait(self, modal):        # the reason prompt answers itself
            return answers.pop(0) if answers else None

        def on_mount(self):
            self.push_screen(screen)

    app = Host()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.pause()
        ids = [r["meta"]["id"] for r in screen._rows]
        assert len(ids) == len(P.shipped().pack.rules) and CHATTR_AUDITD in ids
        banner = _render(screen.query_one("#dt-banner")._Static__content)
        assert "sigma-linux v1" in banner and "not continuously" in banner and "last pass" in banner
        screen.query_one("#dt-table").move_cursor(row=ids.index(CHATTR_AUDITD))
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, InfoModal)
        text = "".join(_render(getattr(s, "_Static__content", "")) for s in app.screen.query("Static"))
        assert AUTHOR in text and "DRL-1.1" in text
        await pilot.press("escape")
        await pilot.pause()
        answers.append("noisy on build servers")
        await pilot.press("x")
        await pilot.pause()
        await pilot.pause()
        assert CHATTR_AUDITD in ST.disabled_rules(tmp_path, A)
        assert not next(r for r in screen._rows if r["meta"]["id"] == CHATTR_AUDITD)["on"]
        await pilot.press("s")
        await pilot.pause()
        assert screen._skipped_view and len(screen._rows) == len(P.skipped(P.shipped()))


def test_importing_a_counting_correlation_groups_by_the_attackers_address(tmp_path, capsys):
    import pytest
    pytest.importorskip("sigma.collection")
    from kratos.cli import app
    from tests.test_detect_pass import failed_login

    fixture = Path(__file__).parent / "fixtures" / "sigma_import" / "ssh_guessing_burst.yml"
    assert app.main(["--data-dir", str(tmp_path), "detect", "import", str(fixture), "--name", "burst"]) == 0
    rule = P.load(tmp_path).rule("SIGMA-5A1F0C3E")[1].meta
    assert rule["count"] == {"window_seconds": 300, "group_by": "source.ip", "op": "gte", "threshold": 4}
    assert rule["samples"]["match"][0]["source.ip"] == "192.0.2.1"
    EventStore(tmp_path / "kratos.db").add([failed_login(A, NOW - 200 + i, "203.0.113.66") for i in range(4)])
    hits = [m for m in R.run_pass(A, tmp_path, now=NOW).matches if m["rule_id"] == "SIGMA-5A1F0C3E"]
    assert [m["group"] for m in hits] == ["203.0.113.66"]


def test_the_couldnt_check_tag_for_a_rule_match_fits_the_answer_block():
    from kratos.triage import registry

    registry._ensure_loaded()
    reason = registry.verifier_for(CHATTR_AUDITD).reason
    assert len(f"couldn't check: {reason}") <= 90 and "events --rule" in reason

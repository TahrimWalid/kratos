"""E.3 on every surface: CLI, TUI, MCP, chat, digest, OCSF, the incident bundle, a backup
restored on a new computer, and the history generator (spec §3.12, §8)."""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


from _baseline_history import END, G, machine, normal_days, raised, run, write
from kratos.lifecycle.decide import Actor

OWNER = Actor("owner", "cli", user_id="owner")
ROOT = Path(__file__).resolve().parents[1]


def _ready(tmp_path, plants=("new_source", "listener")):
    m = machine(0)
    normal_days(m)
    for p in plants:
        m.plant(p, END)
    data = write(tmp_path / "home", [m])
    run(data, m.target, now=time.time())          # deviations "today" for the surfaces that check freshness
    return m, data


# ---------------------------------------------------------------- CLI
def _cli(home: Path, *args: str) -> subprocess.CompletedProcess:
    import os

    env = {**os.environ, "KRATOS_HOME": str(home), "PYTHONPATH": str(ROOT / "src")}
    env.pop("KRATOS_DATA_DIR", None)
    return subprocess.run([sys.executable, "-m", "kratos", "baseline", *args], capture_output=True, text=True,
                          env=env, timeout=120)


def test_cli_show_accept_and_reset_confirmation(tmp_path):
    m, data = _ready(tmp_path)
    out = _cli(data.parent, "show", m.target)
    assert out.returncode == 0, out.stderr
    assert "BASE-001  where each account signs in from: learned" in out.stdout
    assert "deploy: 192.0.2.0/24" in out.stdout and "Deviations today:" in out.stdout
    js = json.loads(_cli(data.parent, "show", m.target, "--json").stdout)
    assert js["machine"] == m.target and {d["name"] for d in js["dims"]} >= {"login_source", "listener"}
    ok = _cli(data.parent, "accept", m.target, "login_source", "deploy", "192.0.2.0/24", "--reason", "vpn")
    assert ok.returncode == 0 and "is normal on" in ok.stdout, ok.stderr
    no = _cli(data.parent, "reset", m.target)
    assert no.returncode == 2 and "--yes" in no.stderr
    bad = _cli(data.parent, "accept", m.target, "nope", "a", "b")
    assert bad.returncode != 0


# ---------------------------------------------------------------- MCP and chat
def test_mcp_baseline_is_read_only_and_scoped(tmp_path, monkeypatch):
    import kratos.mcp_server as mcp_server

    m, data = _ready(tmp_path)
    monkeypatch.setattr(mcp_server, "_data_dir", data)
    doc = mcp_server.kratos_baseline(target=m.target)
    kinds = {k["kind"]: k for k in doc["kinds"]}
    assert kinds["login_source"]["status"] == "active"
    assert any(d["rule"] == "BASE-001" for d in doc["deviations_today"])
    assert "still learning" in doc["note"].lower() or "Still learning" in doc["note"]


def test_chat_baseline_command(tmp_path):
    from kratos.serve import openai_routes

    m, data = _ready(tmp_path)
    text = openai_routes.command_reply("/baseline", target=m.target, data_dir=data)
    assert text and "What's normal on" in text and "BASE-001" in text
    group = openai_routes.command_reply("/baseline", target="@lab", data_dir=data)
    assert "per machine" in group


# ---------------------------------------------------------------- the collection check and the digest
def test_check_summary_has_no_names(tmp_path):
    import kratos.collect.checks  # noqa: F401
    from kratos.baseline import record
    from kratos.collect.registry import get

    m, data = _ready(tmp_path)
    chk = get("baseline")
    assert chk is not None and chk.after == ("log_sync", "live_response", "detect") and chk.cost == "quick"
    doc = record.load(record.path_for(data, m.target))
    line = record.summary_line(doc)
    assert "deviation" in line and "deploy" not in line and "192.0.2" not in line


def test_digest_lists_base_findings_by_rule_text(tmp_path):
    from kratos import finding_facts

    for rid in ("BASE-001", "BASE-002", "BASE-003", "BASE-004", "BASE-005", "BASE-006", "BASE-007", "BASE-008"):
        assert rid in finding_facts.RULE_TEXT
    from kratos.baseline.findings import TITLES

    for t in TITLES.values():
        assert not re.search(r"'[^']+'", t)          # no quoted names in any title


# ---------------------------------------------------------------- OCSF
def test_base_findings_are_ocsf_detection_findings():
    from kratos.outbox.formats import ocsf as F

    for rid in ("BASE-001", "BASE-002", "BASE-003", "BASE-004", "BASE-005", "BASE-006", "BASE-008"):
        assert F.class_of(rid) == F.DETECTION_FINDING, rid


# ---------------------------------------------------------------- export (D.6)
def test_export_includes_the_baseline(tmp_path):
    from kratos.export import create as C
    from kratos.export.scope import ExportRequest

    m, data = _ready(tmp_path)
    from kratos.baseline import decide as BD

    BD.accept(data, m.target, "login_source", "deploy", "192.0.2.0/24", actor=OWNER, reason="vpn")
    me = Actor(user="owner", interface="cli")
    r = C.create(data, ExportRequest(machines=[m.target], start=time.time() - 86400 * 30, end=time.time() + 60,
                                     variant="full"), me)
    files = {p.relative_to(r.bundle).as_posix() for p in r.bundle.rglob("*") if p.is_file()}
    gen = [f for f in files if f.endswith("/baseline.json")]
    assert gen and any("baseline_runs/" in f for f in files)
    assert all(f in (r.bundle / "SHA256SUMS").read_text() for f in gen)
    v = json.loads((r.bundle / gen[0]).read_text())
    assert v["decisions"][0]["by"] == "owner"
    red = C.create(data, ExportRequest(machines=[m.target], start=time.time() - 86400 * 30, end=time.time() + 60,
                                       variant="redacted"), me)
    text = "\n".join(p.read_text(errors="replace") for p in red.bundle.rglob("baseline.*"))
    assert text and "names are left out" in text
    assert not re.search(rf"(?<![\w.-]){re.escape(m.target)}(?![\w-])", text)


# ---------------------------------------------------------------- backup and restore (D.8)
def test_baseline_is_restored_and_not_relearned(tmp_path):
    import _backup_helpers as H

    from kratos.backup import create as CR
    from kratos.backup import restore as RS

    r = H.home(tmp_path, "old")
    H.seed(r)
    m = machine(0)
    normal_days(m)
    G.write(r.data.parent, [m], END, 21)          # roots: <home>/data
    first = run(r.data, m.target)
    assert first["dims"]["login_source"]["status"] == "active"
    from kratos.baseline import decide as BD

    BD.accept(r.data, m.target, "login_source", "deploy", "10.20.0.0/24", actor=OWNER, reason="office")
    ident = H.identity()
    H.set_recipient(r, ident)
    res = CR.create(r.data, actor=H.CLI, dest=tmp_path / "bk", roots=r, copy_to=[])
    new = H.home(tmp_path, "new")
    RS.restore(res.file, [ident], roots=new, actor=H.CLI, accept_signer=H.signer_of(res.file))
    con = sqlite3.connect(new.data / "kratos.db")
    samples = con.execute("SELECT samples FROM baseline_profiles WHERE dim = 'login_source'").fetchone()[0]
    again = run(new.data, m.target, now=END.timestamp() + 60)
    assert again["dims"]["login_source"]["status"] == "active"
    assert again["read"]["events"] == 0                                  # nothing relearned
    assert con.execute("SELECT samples FROM baseline_profiles WHERE dim = 'login_source'").fetchone()[0] == samples
    assert con.execute("SELECT kind FROM baseline_decisions").fetchone() == ("accept",)


# ---------------------------------------------------------------- the generator
def _gen(home: Path, *extra: str) -> dict:
    assert G.main(["--home", str(home), "--days", "21", "--seed", "11", "--machines", "3",
                   "--end", END.isoformat(), *extra]) == 0
    return json.loads((home / "baseline_history.json").read_text())


def test_generator_is_deterministic(tmp_path):
    a, b = _gen(tmp_path / "a"), _gen(tmp_path / "b")
    assert a == b
    ids = [sorted(r[0] for r in sqlite3.connect(h / "data" / "kratos.db").execute(
        "SELECT event_id FROM host_events")) for h in (tmp_path / "a", tmp_path / "b")]
    assert ids[0] == ids[1] and len(ids[0]) > 5000


def test_generator_refuses_a_real_data_folder(tmp_path):
    home = tmp_path / "real"
    (home / "data").mkdir(parents=True)
    sqlite3.connect(home / "data" / "kratos.db").execute("CREATE TABLE x (a)")
    assert G.main(["--home", str(home)]) == 2


def test_generated_history_detection_and_false_positive_rate(tmp_path):
    man = _gen(tmp_path / "g", "--plant", "all")
    data = tmp_path / "g" / "data"
    planted = detected = false = 0
    for mm in man["machines"]:
        doc = run(data, mm["target"])
        want = {(p["rule"], p["subject"], p["key"]) for p in mm["planted"]}
        got = raised(doc)
        planted += len(want)
        detected += len(want & got)
        false += len(got - want)
    assert detected / planted >= 0.9, (detected, planted)
    machine_days = 3 * 7                                   # the judged week on three machines
    assert false / machine_days <= 0.5, false
    clean = _gen(tmp_path / "c", "--plant", "none")
    data = tmp_path / "c" / "data"
    false_clean = sum(len(raised(run(data, mm["target"]))) for mm in clean["machines"])
    assert false_clean / machine_days <= 0.5, false_clean


# ---------------------------------------------------------------- TUI
def test_tui_baseline_screen_shows_status_and_deviations(tmp_path):
    import asyncio

    from textual.app import App

    from kratos.tui_mk2.screens.baseline import BaselineScreen

    m, data = _ready(tmp_path)

    class _A(App):
        def on_mount(self):
            self.push_screen(BaselineScreen(data, machine=m.target))

    async def go():
        app = _A()
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            scr = app.screen
            assert isinstance(scr, BaselineScreen)
            kinds = [r["type"] for r in scr._rows]
            assert "dev" in kinds and "dim" in kinds and "entry" in kinds
            statuses = {r["name"]: r["status"] for r in scr._rows if r["type"] == "dim"}
            assert statuses["login_source"] == "active" and statuses["program"] == "not_learnable"
            # TUI review: identifiers in the data colour (the accent is for what you can act on),
            # local times, and a detail pane + key bar for the selected row
            from kratos.tui_mk2 import theme as T

            table = scr.query_one("#bl-table")
            dim_row = next(i for i, r in enumerate(scr._rows) if r["type"] == "dim")
            cell = table.get_row_at(dim_row)[0]
            assert T.ACCENT not in str(cell.style) and T.DATA in str(cell.style)
            assert "+00:00" not in str(scr.query_one("#bl-banner")._Static__content)
            assert "esc" in str(scr.query_one("#bl-hints")._Static__content)
            assert str(scr.query_one("#bl-detail")._Static__content).strip()
            await pilot.press("escape")

    asyncio.run(go())

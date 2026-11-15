"""E.7b surfaces (§3.14): prepare/start are people-only (refused from MCP/chat/schedule/tool/a
network actor); MCP exposes only a read-only, scoped review view; the CLI read-only sub-commands
work and SARIF exports without code."""
from __future__ import annotations

import json

import pytest

from kratos import authz
from kratos.code import roots as R
from kratos.lifecycle.decide import Actor
from kratos.review import run as RUN
from kratos.review.run import ReviewRefused

M = "192.0.2.90"
OWNER = authz.owner_actor("cli")


def test_review_start_people_only(tmp_path):
    R.add(tmp_path, M, "/srv/app", actor=OWNER)
    R.confirm(tmp_path, M, "/srv/app", actor=OWNER)
    # a network / unattended actor cannot prepare.
    for iface in ("serve", "mcp", "schedule"):
        with pytest.raises(ReviewRefused):
            RUN.prepare_review(tmp_path, Actor(user="x", interface=iface, user_id="u"), M, "/srv/app")
    # nor from inside a tool call.
    from kratos import settings_store
    with settings_store.tool_call_scope("run_nmap_scan"):
        with pytest.raises(ReviewRefused):
            RUN.prepare_review(tmp_path, OWNER, M, "/srv/app")


def test_start_refused_without_plan(tmp_path):
    with pytest.raises(Exception):      # noqa: B017 -- PlanError: no such plan
        RUN.start_review(tmp_path, OWNER, "nope", agreed_usd=1.0)


def test_mcp_review_is_read_only_and_scoped(tmp_path, monkeypatch):
    from kratos import mcp_server
    R.add(tmp_path, M, "/srv/app", actor=OWNER)
    R.confirm(tmp_path, M, "/srv/app", actor=OWNER)
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    doc = mcp_server.kratos_review(M)
    assert "runs" in doc and "verdicts_cached" in doc and "review_findings" in doc
    # there is no MCP tool that prepares or starts a review.
    names = {t.name for t in __import__("asyncio").run(mcp_server.mcp.list_tools())}
    assert "kratos_review" in names
    assert not any("prepare" in n or "review_start" in n for n in names)


def test_cli_review_readonly(tmp_path, capsys):
    from kratos.cli import app as cli
    assert cli.main(["--data-dir", str(tmp_path), "review", "about"]) == 0
    assert "opt-in" in capsys.readouterr().out
    assert cli.main(["--data-dir", str(tmp_path), "review", "runs", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert cli.main(["--data-dir", str(tmp_path), "review", "verdicts"]) == 0


def test_cli_sarif_export(tmp_path, capsys):
    from kratos.cli import app as cli
    from kratos.review import judge as J
    J.write_snapshot(tmp_path, M, {"target": "192.0.2.90", "machine": M, "root": "/srv/app",
                                   "checked_at_epoch": 9e9, "complete": True, "state": "done",
                                   "profile": "p", "destination": "local", "mask_mode": "off", "reproduction": True,
                                   "counts": {}, "reachability": [],
                                   "findings": [{"verdict": "confirmed", "strength": "direct", "rel": "app.py",
                                                 "function": "ping", "cls": "exec", "line": 5, "exposure": "internet",
                                                 "evidence": "a request value reaches os.system()", "drift": False}]})
    out = tmp_path / "r.sarif"
    assert cli.main(["--data-dir", str(tmp_path), "review", "export", "--sarif", str(out), "--machine", M]) == 0
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
    assert "os.system" in json.dumps(doc)       # Kratos's evidence sentence, not code
    assert "def ping" not in json.dumps(doc) and "snippet" not in json.dumps(doc)

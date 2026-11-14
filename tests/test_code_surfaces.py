"""E.7a surfaces: /code in the app (real keypresses), `kratos code ...`, read-only MCP / chat, and
that no network door, tool call or model step can confirm a root or read source for a review."""
from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest
from textual.app import App

from kratos import settings_store
from kratos.adapters import code_facts as CF
from kratos.code import reads as RD
from kratos.code import roots as R
from kratos.code import store as S
from kratos.lifecycle.decide import Actor

M = "192.0.2.50"
OWNER = Actor(user="owner", interface="tui", user_id="owner")


def _offer(dd: Path) -> None:
    S.offer(dd, M, [{"path": "/srv/app", "why": [{"kind": "listener", "detail": "/usr/bin/gunicorn, listening on "
                                                                          "127.0.0.1:8000, works in this folder"}],
                     "serving": []},
                    {"path": "/var/www/site", "why": [{"kind": "web_root", "detail": "nginx root of x"}], "serving": []}])


def test_code_screen_confirm_and_ignore_with_keys(tmp_path, monkeypatch):
    from kratos.tui_mk2.screens.code import CodeScreen

    _offer(tmp_path)

    class _A(App):
        def on_mount(self):
            self.push_screen(CodeScreen(tmp_path, machine=M))

    async def go():
        app = _A()
        async with app.run_test(size=(160, 40)) as pilot:
            await pilot.pause()
            scr = app.screen
            assert isinstance(scr, CodeScreen)
            assert [r["status"] for r in scr._view["roots"]] == ["candidate", "candidate"]
            await pilot.press("c")
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()
            await pilot.press("down", "i")
            await pilot.pause()
            await pilot.press("n")            # anything but y declines
            await pilot.pause()
            await pilot.press("i")
            await pilot.pause()
            await pilot.press("y")
            await pilot.pause()
            await pilot.press("escape")

    asyncio.run(go())
    st = {r["path"]: (r["status"], r["decided_by"]) for r in S.roots(tmp_path, M)}
    assert st["/srv/app"][0] == "confirmed" and st["/var/www/site"][0] == "ignored"


def test_cli_roots_confirm_and_refusal(tmp_path, capsys):
    from kratos.cli import app as cli

    _offer(tmp_path)
    assert cli.main(["--data-dir", str(tmp_path), "code", "roots", M]) == 0
    out = capsys.readouterr().out
    assert "[candidate] /srv/app" in out and "works in this folder" in out
    assert cli.main(["--data-dir", str(tmp_path), "code", "confirm", M, "/srv/app"]) == 0
    assert cli.main(["--data-dir", str(tmp_path), "code", "add", M, "/etc/nginx", "--no-check"]) == 1
    assert "never treats as code" in capsys.readouterr().err
    assert cli.main(["--data-dir", str(tmp_path), "code", "status", M, "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert {r["path"]: r["status"] for r in doc["roots"]}["/srv/app"] == "confirmed"


def test_mcp_code_tool_is_read_only_and_scoped(tmp_path, monkeypatch):
    from kratos import mcp_server
    from kratos.code import present as P

    _offer(tmp_path)
    monkeypatch.setattr(mcp_server, "_data_dir", tmp_path)
    doc = mcp_server.kratos_code(M)
    assert [r["path"] for r in doc["roots"]] == ["/srv/app", "/var/www/site"]
    network = Actor(user="token:x", interface="serve", user_id="u1")
    with pytest.raises(P.ViewError, match="which machine"):
        P.resolve_code_reader(tmp_path, network, None)        # a network door never gets the default machine


def test_root_confirm_and_review_reads_have_no_network_or_model_door():
    """No MCP tool, chat command, registered agent tool or scheduled path reaches the
    people-only code decisions or the review read (source scan)."""
    src = Path(CF.__file__).parents[1]
    forbidden = ("roots.confirm", "roots.ignore", "roots.add", "roots.accept_state", "read_for_review",
                 "RT.confirm", "RT.ignore", "RT.add", "RT.accept_state", "R.confirm(", "R.add(")
    doors = [src / "mcp_server.py", src / "serve" / "mcp_http.py", src / "serve" / "openai_routes.py",
             src / "agent" / "tools.py", src / "agent" / "loop.py", src / "agent" / "scheduled_run.py"]
    for p in doors:
        text = p.read_text()
        for f in forbidden:
            assert f not in text, f"{p.name} reaches {f}"
    for p in (src / "mcp_server.py", src / "serve" / "mcp_http.py"):
        tree = ast.parse(p.read_text())
        names = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assert not any(("confirm" in n or "accept" in n) and "code" in n for n in names)


def test_review_purpose_scoped(tmp_path):
    R.add(tmp_path, M, "/srv/app", actor=Actor(user="owner", interface="cli", user_id="owner"))
    root = S.roots(tmp_path, M)[0]
    S.replace_files(tmp_path, root["id"], "current", [{"relpath": "app.py", "size": 10, "sha256": "a" * 64},
                                                       {"relpath": "settings.yml", "size": 10, "sha256": "b" * 64}])
    sent = []

    def fetch(raw, purpose, paths, *, budget_bytes):
        sent.append((purpose, paths))
        return {"files": {i: {"status": "ok", "data": b"x = 1\n", "sha256": "c" * 64, "size": 6}
                          for i in range(len(paths))}, "via": "ssh"}

    for iface in ("mcp", "serve", "schedule"):
        with pytest.raises(RD.ReviewRefused):
            RD.read_for_review(tmp_path, M, "/srv/app", ["app.py"], actor=Actor(user="x", interface=iface), fetch=fetch)
    with settings_store.tool_call_scope("run_nmap_scan"):
        with pytest.raises(RD.ReviewRefused, match="agent tools"):
            RD.read_for_review(tmp_path, M, "/srv/app", ["app.py"], actor=OWNER, fetch=fetch)
    with pytest.raises(RD.ReviewRefused, match="source extension"):
        RD.read_for_review(tmp_path, M, "/srv/app", ["settings.yml"], actor=OWNER, fetch=fetch)
    with pytest.raises(RD.NotInInventory):
        RD.read_for_review(tmp_path, M, "/srv/app", ["other.py"], actor=OWNER, fetch=fetch)
    with pytest.raises(RD.ReviewRefused, match="confirmed"):
        RD.read_for_review(tmp_path, M, "/srv/elsewhere", ["app.py"], actor=OWNER, fetch=fetch)
    assert sent == []
    got, _info = RD.read_for_review(tmp_path, M, "/srv/app", ["app.py"], actor=OWNER, fetch=fetch)
    assert got["app.py"]["status"] == "ok" and sent == [("review", [b"app.py"])]

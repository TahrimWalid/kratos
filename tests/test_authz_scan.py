"""D.7 §5.2 / §7 "Scan": every entry point checks permission, and removing a check from
any of them fails the scan."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import _authz_scan as S


def test_every_entry_point_checks_permission():
    rep = S.scan()
    assert rep.gaps == []
    # The scan really looked: doors, people-only functions, subcommands, slash commands.
    assert rep.counted["network"] >= 15 and rep.counted["people_only"] >= 12
    assert rep.counted["cli"] >= 55 and rep.counted["tui"] >= 80


@pytest.fixture()
def tree(tmp_path):
    dst = tmp_path / "kratos"
    shutil.copytree(S.DEFAULT_SRC, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def _edit(tree: Path, rel: str, old: str, new: str) -> None:
    p = tree / rel
    text = p.read_text(encoding="utf-8")
    assert text.count(old) >= 1, (rel, old)
    p.write_text(text.replace(old, new), encoding="utf-8")


@pytest.mark.parametrize("rel, old, new, expect", [
    # an MCP-over-HTTP tool
    ("serve/mcp_http.py", '_require(state, actor, authz.P.HUNT, obj="mcp hunt")', "pass", "kratos_hunt"),
    # a stdio MCP tool
    ("mcp_server.py", '_authorize(P.SESSIONS_OWN, obj="list sessions")', "pass", "kratos_list_sessions"),
    # a chat route handler
    ("serve/openai_routes.py",
     "await asyncio.to_thread(authz.require, actor, authz.P.READ, data_dir=state.data_dir, audit_allowed=False)",
     "pass", "list_models"),
    # a people-only function (asset edits)
    ("assets/store.py", "authz.require(actor, authz.P.ASSETS_MANAGE,", "(lambda *a, **k: None)(actor, None,",
     "assets.store:_check_actor"),
    # the decisions' check
    ("lifecycle/decide.py", "authz.require(actor, authz.P.FINDING_DECIDE,", "(lambda *a, **k: None)(actor, None,",
     "_authorize"),
    # the per-read check in tool dispatch
    ("agent/loop.py", "    authz.check_run_access(data_dir=data_dir)\n    refused = _person_tool_refusal",
     "    refused = _person_tool_refusal", "_dispatch_tool_call"),
    # the fleet collector's per-machine check
    ("fleet/collect.py", "authz.check_run_access(host, data_dir=data_dir)", "(lambda *a, **k: None)(host)",
     "_collect_one"),
    # the CLI dispatch
    ("cli/app.py", "_entrypoints.require_cli(", "(lambda *a, **k: None)(", "require_cli"),
    # the TUI dispatch
    ("tui_mk2/screens/session.py", "_entrypoints.require_tui(", "(lambda *a, **k: None)(", "require_tui"),
    # a subcommand left out of the table
    ("authz/entrypoints.py", '    "cmd_investigate": A(P.INVESTIGATE),\n', "", "cmd_investigate"),
    # a slash command left out of the table
    ("authz/entrypoints.py", '"/hunt": A(P.HUNT),', "", "/hunt"),
])
def test_removing_a_check_fails_the_scan(tree, rel, old, new, expect):
    _edit(tree, rel, old, new)
    gaps = S.scan(tree).gaps
    assert any(expect in g for g in gaps), gaps


def test_a_new_people_only_function_without_a_check_fails(tree):
    p = tree / "assets" / "store.py"
    p.write_text(p.read_text(encoding="utf-8") + '''

def sneaky_edit(data_dir, value):
    if settings_store.in_tool_call():
        raise AssetError("no")
    return value
''', encoding="utf-8")
    assert any("sneaky_edit" in g for g in S.scan(tree).gaps)


def test_a_new_mcp_tool_without_a_check_fails(tree):
    p = tree / "mcp_server.py"
    p.write_text(p.read_text(encoding="utf-8") + '''

@mcp.tool()
def kratos_everything() -> dict:
    return {}
''', encoding="utf-8")
    assert any("kratos_everything" in g for g in S.scan(tree).gaps)


def test_a_same_named_ungated_function_does_not_count_as_a_check(tree):
    # collisions make the scan stricter: an ungated `_require` elsewhere breaks the HTTP tools
    p = tree / "serve" / "render.py"
    p.write_text(p.read_text(encoding="utf-8") + "\n\ndef _require(*a, **k):\n    return None\n", encoding="utf-8")
    assert any("mcp_http" in g for g in S.scan(tree).gaps)

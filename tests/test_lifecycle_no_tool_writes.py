"""The model suggests, people decide (0.1 §5.7): no module that defines an agent tool,
and not the MCP server, may reference kratos.lifecycle.decide or settings_store.set.
The runtime refusal inside a tool call (test_lifecycle_apply) is the second layer."""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import kratos.mcp_server as mcp_server


def _decide_refs(source: str) -> list[str]:
    hits: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names = {a.name for a in node.names}
            if mod == "kratos.lifecycle.decide" or (mod in ("kratos.lifecycle", "lifecycle") and "decide" in names):
                hits.append(f"line {node.lineno}: from {mod} import ...")
            if mod.endswith("settings_store") and "set" in names:
                hits.append(f"line {node.lineno}: settings_store.set imported")
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "kratos.lifecycle.decide":
                    hits.append(f"line {node.lineno}: import {a.name}")
        elif isinstance(node, ast.Attribute):
            if node.attr == "set" and isinstance(node.value, ast.Name) and node.value.id.endswith("settings_store"):
                hits.append(f"line {node.lineno}: settings_store.set")
            if node.attr == "decide" and isinstance(node.value, ast.Attribute) and node.value.attr == "lifecycle":
                hits.append(f"line {node.lineno}: lifecycle.decide")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "kratos.lifecycle.decide" in node.value:
            hits.append(f"line {node.lineno}: dynamic import string")
    return hits


def test_no_tool_module_or_mcp_server_reaches_decisions():
    from kratos.agent.tools import TOOL_REGISTRY

    files = {inspect.getsourcefile(t.handler) for t in TOOL_REGISTRY.values()}
    files.add(inspect.getsourcefile(mcp_server))
    assert None not in files and len(files) > 1
    offenders = {f: hits for f in files if (hits := _decide_refs(Path(f).read_text(encoding="utf-8")))}
    assert offenders == {}


def test_the_scan_catches_each_form():
    assert _decide_refs("from kratos.lifecycle import decide\n")
    assert _decide_refs("from kratos.lifecycle.decide import accept_risk\n")
    assert _decide_refs("import kratos.lifecycle.decide\n")
    assert _decide_refs("import kratos\nkratos.lifecycle.decide.verify('k')\n")
    assert _decide_refs("import importlib\nimportlib.import_module('kratos.lifecycle.decide')\n")
    assert _decide_refs("from kratos.settings_store import set\n")
    assert _decide_refs("from kratos import settings_store\nsettings_store.set('a.b', 1)\n")
    assert _decide_refs("from kratos.lifecycle import query\nquery.list_findings('.')\n") == []


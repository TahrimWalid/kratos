"""A verdict or a suggestion never changes a finding's lifecycle state or severity
(docs/phaseB/B.1 §3.1, §7): the triage package does not import the people-only
decision module, and does not touch the lifecycle records table."""
from __future__ import annotations

import ast
import pathlib

TRIAGE = pathlib.Path(__file__).resolve().parents[1] / "src" / "kratos" / "triage"


def _sources():
    return {p.name: p.read_text(encoding="utf-8") for p in TRIAGE.glob("*.py")}


def _imported_modules(src: str) -> set[str]:
    mods: set[str] = set()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
            mods.update(f"{node.module}.{a.name}" for a in node.names)
    return mods


def test_triage_never_imports_the_decision_module():
    for name, src in _sources().items():
        mods = _imported_modules(src)
        assert not any(m.endswith("lifecycle.decide") or m == "kratos.lifecycle.decide" for m in mods), (
            f"{name} imports the people-only decision module -- a verdict is not a decision")


def test_triage_never_writes_finding_state_or_severity():
    for name, src in _sources().items():
        assert "finding_records" not in src, f"{name} must not touch the finding_records table"
        assert "set_state(" not in src, f"{name} must not change a finding's state"


def test_triage_does_not_register_an_agent_tool():
    # the model suggests; it never runs a verification or a decision as a tool
    for name, src in _sources().items():
        assert "@register_tool" not in src, f"{name} must not register an agent tool"

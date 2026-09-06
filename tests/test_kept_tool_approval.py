"""
Tests for self_write_loop.set_kept_tool_approval -- the backend behind the
/settings Tool-approvals tab (Sprint 2 backlog #5): toggle an already-kept
tool's requires_approval, persisted to metadata.json (atomic, lock-held) and
applied live to TOOL_REGISTRY. Built-ins are not editable this way.

Uses a temp kept_tools_dir so the real repo metadata is never touched, and a
throwaway TOOL_REGISTRY entry that is always removed afterward.
"""
from __future__ import annotations

import json
import types

import pytest

from kratos.agent import self_write_loop as swl
from kratos.agent.tools import TOOL_REGISTRY


def _seed(tmp_path, name="dummy_kept", requires_approval=True):
    d = tmp_path / "kept_tools"
    d.mkdir()
    (d / f"{name}.py").write_text("# dummy kept tool\n", encoding="utf-8")
    (d / swl.KEPT_TOOLS_METADATA_FILENAME).write_text(
        json.dumps({name: {"requires_approval": requires_approval, "kept_at": "2026-01-01T00:00:00",
                           "source_file": f"{name}.py"}}),
        encoding="utf-8",
    )
    return d


def test_toggle_persists_to_metadata_and_updates_registry(tmp_path):
    d = _seed(tmp_path, requires_approval=True)
    TOOL_REGISTRY["dummy_kept"] = types.SimpleNamespace(requires_approval=True)
    try:
        swl.set_kept_tool_approval("dummy_kept", False, kept_tools_dir=d)
        meta = json.loads((d / swl.KEPT_TOOLS_METADATA_FILENAME).read_text())
        assert meta["dummy_kept"]["requires_approval"] is False
        assert meta["dummy_kept"]["source_file"] == "dummy_kept.py"  # source preserved
        assert TOOL_REGISTRY["dummy_kept"].requires_approval is False  # live registry updated

        swl.set_kept_tool_approval("dummy_kept", True, kept_tools_dir=d)
        meta = json.loads((d / swl.KEPT_TOOLS_METADATA_FILENAME).read_text())
        assert meta["dummy_kept"]["requires_approval"] is True
        assert TOOL_REGISTRY["dummy_kept"].requires_approval is True
    finally:
        TOOL_REGISTRY.pop("dummy_kept", None)


def test_toggle_rejects_non_kept_tool(tmp_path):
    d = _seed(tmp_path)
    with pytest.raises(KeyError):
        swl.set_kept_tool_approval("not_a_kept_tool", True, kept_tools_dir=d)


def test_set_description_persists_and_clears(tmp_path):
    d = _seed(tmp_path)
    swl.set_kept_tool_description("dummy_kept", "counts sudo events", kept_tools_dir=d)
    meta = json.loads((d / swl.KEPT_TOOLS_METADATA_FILENAME).read_text())
    assert meta["dummy_kept"]["description"] == "counts sudo events"
    # clearing (empty) removes the field entirely
    swl.set_kept_tool_description("dummy_kept", "", kept_tools_dir=d)
    meta = json.loads((d / swl.KEPT_TOOLS_METADATA_FILENAME).read_text())
    assert "description" not in meta["dummy_kept"]


def test_approval_toggle_preserves_description(tmp_path):
    # The metadata rewrite must MERGE, not replace -- a description set earlier
    # must survive an unrelated approval toggle (the merge-preserve fix).
    d = _seed(tmp_path, requires_approval=True)
    swl.set_kept_tool_description("dummy_kept", "a useful note", kept_tools_dir=d)
    TOOL_REGISTRY["dummy_kept"] = types.SimpleNamespace(requires_approval=True)
    try:
        swl.set_kept_tool_approval("dummy_kept", False, kept_tools_dir=d)
    finally:
        TOOL_REGISTRY.pop("dummy_kept", None)
    meta = json.loads((d / swl.KEPT_TOOLS_METADATA_FILENAME).read_text())
    assert meta["dummy_kept"]["requires_approval"] is False
    assert meta["dummy_kept"]["description"] == "a useful note"  # not dropped


def test_set_description_rejects_non_kept_tool(tmp_path):
    d = _seed(tmp_path)
    with pytest.raises(KeyError):
        swl.set_kept_tool_description("not_a_kept_tool", "x", kept_tools_dir=d)

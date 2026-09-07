"""
mk2 render/wiring tests for the feature-14b compaction event.

Scoped deliberately small and app-free: `SessionScreen._render_step` routes a
`context_compacted` transcript step (emitted by agent/loop.py's compaction) to
a receding `render.compaction_line`, and that step touches nothing but
`self._emit_from_worker` -- so the routing can be exercised by binding the
unbound method to a tiny capturing stand-in, no Textual app/pilot needed. (mk2
had no committed test file before this; a full pilot harness is a separate,
larger effort and disproportionate for a 3-line branch.)
"""
from __future__ import annotations

from types import SimpleNamespace

from rich.text import Text

from kratos.tui_mk2 import render as R
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.screens.session import SessionScreen


def test_compaction_line_is_a_receding_note_not_the_amber_notice():
    line = R.compaction_line(5200, 6144)
    assert isinstance(line, Text)
    plain = line.plain
    assert "context compacted" in plain
    assert "5.2k/6.1k" in plain                     # shows how full it got
    assert "transcript" in plain                    # tells the user detail is preserved
    # Must NOT be the amber "!" notice style (this isn't a decision/warning).
    assert not plain.startswith("!")
    styles = {str(span.style) for span in line.spans}
    assert any(T.TEXT_MUTED in s or T.TEXT_FAINTER in s for s in styles)
    assert T.ATTENTION not in " ".join(styles)      # not amber


def test_compaction_line_omits_numbers_when_unknown():
    plain = R.compaction_line(0, 0).plain
    assert "context compacted" in plain
    assert "k/" not in plain                         # no bogus 0.0k/0.0k


def test_tool_description_prefers_metadata_then_registered_then_placeholder():
    tool = SimpleNamespace(description="Registered first line.\nsecond line ignored")
    # metadata description wins
    assert R.tool_description(tool, {"description": "human note"}) == "human note"
    # no metadata -> first line of the tool's own registered description
    assert R.tool_description(tool, None) == "Registered first line."
    assert R.tool_description(tool, {}) == "Registered first line."
    # nothing anywhere -> placeholder
    assert R.tool_description(SimpleNamespace(description=""), None) == "(no description)"


def test_render_step_routes_context_compacted_to_compaction_line():
    emitted: list = []
    fake = SimpleNamespace(_emit_from_worker=emitted.append)

    SessionScreen._render_step(fake, {
        "status": "context_compacted",
        "compaction_count": 1,
        "context_tokens": 5200,
        "context_window": 6144,
    })

    assert len(emitted) == 1
    assert isinstance(emitted[0], Text)
    assert "context compacted" in emitted[0].plain


def test_render_step_ignores_other_tool_less_status_entries():
    # A tool-less, non-compaction status step (e.g. parse_error/rejected) must
    # NOT emit a compaction line -- confirms the branch is specific.
    emitted: list = []
    fake = SimpleNamespace(_emit_from_worker=emitted.append)

    SessionScreen._render_step(fake, {"status": "final_answer_rejected", "violations": ["x"]})
    SessionScreen._render_step(fake, {"status": "parse_error", "raw_response": "{"})

    assert emitted == []


def test_error_detail_reads_common_keys_and_falls_back():
    from kratos.tui_mk2.render import error_detail
    # a tool's own error uses 'message' (the sudo_command_check case), not 'observation'
    assert error_detail({"status": "error", "message": "permission denied"}) == "permission denied"
    # the loop's wrapper error uses 'observation'
    assert error_detail({"status": "error", "observation": "boom"}) == "boom"
    # 'observation' wins when both are present
    assert error_detail({"observation": "outer", "message": "inner"}) == "outer"
    # message-less error -> informative fallback instead of empty
    got = error_detail({"command": "ls", "found": False, "status": "error", "message": ""})
    assert "command=ls" in got and "found=False" in got
    # genuinely nothing -> empty (caller shows 'no error detail')
    assert error_detail({"status": "error"}) == ""
    assert error_detail("plain string") == "plain string"

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


def test_tool_descriptions_are_plain_language_for_people():
    """Screens used to show the model-facing text ("LOCAL KRATOS HOST -- not the
    monitored target. Checks LIVE NETWORK ACTIVITY ... NON-NEGOTIABLE ...")."""
    from kratos.agent.tool_summaries import human_summary, where_it_runs
    from kratos.agent.tools import TOOL_REGISTRY

    for name, tool in TOOL_REGISTRY.items():
        line = R.tool_description(tool, None)
        assert len(line) <= 100, (name, line)
        assert "NON-NEGOTIABLE" not in line and "--" not in line and "Do NOT" not in line, (name, line)
        assert where_it_runs(name, tool) in ("the target", "this Kratos machine", "saved results", "—")
    assert where_it_runs("run_linux_command", TOOL_REGISTRY["run_linux_command"]) == "this Kratos machine"
    # a kept tool without a saved description: its first sentence, shortened, capitals calmed
    kept = SimpleNamespace(name="x", description="Checks LISTENING SERVICES on the target using ss. More text.")
    assert human_summary("x", kept) == "Checks listening services on the target using ss."
    long = SimpleNamespace(name="y", description="word " * 60)
    assert human_summary("y", long).endswith("…") and len(human_summary("y", long)) <= 97


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


# --- lever 3 (docs/clarify_expansion.md): a resolved clarify gets a durable
# panel in the scrollback, not just the modal that already closed -------------

def test_render_step_routes_clarify_to_a_panel_with_question_and_answer():
    emitted: list = []
    fake = SimpleNamespace(_emit_from_worker=emitted.append)

    SessionScreen._render_step(fake, {
        "status": "clarify",
        "clarify_question": "Which target?",
        "clarify_answer": "The monitored target",
    })

    assert len(emitted) == 1
    panel = emitted[0]
    assert panel.title == "Clarifying question"
    rendered = panel.renderable.plain if hasattr(panel.renderable, "plain") else str(panel.renderable)
    assert "Which target?" in rendered and "The monitored target" in rendered


def test_render_step_clarify_with_no_answer_says_so():
    emitted: list = []
    fake = SimpleNamespace(_emit_from_worker=emitted.append)

    SessionScreen._render_step(fake, {
        "status": "clarify",
        "clarify_question": "Which target?",
        "clarify_answer": None,
    })

    rendered = emitted[0].renderable.plain if hasattr(emitted[0].renderable, "plain") else str(emitted[0].renderable)
    assert "no answer given" in rendered.lower()


def test_render_step_ignores_clarify_malformed_and_budget_exhausted():
    # Internal self-correction statuses (like parse_error) never reach the
    # scrollback -- only a genuinely completed "clarify" does.
    emitted: list = []
    fake = SimpleNamespace(_emit_from_worker=emitted.append)

    SessionScreen._render_step(fake, {"status": "clarify_malformed", "raw_response": "{"})
    SessionScreen._render_step(fake, {"status": "clarify_budget_exhausted", "attempted_clarify": {}})

    assert emitted == []


# --- review finding #5: full-tier resume must replay tool_proposal/clarify
# steps too -- these were previously silently dropped (`_render_step_replay`
# returned immediately for any tool-less step) ------------------------------

def _fake_replay_self(**extra):
    emitted: list = []
    base = dict(
        _emit=emitted.append,
        _emit_bubble=lambda r, d: emitted.append(("bubble", r, d)),
        _fmt_stored_time=lambda v: "12:00",
        _fmt_stored_date=lambda v: "2026-01-01",
    )
    base.update(extra)
    return SimpleNamespace(**base), emitted


def test_render_step_replay_shows_tool_proposal():
    fake, emitted = _fake_replay_self()

    SessionScreen._render_step_replay(fake, {
        "tool_proposal": {"name": "list_thing", "description": "lists a thing"},
    }, when_value=None)

    assert len(emitted) == 1
    panel = emitted[0]
    assert panel.title == "Evo-loop suggestion"
    rendered = panel.renderable.plain if hasattr(panel.renderable, "plain") else str(panel.renderable)
    assert "list_thing" in rendered and "lists a thing" in rendered


def test_render_step_replay_does_not_arm_pending_evolve_suggestion():
    # Deliberate deviation from the live _render_step: replay must NOT
    # resurrect a past proposal into session_state, or a later bare /evolve
    # in THIS session could silently act on stale history.
    fake, _ = _fake_replay_self(session_state={})

    SessionScreen._render_step_replay(fake, {
        "tool_proposal": {"name": "list_thing", "description": "lists a thing"},
    }, when_value=None)

    assert "pending_evolve_suggestion" not in fake.session_state


def test_render_step_replay_shows_clarify_question_and_answer():
    fake, emitted = _fake_replay_self()

    SessionScreen._render_step_replay(fake, {
        "status": "clarify",
        "clarify_question": "Which target?",
        "clarify_answer": "The monitored target",
    }, when_value=None)

    assert len(emitted) == 1
    panel = emitted[0]
    assert panel.title == "Clarifying question"
    rendered = panel.renderable.plain if hasattr(panel.renderable, "plain") else str(panel.renderable)
    assert "Which target?" in rendered and "The monitored target" in rendered


def test_render_step_replay_clarify_with_no_answer_says_so():
    fake, emitted = _fake_replay_self()

    SessionScreen._render_step_replay(fake, {
        "status": "clarify",
        "clarify_question": "Which target?",
        "clarify_answer": None,
    }, when_value=None)

    rendered = emitted[0].renderable.plain if hasattr(emitted[0].renderable, "plain") else str(emitted[0].renderable)
    assert "no answer given" in rendered.lower()


def test_render_step_replay_still_ignores_other_toolless_statuses():
    # context_compacted and internal self-corrections stay out of replay too
    # (same as live) -- confirms the new branches are specific, not a
    # blanket "render anything toolless" change.
    fake, emitted = _fake_replay_self()

    SessionScreen._render_step_replay(fake, {"status": "context_compacted", "context_tokens": 100}, when_value=None)
    SessionScreen._render_step_replay(fake, {"status": "clarify_malformed"}, when_value=None)
    SessionScreen._render_step_replay(fake, {"status": "final_answer_rejected"}, when_value=None)

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


def _plain(renderable, width=120):
    from rich.console import Console

    console = Console(width=width, record=True, color_system=None)
    console.print(renderable)
    return console.export_text()


def test_a_tool_result_reads_as_tables_and_labels_not_json():
    """/use used to dump the raw JSON result."""
    result = {
        "status": "ok", "target": "ubuntu@203.0.113.5", "count": 30,
        "entries": [{"user": "root", "pid": str(i), "cpu": "0.0", "command": f"/usr/sbin/daemon-{i}"}
                    for i in range(30)],
        "window": {"label": "2026-10-02T21:09:39+00:00 to 2026-10-03T21:09:39+00:00", "notes": []},
        "events": [{"time": "2026-09-28T22:58:25+00:00", "action": "added_to_group", "user": "eve_admin"}],
        "fetch_errors": [],
    }
    text = _plain(R.tool_result_panel("list_processes", result))
    assert "{" not in text and '"' not in text                     # no JSON
    assert "Entries (30)" in text and "PID" in text and "…and 5 more" in text
    assert "2026-10-02 21:09:39 UTC to 2026-10-03 21:09:39 UTC" in text   # readable times, seconds kept
    assert "eve_admin" in text and "added_to_group" in text        # data is never rewritten
    assert "Fetch errors" in text and "none" in text
    assert "notes" not in text                                       # empty sub-list hidden
    assert "Ctrl+Y copies the full raw result" in text


def test_long_text_and_the_kratos_host_stamp_get_their_own_lines():
    result = {"kratos_host_note": "[THIS RAN ON KRATOS'S OWN HOST ...]", "status": "executed",
              "command": "uptime", "stdout": "line one\nline two\n", "returncode": 0}
    text = _plain(R.tool_result_panel("run_linux_command", result))
    assert "Ran on this Kratos machine, not the target." in text
    assert "Stdout" in text and "line one" in text and "line two" in text
    assert "THIS RAN ON" not in text


def test_any_shape_renders():
    for data in ([{"a": 1}], [], "plain text", 42, None, {"nested": {"deep": {"deeper": [1, 2]}}}):
        assert _plain(R.tool_result_panel("x", data))


def test_home_tip_depends_on_whether_a_machine_is_connected():
    with_target = _plain(R.home_banner("web-01", 19, 2, model="m"))
    assert "ready" in with_target and "/target to switch" in with_target and "new here?" not in with_target
    assert "2 built by you" in with_target
    without = _plain(R.home_banner("", 19, 0, model="m"))
    assert "new here?" in without and "/target <host> to connect" in without


def test_key_hint_lines_fit_an_80_column_terminal():
    """Long one-line key hints (/subagent, /whitelist, Settings) were clipped
    mid-word, even at 120 columns."""
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "src" / "kratos" / "tui_mk2"
    too_long = []
    for f in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(f.read_text())):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str) and " · " in node.value
                    and ("esc" in node.value or "↑↓" in node.value) and not node.value.startswith("Usage:")):
                too_long += [f"{f.name}:{node.lineno} ({len(line)}) {line}"
                             for line in node.value.split("\n") if len(line) > 78]
    assert not too_long, "\n".join(too_long)


def test_a_saved_pipeline_summary_names_the_pipeline_not_the_standard_audit():
    common = dict(status="completed", ran=3, total=3, severity_tally={"medium": 1}, duration_s=6)
    audit = _plain(R.audit_summary_panel(**common))
    assert "Kratos — standard audit" in audit and "Deterministic audit complete" in audit
    pipe = _plain(R.audit_summary_panel(**common, pipeline_name="security-posture-audit"))
    assert "Kratos — pipeline 'security-posture-audit'" in pipe and "Pipeline complete" in pipe
    assert "standard audit" not in pipe
    stopped = _plain(R.audit_summary_panel(**{**common, "status": "aborted"}, aborted_on="run_nmap_scan",
                                           pipeline_name="p"))
    assert "Pipeline stopped" in stopped and "run_nmap_scan" in stopped


def test_home_wordmark_overhangs_the_subtitle_equally_at_any_width():
    """The spaced KRATOS wordmark sticks out past 'security assistant' by the
    same number of cells on both sides, whether the terminal width is odd or
    even (an odd width difference can't centre on a character grid)."""
    from rich.console import Console

    for width in (100, 101, 110, 111, 120):
        con = Console(width=width, record=True, color_system=None)
        con.print(R.home_banner("web-01", 19, 0, model="m"))
        lines = con.export_text().splitlines()
        mark = next(line for line in lines if line.strip().startswith("K "))
        sub = next(line for line in lines if "security assistant" in line)
        left = sub.index("s") - mark.index("K")
        right = mark.rindex("S") - (sub.index("assistant") + len("assistant") - 1)
        assert left == right > 0, (width, left, right)

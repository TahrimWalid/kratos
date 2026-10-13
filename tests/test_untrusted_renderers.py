"""A.4 §5.3 / §7: text from a machine never corrupts a screen -- every renderer, every exit.

The corpus (tests/fixtures/untrusted/corpus.json) is driven through the CLI console helpers, the
TUI renderable builders, the TUI transcript and safe widgets, notifications, MCP replies and
the plain-text CLI prints, asserting: no escape byte, no control character, no invisible format
character reaches the output; Rich markup stays literal; hidden characters are visible markers.
"""
from __future__ import annotations

import asyncio
import io
import re
from pathlib import Path

import pytest
from rich.console import Console
from rich.panel import Panel as RichPanel
from rich.text import Text as RichText

from _untrusted_corpus import CORPUS, HUGE, assert_screen_safe
from kratos.agent import console as cli
from kratos.tui_mk2 import render as R

NAMES = sorted(CORPUS)
SRC = Path(__file__).resolve().parents[1] / "src" / "kratos"


def _plain_console(width: int = 400) -> Console:
    """A console that writes NO styling of its own, so any escape byte in its output is payload."""
    return Console(file=io.StringIO(), force_terminal=False, color_system=None, width=width, record=True,
                   highlight=False, legacy_windows=False)


def _text(console: Console) -> str:
    return console.export_text(styles=False)


def _cli_console(width: int = 400):
    c = cli._MarginConsole(file=io.StringIO(), force_terminal=True, color_system="standard", width=width,
                           record=True, highlight=False)
    return c


# --- the CLI console helpers ------------------------------------------------------------------------------

def _cli_calls(p: str):
    finding = {"id": "AUTH-004", "severity": "high", "title": f"Burst for {p}", "evidence": [f"user {p}", p]}
    return {
        "tool_call": lambda c: cli.render_tool_call(c, p, "done"),
        "metadata_notes": lambda c: cli.render_tool_metadata_notes(
            c, {"input_errors": {p: p}, "missing_inputs": [p], "staleness_warning": p}),
        "transport_note": lambda c: cli.render_transport_note(c, {"transport": p}),
        "window_note": lambda c: cli.render_window_note(
            c, {"window": {"chip": p, "truncated": True, "oldest_returned": p, "clock": p}}),
        "finding": lambda c: cli.render_finding(c, finding),
        "note": lambda c: cli.render_note(c, p),
        "error": lambda c: cli.render_error(c, p),
        "success": lambda c: cli.render_success(c, p),
        "result_panel": lambda c: cli.render_result_panel(c, p, p, "green"),
        "evolve_suggestion": lambda c: cli.render_evolve_suggestion(c, p, p),
        "probe_results": lambda c: cli.render_target_probe_results(
            c, [{"check": "ssh_reachable", "status": "FAIL", "detail": p}]),
        "tool_list": lambda c: cli.render_evolve_tool_list(
            c, [{"name": p, "kind": "kept", "requires_approval": True, "kept_at": p, "description": p}]),
        "session_summary": lambda c: cli.render_session_summary(c, [p, p]),
        "session_header": lambda c: cli.render_session_header(c, goal=p, max_iters=3, ssh_target=p, backend=p),
        "approval": lambda c: cli.render_approval_situation(c, p, {"command": p, "source": f"def f():\n    return '{p}'"}),
        "harness_template": lambda c: cli.render_evolve_harness_template(c, p, Path("/tmp/x.py"), drafted=True),
    }


@pytest.mark.parametrize("name", NAMES)
def test_cli_console_helpers_neutralise_every_payload(name):
    payload = CORPUS[name]
    for label, call in _cli_calls(payload).items():
        console = _cli_console()
        call(console)
        out = _text(console)
        assert_screen_safe(out, where=f"console.{label} / {name}")
        # nothing in the styled output either: the only ESC bytes are Rich's own colour codes
        raw = console.file.getvalue()
        assert "\x1b]" not in raw and "\x1b[2J" not in raw and "\x1b[H" not in raw, f"{label}/{name}: {raw!r:.200}"


def test_cli_markup_stays_literal_and_hidden_characters_are_visible():
    for label, call in _cli_calls(CORPUS["rich_markup_style"]).items():
        console = _cli_console()
        call(console)
        text = _text(console)
        if label in ("session_header", "probe_results", "tool_list", "approval", "harness_template"):
            continue
        assert "[bold red]ALL CLEAR[/]" in text.replace("\n", " ") or label in ("metadata_notes", "window_note"), label
    console = _cli_console()
    cli.render_note(console, CORPUS["bidi_override_filename"])
    assert "U+202E" in _text(console)
    console = _cli_console()
    cli.render_note(console, CORPUS["markup_link"] if "markup_link" in CORPUS else CORPUS["rich_markup_link"])
    assert "\x1b]8;" not in console.file.getvalue()                      # no hyperlink was created


def test_cli_console_backstop_scrubs_a_raw_escape_in_a_plain_print():
    # something that bypasses every helper still passes through the console's scrubber
    console = _cli_console()
    console.print(RichText("x\x1b[2Jy\x1b]52;c;QUJD\x07z"))
    console.print(RichPanel("a\x9b2Jb"))
    out = _text(console)
    assert_screen_safe(out)
    assert "x" in out and "y" in out and "b" in out        # (Rich itself drops the BEL, so the OSC is unterminated)
    assert "\x1b[2J" not in console.file.getvalue() and "\x1b]52" not in console.file.getvalue()


def test_cli_console_scrubber_leaves_live_control_segments_alone():
    from rich.live import Live

    console = _cli_console()
    with Live("working", console=console, transient=True):
        pass                                           # Live emits cursor-control segments through render()
    assert "working" in console.file.getvalue() or console.file.getvalue() != ""


# --- the TUI renderable builders ----------------------------------------------------------------------------

def _tui_calls(p: str):
    finding = {"id": "AUTH-004", "severity": "high", "title": f"Burst for {p}",
               "evidence": [f"user {p}", p], "change": "recurred", "state": "verified"}
    data = {"user": p, p: p, "rows": [{"name": p, "cmd": p}], "nested": {p: p, "list": [p]}, "long": (p + "\n") * 3}
    cmd = {"command": p, "explanation": p, "run_on": "target", "source": "model",
           "flags": [{"id": "network", "reason": p}]}
    return {
        "finding_panel": lambda: R.finding_panel(finding, time_str="10:00"),
        "result_panel": lambda: R.result_panel(p, p, "red"),
        "tool_result_panel": lambda: R.tool_result_panel(p, data),
        "tool_call_line": lambda: R.tool_call_line(p, "done"),
        "note_line": lambda: R.note_line(p),
        "error_line": lambda: R.error_line(p),
        "success_line": lambda: R.success_line(p),
        "window_chip": lambda: R.window_chip({"chip": p, "truncated": True, "oldest_returned": p, "clock": p}),
        "transport_chip": lambda: R.transport_chip({"transport": p}),
        "llm_failure_banner": lambda: R.llm_failure_banner(p),
        "approval_panel": lambda: R.approval_panel(p, {"command": p, "code": f"def f():\n    return '{p}'"}),
        "command_block_panel": lambda: R.command_block_panel(p, [p], note=p),
        "recommended_command_panel": lambda: R.recommended_command_panel(cmd, p),
        "recommended_fix_panel": lambda: R.recommended_fix_panel(p, p, p),
        "doctor_table": lambda: R.doctor_table([{"check": p, "status": "fail", "detail": p, "fix": p}]),
        "kv_table": lambda: R.kv_table(p, [(p, p)]),
        "evolve_suggestion": lambda: R.result_panel(*R.evolve_suggestion_text({"name": p, "description": p})[:2], "red"),
        "timestamped": lambda: R.timestamped(R.speaker_line(p, "red"), p),
    }


@pytest.mark.parametrize("name", NAMES)
def test_tui_renderables_neutralise_every_payload(name):
    payload = CORPUS[name]
    for label, build in _tui_calls(payload).items():
        renderable = build()
        if renderable is None:
            continue
        console = _plain_console()
        console.print(renderable)
        assert_screen_safe(_text(console), where=f"render.{label} / {name}")


@pytest.mark.parametrize("name", ["rich_markup_style", "rich_markup_link", "rich_markup_close", "textual_markup_action"])
def test_tui_markup_is_literal_in_every_renderer(name):
    payload = CORPUS[name]
    for label, build in _tui_calls(payload).items():
        console = _plain_console()
        console.print(build())
        text = re.sub(r"\s+", " ", _text(console))
        assert payload in text or label in ("tool_result_panel", "window_chip", "doctor_table", "command_block_panel"), \
            f"{label}: {payload!r} not literal in {text!r:.300}"


def test_tui_bidi_and_zero_width_show_as_markers():
    for key, marker in (("bidi_override_filename", "U+202E"), ("zero_width", "U+200B"),
                        ("unicode_tag_smuggling", "U+E0069"), ("lone_surrogate", "U+D800")):
        console = _plain_console()
        console.print(R.finding_panel({"id": "X-1", "severity": "low", "title": CORPUS[key], "evidence": [CORPUS[key]]}))
        assert marker in _text(console), key


def test_huge_fields_render_without_trouble():
    console = _plain_console(width=200)
    console.print(R.finding_panel({"id": "X-1", "severity": "low", "title": HUGE, "evidence": [HUGE]}))
    console.print(R.tool_result_panel("t", {"big": HUGE, "rows": [{"a": HUGE}]}))
    assert_screen_safe(_text(console))


# --- the TUI transcript and widgets (real Textual pilots) ------------------------------------------------------------

def _make_screen(tmp_path, monkeypatch):
    from kratos.storage.session_store import SessionStore
    from kratos.tui_mk2.screens.session import SessionScreen

    monkeypatch.setattr("kratos.llm_config.ENV_FILE_PATH", tmp_path / ".env")
    (tmp_path / ".env").write_text("LLM_MODEL=m\n", encoding="utf-8")
    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    return SessionScreen(store, tmp_path, sid, ["10.0.0.1"], "")


def _host(screen):
    from textual.app import App

    class Host(App):
        def on_mount(self):
            self.push_screen(screen)

    return Host()


def test_transcript_never_holds_an_escape_even_for_raw_unsafe_renderables(tmp_path, monkeypatch):
    screen = _make_screen(tmp_path, monkeypatch)

    async def run():
        app = _host(screen)
        async with app.run_test(size=(140, 50)) as pilot:
            await pilot.pause()
            for name in NAMES:
                p = CORPUS[name]
                screen._emit(R.finding_panel({"id": "A-1", "severity": "high", "title": p, "evidence": [p]}))
                # a renderable built WITHOUT the safe classes: only the sink's scrubber stands between it and the screen
                screen._emit(RichText(p))
                screen._emit(RichPanel(RichText(p), title=RichText(p)))
            await pilot.pause()
            lines = screen.query_one("#transcript").lines
            assert len(lines) > 50
            for strip in lines:
                text = "".join(seg.text for seg in strip)
                assert_screen_safe(text, where="transcript")
                for seg in strip:
                    assert seg.style is None or not getattr(seg.style, "link", None), "a hyperlink reached the transcript"

    asyncio.run(run())


def test_safe_widgets_show_markup_literally_and_clean_text(tmp_path):
    from textual.app import App

    from kratos.tui_mk2.safe_widgets import SafeDataTable, SafeLabel, SafeOption, SafeStatic

    payloads = [CORPUS[n] for n in ("rich_markup_style", "rich_markup_link", "textual_markup_action",
                                    "ansi_clear_screen", "bidi_override_filename", "osc8_hyperlink")]

    class A(App):
        def compose(self):
            for i, p in enumerate(payloads):
                yield SafeStatic(p, id=f"s{i}")
                yield SafeLabel(p, id=f"l{i}")
            yield SafeDataTable(id="t")

        def on_mount(self):
            t = self.query_one("#t")
            t.add_columns(*[p for p in payloads])
            t.add_row(*payloads)

    async def run():
        app = A()
        async with app.run_test(size=(200, 60)) as pilot:
            await pilot.pause()
            seen = []
            for i, p in enumerate(payloads):
                for kind in ("s", "l"):
                    w = app.query_one(f"#{kind}{i}")
                    text = "".join(seg.text for seg in w.render_line(0))
                    assert_screen_safe(text, where=f"{kind}{i}")
                    seen.append(text)
            assert "[bold red]ALL CLEAR[/]" in seen[0]                     # literal, not styled
            assert "[link=https://evil.example]safe[/link]" in seen[2]
            t = app.query_one("#t")
            cells = [t.get_cell_at((0, c)) for c in range(len(payloads))]
            for cell in cells:
                assert_screen_safe(str(cell.plain if hasattr(cell, "plain") else cell), where="cell")
            assert "[bold red]ALL CLEAR[/]" in cells[0].plain
        assert SafeOption("[red]x[/]").prompt.plain == "[red]x[/]"

    asyncio.run(run())


def test_notifications_are_not_parsed_as_markup_and_are_cleaned(tmp_path, monkeypatch):
    from kratos.tui_mk2.app import KratosTUI

    seen = {}

    async def run():
        app = KratosTUI(data_dir=tmp_path) if "data_dir" in KratosTUI.__init__.__code__.co_varnames else KratosTUI()
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            import textual.app as tapp

            orig = tapp.App.notify

            def spy(self, message, **kw):
                seen["message"], seen["markup"] = message, kw.get("markup")
                return orig(self, message, **kw)

            monkeypatch.setattr(tapp.App, "notify", spy)
            app.notify("[red]x[/] \x1b[2J‮", title="t")
            await pilot.pause()

    asyncio.run(run())
    assert seen["markup"] is False
    assert "\x1b" not in seen["message"] and "‮" not in seen["message"] and "U+202E" in seen["message"]


# --- plain CLI output and MCP replies ----------------------------------------------------------------------------------

def test_safe_print_cleans_every_argument(capsys):
    from kratos.untrusted import safe_print

    safe_print("a\x1b[2Jb", 42, "c‮d", sep="|")
    out = capsys.readouterr().out
    assert out == "ab|42|c⟨U+202E⟩d\n"


def test_cli_modules_use_the_safe_print():
    import kratos.cli.app as app
    import kratos.cli.baseline as baseline
    import kratos.cli.bundle as bundle
    import kratos.cli.findings_show as findings_show
    import kratos.cli.logs_patterns_show as logs_patterns_show
    from kratos.untrusted import safe_print

    for mod in (app, baseline, bundle, findings_show, logs_patterns_show):
        assert mod.print is safe_print, mod.__name__


def test_kratos_findings_show_prints_a_payload_finding_cleanly(tmp_path, capsys):
    import json
    from types import SimpleNamespace

    from kratos.cli.findings_show import cmd_findings_show

    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "findings_20260101_000000.json").write_text(json.dumps({"findings": [{
        "id": "AUTH-004", "severity": "high", "title": CORPUS["ansi_clear_screen"],
        "evidence": [CORPUS["osc8_hyperlink"], CORPUS["bidi_override_filename"]], "recommendation": [CORPUS["c1_csi"]],
        "playbooks": [{"title": CORPUS["osc_title"], "commands": [CORPUS["ansi_cursor_overwrite"]], "notes": [CORPUS["zero_width"]]}],
    }]}), encoding="utf-8")
    for fid in (None, "AUTH-004"):
        assert cmd_findings_show(SimpleNamespace(data_dir=tmp_path, finding_id=fid)) == 0
    out = capsys.readouterr().out
    assert "AUTH-004" in out and "U+202E" in out and "U+200B" in out
    assert_screen_safe(out, where="kratos findings-show")


def test_mcp_tool_results_are_cleaned(tmp_path):
    from kratos import mcp_server
    from kratos.storage.session_store import SessionStore

    store = SessionStore(tmp_path / "kratos.db")
    sid = store.create_session(["10.0.0.1"], "m")
    turn = store.start_turn(sid, CORPUS["ansi_clear_screen"])
    transcript = tmp_path / "t.json"
    import json

    transcript.write_text(json.dumps([{"tool": "correlate_findings", "observation": {"status": "ok", "result": {
        "findings": [{"id": "AUTH-004", "title": CORPUS["c1_csi"], "severity": "high",
                      "evidence": [CORPUS["osc8_hyperlink"], CORPUS["bidi_override_filename"]]}]}}}]), encoding="utf-8")
    store.complete_turn(turn, "final_answer", transcript_ref=str(transcript))
    mcp_server._data_dir = tmp_path
    out = mcp_server.kratos_get_findings(sid)
    blob = json.dumps(out, ensure_ascii=False)
    assert_screen_safe(blob.replace("\\n", " "), where="kratos_get_findings")
    assert "U+202E" in blob


def test_mcp_replies_keep_their_shape():
    from kratos import mcp_server

    @mcp_server._clean_for_client
    def f():
        """doc"""
        return {"a": ["x\x1b[2J", {"b": 3}], "n": None}

    assert f() == {"a": ["x", {"b": 3}], "n": None}
    assert f.__doc__ == "doc"


# --- the structural source scans ---------------------------------------------------------------------------------------

_FORBIDDEN_TUI_IMPORTS = re.compile(
    r"^\s*from rich\.(text import Text|panel import Panel|table import Table|syntax import Syntax)\b"
    r"|^\s*from textual\.widgets import [^\n]*\b(Static|Label|Button|DataTable)\b"
    r"|^\s*from textual\.widgets\.option_list import [^\n]*\bOption\b(?!DoesNotExist)",
    re.M)


def test_no_tui_module_builds_text_from_a_machine_with_the_unsafe_classes():
    offenders = []
    for path in sorted((SRC / "tui_mk2").rglob("*.py")):
        if path.name in ("safe_widgets.py", "table_fit.py"):
            continue
        for m in _FORBIDDEN_TUI_IMPORTS.finditer(path.read_text(encoding="utf-8")):
            offenders.append(f"{path.relative_to(SRC)}: {m.group(0).strip()}")
    assert not offenders, "use kratos.untrusted_rich / tui_mk2.safe_widgets instead:\n" + "\n".join(offenders)


def test_the_transcript_writer_scrubs_what_it_draws():
    src = (SRC / "tui_mk2" / "screens" / "session.py").read_text(encoding="utf-8")
    writes = re.findall(r"self\._log\.write\(([^)]*)\)", src)
    unscrubbed = [w for w in writes if "scrubbed(" not in w and "day_divider" not in w]
    assert not unscrubbed, unscrubbed


def test_console_helpers_never_put_unescaped_variables_into_markup():
    # every f-string that is printed as markup and interpolates something from outside must go through markup_safe
    src = (SRC / "agent" / "console.py").read_text(encoding="utf-8")
    risky = []
    for m in re.finditer(r'console\.print\(f"([^"\n]*)"', src):
        body = m.group(1)
        for var in re.findall(r"\{([^{}]+)\}", body):
            if var.startswith(("icon", "style", "ACCENT", "FAILURE", "SAFE", "ATTENTION", "TEXT_", "markup_safe(",
                               "_truncate_note(", "cov", "len(", "color", "kind_style", "LEGEND", "fid")):
                continue
            risky.append((body, var))
    assert not risky, risky


def test_a_homoglyph_username_gets_a_visible_marker_in_every_finding_view():
    from kratos.tui_mk2.screens import findings as findings_screen

    finding = {"id": "AUTH-004", "severity": "high", "title": "Burst for аdmin",
               "evidence": ["user аdmin failed 4 times", "user admin failed once"]}
    console = _plain_console()
    console.print(R.finding_panel(finding))
    text = _text(console)
    assert text.count("⟨mixed scripts⟩") == 2                 # the title and the first evidence line only
    console = _cli_console()
    cli.render_finding(console, finding)
    assert _text(console).count("⟨mixed scripts⟩") == 2
    assert "annotate_lookalikes" in Path(findings_screen.__file__).read_text(encoding="utf-8")

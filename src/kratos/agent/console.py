"""
Sprint 3 Phase 2 -- Rich-based rendering for Kratos's CLI. Presentation only,
per docs/sprint3_phase1_cli_overhaul_design.md (Phase 1, approved) and the
Phase 2 scoping decisions recorded in that conversation:

- Scope is `kratos investigate` (cli/app.py::cmd_investigate) plus the ONE
  shared human-approval gate (agent/tools.py::request_approval) -- not the
  ~16 fixed-pipeline subcommands (`scan`, `chat`, `run`, etc.), which keep
  their existing plain-text output. See CLAUDE.md Sprint 3 backlog for the
  "CLI-wide Rich migration for non-investigate subcommands" item this
  deliberately does not attempt.
- request_approval renders ONE generic situation panel built from whatever
  keys are present in its `details` dict, regardless of which tool/gate
  called it (self-write keep, run_linux_command, capture_traffic, live
  threat-intel, vulscan staleness) -- a single shared choke point, not a
  bespoke code path per tool. No control-flow change: request_approval and
  agent/self_approve.py both still block on input(), still have no
  force-accept fallback anywhere in this module.
- No live "in progress" spinner exists for individual tool calls (nmap,
  yara, vulscan, sandbox test) -- agent/loop.py's on_step callback only
  fires AFTER a tool call has already completed (see run_agent's docstring:
  "the moment it's produced"), and changing that timing would mean changing
  agent/loop.py's tool-dispatch logic, explicitly out of scope per the
  design doc. The one genuinely long, observable gap from the CLI's
  perspective is the LLM-call-plus-tool-round-trip BETWEEN consecutive
  on_step calls (the design doc's own operational-facts section: ~76-90s+
  per call locally) -- thinking_spinner() below covers exactly that gap,
  bracketed entirely from cli/app.py's on_step wrapper, without touching
  agent/loop.py at all.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from rich.console import Console, ConsoleDimensions, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from kratos.adapters.findings_engine import FINDING_SUMMARY_TEMPLATES, GENERIC_FINDING_SUMMARY

_no_color_default = False
_console: Console | None = None
_stderr_console: Console | None = None

# Sprint 3 formalized visual identity palette (2026-07-16) -- six named color
# roles, single source of truth for every render helper below. Rich accepts
# hex directly in both markup (f"[{SAFE}]text[/]") and style parameters
# (border_style=SAFE) with no wrapping needed either way. `--no-color`
# behavior is unaffected: Console(no_color=True) strips ANSI color codes at
# the Console level regardless of whether the source was a hex value or a
# named keyword like "green" -- same mechanism as before this pass.
ACCENT = "#5dc9d6"
SAFE = "#5cc270"
ATTENTION = "#e6b45a"
FAILURE = "#e2504a"
TEXT_PRIMARY = "#d6d9de"
TEXT_SECONDARY = "#7f8890"

LEGEND = (
    f"[{SAFE}]green[/] = passed / safe / done    "
    f"[{ATTENTION}]amber[/] = attention / in progress / decision needed    "
    f"[{FAILURE}]red[/] = finding / failure"
)

SEVERITY_STYLE = {
    "critical": FAILURE,
    "high": FAILURE,
    "medium": ATTENTION,
    "low": ATTENTION,
    "info": SAFE,
}

# Plain-language, presentation-only labels for the routine tool-call line.
# Falls back to a humanized tool_name (underscores -> spaces) for anything
# not listed here, including future/kept tools -- never raises on an
# unknown name.
TOOL_PLAIN_LABELS = {
    "run_nmap_scan": "Scanned for open network ports",
    "run_yara_scan": "Scanned files for known malicious signatures",
    "run_vuln_scan": "Checked for known vulnerabilities",
    "check_ip_reputation": "Checked an IP's reputation",
    "collect_system_context": "Collected system context",
    "parse_auth_log": "Parsed authentication logs",
    "read_journalctl": "Read system journal logs",
    "list_open_files": "Listed open files",
    "list_processes": "Listed running processes",
    "check_file_integrity": "Checked file integrity against baseline",
    "run_config_audit": "Audited security configuration",
    "send_notification": "Sent a notification",
    "run_linux_command": "Ran a command",
    "capture_traffic": "Captured network traffic",
    "correlate_findings": "Correlated findings across collected data",
}

_SUBTEST_LINE_RE = re.compile(r'^.*::\S+\s+(PASSED|FAILED|ERROR|SKIPPED)\b.*$', re.MULTILINE)
_CODE_LIKE_RE = re.compile(r'\b(def|class|import)\s')


def configure(no_color: bool) -> None:
    """Call once, early, from cli/app.py::main() -- resets the cached Console
    instances so every later get_console()/get_stderr_console() call (in
    this module and in agent/tools.py::request_approval) picks up the
    setting, including calls from deep inside a tool implementation that
    has no access to argparse's `args`."""
    global _no_color_default, _console, _stderr_console
    _no_color_default = no_color
    _console = None
    _stderr_console = None


def _environ_without_stale_size_vars() -> dict[str, str]:
    """Real fix (2026-07-17, real user report): Rich's own Console.size
    property (rich/console.py) checks the REAL terminal via
    os.get_terminal_size() first, but then OVERRIDES that live value with
    the COLUMNS/LINES environment variables if they happen to be set and
    numeric -- confirmed by reading Rich's actual source, not assumed. Env
    vars are captured once at process start and never update on their own
    when a real terminal is resized (only a live ioctl query does), so on
    any shell/terminal setup that happens to export COLUMNS/LINES (common
    -- tmux, some shell configs, some terminal emulators), Rich silently
    renders every panel/table/word-wrap at the STALE launch-time size
    forever, regardless of how the real window is resized afterward.

    Confirmed via a real PTY test with a real ioctl-driven resize (the
    actual mechanism a real terminal uses, not env vars): with no stale
    COLUMNS/LINES set, Rich's word-wrap correctly re-flows at the new
    width; with them set, output visibly corrupts (words split mid-word,
    continuation lines losing their indentation) -- a direct, reproduced
    match for the reported symptom. prompt_toolkit's own size detection
    (prompt_toolkit/output/vt100.py::_get_size) has no such env-var
    override -- it always queries the live terminal -- which is why the
    input prompt/toolbar/completion menu were NOT affected, only
    everything rendered through this module's Console.

    Only COLUMNS/LINES are stripped -- Rich's Console also reads _environ
    for NO_COLOR/COLORTERM/TERM/TTY_INTERACTIVE/JUPYTER_*, all of which
    stay fully functional (a surgical filter, not Console(_environ={})).
    """
    return {k: v for k, v in os.environ.items() if k not in ("COLUMNS", "LINES")}


# Real fix, second pass (2026-07-17, same real user report -- the first
# fix above was real and confirmed, but insufficient): a resize AFTER
# content has already been printed can still corrupt that ALREADY-PRINTED
# scrollback, which no code running inside Kratos can retroactively touch
# -- by the time the terminal is resized, those characters are just fixed
# text sitting in the terminal's own history. This is the terminal
# emulator's job (reflowing scrollback to the new width), not Kratos's.
#
# The specific, verifiable reason it goes wrong for Kratos's output and
# not plain text: Rich's Panel/Table renderables are built to `expand` to
# EXACTLY the console's reported width -- every row's box-drawing
# characters reach both margins precisely. Terminals track, per row,
# whether it was "soft-wrapped" (the terminal itself broke a too-long
# line) purely by watching whether the cursor advanced past the LAST
# column before a newline -- a line that an application deliberately
# filled edge-to-edge is indistinguishable, at that level, from a line the
# terminal auto-wrapped. Reflow-on-resize (which VS Code's terminal does)
# uses exactly that flag to decide which rows to re-merge/re-split -- so a
# full-width Rich panel row is a false positive for "this was auto-
# wrapped," and gets incorrectly torn apart/reflowed on any later resize,
# independent of whether the CURRENT render used a correct or stale width.
#
# Fix: never let a render reach the console's true last column. A live,
# always-recomputed 1-column margin (NOT a fixed subtracted number baked
# in at construction, which would silently reintroduce the original
# "frozen at launch width" bug) removes the ambiguity at the source, for
# every renderable (Panel, Table, plain text) uniformly, with no per-call-
# site changes needed anywhere else in this codebase.
_WIDTH_MARGIN = 1


class _MarginConsole(Console):
    """Console whose reported width is always 1 less than the real,
    live-detected terminal width (see the module comment above this
    class). Only `.size` needs overriding -- Console.width (rich/console.py)
    is itself defined as `return self.size.width`, so every other Rich
    internal that reads either property gets the margin automatically.
    Height is untouched -- this is specifically about the horizontal
    full-width-row ambiguity, not vertical space."""

    @property
    def size(self) -> ConsoleDimensions:
        dims = super().size
        return ConsoleDimensions(max(1, dims.width - _WIDTH_MARGIN), dims.height)


def get_console() -> Console:
    global _console
    if _console is None:
        _console = _MarginConsole(
            no_color=_no_color_default, highlight=False, _environ=_environ_without_stale_size_vars()
        )
    return _console


def get_stderr_console() -> Console:
    global _stderr_console
    if _stderr_console is None:
        _stderr_console = _MarginConsole(
            no_color=_no_color_default, stderr=True, highlight=False, _environ=_environ_without_stale_size_vars()
        )
    return _stderr_console


def plain_label(tool_name: str) -> str:
    return TOOL_PLAIN_LABELS.get(tool_name, tool_name.replace("_", " ").capitalize())


def render_session_header(console: Console, goal: str, max_iters: int, ssh_target: str, backend: str) -> None:
    body = (
        f"Goal        : {goal}\n"
        f"SSH target  : {ssh_target}\n"
        f"Model       : {backend}\n"
        f"Max steps   : {max_iters}\n\n"
        f"{LEGEND}"
    )
    console.print(Panel(body, title=f"[{ACCENT}]Kratos[/] -- investigation session", border_style=ACCENT))


def unwrap_tool_result(observation: Any) -> tuple[Any, str]:
    """
    execute_tool_call() (agent/loop.py) always wraps a tool's own return
    value as {"status": "ok", "result": <tool's real return>} on the happy
    path -- the outer "status" is only ever "ok", or a wrapper-level "error"
    for a bad tool name/args, a raised exception, or the approval backstop.
    It is NEVER the tool's own domain-level status. A tool that ran to
    completion but reported its own failure (e.g. correlate_findings
    returning {"status": "error", ...} for a hallucinated file path) has
    that status nested one level deeper, inside "result" -- checking only
    the outer dict (as this function's callers used to) reads as a false
    success. Returns (the tool's own real result dict, the effective status
    to render) so a real, nested domain-level failure is never mistaken for
    "done".
    """
    if not isinstance(observation, dict):
        return observation, "done"
    if str(observation.get("status", "")).lower() == "error":
        return observation, "error"
    inner = observation.get("result")
    if isinstance(inner, dict):
        inner_status = str(inner.get("status", "")).lower()
        if inner_status in ("error", "failed"):
            return inner, "error"
        if inner_status == "not_approved":
            return inner, "warn"
        return inner, "done"
    return observation, "done"


def render_tool_call(console: Console, name: str, status: str) -> None:
    icon = {"done": f"[{SAFE}]✓[/]", "error": f"[{FAILURE}]✗[/]", "warn": f"[{ATTENTION}]![/]"}.get(status, f"[{SAFE}]✓[/]")
    console.print(f"{icon} [bold]{name}[/] -- {plain_label(name)}")


_METADATA_NOTE_CHAR_CAP = 110


def _truncate_note(text: str, limit: int = _METADATA_NOTE_CHAR_CAP) -> str:
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "... (full detail in the findings report)"


def render_tool_metadata_notes(console: Console, result: dict[str, Any]) -> None:
    """
    Compact, inline supporting-detail lines shown directly under a tool-call
    line -- NOT a panel. Sprint 3 follow-up: correlate_findings's
    missing_inputs/input_errors/staleness_warning fields previously reached
    the raw JSON/Markdown report and the model's own Observation text, but
    never the styled terminal output at all.

    Deliberately minimal, per design principle 3 (one clear focal point):
    only a populated field gets a line -- a clean result adds nothing, no
    "no issues found" filler -- one line per field, dim/secondary weight so
    a finding panel (when findings exist) stays the visual anchor, not this
    supporting detail.
    """
    input_errors = result.get("input_errors")
    if input_errors:
        text = "; ".join(f"{k}: {v}" for k, v in input_errors.items())
        console.print(f"    [dim {FAILURE}]• input_errors: {_truncate_note(text)}[/]")

    missing_inputs = result.get("missing_inputs")
    if missing_inputs:
        console.print(f"    [dim {ATTENTION}]• missing_inputs: {_truncate_note(', '.join(missing_inputs))}[/]")

    staleness_warning = result.get("staleness_warning")
    if staleness_warning:
        console.print(f"    [dim {ATTENTION}]• staleness_warning: {_truncate_note(staleness_warning)}[/]")


def render_finding(console: Console, finding: dict[str, Any]) -> None:
    fid = str(finding.get("id", "UNKNOWN"))
    severity = str(finding.get("severity") or "info").lower()
    color = SEVERITY_STYLE.get(severity, FAILURE)
    summary = FINDING_SUMMARY_TEMPLATES.get(fid, GENERIC_FINDING_SUMMARY)

    body = Text()
    body.append(summary, style="bold")
    body.append(f"\n[{fid}] {finding.get('title', '')}", style="dim")

    evidence = finding.get("evidence") or []
    if evidence:
        body.append("\n\nDetails:", style="dim")
        for e in evidence[:5]:
            body.append(f"\n  • {e}", style="dim")
        if len(evidence) > 5:
            body.append(f"\n  ... {len(evidence) - 5} more (see the full findings report)", style="dim")

    console.print(Panel(body, title=f"Finding -- {severity.upper()}", border_style=color))


def render_note(console: Console, text: str, style: str = ATTENTION) -> None:
    console.print(f"[{style}]![/{style}] {text}")


def render_error(console: Console, text: str) -> None:
    console.print(f"[{FAILURE}]✗ {text}[/]")


def render_success(console: Console, text: str) -> None:
    console.print(f"[{SAFE}]✓[/] {text}")


def render_result_panel(console: Console, title: str, body: str, border_style: str) -> None:
    console.print(Panel(body, title=title, border_style=border_style))


def render_evolve_suggestion(console: Console, name: str, description: str) -> None:
    """Evo-loop auto-suggest (2026-07-18) -- agent/loop.py's structured
    tool_proposal signal, rendered here. ATTENTION (amber), matching this
    palette's existing "nothing failed, a decision is available" use of
    that color elsewhere (render_note's own default style) -- distinct
    from SAFE (nothing to decide) and FAILURE (something's actually
    wrong). Suggestion only: this function never invokes anything --
    cli/repl.py's /evolve command is the only thing that can ever start
    evo-loop, matching the project's standing no-auto-escalation
    principle."""
    body = (
        f"[bold]{name}[/bold]\n{description}\n\n"
        "[dim]Run [/dim][bold]/evolve[/bold][dim] to have Kratos build this, or "
        '[/dim][bold]/evolve "<your own idea>"[/bold][dim] to propose something else.[/dim]'
    )
    console.print(Panel(body, title="Evo-loop suggestion", border_style=ATTENTION))


def render_evolve_harness_template(console: Console, template_text: str, suggested_path: Path) -> None:
    """cli/repl.py::_resolve_evolve_test_file's starter-scaffold display,
    shown when the suggested/given pytest harness path doesn't exist --
    2026-07-28 UX fix, real complaint: the old "create it first" message
    left a user with nothing concrete to start from. word_wrap=True
    (unlike render_target_setup_checklist's own word_wrap=False): this is
    Python source meant to be READ and copied into an editor via normal
    text selection, not typed character-by-character into a shell, so the
    exact-copy-paste risk that motivated that other panel's choice doesn't
    apply here -- same Syntax(..., word_wrap=True, background_color=
    "default") shape render_approval_situation already uses for source
    display. Never implies this should be saved as-is -- title and the
    template's own TODO comments both say so."""
    console.print(
        Panel(
            Syntax(template_text, "python", word_wrap=True, background_color="default"),
            title=f"Starter harness (save to {suggested_path}, then edit the TODOs before running /evolve again)",
            border_style=ATTENTION,
        )
    )


def render_target_setup_checklist(console: Console, checklist_text: str) -> None:
    """adapters/target_setup.py::generate_target_setup_checklist's output --
    copy-pasteable shell commands for a HUMAN to run ON the target. Kratos
    never runs these itself (see CLAUDE.md's permanent boundary on target
    execution) -- this function only ever prints text, same as every other
    render_* helper in this module. Syntax-highlighted like the evo-loop
    approval panel's source-code display (render_approval_situation), but
    word_wrap=False, deliberately different from that panel's own
    word_wrap=True: this text is meant to be copied and pasted verbatim
    into a target's shell, not just read -- soft-wrapping a long line (e.g.
    the SSH public key, one unbroken base64 token) risks a terminal
    emulator inserting a REAL newline into the clipboard at the visual wrap
    point on copy, silently corrupting that line into two invalid ones.
    Long lines instead extend past view / require horizontal scroll,
    exactly like a real shell would show them -- the underlying text stays
    byte-correct either way."""
    console.print(
        Panel(
            Syntax(checklist_text, "bash", word_wrap=False, background_color="default"),
            title="Target setup checklist -- run these ON the target, Kratos does not run them",
            border_style=ATTENTION,
        )
    )


def render_target_probe_results(console: Console, checks: list[dict[str, str]]) -> None:
    """adapters/ssh_remote.py::run_target_probe_checks's output. Same
    PASS/FAIL/UNKNOWN vocabulary and status-to-color mapping as
    _test_summary_table below (SAFE/FAILURE/ATTENTION), not a new one."""
    status_style = {"PASS": SAFE, "FAIL": FAILURE, "UNKNOWN": ATTENTION}
    table = Table(show_header=True, header_style="bold", title="Target setup check")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for c in checks:
        style = status_style.get(c["status"], TEXT_PRIMARY)
        table.add_row(c["check"], f"[{style}]{c['status']}[/{style}]", c["detail"])
    console.print(table)


def render_session_summary(console: Console, events: list[str]) -> None:
    body = "\n".join(f"- {e}" for e in events) if events else "(no notable events)"
    console.print(Panel(body, title="Session summary", border_style=ACCENT))


def thinking_spinner(console: Console, text: str = "Kratos is working...") -> Live:
    """Started immediately by the caller; covers the gap between one
    on_step() callback and the next (LLM call + tool round-trip), which is
    the only genuinely long, silent stretch reachable without touching
    agent/loop.py -- see module docstring."""
    live = Live(Spinner("dots", text=text), console=console, transient=True, refresh_per_second=8)
    live.start()
    return live


def _is_code_like(value: str) -> bool:
    return "\n" in value and bool(_CODE_LIKE_RE.search(value))


def _looks_like_test_summary(value: str) -> bool:
    return bool(_SUBTEST_LINE_RE.search(value))


def _test_summary_table(value: str) -> Table:
    table = Table(show_header=True, header_style="bold")
    table.add_column("Test")
    table.add_column("Result")
    for m in _SUBTEST_LINE_RE.finditer(value):
        text = m.group(0).strip()
        result_m = re.search(r'(PASSED|FAILED|ERROR|SKIPPED)', text)
        result = result_m.group(1) if result_m else "?"
        name = text.split("::", 1)[0] if "::" in text else text
        style = {"PASSED": SAFE, "FAILED": FAILURE, "ERROR": FAILURE, "SKIPPED": ATTENTION}.get(result, "")
        table.add_row(name, f"[{style}]{result}[/{style}]" if style else result)
    return table


def render_approval_situation(console: Console, title: str, details: dict[str, Any]) -> None:
    """
    The ONE rendering path for every human-approval gate in Kratos (self-write
    keep decisions via agent/self_approve.py, run_linux_command,
    capture_traffic, live threat-intel escalation, vulscan staleness update)
    -- called from agent/tools.py::request_approval, which is itself
    unmodified in control flow (still blocks on input(), still no
    force-accept). Driven entirely by the `details` dict's own keys/values;
    a richer dict (e.g. self-write's source code + test summary + review
    flags) simply renders more/bigger sections, not a different code path.
    """
    renderables: list[Any] = []
    for key, value in details.items():
        label = str(key).replace("_", " ").capitalize()
        text = str(value)
        renderables.append(Text(label, style="bold"))
        if _looks_like_test_summary(text):
            renderables.append(_test_summary_table(text))
        elif _is_code_like(text):
            renderables.append(Syntax(text, "python", word_wrap=True, background_color="default"))
        else:
            renderables.append(Text(text))
        renderables.append(Text(""))

    console.print()
    console.print(Panel(Group(*renderables), title=f"Approval needed: {title}", border_style=ATTENTION))


def approval_prompt_text() -> str:
    return "Approve? [y/N]: "

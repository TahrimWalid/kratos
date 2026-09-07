"""
Rich renderable builders for kratos-mk2's transcript log.

Unlike agent/console.py's render_* helpers (which PRINT to a Console), these
RETURN Rich renderables (Text / Panel / Table) so they can be written into a
Textual RichLog widget with RichLog.write(...). The mk2 palette (theme.py) is
used throughout, not console.py's classic-REPL palette.

Tool-result unwrapping and the plain-language tool labels are shared with the
classic REPL by importing from agent/console.py -- that logic (unwrap_tool_result,
plain_label, the finding-summary templates) is presentation-neutral, so there
is no reason to fork it.
"""
from __future__ import annotations

from typing import Any

from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from kratos.agent.console import plain_label, unwrap_tool_result  # reused, palette-neutral
from kratos.adapters.findings_engine import FINDING_SUMMARY_TEMPLATES, GENERIC_FINDING_SUMMARY
from kratos.tui_mk2 import theme as T

__all__ = [
    "unwrap_tool_result",
    "tool_call_line",
    "finding_panel",
    "result_panel",
    "note_line",
    "error_line",
    "success_line",
    "speaker_line",
    "timestamped",
    "day_divider",
    "approval_panel",
    "recommended_fix_panel",
]


def timestamped(left: Text, time_str: str) -> Table:
    """A message-header line with `left` at the left edge and a fine-print,
    right-aligned time on the same line (WhatsApp-style, mirroring the classic
    REPL's _print_trailing_timestamp). `time_str` is pre-formatted in the
    display zone by the caller via kratos.utils.timeutil -- this layer never
    touches raw datetimes, so display-zone resolution lives in exactly one
    place. A Table.grid does the alignment so it stays correct at any width;
    the timestamp is TEXT_FAINTER so it reads as a caption, not a headline."""
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(justify="right")
    grid.add_row(left, Text(time_str, style=T.TEXT_FAINTER))
    return grid


def day_divider(date_str: str) -> Rule:
    """A subtle full-date separator, shown once when the display-zone day
    changes (like a messaging app's date chip). `date_str` is pre-formatted in
    the display zone by the caller (timeutil). Mirrors the classic REPL's
    _DayMarker."""
    return Rule(date_str, style=T.TEXT_GHOST, characters="·")


def tool_description(tool: Any, meta_entry: dict[str, Any] | None) -> str:
    """The human-facing 'what it does' line for a tool, shared by /tools and the
    Settings Tools tab. Prefers a human/AI-written description stored in the
    kept-tool metadata (set from Settings), then falls back to the tool's own
    registered @register_tool description (first line), then a placeholder."""
    md = (meta_entry or {}).get("description")
    if md and str(md).strip():
        return str(md).strip()
    registered = (getattr(tool, "description", "") or "").strip().splitlines()
    return registered[0] if registered else "(no description)"


def tool_call_line(name: str, status: str) -> Text:
    icon, color = {
        "done": ("✓", T.SAFE),
        "error": ("✗", T.CRITICAL),
        "warn": ("!", T.ATTENTION),
    }.get(status, ("✓", T.SAFE))
    t = Text()
    t.append(f"{icon} ", style=color)
    t.append(name, style=f"bold {T.ACCENT}")
    t.append(f"  {plain_label(name)}", style=T.TEXT_MUTED)
    return t


def _time_subtitle(time_str: str | None) -> Text | None:
    """The in-bubble timestamp: a fine-print, display-zone time tucked into a
    panel's bottom-right border, like a chat app's per-message time. `time_str`
    is pre-formatted by the caller (timeutil); None/"" -> no subtitle."""
    if not time_str:
        return None
    return Text(f" {time_str} ", style=T.TEXT_FAINTER)


def finding_panel(finding: dict[str, Any], time_str: str | None = None) -> Panel:
    fid = str(finding.get("id", "UNKNOWN"))
    severity = str(finding.get("severity") or "info").lower()
    color = T.SEVERITY_COLOR.get(severity, T.CRITICAL)
    summary = FINDING_SUMMARY_TEMPLATES.get(fid, GENERIC_FINDING_SUMMARY)

    body = Text()
    body.append(summary, style=f"bold {T.TEXT_BRIGHT}")
    body.append(f"\n[{fid}] {finding.get('title', '')}", style=T.TEXT_DIM)

    evidence = finding.get("evidence") or []
    if evidence:
        body.append("\n\nDetails:", style=T.TEXT_DIM)
        for e in evidence[:5]:
            body.append(f"\n  • {e}", style=T.TEXT_MUTED)
        if len(evidence) > 5:
            body.append(f"\n  … {len(evidence) - 5} more (see /report)", style=T.TEXT_FAINT)

    return Panel(
        body,
        title=f"Finding — {severity.upper()}",
        title_align="left",
        subtitle=_time_subtitle(time_str),
        subtitle_align="right",
        border_style=color,
    )


def llm_failure_banner(detail: str) -> Panel:
    """Design 14a -- a full-width banner for Kratos's OWN model/API failure,
    distinct from a tool or target problem (which render as inline gutter
    lines). It blocks the whole turn, not one step, so it gets banner weight
    and says plainly "Kratos can't think" rather than looking like a tool
    error. Expands to the full transcript width in the RichLog."""
    body = Text()
    body.append(
        "Kratos couldn't reach its own language model — this is Kratos's reasoning layer, "
        "not a problem with the target or any tool.\n\n",
        style=T.TEXT,
    )
    body.append(f"Detail: {detail}\n", style=T.TEXT_DIM)
    body.append(
        "Check the backend is running (e.g. `kratos llm-serve` for local Ollama) or switch it "
        "with /model, then try the goal again.",
        style=T.TEXT_FAINT,
    )
    return Panel(
        body,
        title="⚠ Kratos can't think — language model unavailable",
        title_align="left",
        border_style=T.CRITICAL,
    )


def result_panel(title: str, body: str, color: str, time_str: str | None = None) -> Panel:
    return Panel(
        Text(body, style=T.TEXT),
        title=title,
        title_align="left",
        subtitle=_time_subtitle(time_str),
        subtitle_align="right",
        border_style=color,
    )


def _prefixed(symbol: str, text: str, color: str) -> Text:
    t = Text()
    t.append(f"{symbol} ", style=color)
    t.append(text, style=color)
    return t


def note_line(text: str) -> Text:
    return _prefixed("!", text, T.ATTENTION)


def compaction_line(context_tokens: int = 0, context_window: int = 0) -> Text:
    """Feature 14b: a receding, informational line marking that the model's
    working context was compacted mid-investigation. Deliberately NOT the amber
    "!" notice style -- it's not a warning or a decision the human must act on;
    earlier steps are just summarized to fit the window, with the full detail
    preserved in the saved transcript (agent/loop.py's compaction only ever
    shrinks the model's prompt, never the record). Rendered faint, like the
    "Done in Ns" footer."""
    line = Text()
    line.append("⤵ context compacted", style=T.TEXT_MUTED)
    if context_window > 0 and context_tokens > 0:
        line.append(
            f"  (was {context_tokens / 1000:.1f}k/{context_window / 1000:.1f}k of the model window) ",
            style=T.TEXT_FAINTER,
        )
    else:
        line.append("  ", style=T.TEXT_FAINTER)
    line.append("— earlier steps summarized; full detail kept in the transcript", style=T.TEXT_FAINTER)
    return line


def error_line(text: str) -> Text:
    return _prefixed("✗", text, T.CRITICAL)


def success_line(text: str) -> Text:
    return _prefixed("✓", text, T.SAFE)


def speaker_line(label: str, color: str) -> Text:
    """A 'Kratos:' / 'you>' style speaker label on its own line."""
    return Text(label, style=f"bold {color}")


def recommended_fix_panel(title: str, command: str, footnote: str) -> Panel:
    """Turn 19b -- recommend-only remediation: the exact command shown for the
    human to run in their OWN session, explicitly NOT executed by Kratos."""
    body = Group(
        Syntax(command, "bash", word_wrap=False, background_color="default"),
        Text(footnote, style=T.TEXT_FAINT),
    )
    return Panel(body, title=f"✓ {title}", title_align="left", border_style=T.SAFE)


def recommended_command_panel(cmd: dict[str, Any], target_label: str) -> Panel:
    """Design 19b -- a recommend-only remediation command the agent produced
    (structured `recommended_commands` from run_agent, feature 19b backend).
    Green, calm, and explicit that Kratos does NOT run it: it's for the human
    to run in their own session (matching the project's permanent
    observe-and-recommend boundary). Copyable via ctrl+y."""
    run_on = str(cmd.get("run_on") or "target")
    where = target_label if run_on == "target" else "Kratos's own host"
    parts: list[Any] = []
    explanation = str(cmd.get("explanation") or "").strip()
    if explanation:
        parts.append(Text(explanation, style=T.TEXT))
        parts.append(Text(""))
    parts.append(Syntax(str(cmd.get("command") or ""), "bash", word_wrap=False, background_color="default"))
    parts.append(Text(f"Run this yourself on {where} — Kratos does not execute it.", style=T.TEXT_FAINT))
    return Panel(Group(*parts), title="✓ recommended fix", title_align="left", border_style=T.SAFE)


_SUBTEST_MARKERS = ("PASSED", "FAILED", "ERROR", "SKIPPED")


def approval_panel(title: str, details: dict[str, Any]) -> Panel:
    """Mirror of agent/console.py::render_approval_situation, but returning a
    renderable for the Textual approval modal instead of printing. Same
    generic 'render whatever keys the details dict has' behavior, so the same
    callers (run_linux_command, capture_traffic, self-write keep, threat-intel,
    vulscan staleness, /reset, /delete) all render through it unchanged."""
    parts: list[Any] = []
    for key, value in details.items():
        label = str(key).replace("_", " ").capitalize()
        text = str(value)
        parts.append(Text(label, style=f"bold {T.TEXT_BRIGHT}"))
        if "\n" in text and any(m in text for m in _SUBTEST_MARKERS):
            parts.append(_subtest_table(text))
        elif "\n" in text and any(kw in text for kw in ("def ", "class ", "import ")):
            parts.append(Syntax(text, "python", word_wrap=True, background_color="default"))
        else:
            parts.append(Text(text, style=T.TEXT))
        parts.append(Text(""))
    return Panel(Group(*parts), title=f"Approval needed: {title}", title_align="left", border_style=T.ATTENTION)


def _subtest_table(value: str) -> Table:
    import re

    table = Table(show_header=True, header_style="bold")
    table.add_column("Test")
    table.add_column("Result")
    for line in value.splitlines():
        m = re.search(r"(PASSED|FAILED|ERROR|SKIPPED)", line)
        if not m or "::" not in line:
            continue
        result = m.group(1)
        name = line.split("::", 1)[0].strip()
        color = {"PASSED": T.SAFE, "FAILED": T.CRITICAL, "ERROR": T.CRITICAL, "SKIPPED": T.ATTENTION}.get(result, "")
        table.add_row(name, Text(result, style=color))
    return table


def profile_blurb(values: dict[str, Any]) -> str:
    """Honest per-backend cost/privacy line, derived from the profile's own
    endpoint (not a hardcoded list): a loopback base URL is a local model (free,
    private); anything else is a remote/cloud endpoint that sees the prompts and
    is usually billed. Shared by the session's /model confirm and the Settings
    Models tab, so both read the same with or without a live session."""
    url = (values.get("LLM_BASE_URL") or "").lower()
    if any(h in url for h in ("127.0.0.1", "localhost", "::1", "0.0.0.0")):
        return "local · free · private (nothing leaves this host)"
    return "cloud API · sends prompts to a third party · usage-billed"


def doctor_table(checks: list[dict[str, str]]) -> Table:
    """Render /doctor's diagnostic rows as a color-coded status table:
    ✓ pass (safe) · ✗ fail (critical) · ! warn (attention) · · info (dim)."""
    icons = {
        "pass": ("✓", T.SAFE),
        "fail": ("✗", T.CRITICAL),
        "warn": ("!", T.ATTENTION),
        "info": ("·", T.TEXT_DIM),
    }
    table = Table(show_header=False, box=None, title="Kratos — self-diagnostic",
                  title_justify="left", title_style=f"bold {T.ACCENT}")
    table.add_column(width=1, no_wrap=True)
    table.add_column(style=T.TEXT_BRIGHT, no_wrap=True)
    table.add_column(style=T.TEXT_MUTED)
    for c in checks:
        icon, color = icons.get(c.get("status", "info"), ("·", T.TEXT_DIM))
        table.add_row(Text(icon, style=color), Text(str(c.get("check", "")), style=color),
                      Text(str(c.get("detail", "")), style=T.TEXT_DIM))
    return table

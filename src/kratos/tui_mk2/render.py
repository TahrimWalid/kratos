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
    "approval_panel",
    "recommended_fix_panel",
]


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


def finding_panel(finding: dict[str, Any]) -> Panel:
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

    return Panel(body, title=f"Finding — {severity.upper()}", title_align="left", border_style=color)


def result_panel(title: str, body: str, color: str) -> Panel:
    return Panel(Text(body, style=T.TEXT), title=title, title_align="left", border_style=color)


def _prefixed(symbol: str, text: str, color: str) -> Text:
    t = Text()
    t.append(f"{symbol} ", style=color)
    t.append(text, style=color)
    return t


def note_line(text: str) -> Text:
    return _prefixed("!", text, T.ATTENTION)


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

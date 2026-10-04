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

import re
from typing import Any

from rich import box
from rich.align import Align
from rich.columns import Columns
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
    "plan_preview_panel",
    "response_plan_panel",
]


def _home_card(label: str, value: Text) -> Panel:
    """One card for the idle home banner (TARGET / MODE / TOOLS). The label sits
    in the rounded top border; the value fills the body."""
    return Panel(value, title=Text(f" {label} ", style=T.TEXT_FAINTER),
                 title_align="left", box=box.ROUNDED, border_style=T.BORDER,
                 padding=(0, 2))


def home_banner(target: str, n_builtin: int, n_kept: int, *,
                model: str = "", model_is_local: bool = False,
                resumed: bool = False) -> Group:
    """The idle / home screen: a centered KRATOS wordmark, a one-line identity,
    three at-a-glance cards (target · model · tools), and starter tips, all
    centred (write it at the full transcript width so it centres). Shown
    when a session has no messages yet. The wordmark + 'Kratos:' voice use the
    active theme's brand color (red by default), so this restyles with the theme.

    The MODEL card shows the active model and whether it's local (free, private)
    or cloud (billed, sees your data) -- a value that actually varies (via
    /model) and carries the pivot's cost/privacy signal, unlike a fixed 'mode'."""
    # Four spaces between letters: 26 cells over the subtitle's 18, an even
    # difference, so the wordmark overhangs by exactly 4 cells on each side at
    # any terminal width (an odd difference can't centre on a character grid).
    wordmark = Align.center(Text("    ".join("KRATOS"), style=f"bold {T.KRATOS_RED}"))
    subtitle = Align.center(Text("security assistant", style=T.TEXT_FAINT))

    tgt = Text(target or "(none set)", style=f"bold {T.ACCENT}" if target else T.TEXT_DIM)
    mdl = Text()
    mdl.append(model or "(unset)", style=f"bold {T.TEXT_BRIGHT}" if model else T.TEXT_DIM)
    if model:
        mdl.append("  ·  local · free" if model_is_local else "  ·  cloud · billed",
                   style=T.SAFE if model_is_local else T.ATTENTION)
    tools = Text()
    tools.append(f"{n_builtin} built-in", style=f"bold {T.TEXT_BRIGHT}")
    tools.append(f" · {n_kept} built by you", style=T.TEXT_MUTED)
    cards = Align.center(Columns(
        [_home_card("TARGET", tgt), _home_card("MODEL", mdl), _home_card("TOOLS LOADED", tools)],
        padding=(0, 1), expand=False))

    # Static, ordered by what a first-time user actually does: connect a machine,
    # ask a question, learn more. (No "connect a sub-agent" tip -- that path isn't
    # built yet; /target is how you point Kratos at a host today.)
    tips = Text()
    # Every line stays under ~66 columns, so the block is whole (and centred) on
    # an 80-column terminal, where the transcript is about 71 wide.
    if target:
        # A machine is already connected: say what to do next, not how to connect.
        tips.append("ready  ", style=f"bold {T.TEXT_FAINTER}")
        tips.append("ask about this machine in plain words  ·  ", style=T.TEXT_DIM)
        tips.append("/target", style=T.ACCENT)
        tips.append(" to switch\n", style=T.TEXT_DIM)
    else:
        tips.append("new here?  ", style=f"bold {T.TEXT_FAINTER}")
        tips.append("/target <host>", style=T.ACCENT)
        tips.append(" to connect, then ask in plain words\n", style=T.TEXT_DIM)
    tips.append("  ·  try  ", style=T.TEXT_FAINTER)
    tips.append("“check this host for signs of an SSH brute-force”\n", style=T.TEXT_MUTED)
    tips.append("  ·  ", style=T.TEXT_FAINTER)
    tips.append("/guide", style=T.ACCENT)
    tips.append(" getting started   ", style=T.TEXT_DIM)
    tips.append("/doctor", style=T.ACCENT)
    tips.append(" check setup   ", style=T.TEXT_DIM)
    tips.append("?", style=T.ACCENT)
    tips.append(" all commands", style=T.TEXT_DIM)

    parts: list[Any] = [Text(""), wordmark, subtitle, Text(""), cards, Text("")]
    if resumed:
        parts.append(Align.center(Text("— resumed prior context loaded —", style=T.TEXT_FAINTER)))
        parts.append(Text(""))
    # Centred as a block (its lines stay left-aligned), like the cards above.
    parts.append(Align.center(tips))
    parts.append(Text(""))
    return Group(*parts)


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
    """The human-facing 'what it does' line for a tool (/tools, Settings → Tools):
    one plain sentence, never the model-facing instructions (agent/tool_summaries)."""
    from kratos.agent.tool_summaries import human_summary

    return human_summary(getattr(tool, "name", "") or "", tool, meta_entry) or "(no description)"


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


def window_chip(window: dict[str, Any]) -> Text | None:
    """The time-window chip under a time-scoped tool call (docs/time_window_design.md
    §3/§4): which exact period was queried, whether it was fully covered, and any clock
    warning -- so a misread window is visible at a glance, never buried."""
    if not isinstance(window, dict) or not (window.get("chip") or window.get("since_utc")):
        return None
    t = Text("    window ", style=T.TEXT_FAINTER)
    t.append(str(window.get("chip") or f"{window.get('since_utc')} → {window.get('until_utc')}"), style=T.TEXT_MUTED)
    pct = window.get("coverage_percent")
    if isinstance(pct, (int, float)):
        if pct >= 100:
            t.append("  · counted in full", style=T.TEXT_FAINTER)
        else:
            t.append(f"  · PARTIAL: {pct:g}% of the window covered", style=T.ATTENTION)
    elif window.get("truncated"):
        t.append(f"  · PARTIAL: nothing seen before {window.get('oldest_returned')}", style=T.ATTENTION)
    else:
        t.append("  · complete", style=T.TEXT_FAINTER)
    if window.get("clock"):
        off = window.get("target_clock_offset_s")
        t.append(f"  · target clock {off:+.0f}s" if isinstance(off, (int, float)) else "  · clock unknown",
                 style=T.ATTENTION)
    return t


def transport_chip(result: Any) -> Text | None:
    """How a target read was obtained, when it wasn't plain SSH: through the
    target's sub-agent, or through it because SSH failed (amber -- a fallback
    should never pass unnoticed). docs/subagent_read_routing.md §5."""
    note = result.get("transport") if isinstance(result, dict) else None
    if not isinstance(note, str) or not note:
        return None
    fallback = "SSH" in note and "failed" in note
    t = Text("    ↳ ", style=T.TEXT_FAINTER)
    t.append(note, style=T.ATTENTION if fallback else T.TEXT_MUTED)
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


# ---------------------------------------------------------------------------
# A tool's result, readable (/use): tables for lists of records, "label: value"
# for the rest, a block for long text -- instead of a raw JSON dump.
# ---------------------------------------------------------------------------
_RESULT_ROWS = 25          # rows shown per table before "…and N more"
_RESULT_COLS = 6           # columns per table
_RESULT_CELL = 80          # characters per cell
_RESULT_SKIP = {"status", "kratos_host_note", "snapshot_file", "persisted"}
_LONG_TEXT = 160


_ACRONYMS = {"ip": "IP", "ips": "IPs", "pid": "PID", "uid": "UID", "gid": "GID", "cpu": "CPU",
             "mem": "memory", "id": "ID", "ssh": "SSH", "tz": "time zone", "utc": "UTC", "url": "URL",
             "cve": "CVE", "cves": "CVEs", "os": "OS", "nmap": "nmap", "yara": "YARA"}
_ISO_TIME = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}(?::\d{2})?)(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?\b")


def _words(key: str) -> str:
    return " ".join(_ACRONYMS.get(w.lower(), w) for w in str(key).replace("_", " ").split())


def _label(key: str) -> str:
    words = _words(key)
    return words[:1].upper() + words[1:]


def _scalar(value: Any) -> str:
    """A value as shown. Data is never rewritten (a username like eve_admin
    stays exactly that); only timestamps get a readable layout, seconds kept."""
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = " ".join(str(value).split())

    def _time(m: re.Match[str]) -> str:               # 2026-10-03T21:09:39+00:00 -> 2026-10-03 21:09:39 UTC
        zone = m.group(3) or ""
        return f"{m.group(1)} {m.group(2)}" + (" UTC" if zone in ("Z", "+00:00") else (f" {zone}" if zone else ""))

    return _ISO_TIME.sub(_time, text)


def _short(value: Any, limit: int = _RESULT_CELL) -> str:
    if isinstance(value, (list, tuple)):
        text = ", ".join(_short(v, limit) for v in value) if all(not isinstance(v, (dict, list)) for v in value) \
            else f"{len(value)} items"
    elif isinstance(value, dict):
        text = ", ".join(f"{_words(k)}: {_short(v, limit)}" for k, v in value.items()
                         if not isinstance(v, (dict, list)) and v not in (None, ""))
        text = text or f"{len(value)} fields"
    else:
        text = _scalar(value)
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _records_table(title: str, rows: list[dict[str, Any]]) -> Table:
    columns: list[str] = []
    for row in rows[:50]:
        for key, value in row.items():
            if key not in columns and not isinstance(value, (dict, list)) or (
                    key not in columns and isinstance(value, list) and all(not isinstance(v, (dict, list)) for v in value)):
                columns.append(key)
    columns = columns[:_RESULT_COLS]
    table = Table(title=f"{title} ({len(rows)})", title_justify="left", title_style=f"bold {T.TEXT_BRIGHT}",
                  show_header=True, header_style="bold", box=box.SIMPLE_HEAD, expand=False)
    for col in columns:
        table.add_column(_label(col), overflow="fold")
    for row in rows[:_RESULT_ROWS]:
        table.add_row(*[Text(_short(row.get(col)), style=T.TEXT_MUTED) for col in columns])
    if len(rows) > _RESULT_ROWS:
        table.caption = f"…and {len(rows) - _RESULT_ROWS} more"
        table.caption_justify = "left"
    return table


def tool_result_view(name: str, data: Any) -> Group:
    """A tool's result as a person would want to read it. Any shape works: a
    record list becomes a table, short values become "label: value" lines, long
    text gets its own block, and nested summaries are shown one level deep."""
    parts: list[Any] = []
    if isinstance(data, list):
        data = {"results": data}
    if not isinstance(data, dict):
        return Group(Text(_short(data, 2000), style=T.TEXT))
    if data.get("kratos_host_note"):
        parts.append(Text("Ran on this Kratos machine, not the target.", style=T.ATTENTION))
    pairs = Table.grid(padding=(0, 2))
    pairs.add_column(style=f"bold {T.TEXT_BRIGHT}", no_wrap=True)
    pairs.add_column(style=T.TEXT_MUTED, overflow="fold")
    tables: list[Any] = []
    blocks: list[Any] = []
    for key, value in data.items():
        if key in _RESULT_SKIP:
            continue
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            tables.append(_records_table(_label(key), value))
        elif isinstance(value, list) and not value:
            pairs.add_row(_label(key), "none")
        elif isinstance(value, str) and ("\n" in value.strip() or len(value) > _LONG_TEXT):
            blocks.append(Panel(Text(value.rstrip(), style=T.TEXT), title=_label(key), title_align="left",
                                border_style=T.BORDER))
        elif isinstance(value, dict) and value:
            simple = {k: v for k, v in value.items() if not isinstance(v, (dict, list))}
            nested = {k: v for k, v in value.items() if isinstance(v, (dict, list))}
            if simple:
                pairs.add_row(_label(key), _short(simple, 140))
            for sub, sub_value in nested.items():
                if not sub_value:
                    continue  # an empty sub-list is noise, not information
                if isinstance(sub_value, list) and all(isinstance(v, dict) for v in sub_value):
                    tables.append(_records_table(f"{_label(key)} — {_words(sub)}", sub_value))
                else:
                    pairs.add_row(f"{_label(key)} — {_words(sub)}" if not simple else f"  {_words(sub)}",
                                  _short(sub_value, 140))
        else:
            pairs.add_row(_label(key), _short(value, 140))
    if pairs.row_count:
        parts.append(pairs)
    for item in tables + blocks:
        parts.append(Text(""))
        parts.append(item)
    parts.append(Text(""))
    parts.append(Text("Ctrl+Y copies the full raw result.", style=T.TEXT_DIM))
    return Group(*parts)


def tool_result_panel(name: str, data: Any, time_str: str | None = None) -> Panel:
    return Panel(tool_result_view(name, data), title=f"{name} — result", title_align="left",
                 subtitle=_time_subtitle(time_str), subtitle_align="right", border_style=T.ACCENT)


# Severity ordering + colors for the audit summary's finding tally (high→low).
_AUDIT_SEVERITIES = ("critical", "high", "medium", "low", "info")


def audit_summary_panel(
    *,
    status: str,
    ran: int,
    total: int,
    severity_tally: dict[str, int],
    duration_s: float,
    aborted_on: str | None = None,
    time_str: str | None = None,
    pipeline_name: str | None = None,
) -> Panel:
    """PreA2 run-summary: a first-class close-out panel for a deterministic
    run (agent/pipeline.py) -- the standard audit (/run), or a saved pipeline
    when `pipeline_name` is given, which then names it instead. Distinct from the agentic investigation's
    conclusion panel -- this one has no LLM narrative; it reports, plainly, what
    the fixed pipeline did and what it found. Green when it completed clean, amber
    when it completed with findings or a required step aborted it."""
    completed = status == "completed"
    total_findings = sum(severity_tally.values())
    worst = next((s for s in _AUDIT_SEVERITIES if severity_tally.get(s)), None)

    if not completed:
        color = T.CRITICAL
    elif worst in ("critical", "high"):
        color = T.CRITICAL
    elif total_findings:
        color = T.ATTENTION
    else:
        color = T.SAFE

    what = "Pipeline" if pipeline_name else "Deterministic audit"
    body = Text()
    if completed:
        body.append(f"{what} complete", style=f"bold {T.TEXT_BRIGHT}")
    else:
        body.append(f"{what} stopped", style=f"bold {T.TEXT_BRIGHT}")
        if aborted_on:
            body.append(f" — required step '{aborted_on}' did not succeed", style=T.CRITICAL)
    body.append(f"\n{ran} of {total} steps completed  ·  {duration_s:.0f}s", style=T.TEXT_MUTED)

    if total_findings:
        body.append("\n\nFindings: ", style=T.TEXT_DIM)
        parts = [f"{severity_tally[s]} {s}" for s in _AUDIT_SEVERITIES if severity_tally.get(s)]
        body.append("  ".join(parts), style=T.SEVERITY_COLOR.get(worst or "info", T.TEXT))
        body.append("   (see /report for the full report)", style=T.TEXT_FAINT)
    else:
        body.append("\n\nNo findings raised by the correlation engine.", style=T.TEXT_MUTED)

    body.append(
        "\n\nSame steps, same logic every run (no LLM). The target itself can vary "
        "between runs, so findings can too.",
        style=T.TEXT_FAINT,
    )

    return Panel(
        body,
        title=f"Kratos — pipeline '{pipeline_name}'" if pipeline_name else "Kratos — standard audit",
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
    line.append("↓ context compacted", style=T.TEXT_MUTED)
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


def evolve_suggestion_text(proposal: dict[str, Any]) -> tuple[str, str]:
    """(title, body) for an evo-loop suggestion panel. A suggestion derived from
    the answer's own "Kratos can't do X" sentence has no name yet -- /evolve
    proposes one."""
    footer = "Run /evolve to have Kratos build this (needs a test harness)."
    if proposal.get("derived_from_answer"):
        return ("Missing capability noticed",
                f"The answer says Kratos couldn't do this:\n{proposal.get('description', '')}\n\n{footer}")
    return "Evo-loop suggestion", f"{proposal.get('name', '')}\n{proposal.get('description', '')}\n\n{footer}"


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
    to run in their own session (matching the observe-and-recommend default; a
    kept tool / a whitelisted opt-in path is a separate, gated capability).
    Copyable via ctrl+y."""
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


def plan_preview_panel(preview: Any) -> Panel:
    """A6.1 -- render a PlanPreview (agent/plan_preview.py). Deterministic
    ('exact') and agentic ('predicted') plans are deliberately visually distinct:
    the exact plan is numbered guaranteed steps in a calm border; the predicted
    plan is a bulleted 'likely areas' list in an amber border, so a prediction is
    never mistaken for a guarantee. Used both by the pre-run confirm gate and by
    /plan on demand (same renderer, two surfaces)."""
    kind = preview.kind
    if kind == "exact":
        border = T.ACCENT
        heading = "will run these exact steps, in order"
        bullet_style = T.SAFE
    elif kind == "predicted":
        border = T.ATTENTION
        heading = "will likely look at these areas — it decides the real steps live"
        bullet_style = T.ATTENTION
    else:  # unavailable
        border = T.TEXT_DIM
        heading = "couldn't be previewed"
        bullet_style = T.TEXT_DIM

    body = Text()
    body.append("Kratos ", style=f"bold {T.KRATOS_RED}")
    body.append(heading, style=f"bold {T.TEXT_BRIGHT}")
    body.append(f"\nTarget: {preview.target}", style=T.TEXT_DIM)

    if preview.note:
        body.append(f"\n\n{preview.note}", style=T.TEXT_MUTED)

    for idx, item in enumerate(preview.items, start=1):
        body.append("\n\n")
        marker = f"{idx}. " if kind == "exact" else "• "
        body.append(marker, style=bullet_style)
        body.append(item.label, style=T.TEXT if item.known else T.TEXT_DIM)
        tags = []
        if kind == "exact":
            tags.append("required" if item.required else "optional")
            if item.conditional:
                tags.append("may be skipped")
        if not item.known:
            tags.append("tool not installed")
        if item.approval_gated:
            tags.append("approval: required")
        elif item.may_ask:
            tags.append("may ask (optional extra)")
        if tags:
            body.append("  [" + " · ".join(tags) + "]", style=T.TEXT_FAINT)
        if item.reason:
            body.append(f"\n    {item.reason}", style=T.TEXT_MUTED)

    if preview.approval_gated_any:
        body.append(
            "\n\nOne or more steps are set to approval: required — they'll pause to ask you "
            "live (and are skipped in unattended scheduled runs). Set a tool to 'auto' in "
            "Settings → Tools to run it without asking. Run anyway?",
            style=T.ATTENTION,
        )
    if preview.may_ask_any:
        body.append(
            "\n\nSteps marked 'may ask' only ask before an optional extra (like refreshing the CVE "
            "list, or a live IP lookup). Declining doesn't stop the step, and unattended runs "
            "decline it automatically.",
            style=T.TEXT_FAINT,
        )
    for caveat in preview.caveats:
        body.append(f"\n\n{caveat}", style=T.TEXT_FAINT)

    title = "Plan — exact steps" if kind == "exact" else ("Plan — likely areas (agent adapts)" if kind == "predicted" else "Plan — unavailable")
    return Panel(body, title=title, title_align="left", border_style=border)


def response_plan_panel(plan: Any, time_str: str | None = None) -> Panel:
    """A6.2 -- render a recommend-only ResponsePlan (agent/ir_playbooks.py) for a
    HIGH/CRITICAL finding: ordered steps, each command host-attributed and (if it
    changes state) flagged, plus what to verify and when to escalate. The border
    is the finding's severity colour; a footer states plainly that Kratos runs
    none of it (the observe-and-recommend default)."""
    color = T.SEVERITY_COLOR.get(str(plan.severity).lower(), T.CRITICAL)
    body: list[Any] = []

    head = Text()
    head.append("Response plan", style=f"bold {T.TEXT_BRIGHT}")
    head.append(f"  ·  {plan.finding_id}", style=T.TEXT_DIM)
    if not plan.curated:
        head.append("  ·  generic (no curated playbook)", style=T.ATTENTION)
    head.append("\nFor you to run in your own session — Kratos executes none of these steps.", style=T.TEXT_MUTED)
    if plan.found_at:
        head.append(f"\nFor the finding observed at {plan.found_at} — re-verify it's still current.", style=T.TEXT_FAINT)
    body.append(head)

    for idx, step in enumerate(plan.steps, start=1):
        body.append(Text(""))
        st = Text()
        st.append(f"{idx}. {step.title}", style=f"bold {T.TEXT}")
        body.append(st)
        if step.note:
            body.append(Text(f"   {step.note}", style=T.TEXT_MUTED))
        for cmd in step.commands:
            meta = Text()
            meta.append("   run on ", style=T.TEXT_FAINT)
            meta.append(cmd.where, style=T.TEXT_DIM)
            if cmd.destructive:
                meta.append("   ! changes state — review before running", style=T.CRITICAL)
            body.append(meta)
            # Wrapped so a long command is readable in full; Ctrl+Y copies the exact text.
            body.append(Syntax(cmd.command, "bash", word_wrap=True, background_color="default"))
            if cmd.explanation:
                body.append(Text(f"   {cmd.explanation}", style=T.TEXT_FAINT))

    if plan.verify:
        body.append(Text(""))
        body.append(Text("Verify", style=f"bold {T.SAFE}"))
        for v in plan.verify:
            body.append(Text(f"  • {v}", style=T.TEXT_MUTED))

    if plan.escalate:
        body.append(Text(""))
        body.append(Text("Escalate", style=f"bold {T.CRITICAL}"))
        for e in plan.escalate:
            body.append(Text(f"  • {e}", style=T.TEXT_MUTED))

    for caveat in plan.caveats:
        body.append(Text(f"\n{caveat}", style=T.TEXT_FAINT))

    if any(step.commands for step in plan.steps):
        body.append(Text("\nCtrl+Y copies this plan's commands exactly (don't select wrapped text).",
                         style=T.TEXT_DIM))

    return Panel(
        Group(*body),
        title=f"Recommended response — {str(plan.severity).upper()}",
        title_align="left",
        subtitle=_time_subtitle(time_str),
        subtitle_align="right",
        border_style=color,
    )


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


def command_block_panel(title: str, commands: list[str], note: str | None = None,
                        copy_hint: bool = False) -> Panel:
    """A6.3 -- a block of shell commands (systemd install steps) to run elsewhere.

    In the TUI's scrolling log an unwrapped long line is clipped at the edge, so
    the command could be neither read nor selected whole. With `copy_hint` the
    block wraps for reading and says that Ctrl+Y copies the exact text (the
    caller makes it the copy target); without it, lines are left unwrapped."""
    body: list[Any] = []
    if note:
        body.append(Text(note, style=T.TEXT_MUTED))
        body.append(Text(""))
    body.append(Syntax("\n".join(commands), "bash", word_wrap=copy_hint, background_color="default"))
    if copy_hint:
        body.append(Text(""))
        body.append(Text("Ctrl+Y copies these commands exactly (don't select wrapped text).", style=T.TEXT_DIM))
    return Panel(Group(*body), title=title, title_align="left", border_style=T.ACCENT)


def schedule_table(schedules: list[Any], errors: list[tuple[str, str]],
                   last_status: dict[str, str] | None = None,
                   missing_preset: set[str] | None = None) -> Group:
    """A6.3 -- list saved schedules with their cadence, unit of work, and last
    run status. Corrupt files (from list_schedules' error list) are surfaced,
    never hidden. `missing_preset` names schedules whose referenced preset has
    been deleted -- flagged so it's visible before the next run, not only when it
    fails unattended."""
    last_status = last_status or {}
    missing_preset = missing_preset or set()
    if not schedules and not errors:
        return Group(Text("No schedules yet. Create one with /schedule new.", style=T.TEXT_MUTED))
    table = Table(show_header=True, header_style="bold", expand=False)
    for col in ("name", "runs", "cadence", "target", "deliver", "last run"):
        table.add_column(col)
    for s in schedules:
        if s.kind == "group":
            unit = f"group: {len(s.jobs)} jobs"
        elif s.kind == "preset":
            unit = f"preset:{s.preset}"
        else:
            unit = s.kind
        dangling = s.name in missing_preset
        if dangling:
            unit += "  ⚠ preset deleted"
        elif not s.is_runnable:
            unit += "  (not runnable)"
        healthy = s.is_runnable and not dangling
        table.add_row(
            Text(s.name, style=T.ACCENT),
            Text(unit, style=T.TEXT if healthy else T.ATTENTION),
            s.cadence,
            s.target or "active",
            ", ".join(s.deliver),
            Text(last_status.get(s.name, "—"), style=T.TEXT_MUTED),
        )
    parts: list[Any] = [table]
    for fn, err in errors:
        parts.append(Text(f"! {fn}: {err}", style=T.CRITICAL))
    return Group(*parts)


def schedule_detail_panel(schedule: Any, records: list[dict], install_commands: list[str]) -> Panel:
    """A6.3 -- one schedule's definition + recent run history + install commands."""
    body = Text()
    body.append(f"{schedule.name}", style=f"bold {T.TEXT_BRIGHT}")
    if schedule.kind == "group":
        body.append(f"\nruns: group of {len(schedule.jobs)} jobs (on_failure={schedule.on_failure})", style=T.TEXT)
        for i, job in enumerate(schedule.jobs, start=1):
            body.append(f"\n    {i}. {schedule.job_label(job, i - 1)}", style=T.TEXT_MUTED)
    else:
        unit = "standard audit" if schedule.kind == "audit" else f"preset '{schedule.preset}'"
        body.append(f"\nruns: {unit}", style=T.TEXT)
    body.append(f"\ncadence: {schedule.cadence}  (systemd OnCalendar={schedule.oncalendar})", style=T.TEXT_MUTED)
    body.append(f"\ntarget: {schedule.target or 'active target at run time'}", style=T.TEXT_MUTED)
    body.append(f"\ndeliver: {', '.join(schedule.deliver)}"
                + (f"  ·  notify only on ≥ {schedule.min_severity}" if schedule.min_severity else ""),
                style=T.TEXT_MUTED)
    if records:
        body.append("\n\nRecent runs:", style=T.TEXT_DIM)
        for r in records[-5:]:
            sev = r.get("severity_tally") or {}
            tally = "  ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if sev.get(k)) or "no findings"
            when = r.get("finished_at", "?")
            body.append(f"\n  • {when} — {r.get('status')} — {tally}", style=T.TEXT_MUTED)
    else:
        body.append("\n\nNo runs recorded yet.", style=T.TEXT_FAINT)
    body.append("\n\nInstall (activate the systemd user timer):", style=T.TEXT_DIM)
    return Panel(
        Group(body, Syntax("\n".join(install_commands), "bash", word_wrap=False, background_color="default")),
        title=f"Schedule — {schedule.name}", title_align="left", border_style=T.ACCENT)


def scheduled_run_result_panel(record: dict) -> Panel:
    """A6.3 -- the result of a run-now (or a reported past run)."""
    status = str(record.get("status", "?"))
    ok = status in ("completed", "final_answer", "max_iters_reached")
    color = T.SAFE if ok else T.CRITICAL
    sev = record.get("severity_tally") or {}
    worst = next((s for s in ("critical", "high", "medium", "low", "info") if sev.get(s)), None)
    if worst in ("critical", "high"):
        color = T.CRITICAL
    elif sev:
        color = T.ATTENTION
    body = Text()
    body.append(f"Scheduled run '{record.get('schedule')}'", style=f"bold {T.TEXT_BRIGHT}")
    body.append(f"\nstatus: {status}   target: {record.get('target')}", style=T.TEXT_MUTED)
    # A6.5: per-job breakdown for a group run.
    for j in (record.get("jobs") or []):
        jt = j.get("severity_tally") or {}
        found = sum(jt.values())
        jok = j.get("status") in ("completed", "final_answer", "max_iters_reached")
        line = f"\n  · {j.get('label')}: {j.get('status')}" + (f", {found} finding(s)" if found else "")
        body.append(line, style=T.TEXT_MUTED if jok else T.CRITICAL)
    if record.get("omitted_gated_tools"):
        body.append(f"\nomitted (approval-gated, unattended): {', '.join(record['omitted_gated_tools'])}", style=T.TEXT_FAINT)
    if sev:
        body.append("\nfindings: " + "  ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if sev.get(k)),
                    style=T.SEVERITY_COLOR.get(worst or "info", T.TEXT))
    else:
        body.append("\nfindings: none raised", style=T.TEXT_MUTED)
    if record.get("report_md"):
        body.append(f"\nreport: {record['report_md']}", style=T.TEXT_FAINT)
    delivered = record.get("delivered") if isinstance(record.get("delivered"), dict) else {}
    why = "" if record.get("notified") else {
        "not_configured": " (notifications aren't set up: KRATOS_NTFY_TOPIC)",
        "refused": " (the ntfy topic was refused — see /doctor)",
        "failed": " (delivery failed)",
    }.get(str(delivered.get("status")), "")
    body.append(f"\nnotified: {'yes' if record.get('notified') else 'no'}{why}", style=T.TEXT_FAINT)
    if record.get("error"):
        body.append(f"\nnote: {record['error']}", style=T.ATTENTION)
    return Panel(body, title="Kratos — scheduled run", title_align="left", border_style=color)


def trigger_fire_line(record: dict) -> Text:
    """A6.4 -- a one-line 'trigger X fired' notice in the transcript."""
    worst = str(record.get("worst_severity") or "info").lower()
    color = T.SEVERITY_COLOR.get(worst, T.ATTENTION)
    t = Text()
    t.append("⚡ ", style=color)
    t.append(f"trigger {record.get('trigger')} fired", style=f"bold {color}")
    ids = ", ".join(record.get("matched_ids") or []) or "(finding)"
    t.append(f"  {record.get('action')} · {ids}", style=T.TEXT_MUTED)
    if record.get("error"):
        t.append(f"  — {record['error']}", style=T.CRITICAL)
    elif record.get("notified"):
        t.append("  · notified", style=T.TEXT_FAINT)
    return t


def trigger_table(triggers: list[Any], errors: list[tuple[str, str]],
                  last_fired: dict[str, str] | None = None) -> Group:
    """A6.4 -- list saved triggers with condition, action, target, cooldown, last fire."""
    last_fired = last_fired or {}
    if not triggers and not errors:
        return Group(Text("No triggers yet. Create one with /trigger new.", style=T.TEXT_MUTED))
    table = Table(show_header=True, header_style="bold", expand=False)
    for col in ("name", "when", "action", "target", "cooldown", "last fired"):
        table.add_column(col)
    for tg in triggers:
        table.add_row(
            Text(tg.name, style=T.ACCENT),
            Text(tg.condition_text, style=T.TEXT if tg.is_valid else T.ATTENTION),
            tg.action,
            tg.target or "any",
            f"{tg.cooldown_minutes}m",
            Text(last_fired.get(tg.name, "—"), style=T.TEXT_MUTED),
        )
    parts: list[Any] = [table]
    for fn, err in errors:
        parts.append(Text(f"! {fn}: {err}", style=T.CRITICAL))
    return Group(*parts)


def trigger_detail_panel(trigger: Any, records: list[dict]) -> Panel:
    """A6.4 -- one trigger's definition + recent fire history."""
    body = Text()
    body.append(trigger.name, style=f"bold {T.TEXT_BRIGHT}")
    body.append(f"\nwhen: {trigger.condition_text}", style=T.TEXT)
    action_help = {
        "notify": "send a sharp alert",
        "playbook": "alert + the response plan (what to do)",
        "investigate": "launch a deeper read-only investigation, then alert",
    }.get(trigger.action, trigger.action)
    body.append(f"\naction: {trigger.action} — {action_help}", style=T.TEXT_MUTED)
    body.append(f"\ntarget: {trigger.target or 'any'}   ·   cooldown: {trigger.cooldown_minutes} min", style=T.TEXT_MUTED)
    body.append("\n\nRecommend / notify / read-only — a trigger doesn't act on the target itself.", style=T.TEXT_FAINT)
    if records:
        body.append("\n\nRecent fires:", style=T.TEXT_DIM)
        for r in records[-5:]:
            ids = ", ".join(r.get("matched_ids") or []) or "(finding)"
            body.append(f"\n  • {r.get('fired_at', '?')[:16]} — {r.get('action')} — {ids}", style=T.TEXT_MUTED)
    else:
        body.append("\n\nHasn't fired yet.", style=T.TEXT_FAINT)
    return Panel(body, title=f"Trigger — {trigger.name}", title_align="left", border_style=T.ACCENT)


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


def doctor_table(checks: list[dict[str, str]]) -> Group:
    """Render /doctor's diagnostic as a plain-language verdict headline followed
    by a color-coded status table (✓ pass · ✗ fail · ! warn · · info). The
    headline answers "is my setup OK?" at a glance before the detail rows -- a
    non-technical user reads the verdict, not the table, first."""
    icons = {
        "pass": ("✓", T.SAFE),
        "fail": ("✗", T.CRITICAL),
        "warn": ("!", T.ATTENTION),
        "info": ("·", T.TEXT_DIM),
    }
    # Verdict from the row statuses (info rows are neutral, not counted).
    p = sum(1 for c in checks if c.get("status") == "pass")
    w = sum(1 for c in checks if c.get("status") == "warn")
    f = sum(1 for c in checks if c.get("status") == "fail")
    if f:
        verdict = Text(f"✗  {f} check{'s' if f != 1 else ''} "
                       f"{'need' if f != 1 else 'needs'} attention", style=f"bold {T.CRITICAL}")
    elif w:
        verdict = Text(f"!  {w} warning{'s' if w != 1 else ''} to review", style=f"bold {T.ATTENTION}")
    else:
        verdict = Text("✓  Everything looks healthy", style=f"bold {T.SAFE}")
    tally = Text(f"   {p} ok · {w} warning{'s' if w != 1 else ''} · {f} problem{'s' if f != 1 else ''}",
                 style=T.TEXT_DIM)

    table = Table(show_header=False, box=None, title="Kratos — self-diagnostic",
                  title_justify="left", title_style=f"bold {T.ACCENT}")
    table.add_column(width=1, no_wrap=True)
    table.add_column(style=T.TEXT_BRIGHT, no_wrap=True)
    # fold, not the default ellipsis: a detail can be a value to copy (a URL, a
    # suggested KRATOS_NTFY_TOPIC=...) and must never be cut off.
    table.add_column(style=T.TEXT_MUTED, overflow="fold")
    for c in checks:
        icon, color = icons.get(c.get("status", "info"), ("·", T.TEXT_DIM))
        table.add_row(Text(icon, style=color), Text(str(c.get("check", "")), style=color),
                      Text(str(c.get("detail", "")), style=T.TEXT_DIM))
        fix = str(c.get("fix", "") or "")
        if fix:  # next step, indented under the row it belongs to
            # Accent only where something needs doing; a hint on an informational
            # row must not read like an error.
            actionable = c.get("status") in ("fail", "warn")
            table.add_row(Text(""), Text(""), Text(f"→ {fix}", style=T.ACCENT if actionable else T.TEXT_MUTED))
    return Group(verdict, tally, Text(""), table)


def preset_table(presets: list[Any], errors: list[tuple[str, str]] | None = None,
                 last_run: dict[str, str] | None = None,
                 unavailable: set[str] | None = None) -> Group:
    """Render saved presets (A2) as a table: name, kind, target, a one-line
    goal/pipeline preview, and (when known) the last-run time. A goal AND a valid
    pipeline preset are both runnable (shown in accent); a non-runnable one (an
    invalid pipeline, or unknown kind) is dimmed so it reads as 'kept but not
    runnable here', never hidden. Unreadable files are surfaced as a trailing note
    rather than silently dropped."""
    last_run = last_run or {}
    unavailable = unavailable or set()
    table = Table(show_header=True, box=None, title="Saved presets",
                  title_justify="left", title_style=f"bold {T.ACCENT}",
                  header_style=f"bold {T.TEXT_DIM}")
    table.add_column("name", style=T.ACCENT, no_wrap=True)
    table.add_column("kind", no_wrap=True)
    table.add_column("target", style=T.TEXT_MUTED, no_wrap=True)
    table.add_column("goal", style=T.TEXT_MUTED)
    table.add_column("last run", style=T.TEXT_FAINT, no_wrap=True)
    for p in presets:
        # "runnable" now spans goal AND pipeline presets (A2 Tier 2); fall back to
        # the tier1 flag for any object that predates is_runnable.
        runnable = getattr(p, "is_runnable", getattr(p, "is_runnable_tier1", True))
        kind = getattr(p, "kind", "goal")
        goal_preview = (getattr(p, "goal", None) or "").splitlines()[0] if getattr(p, "goal", None) else ""
        if len(goal_preview) > 60:
            goal_preview = goal_preview[:57] + "…"
        if not goal_preview and kind == "pipeline":
            n = len(getattr(p, "steps", []) or [])
            goal_preview = (f"{n}-step pipeline" if runnable
                            else "pipeline — not runnable (see /preset show)")
        elif not runnable and not goal_preview:
            goal_preview = "(not runnable in this build)"
        name_style = T.ACCENT if runnable else T.TEXT_FAINT
        kind_style = T.SAFE if runnable else T.TEXT_FAINT
        pname = getattr(p, "name", "?")
        if pname in unavailable:  # runnable shape, but names a tool this build lacks
            goal_preview = (goal_preview + "  " if goal_preview else "") + "⚠ missing tool"
            kind_style = T.ATTENTION
        table.add_row(
            Text(pname, style=name_style),
            Text(kind, style=kind_style),
            Text(getattr(p, "target", None) or "—"),
            Text(goal_preview),
            Text(last_run.get(pname, "—")),
        )
    parts: list[Any] = [table]
    if not presets:
        parts = [Text("No saved presets yet. Create one with /preset new \"<name>\" \"<goal>\".",
                      style=T.TEXT_MUTED)]
    for fname, err in (errors or []):
        parts.append(Text(f"! {fname} couldn't be read: {err}", style=T.ATTENTION))
    return Group(*parts)


def error_detail(result: Any) -> str:
    """Best-effort human error message from a FAILED tool result. The loop wraps
    its own errors under 'observation', but a tool's OWN error dict may use
    'message' / 'error' / 'detail' / 'stderr' (e.g. a self-written/kept tool).
    Reading only 'observation' rendered a real error as "no error detail" — this
    checks the common keys, then falls back to a compact repr of the informative
    fields, so that phrase only shows when there genuinely is nothing."""
    if not isinstance(result, dict):
        return str(result).strip() if result else ""
    for key in ("observation", "message", "error", "detail", "stderr"):
        v = result.get(key)
        if v and str(v).strip():
            return str(v).strip()
    fields = {k: v for k, v in result.items() if k not in ("status", "result") and v not in (None, "", [])}
    return ", ".join(f"{k}={v}" for k, v in fields.items()) if fields else ""


def kv_table(title: str, rows: list[tuple]) -> Table:
    """A simple two-column key/value table (used by /usage and /context). Each
    row is (key, value) or (key, value, value_style)."""
    table = Table(show_header=False, box=None, title=title, title_justify="left",
                  title_style=f"bold {T.ACCENT}")
    table.add_column(style=T.TEXT_MUTED, no_wrap=True)
    table.add_column()
    for r in rows:
        key, value = r[0], r[1]
        style = r[2] if len(r) > 2 else T.TEXT
        table.add_row(Text(str(key)), Text(str(value), style=style))
    return table

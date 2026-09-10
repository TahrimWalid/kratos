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
    "plan_preview_panel",
    "response_plan_panel",
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
) -> Panel:
    """PreA2 run-summary: a first-class close-out panel for a deterministic
    standard audit (agent/pipeline.py). Distinct from the agentic investigation's
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

    body = Text()
    if completed:
        body.append("Deterministic audit complete", style=f"bold {T.TEXT_BRIGHT}")
    else:
        body.append("Deterministic audit aborted", style=f"bold {T.TEXT_BRIGHT}")
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
        title="Kratos — standard audit",
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
    for caveat in preview.caveats:
        body.append(f"\n\n{caveat}", style=T.TEXT_FAINT)

    title = "Plan — exact steps" if kind == "exact" else ("Plan — likely areas (agent adapts)" if kind == "predicted" else "Plan — unavailable")
    return Panel(body, title=title, title_align="left", border_style=border)


def response_plan_panel(plan: Any, time_str: str | None = None) -> Panel:
    """A6.2 -- render a recommend-only ResponsePlan (agent/ir_playbooks.py) for a
    HIGH/CRITICAL finding: ordered steps, each command host-attributed and (if it
    changes state) flagged, plus what to verify and when to escalate. The border
    is the finding's severity colour; a footer states plainly that Kratos runs
    none of it (the permanent observe-and-recommend boundary)."""
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
            body.append(Syntax(cmd.command, "bash", word_wrap=False, background_color="default"))
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


def command_block_panel(title: str, commands: list[str], note: str | None = None) -> Panel:
    """A6.3 -- a copy-pasteable block of shell commands (systemd install steps).
    word_wrap=False so a long line is never soft-wrapped into a broken copy
    (the exact bug fixed for the target-onboarding checklist)."""
    body: list[Any] = []
    if note:
        body.append(Text(note, style=T.TEXT_MUTED))
        body.append(Text(""))
    body.append(Syntax("\n".join(commands), "bash", word_wrap=False, background_color="default"))
    return Panel(Group(*body), title=title, title_align="left", border_style=T.ACCENT)


def schedule_table(schedules: list[Any], errors: list[tuple[str, str]],
                   last_status: dict[str, str] | None = None) -> Group:
    """A6.3 -- list saved schedules with their cadence, unit of work, and last
    run status. Corrupt files (from list_schedules' error list) are surfaced,
    never hidden."""
    last_status = last_status or {}
    if not schedules and not errors:
        return Group(Text("No schedules yet. Create one with /schedule new.", style=T.TEXT_MUTED))
    table = Table(show_header=True, header_style="bold", expand=False)
    for col in ("name", "runs", "cadence", "target", "deliver", "last run"):
        table.add_column(col)
    for s in schedules:
        unit = s.kind if s.kind == "audit" else f"preset:{s.preset}"
        runnable = "" if s.is_runnable else "  (not runnable)"
        table.add_row(
            Text(s.name, style=T.ACCENT),
            Text(unit + runnable, style=T.TEXT if s.is_runnable else T.ATTENTION),
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
    if record.get("omitted_gated_tools"):
        body.append(f"\nomitted (approval-gated, unattended): {', '.join(record['omitted_gated_tools'])}", style=T.TEXT_FAINT)
    if sev:
        body.append("\nfindings: " + "  ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low", "info") if sev.get(k)),
                    style=T.SEVERITY_COLOR.get(worst or "info", T.TEXT))
    else:
        body.append("\nfindings: none raised", style=T.TEXT_MUTED)
    if record.get("report_md"):
        body.append(f"\nreport: {record['report_md']}", style=T.TEXT_FAINT)
    body.append(f"\nnotified: {'yes' if record.get('notified') else 'no'}", style=T.TEXT_FAINT)
    if record.get("error"):
        body.append(f"\nnote: {record['error']}", style=T.ATTENTION)
    return Panel(body, title="Kratos — scheduled run", title_align="left", border_style=color)


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


def preset_table(presets: list[Any], errors: list[tuple[str, str]] | None = None) -> Group:
    """Render saved presets (A2 Tier 1) as a table: name, kind, target, and a
    one-line goal preview. A non-runnable preset (a Tier-2 pipeline, or unknown
    kind) is shown dimmed with its kind so it reads as 'kept but not runnable
    here', never hidden. Unreadable files are surfaced as a trailing note rather
    than silently dropped."""
    table = Table(show_header=True, box=None, title="Saved presets",
                  title_justify="left", title_style=f"bold {T.ACCENT}",
                  header_style=f"bold {T.TEXT_DIM}")
    table.add_column("name", style=T.ACCENT, no_wrap=True)
    table.add_column("kind", no_wrap=True)
    table.add_column("target", style=T.TEXT_MUTED, no_wrap=True)
    table.add_column("goal", style=T.TEXT_MUTED)
    for p in presets:
        runnable = getattr(p, "is_runnable_tier1", True)
        kind = getattr(p, "kind", "goal")
        goal_preview = (getattr(p, "goal", None) or "").splitlines()[0] if getattr(p, "goal", None) else ""
        if len(goal_preview) > 60:
            goal_preview = goal_preview[:57] + "…"
        if not runnable and not goal_preview:
            goal_preview = "(pipeline steps — not runnable in this build)"
        name_style = T.ACCENT if runnable else T.TEXT_FAINT
        kind_style = T.SAFE if kind == "goal" else T.TEXT_FAINT
        table.add_row(
            Text(getattr(p, "name", "?"), style=name_style),
            Text(kind, style=kind_style),
            Text(getattr(p, "target", None) or "—"),
            Text(goal_preview),
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

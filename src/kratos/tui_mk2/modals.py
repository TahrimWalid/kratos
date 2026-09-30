"""
Shared modal screens for kratos-mk2.

Keyboard-first, matching the canvas mockups (every mockup documents single-key
affordances -- `y`/`esc`, `l`/`f`/`b`, etc.). Each modal is typed on its
dismiss value so callers can `await self.app.push_screen_wait(Modal(...))` and
get a real result, or pass a callback for the thread-worker case (approvals).

NAVIGATION / CONFIRMATION STANDARD (agreed 2026-09-08 — keep every new modal
consistent with it):
  * Escape = close the CURRENT layer / back one level (the universal
    convention). Repeated Escape backs out of nesting. Escape is non-printable,
    so it works even when a text Input is focused.
  * ctrl+b = the jump-all-the-way-back-to-the-conversation hatch (SessionScreen).
    A ctrl-combo so it never collides with a focused input.
  * `b` = an OPTIONAL secondary "back" ONLY on no-input list/menu screens where
    it's a meaningful one-level back (ResumeTierModal -> session list, Launch ->
    recent, Phase-2 gallery). Never on input modals (a bare letter is typed into
    the field), never mandatory.
  * Yes/no confirmations: `y` = yes; `n`/`esc`/ANY OTHER KEY = No (fail-safe --
    a stray keypress never confirms). The ONE exception is the scrollable
    ApprovalModal, which keeps explicit y/n/esc so scroll keys still work to read
    a long approval before deciding. Both share the same key legend.
  * Every simple yes/no goes through ConfirmModal (never an ad-hoc dialog), so
    the confirm UI is identical by construction.
"""
from __future__ import annotations

from typing import Any

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView, SelectionList, Static

from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.render import approval_panel, plan_preview_panel


def _decision_hint(affirm: str, refuse: str) -> Text:
    """Shared y / n / esc key legend so every yes/no soft-warning modal reads
    the SAME way: y affirms; n or esc backs out (esc is always 'cancel'). No
    'Enter' and no '(default)' word-salad — three clearly labelled keys."""
    hint = Text()
    hint.append("\n  y ", style=f"bold {T.SAFE}")
    hint.append(f"{affirm}       ", style=T.TEXT)
    hint.append("n ", style=f"bold {T.TEXT_MUTED}")
    hint.append(f"{refuse}       ", style=T.TEXT_DIM)
    hint.append("esc ", style=f"bold {T.TEXT_MUTED}")
    hint.append("cancel", style=T.TEXT_DIM)
    return hint


class CodeModal(ModalScreen[None]):
    """Read-only source viewer (used by /settings → Tools to review a kept
    tool's actual code before trusting it). Scrollable; esc closes."""

    BINDINGS = [Binding("escape,q", "close", "close", show=True)]

    def __init__(self, title: str, code: str) -> None:
        super().__init__()
        self._title = title
        self._code = code

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(Syntax(self._code, "python", word_wrap=True, background_color="default"))
            yield Static(Text("esc close", style=T.TEXT_DIM))

    def action_close(self) -> None:
        self.dismiss(None)


class ApprovalModal(ModalScreen[bool]):
    """The one approval gate rendering for the TUI (agent/tools.py::
    request_approval routes here via approvals.py). Fail-safe: escape / n /
    dismissing without an explicit `y` all deny."""

    BINDINGS = [
        Binding("y", "approve", "approve", show=True),
        Binding("n", "deny", "deny", show=True),
        Binding("escape", "deny", "deny", show=False),
    ]

    def __init__(self, tool_name: str, details: dict[str, Any]) -> None:
        super().__init__()
        self._tool_name = tool_name
        self._details = details

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(approval_panel(self._tool_name, self._details))
            yield Static(_decision_hint("approve", "deny"))

    def action_approve(self) -> None:
        self.dismiss(True)

    def action_deny(self) -> None:
        self.dismiss(False)


class PlanPreviewModal(ModalScreen[bool]):
    """A6.1 -- the pre-run confirm gate. Shows the plan (agent/plan_preview.py)
    and asks run/cancel. Scrollable (a plan can be long), so it keeps EXPLICIT
    y/n/esc bindings like ApprovalModal rather than a catch-all-cancels key, so
    scroll keys still work while reading. Fail-safe: n / esc / dismissing without
    an explicit `y` all CANCEL (nothing runs) -- the safe default for a
    consequential multi-minute run (INVARIANT 2, no force-accept)."""

    BINDINGS = [
        Binding("y", "run", "run", show=True),
        Binding("n", "cancel", "cancel", show=True),
        Binding("escape", "cancel", "cancel", show=False),
    ]

    def __init__(self, preview: Any) -> None:
        super().__init__()
        self._preview = preview

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(plan_preview_panel(self._preview))
            yield Static(_decision_hint("run it", "cancel"))

    def action_run(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class ResumeTierModal(ModalScreen[str | None]):
    """Turn 6b -- resume-depth sub-prompt. Returns 'l', 'f', or None (back)."""

    BINDINGS = [
        Binding("l", "light", "light", show=True),
        Binding("f", "full", "full", show=True),
        Binding("b,escape", "back", "back", show=True),
    ]

    def __init__(self, session_id: str, warn_small_context: bool) -> None:
        super().__init__()
        self._session_id = session_id
        self._warn = warn_small_context

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(f"Resume  {self._session_id}", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(Text("How much of this session should Kratos reload?", style=T.TEXT_MUTED))
            yield Static(Text(""))

            # --- Light -------------------------------------------------------
            light = Text()
            light.append(" l ", style=f"bold {T.BG} on {T.SAFE}")   # filled key chip
            light.append("  Light", style=f"bold {T.TEXT_BRIGHT}")
            light.append("   · recommended", style=T.SAFE)
            yield Static(light)
            yield Static(Text("      Fast, light on context — your goals, outcomes, and a compact summary.",
                              style=T.TEXT_MUTED))
            yield Static(Text("      Won't recall every fine detail of earlier turns word-for-word.",
                              style=T.TEXT_DIM))
            yield Static(Text(""))

            # --- Full --------------------------------------------------------
            full = Text()
            full.append(" f ", style=f"bold {T.BG} on {T.ACCENT}")
            full.append("  Full", style=f"bold {T.TEXT_BRIGHT}")
            yield Static(full)
            yield Static(Text("      Re-reads the whole transcript — precise recall of earlier details.",
                              style=T.TEXT_MUTED))
            yield Static(Text("      Uses much more context; on a small-context (local) model it can overflow "
                              "and force an immediate compaction.",
                              style=T.TEXT_DIM))
            if self._warn:
                yield Static(Text("      ! small-context local model — Full will likely overflow here; pick Light.",
                                  style=T.ATTENTION))
            yield Static(Text(""))

            # --- key legend --------------------------------------------------
            legend = Text()
            legend.append("  l ", style=f"bold {T.SAFE}")
            legend.append("light       ", style=T.TEXT)
            legend.append("f ", style=f"bold {T.ACCENT}")
            legend.append("full       ", style=T.TEXT)
            legend.append("b / esc ", style=f"bold {T.TEXT_MUTED}")
            legend.append("back", style=T.TEXT_DIM)
            yield Static(legend)

    def action_light(self) -> None:
        self.dismiss("l")

    def action_full(self) -> None:
        self.dismiss("f")

    def action_back(self) -> None:
        self.dismiss(None)


class ConfirmModal(ModalScreen[bool]):
    """Generic native confirm (used by /reset, /delete, model/target switch,
    draft-harness, back-to-sessions). No force-accept: only `y` confirms; `n`,
    `escape`, and ANY OTHER KEY cancel (fail-safe — a stray keypress never
    confirms). No text input and no scroll here, so a catch-all key = No is safe
    (unlike the scrollable ApprovalModal, which keeps explicit keys so scroll
    still works). Distinct from ApprovalModal only in that it takes plain
    title/body text rather than a tool details dict."""

    BINDINGS = [
        Binding("y", "confirm", "confirm", show=True),
        Binding("n,escape", "cancel", "cancel", show=True),
    ]

    def on_key(self, event: events.Key) -> None:
        # Fail-safe: any key other than 'y' cancels. 'y' is left to its binding.
        if event.key != "y":
            event.stop()
            self.action_cancel()

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self._title = title
        self._body = body

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ATTENTION}"), classes="modal-title")
            yield Static(Text(self._body, style=T.TEXT))
            yield Static(_decision_hint("confirm", "no"))

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class PromptModal(ModalScreen[str | None]):
    """Generic single-line text prompt (used by /rename, /target, new-session
    target/name, first-run target). Returns the entered text, or None on
    escape. Empty submit returns '' (callers decide what empty means)."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]

    def __init__(self, title: str, hint: str = "", initial: str = "",
                 quick_value: str = "", quick_label: str = "") -> None:
        super().__init__()
        self._title = title
        self._hint = hint
        self._initial = initial
        # Optional one-click shortcut rendered as a small button under the input
        # (e.g. "[Kratos-Host]" on the target prompt). Selecting it dismisses
        # with quick_value; leaving them empty keeps the plain text-only prompt.
        self._quick_value = quick_value
        self._quick_label = quick_label

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            if self._hint:
                yield Static(Text(self._hint, style=T.TEXT_DIM))
            yield Input(value=self._initial, id="prompt-input")
            if self._quick_label:
                yield Button(self._quick_label, id="prompt-quick", variant="primary")
                yield Static(Text("Enter to use what you typed · Tab then Enter (or click) for the option · esc cancel", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

    @on(Button.Pressed, "#prompt-quick")
    def _quick(self, event: Button.Pressed) -> None:
        self.dismiss(self._quick_value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ExecutionConsentModal(ModalScreen[bool]):
    """Control 6's dedicated per-target direct-execution opt-in screen
    (docs/subagent_architecture.md control 6) -- plain-risk language, never
    reassuring/minimizing, never folded into pairing. `y` enables; anything
    else (including a stray key) declines and stays recommend-only, matching
    this file's fail-safe yes/no standard."""

    BINDINGS = [
        Binding("y", "enable", "enable", show=True),
        Binding("n,escape", "decline", "decline", show=True),
    ]

    def on_key(self, event: events.Key) -> None:
        if event.key != "y":
            event.stop()
            self.action_decline()

    def __init__(self, target_label: str) -> None:
        super().__init__()
        self._target_label = target_label

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(f"⚠ enable direct execution for {self._target_label}?", style=f"bold {T.ATTENTION}"),
                         classes="modal-title")
            yield Static(Text(
                "Kratos can be manipulated by data it reads from this target -- a crafted log entry, "
                "for example -- into proposing a harmful action. With this enabled, an approved action "
                "runs directly through the sub-agent instead of only being shown to you to run yourself.",
                style=T.TEXT))
            yield Static(Text(
                "The typed-EXECUTE approval gate stays required either way -- this only decides what "
                "EXECUTE does once confirmed. Reversible any time from here.", style=T.TEXT_FAINT))
            yield Static(_decision_hint("enable direct execution", "decline -- stay recommend-only"))

    def action_enable(self) -> None:
        self.dismiss(True)

    def action_decline(self) -> None:
        self.dismiss(False)


class TypedExecuteModal(ModalScreen[bool]):
    """Control 7's critical-approval gate: the human must TYPE the word
    EXECUTE (not just a keypress) to confirm. Every field shown (`effect`/
    `reversibility`/`blast_radius`/tier) is read from the trusted ActionSpec
    the caller passes in -- never LLM-generated text -- so an injected core
    cannot pair a harmful action with a reassuring false summary.

    Same visual gate for BOTH an opted-in target (typing EXECUTE actually
    dispatches) and a recommend-only one (`can_execute=False` -- there is no
    EXECUTE to type; the rendered command is shown to copy and run
    yourself instead), matching the architecture doc's "same friction, same
    disclosure, in both cases" requirement."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]

    def __init__(self, action_id: str, effect: str, reversibility: str, blast_radius: str,
                 tier: str, argv_preview: str, can_execute: bool) -> None:
        super().__init__()
        self._action_id = action_id
        self._effect = effect
        self._reversibility = reversibility
        self._blast_radius = blast_radius
        self._tier = tier
        self._argv_preview = argv_preview
        self._can_execute = can_execute

    def compose(self) -> ComposeResult:
        tier_color = {"low": T.SAFE, "medium": T.ATTENTION, "high": T.CRITICAL}.get(self._tier, T.TEXT)
        with Vertical(classes="modal-card"):
            yield Static(Text(f"Kratos proposes: {self._action_id}", style=f"bold {T.TEXT_BRIGHT}"),
                         classes="modal-title")
            table = Table(show_header=False, box=None, padding=(0, 1, 0, 0))
            table.add_column(style=T.TEXT_DIM, justify="right", no_wrap=True)
            table.add_column(style=T.TEXT)
            table.add_row("effect", self._effect)
            table.add_row("reversibility", self._reversibility)
            table.add_row("blast radius", self._blast_radius)
            table.add_row("sensitivity", Text(self._tier, style=f"bold {tier_color}"))
            table.add_row("command", Text(self._argv_preview, style=T.ACCENT))
            yield Static(table)
            yield Static(Text(
                "↑ effect / reversibility / blast radius / sensitivity are read from the trusted "
                "action definition -- never generated by the model.", style=T.TEXT_FAINT))
            if self._tier == "high":
                yield Static(Text(
                    "⚠ HIGH sensitivity -- a second confirmation will follow.", style=f"bold {T.CRITICAL}"))
            if self._can_execute:
                yield Static(Text("Type EXECUTE to dispatch to the sub-agent:", style=T.CRITICAL))
                yield Input(placeholder="EXECUTE", id="execute-input")
                yield Static(Text("anything else, or esc, cancels", style=T.TEXT_DIM))
            else:
                yield Static(Text(
                    "This target hasn't opted into direct execution (or isn't reachable right now) -- "
                    "copy the command above and run it yourself.", style=T.ATTENTION))
                yield Static(Text("esc close", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        if self._can_execute:
            self.query_one("#execute-input", Input).focus()

    @on(Input.Submitted, "#execute-input")
    def _submit(self, event: Input.Submitted) -> None:
        if event.value == "EXECUTE":
            self.dismiss(True)
        else:
            self.dismiss(False)  # fail-safe: anything other than the exact word cancels, no retry loop

    def action_cancel(self) -> None:
        self.dismiss(False)


class HelpModal(ModalScreen[None]):
    """Turn 8a -- grouped, aligned /help reference. esc closes."""

    BINDINGS = [Binding("escape,q", "close", "close", show=True)]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(Text("Kratos — commands", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(self._table("Session / navigation", [
                ("/help", "List available commands"),
                ("/guide", "Getting started — the first steps, in plain language"),
                ("/run", "Standard audit — deterministic security sweep of the target (no LLM)"),
                ("/plan [preset|goal]", "Preview a run's steps before it runs (/plan gate on|off toggles auto-preview)"),
                ("/preset-new", "Save a reusable investigation — a plain-language goal, or a tool pipeline"),
                ("/preset-describe", "Describe a pipeline in words → Kratos drafts it for your review"),
                ("/preset-run / -list", "Run (goal or pipeline) or list your saved presets — or just /<name>"),
                ("/preset-show", "Show a preset's full definition (steps, target, any missing tools)"),
                ("/preset-edit / -delete", "Edit (goal or pipeline steps) or delete a preset (pick from a list)"),
                ("/preset-scaffold", "Write an editable pipeline-preset template file (power users)"),
                ("/preset-export / -import", "Share a preset's file, or import one from a .toml"),
                ("/report", "Investigation summary — findings by severity"),
                ("/schedule", "Run an audit/preset on a cadence + deliver the report (systemd timers)"),
                ("/trigger", "If a finding is detected → notify / show its playbook / investigate deeper"),
                ("/doctor", "Self-diagnostic — LLM endpoint, .env, target setup, kept tools"),
                ("/usage", "Token usage + estimated cost this session (local models = free)"),
                ("/context", "What's currently loaded in the context window"),
                ("/investigate-host", "Investigate the Kratos machine itself (not the monitored target)"),
                ("/compact", "Summarize the conversation to free context — Kratos keeps the key points"),
                ("/clear", "Clear the screen + working context (session history kept)"),
                ("/reset", "Wipe the screen + archive history, start this session fresh"),
                ("/delete", "Archive (soft-delete) this session, back to picker"),
                ("/sessions, /back", "Back to the session picker (Ctrl+B) — keeps this session"),
                ("/rename <name>", "Name this session — usable anywhere its ID works"),
                ("/exit, /quit", "Leave the session"),
            ]))
            yield Static(self._table("Evo-loop (write → test → approve → keep a tool)", [
                ("/evolve", "Build the most recent auto-suggested tool"),
                ('/evolve "<idea>"', "Start evo-loop with your own idea"),
                ("/tools", "List tools by kind (Default / Kept / Installed)"),
                ("/use <name> [json]", "Run ONE tool directly — deterministic, no model tool-selection"),
            ]))
            yield Static(self._table("Configuration", [
                ("/target [<ip> …]", "Set/change active target(s) (no arg → prompt) + setup checklist"),
                ("/target verify", "Re-check the active target's setup"),
                ("/model", "Manage LLM backends — switch / add / edit / delete (Models settings)"),
                ("/timezone [<zone>|auto]", "Show / set the display timezone (storage stays UTC)"),
                ("/settings", "Settings — models, tools, name, timezone, this session (also 's' at the picker)"),
                ("Ctrl+T", "Theme picker — from anywhere"),
                ("/whitelist", "A paired target's action whitelist — opt-in + typed-EXECUTE dispatch"),
                ("/preview", "Phase 2 design shells (not wired) — sub-agent / Tailscale / execution"),
            ]))
            yield Static(Text("esc close", style=T.TEXT_DIM))

    def _table(self, heading: str, rows: list[tuple[str, str]]) -> Table:
        table = Table(show_header=False, box=None, title=heading, title_justify="left", title_style=f"bold {T.TEXT_BRIGHT}")
        table.add_column(style=T.ACCENT, no_wrap=True)
        table.add_column(style=T.TEXT_MUTED)
        for cmd, desc in rows:
            table.add_row(cmd, desc)
        return table

    def action_close(self) -> None:
        self.dismiss(None)


class GuideModal(ModalScreen[None]):
    """A short, plain-language 'getting started' orientation, reachable from the
    home/session screen (/guide) AND from the launcher/session picker (? or g) so
    a brand-new user can learn how Kratos works before doing anything. The full
    detail lives in docs/GUIDE.md; this is the on-screen quick version."""

    BINDINGS = [Binding("escape,q", "close", "close", show=True)]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(Text("Kratos — getting started", style=f"bold {T.ACCENT}"),
                         classes="modal-title")
            yield Static(Text(
                "Kratos looks over a machine and tells you, in plain English, what's going on "
                "with it — failed logins, exposed ports, changed files. It explains what it "
                "found and what it would do about it. By default it doesn't change the target "
                "itself; acting on its advice is your call.", style=T.TEXT))
            yield Static(Text("\nFirst steps", style=f"bold {T.TEXT_BRIGHT}"))
            yield Static(self._steps([
                ("1.  /target <host>", "point Kratos at a machine to watch. It checks the SSH "
                 "connection and shows what the target still needs."),
                ("2.  ask in plain words", "e.g. “check this host for signs of an SSH "
                 "brute-force”. Kratos picks its own read-only tools and explains what it finds."),
                ("3.  /doctor", "confirm your setup (model, target, tools) is healthy."),
                ("4.  /report", "see this session's findings, most severe first."),
            ]))
            yield Static(Text("\nGood to know", style=f"bold {T.TEXT_BRIGHT}"))
            yield Static(self._steps([
                ("observe-only", "by default Kratos reads and advises; it doesn't change the "
                 "target itself. Acting on a target is a planned opt-in, not built yet."),
                ("/evolve", "builds a new tool when Kratos is missing one — you review the code first."),
                ("/preset", "saves an investigation to re-run or schedule."),
                ("y / n", "at a permission prompt, y means yes; anything else means no."),
            ]))
            yield Static(Text(
                "\nFull guide:  docs/GUIDE.md        All commands:  ?  or  /help",
                style=T.TEXT_DIM))
            yield Static(Text("esc close", style=T.TEXT_DIM))

    def _steps(self, rows: list[tuple[str, str]]) -> Table:
        return _step_table(rows)

    def action_close(self) -> None:
        self.dismiss(None)


def _step_table(rows: list[tuple[str, str]]) -> Table:
    """Two-column 'label  explanation' table used by the explainer modals."""
    table = Table(show_header=False, box=None, padding=(0, 1, 0, 0))
    table.add_column(style=T.ACCENT, no_wrap=True, justify="left")
    table.add_column(style=T.TEXT_MUTED)
    for left, right in rows:
        table.add_row(left, right)
    return table


class InfoModal(ModalScreen[None]):
    """Read-only detail in the guide's scrollable card: a title and any Rich
    renderable. For "the full story" behind a compact on-screen summary."""

    BINDINGS = [Binding("escape,q,enter,d", "close", "close", show=True)]

    def __init__(self, title: str, body: Any) -> None:
        super().__init__()
        self._title = title
        self._body = body

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(self._body)
            yield Static(Text("\nesc close", style=T.TEXT_DIM))

    def action_close(self) -> None:
        self.dismiss(None)


class EvolveIntroModal(ModalScreen[bool]):
    """What /evolve does, for someone who has never used it: shown once before a
    user's first /evolve, and any time via `/evolve help`. Explanation only --
    it changes nothing about what gets reviewed or when a human must say yes.

    first_time=True: Enter starts the build (True), esc means "not now" (False).
    first_time=False (help): esc/Enter just close."""

    BINDINGS = [
        Binding("enter", "go", "start", show=False),
        Binding("escape,q", "not_now", "close", show=True),
    ]

    def __init__(self, first_time: bool = True) -> None:
        super().__init__()
        self._first_time = first_time

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(Text("Building a new tool with /evolve", style=f"bold {T.ACCENT}"),
                         classes="modal-title")
            yield Static(Text(
                "When Kratos is missing a tool — say, “list the users who can use sudo” — /evolve "
                "builds one. You describe the idea; Kratos writes the code, tests it safely and "
                "shows it to you. Nothing is kept unless you say yes.", style=T.TEXT))
            yield Static(Text("\nHow it works", style=f"bold {T.TEXT_BRIGHT}"))
            yield Static(_step_table([
                ("1.  describe it", "one clear job, in plain words."),
                ("2.  agree on the test", "Kratos drafts a short automatic test and shows you, in "
                 "plain English, what it checks. That test is what “correct” means for the new tool; "
                 "if a check is wrong, you correct it in plain English."),
                ("3.  build and test", "Kratos writes the tool and runs your test in a locked-down "
                 "sandbox (no network, none of your files), trying up to 3 times."),
                ("4.  review and keep", "if it passes, you see the full code and anything worth a "
                 "second look. y keeps it; anything else throws it away."),
            ]))
            yield Static(Text("\nWhy a test is required", style=f"bold {T.TEXT_BRIGHT}"))
            yield Static(Text(
                "A kept tool runs on this machine, outside the sandbox, every time Kratos uses it. "
                "The test is the one thing that pins down what it must do — without it, “the model "
                "says it works” would be the only check. That's why you always see it before "
                "anything is built.", style=T.TEXT_MUTED))
            yield Static(Text("\nAsk before running?", style=f"bold {T.TEXT_BRIGHT}"))
            yield Static(Text(
                "After you keep a tool, Kratos asks whether it may run on its own. Recommended: no, "
                "until you've seen it work — then it asks you every time it runs. Anything but y "
                "keeps it asking. You can change this later in Settings → Tools.", style=T.TEXT_MUTED))
            yield Static(Text("\nIf it doesn't work out", style=f"bold {T.TEXT_BRIGHT}"))
            yield Static(_step_table([
                ("didn't pass", "nothing passed your test in 3 tries. Usually a check is too "
                 "strict — relax it and run again."),
                ("stalled", "the model kept giving back the same code. Describe the idea "
                 "differently."),
                ("you said no", "nothing is saved. Run /evolve again any time."),
            ]))
            hint = ("\nenter start building · esc not now · /evolve help shows this again"
                    if self._first_time else "\nesc close")
            yield Static(Text(hint, style=T.TEXT_DIM))

    def action_go(self) -> None:
        self.dismiss(self._first_time)

    def action_not_now(self) -> None:
        self.dismiss(False)


class ListPickerModal(ModalScreen[Any]):
    """Generic keyboard list picker (used by /model). Each entry is
    (value, label). ↑↓ to move, Enter to pick, esc to cancel (dismiss None)."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]

    # Constrain each row to the card width and wrap, so a long label wraps to
    # the next line instead of overflowing off the right edge of the modal.
    CSS = """
    ListPickerModal ListView { width: 1fr; height: auto; max-height: 20; }
    ListPickerModal ListView > ListItem { width: 1fr; height: auto; }
    ListPickerModal ListView > ListItem > Label { width: 1fr; height: auto; }
    """

    def __init__(self, title: str, entries: list[tuple[Any, str]], subtitle: str = "") -> None:
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._entries = entries

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            if self._subtitle:
                yield Static(Text(self._subtitle, style=T.TEXT_DIM))
            yield ListView(*[ListItem(Label(label)) for _, label in self._entries], id="picker")
            yield Static(Text("↑↓ select · Enter pick · esc cancel", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        self.query_one("#picker", ListView).focus()

    @on(ListView.Selected)
    def _selected(self, event: ListView.Selected) -> None:
        idx = event.list_view.index or 0
        self.dismiss(self._entries[idx][0])

    def action_cancel(self) -> None:
        self.dismiss(None)


class ClarifyModal(ModalScreen[str | None]):
    """A clarifying question with labeled choices (optionally one 'recommended',
    each with a short explanation) plus a free-text 'something else' box —
    an ask-with-choices prompt for genuinely ambiguous requests, rather than
    guessing (same 'ask, don't assume' grain as the approval gate, but
    multiple-choice and non-authorizing).

    Returns the chosen option's `value` (falling back to its `label`), the typed
    free-text, or None if dismissed. Each option is a dict:
    {label, explanation?, recommended?, value?}. Callers that need to branch
    programmatically set a machine `value`; the mid-investigation provider omits
    it, so the model receives the human-meaningful label text as the answer."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]

    def __init__(self, question: str, options: list[dict[str, Any]], subtitle: str = "",
                 title: str = "Kratos needs a steer") -> None:
        super().__init__()
        self._question = question
        self._options = options or []
        self._subtitle = subtitle
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(Text(self._question, style=T.TEXT))
            if self._subtitle:
                yield Static(Text(self._subtitle, style=T.TEXT_DIM))
            items: list[ListItem] = []
            for o in self._options:
                row = Text()
                row.append(str(o.get("label", "")), style=f"bold {T.TEXT_BRIGHT}")
                if o.get("recommended"):
                    row.append("  (recommended)", style=T.SAFE)
                if o.get("explanation"):
                    row.append(f"\n    {o['explanation']}", style=T.TEXT_MUTED)
                items.append(ListItem(Label(row)))
            if items:
                yield ListView(*items, id="clarify-list")
            yield Static(Text("or type your own answer:", style=T.TEXT_DIM))
            yield Input(placeholder="something else…", id="clarify-input")
            yield Static(Text("↑↓ + Enter choose · type + Enter for your own · esc skip", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        if self._options:
            lst = self.query_one("#clarify-list", ListView)
            lst.index = self._recommended_index()
            lst.focus()  # recommended choice is one keypress away
        else:
            self.query_one("#clarify-input", Input).focus()

    def _recommended_index(self) -> int:
        for idx, o in enumerate(self._options):
            if o.get("recommended"):
                return idx
        return 0

    def _value_for(self, idx: int) -> str:
        o = self._options[idx]
        val = o.get("value")
        return str(val) if val is not None else str(o.get("label", ""))

    @on(ListView.Selected, "#clarify-list")
    def _picked(self, event: ListView.Selected) -> None:
        idx = event.list_view.index or 0
        if 0 <= idx < len(self._options):
            self.dismiss(self._value_for(idx))

    @on(Input.Submitted, "#clarify-input")
    def _typed(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        self.dismiss(val or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ToolPickerModal(ModalScreen[str | None]):
    """Searchable tool picker for bare /use: type to filter by name or
    description, ↑↓ to move, Enter to pick, esc to cancel. Returns the chosen
    tool name (or None). `entries` is a list of (name, description)."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        Binding("down", "cursor_down", "down", show=False),
        Binding("up", "cursor_up", "up", show=False),
    ]

    def __init__(self, entries: list[tuple[str, str]]) -> None:
        super().__init__()
        self._entries = entries

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text("Run a tool", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Input(placeholder="type to filter tools…", id="tp-input")
            yield ListView(id="tp-list")
            yield Static(Text("↑↓ select · Enter run · esc cancel", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        self.query_one("#tp-input", Input).focus()
        self._refresh("")

    def _matches(self, query: str) -> list[tuple[str, str]]:
        q = query.strip().lower()
        return [(n, d) for n, d in self._entries if q in n.lower() or q in d.lower()]

    def _refresh(self, query: str) -> None:
        lst = self.query_one("#tp-list", ListView)
        lst.clear()
        for name, desc in self._matches(query):
            row = Text()
            row.append(f"{name:<26}", style=T.ACCENT)
            row.append(desc, style=T.TEXT_MUTED)
            lst.append(ListItem(Label(row)))
        if len(lst):
            lst.index = 0

    @on(Input.Changed, "#tp-input")
    def _changed(self, event: Input.Changed) -> None:
        self._refresh(event.value)

    @on(Input.Submitted, "#tp-input")
    def _submit(self, event: Input.Submitted) -> None:
        matches = self._matches(event.value)
        if matches:
            idx = max(0, self.query_one("#tp-list", ListView).index or 0)
            self.dismiss(matches[idx][0])

    @on(ListView.Selected, "#tp-list")
    def _picked(self, event: ListView.Selected) -> None:
        matches = self._matches(self.query_one("#tp-input", Input).value)
        idx = event.list_view.index or 0
        if 0 <= idx < len(matches):
            self.dismiss(matches[idx][0])

    def action_cursor_down(self) -> None:
        self.query_one("#tp-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#tp-list", ListView).action_cursor_up()

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommandPaletteModal(ModalScreen[str | None]):
    """Turn 7a -- typing '/' opens a filter-as-you-type command palette.
    Returns the chosen command string (e.g. '/report') or None. Purely a
    selector; the caller runs the command."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        Binding("down", "cursor_down", "down", show=False),
        Binding("up", "cursor_up", "up", show=False),
    ]

    def __init__(self, commands: list[tuple[str, str]], initial: str = "/") -> None:
        super().__init__()
        self._commands = commands
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text("Commands", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Input(value=self._initial, id="palette-input")
            yield ListView(id="palette-list")
            yield Static(Text("↑↓ select · Enter run · esc dismiss", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        self.query_one("#palette-input", Input).focus()
        self._refresh("")

    def _matches(self, query: str) -> list[tuple[str, str]]:
        q = query.lstrip("/").lower()
        return [(c, d) for c, d in self._commands if q in c.lstrip("/").lower()]

    def _refresh(self, query: str) -> None:
        lst = self.query_one("#palette-list", ListView)
        lst.clear()
        for cmd, desc in self._matches(query):
            row = Text()
            row.append(f"{cmd:<20}", style=T.ACCENT)
            row.append(desc, style=T.TEXT_MUTED)
            lst.append(ListItem(Label(row)))
        if len(lst):
            lst.index = 0

    @on(Input.Changed, "#palette-input")
    def _changed(self, event: Input.Changed) -> None:
        self._refresh(event.value)

    @on(Input.Submitted, "#palette-input")
    def _submit(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        # If the user typed args (a space), pass the WHOLE command through so
        # inline usage (`/rename foo`, `/target 1.2.3.4`) still works from the
        # palette -- the caller dispatches it exactly like a typed command.
        if " " in val:
            self.dismiss(val)
            return
        matches = self._matches(val)
        if matches:
            # Prefer an EXACT command match over the highlighted substring match,
            # so typing "/tool" and hitting Enter runs /tool, not /tools (which
            # is listed first and also contains "tool"). Only fall back to the
            # highlighted row when there's no exact hit.
            norm = val.lstrip("/").lower()
            exact = next((c for c, _ in matches if c.lstrip("/").lower() == norm), None)
            if exact:
                self.dismiss(exact)
                return
            idx = max(0, self.query_one("#palette-list", ListView).index or 0)
            self.dismiss(matches[idx][0])
            return
        # No match: hand a bare /-command through (dispatch treats an unknown
        # one as goal text, same as typing it directly); otherwise cancel.
        self.dismiss(val if val.startswith("/") else None)

    @on(ListView.Selected, "#palette-list")
    def _picked(self, event: ListView.Selected) -> None:
        matches = self._matches(self.query_one("#palette-input", Input).value)
        idx = event.list_view.index or 0
        if 0 <= idx < len(matches):
            self.dismiss(matches[idx][0])

    def action_cursor_down(self) -> None:
        self.query_one("#palette-list", ListView).action_cursor_down()

    def action_cursor_up(self) -> None:
        self.query_one("#palette-list", ListView).action_cursor_up()

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommandModal(ModalScreen[None]):
    """A read-only shell command shown in a bordered box with a one-click Copy
    button, so the user can paste it EXACTLY into another terminal -- no manual
    retyping, no OCR mistakes, no line-wrap corruption (the command that broke a
    real paste). `c` or the Copy button copies via the terminal's clipboard
    (OSC-52); esc/enter closes. `command` may be multi-line."""

    BINDINGS = [
        Binding("c", "copy", "copy", show=True),
        Binding("escape,enter,q", "close", "close", show=True),
    ]

    CSS = """
    CommandModal #cmd-box { height: auto; }
    CommandModal Horizontal { height: auto; align: left middle; }
    CommandModal Button { margin: 1 1 0 0; }
    """

    def __init__(self, command: str, title: str = "Run this", note: str = "") -> None:
        super().__init__()
        self._command = command
        self._title = title
        self._note = note

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            if self._note:
                yield Static(Text(self._note, style=T.TEXT_DIM))
            # Wrap so the whole command is visible even when it's wider than the
            # box; the copy is always the exact byte-correct string regardless.
            yield Static(
                Panel(Text(self._command, style=T.TEXT_BRIGHT), border_style=T.ACCENT, padding=(0, 1)),
                id="cmd-box",
            )
            with Horizontal():
                yield Button("Copy", id="cmd-copy", variant="primary")
                yield Button("Close", id="cmd-close")
            yield Static(Text("Click Copy (don't select the text) · c copy · esc close", style=T.TEXT_DIM))

    def on_mount(self) -> None:
        self.query_one("#cmd-copy", Button).focus()

    @on(Button.Pressed, "#cmd-copy")
    def _copy_btn(self, event: Button.Pressed) -> None:
        self.action_copy()

    @on(Button.Pressed, "#cmd-close")
    def _close_btn(self, event: Button.Pressed) -> None:
        self.action_close()

    def action_copy(self) -> None:
        self.app.copy_to_clipboard(self._command)
        self.app.notify("Copied to clipboard.", timeout=3)

    def action_close(self) -> None:
        self.dismiss(None)


class MultiSelectModal(ModalScreen[list[Any] | None]):
    """Tick one or more items (space toggles, Enter confirms). Returns the
    ticked values in their original order, or None on esc. At least one must
    stay ticked -- an empty choice would mean "allow nothing", which is what
    disabling is for."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        # priority: the SelectionList would otherwise consume Enter as a toggle,
        # leaving no way to finish with the keyboard.
        Binding("enter", "done", "done", show=True, priority=True),
    ]

    CSS = """
    MultiSelectModal SelectionList { height: auto; max-height: 20; }
    """

    def __init__(self, title: str, entries: list[tuple[Any, str]], selected: list[Any] | None = None,
                 subtitle: str = "") -> None:
        super().__init__()
        self._title = title
        self._subtitle = subtitle
        self._entries = entries
        self._selected = set(selected if selected is not None else [v for v, _ in entries])

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            if self._subtitle:
                yield Static(Text(self._subtitle, style=T.TEXT_DIM))
            yield SelectionList(*[(label, i, value in self._selected)
                                  for i, (value, label) in enumerate(self._entries)], id="multi")
            yield Static(Text("↑↓ move · space tick/untick · Enter done · esc cancel", style=T.TEXT_DIM),
                         id="multi-hint")

    def on_mount(self) -> None:
        self.query_one("#multi", SelectionList).focus()

    def action_done(self) -> None:
        picked = sorted(self.query_one("#multi", SelectionList).selected)
        if not picked:
            self.query_one("#multi-hint", Static).update(
                Text("Tick at least one (esc to cancel).", style=f"bold {T.ATTENTION}"))
            return
        self.dismiss([self._entries[i][0] for i in picked])

    def action_cancel(self) -> None:
        self.dismiss(None)

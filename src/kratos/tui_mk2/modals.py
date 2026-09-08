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

from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView, Static

from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.render import approval_panel


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


class HelpModal(ModalScreen[None]):
    """Turn 8a -- grouped, aligned /help reference. esc closes."""

    BINDINGS = [Binding("escape,q", "close", "close", show=True)]

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="modal-card"):
            yield Static(Text("Kratos — commands", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(self._table("Session / navigation", [
                ("/help", "List available commands"),
                ("/run", "Standard audit — deterministic security sweep of the target (no LLM)"),
                ("/report", "Investigation summary — findings by severity"),
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


class ListPickerModal(ModalScreen[Any]):
    """Generic keyboard list picker (used by /model). Each entry is
    (value, label). ↑↓ to move, Enter to pick, esc to cancel (dismiss None)."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]

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
    Kratos's version of Claude Code's ask-with-choices. Used whenever a request
    is genuinely ambiguous, rather than guessing (same 'ask, don't assume' grain
    as the approval gate, but multiple-choice and non-authorizing).

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

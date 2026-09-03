"""
Shared modal screens for kratos-mk2.

Keyboard-first, matching the canvas mockups (every mockup documents single-key
affordances -- `y`/`esc`, `l`/`f`/`b`, etc.). Each modal is typed on its
dismiss value so callers can `await self.app.push_screen_wait(Modal(...))` and
get a real result, or pass a callback for the thread-worker case (approvals).
"""
from __future__ import annotations

from typing import Any

from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView, Static

from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.render import approval_panel


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
            hint = Text()
            hint.append("  y", style=f"bold {T.SAFE}")
            hint.append(" approve    ", style=T.TEXT_DIM)
            hint.append("Enter / n / esc", style=f"bold {T.TEXT_DIM}")
            hint.append(" deny (default)", style=T.TEXT_DIM)
            yield Static(hint)

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
            yield Static(Text(f"Resume {self._session_id}", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(Text("[l] Light — targets + goal history + compact summary (default)", style=T.TEXT))
            yield Static(Text("[f] Full  — complete transcript replay into context", style=T.TEXT))
            yield Static(Text("[b] Back to session list", style=T.TEXT_DIM))
            if self._warn:
                yield Static(
                    Text(
                        "! Full replay is not recommended on the current local small-context "
                        "backend — Light is safe here.",
                        style=T.ATTENTION,
                    )
                )

    def action_light(self) -> None:
        self.dismiss("l")

    def action_full(self) -> None:
        self.dismiss("f")

    def action_back(self) -> None:
        self.dismiss(None)


class ConfirmModal(ModalScreen[bool]):
    """Generic native confirm (used by /reset, /delete). No force-accept:
    escape / n / anything but `y` denies. Distinct from ApprovalModal only in
    that it takes plain title/body text rather than a tool details dict."""

    BINDINGS = [
        Binding("y", "confirm", "confirm", show=True),
        Binding("n,escape", "cancel", "cancel", show=True),
    ]

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self._title = title
        self._body = body

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ATTENTION}"), classes="modal-title")
            yield Static(Text(self._body, style=T.TEXT))
            hint = Text()
            hint.append("\n  y", style=f"bold {T.SAFE}")
            hint.append(" confirm    ", style=T.TEXT_DIM)
            hint.append("Enter / n / esc", style=f"bold {T.TEXT_DIM}")
            hint.append(" cancel (default)", style=T.TEXT_DIM)
            yield Static(hint)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class PromptModal(ModalScreen[str | None]):
    """Generic single-line text prompt (used by /rename, /target, new-session
    target/name, first-run target). Returns the entered text, or None on
    escape. Empty submit returns '' (callers decide what empty means)."""

    BINDINGS = [Binding("escape", "cancel", "cancel", show=True)]

    def __init__(self, title: str, hint: str = "", initial: str = "") -> None:
        super().__init__()
        self._title = title
        self._hint = hint
        self._initial = initial

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text(self._title, style=f"bold {T.ACCENT}"), classes="modal-title")
            if self._hint:
                yield Static(Text(self._hint, style=T.TEXT_DIM))
            yield Input(value=self._initial, id="prompt-input")

    def on_mount(self) -> None:
        self.query_one("#prompt-input", Input).focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip())

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
                ("/report", "Investigation summary — findings by severity"),
                ("/clear", "Reset conversation continuity (visible history stays)"),
                ("/reset", "Archive this session's history and start fresh"),
                ("/delete", "Archive (soft-delete) this session, back to picker"),
                ("/rename <name>", "Name this session — usable anywhere its ID works"),
                ("/exit, /quit", "Leave the session"),
            ]))
            yield Static(self._table("Evo-loop (write → test → approve → keep a tool)", [
                ("/evolve", "Build the most recent auto-suggested tool"),
                ('/evolve "<idea>"', "Start evo-loop with your own idea"),
                ("/evolve list", "Browse tools reachable by the agent"),
            ]))
            yield Static(self._table("Configuration", [
                ("/target <ip> …", "Set active target(s) — shows setup checklist"),
                ("/target verify", "Re-check the active target's setup"),
                ("/model", "Show / switch the active LLM backend"),
                ("/settings", "Per-tool approval policy (not yet implemented)"),
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
        matches = self._matches(event.value)
        if matches:
            self.dismiss(matches[max(0, self.query_one("#palette-list", ListView).index or 0)][0])
        else:
            self.dismiss(None)

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

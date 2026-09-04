"""
Phase 2 design-preview gallery -- UI SHELLS ONLY.

These screens are pictures of the target UI for the sub-agent / Tailscale /
direct-execution architecture (docs/subagent_architecture.md v2). NONE of it is
wired: as of this file there is no Tailscale integration, no sub-agent, no
telemetry, and no execution channel anywhere in the codebase. Each shell is a
static render with a persistent "NOT WIRED" banner and a to-wire note tied to
the backend layer it depends on.

Deliberately reachable ONLY via `/preview` (a dedicated gallery), never woven
into the normal launch/session flow -- so a finished-looking screen can never be
mistaken for a wired capability. Execution screens (Layer 5) additionally carry
a "gated on Layer 4 (whitelist)" label: per the architecture doc, direct
execution cannot ship until the narrow action whitelist is designed and
independently reviewed, and the whitelist -- not command signing -- is the
security boundary.

Build order mirrors the safe-first sequence: Layer 1 (Tailscale) -> Layer 2
(sub-agent pairing) -> Layer 3 (telemetry/status) are the zero-execution half;
Layer 5 (execution) shells are a separate, clearly-gated batch.
"""
from __future__ import annotations

from typing import Any, Callable

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Static

from kratos.tui_mk2 import theme as T


# ---------------------------------------------------------------------------
# Small helpers to render faithful "mock window" content in the mk2 palette.
# ---------------------------------------------------------------------------
def _win(title: str, *body: Any, border: str = T.BORDER) -> Panel:
    """A mock terminal panel (title bar + body), used to show a mockup state."""
    return Panel(Group(*body), title=title, title_align="left", border_style=border)


def _kv(rows: list[tuple[str, str]]) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=T.TEXT_FAINTER, no_wrap=True)
    grid.add_column(style=T.TEXT)
    for k, v in rows:
        grid.add_row(k, v)
    return grid


def _key(label: str) -> Text:
    t = Text()
    t.append(f" {label} ", style=f"{T.TEXT_BRIGHT} on {T.BORDER}")
    return t


def _state(label: str) -> Text:
    return Text(f"— {label} —", style=T.TEXT_FAINTER)


# ---------------------------------------------------------------------------
# Safe half (Layers 1-3): onboarding, pairing, status, multi-target.
# ---------------------------------------------------------------------------
def _tailscale_onboarding() -> Any:
    connect = _win(
        "kratos — connect",
        Text("No Tailscale account connected.", style=T.TEXT),
        Text(""),
        Text("Kratos pairs with targets over your own Tailscale network. Connect an account to begin.", style=T.TEXT_MUTED),
        Text(""),
        Group(_key("c"), Text("  connect a Tailscale account", style=T.TEXT_DIM)),
        border=T.ACCENT,
    )
    waiting = _win(
        "kratos — connecting",
        Text("Waiting for you to authorize Kratos in your browser…", style=T.ATTENTION),
        Text(""),
        Text("A device-code page opened. Approve it there, then come back — this returns automatically.", style=T.TEXT_MUTED),
        Text("code: ABCD-EFGH   ·   esc cancel", style=T.TEXT_FAINT),
        border=T.ATTENTION,
    )
    connected = _win(
        "kratos — connected",
        Text("✓ Tailscale connected as boss@tailnet", style=T.SAFE),
        Text(""),
        Text("Falls straight into the target dashboard. The account indicator persists; OAuth is never repeated.", style=T.TEXT_MUTED),
        border=T.SAFE,
    )
    return Group(
        _state("13a  first launch — no account"), connect, Text(""),
        _state("13b  OAuth waiting (shared with 13g pairing)"), waiting, Text(""),
        _state("13c  connected → dashboard"), connected, Text(""),
        Text("Also in this flow (not shown): 13d denied/errored (one retry), 13e abandoned/timeout, 13f already-set-up, 13j disconnect/switch account.", style=T.TEXT_FAINT),
    )


def _pairing_wizard() -> Any:
    generate = _win(
        "kratos — pair a target",
        Text("Add a server", style=f"bold {T.TEXT_BRIGHT}"),
        Text("Run this on the target to pair it (expires in 15 min):", style=T.TEXT_MUTED),
        Text(""),
        Panel(Text("curl -fsSL https://…/pair.sh | sh -s -- CODE-7F2A", style=T.TEXT_BRIGHT),
              border_style=T.BORDER, padding=(0, 1)),
        Text("waiting for the target to check in…", style=T.ATTENTION),
        border=T.ACCENT,
    )
    connected = _win(
        "kratos — pair a target",
        Text("✓ web-01 paired", style=f"bold {T.SAFE}"),
        Text("100.94.12.3 · web-01.tailnet · sub-agent v0.3.0 · telemetry live", style=T.TEXT_MUTED),
        Text(""),
        Text("web-01 is recommend-only by default — Kratos will show fixes for you to run, not run "
             "them itself. You can turn on direct execution any time from settings.", style=T.TEXT_DIM),
        border=T.SAFE,
    )
    timeout = _win(
        "kratos — pair a target",
        Text("⧗ pairing code expired unused", style=T.ATTENTION),
        Text("The command/code was never run. Generate a fresh one to try again.", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    handshake = _win(
        "kratos — pair a target",
        Text("✗ handshake failed", style=T.CRITICAL),
        Text("The command ran but the connection broke partway — something went wrong (distinct from "
             "'nobody tried'). Retry pairing.", style=T.TEXT_MUTED),
        border=T.CRITICAL,
    )
    return Group(
        _state("12a / 13g  generate command + code → waiting"), generate, Text(""),
        _state("12a  connected"), connected, Text(""),
        _state("13h  timeout — code expired"), timeout, Text(""),
        _state("13i  handshake failure"), handshake,
    )


def _subagent_status() -> Any:
    def chip(dot: str, color: str, label: str, detail: str) -> Text:
        t = Text()
        t.append(f"{dot} ", style=color)
        t.append(label, style=color)
        t.append(f"   {detail}", style=T.TEXT_FAINT)
        return t

    chips = _win(
        "kratos — sub-agent status chip (footer, next to target IP)",
        chip("●", T.SAFE, "connected", "telemetry flowing · sub-agent v0.3.0"),
        chip("●", T.CRITICAL, "unreachable", "no route on the tailnet — target may be down or off-net"),
        chip("◐", T.ATTENTION, "zombie", "network up, but the agent process isn't responding"),
        border=T.BORDER,
    )
    zombie = _win(
        "kratos — web-01",
        Text("◐ sub-agent not responding", style=f"bold {T.ATTENTION}"),
        Text("web-01 is reachable on the tailnet, but its sub-agent process isn't answering a "
             "heartbeat — a third state, distinct from connected and from unreachable.", style=T.TEXT_MUTED),
        Text("Telemetry is stale; restart the sub-agent on the target to recover.", style=T.TEXT_DIM),
        border=T.ATTENTION,
    )
    return Group(
        _state("11a / 12b  persistent status chip — three states"), chips, Text(""),
        _state("18a  zombie sub-agent (network up, process silent)"), zombie, Text(""),
        Text("Also here (not shown): 11b total target loss during an investigation, 13k a "
             "previously-paired target regressing to unreachable (shows last-good state).", style=T.TEXT_FAINT),
    )


def _multi_target_dashboard() -> Any:
    table = Table(show_header=True, header_style="bold", box=None, expand=True)
    table.add_column("target", style=T.ACCENT)
    table.add_column("address", style=T.TEXT_FAINTER)
    table.add_column("status")
    table.add_column("mode")
    table.add_column("last telemetry", style=T.TEXT_FAINTER)
    table.add_row("web-01", "100.94.12.3", Text("● connected", style=T.SAFE), Text("recommend-only", style=T.SAFE), "12s ago")
    table.add_row("db-01", "100.94.12.8", Text("● connected", style=T.SAFE), Text("recommend-only", style=T.SAFE), "4s ago")
    table.add_row("edge-2", "100.94.12.20", Text("◐ zombie", style=T.ATTENTION), Text("recommend-only", style=T.SAFE), "6m ago")
    table.add_row("cache-1", "100.94.12.31", Text("● unreachable", style=T.CRITICAL), Text("recommend-only", style=T.SAFE), "—")
    dash = _win("kratos — targets", table, border=T.ACCENT)
    return Group(
        _state("12e  multi-target dashboard"), dash, Text(""),
        Text("MVP ships one target; the list is designed in from the start. Every target defaults to "
             "recommend-only. Multi-target EXECUTION (17e broadcast matrix) is Layer 6 and is its own "
             "review gate combined with execution — not previewed in this safe batch.", style=T.TEXT_FAINT),
    )


# Each entry: (id, title, layer, gated, builder, to_wire)
PHASE2_SAFE: list[dict[str, Any]] = [
    {
        "id": "onboarding",
        "title": "Tailscale onboarding (13a–13f, 13j)",
        "layer": "Layer 1 · Tailscale",
        "gated": False,
        "builder": _tailscale_onboarding,
        "to_wire": "OAuth device-flow client, account-state persistence, ephemeral scoped Tailscale auth keys, ACL tagging (Layer 1).",
    },
    {
        "id": "pairing",
        "title": "Sub-agent pairing wizard (12a, 13g–13i)",
        "layer": "Layer 2 · Sub-agent",
        "gated": False,
        "builder": _pairing_wizard,
        "to_wire": "The sub-agent program itself + a pairing handshake over the ephemeral auth key (Layers 1–2).",
    },
    {
        "id": "status",
        "title": "Sub-agent status + zombie (11a/12b/18, 11b/13k)",
        "layer": "Layer 3 · Telemetry",
        "gated": False,
        "builder": _subagent_status,
        "to_wire": "A liveness/heartbeat distinct from TCP reachability, plus the always-on read-only telemetry stream (Layer 3).",
    },
    {
        "id": "multitarget",
        "title": "Multi-target dashboard (12e)",
        "layer": "Layer 3/6 · Telemetry",
        "gated": False,
        "builder": _multi_target_dashboard,
        "to_wire": "Per-target telemetry (Layer 3) for the read-only dashboard; multi-target EXECUTION (17e) is Layer 6 + its own review gate.",
    },
]


class ShellScreen(Screen):
    """A single Phase 2 design shell: a persistent NOT-WIRED banner, the mockup
    body, and a to-wire note. Nothing here is interactive or wired."""

    BINDINGS = [Binding("escape,q,b", "back", "back", show=True)]

    CSS = f"""
    ShellScreen #banner {{
        height: 1;
        background: {T.CRITICAL};
        color: white;
        text-style: bold;
        padding: 0 1;
    }}
    ShellScreen #gate {{
        height: auto;
        background: {T.INSET_BG};
        color: {T.ATTENTION};
        padding: 0 1;
    }}
    ShellScreen #shellbody {{ padding: 1 2; height: 1fr; }}
    ShellScreen #towire {{
        height: auto;
        background: {T.TITLEBAR_BG};
        color: {T.TEXT_DIM};
        padding: 0 1;
    }}
    """

    def __init__(self, entry: dict[str, Any]) -> None:
        super().__init__()
        self._entry = entry

    def compose(self) -> ComposeResult:
        yield Static("⚠  NOT WIRED — Phase 2 design preview · no backend exists", id="banner")
        if self._entry.get("gated"):
            yield Static(
                Text(
                    "GATED ON Layer 4 — direct execution cannot ship until the narrow action "
                    "whitelist is designed and independently reviewed (the whitelist, not signing, "
                    "is the security boundary).",
                ),
                id="gate",
            )
        with VerticalScroll(id="shellbody"):
            yield Static(Text(self._entry["title"], style=f"bold {T.ACCENT}"))
            yield Static(Text(""))
            yield Static(self._entry["builder"]())
        yield Static(Text(f"To wire ({self._entry['layer']}): {self._entry['to_wire']}   ·   esc back"), id="towire")

    def action_back(self) -> None:
        self.dismiss(None)


class Phase2PreviewScreen(Screen):
    """The gallery index of Phase 2 shells. Reachable only via /preview."""

    BINDINGS = [
        Binding("escape,q", "close", "back to session", show=True),
        Binding("enter", "open_selected", "open", show=True),
    ]

    CSS = f"""
    Phase2PreviewScreen {{ padding: 1 2; }}
    Phase2PreviewScreen #pv-banner {{ height: 1; background: {T.CRITICAL}; color: white; text-style: bold; padding: 0 1; }}
    Phase2PreviewScreen #pv-intro {{ height: auto; color: {T.TEXT_DIM}; padding: 1 0; }}
    Phase2PreviewScreen DataTable {{ height: 1fr; }}
    Phase2PreviewScreen #pv-hints {{ height: auto; color: {T.TEXT_DIM}; }}
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static("⚠  PHASE 2 DESIGN PREVIEW — none of these are wired; no sub-agent/Tailscale/execution code exists", id="pv-banner")
            yield Static(
                Text(
                    "Pictures of the target UI (docs/subagent_architecture.md v2). Safe half shown "
                    "first (Tailscale/pairing/telemetry — zero execution). Execution shells arrive as "
                    "a separate batch, gated on Layer 4's whitelist.",
                ),
                id="pv-intro",
            )
            yield DataTable(id="pv-table", cursor_type="row", zebra_stripes=False)
            yield Static(Text("Enter open · esc back to session", style=T.TEXT_DIM), id="pv-hints")

    def on_mount(self) -> None:
        table = self.query_one("#pv-table", DataTable)
        table.add_columns("screen", "layer", "status")
        for e in PHASE2_SAFE:
            table.add_row(e["title"], e["layer"], Text("shell · not wired", style=T.TEXT_FAINTER))
        table.focus()

    def action_open_selected(self) -> None:
        table = self.query_one("#pv-table", DataTable)
        row = table.cursor_row
        if row is not None and 0 <= row < len(PHASE2_SAFE):
            self.app.push_screen(ShellScreen(PHASE2_SAFE[row]))

    @on(DataTable.RowSelected, "#pv-table")
    def _row(self, event: DataTable.RowSelected) -> None:
        row = event.cursor_row
        if row is not None and 0 <= row < len(PHASE2_SAFE):
            self.app.push_screen(ShellScreen(PHASE2_SAFE[row]))

    def action_close(self) -> None:
        self.dismiss(None)

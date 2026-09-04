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

from typing import Any

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
    denied = _win(
        "kratos — connecting",
        Text("✗ authorization denied or errored", style=T.CRITICAL),
        Text("Recoverable — one clear retry action, no dead end.", style=T.TEXT_MUTED),
        Text("r  try again   ·   esc cancel", style=T.TEXT_DIM),
        border=T.CRITICAL,
    )
    abandoned = _win(
        "kratos — connecting",
        Text("⧗ authorization abandoned", style=T.ATTENTION),
        Text("Browser tab closed / no response — detected by timeout, returns to a clean retry rather "
             "than hanging forever.", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    already = _win(
        "kratos — targets",
        Text("Tailscale: connected as boss@tailnet", style=T.SAFE),
        Text("Setup already done → straight to the dashboard. Persistent indicator; OAuth never "
             "repeated.", style=T.TEXT_MUTED),
        border=T.SAFE,
    )
    disconnect = _win(
        "kratos — settings",
        Text("Disconnect Tailscale account?", style=f"bold {T.ATTENTION}"),
        Text("Framed as a trust property, not an apology — a single deliberate keypress, NOT typed "
             "confirmation (that friction stays reserved for real execution, 12c/1e).", style=T.TEXT_MUTED),
        Text("d  disconnect   ·   esc keep connected", style=T.TEXT_DIM),
        border=T.ATTENTION,
    )
    unpair = _win(
        "kratos — web-01",
        Text("Unpair web-01?", style=f"bold {T.ATTENTION}"),
        Text("Sibling to disconnect: same warning language and double-confirm tier, scoped to one "
             "server instead of the whole account.", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    return Group(
        _state("13a  first launch — no account"), connect, Text(""),
        _state("13b  OAuth waiting (shared with 13g pairing)"), waiting, Text(""),
        _state("13c  OAuth success → dashboard"), connected, Text(""),
        _state("13d  OAuth denied / errored — one retry, no dead end"), denied, Text(""),
        _state("13e  OAuth abandoned — timeout → clean retry"), abandoned, Text(""),
        _state("13f  setup already done — straight to dashboard, persistent indicator"), already, Text(""),
        _state("13j  disconnect / switch account — single deliberate keypress"), disconnect, Text(""),
        _state("13m  unpair a single target — double-confirm tier, scoped to one server"), unpair,
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
    total_loss = _win(
        "kratos — web-01",
        Text("✗ can't reach web-01 at all", style=f"bold {T.CRITICAL}"),
        Text("Kratos itself lost the target mid-investigation — distinct from a single tool's timeout. "
             "The investigation pauses rather than reporting a false all-clear.", style=T.TEXT_MUTED),
        border=T.CRITICAL,
    )
    regressed = _win(
        "kratos — targets",
        Text("web-01 · unreachable — last seen 6m ago", style=T.CRITICAL),
        Text("A previously-paired target that regressed to unreachable — distinct from 'never paired'; "
             "recency + last-good state are shown wherever targets are listed.", style=T.TEXT_MUTED),
        border=T.CRITICAL,
    )
    core_off = _win(
        "kratos — targets",
        Text("⚠ Kratos's core dropped off the tailnet", style=f"bold {T.ATTENTION}"),
        Text("Every paired target goes dark at once — shown ONCE at the dashboard level, not repeated "
             "per row. It's Kratos's own connectivity, not each target's.", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    return Group(
        _state("11a / 12b  persistent status chip — three states"), chips, Text(""),
        _state("18a  zombie sub-agent (network up, process silent)"), zombie, Text(""),
        _state("11b  total target loss during an investigation"), total_loss, Text(""),
        _state("13k  a previously-paired target regressing to unreachable"), regressed, Text(""),
        _state("15b  Kratos's core off the tailnet entirely — all targets dark at once"), core_off,
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
        "title": "Tailscale onboarding + disconnect/unpair (13a–13f, 13j, 13m)",
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
        "title": "Sub-agent status / reachability / loss (11a/b, 12b, 13k, 15b, 18)",
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


# ---------------------------------------------------------------------------
# Execution half (Layer 5) -- ALL gated on Layer 4 (the whitelist). These are
# pictures only; nothing dispatches, signs, executes, or defines a whitelist.
# ---------------------------------------------------------------------------
def _exec_consent() -> Any:
    consent = _win(
        "kratos — settings",
        Text("web-01 · 10.0.3.14 · currently recommend-only", style=T.TEXT_FAINTER),
        Panel(
            Group(
                Text("⚠ enable direct execution for web-01?", style=f"bold {T.ATTENTION}"),
                Text(
                    "Kratos can be manipulated by data it reads from this server — a crafted log "
                    "entry, for example — into proposing a harmful action. With this enabled, an "
                    "approved action runs directly through the sub-agent instead of only being shown "
                    "to you to run yourself.", style=T.TEXT_MUTED),
                Text(
                    "The critical-approval gate (typed EXECUTE) stays required either way — this only "
                    "decides what EXECUTE does. Reversible any time from settings.", style=T.TEXT_FAINT),
                Group(_key("e"), Text("  enable direct execution", style=T.TEXT_DIM),
                      _key("esc"), Text("  decline — stay recommend-only", style=T.TEXT_DIM)),
            ),
            border_style=T.ATTENTION,
        ),
        border=T.ATTENTION,
    )
    settings = _win(
        "kratos — settings · direct execution",
        _kv([
            ("web-01", "recommend-only   [ e ] enable"),
            ("db-01", "recommend-only   [ e ] enable"),
            ("edge-2", "DIRECT EXECUTION ON   [ d ] disable"),
        ]),
        Text("Per-target, off by default, reversible. Toggling is a deliberate, logged choice.", style=T.TEXT_FAINT),
        border=T.BORDER,
    )
    discoverable = _win(
        "kratos — pair a target",
        Text("✓ web-01 paired", style=f"bold {T.SAFE}"),
        Panel(
            Group(
                Text("web-01 is recommend-only by default. Turn on direct execution?", style=T.TEXT),
                Group(_key("o"), Text("  open the direct-execution choice now (→ 19a)", style=T.TEXT_DIM),
                      _key("esc"), Text("  skip — won't ask again for web-01", style=T.TEXT_DIM)),
            ),
            border_style=T.BORDER,
        ),
        Text("One-time, dismissible, shown once right after a target's first pairing — never nags again "
             "once dismissed (per-target flag). A suggestion, not a gate: enter still starts "
             "investigating.", style=T.TEXT_FAINT),
        border=T.ACCENT,
    )
    return Group(
        _state("19a  direct-execution opt-in — dedicated consent screen"), consent, Text(""),
        _state("19d  settings — per-target status + toggle"), settings, Text(""),
        _state("19e  first-discoverable moment — one-time post-pairing suggestion (points to 19a)"), discoverable,
        Text(""),
        Text("Consent copy is plain-risk by design (control 6).", style=T.TEXT_FAINT),
    )


def _critical_gate() -> Any:
    gate = _win(
        "kratos — web-01 · CRITICAL APPROVAL",
        Text("Kratos proposes a whitelisted action on web-01:", style=T.TEXT),
        Panel(
            Group(
                Text("enable_service(fail2ban)", style=f"bold {T.TEXT_BRIGHT}"),
                _kv([
                    ("effect", "starts the fail2ban service"),
                    ("reversibility", "reversible — disable_service(fail2ban)"),
                    ("blast radius", "one service on web-01"),
                ]),
                Text("↑ effect / reversibility / blast-radius are read from the trusted whitelist "
                     "action definition — NEVER LLM-generated (control 7).", style=T.TEXT_FAINT),
            ),
            border_style=T.CRITICAL,
        ),
        Text("type EXECUTE to dispatch to the sub-agent   ·   esc cancel", style=T.CRITICAL),
        Text("(recommend-only targets have no EXECUTE field — the command is shown to copy instead, 19b)", style=T.TEXT_FAINT),
        border=T.CRITICAL,
    )
    drop = _win(
        "kratos — web-01 · CRITICAL APPROVAL",
        Text("⚠ sub-agent connectivity dropped while you were typing.", style=T.ATTENTION),
        Text("The EXECUTE field was pulled the instant the channel dropped — a completed EXECUTE can "
             "never sit on a dead channel. Amber (deterministically safe: nothing was sent), inside "
             "the still-red gate.", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    drift = _win(
        "kratos — web-01 · CRITICAL APPROVAL",
        Text("✗ cancelled — target state changed since the diff was generated.", style=T.CRITICAL),
        Text("A pre-flight hash check found the target file changed since Kratos proposed this. It "
             "cancels rather than execute against a stale assumption.", style=T.TEXT_MUTED),
        border=T.CRITICAL,
    )
    unreachable = _win(
        "kratos — web-01 · CRITICAL APPROVAL",
        Text("No EXECUTE field — the sub-agent is unreachable.", style=f"bold {T.ATTENTION}"),
        Text("Nothing dispatchable exists right now, so no EXECUTE is offered at all — amber, not the "
             "red gate. The exact command is shown to copy and run yourself instead (the recommend-only "
             "path, 19b).", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    zombied = _win(
        "kratos — web-01 · CRITICAL APPROVAL",
        Text("No EXECUTE field — the sub-agent isn't responding.", style=f"bold {T.ATTENTION}"),
        Text("Same 'no EXECUTE field' pattern as 12d, but here the process is live-but-silent (zombie), "
             "not a downed connection — wording is specific to that. Amber; copy-and-run-yourself "
             "offered instead.", style=T.TEXT_MUTED),
        border=T.ATTENTION,
    )
    return Group(
        _state("12c / 19c  upgraded critical gate — typed EXECUTE (direct-execution targets)"), gate, Text(""),
        _state("16a  sub-agent drops mid-type — field pulled live"), drop, Text(""),
        _state("17a  state-drift pre-flight — cancels on a changed target file"), drift, Text(""),
        _state("12d  sub-agent unreachable at approval — no EXECUTE offered"), unreachable, Text(""),
        _state("18b  critical approval while zombied — no EXECUTE, live-but-silent wording"), zombied,
    )


def _dispatch_outcomes() -> Any:
    def outcome(icon: str, color: str, title: str, body: str) -> Panel:
        return Panel(Group(Text(f"{icon} {title}", style=f"bold {color}"), Text(body, style=T.TEXT_MUTED)),
                     border_style=color)
    return Group(
        _state("11c  EXECUTE confirmed, sub-agent never ack'd the dispatch"),
        outcome("⚠", T.ATTENTION, "nothing ran", "No ack — nothing was dispatched, no state changed. Amber, not red."), Text(""),
        _state("11d  sub-agent received it and refused to run it"),
        outcome("⚠", T.ATTENTION, "refused before execution", "Rejected before running — target state untouched. Amber."), Text(""),
        _state("11e  connection dropped mid-execution — outcome unknown"),
        outcome("■", T.CRITICAL, "outcome unknown", "Dropped mid-execution — genuinely unknown. Solid alert red (not hazard stripes — those stay reserved for the pre-approval gate)."), Text(""),
        _state("11f  clean success"),
        outcome("✓", T.SAFE, "acked, ran, confirmed", "Green, calm, no ambiguity. The recommend-only equivalent is 19b's copy-the-command path."),
    )


def _revoke_queue() -> Any:
    revoke = _win(
        "kratos — emergency",
        Text("⛔ cut connection to web-01 now?", style=f"bold {T.CRITICAL}"),
        Text("A single keypress, instant effect — the action itself is safe/reversible (it just cuts "
             "the tailnet connection), so friction is the wrong instinct here; the urgency is why "
             "you'd reach for it. Distinct from 13m's routine double-confirm.", style=T.TEXT_MUTED),
        Text("r  revoke now   ·   esc keep connected", style=T.CRITICAL),
        border=T.CRITICAL,
    )
    queue = _win(
        "kratos — CRITICAL APPROVAL (1 of 2)",
        Text("A second critical approval is queued.", style=T.TEXT),
        Text("Critical approvals are strictly serialized — a quiet queue badge, NOT styled with alert "
             "weight itself, so the current gate's seriousness isn't diluted.", style=T.TEXT_MUTED),
        border=T.BORDER,
    )
    return Group(
        _state("15a  emergency revoke — single keypress, instant"), revoke, Text(""),
        _state("15c  two critical approvals at once — serialized, quiet queue badge"), queue,
    )


def _multi_broadcast() -> Any:
    m = Table(show_header=True, header_style="bold", box=None, expand=True)
    m.add_column("node", style=T.ACCENT)
    m.add_column("outcome")
    m.add_row("web-01", Text("✓ ran, confirmed", style=T.SAFE))
    m.add_row("web-02", Text("✓ ran, confirmed", style=T.SAFE))
    m.add_row("web-03", Text("✓ ran, confirmed", style=T.SAFE))
    m.add_row("web-04", Text("✓ ran, confirmed", style=T.SAFE))
    m.add_row("web-05", Text("■ outcome unknown — connection dropped", style=T.CRITICAL))
    return Group(
        _state("17e  multi-target broadcast — per-node outcome matrix"),
        _win("kratos — broadcast: enable_service(fail2ban) → 5 targets", m, border=T.BORDER),
        Text("Mixed outcomes shown per-node so 4 successes aren't buried under 1 failure. NOTE: "
             "multi-target AND execution together is the architecture doc's literal worst case — it "
             "is its OWN review gate (Layer 6 + Layer 5), not two features that happen to compose.",
             style=T.ATTENTION),
    )


# ---------------------------------------------------------------------------
# Edge / capability-limit states (mixed layers, not Layer-4-gated).
# ---------------------------------------------------------------------------
def _error_states() -> Any:
    return Group(
        _state("14a  Kratos's own model/API failure — full-width banner  [ALREADY WIRED in the real TUI]"),
        Panel(Text("⚠ Kratos can't think — language model unavailable. Distinct from a tool/target "
                   "problem. (This one is real today: render.llm_failure_banner.)", style=T.CRITICAL),
              border_style=T.CRITICAL), Text(""),
        _state("14b  context compaction firing (the event) — needs a compaction mechanism in agent/loop.py"),
        Panel(Text("↺ compacting the transcript to free context… a system event, not a finding or a "
                   "failure.", style=T.ATTENTION), border_style=T.ATTENTION), Text(""),
        _state("17b  local inference hardware failure (OOM / thermal on the Kratos host)"),
        Panel(Text("✗ the box Kratos runs on is failing (out of memory / thermal throttle). Restart or "
                   "lighten load — distinct from a cloud-API failure and from sub-agent connectivity.",
                   style=T.CRITICAL), border_style=T.CRITICAL), Text(""),
        _state("17c  payload exceeds the context limit before compaction could run"),
        Panel(Text("✗ too large to process — offers real ways forward instead of silently truncating "
                   "or crashing.", style=T.CRITICAL), border_style=T.CRITICAL),
    )


def _sandbox_hostility() -> Any:
    return Group(
        _state("17d  sandbox hostility — a self-write candidate tries to break its jail"),
        _win("kratos — evo-loop sandbox",
             Text("⛔ candidate killed — attempted to escape the read-only/no-network sandbox", style=f"bold {T.CRITICAL}"),
             Text("Shown as a forensic log of the attempt (network dial, fork attempts), not a routine "
                  "test failure. Nearer-term than Layer 5: could reuse the EXISTING self_test Incus "
                  "sandbox's signals (this jail already exists), not the sub-agent.", style=T.TEXT_MUTED),
             border=T.CRITICAL),
    )


PHASE2_EXECUTION: list[dict[str, Any]] = [
    {"id": "consent", "title": "Direct-execution consent + settings (19a/19d/19e)", "layer": "Layer 5 · Execution",
     "gated": True, "builder": _exec_consent,
     "to_wire": "Per-target opt-in flag store + the consent flow. Gated on Layer 4's whitelist existing first."},
    {"id": "critgate", "title": "Critical gate — typed EXECUTE (12c/19c, 16a, 17a, 12d, 18b)", "layer": "Layer 5 · Execution",
     "gated": True, "builder": _critical_gate,
     "to_wire": "Execution dispatch + the whitelist action definitions supplying effect/reversibility/blast-radius (control 7). Gated on Layer 4."},
    {"id": "outcomes", "title": "Dispatch outcomes (11c–11f)", "layer": "Layer 5 · Execution",
     "gated": True, "builder": _dispatch_outcomes,
     "to_wire": "The signed-command dispatch protocol + its ack/refuse/drop/success states. Gated on Layer 4."},
    {"id": "revoke", "title": "Emergency revoke + queued approvals (15a/15c)", "layer": "Layer 5 · Execution",
     "gated": True, "builder": _revoke_queue,
     "to_wire": "Tailnet key/connection teardown (revoke) + a serialized approval queue. Gated on Layer 4/5."},
    {"id": "broadcast", "title": "Multi-target broadcast matrix (17e)", "layer": "Layer 6 + 5",
     "gated": True, "builder": _multi_broadcast,
     "to_wire": "Multi-target execution model. This is the doc's worst case (multi-target + execution) and is ITS OWN review gate."},
]

PHASE2_EDGE: list[dict[str, Any]] = [
    {"id": "errors", "title": "Error / capability-limit states (14a/14b/17b/17c)", "layer": "Layer 3/6 · mixed",
     "gated": False, "builder": _error_states,
     "to_wire": "14a is already wired. 14b/17c need transcript compaction in agent/loop.py; 17b needs host-health signals."},
    {"id": "sandbox", "title": "Sandbox hostility — forensic view (17d)", "layer": "existing sandbox",
     "gated": False, "builder": _sandbox_hostility,
     "to_wire": "Nearer-term: surface the EXISTING self_test Incus sandbox's escape-attempt signals (no sub-agent needed)."},
]

PHASE2_ALL: list[dict[str, Any]] = PHASE2_SAFE + PHASE2_EXECUTION + PHASE2_EDGE


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
        for e in PHASE2_ALL:
            if e.get("gated"):
                status = Text("shell · GATED on Layer 4", style=T.CRITICAL)
            else:
                status = Text("shell · not wired", style=T.TEXT_FAINTER)
            table.add_row(e["title"], e["layer"], status)
        table.focus()

    def action_open_selected(self) -> None:
        table = self.query_one("#pv-table", DataTable)
        row = table.cursor_row
        if row is not None and 0 <= row < len(PHASE2_ALL):
            self.app.push_screen(ShellScreen(PHASE2_ALL[row]))

    @on(DataTable.RowSelected, "#pv-table")
    def _row(self, event: DataTable.RowSelected) -> None:
        row = event.cursor_row
        if row is not None and 0 <= row < len(PHASE2_ALL):
            self.app.push_screen(ShellScreen(PHASE2_ALL[row]))

    def action_close(self) -> None:
        self.dismiss(None)

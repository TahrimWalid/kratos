"""
Capability 2's consent + approval UI (docs/subagent_architecture.md controls
6/7; docs/subagent_whitelist_design.md §9 #2's tier-driven friction).
Reachable via `/whitelist`.

This screen NEVER executes anything itself. Every dispatch attempt goes
through the real, signed channel: it writes a row into
`kratos.storage.whitelist_store.WhitelistStore`'s dispatch-request queue and
polls for the result -- `kratos subagent-serve` (a separate process running
`CoreServer`) is what actually signs, dispatches, and the AGENT is what
independently re-validates and (only if its own local `execution_enabled`
opt-in is set) executes. If no `subagent-serve` process is running for this
target, dispatching here will simply time out waiting for a result -- an
honest "no core process is servicing this" outcome, not a fake success.

Friction is tier-driven, never hand-picked here: `whitelist.compute_sensitivity_tier`
already decided low/medium/high when the effective action set was built; this
screen only renders accordingly (a louder warning + a second confirmation for
`high`) and never overrides that tier.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Static

from kratos.storage.subagent_store import SubAgentStore
from kratos.storage.whitelist_store import WhitelistStore
from kratos.subagent import whitelist as W
from kratos.subagent.status import derive_status
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import ConfirmModal, ExecutionConsentModal, ListPickerModal, PromptModal, TypedExecuteModal

_POLL_INTERVAL_SECONDS = 0.5
_POLL_TIMEOUT_SECONDS = 40.0

_TIER_COLOR = {"low": T.SAFE, "medium": T.ATTENTION, "high": T.CRITICAL}
_OUTCOME_COLOR = {"ok": T.SAFE, "refused": T.ATTENTION, "error": T.ATTENTION, "unknown": T.CRITICAL}


class WhitelistScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("enter", "activate_selected", "run", show=True),
        Binding("e", "enable_execution", "enable direct execution", show=True),
        Binding("d", "disable_execution", "disable", show=False),
        Binding("t", "check_telemetry", "latest telemetry", show=True),
        Binding("r", "rollback", "rollback last", show=False),
    ]

    CSS = """
    WhitelistScreen { padding: 1 2; }
    WhitelistScreen #wl-banner { height: auto; padding: 0 0 1 0; }
    WhitelistScreen DataTable { height: 12; }
    WhitelistScreen #wl-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    WhitelistScreen #wl-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self._data_dir = data_dir
        self._sa_store = SubAgentStore(data_dir / "kratos.db")
        self._wl_store = WhitelistStore(data_dir / "kratos.db")
        self._target_id: str | None = None
        self._rows: list[dict[str, Any]] = []
        self._last_dispatch: dict[str, Any] | None = None  # for rollback

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="wl-banner")
            yield DataTable(id="wl-table", cursor_type="row")
            yield VerticalScroll(id="wl-log")
            yield Static(
                Text("↑↓ select · enter run · e enable exec · d disable · t telemetry · r rollback last · esc back",
                     style=T.TEXT_DIM),
                id="wl-hints",
            )

    def on_mount(self) -> None:
        table = self.query_one("#wl-table", DataTable)
        table.add_columns("action", "source", "tier")
        targets = self._sa_store.list_targets()
        if not targets:
            self._log(Text(
                "No paired sub-agent targets yet. Pairing has no TUI flow built yet -- "
                "run `kratos subagent-pair` from a terminal, then reopen /whitelist.",
                style=T.ATTENTION))
            return
        if len(targets) == 1:
            self._target_id = targets[0]["target_id"]
            self._refresh()
        else:
            self._pick_target([t["target_id"] for t in targets])

    @work
    async def _pick_target(self, target_ids: list[str]) -> None:
        entries = []
        for tid in target_ids:
            t = self._sa_store.get_target(tid)
            entries.append((tid, f"{tid}  {t.get('hostname') or '?'}" if t else tid))
        picked = await self.app.push_screen_wait(ListPickerModal("Pick a paired target", entries))
        if picked is None:
            self.app.pop_screen()
            return
        self._target_id = picked
        self._refresh()

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    def _log(self, renderable: Any) -> None:
        self.query_one("#wl-log", VerticalScroll).mount(Static(renderable))
        self.query_one("#wl-log", VerticalScroll).scroll_end(animate=False)

    def _refresh(self) -> None:
        if self._target_id is None:
            return
        opted_in = self._wl_store.get_execution_opt_in(self._target_id)
        target = self._sa_store.get_target(self._target_id)
        status = derive_status(target["last_seen"]) if target else "never_connected"
        self._rows = self._wl_store.effective_action_set(self._target_id)

        table = self.query_one("#wl-table", DataTable)
        table.clear()
        for row in self._rows:
            spec = row["spec"]
            tier_text = Text(row["tier"], style=_TIER_COLOR.get(row["tier"], T.TEXT))
            table.add_row(spec.id, row["source"], tier_text, key=spec.id)

        banner = Text()
        banner.append("DIRECT EXECUTION ON" if opted_in else "recommend-only", style=f"bold {T.CRITICAL if opted_in else T.TEXT_MUTED}")
        banner.append(f"  ·  target {self._target_id}  ·  status {status}  ·  {len(self._rows)} action(s) enabled",
                       style=T.TEXT_DIM)
        self.query_one("#wl-banner", Static).update(banner)

    def _can_execute(self) -> bool:
        if self._target_id is None:
            return False
        if not self._wl_store.get_execution_opt_in(self._target_id):
            return False
        target = self._sa_store.get_target(self._target_id)
        if target is None:
            return False
        return derive_status(target["last_seen"]) == "connected"

    # ------------------------------------------------------------------
    # Control 6.
    # ------------------------------------------------------------------
    @work
    async def action_enable_execution(self) -> None:
        if self._target_id is None:
            return
        if self._wl_store.get_execution_opt_in(self._target_id):
            self._log(Text("Direct execution is already enabled for this target.", style=T.TEXT_DIM))
            return
        confirmed = await self.app.push_screen_wait(ExecutionConsentModal(self._target_id))
        if confirmed:
            self._wl_store.set_execution_opt_in(self._target_id, True)
            self._log(Text(f"✓ direct execution enabled for {self._target_id}.", style=f"bold {T.SAFE}"))
        else:
            self._log(Text("Declined -- staying recommend-only.", style=T.TEXT_DIM))
        self._refresh()

    @work
    async def action_disable_execution(self) -> None:
        if self._target_id is None or not self._wl_store.get_execution_opt_in(self._target_id):
            return
        confirmed = await self.app.push_screen_wait(
            ConfirmModal("Disable direct execution?", f"Turn direct execution back off for {self._target_id}?"))
        if confirmed:
            self._wl_store.set_execution_opt_in(self._target_id, False)
            self._log(Text(f"Direct execution disabled for {self._target_id}.", style=T.TEXT_DIM))
            self._refresh()

    # ------------------------------------------------------------------
    # Control 7 -- typed EXECUTE, tier-driven friction.
    # ------------------------------------------------------------------
    def action_activate_selected(self) -> None:
        table = self.query_one("#wl-table", DataTable)
        if table.cursor_row is None or not self._rows or table.cursor_row >= len(self._rows):
            return
        row = self._rows[table.cursor_row]
        self._run_action_flow(row["spec"], row["tier"])

    @work
    async def _run_action_flow(self, spec: W.ActionSpec, tier: str) -> None:
        values = await self._collect_slot_values(spec)
        if values is None:
            return  # cancelled mid-collection
        try:
            argv = W.render_argv(spec, values)
        except (W.ActionSpecError, W.SlotValueError) as e:
            self._log(Text(f"✗ {spec.id}: {e}", style=T.CRITICAL))
            return

        can_execute = self._can_execute()
        confirmed = await self.app.push_screen_wait(
            TypedExecuteModal(spec.id, spec.effect, spec.reversibility, spec.blast_radius, tier,
                               " ".join(argv), can_execute)
        )
        if not can_execute:
            return  # informational gate only -- nothing to dispatch
        if not confirmed:
            self._log(Text("Cancelled -- nothing was dispatched.", style=T.TEXT_DIM))
            return
        if tier == "high":
            second = await self.app.push_screen_wait(ConfirmModal(
                "Second confirmation required (HIGH sensitivity)",
                f"Really dispatch {spec.id} to {self._target_id} now?"))
            if not second:
                self._log(Text("Cancelled at the second confirmation.", style=T.TEXT_DIM))
                return

        await self._dispatch_and_poll(spec, values, tier)

    async def _collect_slot_values(self, spec: W.ActionSpec) -> dict[str, Any] | None:
        values: dict[str, Any] = {}
        for name, slot in spec.slots.items():
            if slot.kind == "enum":
                entries = [(v, v) for v in (slot.values or ())]
                picked = await self.app.push_screen_wait(ListPickerModal(f"{spec.id} -- {name}", entries))
                if picked is None:
                    return None
                values[name] = picked
                continue
            # ip / int_range / token -- prompt + validate, reject-and-reprompt.
            while True:
                raw = await self.app.push_screen_wait(PromptModal(f"{spec.id} -- {name}", hint=f"({slot.kind})"))
                if raw is None:
                    return None
                candidate: Any = raw
                if slot.kind == "int_range":
                    try:
                        candidate = int(raw)
                    except ValueError:
                        self._log(Text(f"'{raw}' is not a whole number -- try again.", style=T.ATTENTION))
                        continue
                try:
                    W._validate_slot_value(spec.id, name, slot, candidate)
                except W.SlotValueError as e:
                    self._log(Text(f"{e} -- try again.", style=T.ATTENTION))
                    continue
                values[name] = candidate
                break
        return values

    async def _dispatch_and_poll(self, spec: W.ActionSpec, values: dict[str, Any], tier: str) -> None:
        assert self._target_id is not None
        version = self._wl_store.get_whitelist_version(self._target_id)
        try:
            request_id = self._wl_store.create_dispatch_request(self._target_id, spec.id, values, version)
        except ValueError as e:
            self._log(Text(f"✗ {e}", style=T.CRITICAL))
            return
        self._log(Text(f"→ dispatch requested: {spec.id} (request {request_id[:8]}…) -- waiting for a result…",
                        style=T.ACCENT))

        elapsed = 0.0
        row = None
        while elapsed < _POLL_TIMEOUT_SECONDS:
            row = self._wl_store.get_dispatch_request(request_id)
            if row and row["status"] == "done":
                break
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
            elapsed += _POLL_INTERVAL_SECONDS
        else:
            self._log(Text(
                f"⚠ no result within {_POLL_TIMEOUT_SECONDS:.0f}s -- is `kratos subagent-serve` running "
                "for this target? Outcome unknown, nothing confirmed either way.", style=f"bold {T.CRITICAL}"))
            return

        result = row["result"] or {}
        status = result.get("status", "unknown")
        color = _OUTCOME_COLOR.get(status, T.CRITICAL)
        icon = {"ok": "✓", "refused": "⚠", "error": "⚠", "unknown": "■"}.get(status, "■")
        detail = result.get("reason") or (
            f"exit_code={result.get('exit_code')}" if status == "ok" else ""
        )
        self._log(Text(f"{icon} {spec.id}: {status}  {detail}", style=f"bold {color}"))
        if status == "ok" and result.get("stdout_tail"):
            self._log(Text(result["stdout_tail"][-2000:], style=T.TEXT_DIM))

        if status == "ok" and tier in ("medium", "high"):
            self._last_dispatch = {"spec": spec, "values": values, "tier": tier}
            note = Text(
                "The next capability-1 telemetry cycle will reflect this change -- press "
                "t to check the latest observed state now", style=T.TEXT_FAINT)
            if spec.inverse_id:
                note.append(f", or r to roll back via {spec.inverse_id}.", style=T.TEXT_FAINT)
            else:
                note.append(".", style=T.TEXT_FAINT)
            self._log(note)

    # ------------------------------------------------------------------
    # Telemetry-confirmed undo window.
    # ------------------------------------------------------------------
    def action_check_telemetry(self) -> None:
        if self._target_id is None:
            return
        latest = self._sa_store.get_latest_telemetry(self._target_id)
        if latest is None:
            self._log(Text("No telemetry received from this target yet.", style=T.TEXT_DIM))
            return
        body = Table(show_header=False, box=None)
        body.add_column(style=T.TEXT_DIM, justify="right")
        body.add_column(style=T.TEXT)
        body.add_row("collected_at", str(latest.get("collected_at")))
        host = (latest["payload"].get("host") or {})
        services = (latest["payload"].get("services") or {})
        body.add_row("uptime_seconds", str(host.get("uptime_seconds")))
        body.add_row("services", str(services)[:300])
        self._log(Text("Latest observed state (real telemetry, not inferred):", style=f"bold {T.ACCENT}"))
        self._log(body)

    def action_rollback(self) -> None:
        if self._last_dispatch is None:
            self._log(Text("Nothing to roll back yet.", style=T.TEXT_DIM))
            return
        prior = self._last_dispatch
        inverse_id = prior["spec"].inverse_id
        if not inverse_id:
            self._log(Text(f"{prior['spec'].id} has no declared inverse action.", style=T.TEXT_DIM))
            return
        inverse_row = next((r for r in self._rows if r["spec"].id == inverse_id), None)
        if inverse_row is None:
            self._log(Text(f"Inverse action {inverse_id!r} isn't currently enabled for this target.",
                            style=T.ATTENTION))
            return
        inverse_spec = inverse_row["spec"]
        carried = {k: v for k, v in prior["values"].items() if k in inverse_spec.slots}
        self._rollback_flow(inverse_spec, inverse_row["tier"], carried)

    @work
    async def _rollback_flow(self, spec: W.ActionSpec, tier: str, carried_values: dict[str, Any]) -> None:
        # Re-collect any slot the inverse needs that wasn't carried over
        # (e.g. a slot the original action didn't have), then run the SAME
        # typed-EXECUTE flow as any other dispatch -- rollback is not a
        # shortcut around the gate, just a pre-filled starting point.
        missing = {name: slot for name, slot in spec.slots.items() if name not in carried_values}
        extra: dict[str, Any] = {}
        if missing:
            fake_spec = W.ActionSpec(
                id=spec.id, layer=spec.layer, argv_template=spec.argv_template, slots=missing,
                effect=spec.effect, reversibility=spec.reversibility, blast_radius=spec.blast_radius,
                requires_typed_execute=True,
            )
            collected = await self._collect_slot_values(fake_spec)
            if collected is None:
                return
            extra = collected
        values = {**carried_values, **extra}
        try:
            argv = W.render_argv(spec, values)
        except (W.ActionSpecError, W.SlotValueError) as e:
            self._log(Text(f"✗ {spec.id}: {e}", style=T.CRITICAL))
            return
        can_execute = self._can_execute()
        confirmed = await self.app.push_screen_wait(
            TypedExecuteModal(spec.id, spec.effect, spec.reversibility, spec.blast_radius, tier,
                               " ".join(argv), can_execute)
        )
        if not can_execute or not confirmed:
            return
        await self._dispatch_and_poll(spec, values, tier)

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

It is also where the allowlist is MANAGED: every built-in action and every
entry of the user's own is listed with its state; `a` adds one (narrow a
built-in template, type a command with {blanks}, or an exact command), `m`
edits, space turns one on/off, `x` deletes (or resets a built-in), `i` shows
details, `c` shows what the target's agent itself allows (its ceiling, its
admin's exact-command file, anything it refused), and `s` asks the agent to
report again. Everything typed here is checked against the target's ceiling
before it is saved -- the agent checks it again regardless.
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
from kratos.subagent import ceiling as C
from kratos.subagent import entry_builder as EB
from kratos.subagent import whitelist as W
from kratos.subagent import whitelist_templates as TPL
from kratos.subagent.status import derive_status
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import (
    CommandModal, ConfirmModal, ExecutionConsentModal, ListPickerModal, MultiSelectModal, PromptModal, TypedExecuteModal,
)
from kratos.tui_mk2.table_fit import fit_columns

_WL_COLUMNS = ("action", "runs", "source", "tier", "state")
_POLL_INTERVAL_SECONDS = 0.5
_POLL_TIMEOUT_SECONDS = 40.0

_TIER_COLOR = {"low": T.SAFE, "medium": T.ATTENTION, "high": T.CRITICAL}
_STATE_COLOR = {"on": T.SAFE, "off": T.TEXT_MUTED, "waiting": T.ATTENTION, "invalid": T.CRITICAL}
# The agent version that enforces its own execution ceiling; anything older
# is refused by core for execution and must be reinstalled.
_MIN_EXEC_AGENT_VERSION = (0, 2, 0)


def _version_tuple(v: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in (v or "").split(".")[:3])
    except ValueError:
        return ()


def build_rows(wl_store: WhitelistStore, target_id: str) -> list[dict[str, Any]]:
    """Every built-in action and every user entry for a target, with a plain
    state: on / off / waiting (exact command the target hasn't allowed yet) /
    invalid (no longer passes the ceiling). Only `on` rows can be run."""
    rows: list[dict[str, Any]] = []
    for m in wl_store.list_maintainer_status(target_id):
        rows.append({"kind": "maintainer", "spec": m["spec"], "tier": m["tier"],
                     "state": "on" if m["enabled"] else "off", "overridden": m["overridden"],
                     "label": m["spec"].id, "source": "built-in", "error": None})
    for e in wl_store.list_user_entries(target_id):
        spec = e.effective_spec or e.stored_spec
        if e.effective_spec is not None:
            state = "on" if e.enabled else "off"
        else:
            state = "waiting" if e.pending else "invalid"
        label = (f"{e.template_id} (yours)" if e.template_id != "custom"
                 else (spec.effect[:44] if spec else "custom entry"))
        rows.append({"kind": "user", "spec": spec, "tier": e.tier or "high", "state": state,
                     "entry_id": e.entry_id, "template_id": e.template_id, "enabled": e.enabled,
                     "label": label, "source": "exact command" if spec is not None and not spec.slots and e.template_id == "custom"
                     else ("your command" if e.template_id == "custom" else "your template"),
                     "error": e.error, "selected_values": e.selected_values})
    return rows
_OUTCOME_COLOR = {"ok": T.SAFE, "refused": T.ATTENTION, "error": T.ATTENTION, "unknown": T.CRITICAL}


class WhitelistScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        # priority: the focused DataTable otherwise consumes Enter itself and
        # the run flow never starts (a real bug, caught by a real-keypress test).
        Binding("enter", "activate_selected", "run", show=True, priority=True),
        Binding("a", "add_entry", "add", show=True),
        Binding("m", "edit_entry", "edit", show=True),
        Binding("space", "toggle_entry", "on/off", show=True),
        Binding("x", "delete_entry", "delete/reset", show=True),
        Binding("i", "entry_details", "details", show=True),
        Binding("c", "show_ceiling", "what the target allows", show=True),
        Binding("s", "resync", "re-sync", show=False),
        Binding("e", "enable_execution", "enable direct execution", show=True),
        Binding("d", "disable_execution", "disable", show=False),
        Binding("t", "check_telemetry", "latest telemetry", show=True),
        Binding("r", "rollback", "rollback last", show=False),
    ]

    CSS = """
    WhitelistScreen { padding: 1 2; }
    WhitelistScreen #wl-banner { height: auto; padding: 0 0 1 0; }
    WhitelistScreen DataTable { height: auto; max-height: 60%; }
    WhitelistScreen #wl-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    WhitelistScreen #wl-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, target_id: str | None = None,
                 preselect: dict[str, Any] | None = None) -> None:
        """`preselect` = {"action_id", "values"}: open straight into the run
        flow for that action with those slot values (used when an
        investigation's recommended command matches an allowlist entry). The
        approval gate is exactly the same; only the typing is pre-filled."""
        super().__init__()
        self._data_dir = data_dir
        self._requested_target = target_id
        self._preselect = preselect
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
                Text("↑↓ select · enter run · a add · m edit · space on/off · x delete · i details · "
                     "c what the target allows · s re-sync · e enable exec · d disable · t telemetry · "
                     "r rollback last · esc back", style=T.TEXT_DIM),
                id="wl-hints",
            )

    def on_mount(self) -> None:
        table = self.query_one("#wl-table", DataTable)
        table.add_columns(*_WL_COLUMNS)
        targets = self._sa_store.list_targets()
        if self._requested_target and any(t["target_id"] == self._requested_target for t in targets):
            self._target_id = self._requested_target
            self._refresh()
            if self._preselect:
                self._start_preselected()
            return
        if not targets:
            self._log(Text(
                "No paired sub-agent targets yet. Use /subagent to add a server "
                "(it walks you through pairing), then reopen /whitelist.",
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

    def on_resize(self, event) -> None:
        self.call_after_refresh(self._refresh)

    def on_screen_resume(self) -> None:
        # Rows filled in the moment a modal (target picker, add/edit flow)
        # closes land before this screen is laid out again and keep the
        # header-only column widths -- every cell cropped to its header.
        # Rebuild once more after the next frame.
        self.call_after_refresh(self._refresh)

    def _refresh(self) -> None:
        if self._target_id is None:
            return
        opted_in = self._wl_store.get_execution_opt_in(self._target_id)
        target = self._sa_store.get_target(self._target_id)
        status = derive_status(target["last_seen"]) if target else "never_connected"
        cursor = self.query_one("#wl-table", DataTable).cursor_row
        self._rows = build_rows(self._wl_store, self._target_id)

        table = self.query_one("#wl-table", DataTable)
        table.clear()
        cells, keys = [], []
        for i, row in enumerate(self._rows):
            spec = row["spec"]
            runs = C.shlex.join(spec.argv_template) if spec else "?"
            cells.append([
                row["label"], runs[:48], row["source"],
                Text(row["tier"], style=_TIER_COLOR.get(row["tier"], T.TEXT)),
                Text(row["state"], style=_STATE_COLOR.get(row["state"], T.TEXT)),
            ])
            keys.append(f"{row['kind']}:{row.get('entry_id') or spec.id}:{i}")
        # Keep tier/state on screen: the command template gives way first (the
        # full command is under i), then the entry name.
        available = table.size.width or max(self.app.size.width - 6, 40)
        for key, row in zip(keys, fit_columns(cells, available, shrink=[(1, 12), (0, 12)], headers=_WL_COLUMNS)):
            table.add_row(*row, key=key)
        if cursor is not None and self._rows:
            table.move_cursor(row=min(cursor, len(self._rows) - 1))
        if self._rows and not self.query_one("#wl-log", VerticalScroll).children:
            # The area under the table is where details and results appear; say so
            # rather than leave it blank.
            self._log(Text("i shows what the highlighted entry runs and how risky it is · enter runs it "
                           "(you confirm first) · a adds your own. Details and results appear here.",
                           style=T.TEXT_DIM))

        enabled = sum(1 for r in self._rows if r["state"] == "on")
        banner = Text()
        banner.append("DIRECT EXECUTION ON" if opted_in else "recommend-only", style=f"bold {T.CRITICAL if opted_in else T.TEXT_MUTED}")
        name = (target or {}).get("name") or self._target_id
        host = (target or {}).get("hostname")
        where = f"{name} ({host})" if host and host != name else name
        banner.append(f"  ·  {where}  ·  status {status}  ·  {enabled} action(s) on", style=T.TEXT_DIM)
        agent = self._wl_store.get_agent_state(self._target_id) or {}
        version = agent.get("agent_version") or (target or {}).get("agent_version")
        if version and _version_tuple(version) < _MIN_EXEC_AGENT_VERSION:
            banner.append(f"\n⚠ this target runs sub-agent {version}, which is too old to execute anything -- "
                          "reinstall it from /subagent.", style=f"bold {T.ATTENTION}")
        if agent.get("rejected"):
            banner.append(f"\n⚠ the agent refused {len(agent['rejected'])} action(s) -- press c for why.",
                          style=T.ATTENTION)
        waiting = sum(1 for r in self._rows if r["state"] == "waiting")
        if waiting:
            banner.append(f"\n{waiting} exact command(s) waiting for the target's admin to allow them -- "
                          "select one and press i.", style=T.ATTENTION)
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
    def _selected_row(self) -> dict[str, Any] | None:
        table = self.query_one("#wl-table", DataTable)
        if table.cursor_row is None or not self._rows or table.cursor_row >= len(self._rows):
            return None
        return self._rows[table.cursor_row]

    def action_activate_selected(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        if row["state"] != "on":
            why = {"off": "it's turned off -- press space to turn it on first",
                   "waiting": "the target's admin hasn't allowed this exact command yet -- press i for the line to add",
                   "invalid": f"it no longer passes the target's rules: {row.get('error')}"}[row["state"]]
            self._log(Text(f"Can't run {row['label']}: {why}.", style=T.ATTENTION))
            return
        self._run_action_flow(row["spec"], row["tier"])

    def _start_preselected(self) -> None:
        pre = self._preselect or {}
        row = next((r for r in self._rows if r["state"] == "on" and r["spec"] is not None
                    and r["spec"].id == pre.get("action_id")), None)
        if row is None:
            self._log(Text("That action is no longer enabled for this target.", style=T.ATTENTION))
            return
        self._log(Text(f"Kratos recommended a command that matches {row['label']}. It still needs your "
                       "approval below.", style=T.ACCENT))
        self._run_action_flow(row["spec"], row["tier"], dict(pre.get("values") or {}))

    @work
    async def _run_action_flow(self, spec: W.ActionSpec, tier: str, values: dict[str, Any] | None = None) -> None:
        if values is None:
            values = await self._collect_slot_values(spec)
        if values is None:
            return  # cancelled mid-collection
        try:
            argv = self._render_preview(spec, values)
        except (W.ActionSpecError, W.SlotValueError, C.CeilingError) as e:
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

    def _render_preview(self, spec: W.ActionSpec, values: dict[str, Any]) -> list[str]:
        """The argv the approval screen shows. Same rule as the agent: an exact
        command the target's admin listed on the target is exempt from the
        maintainer ban list, and the result must fit the target's ceiling."""
        ceiling = self._wl_store.target_ceiling(self._target_id)
        argv = W.render_argv(spec, values, hard_exclusions=not C.uses_local_command(spec, ceiling))
        C.match_argv(argv, ceiling)
        return argv

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
        inverse_row = next((r for r in self._rows if r["state"] == "on" and r["spec"] is not None
                            and r["spec"].id == inverse_id), None)
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
            argv = self._render_preview(spec, values)
        except (W.ActionSpecError, W.SlotValueError, C.CeilingError) as e:
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

    # ------------------------------------------------------------------
    # Managing the allowlist.
    # ------------------------------------------------------------------
    @work
    async def action_toggle_entry(self) -> None:
        row = self._selected_row()
        if row is None or self._target_id is None:
            return
        turning_on = row["state"] != "on"
        if row["kind"] == "maintainer":
            if turning_on and row["tier"] == "high":
                ok = await self.app.push_screen_wait(ConfirmModal(
                    "Turn on a HIGH-risk action?",
                    f"{row['spec'].effect}\n\nReversibility: {row['spec'].reversibility}\n"
                    f"Blast radius: {row['spec'].blast_radius}\n\nHigh-risk actions are off by default. "
                    "Turning it on only makes it available -- every run still needs you to type EXECUTE."))
                if not ok:
                    self._log(Text("Left off.", style=T.TEXT_DIM))
                    return
            self._wl_store.set_maintainer_override(self._target_id, row["spec"].id, turning_on)
        else:
            if turning_on and row["state"] in ("waiting", "invalid"):
                self._log(Text("It's marked on, but it can't run until it passes the target's rules "
                               "(press i for details).", style=T.ATTENTION))
            self._wl_store.set_user_entry_enabled(row["entry_id"], not row.get("enabled", False))
        self._log(Text(f"{row['label']}: {'on' if turning_on else 'off'}.", style=T.TEXT_DIM))
        self._refresh()

    @work
    async def action_delete_entry(self) -> None:
        row = self._selected_row()
        if row is None or self._target_id is None:
            return
        if row["kind"] == "maintainer":
            if not row.get("overridden"):
                self._log(Text("Built-in actions can't be deleted -- press space to turn one off.", style=T.TEXT_DIM))
                return
            ok = await self.app.push_screen_wait(ConfirmModal(
                "Reset to default?", f"Reset {row['label']} to its default ({'off' if row['tier'] == 'high' else 'on'})?"))
            if ok:
                self._wl_store.clear_maintainer_override(self._target_id, row["spec"].id)
                self._log(Text(f"{row['label']}: reset to default.", style=T.TEXT_DIM))
        else:
            ok = await self.app.push_screen_wait(ConfirmModal(
                "Delete this entry?", f"{row['label']}\n\nKratos will no longer be able to run it on this target."))
            if ok:
                self._wl_store.delete_user_entry(row["entry_id"])
                self._log(Text(f"Deleted {row['label']}.", style=T.TEXT_DIM))
        self._refresh()

    def action_entry_details(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        spec = row["spec"]
        body = Table(show_header=False, box=None)
        body.add_column(style=T.TEXT_DIM, justify="right")
        body.add_column(style=T.TEXT)
        body.add_row("entry", row["label"])
        body.add_row("state", row["state"])
        body.add_row("tier", row["tier"])
        if spec is not None:
            body.add_row("runs", C.shlex.join(spec.argv_template))
            for name, slot in spec.slots.items():
                body.add_row(f"{{{name}}}", EB.BlankDraft(name, 0, C.Var(slot)).describe())
            body.add_row("effect", spec.effect)
            body.add_row("reversibility", spec.reversibility)
            body.add_row("blast radius", spec.blast_radius)
        if row.get("error"):
            body.add_row("problem", row["error"])
        self._log(Text(f"Details: {row['label']}", style=f"bold {T.ACCENT}"))
        self._log(body)
        if row["state"] == "waiting" and spec is not None:
            self._show_allow_snippet(C.shlex.join(spec.argv_template))

    def _show_allow_snippet(self, line: str) -> None:
        try:
            snippet = EB.allow_file_snippet(line)
        except C.CeilingError as e:
            self._log(Text(f"✗ {e}", style=T.CRITICAL))
            return
        self.app.push_screen(CommandModal(
            snippet, title="Allow this exact command on the target",
            note=("Run this ON THE TARGET (as its admin). It adds the line to "
                  f"{C.LOCAL_ALLOW_FILE} with the permissions the agent requires. Then press s here to re-sync.")))

    def action_show_ceiling(self) -> None:
        if self._target_id is None:
            return
        state = self._wl_store.get_agent_state(self._target_id) or {}
        ceiling = state.get("ceiling") or {}
        self._log(Text("What this target's agent will run (its own rules -- Kratos can narrow them, never widen them):",
                       style=f"bold {T.ACCENT}"))
        for form in EB.allowed_forms(C.DEFAULT_CEILING):
            self._log(Text(f"  • {form}", style=T.TEXT))
        local = ceiling.get("local_commands") or []
        if local:
            self._log(Text("Exact commands its admin allowed on the target:", style=f"bold {T.ACCENT}"))
            for line in local:
                self._log(Text(f"  • {line}", style=T.TEXT))
        elif state:
            self._log(Text(f"No exact commands allowed on the target ({C.LOCAL_ALLOW_FILE} is empty or absent).",
                           style=T.TEXT_DIM))
        else:
            self._log(Text("This target hasn't reported yet -- it will once `kratos subagent-serve` sees it connect.",
                           style=T.TEXT_DIM))
        for problem in ceiling.get("local_problems") or []:
            self._log(Text(f"  ⚠ {problem}", style=T.ATTENTION))
        for r in state.get("rejected") or []:
            self._log(Text(f"  ⚠ refused {r.get('id')}: {r.get('reason')}", style=T.ATTENTION))
        if state.get("agent_version"):
            self._log(Text(f"agent version {state['agent_version']} · last report {state.get('updated_at')}",
                           style=T.TEXT_FAINT))

    def action_resync(self) -> None:
        if self._target_id is None:
            return
        self._wl_store.request_resync(self._target_id)
        self._log(Text("Asked the agent to report again -- if `kratos subagent-serve` is running and the target is "
                       "connected, press c in a few seconds to see its answer.", style=T.TEXT_DIM))
        self.set_timer(4.0, self._refresh)

    # --- add -------------------------------------------------------------
    @work
    async def action_add_entry(self) -> None:
        if self._target_id is None:
            return
        how = await self.app.push_screen_wait(ListPickerModal("Add to this target's allowlist", [
            ("template", "Start from a built-in action and narrow it (e.g. only the fail2ban service)"),
            ("blanks", "My own command, with {blanks} for what varies  (e.g. fail2ban-client set sshd banip {ip})"),
            ("exact", "One exact command  (e.g. adduser --disabled-password --gecos '' alice)"),
        ]))
        if how == "template":
            await self._add_from_template()
        elif how == "blanks":
            await self._add_with_blanks()
        elif how == "exact":
            await self._add_exact()
        self._refresh()

    async def _add_from_template(self) -> None:
        templates = TPL.list_builtin_templates()
        tid = await self.app.push_screen_wait(ListPickerModal(
            "Which built-in action?", [(t.base.id, f"{t.base.id} -- {t.base.effect}") for t in templates]))
        if tid is None:
            return
        template = TPL.get_template(tid)
        selected: dict[str, tuple[str, ...]] = {}
        for name, slot in template.base.slots.items():
            if slot.kind != "enum" or len(slot.values or ()) < 2:
                continue
            picked = await self.app.push_screen_wait(MultiSelectModal(
                f"{tid}: which {name} values may it use?", [(v, v) for v in slot.values],
                subtitle="Untick anything this target should never do."))
            if picked is None:
                return
            selected[name] = tuple(picked)
        try:
            self._wl_store.create_user_entry(self._target_id, tid, selected_values=selected)
        except (ValueError, W.ActionSpecError, C.CeilingError) as e:
            self._log(Text(f"✗ Not saved: {e}", style=T.CRITICAL))
            return
        self._log(Text(f"✓ Added {tid} (yours), narrowed to {selected or 'its defaults'}. It's on.", style=T.SAFE))

    async def _ask_texts(self, defaults: dict[str, str]) -> dict[str, str] | None:
        out = {}
        prompts = [("effect", "What does it do? (shown on every approval)"),
                   ("reversibility", "How is it undone?"),
                   ("blast_radius", "What can it affect?")]
        for key, title in prompts:
            while True:
                val = await self.app.push_screen_wait(PromptModal(title, initial=defaults.get(key, "")))
                if val is None:
                    return None
                if val.strip():
                    out[key] = val.strip()
                    break
                self._log(Text("This can't be empty -- it's what you'll read before approving a run.", style=T.ATTENTION))
        return out

    async def _add_with_blanks(self) -> None:
        ceiling = self._wl_store.target_ceiling(self._target_id)
        hint = "Allowed forms:\n  " + "\n  ".join(EB.allowed_forms(ceiling)) + "\nUse {name} for a blank."
        drafts = None
        text = ""
        while drafts is None:
            text = await self.app.push_screen_wait(PromptModal("Your command, with {blanks}", hint=hint, initial=text))
            if text is None:
                return
            try:
                drafts = EB.draft_command(text, ceiling)
            except EB.EntryDraftError as e:
                self._log(Text(str(e), style=T.ATTENTION))
        draft = drafts[0]
        if len(drafts) > 1:
            picked = await self.app.push_screen_wait(ListPickerModal(
                "That matches more than one allowed form -- which one?",
                [(i, EB.describe_shape(d.shape)) for i, d in enumerate(drafts)]))
            if picked is None:
                return
            draft = drafts[picked]
        slots: dict[str, W.Slot] = {}
        for blank in draft.blanks:
            slot = blank.default_slot()
            if blank.kind == "enum":
                picked = await self.app.push_screen_wait(MultiSelectModal(
                    f"{{{blank.name}}}: which values may it take?", [(v, v) for v in blank.allowed_values()]))
                if picked is None:
                    return
                slot = W.Slot(kind="enum", values=tuple(picked))
            elif blank.kind == "int_range":
                lo, hi = slot.min_value, slot.max_value
                raw = await self.app.push_screen_wait(PromptModal(
                    f"{{{blank.name}}}: allowed range (min-max, within {lo}-{hi})", initial=f"{lo}-{hi}"))
                if raw is None:
                    return
                try:
                    a, b = (int(x) for x in raw.replace(" ", "").split("-", 1))
                    slot = W.Slot(kind="int_range", min_value=a, max_value=b)
                except ValueError:
                    self._log(Text("Use the form min-max, e.g. 1-60. Nothing saved.", style=T.ATTENTION))
                    return
            else:
                self._log(Text(f"{{{blank.name}}} will accept {blank.describe()}.", style=T.TEXT_DIM))
            slots[blank.name] = slot
        texts = await self._ask_texts(EB.default_texts(draft.shape))
        if texts is None:
            return
        try:
            # Risk flags come from the vetted ceiling shape (the store's floor
            # still lets nothing be declared LESS risky than that).
            entry_id = self._wl_store.create_custom_entry(
                self._target_id, draft.tokens, slots, **texts,
                reversible=draft.shape.reversible,
                disrupts_running_service=draft.shape.disrupts_running_service,
                reachability_adjacent=draft.shape.reachability_adjacent,
            )
        except (ValueError, W.ActionSpecError, C.CeilingError) as e:
            self._log(Text(f"✗ Not saved: {e}", style=T.CRITICAL))
            return
        tier = next((r["tier"] for r in build_rows(self._wl_store, self._target_id)
                     if r.get("entry_id") == entry_id), "?")
        self._log(Text(f"✓ Added: {' '.join(draft.tokens)}  (risk tier: {tier}). It's on.", style=T.SAFE))

    async def _add_exact(self) -> None:
        line = ""
        tokens = None
        while tokens is None:
            line = await self.app.push_screen_wait(PromptModal(
                "The exact command", initial=line,
                hint=("One plain command, no pipes or ';'. It must run without prompting for input "
                      "(e.g. adduser --disabled-password --gecos '' alice). A leading sudo is dropped.")))
            if line is None:
                return
            try:
                tokens = C.parse_command_line(line)
            except C.CeilingError as e:
                self._log(Text(f"{e}", style=T.ATTENTION))
        canonical = C.shlex.join(tokens)
        texts = await self._ask_texts({"effect": f"Runs: {canonical}", "reversibility": "Not automatically reversible.",
                                       "blast_radius": "Whatever this exact command changes on the target."})
        if texts is None:
            return
        try:
            entry_id = self._wl_store.create_exact_command_entry(self._target_id, canonical, **texts)
        except (ValueError, W.ActionSpecError, C.CeilingError) as e:
            self._log(Text(f"✗ Not saved: {e}", style=T.CRITICAL))
            return
        row = next((r for r in build_rows(self._wl_store, self._target_id) if r.get("entry_id") == entry_id), None)
        if row and row["state"] == "waiting":
            self._log(Text(f"✓ Saved {canonical!r} -- waiting for the target. Its admin has to allow this exact line "
                           "on the target (copy the command in the box), then press s.", style=T.ATTENTION))
            self._show_allow_snippet(canonical)
        else:
            self._log(Text(f"✓ Added {canonical!r} (risk tier: {row['tier'] if row else '?'}). It's on.", style=T.SAFE))

    # --- edit ------------------------------------------------------------
    @work
    async def action_edit_entry(self) -> None:
        row = self._selected_row()
        if row is None or self._target_id is None:
            return
        if row["kind"] == "maintainer":
            self._log(Text("Built-in actions can't be edited -- press a and start from its template to make a "
                           "narrower copy, then turn the built-in off.", style=T.TEXT_DIM))
            return
        if row["template_id"] != "custom":
            template = TPL.get_template(row["template_id"])
            if template is None:
                self._log(Text("Its template no longer exists -- delete it.", style=T.ATTENTION))
                return
            selected = dict(row.get("selected_values") or {})
            for name, slot in template.base.slots.items():
                if slot.kind != "enum" or len(slot.values or ()) < 2:
                    continue
                picked = await self.app.push_screen_wait(MultiSelectModal(
                    f"{row['template_id']}: which {name} values may it use?", [(v, v) for v in slot.values],
                    selected=list(selected.get(name, slot.values))))
                if picked is None:
                    return
                selected[name] = tuple(picked)
            try:
                self._wl_store.update_user_entry(row["entry_id"], selected_values=selected)
            except (ValueError, W.ActionSpecError, C.CeilingError) as e:
                self._log(Text(f"✗ Not saved: {e}", style=T.CRITICAL))
                return
            self._log(Text(f"✓ Updated {row['label']}.", style=T.SAFE))
            self._refresh()
            return
        spec = row["spec"]
        slots = dict(spec.slots)
        for name, slot in spec.slots.items():
            if slot.kind != "enum":
                continue
            drafts = EB.match_shapes(list(spec.argv_template), self._wl_store.target_ceiling(self._target_id))
            pos = [t for t in spec.argv_template].index(f"{{{name}}}")
            var = drafts[0].args[pos - 1] if drafts and isinstance(drafts[0].args[pos - 1], C.Var) else C.Var(slot)
            choices = EB.BlankDraft(name, pos, var).allowed_values()
            picked = await self.app.push_screen_wait(MultiSelectModal(
                f"{{{name}}}: which values may it take?", [(v, v) for v in choices], selected=list(slot.values or ())))
            if picked is None:
                return
            slots[name] = W.Slot(kind="enum", values=tuple(picked))
        texts = await self._ask_texts({"effect": spec.effect, "reversibility": spec.reversibility,
                                       "blast_radius": spec.blast_radius})
        if texts is None:
            return
        try:
            self._wl_store.update_custom_entry(row["entry_id"], slots=slots, **texts)
        except (ValueError, W.ActionSpecError, C.CeilingError) as e:
            self._log(Text(f"✗ Not saved: {e}", style=T.CRITICAL))
            return
        self._log(Text(f"✓ Updated {row['label']}.", style=T.SAFE))
        self._refresh()

"""
The "Add / manage sub-agents" screen (capability 1 -- read-only telemetry).
Reachable via `/subagent` (aliases `/agents`, `/connect`).

This is the real onboarding UX for the design canvas's pairing wizard
(phase2_preview.py::_pairing_wizard) and status chip (_subagent_status),
wired to live data:

- lists paired targets with a real liveness status (subagent.status.derive_status
  over each target's persisted last_seen) + latest telemetry availability;
- "add a server" generates a single-use pairing code + a self-contained
  installer script (subagent.installer.generate_installer) the operator runs
  once on the target, then polls until that target checks in.

It NEVER connects to a target and NEVER takes SSH credentials -- getting the
generated installer onto the target and running it once is the operator's one
bootstrap step (the same unavoidable step every agent-based tool has). Direct
execution (capability 2) is a separate screen (`/whitelist`); nothing here
enables or touches it.
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
from kratos.subagent import deploy_diagnosis as DD
from kratos.subagent import hub_address, installer
from kratos.subagent import status as ST
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, ListPickerModal, PromptModal
from kratos.tui_mk2.table_fit import fit_columns
from kratos.utils import ssh_keys
from kratos.utils.hostnames import is_ip_or_hostname


def _cl_default_bind() -> str:
    from kratos.subagent import core_listener as _cl

    return _cl.DEFAULT_BIND_HOST


def valid_ssh_address(addr: str) -> str | None:
    """None if `addr` is usable as an scp/ssh destination, else why not. A
    leading '-' would be read by ssh as an option (e.g. -oProxyCommand=...)."""
    if not addr:
        return "enter an address"
    if addr.startswith("-"):
        return "an address can't start with '-'"
    if any(c.isspace() for c in addr) or any(c in addr for c in "'\"`$;&|<>"):
        return "an address can't contain spaces or shell characters"
    if addr.endswith("@") or addr.startswith("@"):
        return "use user@host"
    return None


# One line on what "add a server" gives you; same honesty as the onboarding
# choice: no inbound port, read-only (telemetry + its own built-in reads),
# execution off by default.
_ADD_SERVER_SUMMARY = (
    "Installs a small agent on {host} that dials OUT to Kratos, streams telemetry and answers investigations "
    "with its own built-in reads only. No inbound port on your box. Approved fixes are opt-in and OFF by default."
)

_DEFAULT_CORE_PORT = 8765
_TABLE_COLUMNS = ("status", "name", "host", "agent", "last contact", "detail")
# How long `L` waits for the new service to register before calling it failed.
_SERVICE_CONFIRM_SECONDS = 15.0
# After a successful SSH deploy, how long to wait for the check-in before
# explaining how to find out why it hasn't happened.
_CHECKIN_HINT_AFTER_SECONDS = 90.0

# Glyph + colour per assessed state (subagent.status.assess). Every state has
# its own label -- a zombie never reads "connected", and "no listener" never
# reads as the target being down.
_STATE_STYLE = {
    ST.STATE_CONNECTED: ("●", T.SAFE),
    ST.STATE_STALLED: ("◐", T.ATTENTION),
    ST.STATE_UNRESPONSIVE: ("◐", T.CRITICAL),
    ST.STATE_RECONNECTING: ("↻", T.ATTENTION),
    ST.STATE_OFFLINE: ("●", T.CRITICAL),
    ST.STATE_NOT_WATCHED: ("?", T.ATTENTION),
    ST.STATE_NEVER: ("○", T.TEXT_DIM),
    ST.STATE_REVOKED: ("⊘", T.TEXT_DIM),
    ST.STATE_SUPERSEDED: ("◌", T.ATTENTION),
}


class SubAgentScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("a", "add_server", "add a server", show=True),
        Binding("t", "telemetry", "latest telemetry", show=True),
        Binding("i", "details", "details", show=True),
        Binding("u", "unpair", "unpair", show=True),
        Binding("p", "repair", "re-pair", show=False),
        Binding("n", "new_code", "new code", show=False),
        Binding("x", "dismiss_code", "dismiss code", show=False),
        Binding("d", "deploy", "deploy over SSH", show=False),
        Binding("f", "forget", "forget", show=False),
        Binding("c", "copy_commands", "copy deploy cmds", show=True),
        Binding("l", "install_service", "always-on listener", show=True),
        Binding("k", "link_target", "link a target", show=True),
        Binding("g", "update_agent", "update agent", show=False),
        Binding("r", "refresh", "refresh", show=False),
    ]

    CSS = """
    SubAgentScreen { padding: 1 2; }
    SubAgentScreen #sa-banner { height: auto; padding: 0 0 0 0; }
    SubAgentScreen #sa-listener { height: auto; padding: 0 0 1 0; }
    SubAgentScreen DataTable { height: auto; max-height: 14; }
    SubAgentScreen #sa-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    SubAgentScreen #sa-hints { height: auto; padding-top: 1; }
    """

    def __init__(
        self,
        data_dir: Path,
        core_port: int = _DEFAULT_CORE_PORT,
        *,
        auto_add: bool = False,
        default_name: str | None = None,
        link_host: str | None = None,
        offer_link_for: str | None = None,
    ) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._core_port = core_port
        self._sa_store = SubAgentStore(self._data_dir / "kratos.db")
        self._targets: list[dict[str, Any]] = []
        self._states: dict[str, ST.ConnectionState] = {}
        # One entry per table row: {"kind": "target", "target", "state"} or
        # {"kind": "pending", "code": <pairing-code row>} -- the cursor maps
        # through this, never through a positional list of targets.
        self._rows: list[dict[str, Any]] = []
        # Codes started from THIS screen: announce their check-in / expiry once
        # (the table itself always shows every pending code, from the DB).
        self._watched_codes: dict[str, dict[str, Any]] = {}
        # systemd scope / lingering are external process calls -- cached so the
        # 3s auto-refresh doesn't spawn systemctl every tick.
        self._svc_cache: tuple[float, str | None, bool | None] | None = None
        # When opened from onboarding: jump straight into the add-a-server flow
        # with the target's name pre-filled.
        self._auto_add = auto_add
        self._default_name = default_name
        # From onboarding's "Sub-agent" choice: once a server added here checks
        # in, investigations of this target read through it (the user already
        # chose that -- docs/subagent_read_routing.md D3).
        self._link_host = link_host
        # Opened from a session: when a box added here checks in and looks like
        # the session's target, ASK whether to read that target through it.
        self._offer_link_for = offer_link_for
        # Per Kratos address: may investigation reads run over a plain (not
        # loopback/Tailscale) network? Asked once, only for such an address.
        self._allow_untrusted: dict[str, bool] = {}
        # The manual scp+ssh deploy commands for the most-recently-added server,
        # so `c` can pop a click-to-copy box for them (same as the authorize cmd).
        self._last_deploy_commands: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                Text("Sub-agents — boxes Kratos reaches through a small agent (telemetry + investigations)",
                     style=f"bold {T.ACCENT}"),
                id="sa-banner",
            )
            yield Static(id="sa-listener")
            yield DataTable(id="sa-table", cursor_type="row")
            yield VerticalScroll(id="sa-log")
            yield Static(
                Text("a add a server · k link to a target · g update agent · u unpair · p re-pair\n"
                     "t telemetry · i details · c copy deploy commands · l always-on listener\n"
                     "n new pairing code · x dismiss code · f forget unpaired · esc back", style=T.TEXT_DIM),
                id="sa-hints",
            )

    def on_mount(self) -> None:
        table = self.query_one("#sa-table", DataTable)
        table.add_columns(*_TABLE_COLUMNS)
        self._refresh()
        # Make sure a listener is up while this screen is open, so paired targets
        # stream telemetry without a second terminal. Defensive getattr: a bare
        # test host App without this method is simply skipped.
        ensure = getattr(self.app, "ensure_core_listener", None)
        # Also when a server is still waiting to check in with its code: without
        # a listener its installer has nothing to dial.
        if ensure is not None and (self._targets or self._sa_store.list_pending_pairing_codes()):
            ensure()
        # Live status: re-derive connected/stale/unreachable and surface a target
        # that checks in ANY way (this add flow, a reconnect, an out-of-band
        # deploy) without needing a manual refresh.
        self.set_interval(3.0, self._refresh)
        if self._auto_add:
            self.action_add_server()

    # ------------------------------------------------------------------
    def _log(self, renderable: Any) -> None:
        log = self.query_one("#sa-log", VerticalScroll)
        log.mount(Static(renderable))
        log.scroll_end(animate=False)

    def action_refresh(self) -> None:
        self._refresh()

    def _service_facts(self) -> tuple[str | None, bool | None]:
        import time as _time

        from kratos.subagent import core_listener as _cl

        if self._svc_cache is None or _time.monotonic() - self._svc_cache[0] > 30:
            self._svc_cache = (_time.monotonic(), _cl.service_scope(), _cl.linger_enabled())
        return self._svc_cache[1], self._svc_cache[2]

    def _refresh_listener_line(self) -> None:
        from kratos.subagent import core_listener as _cl
        from kratos.utils.build_info import current_disk_build

        listeners = self._sa_store.live_listeners(ST.LISTENER_STALE_AFTER_SECONDS)
        here = getattr(self.app, "core_listener_in_process", lambda: False)()
        scope, linger = self._service_facts() if listeners and listeners[0].get("mode") == "service" else (None, None)
        msg, severity, _offer = _cl.describe_listener(
            listeners, in_process_here=here, disk_build=current_disk_build(), scope=scope, linger=linger)
        color = {"ok": T.SAFE, "attention": T.ATTENTION, "critical": T.CRITICAL}.get(severity, T.TEXT_DIM)
        glyph = {"ok": "●", "attention": "◐", "critical": "○"}.get(severity, "·")
        line = Text(f"{glyph} {msg}", style=color)
        from kratos.utils.build_info import restart_hint

        hint = restart_hint()
        if hint:  # this screen's own code may be older than what's described above
            line.append(f"\n◐ {hint}", style=T.ATTENTION)
        from kratos.subagent.agent import AGENT_VERSION

        outdated = [t.get("name") or t.get("hostname") or t["target_id"]
                    for t in self._sa_store.list_targets(include_revoked=False)
                    if ST.agent_outdated(t.get("agent_version"))]
        if outdated:
            names = ", ".join(outdated[:3]) + (f" and {len(outdated) - 3} more" if len(outdated) > 3 else "")
            line.append(f"\n◐ An agent update ({AGENT_VERSION}) is ready for {names}: select it and press g. "
                        "It keeps its pairing.", style=T.ATTENTION)
        self.query_one("#sa-listener", Static).update(line)

    def _refresh(self) -> None:
        self._refresh_listener_line()
        table = self.query_one("#sa-table", DataTable)
        prev = table.cursor_row  # preserve selection across the rebuild (auto-refresh)
        table.clear()
        now = ST.utc_now()
        assessed = ST.assess_all(self._sa_store, now=now)
        self._targets = [t for t, _ in assessed]
        self._states = {t["target_id"]: st for t, st in assessed}
        names = {t["target_id"]: t.get("name") or t.get("hostname") or t["target_id"] for t in self._targets}
        pending = self._sa_store.list_pending_pairing_codes()
        self._announce_watched(now)

        rank = {"critical": 0, "attention": 1, "ok": 2, "muted": 3}
        ordered = sorted(
            assessed,
            key=lambda ts: (ts[1].state == ST.STATE_REVOKED, rank.get(ts[1].severity, 3),
                            (ts[0].get("name") or ts[0].get("hostname") or "").lower()),
        )
        # Live codes are the thing being set up right now: top. An expired code
        # is a leftover attempt -- below the servers, and gone once a server
        # with that name has paired since (the attempt succeeded another way).
        live_codes, expired = [], []
        for c in pending:
            expires = ST.parse_stored_instant(c.get("expires_at"))
            if expires is not None and expires > now:
                live_codes.append(c)
            elif not any(c.get("name") and t.get("name") == c["name"] and not t.get("revoked_at")
                         and t["target_id"] != c.get("replaces_target_id")
                         and (t.get("paired_at") or "") > (c.get("created_at") or "") for t in self._targets):
                expired.append(c)
        targets = [{"kind": "target", "target": t, "state": st} for t, st in ordered]
        self._rows = ([{"kind": "pending", "code": c} for c in live_codes]
                      + [r for r in targets if r["state"].state != ST.STATE_REVOKED]
                      + [{"kind": "pending", "code": c} for c in expired]
                      + [r for r in targets if r["state"].state == ST.STATE_REVOKED])
        if not self._rows:
            table.add_row(Text("— no paired targets yet — press a to add a server —", style=T.TEXT_DIM),
                          "", "", "", "", "")
            return
        cells: list[list] = []
        for row in self._rows:
            if row["kind"] == "pending":
                cells.append(list(_pending_cells(row["code"], now, names)))
                continue
            t, st = row["target"], row["state"]
            glyph, color = _STATE_STYLE.get(st.state, ("○", T.TEXT_DIM))
            dim = st.state == ST.STATE_REVOKED
            cells.append([
                Text(f"{glyph} {st.label}", style=color),
                Text(t.get("name") or "—", style=T.TEXT_DIM if dim else ""),
                Text(t.get("hostname") or "—", style=T.TEXT_DIM if dim else ""),
                (Text(f"{t.get('agent_version')} → g", style=T.ATTENTION)
                 if not dim and ST.agent_outdated(t.get("agent_version"))
                 else Text(t.get("agent_version") or "—", style=T.TEXT_DIM if dim else "")),
                Text(ST.human_age(ST._age(st.last_contact, now)) if st.last_contact else "never", style=T.TEXT_DIM),
                Text(st.reason, style=T.TEXT_DIM),
            ])
        # Keep every column on screen: shorten the detail first (the full text
        # is under i), then long names/hosts.
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(5, 12), (1, 8), (2, 8)], headers=_TABLE_COLUMNS):
            table.add_row(*row)
        if prev is not None and 0 <= prev < len(self._rows):
            try:
                table.move_cursor(row=prev)
            except Exception:  # noqa: BLE001 -- cursor restore is best-effort
                pass

    def _announce_watched(self, now) -> None:
        """Say once when a code started here is used (paired) or runs out --
        whether or not the add flow is still on screen (WS7: the refresh owns
        liveness; there is no separate blocking wait)."""
        for code, ctx in list(self._watched_codes.items()):
            row = self._sa_store.get_pairing_code(code)
            label = ctx.get("name") or "the new server"
            if row is None:
                self._watched_codes.pop(code)
                continue
            if row.get("used_by_target_id"):
                self._watched_codes.pop(code)
                t = self._sa_store.get_target(row["used_by_target_id"]) or {}
                replaced = " It replaced the previous pairing." if row.get("replaces_target_id") else ""
                self._log(Text(f"✓ {label} paired ({t.get('hostname') or '?'}, agent {t.get('agent_version') or '?'})"
                               f" -- telemetry is live.{replaced} It is recommend-only; turn on direct execution "
                               "from /whitelist only if you want it.", style=f"bold {T.SAFE}"))
                self._link_new_agent(row["used_by_target_id"])
                if not self._link_host and self._offer_link_for:
                    self._offer_link_after_checkin(self._offer_link_for)
                continue
            expires = ST.parse_stored_instant(row["expires_at"])
            if expires is not None and expires < now:
                self._watched_codes.pop(code)
                tried = (f" {row['last_attempt_host']} tried to pair with it after it expired."
                         if row.get("last_attempt_host") else "")
                self._log(Text(f"The pairing code for {label} expired unused.{tried} Select its row and press n "
                               "for a fresh code (the installer is regenerated to match).", style=T.ATTENTION))
                continue
            deployed = ctx.get("deployed_at")
            if deployed and not ctx.get("hinted") and (now.timestamp() - deployed) > _CHECKIN_HINT_AFTER_SECONDS:
                ctx["hinted"] = True
                self._checkin_help(label, ctx)

    def _checkin_help(self, label: str, ctx: dict[str, Any]) -> None:
        """The installer ran but nothing checked in: the box can't reach this
        core, or the agent failed to start. Say how to tell which."""
        host = ctx.get("host") or "<core-address>"
        cmd = (f"sudo journalctl -u kratos-subagent -n 30 --no-pager; "
               f"python3 -c \"import socket; socket.create_connection(('{host}', {self._core_port}), 5); "
               f"print('this box CAN reach Kratos at {host}:{self._core_port}')\"")
        self._log(Text(f"{label}'s installer ran, but it hasn't checked in yet. Either the box can't reach this "
                       f"core at {host}:{self._core_port} (firewall / tailnet / wrong address), or the agent failed "
                       "to start. Run the command in the box ON the target to tell which.", style=T.ATTENTION))
        self.app.push_screen(CommandModal(cmd, title="Why hasn't it checked in?",
                                          note="Run ON the target: shows the agent's own log, then tests the path back "
                                               "to this core."))

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    def _selected_row(self) -> dict[str, Any] | None:
        if not self._rows:
            return None
        row = self.query_one("#sa-table", DataTable).cursor_row
        if row is None or row < 0 or row >= len(self._rows):
            return None
        return self._rows[row]

    def _selected_target(self) -> dict[str, Any] | None:
        row = self._selected_row()
        return row["target"] if row and row["kind"] == "target" else None

    def action_telemetry(self) -> None:
        target = self._selected_target()
        if target is None:
            self._log(Text("Select a paired target first.", style=T.TEXT_DIM))
            return
        latest = self._sa_store.get_latest_telemetry(target["target_id"])
        if latest is None:
            self._log(Text(f"No telemetry received from {target.get('name') or target['target_id']} yet.", style=T.TEXT_DIM))
            return
        self._log(Text(f"Latest telemetry from {target.get('name') or target['hostname'] or target['target_id']}:", style=f"bold {T.ACCENT}"))
        self._log(_telemetry_table(latest))

    # ------------------------------------------------------------------
    @work
    async def action_add_server(self) -> None:
        """Add a server: name (with a duplicate guard) → hub address → code →
        installer → optional SSH deploy. Never blocks waiting for the check-in:
        the code's row shows the countdown and the refresh announces the
        result, even if you leave this screen and come back."""
        self._log(Text(_ADD_SERVER_SUMMARY.format(host=self._default_name or "the box"), style=T.TEXT_MUTED))
        name = await self.app.push_screen_wait(
            PromptModal(
                "Add a server",
                hint=_ADD_SERVER_SUMMARY.format(host=self._default_name or "the box")
                     + "\n\nA short label for it (e.g. web-01). Enter to skip.",
                initial=self._default_name or "",
            )
        )
        if name is None:
            return  # cancelled
        name = (name or "").strip() or None
        replaces = None
        if name:
            decision = await self._resolve_duplicate_name(name)
            if decision is None:
                return
            name, replaces = decision
        await self._start_pairing(name, replaces_target_id=replaces)

    async def _resolve_duplicate_name(self, name: str) -> tuple[str, str | None] | None:
        """(name, replaces_target_id) -- or None to stop. Two servers with one
        name make every later choice ambiguous, so ask instead of guessing."""
        existing = [t for t in self._sa_store.list_targets(include_revoked=False)
                    if (t.get("name") or "").lower() == name.lower()]
        waiting = [c for c in self._sa_store.list_pending_pairing_codes(include_expired_since_seconds=0)
                   if (c.get("name") or "").lower() == name.lower()]
        if not existing and not waiting:
            return name, None
        free = _free_name(name, {(t.get("name") or "").lower() for t in self._sa_store.list_targets()}
                          | {(c.get("name") or "").lower() for c in waiting})
        entries: list[tuple[str, str]] = []
        if existing:
            entries.append(("repair", f"Re-pair “{name}” — the old pairing is replaced once the new agent checks in"))
        if waiting:
            entries.append(("reuse", f"Use the code that's already waiting for “{name}” ({waiting[0]['code']})"))
        entries.append(("second", f"Add a different server named “{free}”"))
        what = "is already paired" if existing else "already has a pairing code waiting"
        picked = await self.app.push_screen_wait(ListPickerModal(f"“{name}” {what}", entries))
        if picked == "repair":
            return name, existing[0]["target_id"]
        if picked == "second":
            return free, None
        if picked == "reuse":
            code = waiting[0]
            self._watched_codes.setdefault(code["code"], {"name": name, "host": code.get("core_host")})
            self._log(Text(f"Code {code['code']} for {name} is still valid — use its installer, or press n on its "
                           "row for a fresh one.", style=T.TEXT_MUTED))
            self._announce_listener()  # it can only check in if something is listening
        return None

    def _warn_if_listener_not_on(self, host: str) -> None:
        """The always-on listener may listen only on the addresses machines
        dialed when it was installed; a new address needs it updated (L)."""
        from kratos.subagent import core_listener as _cl

        bound = _cl.installed_bind_hosts(_cl.service_scope())
        if bound is not None and not _cl.bind_covers(bound, host):
            self._log(Text(
                f"⚠ The always-on listener only listens on {', '.join(bound)}, not {host} -- this machine can't "
                "check in until you press L to update it.", style=f"bold {T.ATTENTION}"))

    async def _start_pairing(self, name: str | None, *, replaces_target_id: str | None = None,
                             host: str | None = None) -> None:
        host = host or await self._pick_hub_address()
        if host is None:
            return
        if await self._ask_plain_network(host) is None:
            return
        result = self._sa_store.create_pairing_code(name=name, replaces_target_id=replaces_target_id, core_host=host)
        code = result["code"]
        out_path = self._write_installer(name, host, code)
        if out_path is None:
            self._sa_store.cancel_pairing_code(code)
            return
        self._watched_codes[code] = {"name": name, "host": host, "out_path": str(out_path)}
        # Make sure a listener is accepting connections, so the target can
        # actually check in -- no second terminal needed.
        self._announce_listener()
        self._warn_if_listener_not_on(host)
        self._render_pairing_instructions(name, host, code, result["ttl_seconds"] // 60, out_path)
        # Offer to copy+run the installer on the target over SSH (one keypress
        # instead of manual scp/ssh). Falls back cleanly to the manual steps.
        await self._offer_ssh_deploy(out_path, name, code)
        self._log(Text(f"Waiting for {name or 'the target'} to dial back — this can take a few seconds after the "
                       "installer runs. Its row above counts down; you can leave this screen, the result shows up "
                       "either way.", style=T.ATTENTION))
        self._refresh()

    def _write_installer(self, name: str | None, host: str, code: str) -> Path | None:
        try:
            script = installer.generate_installer(host, code, core_port=self._core_port,
                                                  allow_untrusted_transport=self._allow_untrusted.get(host, False))
        except installer.InstallerError as exc:
            self._log(Text(f"Could not generate installer: {exc}", style=T.CRITICAL))
            return None
        slug = _slug(name) or code.replace("-", "").lower()
        out_path = self._data_dir / f"kratos-subagent-install-{slug}.sh"
        try:
            out_path.write_text(script, encoding="utf-8")
            out_path.chmod(0o600)  # carries a live pairing code
        except OSError as exc:
            self._log(Text(f"Could not write installer to {out_path}: {exc}", style=T.CRITICAL))
            return None
        return out_path

    # --- lifecycle actions on the selected row ---------------------------
    @work
    async def action_new_code(self) -> None:
        row = self._selected_row()
        if row is None or row["kind"] != "pending":
            self._log(Text("Select a pairing-code row (waiting or code expired) to make a fresh code for it.", style=T.TEXT_DIM))
            return
        old = row["code"]
        self._sa_store.cancel_pairing_code(old["code"])
        self._watched_codes.pop(old["code"], None)
        self._log(Text(f"Old code {old['code']} cancelled; making a fresh one for {old.get('name') or 'this server'}.",
                       style=T.TEXT_MUTED))
        await self._start_pairing(old.get("name"), replaces_target_id=old.get("replaces_target_id"),
                                  host=old.get("core_host"))

    @work
    async def action_deploy(self) -> None:
        """(Re)deploy the selected waiting code's installer over SSH -- the retry
        after fixing whatever the last deploy attempt said was wrong."""
        row = self._selected_row()
        if row is None or row["kind"] != "pending":
            self._log(Text("Select a waiting pairing-code row to deploy its installer.", style=T.TEXT_DIM))
            return
        c = row["code"]
        expires = ST.parse_stored_instant(c.get("expires_at"))
        if expires is None or expires <= ST.utc_now():
            self._log(Text("That code has expired — press n on its row for a fresh one.", style=T.ATTENTION))
            return
        host = c.get("core_host")
        if not host:
            self._log(Text("This code was made without a Kratos address — press n on its row for a fresh one.",
                           style=T.ATTENTION))
            return
        out = self._write_installer(c.get("name"), host, c["code"])
        if out is None:
            return
        watched = self._watched_codes.setdefault(c["code"], {"name": c.get("name"), "host": host})
        watched["out_path"] = str(out)
        self._last_deploy_commands = self._deploy_commands(out, watched.get("ssh_addr") or "<user@target>")
        await self._offer_ssh_deploy(out, c.get("name"), c["code"])
        self._refresh()

    def action_dismiss_code(self) -> None:
        row = self._selected_row()
        if row is None or row["kind"] != "pending":
            self._log(Text("Select a pairing-code row (waiting or code expired) to dismiss it.", style=T.TEXT_DIM))
            return
        self._sa_store.cancel_pairing_code(row["code"]["code"])
        self._watched_codes.pop(row["code"]["code"], None)
        self._log(Text(f"Pairing code {row['code']['code']} dismissed — it can no longer be used.", style=T.TEXT_MUTED))
        self._refresh()

    @work
    async def action_repair(self) -> None:
        t = self._selected_target()
        if t is None or t.get("revoked_at"):
            self._log(Text("Select a paired (not unpaired) server to re-pair it.", style=T.TEXT_DIM))
            return
        label = t.get("name") or t.get("hostname") or t["target_id"]
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Re-pair {label}?",
            "Makes a new pairing code and installer. Run that installer on the box: it starts a fresh identity, and "
            "the current pairing is replaced the moment the new one checks in (until then, nothing changes). Use this "
            "when the box lost its identity, was rebuilt, or its agent should be reinstalled cleanly."))
        if ok:
            await self._start_pairing(t.get("name") or t.get("hostname"), replaces_target_id=t["target_id"])

    @work
    async def action_unpair(self) -> None:
        t = self._selected_target()
        if t is None or t.get("revoked_at"):
            self._log(Text("Select a paired server to unpair it.", style=T.TEXT_DIM))
            return
        label = t.get("name") or t.get("hostname") or t["target_id"]
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Unpair {label}?",
            "Kratos stops accepting this server: a live connection is dropped within seconds and it can no longer "
            "send telemetry. This does NOT stop or remove the agent on the box — you'll get the command for that "
            "next. You can pair it again later."))
        if not ok:
            self._log(Text(f"{label} left paired.", style=T.TEXT_DIM))
            return
        self._sa_store.revoke_target(t["target_id"])
        self._log(Text(f"{label} unpaired. Its row stays (dimmed) until you forget it with f.", style=T.TEXT_MUTED))
        self._refresh()
        self.app.push_screen(CommandModal(
            installer.uninstall_command(), title=f"Stop and remove the agent on {label}",
            note="Run this ON the server (it works however the agent was installed). Until then the agent keeps "
                 "trying to connect, and Kratos keeps refusing it."))

    @work
    async def action_forget(self) -> None:
        t = self._selected_target()
        if t is None or not t.get("revoked_at"):
            self._log(Text("Only an unpaired server can be forgotten — unpair it first (u).", style=T.TEXT_DIM))
            return
        label = t.get("name") or t.get("hostname") or t["target_id"]
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Forget {label}?", "Deletes this unpaired server and its stored telemetry and connection history from "
            "Kratos. This can't be undone."))
        if ok and self._sa_store.forget_target(t["target_id"]):
            self._log(Text(f"{label} forgotten.", style=T.TEXT_MUTED))
            self._refresh()

    def action_details(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        if row["kind"] == "pending":
            c = row["code"]
            body = Table(show_header=False, box=None)
            body.add_column(style=T.TEXT_DIM)
            body.add_column()
            for k in ("code", "name", "core_host", "created_at", "expires_at", "last_attempt_at", "last_attempt_host",
                      "last_attempt_reason"):
                if c.get(k):
                    body.add_row(k, str(c[k]))
            self._log(Text("Pairing code:", style=f"bold {T.ACCENT}"))
            self._log(body)
            return
        t, st = row["target"], row["state"]
        conn = self._sa_store.get_connection(t["target_id"]) or {}
        body = Table(show_header=False, box=None)
        body.add_column(style=T.TEXT_DIM)
        body.add_column()
        body.add_row("state", f"{st.label} — {st.reason}")
        for k in ("target_id", "hostname", "agent_version", "paired_at", "last_seen", "revoked_at"):
            if t.get(k):
                body.add_row(k, str(t[k]))
        for k in ("peer", "connected_at", "disconnected_at", "disconnect_reason", "last_telemetry_at",
                  "collect_interval"):
            if conn.get(k) is not None:
                body.add_row(k, str(conn[k]))
        links = [ln for ln in self._sa_store.list_links() if ln["target_id"] == t["target_id"]]
        from kratos.subagent import routing as _routing

        body.add_row("investigated as", ", ".join(f"{ln['host']} ({_routing.MODE_LABELS.get(ln['mode'], ln['mode'])})"
                                                for ln in links) or "— not linked to a target (press k) —")
        self._log(Text(f"{t.get('name') or t['target_id']}:", style=f"bold {T.ACCENT}"))
        self._log(body)
        events = self._sa_store.recent_events(t["target_id"], 24 * 3600)[-10:]
        if events:
            hist = Table(show_header=True, box=None, header_style=T.TEXT_DIM)
            hist.add_column("when")
            hist.add_column("event")
            hist.add_column("detail")
            for e in events:
                hist.add_row(ST.human_age(ST._age(e["at"], ST.utc_now())), e["event"], e.get("detail") or "")
            self._log(hist)

    @work(group="offer-link")
    async def _offer_link_after_checkin(self, host: str) -> None:
        from kratos.tui_mk2 import target_link as TL

        mode = await TL.offer_link(self.app, self._data_dir, host)
        if mode:
            self._log(Text(f"Investigations of {host} now go through this sub-agent "
                           f"({mode.replace('_', ' ')}). /target link changes it later.", style=T.TEXT_MUTED))

    def _link_new_agent(self, target_id: str) -> None:
        if not self._link_host:
            return
        from kratos.subagent import routing as _routing
        from kratos.tui_mk2 import target_link as TL

        if TL.current_link(self._data_dir, self._link_host) is not None:
            return
        try:
            self._log(TL.apply_link(self._data_dir, self._link_host, target_id, _routing.MODE_SUBAGENT))
            self._log(Text(f"Investigations of {self._link_host} now go through this sub-agent. Esc to go back and "
                           "continue; /target link changes it later.", style=T.TEXT_MUTED))
        except ValueError as e:
            self._log(Text(f"Couldn't link {self._link_host}: {e}", style=T.ATTENTION))

    @work
    async def action_link_target(self) -> None:
        """Link a session target (an IP/hostname you investigate) to the
        selected paired box, so investigations read through its sub-agent."""
        from kratos import kratos_config as _kc
        from kratos.tui_mk2 import target_link as TL

        target = self._selected_target()
        if target is None or target.get("revoked_at"):
            self._log(Text("Select a paired server first.", style=T.TEXT_DIM))
            return
        host = await self.app.push_screen_wait(PromptModal(
            f"Which target is {TL.agent_label(target)}?",
            "The IP or hostname you investigate this box as (it must really be this machine)",
            initial=_kc.get_active_target() or target.get("name") or "",
        ))
        if not host or not host.strip():
            return
        mode = await TL.ask_mode(self.app, host.strip(), target)
        if mode is None:
            return
        try:
            self._log(TL.apply_link(self._data_dir, host.strip(), target["target_id"], mode))
        except ValueError as e:
            self._log(Text(f"Couldn't link: {e}", style=T.ATTENTION))

    def _announce_listener(self) -> None:
        ensure = getattr(self.app, "ensure_core_listener", None)
        status = ensure() if ensure else None
        if status == "in_process":
            self._log(Text(
                "Listener is running inside Kratos for now (this session). For always-on monitoring "
                "after you close Kratos, press 'L' to install it as a service.",
                style=T.TEXT_MUTED,
            ))
        elif status == "external":
            self._log(Text("Listener is already running (service) — good.", style=T.TEXT_DIM))
        elif status == "unavailable" or status is None:
            # Couldn't auto-start (or unknown app) -- show the manual command.
            self._log(Text(
                "⚠ No listener is running. Start one (in a terminal) so the target can check in:\n"
                f"    kratos subagent-serve --host {_cl_default_bind()}",
                style=T.ATTENTION,
            ))

    async def _ask_plain_network(self, host: str) -> bool | None:
        """Over a plain network (not loopback or Tailscale) the agent refuses
        investigation reads unless allowed at install time: the channel has no
        encryption of its own, and reads carry log lines and process lists.
        Returns the choice (False when no question was needed), None to stop."""
        if host in self._allow_untrusted:
            return self._allow_untrusted[host]
        if await asyncio.to_thread(hub_address.is_trusted_transport_address, host):
            self._allow_untrusted[host] = False
            return False
        picked = await self.app.push_screen_wait(ListPickerModal(
            f"{host} isn't a Tailscale address",
            [
                ("off", "Telemetry only on this network — use Tailscale for investigations (safer)"),
                ("on", "Also allow investigations — this network is mine and trusted"),
            ],
            subtitle="The link between the box and Kratos has no encryption of its own. Telemetry flows either way; "
                     "investigation reads send log lines and process lists, so the agent refuses them on a plain "
                     "network unless you allow it here. Direct execution is unaffected (still off).",
        ))
        if picked is None:
            return None
        self._allow_untrusted[host] = picked == "on"
        return self._allow_untrusted[host]

    @work
    async def action_update_agent(self) -> None:
        """Update the selected box's agent in place: same pairing, new code
        (e.g. so it can answer investigations). Generates the upgrade
        installer and offers to run it over SSH, like adding a server."""
        target = self._selected_target()
        if target is None or target.get("revoked_at"):
            self._log(Text("Select a paired server to update.", style=T.TEXT_DIM))
            return
        from kratos.subagent.agent import AGENT_VERSION

        label = target.get("name") or target.get("hostname") or target["target_id"]
        host = self._sa_store.core_host_for_target(target["target_id"]) or await self._pick_hub_address()
        if not host:
            return
        allow = await self._ask_plain_network(host)
        if allow is None:
            return
        try:
            script = installer.generate_installer(host, None, core_port=self._core_port, upgrade=True,
                                                  allow_untrusted_transport=allow)
        except installer.InstallerError as exc:
            self._log(Text(f"Could not generate the update: {exc}", style=T.CRITICAL))
            return
        out_path = self._data_dir / f"kratos-subagent-upgrade-{_slug(label) or 'server'}.sh"
        try:
            out_path.write_text(script, encoding="utf-8")
            out_path.chmod(0o600)
        except OSError as exc:
            self._log(Text(f"Could not write {out_path}: {exc}", style=T.CRITICAL))
            return
        self._last_deploy_commands = self._deploy_commands(out_path)
        self._log(Text(
            f"Update for {label}: agent {target.get('agent_version') or '?'} → {AGENT_VERSION}, same pairing, "
            f"execution stays off. Saved {out_path.name}. Run it ON the box (c copies the commands), or deploy "
            "it over SSH next.", style=T.TEXT_MUTED))
        await self._offer_ssh_deploy(out_path, label, upgrade=True)

    async def _offer_ssh_deploy(self, out_path: Path, name: str | None, code: str | None = None,
                                upgrade: bool = False) -> None:
        deploy = await self.app.push_screen_wait(ConfirmModal(
            "Deploy over SSH now?",
            "Copy the installer to the target and run it over SSH for you? "
            "You'll confirm the target's SSH address next. (Or do it yourself with the commands above.)",
        ))
        if not deploy:
            return
        from kratos import kratos_config as _kc

        # Default to the login user Kratos is configured to SSH as (the same one
        # the investigation tools use), never a guessed root.
        previous = (self._watched_codes.get(code) or {}).get("ssh_addr") if code else None
        initial = previous or (f"{_kc.ssh_user_for(self._default_name)}@{self._default_name}" if self._default_name else "")
        while True:
            ssh_addr = await self.app.push_screen_wait(PromptModal(
                "Target SSH address",
                hint="user@host to deploy to (e.g. ubuntu@203.0.113.5). Needs key-based SSH access.",
                initial=initial,
            ))
            ssh_addr = (ssh_addr or "").strip()
            if not ssh_addr:
                return
            problem = valid_ssh_address(ssh_addr)
            if problem is None:
                break
            self._log(Text(f"Not a usable SSH address ({problem}).", style=T.ATTENTION))
            initial = ssh_addr
        if code and code in self._watched_codes:
            self._watched_codes[code]["ssh_addr"] = ssh_addr
        if code and not self._code_usable(code):
            # The operator can sit on these prompts past the 15-minute TTL.
            self._log(Text("That pairing code expired while you were setting this up — select its row and press n "
                           "for a fresh one.", style=T.ATTENTION))
            return
        if code:
            plan = await self._existing_agent_plan(ssh_addr, code, name)
            if plan is None:
                self._log(Text("Deploy cancelled — nothing was changed on the target.", style=T.TEXT_MUTED))
                return
            if plan == "upgrade":
                upgraded = self._write_upgrade_installer(name, code)
                if upgraded is None:
                    return
                # Nothing will redeem this code now; don't leave it looking pending.
                self._sa_store.cancel_pairing_code(code)
                self._watched_codes.pop(code, None)
                out_path, code, upgrade = upgraded, None, True
        # Now that we know the real target address, make `c` copy the concrete
        # commands (with the address filled in) instead of the placeholder.
        self._last_deploy_commands = self._deploy_commands(out_path, ssh_addr)
        self._log(Text(f"Deploying to {ssh_addr} over SSH…", style=T.ATTENTION))
        self._ssh_deploy_worker(str(out_path), ssh_addr, code, upgrade=upgrade)

    def _code_usable(self, code: str) -> bool:
        row = self._sa_store.get_pairing_code(code)
        if row is None or row.get("used_at"):
            return False
        expires = ST.parse_stored_instant(row.get("expires_at"))
        return expires is not None and expires > ST.utc_now()

    async def _existing_agent_plan(self, ssh_addr: str, code: str, name: str | None) -> str | None:
        """'pair' (go ahead), 'upgrade' (keep the box's current pairing, only
        update its agent), or None (cancel). Asks only when the box already runs
        a Kratos agent and this code isn't an intentional re-pair."""
        row = self._sa_store.get_pairing_code(code) or {}
        if row.get("replaces_target_id"):
            return "pair"  # re-pair was chosen on purpose; the installer moves the old identity aside
        found = await asyncio.to_thread(self._probe_existing_agent, ssh_addr)
        if not found:
            return "pair"  # none, or the probe itself failed (the deploy will explain that)
        label = name or "this server"
        choice = await self.app.push_screen_wait(ListPickerModal(
            f"{ssh_addr} already runs a Kratos agent",
            [
                ("upgrade", "Keep its current pairing — just update the agent (no new server row)"),
                ("pair", f"Pair it again as {label} — its old pairing stops receiving data (unpair that row after)"),
                ("cancel", "Cancel — change nothing on the box"),
            ],
            subtitle=f"Found {found}. Updating keeps its history in one row; pairing again starts a new one.",
        ))
        if choice == "upgrade":
            return "upgrade"
        return "pair" if choice == "pair" else None

    def _probe_existing_agent(self, ssh_addr: str) -> str | None:
        """Where an existing agent's state file is on the box, or None (also on
        any SSH failure -- the deploy that follows reports that properly).
        Only checks that the file exists; never reads it (it holds a token)."""
        import subprocess

        script = ('for f in /opt/kratos-subagent/state.json "$HOME/.kratos-subagent/state.json"; do '
                  '[ -e "$f" ] && echo "$f"; done; true')
        try:
            proc = subprocess.run(["ssh", *self._ssh_options(), "--", ssh_addr, script], capture_output=True,
                                  text=True, timeout=30, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return None
        found = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip().endswith("state.json")]
        return " and ".join(found) if proc.returncode == 0 and found else None

    def _write_upgrade_installer(self, name: str | None, code: str) -> Path | None:
        row = self._sa_store.get_pairing_code(code) or {}
        host = row.get("core_host") or (self._watched_codes.get(code) or {}).get("host")
        if not host:
            self._log(Text("Can't build the upgrade: this code has no Kratos address.", style=T.CRITICAL))
            return None
        try:
            script = installer.generate_installer(host, None, core_port=self._core_port, upgrade=True,
                                                  allow_untrusted_transport=self._allow_untrusted.get(host, False))
        except installer.InstallerError as exc:
            self._log(Text(f"Could not generate the upgrade installer: {exc}", style=T.CRITICAL))
            return None
        out_path = self._data_dir / f"kratos-subagent-upgrade-{_slug(name) or 'server'}.sh"
        try:
            out_path.write_text(script, encoding="utf-8")
            out_path.chmod(0o600)
        except OSError as exc:
            self._log(Text(f"Could not write {out_path}: {exc}", style=T.CRITICAL))
            return None
        self._log(Text(f"Upgrading in place: the pairing code was cancelled and {out_path.name} keeps the box's "
                       "current identity.", style=T.TEXT_MUTED))
        return out_path

    @staticmethod
    def _ssh_options() -> list[str]:
        from kratos import kratos_config as _kc

        opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
        # Present exactly Kratos's configured key -- the one whose public half a
        # failure tells the user to authorize. IdentitiesOnly stops ssh offering
        # every key in the agent first and hitting "Too many authentication
        # failures" before it ever tries this one.
        if Path(_kc.SSH_TARGET_KEY_PATH).exists():
            opts += ["-o", "IdentitiesOnly=yes", "-i", str(_kc.SSH_TARGET_KEY_PATH)]
        return opts

    @work(thread=True)
    def _ssh_deploy_worker(self, script_path: str, ssh_addr: str, code: str | None = None, *,
                           upgrade: bool = False) -> None:
        import shlex
        import subprocess

        basename = Path(script_path).name
        ssh_opts = self._ssh_options()
        stage = "copy"
        try:
            scp = subprocess.run(
                ["scp", *ssh_opts, "--", script_path, f"{ssh_addr}:{basename}"],
                capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL,
            )
            if scp.returncode != 0:
                self._deploy_failed(ssh_addr, (scp.stderr or scp.stdout).strip())
                return
            stage = "install"
            # The installer holds a pairing code: remove it once it ran cleanly
            # (kept on failure so the operator can re-run it by hand).
            q = shlex.quote(basename)
            run = subprocess.run(
                ["ssh", *ssh_opts, "--", ssh_addr, f"sh {q} && rm -f {q}"],
                capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL,
            )
            if run.returncode != 0:
                self._deploy_failed(ssh_addr, "\n".join(x for x in (run.stderr, run.stdout) if x).strip())
                return
            row = self._sa_store.get_pairing_code(code) if code else None
            if upgrade:
                waiting = " Its agent restarted on the new code and reconnects as its existing row."
            else:
                waiting = "" if (row is not None and row.get("used_at")) else " Waiting for it to check in…"
            self.app.call_from_thread(self._log, Text(f"✓ Installer ran on {ssh_addr}.{waiting}",
                                                      style=f"bold {T.SAFE}"))
            warning = DD.install_warning(run.stdout)
            if warning is not None:
                self.app.call_from_thread(self._show_diagnosis, warning, ssh_addr, T.ATTENTION)
            if code and code in self._watched_codes:
                import time as _time

                self._watched_codes[code]["deployed_at"] = _time.time()
        except subprocess.TimeoutExpired:
            what = "copying the installer" if stage == "copy" else "running the installer"
            self._deploy_failed(ssh_addr, "", timed_out=what)
        except (OSError, subprocess.SubprocessError) as exc:
            self._deploy_failed(ssh_addr, str(exc))

    def _deploy_failed(self, ssh_addr: str, detail: str, *, timed_out: str | None = None) -> None:
        if timed_out:
            diag = DD.Diagnosis(
                "deploy_timeout", f"{ssh_addr} stopped responding while {timed_out}.",
                "The connection may have dropped, or the target is very slow. Check it by hand, then retry "
                "(press c for the commands).")
        else:
            diag = DD.diagnose(detail, ssh_addr=ssh_addr, authorize_command=ssh_keys.authorize_key_command())
        self.app.call_from_thread(self._show_diagnosis, diag, ssh_addr, T.CRITICAL, detail)

    def _show_diagnosis(self, diag: DD.Diagnosis, ssh_addr: str, style: str, raw: str = "") -> None:
        """Say what went wrong and what to do; pop a copy-safe box for the fix
        command (pasting a wrapped command by hand broke a real deploy)."""
        lines = [diag.summary, diag.next_step]
        if diag.kind == "no_local_key":
            lines.append("Onboarding a target (/target) can create it for you, or run: "
                         f"ssh-keygen -t ed25519 -N '' -f {ssh_keys._key_path()}")
        if diag.retry:
            lines.append("Then select its waiting row and press d to deploy again (n if the code has expired).")
        self._log(Text("\n".join(lines), style=style))
        if raw and diag.kind != "unknown":
            self._log(Text(raw if len(raw) < 600 else raw[-600:], style=T.TEXT_DIM))
        if diag.command:
            where = "ON the target" if diag.run_on == DD.ON_TARGET else "on THIS machine (where Kratos runs)"
            self.app.push_screen(CommandModal(diag.command, title=f"Run this {where}", note=diag.next_step))

    # ------------------------------------------------------------------
    @work
    async def action_install_service(self) -> None:
        """Install (or restart) the always-on listener so telemetry keeps
        arriving after Kratos is closed. Says exactly what it will do first:
        a system service with passwordless sudo, else a user service -- and
        whether that user service will survive logout/boot (lingering)."""
        from kratos.subagent import core_listener as _cl

        scope_now = _cl.service_scope()
        linger = _cl.linger_enabled()
        user_mode, explanation = _cl.service_plan(
            passwordless_sudo=_cl.passwordless_sudo_available(), linger=linger, scope_now=scope_now)
        # Listen only where paired machines dial, when that's known and on this
        # machine; otherwise on all interfaces (review v2 F-10).
        want = _cl.recommended_bind_hosts(self._sa_store.dial_addresses())
        have = _cl.installed_bind_hosts(scope_now)
        rewrite = scope_now is None or have != want
        where = ("all network interfaces (some machine dials an address Kratos can't pin to this computer)"
                 if want == [_cl.DEFAULT_BIND_HOST] else ", ".join(want) + " -- only the addresses your machines dial")
        if scope_now and rewrite:
            explanation += (f"\n\nIt currently listens on {', '.join(have or ['an unknown address'])}; this "
                            f"updates it to listen on {where}.")
        else:
            explanation += f"\n\nIt listens on {where}."
        title = ("Update the always-on listener?" if scope_now and rewrite else
                 "Restart the always-on listener?" if scope_now else "Install the always-on listener?")
        ok = await self.app.push_screen_wait(ConfirmModal(title, explanation + "\n\nPress y to go ahead."))
        if not rewrite:
            cmds = _cl.core_service_restart_commands(user_mode=user_mode)
        else:
            cmds = _cl.core_service_install_commands(self._data_dir, port=self._core_port, bind_host=want,
                                                     user_mode=user_mode)
            if scope_now:  # `enable --now` doesn't restart a service that's already running
                cmds += _cl.core_service_restart_commands(user_mode=user_mode)[1:]
        if not ok:
            self._log(Text("Nothing changed. To do it yourself later, run:\n" + "\n".join(cmds), style=T.TEXT_MUTED))
            return
        # The in-process listener holds the port; hand it over, or the service
        # restart-loops unable to bind until this window closes.
        stopped_here = getattr(self.app, "stop_core_listener", lambda: False)()
        self._log(Text(f"{'Restarting' if scope_now else 'Installing'} the always-on listener "
                       f"({'user' if user_mode else 'system'} service)…", style=T.ATTENTION))
        self._install_service_worker(cmds, user_mode, linger is False, stopped_here)

    @work(thread=True)
    def _install_service_worker(self, cmds: list[str], user_mode: bool, enable_linger: bool,
                                stopped_here: bool) -> None:
        import subprocess
        import time as _time

        from kratos.subagent import core_listener as _cl

        started = _time.time()
        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                self._service_install_failed(cmds, str(exc), stopped_here)
                return
            if proc.returncode != 0:
                self._service_install_failed(cmds, (proc.stderr or proc.stdout).strip(), stopped_here)
                return
        if user_mode and enable_linger:
            self._try_enable_linger()
        # Real confirmation: a SERVICE listener registered after we started.
        for _ in range(int(_SERVICE_CONFIRM_SECONDS / 0.5)):
            _time.sleep(0.5)
            fresh = [lst for lst in self._sa_store.live_listeners(ST.LISTENER_STALE_AFTER_SECONDS)
                     if lst.get("mode") == "service" and (lst.get("started_at") or "") >= _iso(started - 1)]
            if fresh:
                self._svc_cache = None
                self.app.call_from_thread(self._log, Text(
                    f"✓ Always-on listener running (pid {fresh[0].get('pid')}). Telemetry keeps arriving after "
                    "you close Kratos; connected servers reconnect to it within a minute.", style=f"bold {T.SAFE}"))
                self.app.call_from_thread(self._refresh)
                return
        self._service_install_failed(
            cmds, "the commands ran, but no service listener checked in within 15s "
            f"(see `systemctl {'--user ' if user_mode else ''}status {_cl.CORE_SERVICE_NAME}`)".replace(
                "15s", f"{int(_SERVICE_CONFIRM_SECONDS)}s"), stopped_here)

    def _try_enable_linger(self) -> None:
        import getpass
        import subprocess

        user = getpass.getuser()
        try:
            ok = subprocess.run(["loginctl", "enable-linger", user], capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            ok = False
        if ok:
            self.app.call_from_thread(self._log, Text("✓ Lingering turned on: the listener now survives logout "
                                                      "and starts at boot.", style=T.SAFE))
            return
        cmd = f"sudo loginctl enable-linger {user}"
        self.app.call_from_thread(self._log, Text(
            "Lingering is still off (turning it on needs admin rights here), so the listener stops when you log "
            f"out. Run once: {cmd}", style=T.ATTENTION))
        self.app.call_from_thread(self.app.push_screen, CommandModal(
            cmd, title="Keep the listener running after logout",
            note="Run this once on THIS machine (needs sudo). It lets your user services run without a login."))

    def _service_install_failed(self, cmds: list[str], detail: str, stopped_here: bool) -> None:
        if stopped_here:
            # Don't leave the user with NO listener: bring the in-process one back.
            ensure = getattr(self.app, "ensure_core_listener", None)
            if ensure is not None:
                self.app.call_from_thread(ensure)
        self.app.call_from_thread(self._log, Text(
            f"Couldn't set up the always-on listener: {detail}\n"
            + ("Kratos is listening inside this window again for now.\n" if stopped_here else "")
            + "Run these yourself (press c-copy from the box):", style=T.CRITICAL))
        self.app.call_from_thread(self.app.push_screen, CommandModal(
            "\n".join(cmds), title="Always-on listener commands", note="Run on THIS machine."))

    async def _pick_hub_address(self) -> str | None:
        """Ask which address the target should DIAL to reach this core."""
        candidates = hub_address.candidate_hub_addresses()
        entries: list[tuple[str, str]] = []
        for c in candidates:
            if c.kind == "manual":
                entries.append(("__manual__", "Enter a different address…"))
            else:
                entries.append((c.address, f"{c.address}   ({c.kind}) — {c.note}"))
        tailnet = any(c.kind == "tailscale" for c in candidates)
        subtitle = ("The address the agent will DIAL to reach Kratos."
                    + (" Tailscale is listed first: it reaches a box outside your network (a VPS, behind NAT)"
                       " without opening any port." if tailnet else ""))
        picked = await self.app.push_screen_wait(
            ListPickerModal("Which address will the target reach this core at?", entries, subtitle=subtitle)
        )
        if picked is None:
            return None
        if picked == "__manual__":
            hint = "Public IP or hostname the target can reach (e.g. vpn.example.com)."
            while True:
                typed = await self.app.push_screen_wait(PromptModal("Core address", hint=hint))
                typed = (typed or "").strip()
                if not typed:
                    return None
                # Checked here, before any pairing code exists: the address goes
                # into a root-run installer and the agent's command line.
                if is_ip_or_hostname(typed):
                    return typed
                hint = (f"'{typed}' isn't an IP address or hostname — type just the address "
                        "(e.g. 203.0.113.7 or vpn.example.com), or leave it empty to cancel.")
        return picked

    def _render_pairing_instructions(self, name: str | None, host: str, code: str, ttl_min: int, out_path: Path) -> None:
        label = name or "this target"
        # The exact scp+ssh commands, stashed so `c` can pop a click-to-copy box
        # (paste-safe, no OCR/line-wrap corruption). <user@target> is a fill-in.
        self._last_deploy_commands = self._deploy_commands(out_path)
        self._log(Text(f"✓ Pairing code for {label}: {code}", style=f"bold {T.SAFE}"))
        self._log(Text(f"  Single-use and expires in {ttl_min} min — it authorizes this one agent.", style=T.TEXT_DIM))
        self._log(Text(
            f"Saved a one-command installer to:\n"
            f"    {out_path}\n"
            f"Run it ON the box: it installs a service and starts it. Kratos never runs anything on your box on its "
            f"own — the next question offers to copy and run it over SSH for you.\n\n"
            f"To do it yourself (it opens NO inbound port and does not enable execution):\n"
            + "".join(f"    {line}\n" for line in self._last_deploy_commands.splitlines())
            + "\n"
            f"The target will dial back to this core at {host}:{self._core_port}.  Press 'c' to copy these commands.",
            style=T.TEXT_MUTED,
        ))

    def _deploy_commands(self, out_path: Path, ssh_addr: str = "<user@target>") -> str:
        import shlex

        name = shlex.quote(out_path.name)
        return f"scp {shlex.quote(str(out_path))} {ssh_addr}:~/\nssh {ssh_addr} 'sh {name} && rm -f {name}'"

    def action_copy_commands(self) -> None:
        if not self._last_deploy_commands:
            self.app.notify("No deploy commands yet — add a server first ('a').", timeout=3)
            return
        self.app.push_screen(CommandModal(
            self._last_deploy_commands,
            title="Deploy commands (run on this machine)",
            note="Copies the installer to the target and runs it. Replace <user@target> with the target's SSH address.",
        ))


def _slug(name: str | None) -> str:
    if not name:
        return ""
    return "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")


def _telemetry_table(latest: dict[str, Any]) -> Table:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style=T.TEXT_DIM)
    table.add_column()
    payload = latest.get("payload") if isinstance(latest, dict) else None
    if not isinstance(payload, dict):
        payload = latest if isinstance(latest, dict) else {}
    for key in sorted(payload):
        val = payload[key]
        if isinstance(val, (dict, list)):
            val = _compact(val)
        table.add_row(str(key), str(val))
    if latest.get("collected_at"):
        table.add_row("collected_at", str(latest["collected_at"]))
    return table


def _compact(val: Any, limit: int = 80) -> str:
    s = str(val)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def _free_name(name: str, taken: set[str]) -> str:
    n = 2
    while f"{name}-{n}".lower() in taken:
        n += 1
    return f"{name}-{n}"


def _pending_cells(code: dict[str, Any], now, names: dict[str, str]) -> tuple:
    """Table cells for an unused pairing code: a live countdown, or 'expired'
    (plus who tried to use it after that)."""
    expires = ST.parse_stored_instant(code.get("expires_at"))
    left = (expires - now).total_seconds() if expires else -1
    label = code.get("name") or "(unnamed)"
    if code.get("replaces_target_id"):
        label += f" (re-pair of {names.get(code['replaces_target_id'], code['replaces_target_id'])})"
    if left > 0:
        status = Text("… waiting", style=T.ATTENTION)
        detail = (f"code {code['code']} · expires in {int(left) // 60}:{int(left) % 60:02d} · run its installer on the "
                  "server (d deploy over SSH · x dismiss · n new code)")
    else:
        status = Text("✗ code expired", style=T.CRITICAL)
        tried = (f" · {code['last_attempt_host']} tried it {ST.human_age(ST._age(code['last_attempt_at'], now))}"
                 if code.get("last_attempt_at") else "")
        detail = f"code {code['code']} expired {ST.human_age(-left)}{tried} · press n for a fresh code"
    return (status, Text(label), Text(code.get("last_attempt_host") or "—", style=T.TEXT_DIM), Text("—"),
            Text("—", style=T.TEXT_DIM), Text(detail, style=T.TEXT_DIM))

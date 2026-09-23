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
from kratos.subagent import hub_address, installer
from kratos.subagent.status import (
    STATUS_CONNECTED,
    STATUS_NEVER,
    STATUS_STALE,
    STATUS_UNREACHABLE,
    derive_status,
)
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, ListPickerModal, PromptModal


def _cl_default_bind() -> str:
    from kratos.subagent import core_listener as _cl

    return _cl.DEFAULT_BIND_HOST


def _is_publickey_denied(detail: str) -> bool:
    d = (detail or "").lower()
    return "permission denied" in d and "publickey" in d


def _authorize_key_command() -> str | None:
    """`echo '<this host's target pubkey>' >> ~/.ssh/authorized_keys`, for the
    user to paste ON the target so this host can SSH in. None if the pubkey
    can't be read. Mirrors what generate_target_setup_checklist already shows for
    the direct-SSH path -- same key, so authorizing it once covers both."""
    from kratos import kratos_config as _kc

    pub = _kc.SSH_TARGET_KEY_PATH.with_name(_kc.SSH_TARGET_KEY_PATH.name + ".pub")
    try:
        key = pub.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not key:
        return None
    return f"echo '{key}' >> ~/.ssh/authorized_keys"


def _deploy_failure_message(ssh_addr: str, detail: str) -> str:
    """The log message shown when an SSH deploy fails. On a public-key rejection
    (this host's key isn't authorized on the target yet), hand the user the exact
    command to paste ON the target to grant it -- not just 'do it yourself'."""
    lines = [f"Couldn't deploy to {ssh_addr}: {detail}"]
    authorize = _authorize_key_command() if _is_publickey_denied(detail) else None
    if authorize:
        login = ssh_addr.split("@", 1)[0] if "@" in ssh_addr else "the login user"
        lines += [
            "",
            f"{ssh_addr} doesn't accept this host's SSH key yet. Grant it by running this ON the",
            f"target (as {login}, the user you connect as), then press 'a' to retry the deploy:",
            f"    {authorize}",
        ]
    else:
        lines.append("Run the scp/ssh commands above yourself (needs key-based SSH access to the target).")
    return "\n".join(lines)

_DEFAULT_CORE_PORT = 8765
_CHECKIN_POLL_SECONDS = 1.0
_CHECKIN_TIMEOUT_SECONDS = 900  # a pairing code lives 15 min; stop waiting when it can no longer be used.

_STATUS_STYLE = {
    STATUS_CONNECTED: ("●", T.SAFE, "connected"),
    STATUS_STALE: ("◐", T.ATTENTION, "stale"),
    STATUS_UNREACHABLE: ("●", T.CRITICAL, "unreachable"),
    STATUS_NEVER: ("○", T.TEXT_DIM, "never connected"),
}


class SubAgentScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("a", "add_server", "add a server", show=True),
        Binding("t", "telemetry", "latest telemetry", show=True),
        Binding("l", "install_service", "always-on listener", show=True),
        Binding("r", "refresh", "refresh", show=False),
    ]

    CSS = """
    SubAgentScreen { padding: 1 2; }
    SubAgentScreen #sa-banner { height: auto; padding: 0 0 1 0; }
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
    ) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._core_port = core_port
        self._sa_store = SubAgentStore(self._data_dir / "kratos.db")
        self._targets: list[dict[str, Any]] = []
        # When opened from onboarding: jump straight into the add-a-server flow
        # with the target's name pre-filled.
        self._auto_add = auto_add
        self._default_name = default_name

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                Text("Sub-agents — paired targets streaming read-only telemetry", style=f"bold {T.ACCENT}"),
                id="sa-banner",
            )
            yield DataTable(id="sa-table", cursor_type="row")
            yield VerticalScroll(id="sa-log")
            yield Static(
                Text("a add a server · t latest telemetry · l always-on listener · r refresh · esc back", style=T.TEXT_DIM),
                id="sa-hints",
            )

    def on_mount(self) -> None:
        table = self.query_one("#sa-table", DataTable)
        table.add_columns("status", "name", "host", "agent", "last seen")
        self._refresh()
        # Make sure a listener is up while this screen is open, so paired targets
        # stream telemetry without a second terminal. Defensive getattr: a bare
        # test host App without this method is simply skipped.
        ensure = getattr(self.app, "ensure_core_listener", None)
        if ensure is not None and self._targets:
            ensure()
        if self._auto_add:
            self.action_add_server()

    # ------------------------------------------------------------------
    def _log(self, renderable: Any) -> None:
        log = self.query_one("#sa-log", VerticalScroll)
        log.mount(Static(renderable))
        log.scroll_end(animate=False)

    def action_refresh(self) -> None:
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one("#sa-table", DataTable)
        table.clear()
        self._targets = self._sa_store.list_targets()
        if not self._targets:
            table.add_row(Text("— no paired targets yet —", style=T.TEXT_DIM), "", "", "", "")
            return
        for t in self._targets:
            status = derive_status(t.get("last_seen"))
            glyph, color, label = _STATUS_STYLE.get(status, ("○", T.TEXT_DIM, status))
            table.add_row(
                Text(f"{glyph} {label}", style=color),
                Text(t.get("name") or "—"),
                Text(t.get("hostname") or "—"),
                Text(t.get("agent_version") or "—"),
                Text(_short_ts(t.get("last_seen")), style=T.TEXT_DIM),
            )

    def action_back(self) -> None:
        self.app.pop_screen()

    # ------------------------------------------------------------------
    def _selected_target(self) -> dict[str, Any] | None:
        if not self._targets:
            return None
        table = self.query_one("#sa-table", DataTable)
        row = table.cursor_row
        if row is None or row < 0 or row >= len(self._targets):
            return None
        return self._targets[row]

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
        """Full add-a-server flow: name → hub address → code → installer → wait."""
        name = await self.app.push_screen_wait(
            PromptModal(
                "Add a server",
                hint="A short label for this target (e.g. web-01). Enter to skip.",
                initial=self._default_name or "",
            )
        )
        if name is None:
            return  # cancelled
        name = (name or "").strip() or None

        host = await self._pick_hub_address()
        if host is None:
            return

        # A NEW target row appearing after this snapshot = a successful check-in.
        pre_ids = {t["target_id"] for t in self._sa_store.list_targets()}

        result = self._sa_store.create_pairing_code(name=name)
        code = result["code"]
        ttl_min = result["ttl_seconds"] // 60

        try:
            script = installer.generate_installer(host, code, core_port=self._core_port)
        except installer.InstallerError as exc:
            self._log(Text(f"Could not generate installer: {exc}", style=T.CRITICAL))
            return

        slug = _slug(name) or code.replace("-", "").lower()
        out_path = self._data_dir / f"kratos-subagent-install-{slug}.sh"
        try:
            out_path.write_text(script, encoding="utf-8")
        except OSError as exc:
            self._log(Text(f"Could not write installer to {out_path}: {exc}", style=T.CRITICAL))
            return

        # Make sure a listener is accepting connections, so the target can
        # actually check in -- no second terminal needed.
        self._announce_listener()

        self._render_pairing_instructions(name, host, code, ttl_min, out_path)

        # Offer to copy+run the installer on the target over SSH (one keypress
        # instead of manual scp/ssh). Falls back cleanly to the manual steps.
        await self._offer_ssh_deploy(out_path, name)

        self._log(Text(f"Waiting for {name or 'the target'} to check in… (you can leave this screen; it keeps pairing)", style=T.ATTENTION))
        await self._await_checkin(pre_ids, name)

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

    async def _offer_ssh_deploy(self, out_path: Path, name: str | None) -> None:
        deploy = await self.app.push_screen_wait(ConfirmModal(
            "Deploy over SSH now?",
            "Copy the installer to the target and run it over SSH for you? "
            "You'll confirm the target's SSH address next. (Or do it yourself with the commands above.)",
        ))
        if not deploy:
            return
        default_ssh = f"root@{self._default_name}" if self._default_name else ""
        ssh_addr = await self.app.push_screen_wait(PromptModal(
            "Target SSH address",
            hint="user@host to deploy to (e.g. ubuntu@203.0.113.5). Needs key-based SSH access.",
            initial=default_ssh,
        ))
        ssh_addr = (ssh_addr or "").strip()
        if not ssh_addr:
            return
        self._log(Text(f"Deploying to {ssh_addr} over SSH…", style=T.ATTENTION))
        self._ssh_deploy_worker(str(out_path), ssh_addr)

    @work(thread=True)
    def _ssh_deploy_worker(self, script_path: str, ssh_addr: str) -> None:
        import subprocess

        from kratos import kratos_config as _kc

        basename = Path(script_path).name
        ssh_opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
        # Present Kratos's configured target key, so the key we deploy with is the
        # same one whose public half we tell the user to authorize on a failure.
        if _kc.SSH_TARGET_KEY_PATH.exists():
            ssh_opts += ["-i", str(_kc.SSH_TARGET_KEY_PATH)]
        try:
            scp = subprocess.run(
                ["scp", *ssh_opts, script_path, f"{ssh_addr}:{basename}"],
                capture_output=True, text=True, timeout=60,
            )
            if scp.returncode != 0:
                self._deploy_failed(ssh_addr, (scp.stderr or scp.stdout).strip())
                return
            run = subprocess.run(
                ["ssh", *ssh_opts, ssh_addr, f"sh {basename}"],
                capture_output=True, text=True, timeout=120,
            )
            if run.returncode != 0:
                self._deploy_failed(ssh_addr, (run.stderr or run.stdout).strip())
                return
            self.app.call_from_thread(self._log, Text(
                f"✓ Installer ran on {ssh_addr}. Waiting for it to check in…", style=f"bold {T.SAFE}"
            ))
        except (OSError, subprocess.SubprocessError) as exc:
            self._deploy_failed(ssh_addr, str(exc))

    def _deploy_failed(self, ssh_addr: str, detail: str) -> None:
        self.app.call_from_thread(self._log, Text(_deploy_failure_message(ssh_addr, detail), style=T.CRITICAL))
        # On a public-key rejection, also pop a click-to-copy box with the exact
        # authorize command, so the user pastes it verbatim (no OCR/line-wrap
        # corruption -- the failure mode that broke a real manual paste).
        authorize = _authorize_key_command() if _is_publickey_denied(detail) else None
        if authorize:
            login = ssh_addr.split("@", 1)[0] if "@" in ssh_addr else "the login user"
            note = f"Run this ON the target (as {login}), then press 'a' to retry the deploy."
            self.app.call_from_thread(
                self.app.push_screen,
                CommandModal(authorize, title="Authorize Kratos on the target", note=note),
            )

    # ------------------------------------------------------------------
    @work
    async def action_install_service(self) -> None:
        """Install `subagent-serve` as an always-on service so telemetry keeps
        arriving after Kratos is closed (and survives a reboot). System service
        when passwordless sudo is available, else a user service (no root)."""
        from kratos.subagent import core_listener as _cl

        user_mode = not _cl.passwordless_sudo_available()
        cmds = _cl.core_service_install_commands(
            self._data_dir, port=self._core_port, user_mode=user_mode
        )
        kind = "user" if user_mode else "system"
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Install always-on listener?",
            f"Install the telemetry listener as a {kind} service so it keeps receiving "
            f"after you close Kratos and across reboots? You can undo it later with systemctl.",
        ))
        if not ok:
            self._log(Text("To install it later, run these once:\n" + "\n".join(cmds), style=T.TEXT_MUTED))
            return
        self._log(Text(f"Installing the always-on listener ({kind} service)…", style=T.ATTENTION))
        self._install_service_worker(cmds)

    @work(thread=True)
    def _install_service_worker(self, cmds: list[str]) -> None:
        import subprocess

        from kratos.subagent import core_listener as _cl

        for cmd in cmds:
            try:
                proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError) as exc:
                self._service_install_failed(cmds, str(exc))
                return
            if proc.returncode != 0:
                self._service_install_failed(cmds, (proc.stderr or proc.stdout).strip())
                return
        if _cl.listener_running(self._core_port):
            self.app.call_from_thread(self._log, Text(
                "✓ Always-on listener installed and running — telemetry will keep arriving "
                "even when Kratos is closed.", style=f"bold {T.SAFE}",
            ))
        else:
            self.app.call_from_thread(self._log, Text(
                "Service commands ran, but nothing is listening yet — check "
                "`systemctl status kratos-core-listener` (or `--user`).", style=T.ATTENTION,
            ))

    def _service_install_failed(self, cmds: list[str], detail: str) -> None:
        self.app.call_from_thread(self._log, Text(
            f"Couldn't install the service automatically: {detail}\n"
            "Run these once yourself:\n" + "\n".join(cmds),
            style=T.CRITICAL,
        ))

    async def _pick_hub_address(self) -> str | None:
        """Ask which address the target should DIAL to reach this core."""
        candidates = hub_address.candidate_hub_addresses()
        entries: list[tuple[str, str]] = []
        for c in candidates:
            if c.kind == "manual":
                entries.append(("__manual__", "Enter a different address…"))
            else:
                entries.append((c.address, f"{c.address}   ({c.kind}) — {c.note}"))
        picked = await self.app.push_screen_wait(
            ListPickerModal("Which address will the target reach this core at?", entries)
        )
        if picked is None:
            return None
        if picked == "__manual__":
            typed = await self.app.push_screen_wait(
                PromptModal("Core address", hint="Public IP or hostname the target can reach (e.g. vpn.example.com).")
            )
            typed = (typed or "").strip()
            return typed or None
        return picked

    def _render_pairing_instructions(self, name: str | None, host: str, code: str, ttl_min: int, out_path: Path) -> None:
        label = name or "this target"
        self._log(Text(f"✓ Pairing code for {label}: {code}  (expires in {ttl_min} min)", style=f"bold {T.SAFE}"))
        self._log(Text(
            f"Saved a one-command installer to:\n"
            f"    {out_path}\n\n"
            f"Get it onto the target and run it once (it opens NO inbound port, and does not enable execution):\n"
            f"    scp {out_path.name} {label.replace(' ', '-')}:~/     # or copy it over however you like\n"
            f"    ssh <target> 'sh {out_path.name}'\n\n"
            f"The target will dial back to this core at {host}:{self._core_port}.",
            style=T.TEXT_MUTED,
        ))

    async def _await_checkin(self, pre_ids: set[str], name: str | None) -> None:
        waited = 0.0
        while waited < _CHECKIN_TIMEOUT_SECONDS:
            await asyncio.sleep(_CHECKIN_POLL_SECONDS)
            waited += _CHECKIN_POLL_SECONDS
            targets = self._sa_store.list_targets()
            new = [t for t in targets if t["target_id"] not in pre_ids]
            if new:
                t = new[0]
                who = t.get("hostname") or name or t["target_id"]
                self._log(Text(
                    f"✓ {who} paired — {t.get('agent_version') or 'sub-agent'} · telemetry live.\n"
                    f"  It is recommend-only by default; turn on direct execution any time from /whitelist.",
                    style=f"bold {T.SAFE}",
                ))
                self._refresh()
                return
        self._log(Text(
            f"⧗ No check-in within {_CHECKIN_TIMEOUT_SECONDS // 60} min — the code likely expired unused.\n"
            f"  The installer was never run, or this core wasn't listening. Add the server again for a fresh code.",
            style=T.ATTENTION,
        ))


def _short_ts(iso: str | None) -> str:
    if not iso:
        return "never"
    # Keep it compact; display-zone conversion is handled elsewhere for live views.
    return iso.replace("T", " ").split(".")[0].replace("+00:00", "Z")


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

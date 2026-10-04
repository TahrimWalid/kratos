"""
Onboard a newly-entered target: connect Kratos to the machine a user wants to
protect, BEFORE they land in a session that would otherwise just fail.

Reached from the launcher's new-session flow and the first-run wizard, for any
remote target that isn't the Kratos host itself. It asks the one question those
entry points never did -- *how should Kratos reach this box?* -- as a short
list with a live detail panel (what the highlighted option is, how it works,
what it can do today, and the one thing you'll have to do; `d` opens the full
text), and then walks the chosen path to a working connection:

- **Direct SSH** (Kratos connects in, read-only): the path every investigation
  tool uses today. Creates this machine's SSH key first if there is none (only
  on an explicit yes), tries a read-only probe, and then:
  - SSH works -> the probe table; the full setup checklist (journal/sudo/
    firewall access) only if a check still fails.
  - the key isn't accepted yet -> a short walkthrough on how the operator can
    reach the box today (log in another way / someone else runs it / no way in
    yet), with the one authorize line in a copy-safe box. Kratos can't put its
    key on a box it can't log into yet, and it never asks for a password.
  - anything else (timeout, DNS, refused, host key changed, ...) -> what it
    means and the next step, from the same classifier the deploy flow uses.
- **Sub-agent** (a small agent on the target dials back): always-on read-only
  telemetry AND investigations through the agent's fixed set of reads, right
  for a behind-NAT / no-inbound box. Hands off to the real `/subagent` add
  flow; once the new agent checks in, this target is linked to it (that choice
  was the user's, so the link is explicit, docs/subagent_read_routing.md D3).
- **Its paired sub-agent** (only when the typed target looks like a box that is
  already paired): link to it directly -- offered, never assumed.
- **Skip**: proceed anyway; set it up later from `/target` or `/subagent`.

This screen never runs anything on the target and never takes the target's
credentials -- the SSH checklist is for the operator to run, and the probe is
read-only. It is setup guidance, not a safety gate, so "continue" is always
allowed even if a check is still failing.
"""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from kratos import kratos_config as _kconfig
from kratos.subagent import deploy_diagnosis as DD
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, InfoModal, ListPickerModal
from kratos.utils import ssh_keys

# Targets that need no setup -- the Kratos host itself, monitored over loopback.
_LOCAL_TARGETS = {"127.0.0.1", "localhost", "::1"}


# Failures where SSH reached the box but it won't let this machine's key in --
# the first-contact case the walkthrough handles.
_BOOTSTRAP_KINDS = {"key_not_authorized", "password_only", "no_local_key", "auth_failed"}


def _local_hostname() -> str:
    try:
        return socket.gethostname() or "host"
    except OSError:
        return "host"


# The three ways to connect, in list order. Labels stay short; the detail
# panel explains the highlighted one.
_CHOICES = (
    ("ssh", "Direct SSH  (recommended)"),
    ("subagent", "Sub-agent"),
    ("skip", "Skip for now"),
)

# Honest by construction: say exactly what each path can and can't do.
_DETAILS: dict[str, list[tuple[str, str]]] = {
    "ssh": [
        ("What", "Kratos logs into this box over SSH with your key and READS its logs, config, "
                 "processes and ports — read-only. It never changes anything without your approval."),
        ("How", "You authorize Kratos's SSH key on the box once (Kratos gives you the exact one-line "
                "command). It connects on demand when you investigate. Nothing is installed on the box."),
        ("Today", "runs the full investigation toolset."),
        ("You do", "add one authorized_keys line, and make sure the box is reachable (port 22)."),
    ],
    "subagent": [
        ("What", "A small agent you install on the box. It dials OUT to Kratos (no inbound port on "
                 "your box), streams telemetry, and answers investigations with a fixed set of "
                 "built-in reads (logs, processes, open files, config, file hashes, YARA). It can't "
                 "run anything else; fixes stay off unless you turn them on."),
        ("How", "A one-line installer sets it up as a service; it connects out (Tailscale or your "
                "network). Kratos never opens a port on your box."),
        ("Today", "Investigations work through it, except network scans (open ports / vulnerabilities) "
                  "— those need a direct path from Kratos and are skipped, and the answer says so."),
        ("You do", "run one install command on the box (Kratos generates it)."),
    ],
    "skip": [
        ("Later", "Set up with /target (SSH) or /subagent. You can do both, and change any time."),
    ],
}
_CHOICE_LABEL = dict(_CHOICES)
# At this width and up the detail panel sits beside the list; below, under it.
_WIDE_AT = 110


def _detail_table(key: str, details: dict[str, list[tuple[str, str]]] | None = None) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 1, 0, 0), expand=True)
    table.add_column(style=f"bold {T.TEXT_BRIGHT}", no_wrap=True)
    table.add_column(style=T.TEXT_MUTED, ratio=1)
    for label, text in (details or _DETAILS)[key]:
        style = f"bold {T.ATTENTION}" if label == "Today" and key in ("subagent", "paired") else T.TEXT_MUTED
        table.add_row(label, Text(text, style=style))
    return table


def needs_onboarding(target_host: str) -> bool:
    """A remote target the user just entered that isn't the Kratos host."""
    return bool(target_host) and target_host.strip().lower() not in _LOCAL_TARGETS


class OnboardTargetScreen(Screen[str | None]):
    BINDINGS = [
        Binding("escape,q", "skip", "skip / set up later", show=True),
        Binding("p", "reprobe", "re-check", show=True),
        Binding("d", "details", "full details", show=True),
        Binding("c,enter", "continue", "continue", show=True),
    ]

    CSS = """
    OnboardTargetScreen { padding: 1 2; }
    OnboardTargetScreen #ob-banner { height: auto; padding: 0 0 1 0; }
    OnboardTargetScreen #ob-choose { height: 1fr; layout: vertical; }
    OnboardTargetScreen #ob-choose.-wide { layout: horizontal; }
    OnboardTargetScreen #ob-options { height: auto; border: none; padding: 0; margin: 0 0 1 0; }
    OnboardTargetScreen #ob-choose.-wide #ob-options { width: 34; margin: 0 2 0 0; }
    OnboardTargetScreen #ob-detail { height: auto; max-height: 100%; border: round $panel; padding: 0 1; }
    OnboardTargetScreen #ob-log { height: 1fr; border-top: solid $panel; padding-top: 1; display: none; }
    OnboardTargetScreen #ob-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, target_host: str, core_port: int = 8765) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._target_host = target_host
        self._core_port = core_port
        self._method: str | None = None
        # A box this target looks like (by name/hostname/address) that is
        # already paired: offered as its own choice, never linked silently.
        from kratos.tui_mk2 import target_link as TL

        try:
            self._paired = [] if TL.current_link(data_dir, target_host) else TL.matching_agents(data_dir, target_host)
        except Exception:  # noqa: BLE001 -- a store problem must not block onboarding
            self._paired = []
        self._choices = list(_CHOICES)
        self._labels = dict(_CHOICE_LABEL)
        self._details = dict(_DETAILS)
        if self._paired:
            name = TL.agent_label(self._paired[0])
            self._choices.insert(0, ("paired", f"Its paired sub-agent  ({name})"))
            self._labels["paired"] = self._choices[0][1]
            self._details["paired"] = [
                ("What", f"{target_host} looks like {name}, a box you've already paired. Kratos would read it "
                         "through that sub-agent's fixed set of built-in reads."),
                ("Today", "Investigations work through it, except network scans (open ports / vulnerabilities) "
                          "— those need a direct path and are skipped, and the answer says so."),
                ("You do", "confirm it's the same machine — a wrong link would read the wrong box."),
            ]

    def compose(self) -> ComposeResult:
        banner = Text(f"Connect Kratos to {self._target_host}", style=f"bold {T.ACCENT}")
        banner.append("\nHow should Kratos reach it? You can set up both later.", style=T.TEXT_MUTED)
        with Vertical():
            yield Static(banner, id="ob-banner")
            with Container(id="ob-choose"):
                yield OptionList(*(Option(label, id=key) for key, label in self._choices), id="ob-options")
                with VerticalScroll(id="ob-detail"):
                    yield Static(id="ob-detail-body")
            yield VerticalScroll(id="ob-log")
            yield Static(self._choose_hints(), id="ob-hints")

    def on_mount(self) -> None:
        self._apply_width(self.size.width or self.app.size.width)
        options = self.query_one("#ob-options", OptionList)
        options.highlighted = 0
        options.focus()
        # The panel title names the option it describes; the border itself stays quiet.
        self.query_one("#ob-detail").styles.border_title_color = T.ACCENT
        self._show_detail(self._choices[0][0])

    def on_resize(self, event) -> None:
        self._apply_width(event.size.width)
        self.call_after_refresh(self._refresh_choose_hints)

    def _apply_width(self, width: int) -> None:
        self.query_one("#ob-choose").set_class(width >= _WIDE_AT, "-wide")

    @staticmethod
    def _choose_hints(details_cut: bool = False) -> Text:
        # "d full details" only when the panel can't show everything (a short or
        # narrow terminal); on a big screen d would just repeat the panel.
        middle = " · d full details" if details_cut else ""
        return Text(f"↑↓ choose · enter select{middle} · esc set up later", style=T.TEXT_DIM)

    def _refresh_choose_hints(self) -> None:
        if not self._choosing():
            return
        panel = self.query_one("#ob-detail", VerticalScroll)
        cut = panel.virtual_size.height > panel.scrollable_content_region.height
        self.query_one("#ob-hints", Static).update(self._choose_hints(details_cut=cut))

    def _choosing(self) -> bool:
        return self._method is None and self.query_one("#ob-choose").display

    def _highlighted_key(self) -> str:
        options = self.query_one("#ob-options", OptionList)
        index = options.highlighted if options.highlighted is not None else 0
        return options.get_option_at_index(index).id or self._choices[0][0]

    def _show_detail(self, key: str) -> None:
        panel = self.query_one("#ob-detail", VerticalScroll)
        panel.border_title = self._labels.get(key, key)
        self.query_one("#ob-detail-body", Static).update(_detail_table(key, self._details))
        panel.scroll_home(animate=False)
        self.call_after_refresh(self._refresh_choose_hints)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id:
            self._show_detail(event.option.id)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option.id:
            self._select_method(event.option.id)

    def action_details(self) -> None:
        if self._choosing():
            key = self._highlighted_key()
            self.app.push_screen(InfoModal(self._labels[key], _detail_table(key, self._details)))

    # ------------------------------------------------------------------
    def _log(self, renderable) -> None:
        log = self.query_one("#ob-log", VerticalScroll)
        log.mount(Static(renderable))
        log.scroll_end(animate=False)

    def _select_method(self, picked: str) -> None:
        if picked == "skip":
            self.dismiss(None)
            return
        self._method = picked
        # The choice is made: the list gives way to the chosen path's progress.
        self.query_one("#ob-choose").display = False
        self.query_one("#ob-log").display = True
        self.query_one("#ob-hints", Static).update(
            Text("p re-check · c/enter continue · esc set up later", style=T.TEXT_DIM))
        if picked == "ssh":
            _kconfig.set_active_target(self._target_host)
            self._start_ssh()
        elif picked == "paired":
            self._link_paired()
        elif picked == "subagent":
            self._log(Text(
                "Opening sub-agent setup — add your server there (press 'a'), then Esc to come back "
                "and Enter to continue into your session. Once the agent checks in, investigations of "
                f"{self._target_host} read through it.",
                style=T.TEXT_MUTED,
            ))
            from kratos.tui_mk2.screens.subagent import SubAgentScreen

            self.app.push_screen(
                SubAgentScreen(self._data_dir, self._core_port, auto_add=True, default_name=self._target_host,
                               link_host=self._target_host)
            )

    @work
    async def _link_paired(self) -> None:
        from kratos.tui_mk2 import target_link as TL

        agent = self._paired[0]
        mode = await TL.ask_mode(self.app, self._target_host, agent)
        if mode is None:
            self._log(Text("Not linked. Press esc to set up later, or pick another way.", style=T.TEXT_MUTED))
            return
        self._log(TL.apply_link(self._data_dir, self._target_host, agent["target_id"], mode))
        _kconfig.set_active_target(self._target_host)
        ensure = getattr(self.app, "ensure_core_listener", None)
        if ensure is not None:
            ensure()
        self._reprobe_worker()

    # --- direct SSH ------------------------------------------------------
    @work
    async def _start_ssh(self) -> None:
        if ssh_keys.read_local_pubkey() is None and not await self._ensure_local_key():
            self._log(Text(
                "Without an SSH key Kratos can't log in to the target. Press p to try again, or esc to set up later.",
                style=T.ATTENTION,
            ))
            return
        self._reprobe_worker()

    async def _ensure_local_key(self) -> bool:
        """Create (or repair the public half of) this machine's key -- only on
        an explicit yes. True when a usable public key exists afterwards."""
        key = ssh_keys._key_path()
        if key.exists():
            ok = await self.app.push_screen_wait(ConfirmModal(
                "Recreate the public key?",
                f"The key {key} exists but its public half ({ssh_keys.pubkey_path().name}) is missing or unreadable. "
                "Rebuild it from the key? (Nothing changes on the target; press y to go ahead.)"))
            action, what = ssh_keys.derive_public_key, "Rebuilt"
        else:
            ok = await self.app.push_screen_wait(ConfirmModal(
                "Create Kratos's SSH key?",
                f"Kratos logs in to targets with its own key, and {key} doesn't exist yet. Create it now "
                "(ed25519, stays on this machine)? Its public half is what you'll add on the target. "
                "Press y to create it."))
            action, what = (lambda: ssh_keys.generate_local_key(comment=f"kratos@{_local_hostname()}")), "Created"
        if not ok:
            return False
        try:
            await asyncio.to_thread(action)
        except ssh_keys.KeyGenError as exc:
            self._log(Text(f"Couldn't set up the key: {exc}", style=T.CRITICAL))
            return False
        self._log(Text(f"✓ {what} {ssh_keys.pubkey_path()}.", style=T.SAFE))
        return True

    @work(thread=True, exclusive=True, group="ob-probe")
    def _reprobe_worker(self) -> None:
        self._probe_inner()

    def _probe_inner(self) -> None:
        from kratos.adapters.ssh_remote import SSHResult, run_target_probe_checks

        via_agent = self._method == "paired"
        self.app.call_from_thread(self._log, Text(
            f"Checking what Kratos can read on {self._target_host} through its sub-agent…" if via_agent
            else f"Checking whether Kratos can log in to {self._target_host}…", style=T.TEXT_DIM))
        result = run_target_probe_checks()
        from kratos.tui_mk2 import target_memory as TM

        TM.record_check(self._data_dir, self._target_host, "subagent" if via_agent else "ssh",
                        None if isinstance(result, SSHResult) else result)
        if isinstance(result, SSHResult) and via_agent:
            self.app.call_from_thread(self._log, Text(
                f"Couldn't read {self._target_host} through its sub-agent yet: {(result.stderr or '').strip()} "
                "— press p to re-check.", style=T.ATTENTION))
            return
        if isinstance(result, SSHResult):
            addr = f"{_kconfig.SSH_TARGET_USER}@{self._target_host}"
            raw = (result.stderr or result.stdout or "").strip()
            diag = DD.diagnose(raw, ssh_addr=addr, authorize_command=ssh_keys.authorize_key_command())
            self.app.call_from_thread(self._log, Text(
                f"Kratos can't SSH into {self._target_host} yet: {diag.summary}", style=T.CRITICAL))
            if raw:
                self.app.call_from_thread(self._log, Text(raw[-600:], style=T.TEXT_DIM))
            if diag.kind in _BOOTSTRAP_KINDS:
                self.app.call_from_thread(self._bootstrap_walkthrough, diag)
            else:
                self.app.call_from_thread(self._show_fix, diag)
            return

        from kratos.adapters.target_setup import check_label

        table = Table(show_header=True, header_style="bold", title="Setup check")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        colors = {"PASS": T.SAFE, "FAIL": T.CRITICAL, "UNKNOWN": T.ATTENTION, "WARN": T.ATTENTION,
                  "INFO": T.TEXT_MUTED}
        n_fail = 0
        for c in result:
            status = c.get("status", "UNKNOWN")
            if status not in ("PASS", "INFO"):  # INFO is a fact (e.g. the timezone), not a check
                n_fail += 1
            table.add_row(
                check_label(c.get("check", "?")),
                Text(status, style=colors.get(status, T.TEXT_DIM)),
                Text(c.get("detail", ""), style=T.TEXT_DIM),
            )
        self.app.call_from_thread(self._log, table)
        if n_fail == 0 or via_agent:
            self.app.call_from_thread(self._log, Text(
                f"✓ Kratos can reach {self._target_host} — you're ready. Press Enter to start."
                + (" Anything marked FAIL above is something the agent can't read on that box; the "
                   "investigation will say so where it matters." if n_fail and via_agent else ""),
                style=f"bold {T.SAFE}",
            ))
            return
        # SSH works; show the rest of the setup (journal/sudo/firewall access).
        from kratos.adapters import target_setup as _ts

        checklist = _ts.generate_target_setup_checklist(self._target_host)
        self.app.call_from_thread(self._log, Panel(
            Syntax(checklist, "bash", word_wrap=False, background_color="default"),
            title="Run these ON the target (Kratos never runs them)",
            title_align="left",
            border_style=T.ATTENTION,
        ))
        self.app.call_from_thread(self._log, Text(
            f"SSH works, but {n_fail} check(s) aren't passing. Run the commands above on the target, then press "
            "'p' to re-check — or Enter to continue anyway (investigations may be limited until fixed).",
            style=T.ATTENTION,
        ))

    def _show_fix(self, diag: DD.Diagnosis) -> None:
        self._log(Text(f"{diag.next_step}\nThen press 'p' to re-check.", style=T.ATTENTION))
        if diag.command:
            where = "ON the target" if diag.run_on == DD.ON_TARGET else "on THIS machine (where Kratos runs)"
            self.app.push_screen(CommandModal(diag.command, title=f"Run this {where}", note=diag.next_step))

    @work(exclusive=True, group="ob-bootstrap")
    async def _bootstrap_walkthrough(self, diag: DD.Diagnosis) -> None:
        """The first-contact step: this machine's key isn't on the target yet.
        Branch on how the operator can reach the box today."""
        if diag.kind == "no_local_key" or ssh_keys.authorize_key_command() is None:
            if not await self._ensure_local_key():
                return
        authorize = ssh_keys.authorize_key_command()
        if authorize is None:
            return
        user, host = _kconfig.SSH_TARGET_USER, self._target_host
        picked = await self.app.push_screen_wait(ListPickerModal(
            f"How can you reach {host} today?",
            [
                ("login", "I can log in to it another way (password, cloud console, another machine)"),
                ("admin", "Someone else runs it — I'll send them one line"),
                ("none", "I can't get in at all right now"),
            ],
            subtitle="Kratos can't put its key on a box it can't log into yet. One line, run once on the target by "
                     "someone who can, is the whole setup. Kratos never asks for a password.",
        ))
        pw_note = (" If it still refuses after this, key logins are switched off on the target "
                   "(PubkeyAuthentication in /etc/ssh/sshd_config)." if diag.kind == "password_only" else "")
        if picked == "login":
            self._log(Text(f"Log in to {host} as {user} however you normally do, paste the line from the box, then "
                           f"press 'p' here to re-check.{pw_note}", style=T.ATTENTION))
            self.app.push_screen(CommandModal(
                authorize, title=f"Run this ON {host}, logged in as {user}",
                note="It only adds this machine's public key (nothing secret) and is safe to run twice. "
                     f"Logged in as a different user? Ask for the admin version instead.{pw_note}"))
        elif picked == "admin":
            import shlex

            cmd = f"sudo -u {shlex.quote(user)} -H sh -c {shlex.quote(authorize)}"
            self._log(Text(f"Send the line in the box to whoever runs {host}. When they've run it, press 'p' here.",
                           style=T.ATTENTION))
            self.app.push_screen(CommandModal(
                cmd, title=f"For {host}'s admin: run this once (needs sudo)",
                note=f"Adds this machine's public key for the user {user}. It contains no secret; safe to share, "
                     "safe to run twice."))
        else:
            self._log(Text(
                f"Nothing to do until you have a way in to {host}. Press esc to set up later (/target when you're "
                "ready); the sub-agent needs the same one-time access to install, so it can't get around this.",
                style=T.TEXT_MUTED))

    # ------------------------------------------------------------------
    def action_reprobe(self) -> None:
        if self._method == "ssh":
            self._start_ssh()
        elif self._method == "paired":
            self._reprobe_worker()

    def action_continue(self) -> None:
        if self._choosing():
            self._select_method(self._highlighted_key())
            return
        self.dismiss(self._method)

    def action_skip(self) -> None:
        self.dismiss(None)

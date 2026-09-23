"""
Onboard a newly-entered target: connect Kratos to the machine a user wants to
protect, BEFORE they land in a session that would otherwise just fail.

Reached from the launcher's new-session flow and the first-run wizard, for any
remote target that isn't the Kratos host itself. It asks the one question those
entry points never did -- *how should Kratos reach this box?* -- and then walks
the chosen path to a working connection:

- **Direct SSH** (Kratos connects in, read-only): the path every investigation
  tool uses today. Shows the copy-paste setup checklist (add the key, grant
  journal/sudo read access, allow the firewall) that a HUMAN runs ON the target
  -- Kratos never runs it -- then a read-only probe that verifies it, re-runnable
  until green.
- **Sub-agent** (a small agent on the target dials back): always-on read-only
  telemetry, right for a behind-NAT / no-inbound box. Hands off to the real
  `/subagent` add flow.
- **Skip**: proceed anyway; set it up later from `/target` or `/subagent`.

This screen never runs anything on the target and never takes the target's
credentials -- the SSH checklist is for the operator to run, and the probe is
read-only. It is setup guidance, not a safety gate, so "continue" is always
allowed even if a check is still failing.
"""
from __future__ import annotations

from pathlib import Path

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Static

from kratos import kratos_config as _kconfig
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import ListPickerModal

# Targets that need no setup -- the Kratos host itself, monitored over loopback.
_LOCAL_TARGETS = {"127.0.0.1", "localhost", "::1"}


def needs_onboarding(target_host: str) -> bool:
    """A remote target the user just entered that isn't the Kratos host."""
    return bool(target_host) and target_host.strip().lower() not in _LOCAL_TARGETS


class OnboardTargetScreen(Screen[str | None]):
    BINDINGS = [
        Binding("escape,q", "skip", "skip / set up later", show=True),
        Binding("p", "reprobe", "re-check", show=True),
        Binding("c,enter", "continue", "continue", show=True),
    ]

    CSS = """
    OnboardTargetScreen { padding: 1 2; }
    OnboardTargetScreen #ob-banner { height: auto; padding: 0 0 1 0; }
    OnboardTargetScreen #ob-log { height: 1fr; border-top: solid $panel; padding-top: 1; }
    OnboardTargetScreen #ob-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, target_host: str, core_port: int = 8765) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._target_host = target_host
        self._core_port = core_port
        self._method: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                Text(f"Connect Kratos to {self._target_host}", style=f"bold {T.ACCENT}"),
                id="ob-banner",
            )
            yield VerticalScroll(id="ob-log")
            yield Static(
                Text("p re-check · c/enter continue · esc set up later", style=T.TEXT_DIM),
                id="ob-hints",
            )

    def on_mount(self) -> None:
        self._choose_method()

    # ------------------------------------------------------------------
    def _log(self, renderable) -> None:
        log = self.query_one("#ob-log", VerticalScroll)
        log.mount(Static(renderable))
        log.scroll_end(animate=False)

    @work
    async def _choose_method(self) -> None:
        entries = [
            ("ssh", "Direct SSH — Kratos reads logs & config (investigations use this today)"),
            ("subagent", "Sub-agent — always-on telemetry agent that dials back to Kratos"),
            ("skip", "Skip for now — set up later (/target or /subagent)"),
        ]
        picked = await self.app.push_screen_wait(
            ListPickerModal(
                f"How should Kratos reach {self._target_host}?",
                entries,
                subtitle="You can do both later; SSH is the path today's investigations need.",
            )
        )
        if picked is None or picked == "skip":
            self.dismiss(None)
            return
        self._method = picked
        if picked == "ssh":
            _kconfig.set_active_target(self._target_host)
            self._run_ssh_setup()
        elif picked == "subagent":
            self._log(Text(
                "Opening sub-agent setup — add your server there (press 'a'), then Esc to come back "
                "and Enter to continue into your session.",
                style=T.TEXT_MUTED,
            ))
            from kratos.tui_mk2.screens.subagent import SubAgentScreen

            self.app.push_screen(
                SubAgentScreen(self._data_dir, self._core_port, auto_add=True, default_name=self._target_host)
            )

    @work(thread=True)
    def _run_ssh_setup(self) -> None:
        from kratos.adapters import target_setup as _ts

        checklist = _ts.generate_target_setup_checklist(self._target_host)
        panel = Panel(
            Syntax(checklist, "bash", word_wrap=False, background_color="default"),
            title="Run these ON the target (Kratos never runs them)",
            title_align="left",
            border_style=T.ATTENTION,
        )
        self.app.call_from_thread(self._log, panel)
        self._probe_inner()

    @work(thread=True)
    def _reprobe_worker(self) -> None:
        self._probe_inner()

    def _probe_inner(self) -> None:
        from kratos.adapters.ssh_remote import SSHResult, run_target_probe_checks

        result = run_target_probe_checks()
        if isinstance(result, SSHResult):
            self.app.call_from_thread(self._log, Text(
                f"Kratos can't SSH into {self._target_host} yet: "
                f"{(result.stderr or result.stdout or 'no route / auth failed').strip()}\n"
                f"Run the commands above on the target, then press 'p' to re-check.",
                style=T.CRITICAL,
            ))
            return

        table = Table(show_header=True, header_style="bold", title="Setup check")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        colors = {"PASS": T.SAFE, "FAIL": T.CRITICAL, "UNKNOWN": T.ATTENTION}
        n_fail = 0
        for c in result:
            status = c.get("status", "UNKNOWN")
            if status != "PASS":
                n_fail += 1
            table.add_row(
                c.get("check", "?"),
                Text(status, style=colors.get(status, T.TEXT_DIM)),
                Text(c.get("detail", ""), style=T.TEXT_DIM),
            )
        self.app.call_from_thread(self._log, table)
        if n_fail == 0:
            self.app.call_from_thread(self._log, Text(
                f"✓ Kratos can reach {self._target_host} — you're ready. Press Enter to start.",
                style=f"bold {T.SAFE}",
            ))
        else:
            self.app.call_from_thread(self._log, Text(
                f"{n_fail} check(s) not passing. Run the commands above on the target, then press 'p' "
                f"to re-check — or Enter to continue anyway (investigations may be limited until fixed).",
                style=T.ATTENTION,
            ))

    # ------------------------------------------------------------------
    def action_reprobe(self) -> None:
        if self._method == "ssh":
            self._reprobe_worker()

    def action_continue(self) -> None:
        self.dismiss(self._method)

    def action_skip(self) -> None:
        self.dismiss(None)

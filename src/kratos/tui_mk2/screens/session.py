"""
Session screen -- the main workspace (design turns 5a idle, live investigation,
7a palette, 7b interrupt, 7c context meter, 9a header clock, plus /help 8a,
/report 4a, /model 16c, /rename 8b, and the recommend-only remediation of 19b).

Every mechanism used here already exists in Kratos:
  - agent/loop.py::run_agent + its on_step hook drive the live investigation,
  - llm routing (chat vs investigate) reuses cli/repl.py::_route_input,
  - persistence reuses storage/session_store.py exactly as the classic REPL does,
  - approvals reach a Textual modal via agent/tools.py's provider hook.

Investigation and evo-loop run on THREAD workers (run_agent is blocking); the UI
is only ever touched from the event loop via call_from_thread. See
docs/kratos_mk2_tui.md for the per-screen "mechanism exists?" audit.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Input, RichLog, Static
from textual.worker import get_current_worker

from kratos import kratos_config as _kconfig
from kratos.storage.session_store import SessionStore
from kratos.utils import timeutil
from kratos.tui_mk2 import render as R
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import (
    CommandPaletteModal,
    ConfirmModal,
    HelpModal,
    ListPickerModal,
    PromptModal,
)

REPL_MAX_ITERS = 5  # matches cli/repl.py::REPL_MAX_ITERS -- a REPL turn is bounded/cheap

_PALETTE_COMMANDS = [
    ("/report", "investigation summary — findings by severity"),
    ("/evolve", "write a new tool for the current gap"),
    ("/help", "list all commands"),
    ("/model", "show / switch the active LLM backend"),
    ("/timezone", "show / set the display timezone (storage stays UTC)"),
    ("/target", "set or verify the active target"),
    ("/rename", "name this session"),
    ("/clear", "free up context (visible history stays)"),
    ("/reset", "archive history, start this session fresh"),
    ("/delete", "archive (soft-delete) this session"),
    ("/settings", "per-tool approval policy (not yet implemented)"),
    ("/exit", "leave the session"),
]


class _CancelInvestigation(Exception):
    """Raised inside on_step when the user pressed esc -- lets run_agent unwind
    at a step boundary (a blocking LLM/tool call can't be interrupted mid-call,
    so 'interrupted — N of ~M steps' is honest about where it stopped)."""


class SessionScreen(Screen):
    BINDINGS = [
        Binding("escape", "interrupt", "interrupt", show=True),
        Binding("ctrl+p", "palette", "commands", show=True),
    ]

    CSS = f"""
    SessionScreen #transcript {{
        height: 1fr;
        background: {T.BG};
        padding: 0 2;
        scrollbar-size-vertical: 1;
    }}
    SessionScreen #goal {{ height: 3; margin: 0 1; }}
    """

    def __init__(
        self,
        store: SessionStore,
        data_dir: Path,
        session_id: str,
        targets: list[str],
        resume_context: str,
    ) -> None:
        super().__init__()
        self._store = store
        self._data_dir = data_dir
        self.session_state: dict[str, Any] = {
            "session_id": session_id,
            "targets": targets,
            "resume_context": resume_context,
            "backend": self._model_label(),
            "pending_evolve_suggestion": None,
        }
        self._busy = False
        self._ctx_chars = len(resume_context)
        self._last_day: str | None = None  # for the date divider (WhatsApp-style)
        # Resolved once in on_mount (override > system-local > UTC) and passed
        # to every timeutil format call, so live times, resumed/stored times,
        # and the header clock all render in the SAME display zone. Storage
        # stays UTC -- this is display-only (see kratos.utils.timeutil).
        self._display_tz = None

    # --- layout ----------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static(id="appheader")
        with Vertical():
            yield RichLog(id="transcript", wrap=True, markup=False, highlight=False)
        yield Input(placeholder="Describe what to investigate…", id="goal")
        yield Static(id="statusfooter")

    def on_mount(self) -> None:
        self._display_tz = timeutil.resolve_display_tz(self._data_dir)
        if self.session_state["targets"]:
            _kconfig.set_active_target(self.session_state["targets"][0])
        self._refresh_header()
        self._refresh_footer()
        self.set_interval(1.0, self._refresh_header)  # live clock (turn 9a)
        self._render_idle()
        self.query_one("#goal", Input).focus()

    # --- header / footer -------------------------------------------------
    def _model_label(self) -> str:
        from kratos.llm_config import get_active_llm_model

        return get_active_llm_model()

    # --- display-zone time formatting (all via kratos.utils.timeutil) ----
    def _now_time(self) -> str:
        """Live wall-clock HH:MM in the resolved display zone."""
        return timeutil.now_for_display("%H:%M", tz=self._display_tz)

    def _stamp_now(self) -> tuple[str, str]:
        """One instant, formatted as (HH:MM, full date) in the display zone --
        captured once so a message's time and its date-divider check can never
        straddle a second/day boundary."""
        u = timeutil.utc_now()
        return (
            timeutil.format_for_display(u, "%H:%M", tz=self._display_tz),
            timeutil.format_for_display(u, "%A, %B %d, %Y", tz=self._display_tz),
        )

    def _fmt_stored_time(self, value: Any) -> str:
        """A stored (UTC) instant rendered as HH:MM in the display zone --
        falls back to the raw string if unparseable (timeutil's own guard)."""
        return timeutil.format_for_display(value, "%H:%M", tz=self._display_tz)

    def _tz_label(self) -> str:
        # The resolved DISPLAY zone's abbreviation (not the system zone) -- so
        # it stays honest if an override is ever set. %Z on the display-zone
        # instant yields e.g. "EEST" / "+06" / "UTC".
        return timeutil.now_for_display("%Z", tz=self._display_tz) or "local"

    def _refresh_header(self) -> None:
        targets = self.session_state["targets"]
        target = targets[0] if targets else "(no target)"
        now = self._now_time()
        header = Text()
        header.append("KRATOS", style=f"bold {T.KRATOS_RED}")
        header.append("  ·  ", style=T.TEXT_GHOST)
        header.append(target, style=T.ACCENT)
        header.append("  ·  ", style=T.TEXT_GHOST)
        header.append("read-only", style=T.SAFE)
        header.append("  —  no state changes without approval", style=T.TEXT_FAINT)
        header.append("   ", style=T.TEXT_GHOST)
        # right-aligned clock via padding
        try:
            width = self.query_one("#appheader", Static).size.width or 80
        except Exception:  # noqa: BLE001
            width = 80
        clock = f"{now} {self._tz_label()}"
        left = header.plain
        pad = max(1, width - len(left) - len(clock) - 1)
        header.append(" " * pad)
        header.append(clock, style=T.TEXT_DIM)
        self.query_one("#appheader", Static).update(header)

    def _context_pct(self) -> int:
        # APPROXIMATE (documented as such): Kratos exposes no real token count.
        # Heuristic -- cumulative session chars vs. an assumed budget derived
        # from LLAMA_N_CTX * ~4 chars/token. Good enough to warn before a
        # compact (turn 7c); a future session can replace with real usage from
        # the LLM layer. See docs/kratos_mk2_tui.md.
        from kratos.llm_config import LLAMA_N_CTX

        budget_chars = max(1, LLAMA_N_CTX * 4)
        return min(100, int(100 * self._ctx_chars / budget_chars))

    def _refresh_footer(self) -> None:
        st = self.session_state
        pct = self._context_pct()
        bar_w = 10
        filled = int(bar_w * pct / 100)
        color = T.ATTENTION if pct >= 85 else T.TEXT_FAINTER
        footer = Text()
        footer.append(f"session {st['session_id']}", style=T.TEXT_FAINTER)
        footer.append("  ·  ", style=T.TEXT_GHOST)
        footer.append(str(st["backend"]), style=T.TEXT_FAINTER)
        footer.append("  ·  ", style=T.TEXT_GHOST)
        footer.append(f"target {st['targets'][0] if st['targets'] else '(none)'}", style=T.TEXT_FAINTER)
        footer.append("   ", style=T.TEXT_GHOST)
        footer.append("ctx ", style=T.TEXT_FAINTER)
        footer.append("█" * filled + "░" * (bar_w - filled), style=color)
        footer.append(f" {pct}%", style=color)
        if pct >= 85:
            footer.append(" · will compact soon", style=T.ATTENTION)
        self.query_one("#statusfooter", Static).update(footer)

    # --- log helpers -----------------------------------------------------
    @property
    def _log(self) -> RichLog:
        return self.query_one("#transcript", RichLog)

    def _emit(self, renderable: Any) -> None:
        """Write to the transcript from the EVENT LOOP (main-thread callers)."""
        self._log.write(renderable)

    def _emit_from_worker(self, renderable: Any) -> None:
        """Write to the transcript from a THREAD worker (on_step, etc.)."""
        self.app.call_from_thread(self._log.write, renderable)

    def _emit_bubble(self, renderable: Any, date_str: str) -> None:
        """Write a timed 'bubble' (a stamped header line, or a finding/result
        panel that already carries its own subtitle time), preceded by a date
        divider whenever the display-zone day changes. Every timestamped thing
        funnels through here so the divider fires exactly once per day.
        `date_str` is the display-zone full date. Event-loop callers only."""
        if date_str != self._last_day:
            self._last_day = date_str
            self._log.write(R.day_divider(date_str))
        self._log.write(renderable)

    def _emit_bubble_from_worker(self, renderable: Any, date_str: str) -> None:
        self.app.call_from_thread(self._emit_bubble, renderable, date_str)

    def _emit_stamped(self, left: Text, time_str: str, date_str: str) -> None:
        """A message HEADER (you> / Kratos:) with a fine-print trailing time."""
        self._emit_bubble(R.timestamped(left, time_str), date_str)

    def _emit_stamped_from_worker(self, left: Text, time_str: str, date_str: str) -> None:
        self._emit_bubble_from_worker(R.timestamped(left, time_str), date_str)

    def _you_header(self, text: str) -> Text:
        line = Text()
        line.append("you> ", style=f"bold {T.TEXT_DIM}")
        line.append(text, style=T.TEXT)
        return line

    def _kratos_header(self) -> Text:
        return Text("Kratos:", style=f"bold {T.KRATOS_RED}")

    def _render_idle(self) -> None:
        st = self.session_state
        from kratos.agent.tools import TOOL_REGISTRY

        self._emit(Text("KRATOS", style=f"bold {T.KRATOS_RED}"))
        grid = Text()
        grid.append("target      ", style=T.TEXT_FAINTER)
        grid.append(f"{st['targets'][0] if st['targets'] else '(none)'}\n", style=T.TEXT)
        grid.append("mode        ", style=T.TEXT_FAINTER)
        grid.append("read-only", style=T.SAFE)
        grid.append(" — no state changes without explicit approval\n", style=T.TEXT_DIM)
        grid.append("tools       ", style=T.TEXT_FAINTER)
        grid.append(f"{len(TOOL_REGISTRY)} loaded\n", style=T.TEXT)
        self._emit(grid)
        if st["resume_context"]:
            self._emit(Text("— resumed prior context loaded —", style=T.TEXT_FAINTER))
        self._emit(
            Text(
                "Describe what to investigate. Kratos reasons through it step by step "
                "and asks before anything critical.",
                style=T.TEXT_FAINT,
            )
        )
        # First-run tips (turn 10b): shown once per session start, harmless to repeat.
        self._emit(Text("Tips:  Ctrl+P commands · /report summary · /help all commands · esc interrupts", style=T.TEXT_GHOST))
        self._emit(Text(""))

    # --- input -----------------------------------------------------------
    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        if not text:
            return
        if self._busy:
            self.notify("A turn is already running — press esc to interrupt it first.", timeout=3)
            return
        # echo the user's line (with a trailing timestamp / date divider)
        t, d = self._stamp_now()
        self._emit_stamped(self._you_header(text), t, d)
        self._store.touch_session(self.session_state["session_id"])
        if text.startswith("/"):
            self._dispatch_slash(text)
        else:
            self._run_goal(text)

    # --- slash dispatch --------------------------------------------------
    def _dispatch_slash(self, text: str) -> None:
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd in ("/exit", "/quit"):
            self.app.exit()
        elif cmd == "/help":
            self.app.push_screen(HelpModal())
        elif cmd == "/report":
            self._render_report()
        elif cmd == "/clear":
            self.session_state["resume_context"] = ""
            self._ctx_chars = 0
            self._refresh_footer()
            self._emit(R.success_line("Conversation context cleared for this session."))
        elif cmd == "/reset":
            self._reset_flow()
        elif cmd == "/delete":
            self._delete_flow()
        elif cmd == "/rename":
            self._rename_flow(rest)
        elif cmd == "/target":
            self._target_flow(rest)
        elif cmd == "/model":
            self._model_flow()
        elif cmd == "/timezone":
            self._cmd_timezone(rest)
        elif cmd == "/evolve":
            self._evolve_flow(rest)
        elif cmd == "/settings":
            self._emit(R.note_line("/settings is not implemented yet — per-tool approval policy is a separate design pass."))
        elif cmd in ("/scan", "/logs-parse", "/findings-generate", "/run"):
            self._emit(R.note_line(f"{cmd} (deterministic shortcut) isn't ported to the TUI yet — see docs/kratos_mk2_tui.md."))
        else:
            # Unmatched /-prefix falls through to a goal (matches classic REPL).
            self._run_goal(text)

    # --- /report (turn 4a) ----------------------------------------------
    def _render_report(self) -> None:
        findings = self._collect_session_findings()  # list of (finding, when)
        self._emit(Text(""))
        if not findings:
            self._emit(R.result_panel("Report — no findings", "No findings recorded in this session yet. Run an investigation first, or the target is clean so far.", T.SAFE))
            return
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda fw: order.get(str(fw[0].get("severity", "info")).lower(), 5))
        t, d = self._stamp_now()
        self._emit_stamped(self._kratos_header(), t, d)
        self._emit(Text(f"investigation summary — {len(findings)} finding(s), high → low severity", style=T.TEXT_MUTED))
        for f, when_value in findings:
            # Each finding keeps the time it was ORIGINALLY found (its turn's
            # completion time, a stored UTC value), rendered in the display
            # zone -- not when /report was run.
            self._emit(R.finding_panel(f, time_str=self._fmt_stored_time(when_value)))

    def _collect_session_findings(self) -> list[tuple[dict[str, Any], str | None]]:
        """Aggregate correlate_findings output across this session's turns'
        saved transcripts, each paired with the RAW stored (UTC) time the turn
        completed -- formatting into the display zone happens at render time
        via timeutil. Same data path mcp_server.py::kratos_get_findings uses
        (findings live in the turn transcript, produced by correlate_findings).
        New UI (/report), pre-existing data."""
        out: list[tuple[dict[str, Any], str | None]] = []
        for turn in self._store.get_goal_history(self.session_state["session_id"]):
            ref = turn.get("transcript_ref")
            if not ref:
                continue
            try:
                transcript = json.loads(Path(ref).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            when_value = turn.get("completed_at") or turn.get("started_at")
            for step in transcript:
                if step.get("tool") != "correlate_findings":
                    continue
                result, _status = R.unwrap_tool_result(step.get("observation"))
                if isinstance(result, dict) and isinstance(result.get("findings"), list):
                    out.extend((f, when_value) for f in result["findings"])
        return out

    # --- /timezone (display-only override; storage stays UTC) ------------
    def _cmd_timezone(self, rest: str) -> None:
        """/timezone            -> show the current display zone + how it was resolved
           /timezone auto       -> clear any override, use the auto-detected system zone
           /timezone <Zone>     -> pin a display zone (e.g. UTC, Europe/Helsinki, Asia/Dhaka)
        Display-only: this never touches stored times (always UTC), it only
        changes how they're SHOWN. Re-resolves this session's display zone live
        and refreshes the header; the next message re-emits a date divider in
        the new zone (a day boundary can move). Persisted via timeutil so future
        launches and the launch chooser agree."""
        arg = rest.strip()
        if not arg:
            source, tz = timeutil.display_tz_status(self._data_dir)
            name = getattr(tz, "key", None) or self._tz_label()
            self._emit(R.note_line(
                f"Display timezone: {name} ({source}). Change with /timezone <Zone> or /timezone auto."
            ))
            return
        if arg.lower() == "auto":
            timeutil.set_display_timezone_override(self._data_dir, None)
            self._apply_timezone_change()
            self._emit(R.success_line(f"Display timezone: auto ({timeutil.local_tz_name() or 'system local'})."))
            return
        if timeutil.zone_from_name(arg) is None:
            self._emit(R.error_line(f"{arg!r} isn't a known timezone (try UTC, Europe/Helsinki, Asia/Dhaka, …)."))
            return
        timeutil.set_display_timezone_override(self._data_dir, arg)
        self._apply_timezone_change()
        self._emit(R.success_line(f"Display timezone set to {arg} — stored times now shown in this zone."))

    def _apply_timezone_change(self) -> None:
        self._display_tz = timeutil.resolve_display_tz(self._data_dir)
        self._last_day = None  # force a fresh date divider in the new zone
        self._refresh_header()

    # --- /reset, /delete (native confirm modals) -------------------------
    @work
    async def _reset_flow(self) -> None:
        ok = await self.app.push_screen_wait(
            ConfirmModal(
                "Reset session history",
                "Archives this session's stored history and clears its context. The prior "
                "history is NOT deleted — it stays recoverable — but this session will present "
                "as a blank slate going forward.",
            )
        )
        if not ok:
            self._emit(R.note_line("Reset cancelled — nothing changed."))
            return
        self._store.archive_goal_history(self.session_state["session_id"])
        self.session_state["resume_context"] = ""
        self._ctx_chars = 0
        self._refresh_footer()
        self._emit(R.success_line("Session history archived — starting fresh from here."))

    @work
    async def _delete_flow(self) -> None:
        ok = await self.app.push_screen_wait(
            ConfirmModal(
                "Delete this session",
                "Archives (soft-deletes) this session. It's hidden from the normal picker, "
                "but retained and recoverable from the picker's archived view.",
            )
        )
        if not ok:
            self._emit(R.note_line("Delete cancelled — session continues normally."))
            return
        self._store.archive_session(self.session_state["session_id"])
        self.app.pop_screen()  # back to the launch chooser (it refreshes on resume)

    # --- /rename (turn 8b) ----------------------------------------------
    @work
    async def _rename_flow(self, rest: str) -> None:
        name = rest.strip()
        if not name:
            name = await self.app.push_screen_wait(PromptModal("Rename session", "New name"))
            if name is None:
                return
            name = name.strip()
        if not name:
            self._emit(R.note_line("No name given — nothing changed."))
            return
        if name.isdigit() or name.lower() in ("q", "n", "a", "m"):
            self._emit(R.error_line(f"Can't use {name!r} — it would collide with a chooser command/row number."))
            return
        if self._store.get_session(name) is not None:
            self._emit(R.error_line(f"Can't use {name!r} — it's already a real session ID."))
            return
        if self._store.name_taken(name, exclude_session_id=self.session_state["session_id"]):
            self._emit(R.error_line(f"Can't use {name!r} — another session already has that name."))
            return
        self._store.rename_session(self.session_state["session_id"], name)
        self._emit(R.success_line(f"Session renamed to {name!r}."))

    # --- /target ---------------------------------------------------------
    @work(thread=True)
    def _target_flow(self, rest: str) -> None:
        rest = rest.strip()
        if rest == "verify":
            self._probe_target()
            return
        if not rest:
            current = ", ".join(self.session_state["targets"]) or "(none set)"
            self._emit_from_worker(R.note_line(f"Current target(s): {current}"))
            return
        targets = rest.split()
        self.session_state["targets"] = targets
        self._store.set_targets(self.session_state["session_id"], targets)
        _kconfig.set_active_target(targets[0])
        self.app.call_from_thread(self._refresh_header)
        self.app.call_from_thread(self._refresh_footer)
        if len(targets) > 1:
            self._emit_from_worker(
                R.note_line(
                    f"Using {targets[0]} — multi-target execution isn't implemented yet, so the "
                    f"other {len(targets) - 1} target(s) are stored but unused."
                )
            )
        self._emit_from_worker(R.success_line(f"Target(s) set: {', '.join(targets)}"))
        self._show_target_setup(targets[0])

    def _show_target_setup(self, target_host: str) -> None:
        from kratos.adapters import target_setup as _ts
        from rich.panel import Panel
        from rich.syntax import Syntax

        checklist = _ts.generate_target_setup_checklist(target_host)
        self._emit_from_worker(
            Panel(
                Syntax(checklist, "bash", word_wrap=False, background_color="default"),
                title="Target setup — run these ON the target (Kratos never runs them)",
                title_align="left",
                border_style=T.ATTENTION,
            )
        )
        self._probe_target()

    def _probe_target(self) -> None:
        from kratos.adapters.ssh_remote import run_target_probe_checks, SSHResult
        from rich.table import Table

        result = run_target_probe_checks()
        if isinstance(result, SSHResult):
            self._emit_from_worker(R.error_line(f"Could not reach target to verify setup: {(result.stderr or result.stdout).strip()}"))
            return
        table = Table(show_header=True, header_style="bold", title="Target setup check")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        colors = {"PASS": T.SAFE, "FAIL": T.CRITICAL, "UNKNOWN": T.ATTENTION}
        for c in result:
            table.add_row(c["check"], Text(c["status"], style=colors.get(c["status"], T.TEXT)), c["detail"])
        self._emit_from_worker(table)

    # --- /model (turn 16c) ----------------------------------------------
    @work
    async def _model_flow(self) -> None:
        from kratos.adapters import llm_profiles as _llm_profiles
        from kratos.llm_config import ENV_FILE_PATH

        candidates, current = _llm_profiles.list_candidate_profiles(ENV_FILE_PATH)
        if not candidates:
            self._emit(R.note_line("No LLM profiles found in .env."))
            return
        entries = []
        for c in candidates:
            marker = "  (active)" if current is not None and c.model == current.model else ""
            entries.append((c, f"{c.model}{marker}"))
        picked = await self.app.push_screen_wait(
            ListPickerModal("Switch LLM backend", entries, subtitle=f"Active: {self.session_state['backend']}")
        )
        if picked is None:
            return
        if current is not None and picked.model == current.model:
            self._emit(R.note_line(f"{picked.model} is already active — no change."))
            return
        self._apply_model_switch(picked, current)

    @work(thread=True)
    def _apply_model_switch(self, target: Any, current: Any) -> None:
        from kratos.adapters import llm_profiles as _llm_profiles
        from kratos.llm_config import ENV_FILE_PATH, set_active_llm_profile
        from kratos.llm_interface import check_endpoint_reachable

        problems = _llm_profiles.validate_profile(target)
        if problems:
            self._emit_from_worker(R.error_line(f"Can't switch to {target.model}: {'; '.join(problems)}"))
            return
        self._emit_from_worker(R.note_line(f"Checking {target.model} is reachable…"))
        reachable, detail = check_endpoint_reachable(target.values["LLM_BASE_URL"], target.values["LLM_API_KEY"])
        if not reachable:
            self._emit_from_worker(R.error_line(f"Can't switch to {target.model} — endpoint not reachable ({detail})."))
            return
        set_active_llm_profile(target.values)
        _llm_profiles.switch_profile(ENV_FILE_PATH, target, current)
        self.session_state["backend"] = target.model
        self.app.call_from_thread(self._refresh_footer)
        self._emit_from_worker(R.success_line(f"Switched to {target.model} — active now, and set as default in .env."))

    # --- /evolve ---------------------------------------------------------
    @work
    async def _evolve_flow(self, rest: str) -> None:
        stripped = rest.strip()
        if stripped.lower() in ("list", "ls"):
            self._render_evolve_list()
            return
        idea = stripped.strip('"').strip("'").strip()
        pending_name = None
        if not idea:
            pending = self.session_state.get("pending_evolve_suggestion")
            if not pending:
                self._emit(R.note_line('No pending suggestion. Use /evolve "<your idea>" to propose one.'))
                return
            idea = f"{pending.get('name', '')}: {pending.get('description', '')}".strip(": ")
            pending_name = pending.get("name") or None

        default_name = pending_name or self._slug(idea)
        name = await self.app.push_screen_wait(PromptModal("Name this tool", "snake_case", initial=default_name))
        if name is None:
            return
        tool_name = self._slug(name) or default_name

        default_path = f"tests/self_write_harnesses/test_{tool_name}.py"
        harness = await self.app.push_screen_wait(
            PromptModal("Test harness file", "Path to a human-authored pytest harness", initial=default_path)
        )
        if harness is None:
            return
        harness_path = Path(harness.strip() or default_path)
        if not harness_path.exists():
            self._emit(R.error_line(f"No test file at {harness_path} — evo-loop needs a human-authored harness. Create it, then /evolve again."))
            self._emit(R.note_line("(The classic REPL's LLM-drafted-harness helper isn't ported to the TUI yet — see docs/kratos_mk2_tui.md.)"))
            return
        self._run_evolve(idea, harness_path, tool_name)

    def _slug(self, text: str) -> str:
        import re

        words = re.findall(r"[a-z0-9]+", text.lower())[:4]
        return "_".join(words)

    def _render_evolve_list(self) -> None:
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata
        from rich.table import Table

        metadata = _read_metadata(KEPT_TOOLS_DIR)
        table = Table(show_header=True, header_style="bold", title=f"Tools reachable by the agent ({len(TOOL_REGISTRY)})")
        table.add_column("Name")
        table.add_column("Kind")
        table.add_column("Approval")
        table.add_column("Description")
        for name in sorted(TOOL_REGISTRY):
            tool = TOOL_REGISTRY[name]
            is_kept = name in metadata
            desc = (tool.description.strip().splitlines() or [""])[0][:70]
            table.add_row(
                name,
                Text("kept" if is_kept else "built-in", style=T.ACCENT if is_kept else T.TEXT_FAINTER),
                "yes" if tool.requires_approval else "no",
                desc,
            )
        self._emit(table)

    @work(thread=True)
    def _run_evolve(self, idea: str, harness_path: Path, tool_name: str) -> None:
        from kratos.agent.self_write import WriteRequest
        from kratos.agent.self_write_loop import run_self_write_loop

        self._set_busy(True)
        self._emit_from_worker(R.note_line(f"Starting evo-loop (minutes per attempt) — goal: {idea!r}"))
        try:
            outcome = run_self_write_loop(WriteRequest(goal=idea, test_file=harness_path))
        except Exception as e:  # noqa: BLE001
            self._emit_from_worker(R.error_line(f"Evo-loop errored: {e}"))
            self._set_busy(False)
            return
        self.session_state["pending_evolve_suggestion"] = None
        if outcome.status == "approved":
            kd = outcome.keep_decision
            self._emit_from_worker(R.success_line(f"Kept: {kd.tool_name} (requires_approval={kd.requires_approval}) — available now."))
        elif outcome.status == "denied":
            self._emit_from_worker(R.note_line("Evo-loop finished — a candidate passed testing but was not kept."))
        else:
            self._emit_from_worker(R.error_line(f"Evo-loop did not produce an approvable candidate (status: {outcome.status})."))
        self._set_busy(False)

    # --- goal handling: chat vs investigate ------------------------------
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy

    @work(thread=True, exclusive=True, group="turn")
    def _run_goal(self, goal: str) -> None:
        from kratos.cli.repl import _route_input

        self._set_busy(True)
        try:
            should_investigate, second = _route_input(goal, self.session_state.get("resume_context", ""))
        except Exception as e:  # noqa: BLE001
            self._emit_from_worker(R.error_line(f"Routing failed: {e}"))
            self._set_busy(False)
            return

        if should_investigate is None:
            self._emit_from_worker(R.error_line(f"Could not reach the language model — {second or 'no detail'}"))
            self._set_busy(False)
            return

        if not should_investigate:
            t, d = self._stamp_now()
            self._emit_stamped_from_worker(self._kratos_header(), t, d)
            self._emit_from_worker(Text(second or "(no reply)", style=T.TEXT))
            self._log_chat_turn(goal, second or "")
            self._ctx_chars += len(goal) + len(second or "")
            self.app.call_from_thread(self._refresh_footer)
            self._set_busy(False)
            return

        self._run_investigation(goal)
        self._set_busy(False)

    def _run_investigation(self, goal: str) -> None:
        from kratos.agent.loop import run_agent

        self._emit_from_worker(R.note_line(f"Starting investigation (up to {REPL_MAX_ITERS} steps)…"))
        turn_id = self._store.start_turn(self.session_state["session_id"], goal)
        started = time.monotonic()
        worker = get_current_worker()

        def _on_step(step: dict) -> None:
            if worker.is_cancelled:
                raise _CancelInvestigation()
            self._render_step(step)

        try:
            result = run_agent(goal, self._data_dir, max_iters=REPL_MAX_ITERS, on_step=_on_step)
        except _CancelInvestigation:
            self._store.complete_turn(turn_id, "cancelled", transcript_ref=None)
            self._emit_from_worker(R.note_line("Interrupted — nothing was left running on the target. Type a new goal to continue."))
            self._append_outcome(goal, "cancelled")
            return
        except Exception as e:  # noqa: BLE001
            self._store.complete_turn(turn_id, "error", transcript_ref=None)
            self._emit_from_worker(R.error_line(f"Investigation errored: {e}"))
            return

        duration = time.monotonic() - started
        # The conclusion panel carries its own in-bubble timestamp (subtitle),
        # so no separate stamped "Kratos:" header here -- one time per bubble.
        t, d = self._stamp_now()
        if result["status"] == "final_answer":
            self._emit_bubble_from_worker(R.result_panel("Kratos — investigation complete", result["final_answer"], T.SAFE, time_str=t), d)
            status = "final_answer"
        elif result["status"] == "max_iters_reached" and result.get("final_answer"):
            self._emit_bubble_from_worker(R.result_panel("Kratos — investigation incomplete (step limit)", result["final_answer"], T.ATTENTION, time_str=t), d)
            status = "max_iters_reached"
        else:
            self._emit_from_worker(R.error_line(f"Investigation stopped: {result['status']}"))
            status = str(result["status"])
        self._emit_from_worker(Text(f"Done in {duration:.0f}s", style=T.TEXT_FAINTER))

        transcript_path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        transcript_path.write_text(json.dumps(result.get("transcript", []), indent=2, default=str), encoding="utf-8")
        self._store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))
        self._append_outcome(goal, status)
        self._ctx_chars += len(goal) + len(result.get("final_answer", "") or "")
        self.app.call_from_thread(self._refresh_footer)

    def _render_step(self, step: dict) -> None:
        tool_name = step.get("tool")
        if tool_name:
            result, effective_status = R.unwrap_tool_result(step.get("observation"))
            if effective_status == "error":
                err = result.get("observation") if isinstance(result, dict) else None
                self._emit_from_worker(R.error_line(f"{tool_name} failed — {err or 'no error detail'}"))
            elif tool_name == "correlate_findings" and isinstance(result, dict) and result.get("findings"):
                findings = result["findings"]
                line = Text()
                line.append("✓ ", style=T.SAFE)
                line.append(tool_name, style=f"bold {T.ACCENT}")
                line.append(f"  correlated findings ({len(findings)} found)", style=T.TEXT_MUTED)
                self._emit_from_worker(line)
                for f in findings:
                    t, d = self._stamp_now()
                    self._emit_bubble_from_worker(R.finding_panel(f, time_str=t), d)
            else:
                self._emit_from_worker(R.tool_call_line(tool_name, effective_status))
        elif step.get("tool_proposal"):
            proposal = step["tool_proposal"]
            self.session_state["pending_evolve_suggestion"] = proposal
            body = (
                f"{proposal.get('name', '')}\n{proposal.get('description', '')}\n\n"
                'Run /evolve to have Kratos build this (needs a test harness).'
            )
            self._emit_from_worker(R.result_panel("Evo-loop suggestion", body, T.ATTENTION))

    def _append_outcome(self, goal: str, status: str) -> None:
        line = f"- Goal: {goal!r} -> {status}"
        self.session_state["resume_context"] = (self.session_state.get("resume_context", "") + "\n" + line).strip()

    def _log_chat_turn(self, goal: str, reply: str) -> None:
        turn_id = self._store.start_turn(self.session_state["session_id"], goal)
        path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        path.write_text(json.dumps([{"final_answer": reply}], indent=2), encoding="utf-8")
        self._store.complete_turn(turn_id, "chat_reply", transcript_ref=str(path))
        self._append_outcome(goal, "chat_reply")

    def _transcripts_dir(self) -> Path:
        d = self._data_dir / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # --- bindings --------------------------------------------------------
    def action_interrupt(self) -> None:
        if self._busy:
            self.workers.cancel_group(self, "turn")
            self._emit(R.note_line("Interrupting at the next step boundary…"))

    @work
    async def action_palette(self) -> None:
        chosen = await self.app.push_screen_wait(CommandPaletteModal(_PALETTE_COMMANDS))
        if chosen:
            t, d = self._stamp_now()
            self._emit_stamped(self._you_header(chosen), t, d)
            self._dispatch_slash(chosen)

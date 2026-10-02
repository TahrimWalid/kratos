"""
Session screen -- the main workspace: idle state, live investigation, the
command palette, interrupt/re-run, the context meter, the header clock,
plus /help, /report, /model, /rename, and recommend-only remediation
commands.

Every mechanism used here already exists in Kratos:
  - agent/loop.py::run_agent + its on_step hook drive the live investigation,
  - llm routing (chat vs investigate) reuses cli/repl.py::_route_input,
  - persistence reuses storage/session_store.py exactly as the classic REPL does,
  - approvals reach a Textual modal via agent/tools.py's provider hook.

Investigation and evo-loop run on THREAD workers (run_agent is blocking); the UI
is only ever touched from the event loop via call_from_thread.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Input, RichLog, Static
from textual.worker import get_current_worker

from kratos import kratos_config as _kconfig
from kratos.agent import target_lock as _target_lock
from kratos.storage.session_store import SessionStore
from kratos.utils import timeutil
from kratos.tui_mk2 import render as R
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.workers import ResilientWorkerHost
from kratos.tui_mk2.modals import (
    CommandPaletteModal,
    ConfirmModal,
    HelpModal,
    ListPickerModal,
    PlanPreviewModal,
    PromptModal,
)

REPL_MAX_ITERS = 7  # matches cli/repl.py::REPL_MAX_ITERS -- a REPL turn is bounded/cheap
# Transcript panels share one width: the column, but never wider than this
# (long lines are hard to read).
_PANEL_MAX_WIDTH = 100
# A vuln sweep legitimately needs nmap + vuln + config
# + correlate_findings + conclude = 5 steps with ZERO slack, so any single
# rejected-early-conclusion (guard 1) pushed correlate_findings out of budget and
# the run concluded without the correlation engine ever running. 7 leaves room.
FULL_RESUME_DETAILED_TURN_CAP = 5  # matches cli/repl.py -- only the most recent N turns replay in full
CHAT_COMPACTION_KEEP_RECENT = 3    # turns kept verbatim on /compact (matches loop.py's investigation compactor)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")  # strip terminal control codes from captured output
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"  # braille spinner frames for the "working…" activity line

_PALETTE_COMMANDS = [
    ("/run", "standard audit — deterministic security sweep of the target (no LLM)"),
    ("/plan", "preview a run's steps before it runs (or /plan gate on|off)"),
    ("/preset-new", "save a reusable investigation (guided: goal, or a tool pipeline)"),
    ("/preset-describe", "describe a pipeline in words → Kratos drafts it for review"),
    ("/preset-run", "run a saved investigation or pipeline (pick from a list)"),
    ("/preset-scaffold", "write an editable pipeline-preset template file"),
    ("/preset-list", "list saved investigations"),
    ("/preset-show", "show a preset's full definition (steps, target, missing tools)"),
    ("/preset-edit", "edit a saved goal, or a pipeline's steps (pick from a list)"),
    ("/preset-delete", "delete a saved investigation (pick from a list)"),
    ("/preset-export", "show a preset's file to share/back up (pick from a list)"),
    ("/preset-import", "import a preset from a .toml file"),
    ("/report", "investigation summary — findings by severity"),
    ("/schedule", "run an audit/preset on a cadence + deliver the report (systemd)"),
    ("/trigger", "if a finding is detected → notify / show playbook / investigate"),
    ("/doctor", "self-diagnostic — LLM, target setup, and tools health"),
    ("/usage", "token usage + estimated cost this session (local = free)"),
    ("/context", "what's currently loaded in the context window"),
    ("/investigate-host", "investigate THIS Kratos host itself (not the target)"),
    ("/evolve", "write a new tool for the current gap  (/evolve help: how it works)"),
    ("/tools", "list the tools Kratos can use, by kind"),
    ("/use", "run ONE specific tool directly (deterministic, no model)"),
    ("/guide", "getting started — the first steps, in plain language"),
    ("/help", "list all commands"),
    ("/model", "switch / add / edit / delete LLM backends"),
    ("/timezone", "show / set the display timezone (storage stays UTC)"),
    ("/target", "set, change, or verify the active target"),
    ("/rename", "name this session"),
    ("/compact", "summarize the conversation to free context (keeps memory)"),
    ("/clear", "clear the screen + working context (history kept)"),
    ("/reset", "wipe screen + archive history, start fresh"),
    ("/delete", "archive (soft-delete) this session"),
    ("/sessions", "back to the session picker (keeps this session)"),
    ("/settings", "settings — models, tool approvals, timezone"),
    ("/subagent", "add / manage sub-agents — pair a target for read-only telemetry"),
    ("/whitelist", "a paired target's allowlist — add/edit entries, opt-in, typed-EXECUTE dispatch"),
    ("/run-fix", "run the last recommended command via the target's sub-agent (if it's in the allowlist)"),
    ("/preview", "Phase 2 design shells (not wired) — sub-agent / Tailscale / execution UI"),
    ("/exit", "leave the session"),
]


# Forgotten-slash safety net: bare words that are UNAMBIGUOUSLY a command (they
# would essentially never begin a real investigation goal or an English sentence)
# AND whose command is non-destructive. A line starting with one of these is
# treated as the slash command the user meant, with a one-line hint. DELIBERATELY
# EXCLUDES: verb-like/ambiguous words that can legitimately start a goal (run,
# use, report, scan, host, model, preview) -- those stay with the LLM router,
# whose capability-aware nudge points to the slash command when appropriate, so
# the two layers fire on DISJOINT inputs and never fight; and destructive/heavy
# commands (clear, reset, delete, rename, compact) -- never auto-run from a typo.
_BARE_COMMAND_WORDS = frozenset({
    "preset", "presets",
    "preset-new", "preset-list", "preset-ls", "preset-run", "preset-edit",
    "preset-delete", "preset-del", "preset-show", "preset-scaffold",
    "preset-export", "preset-import", "preset-describe",
    "doctor", "health", "usage", "context", "tools", "evolve", "help",
    "settings", "timezone",
})


# Sentinel distinguishing "user cancelled this step" from "" (always-run / no
# condition) in the guided pipeline-step condition picker.
_CANCELLED = object()


class _CancelInvestigation(Exception):
    """Raised inside on_step when the user pressed esc -- lets run_agent unwind
    at a step boundary (a blocking LLM/tool call can't be interrupted mid-call,
    so 'interrupted — N of ~M steps' is honest about where it stopped)."""


class SessionScreen(ResilientWorkerHost, Screen):
    BINDINGS = [
        Binding("escape", "interrupt", "interrupt", show=True),
        # ctrl+c also stops the current response, a conventional stop-the-
        # current-response affordance. priority so it overrides Textual's
        # default ctrl+c quit; a no-op when
        # idle (nothing running) rather than quitting — leave the session with
        # /exit or q at the chooser.
        Binding("ctrl+c", "interrupt", "stop", show=False, priority=True),
        Binding("ctrl+p", "palette", "commands", show=True),
        Binding("ctrl+y", "copy_last", "copy answer", show=True),
        # Edit a previous turn: ↑/↓ recall prior turns into the
        # prompt for editing; resending a recalled turn discards it and
        # everything after (see on_input_submitted). Arrow-key history recall
        # is used instead of a double-esc gesture -- more idiomatic and doesn't
        # collide with esc=interrupt, same spirit as the cursor-vs-number-keys
        # chooser adaptation.
        Binding("up", "history_prev", "prev turn", show=False),
        Binding("down", "history_next", "next turn", show=False),
        # Re-run the last goal (e.g. after interrupting one). A
        # true mid-loop "resume" isn't possible (run_agent has no checkpoint),
        # so this honestly re-runs the same goal fresh.
        Binding("ctrl+r", "rerun", "re-run last", show=True),
        # Leave this conversation and return to the session picker (start page).
        # Confirm-gated so it's never a single-keystroke exit from an active
        # session; the session is kept and stays resumable (unlike /delete).
        Binding("ctrl+b", "back_to_sessions", "sessions", show=True),
    ]

    CSS = f"""
    SessionScreen #transcript {{
        height: 1fr;
        background: {T.BG};
        padding: 0 2;
        scrollbar-size-vertical: 1;
    }}
    SessionScreen #goal {{ height: 3; margin: 0 1; }}
    SessionScreen #activity {{ height: 1; margin: 0 2; color: {T.ACCENT}; }}
    """

    def __init__(
        self,
        store: SessionStore,
        data_dir: Path,
        session_id: str,
        targets: list[str],
        resume_context: str,
        full_replay: bool = False,
    ) -> None:
        super().__init__()
        self._store = store
        self._data_dir = data_dir
        self._full_replay = full_replay
        self.session_state: dict[str, Any] = {
            "session_id": session_id,
            "targets": targets,
            "resume_context": resume_context,
            "backend": self._model_label(),
            "pending_evolve_suggestion": None,
        }
        self._busy = False
        # Live "working…" activity indicator (spinner + elapsed) shown while a
        # turn runs — covers the silent gap before the first output, especially
        # for slower thinking models. Driven by a single event-loop interval
        # that reads the busy flag (thread-safe; workers only set the flag).
        self._busy_since: float | None = None
        self._spin_i = 0
        self._activity_active = False
        self._ctx_chars = len(resume_context)
        self._last_day: str | None = None  # for the date divider (WhatsApp-style)
        self._last_answer = ""             # most recent Kratos answer/reply, for ctrl+y copy
        self._last_commands: list[str] = []  # recommended commands from the last turn, for ctrl+y
        # Recommended commands from the last turn that match an ENABLED
        # allowlist entry on the target's paired sub-agent -- what /run-fix offers.
        self._runnable_fixes: list[dict[str, Any]] = []
        self._last_target_commands: list[dict[str, Any]] = []
        # ↑/↓ non-destructive message-history recall state (shell-style):
        self._hist_turns: list[dict[str, Any]] | None = None  # loaded lazily on first ↑
        self._hist_index = 0               # position within _hist_turns; == len means "composing new"
        self._pre_recall_draft = ""        # the in-progress input saved when recall started
        self._last_goal = ""               # most recent goal, for ctrl+r re-run
        # Resolved once in on_mount (override > system-local > UTC) and passed
        # to every timeutil format call, so live times, resumed/stored times,
        # and the header clock all render in the SAME display zone. Storage
        # stays UTC -- this is display-only (see kratos.utils.timeutil).
        self._display_tz = None
        # Optional user name (General settings): when set, the prompt label is
        # "<name>>" instead of "you>". Loaded in on_mount, live-updatable.
        self._user_name = ""

    # --- layout ----------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Static(id="appheader")
        with Vertical():
            # min_width: RichLog lays renderables out at >= 78 columns by default,
            # which clips the right edge of every panel on an 80-column terminal
            # (the log itself is narrower than the terminal).
            yield RichLog(id="transcript", wrap=True, markup=False, highlight=False, min_width=40)
        yield Static("", id="activity")  # live "working…" spinner while a turn runs
        yield Input(placeholder="Describe what to investigate…", id="goal")
        yield Static(id="statusfooter")

    def on_mount(self) -> None:
        from kratos import llm_interface

        llm_interface.reset_session_token_usage()  # fresh cumulative accounting for this session
        self._display_tz = timeutil.resolve_display_tz(self._data_dir)
        self._user_name = (_kconfig.load_local_config(self._data_dir).get("user_name") or "").strip()
        if self.session_state["targets"]:
            _kconfig.set_active_target(self.session_state["targets"][0])
        self._refresh_header()
        self._refresh_footer()
        self.set_interval(1.0, self._refresh_header)  # live clock
        self.set_interval(0.12, self._tick_activity)  # "working…" spinner while busy
        self._render_idle()
        if self._full_replay:
            self._render_full_replay()
        self.query_one("#goal", Input).focus()
        self._maybe_timezone_fallback()  # only fires if auto-detect failed

    # --- one-time manual timezone entry when auto-detect fails ---
    @work
    async def _maybe_timezone_fallback(self) -> None:
        source, _tz = timeutil.display_tz_status(self._data_dir)
        if source != "fallback":
            return  # normal case: system zone detected, nothing to ask
        config = _kconfig.load_local_config(self._data_dir)
        if config.get("tz_fallback_prompted"):
            return  # one-time only, never nags again
        _kconfig.save_local_config(self._data_dir, tz_fallback_prompted=True)
        answer = await self.app.push_screen_wait(
            PromptModal(
                "Timezone couldn't be auto-detected",
                "Enter a zone (e.g. Asia/Dhaka, Europe/Helsinki, UTC), or leave blank to use UTC",
            )
        )
        if answer and timeutil.zone_from_name(answer.strip()):
            timeutil.set_display_timezone_override(self._data_dir, answer.strip())
            self._apply_timezone_change()
            self._emit(R.success_line(f"Display timezone set to {answer.strip()}."))
        else:
            self._emit(R.note_line("Using UTC for display. Change anytime with /timezone <zone>."))

    def action_copy_last(self) -> None:
        # Copy Kratos's most recent answer/reply to the clipboard
        # (via the terminal's OSC-52, Textual's copy_to_clipboard) with a
        # transient confirmation. If the last turn produced recommended
        # commands, those are copied instead (joined one per line).
        if self._last_commands:
            self.app.copy_to_clipboard("\n".join(self._last_commands))
            self.notify(f"Copied {len(self._last_commands)} recommended command(s) to the clipboard.", timeout=3)
            return
        if not self._last_answer.strip():
            self.notify("Nothing to copy yet — run a goal first.", timeout=3)
            return
        self.app.copy_to_clipboard(self._last_answer)
        self.notify("Copied Kratos's last answer to the clipboard.", timeout=3)

    # --- ↑/↓ non-destructive message history recall (shell-style) --------
    def action_history_prev(self) -> None:
        """↑ -- recall an earlier message into the prompt (shell-history style).
        First press snapshots the current draft and jumps to the latest prior
        message; further presses go older. Non-destructive: sending is always a
        fresh turn and never discards history (to fix a message that's mid-reply,
        press esc/Ctrl+C to stop, then type)."""
        if self._busy:
            return
        inp = self.query_one("#goal", Input)
        if self._hist_turns is None:
            self._hist_turns = self._store.get_goal_history(self.session_state["session_id"])
            self._hist_index = len(self._hist_turns)
            self._pre_recall_draft = inp.value
        if not self._hist_turns or self._hist_index == 0:
            return
        self._hist_index -= 1
        inp.value = self._hist_turns[self._hist_index]["goal"]
        inp.cursor_position = len(inp.value)

    def action_history_next(self) -> None:
        """↓ -- move toward newer messages, and past the newest back to the draft
        you were composing."""
        if self._busy or self._hist_turns is None:
            return
        inp = self.query_one("#goal", Input)
        if self._hist_index < len(self._hist_turns) - 1:
            self._hist_index += 1
            inp.value = self._hist_turns[self._hist_index]["goal"]
        else:
            self._hist_index = len(self._hist_turns)
            inp.value = self._pre_recall_draft
        inp.cursor_position = len(inp.value)

    def _reset_recall(self) -> None:
        self._hist_turns = None
        self._hist_index = 0
        self._pre_recall_draft = ""

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

    def _fmt_stored_date(self, value: Any) -> str:
        """A stored (UTC) instant rendered as a full date in the display zone."""
        return timeutil.format_for_display(value, "%A, %B %d, %Y", tz=self._display_tz)

    def _tz_label(self) -> str:
        # The resolved DISPLAY zone's abbreviation (not the system zone) -- so
        # it stays honest if an override is ever set. %Z on the display-zone
        # instant yields e.g. "EEST" / "+06" / "UTC".
        return timeutil.now_for_display("%Z", tz=self._display_tz) or "local"

    def on_resize(self, event) -> None:
        # The footer drops lower-priority parts to fit; re-fit at the new width.
        self.call_after_refresh(self._refresh_footer)

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
        # right-aligned clock via padding
        try:
            width = self.query_one("#appheader", Static).size.width or 80
        except Exception:  # noqa: BLE001
            width = 80
        clock = f"{now} {self._tz_label()}"
        tagline = "  —  no state changes without approval"
        # On a narrow terminal the tagline gives way before the clock does.
        if header.cell_len + len(tagline) + 3 + len(clock) + 1 <= width:
            header.append(tagline, style=T.TEXT_FAINT)
        header.append("   ", style=T.TEXT_GHOST)
        left = header.plain
        pad = max(1, width - len(left) - len(clock) - 1)
        header.append(" " * pad)
        header.append(clock, style=T.TEXT_DIM)
        self.query_one("#appheader", Static).update(header)

    def _context_pct(self) -> tuple[int, int, int, bool]:
        # Real token accounting: the last LLM call's prompt_tokens
        # vs the active model's context window. Returns (pct, used, window,
        # estimated). The window is MODEL-AWARE (get_context_window_tokens
        # tracks the live /model profile), so a /model switch rescales this live.
        #
        # Before the first real LLM call of the process (a fresh OR just-resumed
        # session), there is no measured usage. Rather than show 0 and then jump
        # to the real value on the first message -- confusing on a resumed
        # session, since it would look like the meter reset to 0 and then
        # suddenly jumped -- approximate the loaded working-context size
        # (~4 chars/token) so the meter reflects a resume's context
        # immediately. Marked `estimated` so the footer can show a ~.
        from kratos import llm_interface

        window = llm_interface.get_context_window_tokens() or 1
        usage = llm_interface.get_last_token_usage()
        if usage is not None:
            used, estimated = usage.prompt_tokens, False
        else:
            used = len(self.session_state.get("resume_context", "")) // 4
            estimated = used > 0
        return min(100, int(100 * used / window)), used, window, estimated

    @staticmethod
    def _fmt_tok(n: int) -> str:
        return f"{n / 1000:.1f}k" if n >= 1000 else str(n)

    def _refresh_footer(self) -> None:
        st = self.session_state
        pct, used, window, estimated = self._context_pct()
        bar_w = 10
        filled = int(bar_w * pct / 100)
        if pct >= 85:
            color = T.CRITICAL       # red: near/over the window (compaction imminent)
        elif pct >= 75:
            color = T.ATTENTION      # amber: getting full
        else:
            color = T.TEXT_FAINTER
        meter = Text()
        meter.append("ctx ", style=T.TEXT_FAINTER)
        meter.append("█" * filled + "░" * (bar_w - filled), style=color)
        approx = "~" if estimated else ""  # ~ = estimated from loaded context, not yet measured
        meter.append(f" {approx}{pct}% ({self._fmt_tok(used)}/{self._fmt_tok(window)})", style=color)
        if pct >= 85:
            meter.append(" · will compact soon", style=T.CRITICAL)
        from kratos.utils.build_info import newer_build_on_disk

        if newer_build_on_disk():
            meter.append("  ·  updated on disk — restart Kratos", style=T.ATTENTION)
        # What comes before the meter gives way on a narrow terminal (session id
        # first, then the model name) so the context meter is never cut off.
        parts = [f"session {st['session_id']}", str(st["backend"]),
                 f"target {st['targets'][0] if st['targets'] else '(none)'}"]
        try:
            width = self.query_one("#statusfooter", Static).size.width or self.app.size.width
        except Exception:  # noqa: BLE001
            width = 0
        while True:
            footer = Text()
            for i, part in enumerate(parts):
                if i:
                    footer.append("  ·  ", style=T.TEXT_GHOST)
                footer.append(part, style=T.TEXT_FAINTER)
            footer.append("   ", style=T.TEXT_GHOST)
            footer.append_text(meter)
            if not width or footer.cell_len <= width or len(parts) == 1:
                break
            parts.pop(0)
        self.query_one("#statusfooter", Static).update(footer)

    def refresh_theme(self) -> None:
        """Called after a live theme-pack switch (KratosTUI.apply_theme_pack):
        re-render the header/footer so they pick up the new palette. Scrolled
        transcript lines keep their original colors until the next launch."""
        self._refresh_header()
        self._refresh_footer()

    # --- log helpers -----------------------------------------------------
    @property
    def _log(self) -> RichLog:
        return self.query_one("#transcript", RichLog)

    def _write(self, renderable: Any) -> None:
        """The one place the transcript is written. Panels (findings, results,
        conclusions) all get the same width -- the column, up to a readable
        maximum -- instead of each shrinking to its own text, which left their
        right edges staggered. Everything else keeps its natural width."""
        if isinstance(renderable, Panel):
            width = self._log.scrollable_content_region.width
            if width > 0:
                self._log.write(renderable, width=min(width, _PANEL_MAX_WIDTH))
            else:  # not laid out yet: the deferred render fills the width once it is
                self._log.write(renderable, expand=True)
            return
        self._log.write(renderable)

    def _write_full(self, renderable: Any) -> None:
        """Write at the transcript's full width (for content that centres itself)."""
        width = self._log.scrollable_content_region.width
        if width > 0:
            self._log.write(renderable, width=width)
        else:
            self._log.write(renderable, expand=True)

    def _emit(self, renderable: Any) -> None:
        """Write to the transcript from the EVENT LOOP (main-thread callers)."""
        self._write(renderable)

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
        self._write(renderable)

    def _emit_bubble_from_worker(self, renderable: Any, date_str: str) -> None:
        self.app.call_from_thread(self._emit_bubble, renderable, date_str)

    def _emit_stamped(self, left: Text, time_str: str, date_str: str) -> None:
        """A message HEADER (you> / Kratos:) with a fine-print trailing time."""
        self._emit_bubble(R.timestamped(left, time_str), date_str)

    def _emit_stamped_from_worker(self, left: Text, time_str: str, date_str: str) -> None:
        self._emit_bubble_from_worker(R.timestamped(left, time_str), date_str)

    def _you_header(self, text: str) -> Text:
        label = f"{self._user_name}> " if self._user_name else "you> "
        line = Text()
        # The user's voice: ADMIN color (its whole purpose), brighter than the
        # old TEXT_DIM so the label reads clearly against Kratos's own lines.
        line.append(label, style=f"bold {T.ADMIN}")
        line.append(text, style=T.TEXT)
        return line

    def _set_user_name(self, name: str) -> None:
        """Live-update the prompt label (called by the General settings tab).
        RichLog is append-only, so this affects lines emitted from here on --
        prior 'you>' headers stay as they were, which is fine."""
        self._user_name = (name or "").strip()

    def _kratos_header(self) -> Text:
        return Text("Kratos:", style=f"bold {T.KRATOS_RED}")

    def _render_idle(self) -> None:
        st = self.session_state
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

        # Split the registry into built-in vs kept for the TOOLS card.
        try:
            kept = set(_read_metadata(KEPT_TOOLS_DIR).keys())
        except Exception:  # noqa: BLE001 -- the banner must never fail to render
            kept = set()
        n_kept = sum(1 for name in TOOL_REGISTRY if name in kept)
        n_builtin = len(TOOL_REGISTRY) - n_kept

        target = st["targets"][0] if st["targets"] else ""
        from kratos.llm_config import get_active_llm_base_url, get_active_llm_model
        model = get_active_llm_model()
        base = (get_active_llm_base_url() or "").lower()
        is_local = any(h in base for h in ("127.0.0.1", "localhost", "::1", "0.0.0.0"))
        # Full transcript width, so the centred home block is centred on screen
        # rather than inside a block sized to its own text at the left edge.
        self._write_full(R.home_banner(target, n_builtin, n_kept, model=model,
                                       model_is_local=is_local, resumed=bool(st["resume_context"])))
        # Secondary hints (kept dim, below the banner) for the less-obvious moves.
        # Two short lines, so they stay whole and centred even at 80 columns.
        self._write_full(Text(
            "Ctrl+P commands · ↑/↓ edit a previous turn · Ctrl+B session list\n"
            "esc stops a response · “investigate your own host” checks Kratos",
            style=T.TEXT_GHOST, justify="center"))
        self._emit(Text(""))

    # --- full-tier resume: on-screen replay ([f]) ---------------
    def _render_full_replay(self) -> None:
        """Re-render the session's prior turns on screen when resumed at full
        tier, so a resumed session shows its history (not just feeds it to the
        model). Only the most recent FULL_RESUME_DETAILED_TURN_CAP turns replay
        in full; older ones collapse to a one-liner (one format, bounded
        output on long sessions). Mirrors cli/repl.py's own replay split, and
        renders through the SAME bubble helpers live turns use, with each turn
        stamped at its real historical (display-zone) time."""
        history = self._store.get_goal_history(self.session_state["session_id"])
        if not history:
            return
        self._emit(Text(f"— resumed context ({len(history)} prior turn(s)) —", style=T.TEXT_FAINTER))
        detailed_from = max(0, len(history) - FULL_RESUME_DETAILED_TURN_CAP)
        for i, turn in enumerate(history):
            if i < detailed_from:
                status = turn.get("status") or "in_progress"
                self._emit(Text(f"- {turn['goal']!r} → {status}", style=T.TEXT_FAINTER))
            else:
                self._render_replay_turn(turn)
        self._emit(Text("— end resumed context · new activity below —", style=T.TEXT_FAINTER))
        self._emit(Text(""))

    def _render_replay_turn(self, turn: dict[str, Any]) -> None:
        goal = turn["goal"]
        status = turn.get("status") or "in_progress"
        started = turn.get("started_at")
        completed = turn.get("completed_at") or started
        self._emit_stamped(self._you_header(goal), self._fmt_stored_time(started), self._fmt_stored_date(started))

        ref = turn.get("transcript_ref")
        if not ref:
            self._emit(R.note_line("(no saved transcript for this turn)"))
            return
        try:
            transcript = json.loads(Path(ref).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            self._emit(R.note_line(f"(could not load transcript: {e})"))
            return

        if status == "chat_reply":
            reply = transcript[0].get("final_answer", "") if transcript else ""
            self._emit_stamped(self._kratos_header(), self._fmt_stored_time(completed), self._fmt_stored_date(completed))
            self._emit(Text(reply or "(no reply)", style=T.TEXT))
            return

        final_present = bool(transcript) and "final_answer" in transcript[-1]
        for step in (transcript[:-1] if final_present else transcript):
            self._render_step_replay(step, completed)
        if final_present:
            self._emit_bubble(
                R.result_panel("Kratos — concluded", transcript[-1]["final_answer"], T.SAFE, time_str=self._fmt_stored_time(completed)),
                self._fmt_stored_date(completed),
            )
        if status == "cancelled":
            self._emit(Text("Investigation cancelled.", style=T.TEXT_FAINT))

    def _render_step_replay(self, step: dict, when_value: Any) -> None:
        """Event-loop counterpart of _render_step (which is worker-thread only).
        Kept separate per the classic REPL's own precedent -- live and replay
        rendering have a real behavioral difference (replay owns the answer;
        on_step defers it) that's cleaner as two small functions than one
        special-cased one."""
        tool_name = step.get("tool")
        if tool_name:
            result, effective_status = R.unwrap_tool_result(step.get("observation"))
            if effective_status == "error":
                err = R.error_detail(result)
                self._emit(R.error_line(f"{tool_name} failed — {err or 'no error detail'}"))
            elif tool_name == "correlate_findings" and isinstance(result, dict) and result.get("findings"):
                findings = result["findings"]
                line = Text()
                line.append("✓ ", style=T.SAFE)
                line.append(tool_name, style=f"bold {T.ACCENT}")
                line.append(f"  correlated findings ({len(findings)} found)", style=T.TEXT_MUTED)
                self._emit(line)
                for f in findings:
                    self._emit_bubble(R.finding_panel(f, time_str=self._fmt_stored_time(when_value)), self._fmt_stored_date(when_value))
            else:
                self._emit(R.tool_call_line(tool_name, effective_status))
        elif step.get("tool_proposal"):
            # Review finding #5: previously silently dropped on replay (this
            # branch didn't exist at all -- the leading `if not tool_name:
            # return` skipped every tool-less step). Deliberately does NOT
            # touch session_state["pending_evolve_suggestion"] the way the
            # LIVE version (_render_step) does -- resurrecting a stale past
            # suggestion as if it just happened now could make a later bare
            # /evolve act on a proposal from a past, possibly since-resolved
            # turn. This is purely the historical record; only a live
            # suggestion arms /evolve's no-arg shortcut.
            proposal = step["tool_proposal"]
            body = (
                f"{proposal.get('name', '')}\n{proposal.get('description', '')}\n\n"
                'Run /evolve to have Kratos build this (needs a test harness).'
            )
            self._emit(R.result_panel("Evo-loop suggestion", body, T.ATTENTION))
        elif step.get("status") == "clarify":
            # Review finding #5: same gap as tool_proposal above -- without
            # this, a mid-investigation clarify Q&A vanishes from a full-tier
            # resume even though it genuinely happened and shaped the rest of
            # that investigation. No bubble/timestamp, matching how the LIVE
            # version (_render_step) renders this too (plain, not a bubble).
            question = step.get("clarify_question", "")
            answer = step.get("clarify_answer")
            body = (f"Q: {question}\nA: {answer}" if answer
                   else f"Q: {question}\n(no answer given — Kratos proceeded with its best judgment)")
            self._emit(R.result_panel("Clarifying question", body, T.ACCENT))

    # --- input -----------------------------------------------------------
    def on_input_changed(self, event: Input.Changed) -> None:
        # A lone "/" typed into the empty prompt opens the command
        # palette (which filters as you type and can still take inline args).
        # Only a deliberate single "/" triggers it -- a pasted/typed "/cmd args"
        # arrives as a longer string and is left for normal inline submission.
        if event.value == "/" and not self._busy:
            event.input.value = ""
            self._reset_recall()  # opening the palette abandons any in-progress turn recall
            self.action_palette()
        elif event.value == "?" and not self._busy:
            # A lone "?" on the empty prompt opens help (vim/less convention,
            # always terminal-deliverable — unlike F1/ctrl+?). Typing "?" inside
            # a longer message is untouched (only a sole "?" triggers it).
            event.input.value = ""
            self.action_help()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        event.input.value = ""
        self._reset_recall()  # sending clears any ↑/↓ history navigation
        if not text:
            return
        if self._busy:
            self.notify("A turn is already running — press esc or Ctrl+C to stop it first.", timeout=3)
            return
        # echo the user's line (with a trailing timestamp / date divider)
        t, d = self._stamp_now()
        self._emit_stamped(self._you_header(text), t, d)
        self._store.touch_session(self.session_state["session_id"])
        # ↑/↓ recall is non-destructive: sending is always a fresh turn, never
        # discards history. An earlier "edit a previous turn truncates from
        # here" design produced a confusing "discarded N turns" line whenever ↑
        # had been pressed; ctrl+c-stop-then-retype covers editing instead.
        if text.startswith("/"):
            self._dispatch_slash(text)
        elif text.split(maxsplit=1)[0].lower() in _BARE_COMMAND_WORDS:
            # Forgotten-slash safety net (deterministic, pre-LLM): the line starts
            # with an unambiguous command word, so the user clearly meant the
            # command and just dropped the "/". Run it, with a hint. Disjoint from
            # the LLM router's capability nudge (which handles natural-language
            # questions), so they never overpower each other.
            self._emit(R.note_line(
                f"“{text.split(maxsplit=1)[0].lower()}” is a command — running /{text}. "
                "(Commands start with a slash.)"))
            self._dispatch_slash("/" + text)
        else:
            self._run_goal(text)

    # --- slash dispatch --------------------------------------------------
    def _dispatch_slash(self, text: str) -> None:
        """Guarded entry point for every command (typed or from the palette): a bug
        in ANY handler surfaces as a friendly line and the session survives.
        Without this, an unhandled exception here crashes the whole TUI -- Textual
        re-raises exceptions thrown inside an event handler."""
        try:
            self._dispatch_slash_impl(text)
        except Exception as e:  # noqa: BLE001 -- a command must never crash the session
            self._emit(R.error_line(
                f"That command hit an unexpected error and stopped — the session is fine ({e}). "
                "If it keeps happening, /doctor can help diagnose it."))
            try:
                self._set_busy(False)   # a handler may have set busy before raising
            except Exception:  # noqa: BLE001
                pass

    def _dispatch_slash_impl(self, text: str) -> None:
        parts = text.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if cmd in ("/exit", "/quit"):
            self.app.exit()
        elif cmd in ("/sessions", "/back"):
            self.action_back_to_sessions()
        elif cmd == "/help":
            self.app.push_screen(HelpModal())
        elif cmd == "/report":
            self._render_report()
        elif cmd in ("/schedule", "/schedules"):
            self._schedule_flow(rest)
        elif cmd in ("/trigger", "/triggers"):
            self._trigger_flow(rest)
        elif cmd in ("/preset", "/presets"):
            self._preset_flow(rest)
        # Discrete, guided preset commands (hyphenated so they're single tokens
        # that pick cleanly from the / completion menu, and each drives the rest
        # of the flow via modals — name/goal prompts, or a picker — instead of
        # needing inline quoted args typed past the menu).
        elif cmd == "/preset-new":
            self._preset_new_guided()
        elif cmd in ("/preset-describe", "/describe"):
            self._preset_describe_flow(rest)
        elif cmd in ("/preset-scaffold", "/preset-new-pipeline"):
            self._preset_scaffold(rest)
        elif cmd in ("/preset-list", "/preset-ls"):
            self._preset_render_list()
        elif cmd == "/preset-run":
            self._preset_guided("run")
        elif cmd == "/preset-edit":
            self._preset_guided("edit")
        elif cmd in ("/preset-delete", "/preset-del"):
            self._preset_guided("delete")
        elif cmd == "/preset-show":
            self._preset_guided("show")
        elif cmd == "/preset-export":
            self._preset_guided("export")
        elif cmd == "/preset-import":
            self._preset_flow("import " + rest if rest else "import")
        elif cmd in ("/doctor", "/health"):
            self._doctor_flow()
        elif cmd in ("/guide", "/start", "/getting-started"):
            self._render_guide()
        elif cmd == "/usage":
            self._render_usage()
        elif cmd == "/context":
            self._render_context()
        elif cmd == "/clear":
            self._clear_flow()
        elif cmd == "/compact":
            self._compact_flow()
        elif cmd == "/reset":
            self._reset_flow()
        elif cmd == "/delete":
            self._delete_flow()
        elif cmd == "/rename":
            self._rename_flow(rest)
        elif cmd == "/target":
            self._target_flow(rest)
        elif cmd == "/model":
            # /model is a quick shortcut into the Models tab of Settings (full
            # switch/add/edit/delete manager), not a bare picker.
            from kratos.tui_mk2.screens.settings import SettingsScreen

            self.app.push_screen(SettingsScreen(self))
        elif cmd == "/timezone":
            self._cmd_timezone(rest)
        elif cmd == "/evolve":
            self._evolve_entry(rest)
        elif cmd == "/tools":
            self._render_tools()
        elif cmd in ("/use", "/tool", "/run-tool"):
            self._tool_flow(rest)
        elif cmd == "/settings":
            from kratos.tui_mk2.screens.settings import SettingsScreen

            self.app.push_screen(SettingsScreen(self))
        elif cmd == "/preview":
            from kratos.tui_mk2.screens.phase2_preview import Phase2PreviewScreen

            self.app.push_screen(Phase2PreviewScreen())
        elif cmd in ("/subagent", "/subagents", "/agents", "/connect"):
            from kratos.tui_mk2.screens.subagent import SubAgentScreen

            self.app.push_screen(SubAgentScreen(self._data_dir))
        elif cmd == "/whitelist":
            from kratos.tui_mk2.screens.whitelist import WhitelistScreen

            self.app.push_screen(WhitelistScreen(self._data_dir))
        elif cmd in ("/run-fix", "/run-recommended"):
            self._run_fix_flow()
        elif cmd in ("/investigate-host", "/investigate-self", "/host"):
            self._investigate_host_flow(rest)
        elif cmd == "/run":
            # The deterministic standard audit (agent/pipeline.py), NOT
            # a hand-coded pipeline. Target-correct, mk2-rendered, no LLM.
            # Gated by a pre-run preview+confirm (default on) for heavy runs.
            self._run_standard_audit_gated()
        elif cmd == "/plan":
            # Preview a run's plan WITHOUT running it. No arg = the standard
            # audit (exact); a preset name = that preset; free text = a predicted
            # agentic plan. Also toggles the auto-gate: /plan gate on|off.
            self._plan_flow(rest)
        elif cmd in ("/scan", "/logs-parse", "/findings-generate"):
            self._run_shortcut(cmd.lstrip("/"), rest)
        elif self._run_named_preset(cmd.lstrip("/")):
            # /<name> runs a saved preset as a first-class command.
            # Reached ONLY after every built-in above, so a preset can never
            # shadow a built-in command (built-in always wins). Handled inside
            # _run_named_preset, which returns True iff it matched a preset.
            pass
        else:
            # Unmatched /-prefix falls through to a goal (matches classic REPL).
            self._run_goal(text)

    def _run_named_preset(self, bare: str) -> bool:
        """If `bare` (a /-stripped command word) names a saved preset,
        run it and return True; else return False so dispatch falls through to a
        goal. Checked live, so presets added/deleted mid-session resolve correctly
        with no caching."""
        from kratos.agent import presets as _P

        if bare and _P.preset_exists(self._data_dir, bare):
            self._preset_run([bare])
            return True
        return False

    # --- /usage (token + cost transparency) -----------------
    # Rough per-1M-token rates (USD input, output) — APPROXIMATE, provider
    # pricing changes; edit here. Only used to show an estimate, never billed.
    _MODEL_RATES: dict[str, tuple[float, float]] = {
        "gemini-3.1-flash-lite": (0.10, 0.40),
        "gemini-3.1-pro-preview": (1.25, 5.00),
    }

    def _render_usage(self) -> None:
        from kratos import llm_interface
        from kratos.llm_config import get_active_llm_base_url, get_active_llm_model

        u = llm_interface.get_session_token_usage()
        model = get_active_llm_model()
        base = (get_active_llm_base_url() or "").lower()
        local = any(h in base for h in ("127.0.0.1", "localhost", "::1", "0.0.0.0"))

        rows = [
            ("model", model),
            ("prompt tokens", f"{u.prompt_tokens:,}"),
            ("completion tokens", f"{u.completion_tokens:,}"),
            ("total tokens", f"{u.total_tokens:,}"),
        ]
        if local:
            rows.append(("cost", "local model — free · private (nothing billed)", T.SAFE))
        else:
            rate = self._MODEL_RATES.get(model)
            if rate:
                cost = (u.prompt_tokens / 1e6) * rate[0] + (u.completion_tokens / 1e6) * rate[1]
                rows.append(("cost (rough est.)", f"~${cost:.4f} this process — approximate, verify with your provider", T.ATTENTION))
            else:
                rows.append(("cost", f"cloud · usage-billed — no rate on file for {model}, see your provider's pricing", T.ATTENTION))
        self._emit(R.kv_table("Token usage — this process", rows))
        if u.total_tokens == 0:
            self._emit(R.note_line(
                "No measured LLM calls yet this run. Counting is per-process (resets on restart), so a "
                "just-resumed session shows 0 until its next message — prior-run usage isn't tracked."))
        else:
            self._emit(R.note_line("Counts are for this process (reset on restart). Local models are always free."))

    # --- /context (what's in the window) --------------------
    def _render_context(self) -> None:
        from kratos.llm_config import get_active_llm_context_source, get_active_llm_model

        pct, used, window, estimated = self._context_pct()
        source = get_active_llm_context_source()
        source_txt, source_style = {
            "provider": ("reported by the provider", T.TEXT),
            "catalog": ("public catalog — the model's published max; the provider may allow less", T.ATTENTION),
            "user": ("set by you", T.TEXT),
            "env": ("KRATOS_LLM_CONTEXT_WINDOW override", T.TEXT),
            "local": ("local model budget", T.TEXT),
            "default": ("not detected — using the safe default; set it in /settings → Models", T.ATTENTION),
        }.get(source, (source, T.TEXT))
        resume = self.session_state.get("resume_context", "") or ""
        turns = len(self._store.get_goal_history(self.session_state["session_id"]))
        meter = "estimated from loaded context" if estimated else "measured (last LLM call)"
        rows = [
            ("model", get_active_llm_model()),
            ("context window", f"{window:,} tokens"),
            ("window source", source_txt, source_style),
            ("in use", f"{used:,} tokens  ({pct}%)  — {meter}", T.ATTENTION if pct >= 75 else T.TEXT),
            ("working memory", f"{len(resume):,} chars  (~{len(resume)//4:,} tokens of conversation kept)"),
            ("turns in this session", str(turns)),
        ]
        self._emit(R.kv_table("Context window — what's loaded", rows))
        if pct >= 75:
            self._emit(R.note_line("Getting full — /compact summarizes older turns (keeping the recent ones) to free space."))
        else:
            self._emit(R.note_line("/compact frees space by summarizing older turns; recent turns are kept verbatim."))

    # --- /guide (getting started) ---------------------------
    def _render_guide(self) -> None:
        """Open the getting-started guide -- the same modal the launcher's ?/g
        shows, so the guide reads identically from either place. The full detail
        lives in the shipped docs/GUIDE.md."""
        from kratos.tui_mk2.modals import GuideModal

        self.app.push_screen(GuideModal())

    # --- /doctor (self-diagnostic) --------------------------
    @work(thread=True, exclusive=True, group="turn")
    def _doctor_flow(self) -> None:
        """Run Kratos's self-diagnostic (LLM endpoint, .env, backend, target
        setup, kept tools) off the event loop -- the endpoint probe and the
        target SSH check are blocking network work."""
        from kratos.agent import doctor

        self._set_busy(True)
        self._emit_from_worker(R.note_line("Running diagnostics — checking LLM, target, and tools…"))
        try:
            checks = doctor.run_diagnostics(self._data_dir)
        except Exception as e:  # noqa: BLE001 -- should not happen (each check is guarded), but never crash the screen
            self._emit_from_worker(R.error_line(f"Diagnostic run failed: {e}"))
            self._set_busy(False)
            return
        # The verdict headline now leads the table (render.doctor_table), so no
        # trailing summary line is needed -- the "is my setup OK?" answer is read
        # first, not last.
        self._emit_bubble_from_worker(R.doctor_table(checks), self._stamp_now()[1])
        self._set_busy(False)

    # --- /report -----------------------------------------------------
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
        from kratos.agent.ir_playbooks import build_response_plan

        for f, when_value in findings:
            # Each finding keeps the time it was ORIGINALLY found (its turn's
            # completion time, a stored UTC value), rendered in the display
            # zone -- not when /report was run.
            when_str = self._fmt_stored_time(when_value)
            self._emit(R.finding_panel(f, time_str=when_str))
            # Auto-attach a recommend-only response plan for HIGH/CRITICAL
            # findings (build_response_plan returns None below that, so no
            # manufactured urgency on info/low). Recommend-only, curated
            # templates -- Kratos runs nothing.
            if str(f.get("severity", "")).lower() in ("high", "critical"):
                plan = build_response_plan(f, found_at=when_str)
                if plan is not None:
                    self._emit(R.response_plan_panel(plan, time_str=when_str))

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

    # --- /preset (saved natural-language investigation goals) ---
    _PRESET_USAGE = (
        "Usage: /preset list  ·  /preset new  (guided: goal or pipeline)  ·  "
        "/preset describe \"<goal>\"  ·  /preset run \"<name>\"  ·  /preset show \"<name>\"  ·  "
        "/preset edit \"<name>\"  ·  /preset delete \"<name>\"  ·  "
        "/preset scaffold \"<name>\"  ·  /preset export \"<name>\"  ·  "
        "/preset import <path>  ·  or just /<name> to run one"
    )

    @work
    async def _preset_flow(self, rest: str) -> None:
        import shlex
        from kratos.agent import presets as _P

        try:
            tokens = shlex.split(rest) if rest.strip() else []
        except ValueError:
            self._emit(R.error_line(
                "Couldn't parse that — check your quotes. " + self._PRESET_USAGE))
            return

        sub = tokens[0].lower() if tokens else "list"
        args = tokens[1:]
        if sub in ("list", "ls"):
            self._preset_render_list()
        elif sub in ("new", "add", "create"):
            if args:
                # Inline power-user form always creates a GOAL preset.
                await self._preset_new(args)
            else:
                self._preset_new_guided()
        elif sub in ("scaffold", "new-pipeline"):
            self._preset_scaffold(args[0] if args else "")
        elif sub == "describe":
            self._preset_describe_flow(" ".join(args))
        elif sub == "export":
            self._preset_export(args)
        elif sub == "import":
            await self._preset_import(args)
        elif sub == "run":
            self._preset_run(args)
        elif sub in ("edit", "update"):
            await self._preset_edit(args)
        elif sub in ("delete", "del", "rm", "remove"):
            await self._preset_delete(args)
        elif sub in ("show", "view"):
            self._preset_show(args)
        elif tokens and _P.preset_exists(self._data_dir, tokens[0]):
            # /preset <existing-name> is a convenient shorthand for run.
            self._preset_run([tokens[0]])
        else:
            self._emit(R.note_line(self._PRESET_USAGE))

    def _preset_render_list(self) -> None:
        from kratos.agent import presets as _P
        from kratos.agent.tools import TOOL_REGISTRY

        presets, errors = _P.list_presets(self._data_dir)
        run_meta = _P.preset_run_meta(self._data_dir)
        # Render each preset's last-run time in the display timezone (stored UTC).
        last_run = {name: self._fmt_stored_time(meta.get("last_run_at"))
                    for name, meta in run_meta.items() if meta.get("last_run_at")}
        # Pipelines that name a tool this build doesn't have: structurally runnable,
        # but a required step fails at run time -- mark them so it's visible before
        # a run, not only in /preset show. (Registry check stays here; render stays pure.)
        unavailable = {
            p.name for p in presets
            if getattr(p, "is_pipeline", False) and p.steps
            and any(s.get("tool") not in TOOL_REGISTRY for s in p.steps)
        }
        self._emit(R.preset_table(presets, errors, last_run=last_run, unavailable=unavailable))

    @work
    async def _preset_guided(self, action: str) -> None:
        """The guided (menu-friendly) path for run/edit/delete/show: pick a
        preset from a list instead of typing its name. `run` and `edit` only
        offer runnable (goal) presets; delete/show offer all. Then hands off to
        the same sub-flow the inline `/preset <sub> <name>` form uses."""
        from kratos.agent import presets as _P

        presets, _errors = _P.list_presets(self._data_dir)
        if action == "run":
            # Both goal AND pipeline presets are runnable now (Tier 2).
            candidates = [p for p in presets if p.is_runnable]
            empty_hint = "No runnable presets yet. Create one with /preset-new."
        elif action == "edit":
            # Editable kinds: goal presets (edit the goal) and pipeline presets
            # (the in-place step editor) — including a broken pipeline, so it can
            # be fixed. Unknown-kind presets aren't editable here.
            candidates = [p for p in presets if p.kind in ("goal", "pipeline")]
            empty_hint = "No editable presets yet. Create one with /preset-new."
        else:
            candidates = presets
            empty_hint = "No saved presets yet. Create one with /preset-new."
        if not candidates:
            self._emit(R.note_line(empty_hint))
            return

        def _preview(p: Any) -> str:
            if p.goal:
                return p.goal[:56]
            if p.is_pipeline:
                return f"({len(p.steps)}-step pipeline)"
            return f"({p.kind})"

        entries = [(p.name, f"{p.name}   {_preview(p)}") for p in candidates]
        name = await self.app.push_screen_wait(
            ListPickerModal(f"Preset to {action}", entries, subtitle="↑↓ pick · esc cancel"))
        if name is None:
            return
        if action == "run":
            self._preset_run([name])
        elif action == "edit":
            await self._preset_edit([name])
        elif action == "delete":
            await self._preset_delete([name])
        elif action == "show":
            self._preset_show([name])
        elif action == "export":
            self._preset_export([name])

    @work
    async def _preset_new_conversational(self, name: str, goal: str) -> None:
        """NL preset creation ("save this as a preset called X to do Y"): the
        model extracted name+goal; confirm with the human before writing (a weak
        model can mis-extract), then save. On decline, point at the guided flow."""
        from kratos.agent import presets as _P

        ok, canonical, err = _P.validate_preset_name(name or "")
        if not ok:
            self._emit(R.error_line(
                f"Couldn't use that as a preset name ({err}) Try /preset-new to create one."))
            return
        goal = (goal or "").strip()
        if not goal:
            self._emit(R.note_line("I didn't catch a goal to save. Try /preset-new."))
            return
        confirm = await self.app.push_screen_wait(ConfirmModal(
            "Save this preset?",
            f"Save preset {canonical!r} with this goal?\n\n{goal}"))
        if not confirm:
            self._emit(R.note_line("Didn't save it. Use /preset-new if you want to create it yourself."))
            return
        if _P.preset_exists(self._data_dir, canonical):
            overwrite = await self.app.push_screen_wait(ConfirmModal(
                "Overwrite preset?",
                f"A preset named {canonical!r} already exists. Replace it?"))
            if not overwrite:
                self._emit(R.note_line("Kept the existing preset — nothing changed."))
                return
        try:
            preset = _P.save_preset(self._data_dir, name=canonical, goal=goal)
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        self._emit(R.success_line(
            f"Saved preset {preset.name!r}. Run it anytime with /preset-run (or /preset run \"{preset.name}\")."))

    def _preset_run_conversational(self, name: str) -> None:
        """NL preset run ("run my X preset"): resolve by name and run, or give a
        helpful error naming the presets that do exist."""
        from kratos.agent import presets as _P

        try:
            preset = _P.load_preset(self._data_dir, name or "")
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        if preset is None:
            existing = [p.name for p in _P.list_presets(self._data_dir)[0]]
            hint = (f" Your presets: {', '.join(existing)}." if existing
                    else " You have no presets yet — create one with /preset-new.")
            self._emit(R.error_line(f"No preset named {name!r}.{hint}"))
            return
        self._preset_dispatch_run(preset)

    def _preset_resolve(self, args: list[str], action: str):
        """Load a single named preset from args[0], emitting a clear error and
        returning None on a missing arg / unknown name / corrupt file."""
        from kratos.agent import presets as _P

        if not args:
            self._emit(R.error_line(f"Which preset? Usage: /preset {action} \"<name>\""))
            return None
        try:
            preset = _P.load_preset(self._data_dir, args[0])
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return None
        if preset is None:
            self._emit(R.error_line(f"No preset named {args[0]!r}. See /preset list."))
            return None
        return preset

    def _preset_show(self, args: list[str]) -> None:
        preset = self._preset_resolve(args, "show")
        if preset is None:
            return
        head = (f"kind: {preset.kind}\n"
                f"target: {preset.target or '— (uses the active target)'}\n")
        if getattr(preset, "generated", False):
            head += ("status: AI-drafted, not yet confirmed — running it asks you to confirm once "
                     "(and it can't be scheduled until then)\n")
        if preset.is_pipeline:
            from kratos.agent.pipeline import is_local_host_tool
            from kratos.agent.tools import TOOL_REGISTRY

            lines = [head]
            unknown: list[str] = []
            if preset.steps:
                lines.append("steps (run top-to-bottom):")
                for i, s in enumerate(preset.steps, 1):
                    host = "Kratos host" if is_local_host_tool(s["tool"]) else "target"
                    flags = "required" if s.get("required", True) else "optional"
                    argstr = f"  args: {self._format_step_args(s['args'])}" if s.get("args") else ""
                    whenstr = f"  when={s['when']!r}" if s.get("when") else ""
                    miss = "  ✗ not available in this build" if s["tool"] not in TOOL_REGISTRY else ""
                    if miss:
                        unknown.append(s["tool"])
                    lines.append(f"  {i}. {s['tool']}  [{host}, {flags}]{argstr}{whenstr}{miss}")
            else:
                lines.append("(no valid steps)")
            if not preset.is_runnable and preset.unsupported_reason:
                lines.append("")
                lines.append(f"⚠ {preset.unsupported_reason}")
            elif unknown:
                # Structurally runnable, but a tool it names isn't loaded here --
                # a required step would fail-fast at run time. Warn now, don't block
                # (a kept tool may load later; existence is a run-time concern by design).
                lines.append("")
                lines.append(
                    f"⚠ references {'a tool' if len(unknown) == 1 else 'tools'} not available in this "
                    f"build: {', '.join(dict.fromkeys(unknown))}. A required step would stop the run — "
                    "build the tool with /evolve, or edit the pipeline with /preset edit.")
            body = "\n".join(lines)
        else:
            body = head + "\n" + (preset.goal or "(no goal)")
        self._emit(R.result_panel(f"preset — {preset.name}", body, T.ACCENT))

    def _preset_export(self, args: list[str]) -> None:
        """Show a preset's file path + its full TOML so it can be shared/backed up
        (the file IS the portable artifact — copy it, drop it in another Kratos's
        presets dir, or import it with /preset import)."""
        preset = self._preset_resolve(args, "export")
        if preset is None:
            return
        try:
            content = preset.path.read_text(encoding="utf-8")
        except OSError as e:
            self._emit(R.error_line(f"Couldn't read {preset.path.name}: {e}"))
            return
        self._emit(R.result_panel(
            f"preset {preset.name!r} — {preset.path}", content, T.ACCENT))
        self._emit(R.note_line(
            "Share this file, or copy it into another Kratos's presets folder. "
            "Import one with  /preset import <path>."))

    async def _preset_import(self, args: list[str]) -> None:
        """Import a preset TOML from a path into this Kratos's presets, validated
        through the normal save path (a broken/foreign file is rejected clearly)."""
        from kratos.agent import presets as _P

        if args:
            src = args[0]
        else:
            src = await self.app.push_screen_wait(PromptModal(
                "Import a preset", "Path to a .toml preset file"))
            if src is None or not src.strip():
                return
            src = src.strip()
        try:
            preset, warnings = _P.import_preset_file(self._data_dir, src)
        except _P.PresetError as e:
            # If it already exists, offer to overwrite.
            if "already exists" in str(e):
                overwrite = await self.app.push_screen_wait(ConfirmModal(
                    "Overwrite preset?", str(e) + "\n\nReplace the existing one?"))
                if not overwrite:
                    self._emit(R.note_line("Kept the existing preset — nothing imported."))
                    return
                try:
                    preset, warnings = _P.import_preset_file(self._data_dir, src, overwrite=True)
                except _P.PresetError as e2:
                    self._emit(R.error_line(str(e2)))
                    return
            else:
                self._emit(R.error_line(str(e)))
                return
        for w in warnings:
            self._emit(R.note_line(f"⚠ {w}"))
        self._emit(R.success_line(
            f"Imported preset {preset.name!r} ({preset.kind}). Run it with /preset-run."))

    def _preset_run(self, args: list[str]) -> None:
        preset = self._preset_resolve(args, "run")
        if preset is None:
            return
        self._preset_dispatch_run(preset)

    def _preset_dispatch_run(self, preset: Any) -> None:
        """Route a resolved preset to the right runner: a deterministic PIPELINE
        goes to the pipeline turn worker (no LLM), a GOAL goes to the agentic
        loop. An AI-GENERATED pipeline first gets a danger-confirm
        ('generated ≠ trusted-to-run'). A not-yet-runnable preset
        (unknown kind, empty, or an invalid pipeline) is kept and its reason
        shown, never errored out."""
        from kratos.agent import presets as _P

        if preset.is_runnable_pipeline:
            if preset.generated:
                # An extra, explicit confirm for AI-drafted steps, on top
                # of the normal per-run approvals (which still apply).
                self._danger_confirm_and_run(preset)
            else:
                self._start_pipeline_preset(preset)
        elif preset.is_runnable_tier1:
            _P.record_preset_run(self._data_dir, preset.name)
            self._emit(R.note_line(f"Running preset {preset.name!r}: {preset.goal}"))
            self._preset_run_worker(preset.goal, preset.target)
        else:
            # Forward-compat: kept and shown, just not runnable in this build.
            self._emit(R.note_line(preset.unsupported_reason))

    def _start_pipeline_preset(self, preset: Any) -> None:
        """Run a runnable pipeline preset (records last-run, then the shared
        deterministic turn worker). Assumes any generated-preset danger-confirm
        has already passed."""
        from kratos.agent import presets as _P
        from kratos.agent.pipeline import steps_from_specs

        _P.record_preset_run(self._data_dir, preset.name)
        steps = steps_from_specs(preset.steps)
        self._emit(R.note_line(
            f"Running pipeline preset {preset.name!r} — {len(steps)} deterministic step(s), no LLM."))
        self._run_pipeline_turn(
            steps,
            turn_label=f"/preset run {preset.name} (pipeline)",
            intro=f"Pipeline preset {preset.name!r}: {len(steps)} step(s), same sequence every run.",
            remember_label=f"/preset {preset.name}",
            remember_kind="pipeline preset",
            pin_target=preset.target or None,
        )

    @work
    async def _danger_confirm_and_run(self, preset: Any) -> None:
        """An AI-drafted pipeline is `generated=True` = "not yet
        human-acknowledged to run". Before its FIRST run, name exactly what it
        will run (which tool, on which host) and require an explicit confirm; that
        confirm IS the acknowledgment, so accepting GRADUATES it (persist
        `generated=False`) — it's a normal trusted pipeline thereafter, no more
        per-run nag. Declining runs nothing and leaves it un-graduated."""
        from kratos.agent import presets as _P
        from kratos.agent.pipeline import is_local_host_tool

        lines = []
        for i, s in enumerate(preset.steps, 1):
            host = "the Kratos host" if is_local_host_tool(s["tool"]) else (preset.target or "the target")
            lines.append(f"{i}. {s['tool']} — on {host}")
        body = ("This pipeline was DRAFTED BY AI from a description and hasn't been run yet. "
                "Review what it will run:\n\n" + "\n".join(lines)
                + "\n\nRun it now? (Confirming marks it acknowledged, so you won't be asked "
                "again. Each step still follows Kratos's normal per-tool approvals.)")
        ok = await self.app.push_screen_wait(ConfirmModal("Run this AI-generated pipeline?", body))
        if not ok:
            self._emit(R.note_line(
                "Didn't run it. View it with /preset show, or edit it with /preset-edit."))
            return
        # Graduate: record the human's acknowledgment so it persists (confirm once,
        # not every run). If the re-save fails, still run this once.
        try:
            _P.save_preset(self._data_dir, name=preset.name, kind="pipeline",
                           steps=preset.steps, target=preset.target,
                           created_at=preset.created_at, generated=False)
            self._emit(R.note_line(
                f"Acknowledged — {preset.name!r} is now a trusted pipeline (no confirm needed next time)."))
        except _P.PresetError:
            pass
        self._start_pipeline_preset(preset)

    @work(thread=True, exclusive=True, group="turn")
    def _preset_run_worker(self, goal: str, target: str | None) -> None:
        # Run the preset's goal through the SAME agentic loop typing it would use
        # (so all guards / approval-gating / the observe-and-recommend boundary
        # hold — a preset stores a goal, never actions). If the preset pins its
        # own target, set it for this run and restore after (same set/restore
        # mechanism /investigate-host uses), so a preset can target a specific
        # host without permanently changing the session's target.
        prior = None
        active = self.session_state["targets"][0] if self.session_state["targets"] else None
        if target and target != active:
            prior = _kconfig.get_active_target()
            _kconfig.set_active_target(target)
            self._emit_from_worker(R.note_line(
                f"Preset target: {target} (the session target is restored afterward)."))
        try:
            self._run_investigation(goal)
        finally:
            if prior is not None:
                _kconfig.set_active_target(prior)

    async def _preset_new(self, args: list[str]) -> None:
        from kratos.agent import presets as _P

        if args:
            name_raw = args[0]
        else:
            name_raw = await self.app.push_screen_wait(
                PromptModal("New preset", "Short name (e.g. weekly-audit)"))
            if name_raw is None:
                return
        ok, canonical, err = _P.validate_preset_name(name_raw)
        if not ok:
            self._emit(R.error_line(err or "Invalid preset name."))
            return
        if _P.preset_exists(self._data_dir, canonical):
            overwrite = await self.app.push_screen_wait(ConfirmModal(
                "Overwrite preset?",
                f"A preset named {canonical!r} already exists. Replace it?"))
            if not overwrite:
                self._emit(R.note_line("Kept the existing preset — nothing changed."))
                return

        goal = args[1] if len(args) > 1 else None
        if goal is None:
            goal = await self.app.push_screen_wait(PromptModal(
                f"Goal for {canonical!r}", "What should this preset investigate?"))
            if goal is None:
                return
        goal = (goal or "").strip()
        if not goal:
            self._emit(R.note_line("No goal given — preset not created."))
            return
        try:
            preset = _P.save_preset(self._data_dir, name=canonical, goal=goal)
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        self._emit(R.success_line(
            f"Saved preset {preset.name!r}. Run it with /preset run \"{preset.name}\"."))

    # --- Conversational pipeline authoring -------------
    def _suggest_describe(self, goal: str | None) -> None:
        """Conversational nudge: the message sounds like a multi-step
        pipeline. SUGGEST /preset-describe — never auto-draft or auto-run."""
        g = (goal or "").strip()
        hint = f' /preset-describe "{g}"' if g else " /preset-describe"
        self._emit(R.note_line(
            "That sounds like a multi-step pipeline you could save and re-run. Want me to draft "
            f"one for review? Try{hint}  (I'll show it before anything is saved)."))

    @work
    async def _preset_describe_flow(self, goal: str) -> None:
        """Draft a deterministic pipeline from a plain-language
        description, show it IN FULL for review, and save it (never auto-run) as
        a `kind="pipeline"` preset. The draft is an LLM step; the human reviews
        the concrete steps, so the run itself stays deterministic/LLM-free."""
        import asyncio

        from kratos.agent import presets as _P
        from kratos.agent.pipeline_draft import DraftResult, draft_pipeline
        from kratos.agent.tools import TOOL_REGISTRY, tool_reaches_approval

        goal = (goal or "").strip()
        if not goal:
            goal = await self.app.push_screen_wait(PromptModal(
                "Describe a pipeline",
                "e.g. scan the target, then look up the top source IP from the findings"))
            if goal is None or not goal.strip():
                return
            goal = goal.strip()

        self._emit(R.note_line(
            "Drafting a pipeline from your description (LLM, a moment) — I'll show it for review "
            "before anything is saved, and it runs deterministically once saved (no AI in the run)."))
        draft = await asyncio.to_thread(draft_pipeline, goal, registry=TOOL_REGISTRY)

        # Lever 3 (docs/clarify_expansion.md): the drafter may ask ONE
        # clarifying question instead of guessing when the description is too
        # thin/forked. Capped at a single round here (not the loop's own
        # MAX_CLARIFY_QUESTIONS — this is a one-shot draft, not a ReAct run):
        # ask once, re-draft with whatever was learned (an answer, or an
        # explicit "no answer, do your best"), and accept whatever comes back
        # next rather than clarifying indefinitely.
        if draft.clarify is not None:
            from kratos.tui_mk2.modals import ClarifyModal

            answer = await self.app.push_screen_wait(ClarifyModal(
                draft.clarify["question"], draft.clarify["options"],
                subtitle=f"Your description: {goal}"))
            if answer and answer.strip():
                goal = f"{goal}\n\n(Clarification -- {draft.clarify['question']}: {answer.strip()})"
            else:
                goal = (
                    f"{goal}\n\n(No clarification given for -- {draft.clarify['question']} -- "
                    "pick your best reasonable interpretation and proceed.)"
                )
            self._emit(R.note_line("Drafting again with that in mind…"))
            draft = await asyncio.to_thread(draft_pipeline, goal, registry=TOOL_REGISTRY)
            if draft.clarify is not None:
                # Asked twice despite being told to proceed either way -- don't
                # loop forever; report it as a draft failure instead.
                draft = DraftResult(
                    error="Couldn't draft a pipeline for this without more detail — try "
                          "/preset-describe again with more specifics, or build one "
                          "step-by-step with /preset-new.")

        if draft.error:
            self._emit(R.error_line(draft.error))
            return

        parsed = _P.parse_pipeline(draft.steps, registry=TOOL_REGISTRY)
        # A drafted step naming a tool that
        # doesn't exist is a real gap. Offer to BUILD it via the guided evo-loop
        # wrapper; on success the tool is registered and we re-parse + continue.
        # Declining / cancelling / a non-kept build stops honestly (never save a
        # will-fail pipeline). Auto-creating a missing whitelist entry for the
        # tool is NOT in scope here — an invalid reference still stops via
        # parsed.errors.
        missing_tools = sorted({s["tool"] for s in parsed.steps if s["tool"] not in TOOL_REGISTRY})
        if missing_tools:
            parsed = await self._offer_build_missing_tools(missing_tools, draft.steps)
            if parsed is None:
                return  # declined / cancelled / still missing — reason already emitted
        if parsed.errors:
            # A drafted reference/field/shape that isn't valid — stop honestly.
            self._emit(R.error_line("I drafted a pipeline, but it isn't valid to save:"))
            for e in parsed.errors[:6]:
                self._emit(R.note_line(f"  • {e}"))
            self._emit(R.note_line(
                "This usually means it needs an output that isn't threadable yet. Build it "
                "step-by-step with /preset-new, or rephrase and try /preset-describe again."))
            return

        self._emit(R.note_line("Drafted pipeline — review it before saving:"))
        self._emit(self._pipeline_steps_note(parsed.steps))
        for w in parsed.warnings:
            self._emit(R.note_line(f"⚠ {w}"))
        gated = sorted({s["tool"] for s in parsed.steps
                        if tool_reaches_approval(TOOL_REGISTRY.get(s["tool"]))})
        if gated:  # Reuse the standard approval-required wording.
            self._emit(R.note_line(
                f"Note: {', '.join(gated)} may pause for approval when run (and are skipped in an "
                "unattended/scheduled run — set to 'auto' in Settings → Tools to include them)."))

        ok = await self.app.push_screen_wait(ConfirmModal(
            "Save this drafted pipeline?",
            "I drafted this from your description. Save it as a preset? You'll run it separately, "
            "so you can read the steps first."))
        if not ok:
            self._emit(R.note_line(
                "Didn't save the draft. Rephrase and try /preset-describe again, or build one with /preset-new."))
            return

        # Resolve a name (the draft suggests one; fall back to a prompt).
        canonical = None
        if draft.name:
            name_ok, canonical, _err = _P.validate_preset_name(draft.name)
            if not name_ok:
                canonical = None
        if canonical is None:
            typed = await self.app.push_screen_wait(PromptModal(
                "Name this preset", "Short name (e.g. weekly-audit)"))
            if typed is None:
                return
            name_ok, canonical, err = _P.validate_preset_name(typed)
            if not name_ok:
                self._emit(R.error_line(err or "Invalid preset name."))
                return
        if _P.preset_exists(self._data_dir, canonical):
            overwrite = await self.app.push_screen_wait(ConfirmModal(
                "Overwrite preset?", f"A preset named {canonical!r} already exists. Replace it?"))
            if not overwrite:
                self._emit(R.note_line("Kept the existing preset — nothing changed."))
                return

        try:
            preset, warnings = _P.save_preset_with_warnings(
                self._data_dir, name=canonical, kind="pipeline", steps=parsed.steps, generated=True)
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        for w in warnings:
            self._emit(R.note_line(f"⚠ {w}"))
        # Save-then-separately-run; name the run command so it's one keystroke.
        self._emit(R.success_line(
            f"Saved AI-drafted pipeline {preset.name!r}. Review it any time with /preset show "
            f"\"{preset.name}\"; run it with /{preset.name} when ready (you'll get a confirm first, "
            "since it's AI-generated)."))

    async def _offer_build_missing_tools(self, missing_tools: list[str], draft_steps: list[dict]):
        """A drafted pipeline names tool(s) Kratos doesn't have.
        Offer to build each via the guided evo-loop wrapper (run_guided_build) —
        the SAME write → test → review → keep flow /evolve uses, so NOTHING here
        relaxes the human-authored-test principle or the no-force-accept keep
        gate (run_guided_build wraps run_self_write_loop unmodified). On success
        the tool is registered; we re-parse and return the fresh PipelineParse to
        continue with. If the user renamed a tool mid-build, the drafted step is
        repointed to the actually-kept name. Declining / cancelling / a non-kept
        build stops honestly (returns None after a clear reason) — a pipeline is
        never saved while it still references a missing tool.

        Runs the blocking guided build on a worker thread (asyncio.to_thread);
        its TextualGuidedPrompter bridges each question/approval back to the
        event loop, exactly as the /evolve thread worker does."""
        import asyncio

        from kratos.agent import presets as _P
        from kratos.agent.guided_evolve import run_guided_build
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.tui_mk2.guided import TextualGuidedPrompter

        names = ", ".join(repr(t) for t in missing_tools)
        plural = len(missing_tools) > 1
        proceed = await self.app.push_screen_wait(ConfirmModal(
            "This pipeline needs a tool that doesn't exist yet",
            f"The draft uses {names}, which Kratos doesn't have. Build "
            f"{'them' if plural else 'it'} now with the guided tool builder? You'll describe what "
            f"{'each one' if plural else 'it'} does, review the code, and approve keeping it — the "
            "same safe write → test → keep flow as /evolve."))
        if not proceed:
            self._emit(R.note_line(
                f"Didn't build {names}. Rephrase the pipeline to use existing tools (/tools lists "
                "them), or build one yourself with /evolve, then try /preset-describe again."))
            return None

        prompter = TextualGuidedPrompter(self.app, self)
        renames: dict[str, str] = {}
        for name in missing_tools:
            self._emit(R.note_line(
                f"Building the missing tool {name!r} — describe what it should do."))
            self._set_busy(True)
            try:
                # goal="" makes the guided flow ask what THIS tool should do (the
                # drafter supplies a name, not a per-tool spec); the drafted name
                # is pre-filled. run_guided_build wraps run_self_write_loop
                # unmodified, so every keep/approval invariant still holds.
                result = await asyncio.to_thread(run_guided_build, "", prompter, suggested_name=name)
            except Exception as e:  # noqa: BLE001 — never crash the describe flow
                self._emit(R.error_line(f"Tool build errored: {e}"))
                return None
            finally:
                self._set_busy(False)
            if result is None or result.status != "kept":
                reason = result.message if result is not None else "cancelled"
                self._emit(R.note_line(
                    f"{name!r} wasn't built ({reason}). The pipeline can't be saved without it — "
                    "rephrase to use existing tools, or try /preset-describe again once it exists."))
                return None
            if result.tool_name and result.tool_name != name:
                renames[name] = result.tool_name  # user renamed it mid-build
            self._emit(R.success_line(f"Built and kept {result.tool_name!r}."))

        steps = draft_steps
        if renames:
            steps = [{**s, "tool": renames.get(s["tool"], s["tool"])} for s in draft_steps]
        parsed = _P.parse_pipeline(steps, registry=TOOL_REGISTRY)
        still_missing = sorted({s["tool"] for s in parsed.steps if s["tool"] not in TOOL_REGISTRY})
        if still_missing:
            self._emit(R.error_line(
                f"Still missing after building: {', '.join(still_missing)}. Can't save the pipeline."))
            return None
        self._emit(R.success_line("Built the missing tool(s) — continuing with the pipeline."))
        return parsed

    # --- Guided pipeline authoring ---------------------------
    @work
    async def _preset_new_guided(self) -> None:
        """/preset-new entry: choose GOAL (natural-language, agentic) vs PIPELINE
        (an ordered, deterministic list of tool steps — no LLM), then run the
        matching authoring flow."""
        kind = await self.app.push_screen_wait(ListPickerModal(
            "What kind of preset?",
            [("goal", "goal      A plain-language investigation — the AI agent decides the steps"),
             ("pipeline", "pipeline  An ordered list of tool steps — deterministic, no LLM, repeatable")],
            subtitle="↑↓ pick · esc cancel"))
        if kind is None:
            return
        if kind == "goal":
            await self._preset_new([])
        else:
            await self._preset_new_pipeline()

    async def _preset_new_pipeline(self, name_raw: str | None = None) -> None:
        """Build a kind='pipeline' preset via the guided step builder."""
        from kratos.agent import presets as _P

        if not name_raw:
            name_raw = await self.app.push_screen_wait(
                PromptModal("New pipeline preset", "Short name (e.g. nightly-audit)"))
            if name_raw is None:
                return
        ok, canonical, err = _P.validate_preset_name(name_raw)
        if not ok:
            self._emit(R.error_line(err or "Invalid preset name."))
            return
        if _P.preset_exists(self._data_dir, canonical):
            overwrite = await self.app.push_screen_wait(ConfirmModal(
                "Overwrite preset?",
                f"A preset named {canonical!r} already exists. Replace it?"))
            if not overwrite:
                self._emit(R.note_line("Kept the existing preset — nothing changed."))
                return

        self._emit(R.note_line(
            "Build the pipeline: pick tools in the order they should run. It's deterministic "
            "(same steps every run, no AI deciding)."))
        steps = await self._build_pipeline_steps()
        if not steps:
            self._emit(R.note_line("Cancelled — no pipeline created (a pipeline needs at least one step)."))
            return

        target = await self.app.push_screen_wait(PromptModal(
            f"Target for {canonical!r} (optional)",
            "Leave blank to use whatever target is active when it runs", initial=""))
        target = (target or "").strip() or None  # esc/blank => no pinned target

        try:
            preset, warnings = _P.save_preset_with_warnings(
                self._data_dir, name=canonical, kind="pipeline", steps=steps, target=target)
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        for w in warnings:
            self._emit(R.note_line(f"⚠ {w}"))
        self._emit(R.success_line(
            f"Saved pipeline preset {preset.name!r} ({len(preset.steps)} step(s)). "
            "Run it with /preset-run, or schedule it with /schedule."))

    def _format_step_args(self, args: dict[str, Any]) -> str:
        """Human-readable step args, rendering a step-output reference in plain
        language ('ip = the top source IP from the "correlate" step') rather than
        raw {from=…} syntax."""
        from kratos.agent import pipeline_refs as _refs

        parts: list[str] = []
        for k, v in (args or {}).items():
            if _refs.is_reference(v):
                parts.append(f"{k} = {_refs.describe_reference(v)}")
            else:
                parts.append(f"{k}={v!r}")
        return ", ".join(parts)

    def _pipeline_steps_note(self, steps: list[dict[str, Any]]) -> Any:
        """A compact, host/required/condition-labeled listing of a pipeline's
        steps (used by the in-place editor between actions)."""
        from kratos.agent.pipeline import is_local_host_tool

        if not steps:
            return R.note_line("(no steps yet)")
        body = Text()
        for i, s in enumerate(steps, 1):
            host = "Kratos host" if is_local_host_tool(s["tool"]) else "target"
            flags = "required" if s.get("required", True) else "optional"
            body.append(f"  {i}. ", style=T.TEXT_DIM)
            body.append(s["tool"], style=f"bold {T.ACCENT}")
            body.append(f"  [{host}, {flags}]", style=T.TEXT_MUTED)
            if s.get("args"):
                body.append(f"  {self._format_step_args(s['args'])}", style=T.TEXT_FAINT)
            if s.get("when"):
                body.append(f"  when={s['when']!r}", style=T.TEXT_FAINT)
            if i < len(steps):
                body.append("\n")
        return body

    async def _preset_edit_pipeline(self, preset: Any) -> None:
        """In-place pipeline step editor: add / remove /
        reorder / retarget a step's condition & fail-fast, on a working copy;
        nothing is written until 'save'. Cancel discards. Re-validated on save."""
        from kratos.agent import presets as _P

        steps: list[dict[str, Any]] = [dict(s) for s in preset.steps]  # working copy
        while True:
            self._emit(self._pipeline_steps_note(steps))
            entries: list[tuple[str, str]] = [("__add__", "+ add a step")]
            for i, s in enumerate(steps):
                entries.append((f"edit:{i}", f"✎ step {i + 1}: {s['tool']}"))
            if steps:
                entries.append(("__save__", f"✓ save changes ({len(steps)} step(s))"))
            entries.append(("__cancel__", "✗ cancel (discard changes)"))
            pick = await self.app.push_screen_wait(ListPickerModal(
                f"Edit pipeline {preset.name!r}", entries, subtitle="↑↓ pick · esc cancel"))
            if pick is None or pick == "__cancel__":
                self._emit(R.note_line("No changes saved — the preset is unchanged."))
                return
            if pick == "__save__":
                if not steps:
                    self._emit(R.note_line("A pipeline needs at least one step — add one before saving."))
                    continue
                try:
                    # Preserve the generated/acknowledged state across an edit —
                    # editing is one human act, not the graduation event (only an
                    # accepted run-confirm graduates). Editing an un-acknowledged
                    # AI draft keeps it un-acknowledged (confirm again on run —
                    # the steps just changed); editing a trusted one keeps it
                    # trusted. Trust never changes silently as a side effect.
                    _saved, warnings = _P.save_preset_with_warnings(
                        self._data_dir, name=preset.name, kind="pipeline", steps=steps,
                        target=preset.target, created_at=preset.created_at,
                        generated=preset.generated)
                except _P.PresetError as e:
                    self._emit(R.error_line(str(e)))
                    continue
                for w in warnings:
                    self._emit(R.note_line(f"⚠ {w}"))
                self._emit(R.success_line(f"Updated pipeline preset {preset.name!r} ({len(steps)} step(s))."))
                return
            if pick == "__add__":
                name = await self._pick_pipeline_tool()
                if name is not None:
                    step = await self._build_pipeline_step(
                        name, is_first=not steps, prior_steps=steps)
                    if step is not None:
                        steps.append(step)
                continue
            if pick.startswith("edit:"):
                await self._edit_pipeline_step(steps, int(pick.split(":", 1)[1]))

    async def _pick_pipeline_tool(self) -> str | None:
        """Pick a single tool for a new step; returns the tool name or None."""
        pick = await self.app.push_screen_wait(ListPickerModal(
            "Which tool?", self._pipeline_tool_entries(), subtitle="↑↓ pick · esc cancel"))
        return pick.split(":", 1)[1] if pick else None

    async def _edit_pipeline_step(self, steps: list[dict[str, Any]], idx: int) -> None:
        """Sub-menu for one step: condition / fail-fast toggle / move / remove."""
        if not (0 <= idx < len(steps)):
            return
        s = steps[idx]
        opts: list[tuple[str, str]] = [
            ("condition", f"change condition (now: {s.get('when') or 'always'})"),
            ("required", f"toggle fail-fast (now: {'required' if s.get('required', True) else 'optional'})"),
        ]
        if idx > 0:
            opts.append(("up", "move up"))
        if idx < len(steps) - 1:
            opts.append(("down", "move down"))
        opts.append(("remove", "remove this step"))
        opts.append(("back", "back"))
        pick = await self.app.push_screen_wait(ListPickerModal(
            f"Step {idx + 1}: {s['tool']}", opts, subtitle="↑↓ pick · esc back"))
        if pick in (None, "back"):
            return
        if pick == "condition":
            when = await self._pick_step_condition(s["tool"], is_first=(idx == 0))
            if when is not _CANCELLED:
                if when:
                    s["when"] = when
                else:
                    s.pop("when", None)
        elif pick == "required":
            s["required"] = not s.get("required", True)
        elif pick == "up" and idx > 0:
            steps[idx - 1], steps[idx] = steps[idx], steps[idx - 1]
        elif pick == "down" and idx < len(steps) - 1:
            steps[idx + 1], steps[idx] = steps[idx], steps[idx + 1]
        elif pick == "remove":
            steps.pop(idx)

    def _pipeline_tool_entries(self) -> list[tuple[str, str]]:
        """`(f"tool:<name>", label)` entries for every registry tool, host/target
        labeled — shared by the builder and the step editor's 'add'."""
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.pipeline import is_local_host_tool

        out: list[tuple[str, str]] = []
        for n in sorted(TOOL_REGISTRY):
            host = "host" if is_local_host_tool(n) else "target"
            desc = (TOOL_REGISTRY[n].description or "").splitlines()[0][:40]
            out.append((f"tool:{n}", f"+ {n}  [{host}]  {desc}"))
        return out

    async def _build_pipeline_steps(self) -> list[dict[str, Any]] | None:
        """Guided step builder: pick-a-tool → add → remove → done,
        mirroring the group-job builder. Returns the ordered step dicts, or
        None if cancelled before adding any."""
        steps: list[dict[str, Any]] = []
        while True:
            entries: list[tuple[str, str]] = list(self._pipeline_tool_entries())
            if steps:
                entries.append(("__remove__", f"− remove a step  ({len(steps)} added)"))
                entries.append(("__done__", f"✓ done — save these {len(steps)} step(s)"))
            title = ("Add the first step" if not steps
                     else f"Add another step, or finish — {len(steps)} so far")
            pick = await self.app.push_screen_wait(ListPickerModal(
                title, entries,
                subtitle="↑↓ pick · steps run top-to-bottom · esc cancel"))
            if pick is None:
                return steps or None
            if pick == "__done__":
                return steps
            if pick == "__remove__":
                if steps:
                    which = await self.app.push_screen_wait(ListPickerModal(
                        "Remove which step?",
                        [(str(i), f"{i + 1}. {s['tool']}") for i, s in enumerate(steps)],
                        subtitle="↑↓ pick · esc keep all"))
                    if which is not None:
                        steps.pop(int(which))
                continue
            if pick.startswith("tool:"):
                step = await self._build_pipeline_step(
                    pick.split(":", 1)[1], is_first=not steps, prior_steps=steps)
                if step is not None:
                    steps.append(step)

    async def _build_pipeline_step(self, name: str, *, is_first: bool = False,
                                   prior_steps: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        """Collect one step: for each REQUIRED arg, either type a value OR thread
        it from an earlier step's output (menu-driven, no syntax);
        then the fail-fast vs resilient choice (default fail-fast) and an
        optional `when` condition. Returns the step
        dict, or None if cancelled."""
        from kratos.agent.tools import TOOL_REGISTRY

        prior_steps = prior_steps or []
        tool = TOOL_REGISTRY[name]
        params = getattr(tool, "parameters", {}) or {}
        args: dict[str, Any] = {}
        for pname in self._missing_required_args(tool, {}):
            spec = params.get(pname) or {}
            # Offer threading this arg from an earlier compatible step.
            ref = await self._maybe_thread_arg(name, pname, spec, prior_steps)
            if ref is _CANCELLED:
                return None
            if ref is not None:
                args[pname] = ref
                continue
            hint = str(spec.get("description") or f"value for {pname}")[:80]
            val = await self.app.push_screen_wait(PromptModal(f"{name}: {pname}", hint))
            if val is None or not val.strip():
                self._emit(R.note_line(f"Step {name} skipped (it needs '{pname}')."))
                return None
            args[pname] = self._coerce_arg(val.strip(), spec)

        required = await self.app.push_screen_wait(ListPickerModal(
            f"If '{name}' fails…",
            [("required", "abort the whole run (fail-fast — recommended)"),
             ("optional", "carry on with the next step (skip just this one)")],
            subtitle="↑↓ pick · esc cancel this step"))
        if required is None:
            return None

        when = await self._pick_step_condition(name, is_first=is_first)
        if when is _CANCELLED:
            return None
        # Auto-assign a stable, unique label so a later step can reference this
        # one BY NAME — a label survives reordering in the editor,
        # unlike a positional index. (A forward reference created by reordering is
        # caught at save-time re-validation.)
        step: dict[str, Any] = {
            "tool": name, "args": args, "required": required == "required",
            "label": self._unique_step_label(name, prior_steps),
        }
        if when:
            step["when"] = when
        return step

    @staticmethod
    def _unique_step_label(name: str, prior_steps: list[dict[str, Any]]) -> str:
        """A label unique within the pipeline (the tool name, deduped) so
        step-output references resolve by a stable name."""
        existing = {s.get("label") for s in prior_steps if s.get("label")}
        label, n = name, 2
        while label in existing:
            label, n = f"{name}-{n}", n + 1
        return label

    async def _maybe_thread_arg(self, consumer_tool: str, arg_name: str,
                                spec: dict[str, Any], prior_steps: list[dict[str, Any]]) -> Any:
        """If an earlier step exposes a type-compatible
        whitelisted output, offer to thread it into this arg — a producer picker
        then a field picker, no reference syntax typed. Returns a reference dict
        (thread it), None (type a value instead), or _CANCELLED (abort the step)."""
        from kratos.agent import pipeline_refs as _refs

        arg_type = str(spec.get("type") or "")
        # (ref_from, display, [(field, label, needs_first)]) for each compatible producer.
        producers: list[tuple[str, str, list[tuple[str, str, bool]]]] = []
        for idx, s in enumerate(prior_steps, start=1):
            fields = _refs.compatible_fields(arg_type, s.get("tool", ""))
            if fields:
                ref_from = s.get("label") or str(idx)
                display = s.get("label") or f"step {idx}: {s.get('tool')}"
                producers.append((ref_from, display, fields))
        if not producers:
            return None  # nothing to thread — caller prompts for a typed value

        choice = await self.app.push_screen_wait(ListPickerModal(
            f"{consumer_tool}: {arg_name}",
            [("__type__", "type a value"),
             ("__thread__", "use a result from an earlier step")],
            subtitle="↑↓ pick · esc cancel this step"))
        if choice is None:
            return _CANCELLED
        if choice == "__type__":
            return None

        prod = await self.app.push_screen_wait(ListPickerModal(
            "Use a result from which step?",
            [(rf, disp) for rf, disp, _ in producers], subtitle="↑↓ pick · esc cancel"))
        if prod is None:
            return _CANCELLED
        fields = next(f for rf, _d, f in producers if rf == prod)
        fpick = await self.app.push_screen_wait(ListPickerModal(
            "Which value?",
            [(fname, label + (" (first match)" if nf else "")) for fname, label, nf in fields],
            subtitle="↑↓ pick · esc cancel"))
        if fpick is None:
            return _CANCELLED
        needs_first = next(nf for fn, _l, nf in fields if fn == fpick)
        ref: dict[str, Any] = {"from": prod, "field": fpick}
        if needs_first:
            ref["select"] = "first"
        # Dependency warning (create-time) if the producer is optional/conditional.
        prod_step = next((s for i, s in enumerate(prior_steps, 1)
                          if (s.get("label") or str(i)) == prod), None)
        if prod_step is not None and (not prod_step.get("required", True) or prod_step.get("when")):
            self._emit(R.note_line(
                f"Note: this step needs a value from '{prod}'. If '{prod}' is skipped (its "
                "condition, or approval in an unattended run), this step is skipped too."))
        return ref

    async def _pick_step_condition(self, name: str, *, is_first: bool) -> Any:
        """Offer an optional `when` condition for a step: always-run (the default),
        a couple of common finding-based predicates, or a validated custom one.
        Returns the condition string ("" = always run) or the _CANCELLED sentinel
        if the user escaped out of authoring this step."""
        choice = await self.app.push_screen_wait(ListPickerModal(
            f"When should '{name}' run?",
            [("", "always — run it every time (simplest)"),
             ("has_finding()", "only if an earlier step found something"),
             ("has_finding(min_severity='high')", "only if a HIGH or CRITICAL finding exists"),
             ("has_finding(min_severity='medium')", "only if a MEDIUM+ finding exists"),
             ("__custom__", "custom condition… (advanced)")],
            subtitle="↑↓ pick · esc cancel this step"))
        if choice is None:
            return _CANCELLED
        if choice == "__custom__":
            return await self._prompt_custom_condition(name)
        if choice and is_first:
            self._emit(R.note_line(
                f"Heads up: '{name}' is the first step, so no findings exist yet — this "
                "condition will always skip it. Conditions usually go on LATER steps."))
        return choice

    async def _prompt_custom_condition(self, name: str) -> Any:
        """Prompt for a custom `when` predicate and validate it against the
        whitelisted grammar (never eval). Re-prompts on an invalid predicate;
        empty/esc cancels the whole step (fail-safe, no half-authored condition)."""
        from kratos.agent.pipeline_when import WhenError, compile_when

        hint = ("e.g.  has_finding(min_severity='high')  ·  finding_count >= 3  ·  "
                "finding_id == 'CORR-SSH-001'")
        while True:
            raw = await self.app.push_screen_wait(PromptModal(
                f"Condition for '{name}'", hint))
            if raw is None or not raw.strip():
                self._emit(R.note_line(f"No condition set — step '{name}' not added."))
                return _CANCELLED
            try:
                compile_when(raw.strip())  # validate only
            except WhenError as e:
                self._emit(R.error_line(f"That condition isn't valid: {e}. Try again, or esc to cancel."))
                continue
            return raw.strip()

    @staticmethod
    def _coerce_arg(value: str, spec: dict[str, Any]) -> Any:
        """Coerce a typed-in arg to the tool parameter's declared type when it's
        known (integer/number/boolean); otherwise keep the string. A failed
        numeric coercion falls back to the raw string rather than erroring — the
        tool's own arg handling reports a bad value at run time."""
        t = str(spec.get("type") or "").lower()
        try:
            if t in ("integer", "int"):
                return int(value)
            if t in ("number", "float"):
                return float(value)
        except ValueError:
            return value
        if t in ("boolean", "bool"):
            return value.lower() in ("true", "yes", "1", "y", "on")
        return value

    @work
    async def _preset_scaffold(self, name_raw: str) -> None:
        """Files-first bridge: write a commented, valid pipeline
        template into the presets dir for hand-editing, then point at /preset-run.
        The guided builder (/preset-new → pipeline) is the primary path; this is
        for power users who prefer their own editor."""
        from kratos.agent import presets as _P

        if not name_raw.strip():
            name_raw = await self.app.push_screen_wait(
                PromptModal("Scaffold a pipeline preset", "Short name (e.g. nightly-audit)"))
            if name_raw is None:
                return
        ok, canonical, err = _P.validate_preset_name(name_raw)
        if not ok:
            self._emit(R.error_line(err or "Invalid preset name."))
            return
        if _P.preset_exists(self._data_dir, canonical):
            overwrite = await self.app.push_screen_wait(ConfirmModal(
                "Overwrite preset?",
                f"A preset named {canonical!r} already exists. Replace it with a fresh template?"))
            if not overwrite:
                self._emit(R.note_line("Kept the existing preset — nothing changed."))
                return
        try:
            path = _P.write_pipeline_scaffold(self._data_dir, canonical)
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        self._emit(R.command_block_panel(
            "Pipeline template written — edit it, then run it", [str(path)],
            note="It's a valid starter pipeline (nmap → correlate). Edit the [[steps]], then "
                 "run with /preset-run. Kratos validates it on load and shows any problems."))

    async def _preset_edit(self, args: list[str]) -> None:
        from kratos.agent import presets as _P

        preset = self._preset_resolve(args, "edit")
        if preset is None:
            return
        if preset.is_pipeline:
            await self._preset_edit_pipeline(preset)
            return
        if preset.kind != "goal":
            reason = preset.unsupported_reason
            prefix = (reason + " ") if reason else ""
            self._emit(R.note_line(
                prefix + f"This preset kind can't be edited here — edit {preset.path.name} directly."))
            return
        new_goal = await self.app.push_screen_wait(PromptModal(
            f"Edit {preset.name!r}", "New goal", initial=preset.goal or ""))
        if new_goal is None:
            return
        new_goal = new_goal.strip()
        if not new_goal:
            self._emit(R.note_line("Empty goal — preset unchanged."))
            return
        try:
            _P.save_preset(self._data_dir, name=preset.name, goal=new_goal,
                           target=preset.target, created_at=preset.created_at)
        except _P.PresetError as e:
            self._emit(R.error_line(str(e)))
            return
        self._emit(R.success_line(f"Updated preset {preset.name!r}."))

    async def _preset_delete(self, args: list[str]) -> None:
        from kratos.agent import presets as _P

        preset = self._preset_resolve(args, "delete")
        if preset is None:
            return
        from kratos.agent import schedules as _S

        body = f"Delete preset {preset.name!r}? This removes {preset.path.name}."
        dependents = _S.schedules_referencing_preset(self._data_dir, preset.name)
        if dependents:  # a schedule points at this preset -- warn before breaking it
            body += (f"\n\n⚠ {len(dependents)} schedule(s) run this preset "
                     f"({', '.join(dependents)}). They'll fail until you repoint or delete them.")
        ok = await self.app.push_screen_wait(ConfirmModal("Delete preset?", body))
        if not ok:
            self._emit(R.note_line("Kept the preset — nothing deleted."))
            return
        if _P.delete_preset(self._data_dir, preset.name):
            self._emit(R.success_line(f"Deleted preset {preset.name!r}."))
        else:
            self._emit(R.error_line(f"Couldn't delete {preset.name!r}."))

    # --- /schedule (run a preset/audit on a cadence, deliver report) ---
    _SCHEDULE_USAGE = (
        "Usage: /schedule list  ·  /schedule new  ·  /schedule show \"<name>\"  ·  "
        "/schedule run-now \"<name>\"  ·  /schedule install \"<name>\"  ·  "
        "/schedule delete \"<name>\""
    )

    @work
    async def _schedule_flow(self, rest: str) -> None:
        import shlex
        from kratos.agent import schedules as _S

        try:
            tokens = shlex.split(rest) if rest.strip() else []
        except ValueError:
            self._emit(R.error_line("Couldn't parse that — check your quotes. " + self._SCHEDULE_USAGE))
            return
        sub = tokens[0].lower() if tokens else "list"
        args = tokens[1:]
        if sub in ("list", "ls"):
            self._schedule_render_list()
        elif sub in ("new", "add", "create"):
            await self._schedule_new()
        elif sub in ("show", "view"):
            await self._schedule_show(args)
        elif sub in ("delete", "del", "rm", "remove"):
            await self._schedule_delete(args)
        elif sub in ("run-now", "run"):
            await self._schedule_run_now(args)
        elif sub == "install":
            await self._schedule_install(args)
        elif tokens and _S.schedule_exists(self._data_dir, tokens[0]):
            await self._schedule_show([tokens[0]])
        else:
            self._emit(R.note_line(self._SCHEDULE_USAGE))

    def _schedule_render_list(self) -> None:
        from kratos.agent import presets as _P
        from kratos.agent import schedules as _S

        schedules, errors = _S.list_schedules(self._data_dir)
        last: dict[str, str] = {}
        for s in schedules:
            rec = _S.last_run_record(self._data_dir, s.name)
            if rec:
                last[s.name] = f"{rec.get('finished_at', '?')[:16]} · {rec.get('status')}"
        # Flag any schedule whose referenced preset was deleted -- visible before
        # the next unattended run fails, mirroring /preset list's missing-tool flag.
        existing = {p.name for p in _P.list_presets(self._data_dir)[0]}
        missing = {
            s.name for s in schedules
            if not self._schedule_referenced_presets(s).issubset(existing)
        }
        self._emit(R.schedule_table(schedules, errors, last, missing_preset=missing))

    @staticmethod
    def _schedule_referenced_presets(schedule: Any) -> set[str]:
        """The preset name(s) a schedule runs (direct or via group jobs)."""
        names: set[str] = set()
        if getattr(schedule, "kind", None) == "preset" and schedule.preset:
            names.add(schedule.preset)
        elif getattr(schedule, "kind", None) == "group":
            names.update(j.get("preset") for j in (schedule.jobs or []) if (j or {}).get("preset"))
        return names

    async def _schedule_resolve(self, args: list[str], action: str):
        """Resolve a schedule from an inline name or a picker."""
        from kratos.agent import schedules as _S

        if args:
            try:
                sch = _S.load_schedule(self._data_dir, args[0])
            except _S.ScheduleError as e:
                self._emit(R.error_line(str(e)))
                return None
            if sch is None:
                self._emit(R.error_line(f"No schedule named {args[0]!r}."))
            return sch
        schedules, _errors = _S.list_schedules(self._data_dir)
        if not schedules:
            self._emit(R.note_line("No schedules yet. Create one with /schedule new."))
            return None
        entries = [(s.name, f"{s.name}   {s.kind} · {s.cadence}") for s in schedules]
        name = await self.app.push_screen_wait(
            ListPickerModal(f"Schedule to {action}", entries, subtitle="↑↓ pick · esc cancel"))
        if name is None:
            return None
        return _S.load_schedule(self._data_dir, name)

    def _schedulable_presets(self) -> tuple[list, list]:
        """Runnable presets split into (schedulable, ungraduated_generated). An
        AI-drafted (`generated=True`) pipeline is EXCLUDED from schedules/groups
        until it's been confirmed once interactively — it can't run unattended
        (the headless runner refuses it), so scheduling it would just skip every
        fire. Confirming it once (running /<name>) graduates it to schedulable."""
        from kratos.agent import presets as _P

        runnable = [p for p in _P.list_presets(self._data_dir)[0] if p.is_runnable]
        schedulable = [p for p in runnable if not getattr(p, "generated", False)]
        ungraduated = [p for p in runnable if getattr(p, "generated", False)]
        return schedulable, ungraduated

    async def _schedule_new(self) -> None:
        from kratos.agent import schedules as _S
        from kratos.agent import schedule_units as _U
        from kratos.agent.scheduled_run import active_backend_is_cloud

        kind = await self.app.push_screen_wait(ListPickerModal(
            "What should this schedule run?",
            [("audit", "audit   Standard audit — deterministic, no LLM, free"),
             ("preset", "preset  A saved goal preset — runs the AI agent"),
             ("group", "group   Several jobs in order, on one cadence")],
            subtitle="↑↓ pick · esc cancel"))
        if kind is None:
            return

        preset_name = None
        jobs: list[dict] = []
        on_failure = "continue"
        if kind == "preset":
            presets, ungraduated = self._schedulable_presets()
            if not presets:
                if ungraduated:
                    self._emit(R.note_line(
                        "Your runnable presets are all AI-drafted and not confirmed yet. Run one and "
                        f"confirm it first (e.g. /{ungraduated[0].name}), then it can be scheduled."))
                else:
                    self._emit(R.note_line("No runnable presets yet. Create one with /preset-new first."))
                return
            if ungraduated:
                self._emit(R.note_line(
                    f"Not shown: {len(ungraduated)} AI-drafted preset(s) not confirmed yet — run one "
                    "(/<name>) and confirm it to make it schedulable."))

            def _row(p: Any) -> str:
                body = p.goal or (f"{len(p.steps)}-step pipeline" if p.is_pipeline else "")
                tag = "pipeline · no LLM" if p.is_runnable_pipeline else "goal · AI"
                return f"{p.name}   [{tag}]  {body[:44]}"

            preset_name = await self.app.push_screen_wait(ListPickerModal(
                "Which preset should it run?",
                [(p.name, _row(p)) for p in presets],
                subtitle="↑↓ pick · esc cancel"))
            if preset_name is None:
                return
            picked = next((p for p in presets if p.name == preset_name), None)
            # Guardrail 2: warn before scheduling an AGENTIC (goal) run on a paid
            # backend. A pipeline preset makes no LLM calls, so it costs nothing
            # unattended — no warning for it.
            if picked is not None and picked.is_runnable_tier1 and active_backend_is_cloud():
                ok = await self.app.push_screen_wait(ConfirmModal(
                    "Cloud backend — unattended cost",
                    "This preset runs the AI model, and the active backend is a paid cloud "
                    "endpoint. A scheduled run will spend money every time it fires, unattended. "
                    "Prefer a local model for schedules. Continue anyway?"))
                if not ok:
                    self._emit(R.note_line("Schedule not created. Switch to a local backend with /model, or pick the standard audit."))
                    return
        elif kind == "group":
            jobs = await self._schedule_build_group_jobs()
            if jobs is None or not jobs:
                if jobs is not None:  # None = cancelled; [] = added nothing
                    self._emit(R.note_line("A group needs at least one job — nothing created."))
                return
            # Cost warning once if any job is an AGENTIC (goal) preset on a paid
            # backend. Pipeline preset jobs make no LLM calls, so they don't count.
            if active_backend_is_cloud() and self._group_has_agentic_job(jobs):
                ok = await self.app.push_screen_wait(ConfirmModal(
                    "Cloud backend — unattended cost",
                    "This group includes a preset that runs the AI model, and the active backend "
                    "is a paid cloud endpoint. Each scheduled run spends money, unattended. "
                    "Prefer a local model. Continue anyway?"))
                if not ok:
                    self._emit(R.note_line("Group not created. Switch to a local backend with /model."))
                    return
            on_failure = await self.app.push_screen_wait(ListPickerModal(
                "If a job fails…",
                [("continue", "continue — run the remaining jobs anyway"),
                 ("abort", "abort — stop; skip the remaining jobs")],
                subtitle="↑↓ pick · esc cancel"))
            if on_failure is None:
                return

        name_raw = await self.app.push_screen_wait(PromptModal(
            "Schedule name", "Short name (e.g. weekly-audit)"))
        if name_raw is None:
            return
        cadence = await self.app.push_screen_wait(ListPickerModal(
            "How often?",
            [(c, c) for c in ("hourly", "daily", "weekly", "monthly")],
            subtitle="↑↓ pick · esc cancel"))
        if cadence is None:
            return
        min_sev = await self.app.push_screen_wait(ListPickerModal(
            "Notify when?",
            [("", "Always — every run sends a report"),
             ("medium", "Only if a MEDIUM+ finding is raised"),
             ("high", "Only if a HIGH+ finding is raised"),
             ("critical", "Only if a CRITICAL finding is raised")],
            subtitle="↑↓ pick · esc cancel"))
        if min_sev is None:
            return

        try:
            sch = _S.save_schedule(
                self._data_dir, name=name_raw, kind=kind, preset=preset_name,
                cadence=cadence, deliver=["ntfy"], min_severity=(min_sev or None),
                jobs=jobs, on_failure=on_failure)
        except _S.ScheduleError as e:
            self._emit(R.error_line(str(e)))
            return

        service_path, timer_path = _U.write_units(sch, self._data_dir)
        cmds = _U.install_commands(sch, service_path, timer_path)
        detail = f"{sch.kind}, {sch.cadence}" + (f", {len(sch.jobs)} jobs" if sch.kind == "group" else "")
        self._emit(R.success_line(f"Saved schedule {sch.name!r} ({detail})."))
        from kratos.agent.notify import notify_config_status

        if notify_config_status()[0] in ("off", "bad"):
            self._emit(R.note_line("Notifications are off, so this schedule will only save reports on disk. "
                                   "To get alerts, set KRATOS_NTFY_TOPIC in .env (/doctor suggests one)."))
        self._emit(R.command_block_panel(
            "Activate it — run these once (Kratos never runs systemctl for you)", cmds,
            note="systemd then owns the timing, reboot-survival, and catch-up. "
                 "Test it any time with /schedule run-now."))

    def _group_has_agentic_job(self, jobs: list[dict]) -> bool:
        """True if any group job runs the LLM (a goal preset) — the only kind
        that costs money on a paid backend. An audit job and a pipeline preset
        job are both deterministic/LLM-free."""
        from kratos.agent import presets as _P

        for j in jobs:
            if j.get("kind") != "preset":
                continue
            p = _P.load_preset(self._data_dir, j.get("preset") or "")
            if p is not None and p.is_runnable_tier1:
                return True
        return False

    async def _schedule_build_group_jobs(self):
        """Guided loop to build a group's ordered job list. Returns the list of
        jobs, or None if the user cancelled before adding any."""
        presets, ungraduated = self._schedulable_presets()
        if ungraduated:
            self._emit(R.note_line(
                f"Not shown as group jobs: {len(ungraduated)} AI-drafted preset(s) not confirmed yet "
                "— run one (/<name>) and confirm it to make it schedulable."))
        jobs: list[dict] = []
        while True:
            entries = [("audit", "+ standard audit (deterministic, free)")]
            entries += [(f"preset:{p.name}",
                         f"+ preset: {p.name} ({'pipeline · no LLM' if p.is_runnable_pipeline else 'goal · AI'})")
                        for p in presets]
            if jobs:
                entries.append(("__done__", f"✓ done — {len(jobs)} job(s) added, in this order"))
            title = ("Add the first job to the group" if not jobs
                     else f"Add another job (or finish) — {len(jobs)} so far")
            pick = await self.app.push_screen_wait(ListPickerModal(
                title, entries, subtitle="↑↓ pick · jobs run in the order you add them · esc cancel"))
            if pick is None:
                return jobs if jobs else None
            if pick == "__done__":
                return jobs
            if pick == "audit":
                jobs.append({"kind": "audit"})
            elif pick.startswith("preset:"):
                jobs.append({"kind": "preset", "preset": pick.split(":", 1)[1]})

    async def _schedule_show(self, args: list[str]) -> None:
        from kratos.agent import schedules as _S
        from kratos.agent import schedule_units as _U

        sch = await self._schedule_resolve(args, "show")
        if sch is None:
            return
        records = _S.read_run_records(self._data_dir, sch.name)
        service_path, timer_path = _U.write_units(sch, self._data_dir)
        cmds = _U.install_commands(sch, service_path, timer_path)
        self._emit(R.schedule_detail_panel(sch, records, cmds))

    async def _schedule_install(self, args: list[str]) -> None:
        from kratos.agent import schedule_units as _U

        sch = await self._schedule_resolve(args, "install")
        if sch is None:
            return
        service_path, timer_path = _U.write_units(sch, self._data_dir)
        self._emit(R.command_block_panel(
            f"Install {sch.unit_name}.timer", _U.install_commands(sch, service_path, timer_path)))

    async def _schedule_delete(self, args: list[str]) -> None:
        from kratos.agent import schedules as _S
        from kratos.agent import schedule_units as _U

        sch = await self._schedule_resolve(args, "delete")
        if sch is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Delete schedule?",
            f"Delete schedule {sch.name!r}? This removes its definition and run history."))
        if not ok:
            self._emit(R.note_line("Kept the schedule — nothing deleted."))
            return
        if _S.delete_schedule(self._data_dir, sch.name):
            self._emit(R.success_line(f"Deleted schedule {sch.name!r}."))
            self._emit(R.command_block_panel(
                "If you installed its timer, remove it too", _U.uninstall_commands(sch)))
        else:
            self._emit(R.error_line(f"Couldn't delete {sch.name!r}."))

    async def _schedule_run_now(self, args: list[str]) -> None:
        sch = await self._schedule_resolve(args, "run now")
        if sch is None:
            return
        if not sch.is_runnable:
            self._emit(R.note_line(sch.unsupported_reason))
            return
        self._emit(R.note_line(
            f"Running schedule {sch.name!r} now (headless, approval-gated tools excluded)…"))
        self._schedule_run_now_worker(sch.name)

    @work(thread=True, exclusive=True, group="turn")
    def _schedule_run_now_worker(self, name: str) -> None:
        from kratos.agent import schedules as _S
        from kratos.agent.scheduled_run import run_scheduled

        self._set_busy(True)
        try:
            sch = _S.load_schedule(self._data_dir, name)
            if sch is None:
                self._emit_from_worker(R.error_line(f"Schedule {name!r} vanished."))
                return
            record = run_scheduled(sch, self._data_dir, deliver=True)
            self._emit_from_worker(R.scheduled_run_result_panel(record))
        except Exception as e:  # noqa: BLE001
            self._emit_from_worker(R.error_line(f"Scheduled run errored: {e}"))
        finally:
            self._set_busy(False)
            self.app.call_from_thread(self._refresh_footer)

    # --- /trigger (if condition detected, notify/playbook/investigate) ---
    _TRIGGER_USAGE = (
        "Usage: /trigger list  ·  /trigger new  ·  /trigger show \"<name>\"  ·  "
        "/trigger test \"<name>\"  ·  /trigger delete \"<name>\""
    )

    @work
    async def _trigger_flow(self, rest: str) -> None:
        import shlex
        from kratos.agent import triggers as _T

        try:
            tokens = shlex.split(rest) if rest.strip() else []
        except ValueError:
            self._emit(R.error_line("Couldn't parse that — check your quotes. " + self._TRIGGER_USAGE))
            return
        sub = tokens[0].lower() if tokens else "list"
        args = tokens[1:]
        if sub in ("list", "ls"):
            self._trigger_render_list()
        elif sub in ("new", "add", "create"):
            await self._trigger_new()
        elif sub in ("show", "view"):
            await self._trigger_show(args)
        elif sub in ("delete", "del", "rm", "remove"):
            await self._trigger_delete(args)
        elif sub == "test":
            await self._trigger_test(args)
        elif tokens and _T.trigger_exists(self._data_dir, tokens[0]):
            await self._trigger_show([tokens[0]])
        else:
            self._emit(R.note_line(self._TRIGGER_USAGE))

    def _trigger_render_list(self) -> None:
        from kratos.agent import triggers as _T

        triggers, errors = _T.list_triggers(self._data_dir)
        last: dict[str, str] = {}
        for tg in triggers:
            rec = _T.last_fire_record(self._data_dir, tg.name)
            if rec:
                last[tg.name] = f"{str(rec.get('fired_at', '?'))[:16]} · {rec.get('action')}"
        self._emit(R.trigger_table(triggers, errors, last))

    async def _trigger_resolve(self, args: list[str], action: str):
        from kratos.agent import triggers as _T

        if args:
            try:
                tg = _T.load_trigger(self._data_dir, args[0])
            except _T.TriggerError as e:
                self._emit(R.error_line(str(e)))
                return None
            if tg is None:
                self._emit(R.error_line(f"No trigger named {args[0]!r}."))
            return tg
        triggers, _errors = _T.list_triggers(self._data_dir)
        if not triggers:
            self._emit(R.note_line("No triggers yet. Create one with /trigger new."))
            return None
        entries = [(t.name, f"{t.name}   {t.condition_text} → {t.action}") for t in triggers]
        name = await self.app.push_screen_wait(
            ListPickerModal(f"Trigger to {action}", entries, subtitle="↑↓ pick · esc cancel"))
        if name is None:
            return None
        return _T.load_trigger(self._data_dir, name)

    async def _trigger_new(self) -> None:
        from kratos.agent import triggers as _T
        from kratos.agent.scheduled_run import active_backend_is_cloud

        sev = await self.app.push_screen_wait(ListPickerModal(
            "Fire when the findings reach which severity?",
            [("", "Any severity — match on a specific finding-ID instead"),
             ("medium", "MEDIUM or higher"),
             ("high", "HIGH or higher"),
             ("critical", "CRITICAL only")],
            subtitle="↑↓ pick · esc cancel"))
        if sev is None:
            return
        fid = await self.app.push_screen_wait(PromptModal(
            "Specific finding-ID? (optional)",
            "e.g. CORR-SSH-001 — or leave blank to match on severity only"))
        if fid is None:
            return
        fid = fid.strip()
        if not sev and not fid:
            self._emit(R.error_line("A trigger needs a condition — pick a severity and/or a finding-ID."))
            return

        action = await self.app.push_screen_wait(ListPickerModal(
            "What should happen when it fires?",
            [("notify", "notify — send a sharp alert"),
             ("playbook", "playbook — alert + the response plan (what to do)"),
             ("investigate", "investigate — a deeper read-only investigation, then alert")],
            subtitle="↑↓ pick · esc cancel"))
        if action is None:
            return
        # Cost gate: an investigate action runs the AI model unattended on the cadence.
        if action == "investigate" and active_backend_is_cloud():
            ok = await self.app.push_screen_wait(ConfirmModal(
                "Cloud backend — unattended cost",
                "The 'investigate' action runs the AI model, and the active backend is a paid "
                "cloud endpoint. Every time this trigger fires on a scheduled run it spends money, "
                "unattended. Prefer a local model. Continue anyway?"))
            if not ok:
                self._emit(R.note_line("Trigger not created. Switch to a local backend with /model, or pick notify/playbook."))
                return
        # Coverage honesty: an investigate action's deep-dive runs on the SCHEDULED
        # cadence (interactive /run only notifies it's deferred). With no schedule,
        # that deeper investigation never actually happens — nudge, don't block.
        if action == "investigate":
            from kratos.agent import schedules as _S
            if not _S.list_schedules(self._data_dir)[0]:
                self._emit(R.note_line(
                    "Note: an 'investigate' trigger runs its deeper look during SCHEDULED runs. "
                    "You have no schedules yet — create one with /schedule new so it actually "
                    "runs; otherwise it will only notify that the deep-dive is deferred."))

        cooldown = await self.app.push_screen_wait(ListPickerModal(
            "Cooldown — how long to wait before it can fire again?",
            [(str(v), f"{k}  (won't re-alert for {k})") for k, v in _T.COOLDOWN_CHOICES.items()],
            subtitle="↑↓ pick · esc cancel"))
        if cooldown is None:
            return

        name_raw = await self.app.push_screen_wait(PromptModal(
            "Trigger name", "Short name (e.g. high-severity-alert)"))
        if name_raw is None:
            return
        try:
            tg = _T.save_trigger(self._data_dir, name=name_raw, action=action,
                                 min_severity=(sev or None), finding_id=(fid or None),
                                 cooldown_minutes=int(cooldown))
        except _T.TriggerError as e:
            self._emit(R.error_line(str(e)))
            return
        self._emit(R.success_line(
            f"Saved trigger {tg.name!r}: when {tg.condition_text} → {tg.action}."))
        self._emit(R.note_line(
            "It's evaluated after every scheduled run (and after /run). "
            "Try it now with /trigger test."))

    async def _trigger_show(self, args: list[str]) -> None:
        from kratos.agent import triggers as _T

        tg = await self._trigger_resolve(args, "show")
        if tg is None:
            return
        self._emit(R.trigger_detail_panel(tg, _T.read_fire_records(self._data_dir, tg.name)))

    async def _trigger_delete(self, args: list[str]) -> None:
        from kratos.agent import triggers as _T

        tg = await self._trigger_resolve(args, "delete")
        if tg is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Delete trigger?",
            f"Delete trigger {tg.name!r}? This removes its definition and fire history."))
        if not ok:
            self._emit(R.note_line("Kept the trigger — nothing deleted."))
            return
        if _T.delete_trigger(self._data_dir, tg.name):
            self._emit(R.success_line(f"Deleted trigger {tg.name!r}."))
        else:
            self._emit(R.error_line(f"Couldn't delete {tg.name!r}."))

    async def _trigger_test(self, args: list[str]) -> None:
        """Show what a trigger WOULD do on a matching finding — no delivery, no
        real investigation, no cooldown side effects."""
        from kratos.agent import triggers as _T
        from kratos.agent.trigger_eval import preview_trigger

        tg = await self._trigger_resolve(args, "test")
        if tg is None:
            return
        # A synthetic finding that satisfies this trigger's condition, so the test
        # always demonstrates a fire (structured fields only — no evidence).
        synthetic = {
            "id": tg.finding_id or "CORR-SSH-001",
            "severity": tg.min_severity or "high",
            "title": "sample finding for a trigger test",
        }
        target = self.session_state["targets"][0] if self.session_state["targets"] else "the target"
        preview = preview_trigger(self._data_dir, tg, [synthetic], target)
        self._emit(R.note_line(
            f"Test — if a {synthetic['severity']} finding "
            f"{'(' + synthetic['id'] + ') ' if tg.finding_id else ''}appears on {target}, "
            f"trigger {tg.name!r} would fire ({tg.action}). No notification was sent."))
        if preview.get("body"):
            self._emit(R.result_panel(f"Would send — {tg.action}", preview["body"], T.ACCENT))

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

    def _clear_screen(self, archive: bool) -> None:
        """Shared by /clear and /reset. Wipes the visible transcript (like a
        shell `clear`), resets the working context + token meter so the next
        turn starts fresh, and re-renders the idle banner so the screen isn't
        left blank. When `archive`, the stored goal history is also archived
        (soft-deleted, recoverable) so a later resume won't bring it back."""
        from kratos import llm_interface

        if archive:
            self._store.archive_goal_history(self.session_state["session_id"])
        llm_interface.reset_session_token_usage()   # drops the context meter to 0
        self.session_state["resume_context"] = ""
        self._ctx_chars = 0
        self._reset_recall()
        self._last_day = None
        self._log.clear()
        self._render_idle()
        self._refresh_footer()

    # --- /clear, /reset, /delete (native confirm modals) -----------------
    @work
    async def _clear_flow(self) -> None:
        ok = await self.app.push_screen_wait(
            ConfirmModal(
                "Clear screen",
                "Wipes the on-screen conversation and resets the working context (and the token "
                "meter) so the next turn starts fresh — like a shell 'clear'. Your session HISTORY "
                "is kept and can still be resumed; only the current view and in-memory context go.",
            )
        )
        if not ok:
            self._emit(R.note_line("Clear cancelled — nothing changed."))
            return
        self._clear_screen(archive=False)
        self._emit(R.success_line("Cleared — screen wiped and working context reset. Session history kept."))

    @work
    async def _reset_flow(self) -> None:
        ok = await self.app.push_screen_wait(
            ConfirmModal(
                "Reset session",
                "Wipes this session's on-screen conversation and archives its stored history, "
                "starting it as a blank slate. The prior history is NOT deleted — it stays "
                "recoverable — but won't be shown or resumed here going forward.",
            )
        )
        if not ok:
            self._emit(R.note_line("Reset cancelled — nothing changed."))
            return
        self._clear_screen(archive=True)
        self._emit(R.success_line("Session reset — history archived, starting fresh from here."))

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

    # --- /rename -----------------------------------------------------
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
    @work
    async def _target_flow(self, rest: str) -> None:
        """`/target verify` re-probes; `/target <ip...>` sets directly; `/target`
        with no argument opens the same set-target prompt the new-session flow
        uses, so a mid-session target change is a first-class action rather than
        just a read-out of the current value."""
        rest = rest.strip()
        if rest == "verify":
            self._probe_target_worker()
            return
        if not rest:
            from kratos.tui_mk2.target_input import KRATOS_HOST_SENTINEL, KRATOS_HOST_VALUE

            current = ", ".join(self.session_state["targets"])
            answer = await self.app.push_screen_wait(PromptModal(
                "Set target",
                "IP/hostname(s) to investigate, space-separated (empty = keep current)",
                initial=current,
                quick_value=KRATOS_HOST_SENTINEL,
                quick_label="[Kratos-Host] — this machine (127.0.0.1)",
            ))
            if answer is None:
                self._emit(R.note_line(f"Target unchanged — current: {current or '(none set)'}"))
                return
            if answer == KRATOS_HOST_SENTINEL:
                self._apply_target([KRATOS_HOST_VALUE])
                return
            rest = answer.strip()
            if not rest:
                self._emit(R.note_line(f"Target unchanged — current: {current or '(none set)'}"))
                return
        await self._apply_target_checked(rest.split(), raw=rest)

    async def _apply_target_checked(self, tokens: list[str], raw: str) -> None:
        """Apply typed target tokens, but when they look like a pasted phrase
        rather than hosts (valid individually, ambiguous together) ASK instead
        of guessing — the clarify path for the target field."""
        from kratos.tui_mk2.modals import ClarifyModal
        from kratos.tui_mk2.target_input import looks_like_word_salad

        if looks_like_word_salad(tokens):
            n = len(tokens)
            answer = await self.app.push_screen_wait(ClarifyModal(
                f"“{raw}” looks more like a phrase than a set of hosts. What did you mean?",
                [
                    {"value": "first", "label": f"Just one target: {tokens[0]}",
                     "explanation": "Use only the first word as the host.", "recommended": True},
                    {"value": "multi", "label": f"All {n} as separate targets",
                     "explanation": ", ".join(tokens)},
                    {"value": "retype", "label": "Let me retype it",
                     "explanation": "Reopen the target prompt."},
                ],
            ))
            if answer in (None, "retype"):
                self._emit(R.note_line("Target unchanged — retype it with /target."))
                return
            if answer == "first":
                self._apply_target([tokens[0]])
                return
            if answer == "multi":
                self._apply_target(tokens)
                return
            # Typed something else: treat it as fresh target input.
            self._apply_target(answer.split())
            return
        self._apply_target(tokens)

    def _apply_target(self, targets: list[str]) -> None:
        """Set the active target(s), persist, refresh the header/footer, and run
        the setup checklist + probe. Shared by /target and the conversational
        'change target' control (after its approval). Validates first — the one
        choke point that stops a pasted command line / quoted goal from becoming
        an unresolvable active target (Sprint-4 gap)."""
        from kratos.tui_mk2.target_input import expand_host_aliases, validate_targets

        targets, err = validate_targets(expand_host_aliases(targets))
        if err:
            self._emit(R.error_line(err))
            return
        self.session_state["targets"] = targets
        self._store.set_targets(self.session_state["session_id"], targets)
        _kconfig.set_active_target(targets[0])
        self._refresh_header()
        self._refresh_footer()
        if len(targets) > 1:
            self._emit(
                R.note_line(
                    f"Using {targets[0]} — multi-target execution isn't implemented yet, so the "
                    f"other {len(targets) - 1} target(s) are stored but unused."
                )
            )
        self._emit(R.success_line(f"Target(s) set: {', '.join(targets)}"))
        if _kconfig.remember_first_target(self._data_dir, targets[0]):
            self._emit(R.note_line(f"Saved {targets[0]} as your default target for command-line and "
                                   "scheduled runs."))
        self._setup_target_worker(targets[0])

    @work(thread=True)
    def _setup_target_worker(self, target_host: str) -> None:
        self._show_target_setup(target_host)  # blocking SSH checklist + probe

    @work(thread=True)
    def _probe_target_worker(self) -> None:
        self._probe_target()

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

    # --- model cost/privacy blurb (used by the Settings Models tab) ------
    @staticmethod
    def _profile_blurb(values: dict[str, str]) -> str:
        """Honest cost/privacy disclosure per backend option. A
        thin delegate to render.profile_blurb so the Settings screen can render
        the same line with no live session (single source of truth)."""
        return R.profile_blurb(values)

    # --- /evolve ---------------------------------------------------------
    # Persisted (like the first-run "trusted" flag) once the /evolve explainer
    # has been seen, so it is shown before a user's first build and never again
    # unless asked for with /evolve help.
    _EVOLVE_INTRO_SEEN_KEY = "evolve_intro_seen"

    def _evolve_entry(self, rest: str) -> None:
        from kratos.tui_mk2.modals import EvolveIntroModal

        arg = rest.strip().lower()
        if arg in ("help", "?", "intro", "explain"):
            self.app.push_screen(EvolveIntroModal(first_time=False))
            return
        if arg in ("list", "ls") or _kconfig.load_local_config(self._data_dir).get(self._EVOLVE_INTRO_SEEN_KEY):
            self._evolve_flow(rest)
            return
        self._evolve_intro_then_build(rest)

    @work(group="evolve-intro")
    async def _evolve_intro_then_build(self, rest: str) -> None:
        from kratos.tui_mk2.modals import EvolveIntroModal

        go = await self.app.push_screen_wait(EvolveIntroModal(first_time=True))
        # Seen either way: "not now" is still having read it.
        _kconfig.save_local_config(self._data_dir, **{self._EVOLVE_INTRO_SEEN_KEY: True})
        if go:
            self._evolve_flow(rest)
        else:
            self._emit(R.note_line("Run /evolve whenever you're ready — /evolve help shows that explainer again."))

    @work(thread=True)
    def _evolve_flow(self, rest: str) -> None:
        """Guided /evolve. Drives the UI-agnostic guided build
        (agent.guided_evolve.run_guided_build) through a Textual prompter, so
        the whole write -> test -> approve -> keep experience -- plain-English
        review of what the test checks, recovery guidance, the friendly keep
        prompt -- is shared with the conversational pipeline-drafting flow's
        own missing-tool hand-off rather than reimplemented here. A thread
        worker because the build ends in the
        blocking loop; each prompt bridges back to the event loop."""
        from kratos.agent.guided_evolve import run_guided_build
        from kratos.tui_mk2.guided import TextualGuidedPrompter

        stripped = rest.strip()
        if stripped.lower() in ("list", "ls"):
            self.app.call_from_thread(self._render_evolve_list)
            return

        idea = stripped.strip('"').strip("'").strip()
        suggested_name = None
        if not idea:
            pending = self.session_state.get("pending_evolve_suggestion")
            if pending:
                idea = f"{pending.get('name', '')}: {pending.get('description', '')}".strip(": ")
                suggested_name = pending.get("name") or None
            # else: leave idea empty -- run_guided_build asks for it itself.

        prompter = TextualGuidedPrompter(self.app, self)
        self._set_busy(True)
        result = None
        try:
            result = run_guided_build(idea, prompter, suggested_name=suggested_name)
        except Exception as e:  # noqa: BLE001 -- never crash the screen
            self._emit_from_worker(R.error_line(f"Evo-loop errored: {e}"))
        finally:
            self._set_busy(False)
        # Clear a pending auto-suggestion only once we actually acted on it (a
        # build ran, to any outcome). A plain cancel / back-out or a "saved to
        # edit" keeps it, so the user can retry with bare /evolve.
        if result is not None and result.status not in ("cancelled", "no_harness"):
            self.session_state["pending_evolve_suggestion"] = None

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

    # --- /tools (classified overview) ------------------------------------
    # --- /tool <name>: deterministic single-tool run --------------------
    def _tool_picker_entries(self) -> list[tuple[str, str]]:
        from kratos.agent.tools import TOOL_REGISTRY

        entries = []
        for n in sorted(TOOL_REGISTRY):
            desc = (TOOL_REGISTRY[n].description or "").splitlines()[0]
            entries.append((n, desc[:70]))
        return entries

    @work
    async def _tool_flow(self, rest: str) -> None:
        """`/use <name> [json-args]` runs EXACTLY that tool via the real
        dispatch (execute_tool_call) with NO model tool-selection — the
        deterministic override for when you know which tool you want. Bare
        `/use` opens a searchable picker. Approval gates and the pre-dispatch
        guards still apply (this is the same path the agent uses, chosen by you)."""
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.tui_mk2.modals import ToolPickerModal

        parts = rest.split(maxsplit=1)
        args: dict[str, Any] = {}
        if not parts:
            # Bare /use -> searchable pick-from-list (type to filter).
            picked = await self.app.push_screen_wait(ToolPickerModal(self._tool_picker_entries()))
            if not picked:
                return
            name = picked
        else:
            name = parts[0]
            argstr = parts[1].strip() if len(parts) > 1 else ""
            if argstr:
                try:
                    parsed = json.loads(argstr)
                    if not isinstance(parsed, dict):
                        raise ValueError("args must be a JSON object")
                    args = parsed
                except Exception as e:  # noqa: BLE001
                    self._emit(R.error_line(
                        f"Couldn't parse args: {e}. Pass a JSON object, e.g. "
                        '/use check_ip_reputation {"ip": "1.2.3.4"}'))
                    return
        if name not in TOOL_REGISTRY:
            near = [t for t in sorted(TOOL_REGISTRY) if name.lower() in t.lower()]
            hint = f" Did you mean: {', '.join(near[:3])}?" if near else ""
            self._emit(R.error_line(f"No tool named '{name}'. See /tools for the list.{hint}"))
            return
        # Arg discovery: if a required arg is missing, show the tool's parameters
        # as usage instead of dispatching into a cryptic "missing argument" error.
        missing = self._missing_required_args(TOOL_REGISTRY[name], args)
        if missing:
            self._emit(self._tool_usage(name, TOOL_REGISTRY[name], missing))
            return
        self._run_tool_worker(name, args)

    def _missing_required_args(self, tool: Any, args: dict[str, Any]) -> list[str]:
        """Required handler params (no default) not satisfied by args. data_dir
        is auto-injected by execute_tool_call, so it never counts as missing."""
        import inspect

        try:
            sig = inspect.signature(tool.handler)
        except (ValueError, TypeError):
            return []
        missing = []
        for pname, p in sig.parameters.items():
            if pname == "data_dir" or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                continue
            if p.default is p.empty and pname not in args:
                missing.append(pname)
        return missing

    def _tool_usage(self, name: str, tool: Any, missing: list[str]) -> Text:
        params = getattr(tool, "parameters", {}) or {}
        body = Text()
        body.append(f"/use {name} needs: ", style=T.ATTENTION)
        body.append(", ".join(missing), style=f"bold {T.TEXT_BRIGHT}")
        for pname in missing:
            spec = params.get(pname) or {}
            body.append(f"\n  {pname}", style=f"bold {T.ACCENT}")
            if spec.get("type"):
                body.append(f" ({spec['type']})", style=T.TEXT_DIM)
            if spec.get("description"):
                body.append(f" — {spec['description']}", style=T.TEXT_MUTED)
        example = "{" + ", ".join(f'"{m}": ...' for m in missing) + "}"
        body.append(f"\nPass as JSON, e.g.  /use {name} {example}", style=T.TEXT_DIM)
        return body

    @work(thread=True, exclusive=True, group="turn")
    def _run_tool_worker(self, name: str, args: dict[str, Any]) -> None:
        from kratos.agent.loop import execute_tool_call

        self._set_busy(True)
        self._emit_from_worker(R.note_line(f"Running '{name}' directly (deterministic — no model tool-selection)…"))
        try:
            result = execute_tool_call(name, args, self._data_dir)
        except Exception as e:  # noqa: BLE001 -- should be wrapped already, but never crash the screen
            self._emit_from_worker(R.error_line(f"{name} errored: {e}"))
            self._set_busy(False)
            return
        inner, status = R.unwrap_tool_result(result)
        if status == "error":
            self._emit_from_worker(R.error_line(f"{name} failed — {R.error_detail(inner) or 'no error detail'}"))
        elif name == "correlate_findings" and isinstance(inner, dict) and inner.get("findings"):
            self._emit_from_worker(R.tool_call_line(name, status))
            t, d = self._stamp_now()
            for f in inner["findings"]:
                self._emit_bubble_from_worker(R.finding_panel(f, time_str=t), d)
        else:
            self._emit_from_worker(R.tool_call_line(name, status))
            body = json.dumps(inner, indent=2, default=str) if isinstance(inner, (dict, list)) else str(inner)
            if len(body) > 4000:
                body = body[:4000] + "\n… (truncated)"
            t, d = self._stamp_now()
            self._emit_bubble_from_worker(R.result_panel(f"{name} — result", body, T.ACCENT, time_str=t), d)
        self._set_busy(False)

    def _render_tools(self) -> None:
        """A read-only peek at every tool the agent can reach, grouped by kind:
        Default (built into Kratos), Kept (written & approved via /evolve), and
        Installed (kept tools that needed a package installed first — a future
        category, empty today). Each row shows a short description: a human/AI
        note from the tool's metadata if set, else its own registered
        description. Code review + description editing live in /settings → Tools."""
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

        metadata = _read_metadata(KEPT_TOOLS_DIR)
        default_names: list[str] = []
        kept_names: list[str] = []
        installed_names: list[str] = []
        for name in sorted(TOOL_REGISTRY):
            entry = metadata.get(name)
            if entry is None:
                default_names.append(name)
            elif entry.get("installed"):
                installed_names.append(name)
            else:
                kept_names.append(name)

        self._emit(Text(""))
        self._emit(Text(f"Tools Kratos can use — {len(TOOL_REGISTRY)} total", style=f"bold {T.KRATOS_RED}"))
        self._emit(self._tools_table("Default Tools", "built into Kratos", default_names, metadata, kept=False))
        self._emit(self._tools_table("Kept Tools", "written & approved via /evolve", kept_names, metadata, kept=True))
        self._emit(self._tools_table(
            "Installed Tools", "kept tools backed by a package installed via an approved command",
            installed_names, metadata, kept=True))
        if not installed_names:
            self._emit(Text(
                "  (none yet — this category is for tools that need a package installed first)",
                style=T.TEXT_GHOST))
        self._emit(Text("Review a kept tool's code or edit its description in /settings → Tools.", style=T.TEXT_FAINT))

    def _tools_table(self, heading: str, subtitle: str, names: list[str], metadata: dict, kept: bool):
        from kratos.agent.tools import TOOL_REGISTRY
        from rich.table import Table

        table = Table(
            show_header=True, header_style="bold", title=f"{heading} — {len(names)}",
            title_justify="left", title_style=f"bold {T.TEXT_BRIGHT}",
            caption=subtitle, caption_justify="left", caption_style=T.TEXT_GHOST)
        table.add_column("Name", no_wrap=True)
        if kept:
            table.add_column("Approval")
            table.add_column("Kept at")
        table.add_column("Description")
        for name in names:
            tool = TOOL_REGISTRY[name]
            entry = metadata.get(name)
            row: list[Any] = [Text(name, style=T.ACCENT)]
            if kept:
                row.append(Text("required" if tool.requires_approval else "auto",
                                style=T.ATTENTION if tool.requires_approval else T.TEXT_DIM))
                row.append(Text(str((entry or {}).get("kept_at", "")), style=T.TEXT_FAINTER))
            row.append(Text(R.tool_description(tool, entry), style=T.TEXT_MUTED))
            table.add_row(*row)
        return table

    # --- deterministic subcommand shortcuts (/scan, /run, ...) -----------
    @work(thread=True)
    def _run_shortcut(self, subcommand: str, rest: str) -> None:
        """Run a fixed-pipeline subcommand (the same build_parser() ->
        args.func(args) path `kratos <sub>` uses from the shell) and capture
        its output into the transcript. Those commands print via plain print()
        and the classic Rich console to stdout; captured here (worker thread,
        brief) and shown as a panel. ANSI is stripped so it reads cleanly in
        the log. Any approval the command triggers still routes to the modal
        via the provider (worker-thread safe)."""
        import contextlib
        import io

        from kratos.cli.app import build_parser

        self._set_busy(True)
        try:
            parser = build_parser()
            argv = ["--data-dir", str(self._data_dir), subcommand, *rest.split()]
            try:
                parsed = parser.parse_args(argv)
            except SystemExit:
                self._emit_from_worker(R.error_line(f"Could not parse arguments for /{subcommand}: {rest!r}"))
                return
            self._emit_from_worker(R.note_line(f"Running /{subcommand}…"))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                try:
                    parsed.func(parsed)
                except Exception as e:  # noqa: BLE001 -- surface, don't crash the TUI
                    buf.write(f"\n[error] {e}\n")
            text = _ANSI_RE.sub("", buf.getvalue()).rstrip()
            self._emit_from_worker(R.result_panel(f"kratos {subcommand}", text or "(no output)", T.ACCENT))
        finally:
            self._set_busy(False)

    # --- /run: the deterministic standard audit --------------------
    # --- preview-plan: pre-run confirm gate + /plan on demand -------
    def _plan_gate_enabled(self) -> bool:
        """Whether heavy deterministic runs (the standard audit / future
        pipelines) show a preview+confirm before running. Default ON (novice-
        facing + a slow backend -> automatic protection beats a command you have
        to remember). Persisted in local config; toggle with `/plan gate off`."""
        cfg = _kconfig.load_local_config(self._data_dir)
        return bool(cfg.get("plan_gate", True))

    def _target_label(self) -> str:
        return self.session_state["targets"][0] if self.session_state["targets"] else "the target"

    @work
    async def _run_standard_audit_gated(self) -> None:
        """Build the EXACT preview (cheap, no LLM, no target contact),
        show it for confirm/cancel if the gate is on, then run the existing
        deterministic audit worker. Cancel runs nothing and leaves clean state."""
        from kratos.agent.plan_preview import preview_pipeline
        from kratos.agent.pipeline import standard_audit_steps

        if self._plan_gate_enabled():
            preview = preview_pipeline(standard_audit_steps(), self._target_label())
            proceed = await self.app.push_screen_wait(PlanPreviewModal(preview))
            if not proceed:
                self._emit(R.note_line("Standard audit cancelled — nothing ran."))
                return
        self._run_standard_audit()

    @work(thread=True)
    def _plan_flow(self, rest: str) -> None:
        """/plan -- preview a run's plan WITHOUT running it (the same renderer the
        gate uses). No arg -> the standard audit (exact). A preset name -> that
        preset (exact if it's a pipeline, predicted if it's an agentic goal).
        Free text -> a predicted agentic plan. `/plan gate [on|off]` toggles the
        auto-gate. A thread worker because the predicted path makes one LLM call;
        the cheap paths just render."""
        from kratos.agent.plan_preview import preview_agentic, preview_pipeline
        from kratos.agent.pipeline import standard_audit_steps
        from kratos.agent import presets as _P

        rest = (rest or "").strip()
        parts = rest.split(maxsplit=1)

        # `/plan gate [on|off]`
        if parts and parts[0].lower() == "gate":
            arg = parts[1].strip().lower() if len(parts) > 1 else ""
            if arg in ("on", "off"):
                _kconfig.save_local_config(self._data_dir, plan_gate=(arg == "on"))
                state = "on" if arg == "on" else "off"
                self._emit_from_worker(R.note_line(
                    f"Pre-run plan gate is now {state}. "
                    + ("Heavy runs will preview + ask before running." if arg == "on"
                       else "Heavy runs start immediately; use /plan to preview on demand.")))
            else:
                cur = "on" if self._plan_gate_enabled() else "off"
                self._emit_from_worker(R.note_line(
                    f"Pre-run plan gate is {cur}. Use /plan gate on  or  /plan gate off to change it."))
            return

        target = self._target_label()

        # No arg -> the deterministic standard audit's exact plan.
        if not rest:
            self._emit_from_worker(R.plan_preview_panel(
                preview_pipeline(standard_audit_steps(), target)))
            return

        # An existing preset name -> preview that preset.
        preset = _P.load_preset(self._data_dir, rest) if _P.preset_exists(self._data_dir, rest) else None
        if preset is not None:
            ptarget = preset.target or target
            if preset.kind == "pipeline":
                # A pipeline preset has an EXACT declared step list (a `when` step
                # renders as conditional). Preview the parsed, normalized steps.
                if preset.steps:
                    from kratos.agent.pipeline import steps_from_specs
                    self._emit_from_worker(R.plan_preview_panel(
                        preview_pipeline(steps_from_specs(preset.steps), ptarget,
                                         title=f"Preset: {preset.name}")))
                    return
                self._emit_from_worker(R.note_line(
                    f"Preset {preset.name!r} is a pipeline but declares no valid steps to preview."))
                return
            if preset.goal:
                self._emit_from_worker(R.note_line(
                    f"Predicting the plan for preset {preset.name!r} (one quick model call)…"))
                self._emit_from_worker(R.plan_preview_panel(
                    preview_agentic(preset.goal, ptarget)))
                return
            self._emit_from_worker(R.note_line(
                f"Preset {preset.name!r} has no goal to preview."))
            return

        # Free text -> a predicted agentic plan for that goal.
        self._emit_from_worker(R.note_line("Predicting the plan (one quick model call)…"))
        self._emit_from_worker(R.plan_preview_panel(preview_agentic(rest, target)))

    def _run_standard_audit(self) -> None:
        """Built-in standard audit -- a thin call into the shared pipeline
        turn worker with the fixed, target-correct step sequence. No LLM in the
        decision path; nothing about Kratos's own host is folded into the
        target's findings (standard_audit_steps is target-facing by design)."""
        from kratos.agent.pipeline import standard_audit_steps

        target = self.session_state["targets"][0] if self.session_state["targets"] else "the target"
        self._run_pipeline_turn(
            standard_audit_steps(),
            turn_label="/run — standard audit",
            intro=(f"Standard audit — a fixed, deterministic security sweep of {target} "
                   "(no LLM; same steps every run)."),
            remember_label="/run — standard audit",
            remember_kind="deterministic audit",
        )

    def _pipeline_host_note(self, steps: list[Any], target_label: str) -> Text | None:
        """Target-correctness: a labeled note when a pipeline includes
        Kratos-HOST tools, so their output is never silently read as the target's.
        Returns None for a purely target-facing pipeline (the common case)."""
        from kratos.agent.pipeline import is_local_host_tool

        local = sorted({s.tool for s in steps if is_local_host_tool(s.tool)})
        has_target = any(not is_local_host_tool(s.tool) for s in steps)
        if local and has_target:
            return R.note_line(
                f"Note: this pipeline mixes checks — {', '.join(local)} run on THIS Kratos "
                f"host, the rest on {target_label}. Host-tool results describe the Kratos "
                "machine, never the target.")
        if local and not has_target:
            return R.note_line(
                f"Note: every step here inspects THIS Kratos host, not {target_label} — the "
                "findings describe the Kratos machine, not the target.")
        return None

    @work(thread=True, exclusive=True, group="turn")
    def _run_pipeline_turn(
        self,
        steps: list[Any],
        *,
        turn_label: str,
        intro: str,
        remember_label: str,
        remember_kind: str = "pipeline",
        pin_target: str | None = None,
    ) -> None:
        """Shared worker for any deterministic pipeline run (the built-in
        standard audit AND a user's kind='pipeline' preset). Renders mk2-first:
        per-step tool-call lines and finding panels while it runs, then a
        run-summary panel; persists the step transcript so /report can pull an
        audit turn's findings; evaluates triggers. A per-preset `pin_target` is
        set for this run and restored after (like /investigate-host), so a
        pipeline preset can target a specific host without changing the session
        target."""
        from kratos.agent.pipeline import run_pipeline

        self._set_busy(True)
        # Per-preset target pin (restored in every exit path below).
        prior_target = None
        if pin_target and pin_target != _kconfig.get_active_target():
            prior_target = _kconfig.get_active_target()
            _kconfig.set_active_target(pin_target)
        run_target = _kconfig.get_active_target()
        target_label = pin_target or (
            self.session_state["targets"][0] if self.session_state["targets"] else "the target")

        # Concurrency: one run per target at a time. Bail cleanly if a
        # background scheduled run (or another investigation) holds the target.
        audit_lock = _target_lock.try_acquire_target(self._data_dir, run_target)
        if audit_lock is None:
            self._emit_from_worker(R.note_line(
                f"A run is active on {target_label} (likely a scheduled audit) — waiting for it "
                "to finish… (usually quick; press esc to stop)"))
            audit_lock = _target_lock.acquire_target_blocking(
                self._data_dir, run_target, timeout=20.0,
                should_stop=lambda: get_current_worker().is_cancelled)
        if audit_lock is None:
            self._emit_from_worker(R.note_line(
                f"{target_label} is still busy (it may be a long run) — try again in a bit."))
            if prior_target is not None:
                _kconfig.set_active_target(prior_target)
            self._set_busy(False)
            return

        self._emit_from_worker(R.note_line(intro))
        host_note = self._pipeline_host_note(steps, target_label)
        if host_note is not None:
            self._emit_from_worker(host_note)
        turn_id = self._store.start_turn(self.session_state["session_id"], turn_label)
        started = time.monotonic()
        worker = get_current_worker()

        def _on_step(sr) -> None:
            if worker.is_cancelled:
                raise _CancelInvestigation()
            if sr.status == "ok":
                if sr.tool == "correlate_findings" and sr.result and sr.result.get("findings"):
                    findings = sr.result["findings"]
                    line = Text()
                    line.append("✓ ", style=T.SAFE)
                    line.append(sr.tool, style=f"bold {T.ACCENT}")
                    line.append(f"  correlated findings ({len(findings)} found)", style=T.TEXT_MUTED)
                    self._emit_from_worker(line)
                    for f in findings:
                        t, d = self._stamp_now()
                        self._emit_bubble_from_worker(R.finding_panel(f, time_str=t), d)
                else:
                    self._emit_from_worker(R.tool_call_line(sr.tool, "done"))
            elif sr.status == "skipped":
                self._emit_from_worker(R.note_line(f"{sr.label} — skipped ({sr.detail or 'condition not met'})"))
            elif sr.status == "not_approved":
                self._emit_from_worker(R.note_line(f"{sr.tool} — not approved; skipped"))
            else:
                self._emit_from_worker(R.error_line(f"{sr.tool} failed — {sr.detail or 'no error detail'}"))
            self.app.call_from_thread(self._refresh_footer)

        try:
            outcome = run_pipeline(steps, self._data_dir, on_step=_on_step)
        except _CancelInvestigation:
            self._store.complete_turn(turn_id, "cancelled", transcript_ref=None)
            self._emit_from_worker(R.note_line("Interrupted — nothing was left running on the target."))
            self._remember_turn(remember_label, "(run interrupted before it concluded)")
            return
        except Exception as e:  # noqa: BLE001
            self._store.complete_turn(turn_id, "error", transcript_ref=None)
            self._emit_from_worker(R.error_line(f"{remember_label} errored: {e}"))
            return
        finally:
            self._set_busy(False)
            _target_lock.release_target(audit_lock)
            if prior_target is not None:
                _kconfig.set_active_target(prior_target)

        duration = time.monotonic() - started
        t, d = self._stamp_now()
        self._emit_bubble_from_worker(
            R.audit_summary_panel(
                status=outcome.status,
                ran=outcome.ran,
                total=len(outcome.steps),
                severity_tally=outcome.severity_tally,
                duration_s=duration,
                aborted_on=outcome.aborted_on,
                time_str=t,
            ),
            d,
        )
        self._emit_from_worker(Text(f"Done in {duration:.0f}s", style=T.TEXT_FAINTER))

        # Evaluate triggers against this run's findings. run_investigations
        # =False keeps an interactive run snappy — an investigate-action trigger
        # notifies that the deeper look runs on the scheduled cadence rather than
        # blocking here on an LLM call (the target lock is already released too).
        try:
            from kratos.agent.trigger_eval import evaluate_triggers
            for tf in evaluate_triggers(self._data_dir, outcome.findings, run_target,
                                        run_investigations=False):
                self._emit_from_worker(R.trigger_fire_line(tf))
        except Exception as e:  # noqa: BLE001
            self._emit_from_worker(R.note_line(f"(trigger evaluation skipped: {e})"))

        # Persist a step transcript for the turn record (not a run_agent
        # transcript -- a deterministic pipeline has no LLM reasoning). Each step
        # carries an `observation` in execute_tool_call's wrapped shape
        # ({"status": "ok", "result": <tool return>}), so /report's
        # _collect_session_findings (and mcp_server.kratos_get_findings, same
        # path) can pull the correlate_findings findings out of an audit turn
        # exactly as it does for an agentic investigation turn.
        def _step_observation(s) -> dict[str, Any]:
            if s.status == "ok":
                return {"status": "ok", "result": s.result or {}}
            return {"status": s.status, "observation": s.detail}

        transcript = [
            {"tool": s.tool, "label": s.label, "status": s.status,
             "detail": s.detail, "observation": _step_observation(s)}
            for s in outcome.steps
        ]
        transcript_path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        transcript_path.write_text(json.dumps(transcript, indent=2, default=str), encoding="utf-8")
        status = "final_answer" if outcome.status == "completed" else "error"
        self._store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))
        n = sum(outcome.severity_tally.values())
        self._remember_turn(
            remember_label,
            f"({remember_kind} {outcome.status}; {outcome.ran}/{len(outcome.steps)} steps, {n} finding(s))",
        )
        self.app.call_from_thread(self._refresh_footer)

    # --- goal handling: chat vs investigate ------------------------------
    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        # Stamp the start so the activity spinner can show elapsed time. Safe to
        # set from a worker thread (plain assignment); the spinner tick reads it
        # on the event loop.
        self._busy_since = time.monotonic() if busy else None

    def _tick_activity(self) -> None:
        """Event-loop interval: animate a 'working…' spinner + elapsed time
        while a turn runs, so the silent gap before the first output (and long
        thinking-model pauses) shows visible progress. Cleared when idle."""
        try:
            act = self.query_one("#activity", Static)
        except Exception:  # noqa: BLE001 -- widget not mounted yet
            return
        if self._busy and self._busy_since is not None:
            self._spin_i = (self._spin_i + 1) % len(_SPINNER)
            elapsed = time.monotonic() - self._busy_since
            act.update(Text(f"{_SPINNER[self._spin_i]} hacking… {elapsed:.0f}s", style=T.ACCENT))
            self._activity_active = True
        elif self._activity_active:
            act.update("")
            self._activity_active = False

    def action_rerun(self) -> None:
        """Re-run the last goal (honest re-run, not a mid-loop
        resume). Handy right after an interrupt, or to repeat a goal."""
        if self._busy:
            self.notify("A turn is already running.", timeout=3)
            return
        if not self._last_goal:
            self.notify("Nothing to re-run yet.", timeout=3)
            return
        t, d = self._stamp_now()
        self._emit_stamped(self._you_header(self._last_goal), t, d)
        self._emit(R.note_line("Re-running the previous goal."))
        self._run_goal(self._last_goal)

    @work(thread=True, exclusive=True, group="turn")
    def _run_goal(self, goal: str) -> None:
        from kratos.tui_mk2.command_intent import route_message

        self._last_goal = goal
        self._set_busy(True)
        started = time.monotonic()
        try:
            route = route_message(goal, self.session_state.get("resume_context", ""))
        except Exception as e:  # noqa: BLE001
            self._emit_from_worker(R.error_line(f"Routing failed: {e}"))
            self._set_busy(False)
            return

        # If Ctrl+C / esc was pressed DURING the routing call (the first, and on a
        # thinking model slow, LLM call — which can't be interrupted mid-flight),
        # honor it the moment that call returns, instead of marching on to
        # "Starting investigation…" for a turn the user already asked to stop.
        if get_current_worker().is_cancelled:
            self._emit_from_worker(R.note_line(
                "Interrupted — stopped before it started. Press Ctrl+R to run it, or type a new one."))
            self._set_busy(False)
            return

        if route.kind == "failed":
            self._emit_from_worker(R.llm_failure_banner(route.reason or "no detail available"))
            self._set_busy(False)
            return

        if route.kind == "command":
            # A conversational control request. Controls run on the event loop
            # (they show modals / push screens); the user's line was already
            # echoed, so this turn is done as far as the thread worker.
            self.app.call_from_thread(self._on_command_intent, route.command, route.args)
            self._set_busy(False)
            return

        if route.kind == "clarify_host":
            # The router couldn't tell target vs. Kratos's own host. Ask on the
            # event loop, then launch the right investigation worker from there
            # (this worker is done — the follow-up owns its own busy flag).
            self.app.call_from_thread(self._clarify_host_flow, goal)
            self._set_busy(False)
            return

        if route.kind == "preset_new":
            # "save this as a preset called X …" — extracted name+goal. Confirm on
            # the event loop before writing (the model extracted it; the human
            # gets the last word), then this worker is done.
            self.app.call_from_thread(
                self._preset_new_conversational, route.preset_name, route.preset_goal)
            self._set_busy(False)
            return

        if route.kind == "preset_run":
            # "run my X preset" — resolve + run on the event loop (which may kick
            # its own investigation worker).
            self.app.call_from_thread(self._preset_run_conversational, route.preset_name)
            self._set_busy(False)
            return

        if route.kind == "pipeline_suggest":
            # The message sounds like a multi-step pipeline. Only
            # SUGGEST /preset-describe — never auto-draft or auto-run (drafting is
            # code generation; entry into it must be explicit). Same
            # suggest-don't-auto-act shape as the tool_proposal auto-suggest.
            self.app.call_from_thread(self._suggest_describe, route.preset_goal)
            self._set_busy(False)
            return

        if route.kind == "chat":
            reply = route.reply or ""
            t, d = self._stamp_now()
            self._emit_stamped_from_worker(self._kratos_header(), t, d)
            self._emit_from_worker(Text(reply or "(no reply)", style=T.TEXT))
            self._last_answer = reply
            self._last_commands = []  # a chat reply carries no remediation commands
            self._runnable_fixes = []
            self._log_chat_turn(goal, reply)
            self._ctx_chars += len(goal) + len(reply)
            self._maybe_auto_compact()  # keep the growing chat context within the window
            self._emit_from_worker(Text(f"Done in {time.monotonic() - started:.0f}s", style=T.TEXT_FAINTER))
            self.app.call_from_thread(self._refresh_footer)
            self._set_busy(False)
            return

        # kind == "investigate" (monitored target) or "investigate_host"
        # (Kratos's OWN machine — only when the user unambiguously asked for it).
        # Handled in THIS worker (not a second one) so the busy flag never hands
        # off mid-turn. Self-host pins the active target to loopback for the run.
        if route.kind == "investigate_host":
            self._run_investigation(goal, target_override="127.0.0.1")
        else:
            self._run_investigation(goal)
        self._maybe_auto_compact()
        self._set_busy(False)

    # --- /investigate-host: deliberate self-investigation --------------------
    _HOST_GOAL_DEFAULT = (
        "Give a security situation report on THIS Kratos host itself: check its own "
        "auth/system logs, listening ports, and running processes for anything unusual."
    )

    def _investigate_host_flow(self, rest: str) -> None:
        """`/investigate-host [goal]` (aliases /investigate-self, /host) —
        deliberately investigate the Kratos machine itself instead of the
        configured target. Explicit-intent only: the default host for any
        investigation is always the monitored target; self-investigation
        happens only through this command or an unambiguous NL self-reference
        (routed as kind='investigate_host'). Reached from the event loop; the
        actual run is a thread worker so it owns the busy flag cleanly."""
        goal = rest.strip() or self._HOST_GOAL_DEFAULT
        self._run_host_investigation(goal)

    @work(thread=True, exclusive=True, group="turn")
    def _run_host_investigation(self, goal: str) -> None:
        self._last_goal = goal
        self._set_busy(True)
        try:
            self._run_investigation(goal, target_override="127.0.0.1")
            self._maybe_auto_compact()
        finally:
            self._set_busy(False)

    @work(thread=True, exclusive=True, group="turn")
    def _run_target_investigation(self, goal: str) -> None:
        """Investigate the configured monitored target — the worker entry used
        when a clarify resolves to 'target' (the normal in-`_run_goal` path
        already covers the unambiguous case)."""
        self._last_goal = goal
        self._set_busy(True)
        try:
            self._run_investigation(goal)
            self._maybe_auto_compact()
        finally:
            self._set_busy(False)

    @work
    async def _clarify_host_flow(self, goal: str) -> None:
        """Router was unsure which host — ask, then launch the right worker.
        Default/recommended is the monitored target (matching the router's own
        default-to-target rule); dismiss = do nothing (user can retype)."""
        from kratos.tui_mk2.modals import ClarifyModal

        current = self.session_state["targets"][0] if self.session_state["targets"] else "(none set)"
        answer = await self.app.push_screen_wait(ClarifyModal(
            "Did you mean the monitored target, or the Kratos host itself?",
            [
                {"value": "target", "label": "The monitored target",
                 "explanation": f"{current} — the system Kratos watches.", "recommended": True},
                {"value": "host", "label": "This Kratos host",
                 "explanation": "The machine Kratos runs on (a self-check)."},
            ],
            subtitle=f"Your request: {goal}",
        ))
        if answer == "host":
            self._run_host_investigation(goal)
        elif answer == "target":
            self._run_target_investigation(goal)
        # None / anything else: let the user retype rather than guess.

    # --- conversational controls (design: talk-to-run, approval-gated) ---
    def _on_command_intent(self, name: str, args: str) -> None:
        """Dispatch a control the user asked for in plain language (see
        tui_mk2/command_intent.py). Runs on the event loop. Read-only controls
        run immediately; model/target (what Kratos talks to) go through an
        explicit y/n confirm inside their own handlers."""
        args = (args or "").strip()
        self._emit(R.note_line(
            f"Interpreting that as the '{name}' control{f' — {args}' if args else ''}."))
        if name == "report":
            self._render_report()
        elif name == "tools":
            self._render_tools()
        elif name == "help":
            self.app.push_screen(HelpModal())
        elif name == "rename":
            self._rename_flow(args)
        elif name == "timezone":
            self._cmd_timezone(args)
        elif name == "model":
            self._conversational_model(args)
        elif name == "target":
            self._conversational_target(args)

    @work
    async def _conversational_model(self, args: str) -> None:
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH

        candidates, current = _p.list_candidate_profiles(ENV_FILE_PATH)
        if not args:
            active = current.model if current else "(none)"
            listed = ", ".join(c.model for c in candidates) or "(none configured)"
            self._emit(R.note_line(
                f"Active model: {active}. Available: {listed}. Say 'switch to <name>', or open /model."))
            return
        matches = [c for c in candidates if c.model.lower() == args.lower()]
        if not matches:
            matches = [c for c in candidates if args.lower() in c.model.lower()]
        if not matches:
            listed = ", ".join(c.model for c in candidates) or "(none)"
            self._emit(R.error_line(f"No configured model matches {args!r}. Available: {listed}."))
            return
        if len(matches) > 1:
            self._emit(R.note_line(
                f"{args!r} matches several models: {', '.join(m.model for m in matches)}. Be more specific."))
            return
        target = matches[0]
        if current is not None and target.model == current.model:
            self._emit(R.note_line(f"{target.model} is already active."))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Switch model?",
            f"Switch the active LLM backend to '{target.model}'?\n\n{self._profile_blurb(target.values)}"))
        if not ok:
            self._emit(R.note_line("Model switch cancelled — nothing changed."))
            return
        self._switch_model_worker(target, current)

    @work(thread=True)
    def _switch_model_worker(self, target: Any, current: Any) -> None:
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH, set_active_llm_profile
        from kratos.llm_interface import check_endpoint_reachable

        problems = _p.validate_profile(target)
        if problems:
            self._emit_from_worker(R.error_line(f"Can't switch to {target.model}: {'; '.join(problems)}"))
            return
        self._emit_from_worker(R.note_line(f"Checking {target.model} is reachable…"))
        reachable, detail = check_endpoint_reachable(target.values["LLM_BASE_URL"], target.values["LLM_API_KEY"])
        if not reachable:
            self._emit_from_worker(R.error_line(f"Can't switch to {target.model} — not reachable ({detail})."))
            return
        values = dict(target.values)
        set_active_llm_profile(values)
        _p.switch_profile(ENV_FILE_PATH, target, current)
        # Detect-once-and-save the context window if this profile has none.
        from kratos.adapters.llm_context_autofill import autofill_context_window, describe
        ctx_note = describe(autofill_context_window(ENV_FILE_PATH, values), target.model)
        if ctx_note:
            set_active_llm_profile(values)   # re-sync with the newly saved window
        self.session_state["backend"] = target.model
        self.app.call_from_thread(self._refresh_footer)
        self._emit_from_worker(R.success_line(f"Switched to {target.model} — active now, saved to .env."))
        if ctx_note:
            self._emit_from_worker(R.note_line(ctx_note))

    @work
    async def _conversational_target(self, args: str) -> None:
        if not args:
            current = ", ".join(self.session_state["targets"]) or "(none set)"
            self._emit(R.note_line(f"Current target: {current}. Say 'change target to <ip>' to switch."))
            return
        from kratos.tui_mk2.target_input import validate_targets

        targets, err = validate_targets(args.split())
        if err:
            # Reject before the approval modal — don't ask the user to confirm
            # switching to something that isn't a host in the first place.
            self._emit(R.error_line(err))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Change target?",
            f"Change the investigation target to {', '.join(targets)}?\n\n"
            "Kratos will investigate this host (read/observe-only) from now on. "
            "Nothing runs on it without a further approval."))
        if not ok:
            self._emit(R.note_line("Target change cancelled — nothing changed."))
            return
        self._apply_target(targets)

    def _run_investigation(self, goal: str, target_override: str | None = None) -> None:
        from kratos.agent.loop import run_agent

        # /investigate-host (and its NL trigger) pin the active target to
        # loopback for THIS run only, so Kratos investigates its own machine on
        # explicit request. run_agent resolves the host via the global active
        # target (same pattern the MCP server uses), so we set + restore it
        # around the call; loop.py's _LOOPBACK_SELF_TARGETS already permits it.
        prior_active = None
        if target_override:
            prior_active = _kconfig.get_active_target()
            _kconfig.set_active_target(target_override)
            self._emit_from_worker(R.note_line(
                f"Investigating THIS Kratos host ({target_override}) — its own logs, ports, and "
                "posture, not the configured target."))
        # Concurrency: take the per-target run lock so this and a
        # background scheduled run never hit the same host at once. Non-blocking:
        # if busy, say so and bail cleanly rather than colliding. Keyed by the
        # effective target, so a self-host run doesn't block a target run.
        _eff_target = target_override or _kconfig.get_active_target()
        _w = get_current_worker()
        _lock = _target_lock.try_acquire_target(self._data_dir, _eff_target)
        if _lock is None:
            # Busy: wait out a quick collision (a scheduled audit is usually
            # short) rather than making the user retry; esc stops the wait.
            self._emit_from_worker(R.note_line(
                f"A run is active on {_eff_target} (likely a scheduled audit) — waiting for it "
                "to finish… (usually quick; press esc to stop)"))
            _lock = _target_lock.acquire_target_blocking(
                self._data_dir, _eff_target, timeout=20.0, should_stop=lambda: _w.is_cancelled)
        if _lock is None:
            self._emit_from_worker(R.note_line(
                f"{_eff_target} is still busy (it may be a long run) — try again in a bit."))
            if target_override:
                _kconfig.set_active_target(prior_active)
            return
        self._emit_from_worker(R.note_line(f"Starting investigation (up to {REPL_MAX_ITERS} steps)…"))
        turn_id = self._store.start_turn(self.session_state["session_id"], goal)
        started = time.monotonic()
        worker = get_current_worker()

        def _on_step(step: dict) -> None:
            if worker.is_cancelled:
                raise _CancelInvestigation()
            self._render_step(step)
            # Live context meter: each step follows an LLM call, so the
            # last-call prompt_tokens has advanced -- refresh the footer.
            self.app.call_from_thread(self._refresh_footer)

        try:
            # Hand the ongoing conversation to the investigation so it can
            # resolve references to earlier turns (goes in run_agent's
            # never-compacted preamble — safe from the same context-loss
            # risk the compaction guard protects against, since it's the
            # user's own conversation, not untrusted target data).
            result = run_agent(
                goal, self._data_dir, max_iters=REPL_MAX_ITERS, on_step=_on_step,
                prior_context=self.session_state.get("resume_context") or None,
                # named time windows ("the incident window") persist per session
                session_id=self.session_state.get("session_id"),
            )
        except _CancelInvestigation:
            self._store.complete_turn(turn_id, "cancelled", transcript_ref=None)
            self._emit_from_worker(R.note_line("Interrupted — nothing was left running on the target. Press Ctrl+R to re-run this goal, or type a new one."))
            self._remember_turn(goal, "(investigation interrupted before it concluded)")
            return
        except Exception as e:  # noqa: BLE001
            self._store.complete_turn(turn_id, "error", transcript_ref=None)
            self._emit_from_worker(R.error_line(f"Investigation errored: {e}"))
            return
        finally:
            # Always restore the configured target after a self-host run,
            # including on the cancel/error early-returns above, and release the
            # per-target lock (the target is no longer being contacted once
            # run_agent has returned; the rest is local rendering/DB).
            if target_override:
                _kconfig.set_active_target(prior_active)
            _target_lock.release_target(_lock)

        duration = time.monotonic() - started
        # The conclusion panel carries its own in-bubble timestamp (subtitle),
        # so no separate stamped "Kratos:" header here -- one time per bubble.
        t, d = self._stamp_now()
        self._last_answer = result.get("final_answer", "") or ""
        if result["status"] == "final_answer":
            self._emit_bubble_from_worker(R.result_panel("Kratos — investigation complete", result["final_answer"], T.SAFE, time_str=t), d)
            status = "final_answer"
        elif result["status"] == "max_iters_reached" and result.get("final_answer"):
            self._emit_bubble_from_worker(R.result_panel("Kratos — investigation incomplete (step limit)", result["final_answer"], T.ATTENTION, time_str=t), d)
            status = "max_iters_reached"
        elif result["status"] == "llm_unavailable":
            # Kratos's own model failed mid-investigation -> banner,
            # not an inline tool-style error.
            self._emit_from_worker(R.llm_failure_banner("the language model became unavailable during the investigation"))
            status = "llm_unavailable"
        else:
            self._emit_from_worker(R.error_line(f"Investigation stopped: {result['status']}"))
            status = str(result["status"])

        # Structured recommend-only remediation: render each command the
        # agent produced as its own panel, and remember them for ctrl+y copy.
        commands = result.get("recommended_commands") or []
        self._last_commands = [str(c.get("command") or "") for c in commands if c.get("command")]
        if target_override:
            target_label = f"this Kratos host ({target_override})"
        else:
            target_label = self.session_state["targets"][0] if self.session_state["targets"] else "the target"
        for c in commands:
            self._emit_from_worker(R.recommended_command_panel(c, target_label))
        if self._last_commands:
            self._emit_from_worker(R.note_line("Ctrl+Y copies the recommended command(s) — Kratos does not run them."))
        self._last_target_commands = [] if target_override else [
            c for c in commands if str(c.get("run_on") or "target") == "target"]
        self._runnable_fixes = [] if target_override else self._match_runnable_fixes(commands)
        if self._runnable_fixes:
            names = ", ".join(f["label"] for f in self._runnable_fixes)
            self._emit_from_worker(R.note_line(
                f"This target's sub-agent can run {'this' if len(self._runnable_fixes) == 1 else 'these'} "
                f"({names}) — type /run-fix to review and approve it. Nothing runs without you typing EXECUTE."))

        self._emit_from_worker(Text(f"Done in {duration:.0f}s", style=T.TEXT_FAINTER))

        transcript_path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        transcript_path.write_text(json.dumps(result.get("transcript", []), indent=2, default=str), encoding="utf-8")
        self._store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))
        self._remember_turn(goal, result.get("final_answer") or f"(investigation ended: {status})")
        self._ctx_chars += len(goal) + len(result.get("final_answer", "") or "")
        self.app.call_from_thread(self._refresh_footer)

    def _match_runnable_fixes(self, commands: list[dict[str, Any]], target_id: str | None = None) -> list[dict[str, Any]]:
        """Recommended target commands that are exactly one run of an ENABLED
        allowlist entry on this session's target's paired sub-agent. Only
        offers -- running still goes through /whitelist's typed-EXECUTE gate.
        `target_id` names the sub-agent explicitly (the user picked it);
        otherwise it is found by the session target's name/hostname, and only
        a UNIQUE match counts -- never a guess about which machine."""
        targets = self.session_state.get("targets") or []
        if not commands or (not targets and target_id is None):
            return []
        try:
            from kratos.storage.subagent_store import SubAgentStore
            from kratos.storage.whitelist_store import WhitelistStore
            from kratos.subagent.entry_builder import match_recommendation
            from kratos.tui_mk2.screens.whitelist import build_rows

            if target_id is None:
                wanted = str(targets[0]).strip().lower()
                paired = [t for t in SubAgentStore(self._data_dir / "kratos.db").list_targets()
                          if not t.get("revoked_at")
                          and wanted in {str(t.get("name") or "").lower(), str(t.get("hostname") or "").lower()}]
                if len(paired) != 1:
                    return []  # none, or ambiguous -- /run-fix asks instead of guessing
                target_id = paired[0]["target_id"]
            tid = target_id
            rows = [r for r in build_rows(WhitelistStore(self._data_dir / "kratos.db"), tid) if r["state"] == "on"]
        except Exception:  # noqa: BLE001 -- an offer is optional; never break the turn over it
            return []
        out = []
        for c in commands:
            if str(c.get("run_on") or "target") != "target":
                continue
            hit = match_recommendation(str(c.get("command") or ""), rows)
            if hit:
                row, values = hit
                out.append({"target_id": tid, "action_id": row["spec"].id, "values": values,
                            "label": row["label"], "command": str(c.get("command"))})
        return out

    @work
    async def _run_fix_flow(self) -> None:
        fixes = list(self._runnable_fixes)
        if not fixes and self._last_target_commands:
            # The session target couldn't be tied to one paired sub-agent
            # automatically -- ask which machine it is rather than guess.
            from kratos.storage.subagent_store import SubAgentStore

            paired = [t for t in SubAgentStore(self._data_dir / "kratos.db").list_targets() if not t.get("revoked_at")]
            if paired:
                label = (self.session_state.get("targets") or ["the target"])[0]
                tid = await self.app.push_screen_wait(ListPickerModal(
                    f"Which paired machine is {label}?",
                    [(t["target_id"], f"{t.get('name') or '?'}  ({t.get('hostname') or '?'}, {t['target_id']})") for t in paired]))
                if tid is None:
                    return
                fixes = self._match_runnable_fixes(self._last_target_commands, target_id=tid)
        if not fixes:
            self._emit(R.note_line(
                "No recommended command from the last investigation matches an enabled allowlist entry on this "
                "target's sub-agent. Add one in /whitelist (a → exact command or a command with blanks)."))
            return
        fix = fixes[0]
        if len(fixes) > 1:
            idx = await self.app.push_screen_wait(ListPickerModal(
                "Which recommended command?", [(i, f["command"]) for i, f in enumerate(fixes)]))
            if idx is None:
                return
            fix = fixes[idx]
        from kratos.tui_mk2.screens.whitelist import WhitelistScreen

        self.app.push_screen(WhitelistScreen(self._data_dir, target_id=fix["target_id"],
                                             preselect={"action_id": fix["action_id"], "values": fix["values"]}))

    def _render_step(self, step: dict) -> None:
        tool_name = step.get("tool")
        if tool_name:
            result, effective_status = R.unwrap_tool_result(step.get("observation"))
            if effective_status == "error":
                err = R.error_detail(result)
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
            chip = R.window_chip(result.get("window")) if isinstance(result, dict) else None
            if chip is not None:
                self._emit_from_worker(chip)
        elif step.get("tool_proposal"):
            proposal = step["tool_proposal"]
            self.session_state["pending_evolve_suggestion"] = proposal
            body = (
                f"{proposal.get('name', '')}\n{proposal.get('description', '')}\n\n"
                'Run /evolve to have Kratos build this (needs a test harness).'
            )
            self._emit_from_worker(R.result_panel("Evo-loop suggestion", body, T.ATTENTION))
        elif step.get("status") == "context_compacted":
            # agent/loop.py folded the oldest turns to stay within
            # the model's context window. Informational only -- the record is
            # untouched -- so it renders as a faint line, and the footer context
            # meter will drop on the next step as the prompt shrinks.
            self._emit_from_worker(
                R.compaction_line(step.get("context_tokens", 0), step.get("context_window", 0))
            )
        elif step.get("status") == "clarify":
            # A resolved mid-investigation clarify (docs/clarify_expansion.md).
            # The modal itself already gathered the answer (via the provider in
            # tui_mk2/approvals.py, which also drops the "paused" lead-in line);
            # this is the DURABLE record in the scrollback -- without it, once
            # the modal closes there'd be no trace the question was ever asked,
            # unlike an approval (whose next tool-call line implicitly shows the
            # outcome). Only a genuinely completed clarify renders here --
            # clarify_malformed/clarify_budget_exhausted are internal
            # self-corrections, same as parse_error, and stay out of the
            # scrollback like every other silent-retry status.
            question = step.get("clarify_question", "")
            answer = step.get("clarify_answer")
            body = (f"Q: {question}\nA: {answer}" if answer
                   else f"Q: {question}\n(no answer given — Kratos proceeded with its best judgment)")
            self._emit_from_worker(R.result_panel("Clarifying question", body, T.ACCENT))

    @work(thread=True)
    def _compact_flow(self) -> None:
        """Manual /compact — summarize the working conversation context into a
        compact summary, freeing token budget while KEEPING the memory (unlike
        /clear, which discards it). The manual companion to the
        automatic compaction inside run_agent: this one operates on the
        session's chat/resume context (`resume_context`), which run_agent's loop
        never sees, so it's fully independent of the investigation compactor
        (touches no investigation transcript or guard state)."""
        self._set_busy(True)
        try:
            self._do_compact(manual=True)
        finally:
            self._set_busy(False)

    def _do_compact(self, manual: bool) -> bool:
        """Summarize resume_context, keeping memory. Shared by /compact (manual)
        and the automatic near-limit trigger (_maybe_auto_compact). Runs the LLM
        call inline — every caller is already on a thread worker. Returns True if
        it compacted.

        GUARANTEES the result fits within a target fraction of the model window
        (~60%), so auto-compaction actually pulls the meter back under the limit
        even when the recent turns are large (e.g. a [f] full-resume blob or long
        investigation answers) — it keeps the summary plus only as many newest
        turns as fit, and hard-caps as a last resort. Operates only on chat
        context; never touches run_agent's own transcript or guard state."""
        from kratos.llm_interface import agent_chat, get_context_window_tokens, reset_session_token_usage

        ctx = self.session_state.get("resume_context", "").strip()
        if not ctx:
            if manual:
                self._emit_from_worker(R.note_line("Nothing to compact yet — the working context is empty."))
            return False
        window = get_context_window_tokens() or 1
        target_chars = max(2000, int(window * 0.6) * 4)  # result should fit ~60% of the window (~4 chars/tok)
        # Keep the most recent turns VERBATIM and summarize only the older ones
        # (matches the investigation compactor's own approach). Turns are separated
        # by blank lines (_remember_turn joins with "\n\n").
        chunks = [c for c in ctx.split("\n\n") if c.strip()]
        if len(chunks) > 1:
            keep = min(CHAT_COMPACTION_KEEP_RECENT, len(chunks) - 1)  # always summarize >=1
            older, recent = chunks[:-keep], chunks[-keep:]
        else:
            older, recent = chunks, []  # a single blob: summarize it whole
        if manual:
            self._emit_from_worker(R.note_line("Compacting the conversation (summarizing older turns, a moment)…"))
        else:
            # Auto-compaction near the window limit — the receding ↓ notice, same
            # visual language as the investigation loop's own compaction event.
            self._emit_from_worker(R.compaction_line())
        # Bound what we send the summarizer so an enormous context can't itself
        # overflow a small window — keep the newest tail of the older section.
        older_text = "\n\n".join(older)
        max_input = target_chars * 6
        if len(older_text) > max_input:
            older_text = "[…older conversation truncated…]\n" + older_text[-max_input:]
        summary = agent_chat(
            "You are a precise conversation summarizer.",
            "Summarize the following earlier conversation so it can be resumed later with the key "
            "facts, decisions, findings, targets, and open threads preserved. Be concise but do NOT "
            "drop concrete details. Write it as notes.\n\n" + older_text,
            max_tokens=800,
        )
        if not summary or not summary.strip():
            if manual:
                self._emit_from_worker(R.error_line("Compaction failed — the model returned no summary. Context unchanged."))
            return False
        # Assemble the result under target_chars: the summary, plus as many of the
        # newest recent turns as fit. This is what actually GUARANTEES the meter
        # drops below the limit, regardless of how big the recent turns are.
        summary_block = f"[Earlier conversation summary:]\n{summary.strip()}"
        kept_recent: list[str] = []
        used = len(summary_block)
        for chunk in reversed(recent):
            if used + len(chunk) + 2 > target_chars:
                break
            kept_recent.insert(0, chunk)
            used += len(chunk) + 2
        new_ctx = "\n\n".join([summary_block, *kept_recent])
        if len(new_ctx) > target_chars:  # even the summary alone is over -> hard cap
            new_ctx = new_ctx[:target_chars]
        self.session_state["resume_context"] = new_ctx
        reset_session_token_usage()  # meter now reflects the smaller context
        self.app.call_from_thread(self._refresh_footer)
        if manual:
            kept = f" (kept the last {len(kept_recent)} turn(s) verbatim)" if kept_recent else ""
            self._emit_from_worker(R.success_line(
                f"Context compacted — earlier conversation summarized{kept}; Kratos still remembers the key points."))
        return True

    def _maybe_auto_compact(self) -> None:
        """Automatically compact the conversation context once it crosses the
        same 85% fill the investigation loop and the footer's "will compact
        soon" warning use — so a long chat stays within the model window without
        the user having to run /compact. Called after each turn appends to the
        working context; a no-op below the threshold. Runs on the calling thread
        worker (both call sites are workers).

        Only fires on a REAL measured token fill, never the rough char estimate
        (`estimated` is True before any real LLM call — e.g. right after a model/
        window change) so it can't over-eagerly compact off a stale estimate."""
        pct, _used, _window, estimated = self._context_pct()
        if not estimated and pct >= 85:
            self._do_compact(manual=False)

    def _remember_turn(self, user_text: str, kratos_text: str) -> None:
        """Append a SUBSTANTIVE record of this turn to the model-facing working
        context, so multi-turn conversation actually remembers what was said.
        The previous _append_outcome stored only "Goal -> status" — the user's
        message with no reply — which is why follow-ups (and light resumes) had
        no memory of the conversation's content: the model literally never saw
        its own prior answers. Both sides are kept now; auto-compaction /
        /compact keep it bounded."""
        block = f"You: {user_text}\nKratos: {kratos_text}".strip()
        ctx = self.session_state.get("resume_context", "")
        self.session_state["resume_context"] = (ctx + "\n\n" + block).strip() if ctx else block

    def _log_chat_turn(self, goal: str, reply: str) -> None:
        turn_id = self._store.start_turn(self.session_state["session_id"], goal)
        path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        path.write_text(json.dumps([{"final_answer": reply}], indent=2), encoding="utf-8")
        self._store.complete_turn(turn_id, "chat_reply", transcript_ref=str(path))
        self._remember_turn(goal, reply)

    def _transcripts_dir(self) -> Path:
        d = self._data_dir / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d

    # --- bindings --------------------------------------------------------
    def action_interrupt(self) -> None:
        if self._busy:
            self.workers.cancel_group(self, "turn")
            self._emit(R.note_line("Interrupting at the next step boundary…"))

    def action_help(self) -> None:
        self.app.push_screen(HelpModal())

    def _palette_commands(self) -> list[tuple[str, str]]:
        """The static command list PLUS a live `/<name>` entry per saved runnable
        preset, so the palette reflects presets added/deleted this
        session with no caching."""
        from kratos.agent import presets as _P

        commands = list(_PALETTE_COMMANDS)
        try:
            presets, _errors = _P.list_presets(self._data_dir)
        except Exception:  # noqa: BLE001 -- palette must never fail to open
            presets = []
        for p in presets:
            if not p.is_runnable:
                continue
            kind = "pipeline" if p.is_pipeline else "goal"
            summary = (p.goal or (f"{len(p.steps)}-step pipeline" if p.is_pipeline else ""))[:48]
            commands.append((f"/{p.name}", f"run saved {kind} preset — {summary}"))
        return commands

    @work
    async def action_palette(self) -> None:
        chosen = await self.app.push_screen_wait(CommandPaletteModal(self._palette_commands()))
        if chosen:
            t, d = self._stamp_now()
            self._emit_stamped(self._you_header(chosen), t, d)
            self._dispatch_slash(chosen)

    @work
    async def action_back_to_sessions(self) -> None:
        """Ctrl+B (or /sessions, /back) — leave this conversation and return to
        the session picker (the start page). Confirm-gated so it can't be a
        single-keystroke exit from an active session. The session is KEPT and
        stays resumable from the list — nothing is archived or deleted (that's
        /delete). A running turn must be stopped first (esc / Ctrl+C), matching
        how typed slash commands are gated, and so the thread worker isn't left
        touching a popped screen."""
        if self._busy:
            self.notify("A turn is running — press esc or Ctrl+C to stop it first.", timeout=3)
            return
        ok = await self.app.push_screen_wait(
            ConfirmModal(
                "Back to session list",
                "Leave this conversation and return to the session picker.\n\n"
                "This session is kept and stays resumable from the list — nothing is deleted.",
            )
        )
        if not ok:
            self._emit(R.note_line("Staying in this session."))
            return
        self.app.pop_screen()  # back to the launch chooser (it refreshes on resume)

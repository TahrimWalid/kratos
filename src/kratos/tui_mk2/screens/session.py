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

import asyncio
import json
import re
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

REPL_MAX_ITERS = 7  # matches cli/repl.py::REPL_MAX_ITERS -- a REPL turn is bounded/cheap
# Raised 5 -> 7 (2026-09-08): a vuln sweep legitimately needs nmap + vuln + config
# + correlate_findings + conclude = 5 steps with ZERO slack, so any single
# rejected-early-conclusion (guard 1) pushed correlate_findings out of budget and
# the run concluded without the correlation engine ever running. 7 leaves room.
FULL_RESUME_DETAILED_TURN_CAP = 5  # matches cli/repl.py -- only the most recent N turns replay in full
CHAT_COMPACTION_KEEP_RECENT = 3    # turns kept verbatim on /compact (matches loop.py's investigation compactor)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")  # strip terminal control codes from captured output
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"  # braille spinner frames for the "working…" activity line

_PALETTE_COMMANDS = [
    ("/report", "investigation summary — findings by severity"),
    ("/doctor", "self-diagnostic — LLM, target setup, and tools health"),
    ("/usage", "token usage + estimated cost this session (local = free)"),
    ("/context", "what's currently loaded in the context window"),
    ("/investigate-host", "investigate THIS Kratos host itself (not the target)"),
    ("/evolve", "write a new tool for the current gap"),
    ("/tools", "list the tools Kratos can use, by kind"),
    ("/use", "run ONE specific tool directly (deterministic, no model)"),
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
    ("/preview", "Phase 2 design shells (not wired) — sub-agent / Tailscale / execution UI"),
    ("/exit", "leave the session"),
]


class _CancelInvestigation(Exception):
    """Raised inside on_step when the user pressed esc -- lets run_agent unwind
    at a step boundary (a blocking LLM/tool call can't be interrupted mid-call,
    so 'interrupted — N of ~M steps' is honest about where it stopped)."""


class SessionScreen(Screen):
    BINDINGS = [
        Binding("escape", "interrupt", "interrupt", show=True),
        # ctrl+c also stops the current response (parity with Claude Code).
        # priority so it overrides Textual's default ctrl+c quit; a no-op when
        # idle (nothing running) rather than quitting — leave the session with
        # /exit or q at the chooser.
        Binding("ctrl+c", "interrupt", "stop", show=False, priority=True),
        Binding("ctrl+p", "palette", "commands", show=True),
        Binding("ctrl+y", "copy_last", "copy answer", show=True),
        # Design 10a "edit a previous turn": ↑/↓ recall prior turns into the
        # prompt for editing; resending a recalled turn discards it and
        # everything after (see on_input_submitted). Adapted from the mockup's
        # double-esc to arrow-key history recall -- more idiomatic and doesn't
        # collide with esc=interrupt, same spirit as the cursor-vs-number-keys
        # chooser adaptation.
        Binding("up", "history_prev", "prev turn", show=False),
        Binding("down", "history_next", "next turn", show=False),
        # Design 7b -- re-run the last goal (e.g. after interrupting one). A
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
        self._last_answer = ""             # most recent Kratos answer/reply, for ctrl+y copy (14d)
        self._last_commands: list[str] = []  # recommended commands from the last turn (19b), for ctrl+y
        # ↑/↓ non-destructive message-history recall state (shell-style):
        self._hist_turns: list[dict[str, Any]] | None = None  # loaded lazily on first ↑
        self._hist_index = 0               # position within _hist_turns; == len means "composing new"
        self._pre_recall_draft = ""        # the in-progress input saved when recall started
        self._last_goal = ""               # most recent goal, for ctrl+r re-run (7b)
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
            yield RichLog(id="transcript", wrap=True, markup=False, highlight=False)
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
        self.set_interval(1.0, self._refresh_header)  # live clock (turn 9a)
        self.set_interval(0.12, self._tick_activity)  # "working…" spinner while busy
        self._render_idle()
        if self._full_replay:
            self._render_full_replay()
        self.query_one("#goal", Input).focus()
        self._maybe_timezone_fallback()  # turn 9b (only fires if auto-detect failed)

    # --- turn 9b: one-time manual timezone entry when auto-detect fails ---
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
        # Turn 14d: copy Kratos's most recent answer/reply to the clipboard
        # (via the terminal's OSC-52, Textual's copy_to_clipboard) with a
        # transient confirmation -- the concrete "copy" affordance the design
        # asks for. A structured per-command 19b copy panel needs the
        # remediation-command structure that doesn't exist yet (see the doc).
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

    def _context_pct(self) -> tuple[int, int, int, bool]:
        # REAL token accounting (feature 7c): the last LLM call's prompt_tokens
        # vs the active model's context window. Returns (pct, used, window,
        # estimated). The window is MODEL-AWARE (get_context_window_tokens
        # tracks the live /model profile), so a /model switch rescales this live.
        #
        # Before the first real LLM call of the process (a fresh OR just-resumed
        # session), there is no measured usage. Rather than show 0 and then jump
        # to the real value on the first message (the confusing "[f] resume rolls
        # to 0, then a short 'ok' shows 47%" report), approximate the loaded
        # working-context size (~4 chars/token) so the meter reflects a resume's
        # context immediately. Marked `estimated` so the footer can show a ~.
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
        footer = Text()
        footer.append(f"session {st['session_id']}", style=T.TEXT_FAINTER)
        footer.append("  ·  ", style=T.TEXT_GHOST)
        footer.append(str(st["backend"]), style=T.TEXT_FAINTER)
        footer.append("  ·  ", style=T.TEXT_GHOST)
        footer.append(f"target {st['targets'][0] if st['targets'] else '(none)'}", style=T.TEXT_FAINTER)
        footer.append("   ", style=T.TEXT_GHOST)
        footer.append("ctx ", style=T.TEXT_FAINTER)
        footer.append("█" * filled + "░" * (bar_w - filled), style=color)
        approx = "~" if estimated else ""  # ~ = estimated from loaded context, not yet measured
        footer.append(f" {approx}{pct}% ({self._fmt_tok(used)}/{self._fmt_tok(window)})", style=color)
        if pct >= 85:
            footer.append(" · will compact soon", style=T.CRITICAL)
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
        self._emit(Text("Tips:  ? help · Ctrl+P commands · ↑/↓ edit a previous turn · Ctrl+B session list · /compact free context · esc or Ctrl+C stops a response", style=T.TEXT_GHOST))
        self._emit(Text("Or just ask: “switch to <model>”, “change the target to <host>”, “show the report” — Kratos confirms before changing its model or target.", style=T.TEXT_GHOST))
        self._emit(Text("Investigations target the monitored host by default; ask about “your own host” (or /investigate-host) to check the Kratos machine itself.", style=T.TEXT_GHOST))
        self._emit(Text(""))

    # --- full-tier resume: on-screen replay (turn 6b, [f]) ---------------
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
        if not tool_name:
            return
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

    # --- input -----------------------------------------------------------
    def on_input_changed(self, event: Input.Changed) -> None:
        # Turn 7a: a lone "/" typed into the empty prompt opens the command
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
        # ↑/↓ recall is now non-destructive: sending is always a fresh turn, never
        # discards history (the old "edit a previous turn truncates from here"
        # design 10a caused a confusing "discarded N turns" line whenever ↑ had
        # been pressed; ctrl+c-stop-then-retype covers editing instead).
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
        elif cmd in ("/sessions", "/back"):
            self.action_back_to_sessions()
        elif cmd == "/help":
            self.app.push_screen(HelpModal())
        elif cmd == "/report":
            self._render_report()
        elif cmd in ("/doctor", "/health"):
            self._doctor_flow()
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
            self._evolve_flow(rest)
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
        elif cmd in ("/investigate-host", "/investigate-self", "/host"):
            self._investigate_host_flow(rest)
        elif cmd == "/run":
            # PreA2: the deterministic standard audit (agent/pipeline.py), NOT
            # the retired legacy cmd_run. Target-correct, mk2-rendered, no LLM.
            self._run_standard_audit()
        elif cmd in ("/scan", "/logs-parse", "/findings-generate"):
            self._run_shortcut(cmd.lstrip("/"), rest)
        else:
            # Unmatched /-prefix falls through to a goal (matches classic REPL).
            self._run_goal(text)

    # --- /usage (token + cost transparency, feature A3) -----------------
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

    # --- /context (what's in the window, feature A4) --------------------
    def _render_context(self) -> None:
        from kratos.llm_config import get_active_llm_model

        pct, used, window, estimated = self._context_pct()
        resume = self.session_state.get("resume_context", "") or ""
        turns = len(self._store.get_goal_history(self.session_state["session_id"]))
        meter = "estimated from loaded context" if estimated else "measured (last LLM call)"
        rows = [
            ("model", get_active_llm_model()),
            ("context window", f"{window:,} tokens"),
            ("in use", f"{used:,} tokens  ({pct}%)  — {meter}", T.ATTENTION if pct >= 75 else T.TEXT),
            ("working memory", f"{len(resume):,} chars  (~{len(resume)//4:,} tokens of conversation kept)"),
            ("turns in this session", str(turns)),
        ]
        self._emit(R.kv_table("Context window — what's loaded", rows))
        if pct >= 75:
            self._emit(R.note_line("Getting full — /compact summarizes older turns (keeping the recent ones) to free space."))
        else:
            self._emit(R.note_line("/compact frees space by summarizing older turns; recent turns are kept verbatim."))

    # --- /doctor (self-diagnostic, feature A1) --------------------------
    @work(thread=True, exclusive=True, group="turn")
    def _doctor_flow(self) -> None:
        """Run Kratos's self-diagnostic (LLM endpoint, .env, backend, target
        setup, kept tools) off the event loop -- the endpoint probe and the
        target SSH check are blocking network work."""
        from kratos.agent import doctor

        self._set_busy(True)
        self._emit_from_worker(R.note_line("Running diagnostics — checking LLM, target, and tools…"))
        try:
            checks = doctor.run_diagnostics()
        except Exception as e:  # noqa: BLE001 -- should not happen (each check is guarded), but never crash the screen
            self._emit_from_worker(R.error_line(f"Diagnostic run failed: {e}"))
            self._set_busy(False)
            return
        self._emit_bubble_from_worker(R.doctor_table(checks), self._stamp_now()[1])
        p, w, f = doctor.summarize(checks)
        if f:
            self._emit_from_worker(R.error_line(f"{f} problem(s) found — see the failing rows above."))
        elif w:
            self._emit_from_worker(R.note_line(f"{p} ok, {w} warning(s) — review the amber rows."))
        else:
            self._emit_from_worker(R.success_line(f"All good — {p} checks passed."))
        self._set_busy(False)

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

    def _clear_screen(self, archive: bool) -> None:
        """Shared by /clear and /reset. Wipes the visible transcript (like a
        shell `clear`), resets the working context + token meter so the next
        turn starts fresh, and re-renders the idle banner so the screen isn't
        left blank. When `archive`, the stored goal history is also archived
        (soft-deleted, recoverable) so a later resume won't bring it back."""
        from kratos import llm_interface

        if archive:
            self._store.archive_goal_history(self.session_state["session_id"])
        llm_interface.reset_session_token_usage()   # drops the 7c context meter to 0
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
        """Turn 16c -- honest cost/privacy disclosure per backend option. Now a
        thin delegate to render.profile_blurb so the Settings screen can render
        the same line with no live session (single source of truth)."""
        return R.profile_blurb(values)

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
            if pending:
                idea = f"{pending.get('name', '')}: {pending.get('description', '')}".strip(": ")
                pending_name = pending.get("name") or None
            else:
                # Bare /evolve with no pending suggestion: ASK for the idea in a
                # box (this used to just print a note and return, so /evolve
                # looked unwired unless you passed the idea inline as
                # /evolve "<idea>"). Now typing /evolve opens the flow.
                answer = await self.app.push_screen_wait(
                    PromptModal(
                        "New tool — what should it do?",
                        'One sentence, e.g. "list which users have sudo on the target"',
                    )
                )
                if answer is None:
                    return
                idea = answer.strip().strip('"').strip("'").strip()
                if not idea:
                    self._emit(R.note_line("No idea given — nothing to build."))
                    return

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
        if harness_path.suffix != ".py":
            self._emit(R.error_line(f"{harness_path} isn't a .py file — evo-loop needs a pytest harness."))
            return
        if not harness_path.exists():
            await self._draft_harness_flow(idea, tool_name, harness_path)
            return
        self._run_evolve(idea, harness_path, tool_name)

    async def _draft_harness_flow(self, idea: str, tool_name: str, harness_path: Path) -> None:
        """Turn: /evolve against a missing harness. Offers an LLM-drafted
        starter (reusing cli/repl.py's own _draft_evolve_harness), shown for
        REVIEW and never trusted unedited -- saving is an explicit choice, and
        even 'save & build now' only proceeds after the full draft was shown.
        Same human-authored-test principle as the classic REPL, just a lower
        cold-start cost."""
        want = await self.app.push_screen_wait(
            ConfirmModal(
                "Draft a starter harness with the LLM?",
                f"No test file at {harness_path}. Evo-loop needs a human-authored pytest harness that "
                "defines 'correct' for this tool. I can draft one for you to review and edit — it is "
                "never trusted unedited. Draft one now?",
            )
        )
        code, drafted = None, False
        if want:
            self._emit(R.note_line("Drafting a starter harness (LLM, a moment)…"))
            code = await asyncio.to_thread(self._draft_harness_blocking, tool_name, idea)
            drafted = bool(code)
        if not code:
            code = self._static_harness(tool_name, idea)
        self._emit(self._harness_panel(code, drafted))

        choice = await self.app.push_screen_wait(
            ListPickerModal(
                "Harness draft — what next?",
                [
                    ("s", "[s] save and start building now"),
                    ("e", "[e] save so I can edit it first"),
                    ("d", "[d] discard"),
                ],
                subtitle="Review the assertions — they're the model's best guess at the interface.",
            )
        )
        if choice == "s":
            harness_path.parent.mkdir(parents=True, exist_ok=True)
            harness_path.write_text(code, encoding="utf-8")
            self._emit(R.success_line(f"Saved to {harness_path} — starting evo-loop now."))
            self._run_evolve(idea, harness_path, tool_name)
        elif choice == "e":
            harness_path.parent.mkdir(parents=True, exist_ok=True)
            harness_path.write_text(code, encoding="utf-8")
            self._emit(R.success_line(f"Saved to {harness_path}."))
            self._emit(R.note_line("Review it (especially the assertions), then run /evolve again to build."))
        else:
            self._emit(R.note_line(f"Discarded — write your own harness at {harness_path}, then /evolve again."))

    def _draft_harness_blocking(self, tool_name: str, idea: str) -> str | None:
        from kratos.agent import console as _c
        from kratos.cli.repl import _draft_evolve_harness

        return _draft_evolve_harness(_c.get_console(), tool_name, idea)

    def _static_harness(self, tool_name: str, idea: str) -> str:
        from kratos.cli.repl import _build_evolve_harness_template

        return _build_evolve_harness_template(tool_name, idea)

    def _harness_panel(self, code: str, drafted: bool) -> Any:
        from rich.panel import Panel
        from rich.syntax import Syntax

        title = (
            "LLM-DRAFTED harness — READ before saving (assertions are guesses)"
            if drafted
            else "Starter harness — edit the TODOs before running /evolve"
        )
        return Panel(
            Syntax(code, "python", word_wrap=True, background_color="default"),
            title=title,
            title_align="left",
            border_style=T.ATTENTION,
        )

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
        n = len(outcome.attempt_history)
        if outcome.status == "approved":
            kd = outcome.keep_decision
            self._emit_from_worker(R.success_line(f"Kept: {kd.tool_name} (requires_approval={kd.requires_approval}) — available now."))
        elif outcome.status == "denied":
            self._emit_from_worker(R.note_line("Evo-loop finished — a candidate passed testing but was not kept (denied)."))
        elif outcome.status == "write_failed":
            # 15d "never got there": no testable candidate was ever produced.
            self._emit_from_worker(R.error_line(
                f"Evo-loop never produced a testable candidate — the write step failed before any "
                f"sandbox test could run ({n} attempt(s)). Try a clearer idea or a simpler harness."
            ))
        elif outcome.status == "stalled_no_variation":
            self._emit_from_worker(R.error_line(
                f"Evo-loop stalled — the model stopped varying its output (converged, then repeated "
                f"the same candidate) after {n} attempt(s). No new candidate to try."
            ))
        elif outcome.status == "exhausted_retries":
            self._emit_from_worker(R.error_line(
                f"Evo-loop ran out of attempts ({n}) while still trying different fixes — none passed "
                f"the harness. Consider loosening/clarifying the harness assertions."
            ))
        elif outcome.status == "infra_error":
            self._emit_from_worker(R.error_line(
                "Evo-loop hit a sandbox infrastructure error (not a problem with the candidate code) "
                "— check the Incus sandbox is available."
            ))
        else:
            self._emit_from_worker(R.error_line(f"Evo-loop did not produce an approvable candidate (status: {outcome.status})."))
        self._set_busy(False)

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

    # --- /run: the PreA2 deterministic standard audit --------------------
    @work(thread=True, exclusive=True, group="turn")
    def _run_standard_audit(self) -> None:
        """Run the built-in deterministic standard audit (agent/pipeline.py) and
        render it mk2-first: per-step tool-call lines and finding panels while it
        runs, then a run-summary panel. No LLM in the decision path -- the step
        sequence is fixed and target-correct (target-facing tools only; nothing
        about Kratos's own host is folded into the target's findings)."""
        from kratos.agent.pipeline import run_pipeline, standard_audit_steps

        self._set_busy(True)
        target = self.session_state["targets"][0] if self.session_state["targets"] else "the target"
        self._emit_from_worker(R.note_line(
            f"Standard audit — a fixed, deterministic security sweep of {target} "
            "(no LLM; same steps every run)."))
        turn_id = self._store.start_turn(self.session_state["session_id"], "/run — standard audit")
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
            outcome = run_pipeline(standard_audit_steps(), self._data_dir, on_step=_on_step)
        except _CancelInvestigation:
            self._store.complete_turn(turn_id, "cancelled", transcript_ref=None)
            self._emit_from_worker(R.note_line("Interrupted — nothing was left running on the target."))
            self._remember_turn("/run — standard audit", "(audit interrupted before it concluded)")
            return
        except Exception as e:  # noqa: BLE001
            self._store.complete_turn(turn_id, "error", transcript_ref=None)
            self._emit_from_worker(R.error_line(f"Standard audit errored: {e}"))
            return
        finally:
            self._set_busy(False)

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

        # Persist a lightweight step transcript for the turn record (not a
        # run_agent transcript -- a deterministic pipeline has no LLM reasoning).
        transcript = [
            {"tool": s.tool, "label": s.label, "status": s.status, "detail": s.detail}
            for s in outcome.steps
        ]
        transcript_path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        transcript_path.write_text(json.dumps(transcript, indent=2, default=str), encoding="utf-8")
        status = "final_answer" if outcome.status == "completed" else "error"
        self._store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))
        n = sum(outcome.severity_tally.values())
        self._remember_turn(
            "/run — standard audit",
            f"(deterministic audit {outcome.status}; {outcome.ran}/{len(outcome.steps)} steps, {n} finding(s))",
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
        """Design 7b -- re-run the last goal (honest re-run, not a mid-loop
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

        if route.kind == "chat":
            reply = route.reply or ""
            t, d = self._stamp_now()
            self._emit_stamped_from_worker(self._kratos_header(), t, d)
            self._emit_from_worker(Text(reply or "(no reply)", style=T.TEXT))
            self._last_answer = reply
            self._last_commands = []  # a chat reply carries no remediation commands
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
        set_active_llm_profile(target.values)
        _p.switch_profile(ENV_FILE_PATH, target, current)
        self.session_state["backend"] = target.model
        self.app.call_from_thread(self._refresh_footer)
        self._emit_from_worker(R.success_line(f"Switched to {target.model} — active now, saved to .env."))

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
        self._emit_from_worker(R.note_line(f"Starting investigation (up to {REPL_MAX_ITERS} steps)…"))
        turn_id = self._store.start_turn(self.session_state["session_id"], goal)
        started = time.monotonic()
        worker = get_current_worker()

        def _on_step(step: dict) -> None:
            if worker.is_cancelled:
                raise _CancelInvestigation()
            self._render_step(step)
            # Live context meter (7c): each step follows an LLM call, so the
            # last-call prompt_tokens has advanced -- refresh the footer.
            self.app.call_from_thread(self._refresh_footer)

        try:
            # #2: hand the ongoing conversation to the investigation so it can
            # resolve references to earlier turns (goes in run_agent's
            # never-compacted preamble — C7-safe, and it's the user's own
            # conversation, not untrusted target data).
            result = run_agent(
                goal, self._data_dir, max_iters=REPL_MAX_ITERS, on_step=_on_step,
                prior_context=self.session_state.get("resume_context") or None,
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
            # including on the cancel/error early-returns above.
            if target_override:
                _kconfig.set_active_target(prior_active)

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
            # Design 14a: Kratos's own model failed mid-investigation -> banner,
            # not an inline tool-style error.
            self._emit_from_worker(R.llm_failure_banner("the language model became unavailable during the investigation"))
            status = "llm_unavailable"
        else:
            self._emit_from_worker(R.error_line(f"Investigation stopped: {result['status']}"))
            status = str(result["status"])

        # Structured recommend-only remediation (19b): render each command the
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

        self._emit_from_worker(Text(f"Done in {duration:.0f}s", style=T.TEXT_FAINTER))

        transcript_path = self._transcripts_dir() / f"{self.session_state['session_id']}_turn{turn_id}.json"
        transcript_path.write_text(json.dumps(result.get("transcript", []), indent=2, default=str), encoding="utf-8")
        self._store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))
        self._remember_turn(goal, result.get("final_answer") or f"(investigation ended: {status})")
        self._ctx_chars += len(goal) + len(result.get("final_answer", "") or "")
        self.app.call_from_thread(self._refresh_footer)

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
        elif step.get("tool_proposal"):
            proposal = step["tool_proposal"]
            self.session_state["pending_evolve_suggestion"] = proposal
            body = (
                f"{proposal.get('name', '')}\n{proposal.get('description', '')}\n\n"
                'Run /evolve to have Kratos build this (needs a test harness).'
            )
            self._emit_from_worker(R.result_panel("Evo-loop suggestion", body, T.ATTENTION))
        elif step.get("status") == "context_compacted":
            # Feature 14b: agent/loop.py folded the oldest turns to stay within
            # the model's context window. Informational only -- the record is
            # untouched -- so it renders as a faint line, and the 7c footer meter
            # will drop on the next step as the prompt shrinks.
            self._emit_from_worker(
                R.compaction_line(step.get("context_tokens", 0), step.get("context_window", 0))
            )

    @work(thread=True)
    def _compact_flow(self) -> None:
        """Manual /compact — summarize the working conversation context into a
        compact summary, freeing token budget while KEEPING the memory (unlike
        /clear, which discards it). The Claude-Code-style companion to the
        automatic 14b compaction inside run_agent: this one operates on the
        session's chat/resume context (`resume_context`), which run_agent's loop
        never sees, so it's C7-orthogonal (touches no investigation transcript
        or guard state)."""
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
        turns as fit, and hard-caps as a last resort. C7-orthogonal (chat context
        only; never touches run_agent's transcript/guards)."""
        from kratos.llm_interface import agent_chat, get_context_window_tokens, reset_session_token_usage

        ctx = self.session_state.get("resume_context", "").strip()
        if not ctx:
            if manual:
                self._emit_from_worker(R.note_line("Nothing to compact yet — the working context is empty."))
            return False
        window = get_context_window_tokens() or 1
        target_chars = max(2000, int(window * 0.6) * 4)  # result should fit ~60% of the window (~4 chars/tok)
        # Keep the most recent turns VERBATIM and summarize only the older ones
        # (matches the investigation compactor + Claude Code). Turns are separated
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
            # Auto-compaction near the window limit — the receding ⤵ notice, same
            # visual language as the investigation loop's 14b compaction event.
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
        same 85% fill the investigation loop (14b) and the footer's "will compact
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
        its own prior answers. Both sides are kept now; auto-compaction (14b) /
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

    @work
    async def action_palette(self) -> None:
        chosen = await self.app.push_screen_wait(CommandPaletteModal(_PALETTE_COMMANDS))
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

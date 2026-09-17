"""
Sprint 3 -- interactive session mode (REPL).
Reference: docs/sprint3_interactive_session_mode_design.md (approved).

Entry point called from cli/app.py::main() on bare `kratos` (no args) only --
`kratos investigate "<goal>"` and every other shell subcommand are completely
unaffected, unchanged code paths. This module is CLI-layer orchestration: it
calls agent/loop.py::run_agent() and cli/app.py's existing cmd_* functions
exactly as they already exist, and renders through agent/console.py's
existing helpers -- no changes to agent/loop.py dispatch, agent/self_approve.py
control flow, or agent/tools.py::request_approval's rendering logic (it's
called exactly as cmd_investigate already calls it, via the same
run_agent()/execute_tool_call() path).

Slash-equivalents for deterministic subcommands (§3) are thin wrappers: they
build a synthetic argv list and parse it through the REAL build_parser(),
then call the REAL args.func(args) -- the same parsing path a shell
invocation uses, not a hand-built Namespace that could drift from the real
subparser definitions over time. This is what makes "byte-identical output
to the shell subcommand" (design doc §9 verification item 3) structurally
guaranteed rather than something that has to be separately kept in sync.
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style

from kratos.agent import console as _console
from kratos.agent.loop import run_agent, DEFAULT_MAX_ITERS
from kratos.agent.tools import request_approval
from kratos import kratos_config as _kconfig
from kratos.llm_config import (
    LLM_OPENAI_MODEL,
    LLAMA_N_CTX,
    LLM_BACKEND,
    ENV_FILE_PATH,
    get_active_llm_model,
    get_active_llm_backend,
    set_active_llm_profile,
)
from kratos.adapters import llm_profiles as _llm_profiles
from kratos.llm_interface import agent_chat, check_endpoint_reachable
from kratos.storage.session_store import SessionStore
from kratos.utils import timeutil as _timeutil

# ---------------------------------------------------------------------------
# Display timezone (UTC-storage / local-display split, see utils/timeutil.py).
# Stored timestamps are absolute UTC; the REPL renders them (and live "now"
# markers) in ONE resolved display zone -- the user's auto-detected system
# zone by default, or a persisted override. Resolved once per session launch
# (run_session) into this module global -- each `kratos` process runs a
# single session serially, the same reason kratos_config._active_target_override
# is a module global rather than threaded through every render helper's
# signature. None until a session sets it: the two helpers below then fall
# back to timeutil's own auto-detection, which matches the previous
# datetime.now()-in-local-time behavior, so a stray direct call (e.g. a unit
# test on a render helper) still renders sensibly.
# ---------------------------------------------------------------------------
_DISPLAY_TZ = None


def _set_display_tz(tz) -> None:
    global _DISPLAY_TZ
    _DISPLAY_TZ = tz


def _display_now(fmt: str = "%H:%M") -> str:
    """Current instant, rendered in the session's display zone."""
    return _timeutil.now_for_display(fmt, tz=_DISPLAY_TZ)


def _display_stored(value: Any, fmt: str = "%H:%M") -> str:
    """A stored (UTC) timestamp string/datetime, rendered in the display
    zone. A legacy naive value is interpreted as local time -- see
    timeutil.parse_stored_instant."""
    return _timeutil.format_for_display(value, fmt, tz=_DISPLAY_TZ)

# Deliberately lower, separate default from DEFAULT_MAX_ITERS (agent/loop.py)
# -- design doc §4.1: a REPL turn is the repeatedly-invoked case (keep it
# bounded/cheap), a deliberate `kratos investigate` call (in or out of the
# REPL) is the exploratory one and keeps its own existing default unchanged.
# Raised 5 -> 7 (2026-09-08): a vuln sweep needs nmap + vuln + config +
# correlate_findings + conclude = 5 steps with no slack, so a single early
# guard-1-rejected conclusion pushed correlate_findings out of budget entirely.
REPL_MAX_ITERS = 7

# Bug fix (2026-07-16, real user report): plain input used to go straight to
# implicit investigate unconditionally -- "hi" launched a full bounded
# tool-calling loop, including a real, live nmap scan against the target,
# with no confirmation. A deterministic greeting/keyword list was
# considered and rejected as brittle and against the actual goal (Kratos
# should decide per-turn whether a tool call is warranted, the way Claude
# Code does, not via an external pattern-match gate). Fix: one single,
# cheap LLM completion (same active backend, low max_tokens, NO tools)
# decides INVESTIGATE-or-chat before run_agent is ever invoked -- cheaper
# than the multi-step tool loop it replaces for a trivial input, and the
# real investigate loop's own safety properties (mandatory tool-calling,
# mandatory correlation, guards) are completely untouched, since this
# routing decision happens strictly before that loop is ever entered.
_INVESTIGATE_SENTINEL = "INVESTIGATE"
_ROUTING_SYSTEM_PROMPT = (
    "You are Kratos, an offline cybersecurity assistant. You can have a normal "
    "conversation, AND you can investigate/scan/analyze a monitored target for "
    "security issues when genuinely asked to.\n\n"
    "Decide: is the user's message a genuine request for you to investigate, scan, "
    "check, or analyze the target/system for security issues right now?\n\n"
    f"If YES: respond with exactly this one word and nothing else: {_INVESTIGATE_SENTINEL}\n\n"
    "If NO (greetings, thanks, small talk, questions about what you are or what you "
    "can do, or anything that isn't actually asking you to go check something right "
    "now): respond normally and conversationally, as Kratos would -- helpful, brief, "
    "no markdown, no tool-calling talk."
)
_ROUTING_MAX_TOKENS = 200


def _route_input(goal: str, resume_context: str = "") -> tuple[bool | None, str | None]:
    """Returns (should_investigate, second_value). should_investigate is
    None if the routing call itself failed (LLM unreachable) -- distinct
    from False (LLM reached, decided this is not an investigation) so the
    caller can report the real failure instead of silently treating it as
    chat. second_value is overloaded by design, matching should_investigate:
    the chat reply text when should_investigate is False, or the real
    underlying failure reason (e.g. "openai_compatible query error: 503
    Server Error...") when should_investigate is None -- never both.

    resume_context (the same running session summary _run_investigate_turn
    already prepends to the real goal) is threaded through here too -- real
    testing found a routing false-positive on a context-dependent follow-up
    ("ok cool, what about now?") when the router saw only the bare message
    with no session history to disambiguate it against."""
    full_prompt = goal
    if resume_context:
        full_prompt = f"[Recent session context:]\n{resume_context}\n\n[User's new message:] {goal}"

    # Real, reported bug: llm_interface.py's own internal diagnostic prints
    # (e.g. "[KRATOS-LLM] openai_compatible query error: 503 Server Error:
    # Service Unavailable...") go straight to stderr and, in a real
    # terminal, land right above this function's own clean render_error --
    # an ugly, inconsistent stack of raw log text next to styled Rich
    # output. Not touching llm_interface.py itself (it's a shared,
    # lower-level module other callers -- `kratos chat`, `kratos
    # investigate` from the shell -- still rely on seeing raw); instead,
    # capture stderr narrowly around just this one call and fold the real
    # underlying reason into the caller's own clean error message instead
    # of discarding it.
    import contextlib
    import io

    captured = io.StringIO()
    with contextlib.redirect_stderr(captured):
        response = agent_chat(_ROUTING_SYSTEM_PROMPT, full_prompt, max_tokens=_ROUTING_MAX_TOKENS)
    if response is None:
        detail = captured.getvalue().strip().splitlines()
        reason = detail[0].removeprefix("[KRATOS-LLM] ").strip() if detail else "no detail available"
        return None, reason
    # Strict, unambiguous check per the fix's own requirement -- not a
    # substring match, which could false-positive on a real conversational
    # reply that happens to mention the word. Tolerates case and a trailing
    # period/whitespace (real, observed model output variance during
    # testing -- see the implementation report), but the ENTIRE response
    # must reduce to just the sentinel, nothing more.
    normalized = response.strip().rstrip(".").strip().upper()
    if normalized == _INVESTIGATE_SENTINEL:
        return True, None
    return False, response.strip()


SLASH_COMMAND_NAMES = [
    "/help", "/clear", "/reset", "/delete", "/rename", "/evolve", "/exit", "/quit", "/target", "/settings",
    "/model", "/timezone", "/scan", "/logs-parse", "/findings-generate", "/run",
]

# Slash-equivalent -> real shell subcommand name (design doc §3's shorthand
# `/log-parse` doesn't match the real subcommand `logs-parse` -- flagged in
# the Step 1 audit; using the real name here so `/logs-parse` inside a
# session and `kratos logs-parse` from the shell are the same word, not a
# confusing mismatch).
_SHORTCUT_TO_SUBCOMMAND = {
    "/scan": "scan",
    "/logs-parse": "logs-parse",
    "/findings-generate": "findings-generate",
    "/run": "run",
}

TRANSCRIPTS_DIRNAME = "sessions"

# Real fix (2026-07-17): was hardcoded to 9 everywhere the chooser/archived-
# view fetched sessions, tied to the old single-digit-only "[1-9] pick a
# session" affordance. Digit-based selection (`choice.isdigit() and 1 <=
# int(choice) <= len(sessions)`) already generalizes to multi-digit numbers
# fine -- raising this and making the footer text reflect the real count
# (see _render_chooser/_render_archived_chooser) needed no other selection-
# logic changes. "Reasonable", not exhaustively paginated -- see the real
# incident this responds to (CLAUDE.md, chooser-junk-input fix): a session
# shouldn't become unreachable through normal use just because a handful of
# newer rows exist, but full pagination is more machinery than today's
# actual scale (single-digit session counts) justifies.
CHOOSER_SESSION_LIMIT = 20

# REPL polish (kratos_repl_polish mockup, 2026-07-17) -- completion-menu
# theming for the /-command popup. Real-usage follow-up fix (2026-07-17,
# user-reported screenshot): the original fg-only version left prompt_toolkit's
# own default mid-gray box background in place for every UNselected entry
# (the common case -- nothing is "current" until the user actually presses
# Down, so most of the time every row rendered with that default), producing
# a washed-out gray-on-gray look. Explicit bg on every row -- not just the
# selected one -- fixes that regardless of terminal/renderer default. Two
# new dark, menu-specific constants (no equivalent already existed in
# console.py's foreground-oriented palette): _MENU_BG (a deliberately dark,
# neutral panel background, distinct from the terminal's own default so the
# popup reads as a distinct surface) and _MENU_FG_SELECTED (a near-black
# text color for real contrast against the ACCENT-filled selected row,
# safer than relying on "reverse", whose actual rendered colors depend on
# the terminal's own default-background assumption).
_MENU_BG = "#20242b"
_MENU_FG_SELECTED = "#12151a"
_PT_STYLE = Style.from_dict({
    "completion-menu": f"bg:{_MENU_BG}",
    "completion-menu.completion": f"bg:{_MENU_BG} fg:{_console.TEXT_PRIMARY}",
    "completion-menu.completion.current": f"bg:{_console.ACCENT} fg:{_MENU_FG_SELECTED} bold",
    "scrollbar.background": f"bg:{_MENU_BG}",
    "scrollbar.button": f"bg:{_console.TEXT_SECONDARY}",
})


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _transcripts_dir(data_dir: Path) -> Path:
    d = data_dir / TRANSCRIPTS_DIRNAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _model_backend_label() -> str:
    return LLM_OPENAI_MODEL


class _DayMarker:
    """Tracks whether today's date has already been printed this process --
    design doc §9.1: date shown only on the first message of a new day, not
    on every line."""

    def __init__(self) -> None:
        self._last_date: str | None = None

    def maybe_render(self, console) -> None:
        today = _display_now("%A, %B %d, %Y")
        if today != self._last_date:
            console.print(f"[{_console.TEXT_SECONDARY}]-- {today} --[/]")
            self._last_date = today


def _print_trailing_timestamp(console, left: str, when: datetime | None = None) -> None:
    """Rich-rendered line with `left` anchored to the left edge and a dim
    HH:MM timestamp right-aligned on the same line -- the kratos_repl_polish
    mockup's (2026-07-17) "trailing metadata" timestamp treatment, replacing
    the old leading `HH:MM label` prefix style. A Table.grid (not manual
    width math) does the alignment so it stays correct regardless of
    terminal width or label length. Only for Rich console.print call sites;
    the live input line uses prompt_toolkit's own `rprompt` instead, since
    that content's final width isn't known until the user finishes typing
    -- see run_session's main loop."""
    from rich.table import Table

    # Stored timestamps are absolute UTC; render `when` in the display zone.
    # A live call (when=None) shows the current instant in that same zone.
    hhmm = _display_stored(when, "%H:%M") if when is not None else _display_now("%H:%M")
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(justify="right")
    grid.add_row(left, f"[{_console.TEXT_SECONDARY}]{hhmm}[/]")
    console.print(grid)


def _timestamp_line(console, label: str, when: datetime | None = None) -> None:
    """Dim HH:MM marker, now trailing/right-aligned (see
    _print_trailing_timestamp) rather than a leading prefix. `when` defaults
    to now (all existing live call sites are unaffected); full-tier resume
    replay passes the turn's real historical timestamp instead -- a
    replayed chat reply must show when it actually happened, not the
    current resume time.

    ACCENT-colored (2026-07-17, real user report): every call site here
    passes literally "kratos:" -- this is Kratos's own response line, and
    before this fix it rendered in plain bold with no color at all, making
    it visually indistinguishable from the "kratos> "-prefixed input line a
    user had just typed on the line above (same word, same weight, no
    color difference -- no way to tell who said what at a glance, unlike
    Claude Code's own clearly-differentiated turns). The input prompt was
    renamed away from "kratos> " to "you> " in the same pass (see
    run_session's main loop) so the "kratos" word/color is now reserved
    for Kratos's own voice exclusively."""
    _print_trailing_timestamp(console, f"[bold {_console.ACCENT}]{label}[/bold {_console.ACCENT}]", when=when)


_TOOLBAR_BG = "#1a1d23"

# 2026-07-17, real user report: the input prompt used to read "kratos> ",
# the exact same word Kratos's own response lines use ("kratos:", see
# _timestamp_line) -- no visual distinction at all between "what you typed"
# and "what Kratos said", unlike Claude Code's own clearly-differentiated
# turns. Renamed to "you> ", styled distinctly (TEXT_SECONDARY, muted) so
# "kratos" as a word/color is now reserved exclusively for Kratos's own
# voice. Used everywhere a user's own input is echoed or replayed --
# the live prompt, the pending-input echo, and full-tier resume replay.
_USER_PROMPT_LABEL = "you> "
_USER_PROMPT_STYLED = FormattedText([(f"fg:{_console.TEXT_SECONDARY} bold", _USER_PROMPT_LABEL)])


def _toolbar_fragments(session_state: dict[str, Any]) -> FormattedText:
    """Bottom-toolbar content for the REPL's PromptSession -- kratos_repl_polish
    mockup (2026-07-17): `kratos model: <model> · target: <target(s)> ·
    session <id>`. ACCENT for the "kratos" label, TEXT_SECONDARY for the rest.
    Passed to PromptSession as a callable (not a static value), so
    prompt_toolkit re-evaluates it on every redraw -- reading straight from
    session_state (mutated in place by /target, see _cmd_target) keeps it
    live across turns with no extra wiring. /model has no live mid-session
    switching yet (see _cmd_model), so the model field is correctly static
    for a session's lifetime, not a gap in this function.

    Explicit `bg:` on BOTH fragments (2026-07-17, real user report + real
    screenshot): the original version only set `fg` and relied on
    prompt_toolkit's own "bottom-toolbar" base class for the background,
    which rendered inconsistently between the "kratos" fragment and the
    rest of the bar (a visibly different-looking patch of color under
    "kratos" specifically, not a clean single-color bar). Pinning the same
    explicit `_TOOLBAR_BG` on every fragment removes that ambiguity outright
    instead of depending on default-style inheritance behaving the same way
    across terminals/renderers.
    """
    model = session_state.get("backend") or "?"
    targets = ", ".join(session_state.get("targets") or []) or "(none)"
    sid = session_state.get("session_id") or "?"
    return FormattedText([
        (f"bg:{_TOOLBAR_BG} fg:{_console.ACCENT} bold", " kratos"),
        (f"bg:{_TOOLBAR_BG} fg:{_console.TEXT_SECONDARY}", f" model: {model} · target: {targets} · session {sid} "),
    ])


# ---------------------------------------------------------------------------
# Step 2 / 5 -- chooser + tiered resume
# ---------------------------------------------------------------------------

def _build_sessions_table(sessions: list[dict[str, Any]]):
    """Real fix (2026-07-17): added the ID column. Real incident this
    responds to -- a user couldn't tell which chooser row was which real
    session (no way to cross-check a row against the "Resume <id>:" prompt
    that appears one step later), which was part of what made a mistyped
    menu selection ("f", meant for the resume-tier prompt) confusing rather
    than immediately diagnosable. Shows the FULL session_id (12 hex chars,
    see SessionStore.create_session) rather than a truncated prefix -- a
    truncated ID that LOOKS like a real match but isn't defeats the entire
    point of this column. Name column added 2026-07-18 (/rename) -- shows
    `s["name"]` if set, a dim placeholder if not; `s["name"]` is always a
    real dict key here since every SessionStore query builds these dicts
    via `SELECT *`, so a NULL name just becomes None, never a missing key."""
    from rich.table import Table

    table = Table(show_header=True, header_style="bold")
    table.add_column("#")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Target(s)")
    table.add_column("Last goal")
    table.add_column("Last active")
    for i, s in enumerate(sessions, start=1):
        name = s.get("name") or f"[{_console.TEXT_SECONDARY}](unnamed)[/]"
        targets = ", ".join(s["targets"]) if s["targets"] else "(none set)"
        goal = (s["latest_goal"] or "(no turns yet)")
        if len(goal) > 50:
            goal = goal[:47] + "..."
        # last_active_at is stored as absolute UTC -- render it in the
        # display zone so the chooser's "Last active" column reads in the
        # user's own local time, not UTC.
        last_active = _display_stored(s["last_active_at"], "%Y-%m-%d %H:%M")
        table.add_row(str(i), s["session_id"], name, targets, goal, last_active)
    return table


def _render_chooser(console, sessions: list[dict[str, Any]]) -> None:
    from rich.panel import Panel

    console.print(
        Panel(
            _build_sessions_table(sessions),
            title=f"[{_console.ACCENT}]Kratos[/] -- recent sessions",
            border_style=_console.ACCENT,
        )
    )
    # Bare literal brackets are Rich markup syntax (Rich tries to interpret
    # "[n]" as a style tag and silently swallows it) -- real bug, confirmed
    # via an actual render showing "[Enter] continue most recent     new
    # session    [1-9] pick a session     quit" with [n]/[q] missing
    # entirely. rich.markup.escape() (or doubled brackets) is required for
    # any literal bracket text, not just a defensive habit.
    from rich.markup import escape

    pick_hint = f"[1-{len(sessions)}] pick a session" if sessions else "[1-9] pick a session"
    more_hint = "    [m] more sessions" if len(sessions) >= CHOOSER_SESSION_LIMIT else ""
    console.print(
        escape(
            f"[Enter] continue most recent    [n] new session    {pick_hint}    "
            f"[a] archived sessions{more_hint}    [q] quit\n"
        )
    )


def _render_archived_chooser(console, sessions: list[dict[str, Any]]) -> None:
    """The /delete recovery-path view -- same table shape as the main
    chooser (_build_sessions_table), different title/footer since the only
    actions here are "restore and resume" or "go back", not the full
    Enter/n/q command set."""
    from rich.panel import Panel
    from rich.markup import escape

    console.print(
        Panel(
            _build_sessions_table(sessions),
            title=f"[{_console.ACCENT}]Kratos[/] -- archived sessions",
            border_style=_console.ACCENT,
        )
    )
    console.print(escape(f"[Enter] back    [1-{len(sessions)}] restore and resume\n"))


def _choose_archived_session(
    console, store: SessionStore, data_dir: Path
) -> tuple[str, list[str], str, str | None] | None:
    """Recovery path for /delete's soft-delete -- a soft-delete without a
    way back isn't actually soft. Restoring (not just viewing) is the
    chosen mechanism: picking an archived session here unarchives it via
    store.restore_session() and resumes it through the exact same
    _resolve_resume_tier flow a normal chooser pick uses, so it comes back
    fully usable (history and all), not merely inspectable. Returns None if
    the user backs out (empty or invalid input) -- the caller
    (_choose_session) re-shows the main chooser in that case rather than
    leaving the user stuck in this sub-view."""
    archived = store.list_archived_sessions(limit=CHOOSER_SESSION_LIMIT)
    if not archived:
        _console.render_note(console, "No archived sessions.")
        return None

    _render_archived_chooser(console, archived)
    raw_choice = input("> ").strip()
    if not raw_choice or not raw_choice.isdigit() or not (1 <= int(raw_choice) <= len(archived)):
        return None

    picked = archived[int(raw_choice) - 1]
    store.restore_session(picked["session_id"])
    _console.render_success(console, f"Session {picked['session_id']} restored.")
    resume_context, pending = _resolve_resume_tier(console, store, picked, data_dir)
    return picked["session_id"], picked["targets"], resume_context, pending


def _choose_more_sessions(
    console, store: SessionStore, data_dir: Path
) -> tuple[str, list[str], str, str | None] | None:
    """[m] more sessions -- the CHOOSER_SESSION_LIMIT overflow view (Fix 3,
    2026-07-17): everything past the first page, in one follow-up view
    (not deep pagination -- see CHOOSER_SESSION_LIMIT's own comment for
    why that's the deliberately simpler choice for today's real scale).
    Mirrors _choose_archived_session's shape exactly: pick a row to resume
    it normally, or back out (any non-digit/out-of-range input) to the
    main chooser -- never a silent fallthrough into treating input as a
    goal, same as the main chooser and resume-tier prompt fixes."""
    more = store.list_recent_sessions(limit=1000, offset=CHOOSER_SESSION_LIMIT)
    if not more:
        _console.render_note(console, "No additional sessions.")
        return None

    from rich.panel import Panel
    from rich.markup import escape

    console.print(
        Panel(
            _build_sessions_table(more),
            title=f"[{_console.ACCENT}]Kratos[/] -- more sessions",
            border_style=_console.ACCENT,
        )
    )
    console.print(escape(f"[Enter] back    [1-{len(more)}] pick a session\n"))
    raw_choice = input("> ").strip()
    if not raw_choice or not raw_choice.isdigit() or not (1 <= int(raw_choice) <= len(more)):
        return None

    picked = more[int(raw_choice) - 1]
    resume_context, pending = _resolve_resume_tier(console, store, picked, data_dir)
    return picked["session_id"], picked["targets"], resume_context, pending


def _resolve_session_by_id_or_name(
    console, store: SessionStore, data_dir: Path, identifier: str
) -> tuple[str, list[str], str, str | None] | None:
    """Real fix (2026-07-18, real user report): resume a session by its
    exact ID -- typed directly at the chooser prompt, or via `kratos
    --resume <id>` from the shell (cli/app.py::main() threads it through
    run_session()). A real DB lookup (SessionStore.get_session), not
    limited to whatever page the chooser happens to be showing -- an ID
    from an older/archived session still resolves. An archived session is
    auto-restored (same as picking it from the [a] recovery view) rather
    than requiring a second confirmation step, since typing a specific ID
    by hand is already an unambiguous "I want THIS one" signal. Routes
    through the SAME _resolve_resume_tier flow every other pick uses, so
    this always lands on the real [l]/[f] prompt, never a special-cased
    shortcut.

    Name support (2026-07-18, /rename): tries an exact ID match FIRST,
    then falls back to an exact name match -- deterministic precedence, no
    ambiguity, since a real session_id (uuid4().hex[:12]) and a
    human-chosen name are never validated against each other's format.
    Both `--resume <id>` and `--resume <name>` (and typing either directly
    at the chooser prompt) go through this one function, so the raw ID
    ALWAYS keeps working even after a session is renamed -- a name is an
    additional way in, never a replacement for the ID.

    Returns None (never raises) if neither an ID nor a name match exists
    -- callers fall back to the normal chooser rather than dead-ending."""
    session = store.get_session(identifier) or store.get_session_by_name(identifier)
    if session is None:
        _console.render_error(console, f"No session found with ID or name {identifier!r}.")
        return None
    session_id = session["session_id"]
    if session.get("status") == "archived":
        store.restore_session(session_id)
        _console.render_success(console, f"Session {session_id} was archived -- restored.")
    resume_context, pending = _resolve_resume_tier(console, store, session, data_dir)
    return session["session_id"], session["targets"], resume_context, pending


def _choose_session(console, store: SessionStore, data_dir: Path) -> tuple[str, list[str], str, str | None]:
    """Returns (session_id, targets, resume_context_text, pending_input).

    Real fix (2026-07-17): the chooser prompt used to fall through on ANY
    unrecognized input -- treating it as the session's first real message,
    defaulting to the most-recently-active session. That was itself a fix
    for an earlier bug (a genuine first message typed here used to vanish
    silently with zero feedback), but real usage showed the opposite
    failure is worse: a mistyped/misdirected keystroke (e.g. "f", meant for
    the NEXT prompt) silently became a real chat turn on whatever session
    happened to be most recent, with nothing to indicate that's what
    happened -- confusing, and with no session-ID column (see
    _build_sessions_table's own fix) there was no way to even tell which
    session it landed on. Reverted to strict validation: only the
    documented options are accepted; anything else is REJECTED with a
    visible message and the SAME prompt re-shown -- never silently
    swallowed (the old bug this replaces) and never silently promoted to a
    goal (the new bug this fixes). pending_input can still be returned as
    non-None structurally (kept for _run_one_session's existing handling,
    unmodified) but no code path in this function produces one anymore.
    """
    while True:
        sessions = store.list_recent_sessions(limit=CHOOSER_SESSION_LIMIT)

        if not sessions:
            # Real first run: no chooser noise, just start fresh silently.
            # get_active_target() (not the raw SSH_TARGET_HOST default) so a
            # wizard-persisted default target is what a brand-new session
            # actually starts with -- see run_session()'s wizard wiring.
            default_target = _kconfig.get_active_target()
            session_id = store.create_session([default_target], _model_backend_label())
            return session_id, [default_target], "", None

        _render_chooser(console, sessions)

        choice: str | None = None
        id_match: dict[str, Any] | None = None
        while choice is None and id_match is None:
            raw_choice = input("> ").strip()
            c = raw_choice.lower()
            if c in ("q", "n", "a", "m", "") or (c.isdigit() and 1 <= int(c) <= len(sessions)):
                choice = c
                break
            # Real fix (2026-07-18): typing a session ID OR name directly
            # (not just its row number) is also a valid selection -- a
            # real DB lookup, so it works for ANY session, not just what's
            # on this page (see _resolve_session_by_id_or_name, shared
            # with --resume).
            id_match = store.get_session(raw_choice) or store.get_session_by_name(raw_choice)
            if id_match is None:
                _console.render_note(
                    console,
                    f"{raw_choice!r} isn't a valid option -- try again "
                    f"(Enter, n, 1-{len(sessions)}, a session ID/name, a, or q).",
                )

        if id_match is not None:
            if id_match.get("status") == "archived":
                store.restore_session(id_match["session_id"])
                _console.render_success(console, f"Session {id_match['session_id']} was archived -- restored.")
            resume_context, pending = _resolve_resume_tier(console, store, id_match, data_dir)
            return id_match["session_id"], id_match["targets"], resume_context, pending

        if choice == "q":
            raise SystemExit(0)

        if choice == "n":
            default_target = _kconfig.get_active_target()
            target_input = input(f"Target(s) [default: {default_target}]: ").strip()
            targets = target_input.split() if target_input else [default_target]
            session_id = store.create_session(targets, _model_backend_label())
            return session_id, targets, "", None

        if choice == "a":
            archived_result = _choose_archived_session(console, store, data_dir)
            if archived_result is not None:
                return archived_result
            continue  # user backed out -- re-show this same chooser

        if choice == "m":
            more_result = _choose_more_sessions(console, store, data_dir)
            if more_result is not None:
                return more_result
            continue  # user backed out -- re-show this same chooser

        if choice == "":
            # design doc §5: Enter is the documented fast-path default for
            # "continue the most recent" -- genuinely unambiguous, no note needed.
            picked = sessions[0]
        else:
            picked = sessions[int(choice) - 1]

        resume_context, pending = _resolve_resume_tier(console, store, picked, data_dir)
        return picked["session_id"], picked["targets"], resume_context, pending


def _resolve_resume_tier(
    console, store: SessionStore, session: dict[str, Any], data_dir: Path
) -> tuple[str, str | None]:
    # Real bug found and fixed during verification: LLAMA_N_CTX is a STATIC
    # default (6144) that exists regardless of which backend is actually
    # active -- it only means anything on the direct llama_cpp in-process
    # load path. OR-ing it in here made this warning fire unconditionally,
    # confirmed via a real test with Gemini active (LLM_OPENAI_MODEL ==
    # "gemini-2.5-pro") where the "local small-context backend" warning
    # still incorrectly appeared. Design doc §7 specifically calls out "the
    # local qwen2.5:7b / 6144-context backend" as the one to warn about --
    # keying off the actually-resolved model name alone is the correct,
    # non-guessed check. get_active_llm_model() (2026-07-18, /model) --
    # not the frozen LLM_OPENAI_MODEL import -- since /delete's chooser-
    # restart loop can reach this resume-tier prompt again, in the SAME
    # process, after a mid-session /model switch; the frozen import would
    # silently keep reporting the process's STARTUP model forever.
    is_local_small_context = get_active_llm_model() == "qwen2.5:7b"

    from rich.markup import escape

    console.print(f"\nResume [{_console.ACCENT}]{session['session_id']}[/]:")
    console.print(escape("  [l] Light -- targets + goal history + compact summary (default)"))
    console.print(escape("  [f] Full  -- complete transcript replay into context"))
    if is_local_small_context:
        _console.render_note(
            console,
            "Full replay is not recommended on the current local, small-context backend -- "
            "it can silently truncate or degrade the model's grasp of the new goal. Light is safe here.",
        )

    # Real fix (2026-07-17): strict validation, matching the chooser prompt's
    # own fix -- see _choose_session's docstring for the full real-incident
    # rationale (a literal "f" typed here, in one real case, is exactly what
    # this reverts: it used to silently become a chat message on whatever
    # session was picked, instead of being recognized as Full resume or
    # rejected). Only "", "l", "f" are accepted; anything else is rejected
    # with a visible message and the SAME prompt re-shown.
    tier: str | None = None
    while tier is None:
        raw_tier = input("> ").strip()
        t = raw_tier.lower()
        if t in ("", "l", "f"):
            tier = t
        else:
            _console.render_note(console, f"{raw_tier!r} isn't a resume option -- try again (Enter, l, or f).")

    history = store.get_goal_history(session["session_id"])
    if tier == "f":
        _render_resumed_full_history(console, history)
        return _build_full_resume_context(history, data_dir), None
    return _build_light_resume_context(history), None


# Real bug fix (2026-07-17): [f] Full resume correctly fed the whole prior
# transcript into the LLM's context (unchanged, still does -- see
# _build_full_resume_context below), but nothing ever rendered it back to
# the terminal -- the user saw an empty session start with zero visible
# trace that history had been loaded, even though the model actually had
# it. This section renders that same history back on screen.
#
# Approach: full step-by-step replay calling the SAME console.py render
# helpers live execution uses (render_tool_call/render_finding/
# render_result_panel/etc., via _render_step_for_replay below), not a new
# text-only summary format -- a resumed turn looks exactly like it did the
# first time it ran. Deliberately NOT sharing one function with
# _run_investigate_turn's live on_step callback, even though the rendering
# logic overlaps: on_step skips final_answer-shaped steps on purpose (the
# caller renders that panel once, itself, right after run_agent() returns --
# rendering it again from on_step would double it), while replay is the ONLY
# renderer for a historical turn's answer and must render it. Forcing both
# through one function would need one of them to special-case around the
# other; two small functions calling the same underlying console.py helpers
# is more honest about that real behavioral difference, and on_step itself
# is untouched -- zero risk to live rendering. Those helpers are already
# compact (one line
# per tool call, no raw observation dumps), so this doesn't turn into a
# wall of JSON on its own. The one real length risk is a session with MANY
# turns, not a single verbose one -- capped via
# FULL_RESUME_DETAILED_TURN_CAP: only the most recent N turns get the full
# replay, older ones collapse to the same compact one-liner light resume
# already uses (one format to maintain, not two). This only affects what's
# RE-RENDERED on screen -- _build_full_resume_context (the actual context
# fed to the model) is untouched and still includes every turn regardless.
FULL_RESUME_DETAILED_TURN_CAP = 5


def _parse_turn_time(iso_str: str | None) -> datetime | None:
    if not iso_str:
        return None
    try:
        return datetime.fromisoformat(iso_str)
    except ValueError:
        return None


def _render_step_for_replay(console, step: dict) -> None:
    """Renders one transcript step (a tool call, or a final_answer) for
    full-tier resume replay (_render_turn_replay) -- NOT called by
    _run_investigate_turn's live on_step, see the module-level comment
    above for why. Tool-call branch mirrors on_step's own logic exactly
    (same console.py helpers, same tool_name-truthy check) so a replayed
    tool call looks identical to how it rendered live."""
    tool_name = step.get("tool")
    if tool_name:
        tool_result, effective_status = _console.unwrap_tool_result(step.get("observation"))
        if effective_status == "error":
            error_text = tool_result.get("observation") if isinstance(tool_result, dict) else None
            _console.render_error(console, f"{tool_name} failed -- {error_text or 'no error detail available'}")
        elif tool_name == "correlate_findings" and isinstance(tool_result, dict) and tool_result.get("findings"):
            findings = tool_result["findings"]
            console.print(f"[{_console.SAFE}]✓[/] [bold]{tool_name}[/bold] -- {_console.plain_label(tool_name)} ({len(findings)} found)")
            for finding in findings:
                _console.render_finding(console, finding)
            _console.render_tool_metadata_notes(console, tool_result)
        else:
            _console.render_tool_call(console, tool_name, effective_status)
    elif "final_answer" in step:
        _console.render_result_panel(console, "Concluded", step["final_answer"], _console.SAFE)


def _render_turn_replay(console, turn: dict[str, Any]) -> None:
    """Full step-by-step replay of one past turn -- called only for turns
    within FULL_RESUME_DETAILED_TURN_CAP."""
    goal = turn["goal"]
    status = turn.get("status") or "in_progress"
    when = _parse_turn_time(turn.get("started_at"))
    _print_trailing_timestamp(console, f"[{_console.TEXT_SECONDARY} bold]{_USER_PROMPT_LABEL}[/]{goal}", when=when)

    ref = turn.get("transcript_ref")
    if not ref:
        _console.render_note(console, "(no saved transcript for this turn)")
        return
    try:
        transcript = json.loads(Path(ref).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        _console.render_note(console, f"(could not load transcript: {e})")
        return

    if status == "chat_reply":
        # _log_chat_turn saves a single-entry [{"final_answer": reply}]
        # "transcript" purely so full-resume CONTEXT-building
        # (_build_full_resume_context) can reuse its existing step-shape
        # parsing for free -- it was never an investigation and must not
        # look like one on replay, so this branches to the same plain-text
        # rendering a live chat reply gets in _handle_goal, not the
        # tool-call/panel rendering below.
        reply = transcript[0].get("final_answer", "") if transcript else ""
        # Real historical time (completed_at, falling back to started_at),
        # NOT _timestamp_line's own datetime.now() default -- a replayed
        # reply must show when it actually happened, not the current
        # resume time (caught via a real test: the two could legitimately
        # be minutes apart).
        reply_time = _parse_turn_time(turn.get("completed_at")) or _parse_turn_time(turn.get("started_at"))
        _timestamp_line(console, "kratos:", when=reply_time)
        console.print(reply or "(no reply)")
        return

    # Same shape live rendering uses: tool-call lines as they happened, then
    # ONE "HH:MM kratos:" timestamp line right before the concluding panel
    # (_run_investigate_turn does the same immediately before its own
    # render_result_panel call) -- a final_answer entry is always the last
    # transcript entry (agent/loop.py returns immediately after recording
    # it), so splitting off just the last entry is equivalent to a more
    # complex per-step type check.
    final_present = bool(transcript) and "final_answer" in transcript[-1]
    for step in (transcript[:-1] if final_present else transcript):
        _render_step_for_replay(console, step)
    if final_present:
        answer_time = _parse_turn_time(turn.get("completed_at")) or _parse_turn_time(turn.get("started_at"))
        _timestamp_line(console, "kratos:", when=answer_time)
        _render_step_for_replay(console, transcript[-1])
    if status == "cancelled":
        console.print(f"[{_console.TEXT_SECONDARY}]Investigation cancelled.[/]")


def _render_resumed_full_history(console, history: list[dict[str, Any]]) -> None:
    """The actual display fix -- called only from the [f] Full branch of
    _resolve_resume_tier, right before it builds the (unchanged) LLM
    context. Clearly bracketed by dim dividers so replayed history reads as
    history, never confusable with new activity in the current turn."""
    if not history:
        return
    console.print(f"\n[{_console.TEXT_SECONDARY}]-- resumed context ({len(history)} prior turn(s)) --[/]")

    detailed_from = max(0, len(history) - FULL_RESUME_DETAILED_TURN_CAP)
    for i, turn in enumerate(history):
        if i < detailed_from:
            status = turn.get("status") or "in_progress"
            console.print(f"[{_console.TEXT_SECONDARY}]- Goal: {turn['goal']!r} -> {status}[/]")
        else:
            _render_turn_replay(console, turn)

    console.print(f"[{_console.TEXT_SECONDARY}]-- end resumed context -- new activity below --[/]\n")


def _final_reply_from_transcript(transcript_ref: Any) -> str | None:
    """The final answer/reply a turn produced, read from its saved transcript
    (the last step carrying a 'final_answer'). Light — just the conclusion, not
    the tool observations the full builder replays. Returns None if unavailable."""
    if not transcript_ref:
        return None
    try:
        transcript = json.loads(Path(transcript_ref).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for step in reversed(transcript):
        if isinstance(step, dict) and step.get("final_answer"):
            return str(step["final_answer"])
    return None


def _build_light_resume_context(history: list[dict[str, Any]]) -> str:
    """A LIGHT resume summary that still retains substance: each turn's message
    AND its final reply/answer (trimmed), but not the full tool-observation
    detail the full builder replays. The earlier version stored only
    'Goal -> status', so a light resume had the user's questions but none of
    Kratos's answers — the model effectively forgot the conversation. Keeping a
    trimmed reply per turn lets a light resume actually remember what was
    discussed while staying far smaller than a full transcript replay."""
    if not history:
        return ""
    lines = ["[Prior session summary -- messages and Kratos's replies, trimmed (not full tool detail):]"]
    for h in history:
        reply = _final_reply_from_transcript(h.get("transcript_ref"))
        if reply:
            trimmed = reply if len(reply) <= 400 else reply[:400].rstrip() + "…"
            lines.append(f"- You: {h['goal']!r}\n  Kratos: {trimmed}")
        else:
            status = h.get("status") or "in_progress"
            lines.append(f"- You: {h['goal']!r} -> {status} (no saved reply)")
    return "\n".join(lines)


def _build_full_resume_context(history: list[dict[str, Any]], data_dir: Path) -> str:
    if not history:
        return ""
    lines = ["[Prior session -- full transcript replay:]"]
    for h in history:
        lines.append(f"\n=== Turn: {h['goal']!r} (status: {h.get('status')}) ===")
        ref = h.get("transcript_ref")
        if not ref:
            lines.append("(no saved transcript for this turn)")
            continue
        try:
            transcript = json.loads(Path(ref).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            lines.append(f"(could not load transcript: {e})")
            continue
        for step in transcript:
            if "final_answer" in step:
                lines.append(f"Concluded: {step['final_answer']}")
            elif "tool" in step:
                lines.append(f"Used {step['tool']}({step.get('args')}) -> {step.get('observation')}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Step 6 -- slash commands
# ---------------------------------------------------------------------------

def _cmd_help(console, **_: Any) -> None:
    from rich.table import Table

    console.print("\n[bold]Session / navigation[/]")
    t = Table(show_header=False, box=None)
    t.add_row("/help", "List available commands")
    t.add_row("/clear", "Free up context: reset conversation continuity (visible history stays on screen)")
    t.add_row("/reset", "Archive this session's history and start it fresh (session keeps running)")
    t.add_row("/delete", "Archive (soft-delete) this session and return to the session picker")
    t.add_row("/rename <name>", "Give this session a name -- usable anywhere its ID already works")
    t.add_row("/exit, /quit", "Leave the session")
    console.print(t)

    console.print("[bold]Evo-loop (write → test → approve → keep a new tool)[/]")
    t = Table(show_header=False, box=None)
    t.add_row("/evolve", "Build the most recent auto-suggested tool, if one is pending")
    t.add_row("/evolve \"<idea>\"", "Start evo-loop fresh with your own idea instead")
    t.add_row("/evolve list", "Browse tools already reachable by the agent (built-in + kept)")
    console.print(t)

    console.print("[bold]Configuration[/]")
    t = Table(show_header=False, box=None)
    t.add_row("/target <ip> [<ip2> ...]", "Set the active target(s) -- shows a setup checklist + verifies it")
    t.add_row("/target verify", "Re-check the active target's setup without changing it")
    t.add_row("/settings", "Per-tool approval policy (not yet implemented)")
    t.add_row("/model", "Show/switch the active LLM backend (only models already listed in .env)")
    t.add_row("/timezone [<zone>|auto]", "Show or pin the display timezone (stored data is always UTC)")
    console.print(t)

    console.print("[bold]Deterministic tool shortcuts[/]")
    t = Table(show_header=False, box=None)
    for slash, sub in _SHORTCUT_TO_SUBCOMMAND.items():
        t.add_row(slash, f"Same as `kratos {sub}`")
    console.print(t)
    console.print()


def _cmd_clear(console, session_state: dict[str, Any], **_: Any) -> None:
    """Narrow, non-destructive by design and by audit (2026-07-17): resets
    ONLY session_state['resume_context'], the in-memory running-summary
    string _run_investigate_turn/_log_chat_turn/_handle_goal thread into
    each new turn for continuity. Confirmed via real code audit + a real
    PTY session (a few real turns, /clear, then checking the terminal and
    the DB) that this has NEVER touched anything else: it takes no `store`
    argument, so it cannot reach goal_history, and nothing in this module
    ever issues a screen-clear escape sequence, so prior visible output
    stays on screen untouched. Frees up context-window budget for new work
    -- that's the whole job. For a full session-DATA reset (archives the
    stored history too, session presents as blank going forward), see
    /reset (_cmd_reset) below; for archiving the session itself, see
    /delete (_cmd_delete)."""
    session_state["resume_context"] = ""
    _console.render_success(console, "Conversation context cleared for this session.")


def _cmd_reset(console, session_state: dict[str, Any], store: SessionStore, **_: Any) -> None:
    """Full session-DATA reset (distinct from /clear's narrow in-memory-only
    scope above): archives this session's stored goal_history (never
    deletes it -- see SessionStore.archive_goal_history) so it presents as
    a blank slate going forward, AND clears session_state['resume_context']
    the same way /clear does, since the in-memory continuity string would
    otherwise still reference the just-archived turns. The session itself
    (id, target) keeps running -- distinct from /delete, which archives the
    SESSION row. Requires confirmation, no force-accept: reuses
    agent/tools.py::request_approval UNMODIFIED rather than a bespoke
    input() prompt, for the same fail-safe-on-interrupt behavior and
    rendered situation panel every other approval gate in this project
    already uses (see that module's own docstring -- it's designed to be a
    generic, reusable blocking-approval primitive, not something coupled to
    TOOL_REGISTRY tool calls specifically)."""
    approved = request_approval(
        "Reset session history",
        {
            "session": session_state["session_id"],
            "action": (
                "Archives this session's stored history (goal_history) and clears its current "
                "conversation context. The prior history is NOT deleted -- it stays in the "
                "database, recoverable -- but this session will present as a blank slate going "
                "forward."
            ),
        },
    )
    if not approved:
        _console.render_note(console, "Reset cancelled -- nothing changed.")
        return

    store.archive_goal_history(session_state["session_id"])
    session_state["resume_context"] = ""
    _console.render_success(console, "Session history archived -- starting fresh from here.")


def _cmd_delete(console, session_state: dict[str, Any], store: SessionStore, **_: Any) -> bool:
    """Soft-deletes ONLY the currently running session -- never another
    session in the DB (deleting arbitrary other sessions from the chooser
    is a reasonable future idea but explicitly out of scope here, see
    CLAUDE.md backlog). Requires confirmation, no force-accept (same
    request_approval reuse as _cmd_reset). On confirm: marks
    sessions.status='archived' (row and all its history retained, never
    removed), sets session_state['restart_chooser'] = True so the caller
    (_run_one_session) re-shows the exact startup chooser bare `kratos`
    uses instead of ending the whole process, and returns False to end
    THIS session's input loop -- same signal /exit's branch in
    _dispatch_slash returns directly. The archived-sessions view there
    ([a]) is the recovery path back to it (see _choose_archived_session).

    Returns True (keep this session's loop going) on decline -- the normal
    _dispatch_slash contract, not a special case."""
    approved = request_approval(
        "Delete this session",
        {
            "session": session_state["session_id"],
            "action": (
                "Archives (soft-deletes) this running session. It will be hidden from the "
                "normal session picker, but the data is retained and recoverable from the "
                "picker's archived-sessions view ([a])."
            ),
        },
    )
    if not approved:
        _console.render_note(console, "Delete cancelled -- session continues normally.")
        return True

    store.archive_session(session_state["session_id"])
    session_state["restart_chooser"] = True
    _console.render_success(console, "Session archived. Returning to the session picker...")
    return False


def _run_target_probe(console) -> None:
    """Shared by /target (after setting a new target) and /target verify
    (re-checking the active target without changing it). Read-only --
    adapters/ssh_remote.py::run_target_probe_checks never mutates target
    state, same trust class as run_config_audit_checks."""
    from kratos.adapters.ssh_remote import run_target_probe_checks, SSHResult

    result = run_target_probe_checks()
    if isinstance(result, SSHResult):
        _console.render_error(
            console, f"Could not reach target to verify setup: {(result.stderr or result.stdout).strip()}"
        )
        return
    _console.render_target_probe_results(console, result)


def _show_target_setup(console, target_host: str) -> None:
    """Shown whenever a NEW target is set (/target <ip>, or the first-run
    wizard's target step) -- 2026-07-18, real gap found and fixed: neither
    of those paths validated or explained anything before this existed
    (confirmed via a real audit: not even IP/hostname format checking).
    Prints the copy-pasteable setup checklist, then immediately probes what
    already works -- so a freshly-added target that hasn't been set up yet
    shows exactly what's still missing, and a target set up correctly ahead
    of time (e.g. today's dev/test Incus container) shows all-PASS with no
    extra ceremony."""
    from kratos.adapters import target_setup as _target_setup

    checklist = _target_setup.generate_target_setup_checklist(target_host)
    _console.render_target_setup_checklist(console, checklist)
    _run_target_probe(console)


def _cmd_target(console, session_state: dict[str, Any], store: SessionStore, arg_text: str, **_: Any) -> None:
    if arg_text.strip() == "verify":
        _run_target_probe(console)
        return

    targets = arg_text.split()
    if not targets:
        current = ", ".join(session_state["targets"]) or "(none set)"
        console.print(f"Current target(s): {current}")
        return
    session_state["targets"] = targets
    store.set_targets(session_state["session_id"], targets)
    # Real bug fix (2026-07-16): this used to only store/display the value --
    # investigations still silently hit the globally-configured SSH target
    # regardless. set_active_target() is the actual override every
    # target-facing tool now resolves its host through (see
    # kratos_config.py/adapters/ssh_remote.py). Multi-target execution is
    # explicitly out of scope (design doc §8) -- only the first target is
    # ever used; say so explicitly rather than silently dropping the rest.
    _kconfig.set_active_target(targets[0])
    if len(targets) > 1:
        _console.render_note(
            console,
            f"Using {targets[0]} for investigations in this session -- multi-target "
            f"execution isn't implemented yet, so the other {len(targets) - 1} target(s) "
            "are stored but won't be used.",
        )
    _console.render_success(console, f"Target(s) set: {', '.join(targets)}")
    _show_target_setup(console, targets[0])


def _cmd_rename(console, session_state: dict[str, Any], store: SessionStore, arg_text: str, **_: Any) -> None:
    """/rename <name> -- give the current session a human-readable name,
    usable as an alternative to its raw ID everywhere the ID already works
    (--resume, typing directly at the chooser prompt) -- see
    _resolve_session_by_id_or_name. The raw ID keeps working unchanged; a
    name is purely additive, never a replacement. Validation is all
    against real collision risks, not arbitrary restrictions: rejects
    empty input (shows the current name instead, same "/target with no
    arg" convention), a purely-numeric name (would collide with
    row-number selection at the chooser), a name matching a reserved
    chooser token (q/n/a/m -- checked before any ID/name lookup, so the
    session would never be reachable by that name), a name that happens
    to equal another session's real ID (that OTHER session would always
    win resolution, silently shadowing this rename), and a name already
    used by another session (an ambiguous --resume target)."""
    name = arg_text.strip()
    if not name:
        current = store.get_session(session_state["session_id"])
        current_name = (current or {}).get("name")
        console.print(f"Current name: {current_name or '(unnamed)'}")
        console.print("Usage: /rename <name>")
        return

    if name.isdigit():
        _console.render_error(
            console,
            f"Can't use {name!r} -- a purely numeric name would be ambiguous with "
            "row-number selection at the chooser.",
        )
        return
    if name.lower() in ("q", "n", "a", "m"):
        _console.render_error(
            console,
            f"Can't use {name!r} -- that's a reserved chooser command; the session would "
            "never be reachable by that name.",
        )
        return
    if store.get_session(name) is not None:
        _console.render_error(
            console,
            f"Can't use {name!r} -- it's already a real session ID; using it as a name "
            "would be ambiguous.",
        )
        return
    if store.name_taken(name, exclude_session_id=session_state["session_id"]):
        _console.render_error(console, f"Can't use {name!r} -- another session already has that name.")
        return

    store.rename_session(session_state["session_id"], name)
    _console.render_success(console, f"Session renamed to {name!r}.")


# ---------------------------------------------------------------------------
# Evo-loop (/evolve) -- Sprint 3, 2026-07-18
#
# "Evo-loop" is the user-facing name for agent/self_write_loop.py::
# run_self_write_loop() (Sprint 2's write -> sandbox test -> human-approve
# -> keep pipeline). Internal module/function names (self_write.py,
# self_test.py, self_approve.py, self_write_loop.py, run_self_write_loop)
# are UNCHANGED per this task's own scope -- terminology-only rename,
# user-facing strings only.
#
# Step 1 audit finding (2026-07-18, confirmed before writing any of this):
# run_self_write_loop() had exactly ONE caller in the whole repo --
# scripts/dev/run_self_write_count_failed_ssh_attempts.py, a standalone
# throwaway dev script, not wired into `kratos investigate` or the REPL.
# CLAUDE.md's repeated "no caller anywhere in the codebase" note was still
# accurate at the moment this was written. This section is the first real
# wiring of that pipeline into a live entry point.
#
# Second Step 1 finding, not anticipated by the original task spec:
# WriteRequest.test_file (agent/self_write.py) is a REQUIRED,
# human-authored pytest harness, not something any existing code path can
# synthesize from a plain-language idea -- every real kept tool this
# project has ever produced (count_failed_sudo_attempts,
# count_failed_ssh_attempts) needed one hand-written first. /evolve
# deliberately does NOT auto-generate one: doing so would weaken the one
# part of this pipeline that actually defines "correct", undermining the
# adversarial hardening Phase 3b specifically built around trusting real,
# human-authored tests. See _resolve_evolve_test_file.
#
# Third Step 1 finding: agent/console.py::render_approval_situation
# already auto-detects test-summary-shaped and code-like text generically
# from whatever `details` dict a caller passes it -- self_approve.py's own
# _prompt_for_keep_decision already builds a details dict with the full
# source (syntax-highlighted) and sub-test results (rendered as a table).
# No new rendering was needed for the write/sandbox-test/approval stages
# themselves -- confirmed by reading that code, not assumed. This section
# only adds the auto-suggest panel (agent/console.py::render_evolve_suggestion,
# for agent/loop.py's tool_proposal signal) and a closing outcome summary.
# ---------------------------------------------------------------------------

# Evo-loop's pure, UI-agnostic helpers (name slugging/suggestion, harness
# drafting + static template) now live in the agent layer so the guided-build
# core (agent/guided_evolve.py) and A2 s5.6 Stage 3 can share them without a
# cli dependency. Re-exported here so this module's own interactive helpers
# (_resolve_evolve_tool_name / _resolve_evolve_test_file) and the existing
# tests that patch `kratos.cli.repl.<name>` keep resolving unchanged.
from kratos.agent.guided_evolve import (  # noqa: E402
    _EVOLVE_SLUG_MAX_WORDS,
    _slugify_name_hint,
    _build_evolve_harness_template,
    _EVOLVE_HARNESS_DRAFT_SYSTEM_PROMPT,
    _draft_evolve_harness,
    _suggest_evolve_tool_name,
)


def _resolve_evolve_tool_name(console, goal: str, suggested_name: str | None = None) -> str:
    """Prompts for a tool name. If one is already known (a real
    auto-suggested tool_proposal already includes the model's own chosen
    name -- see session_state['pending_evolve_suggestion']), it's offered
    as the default: pressing Enter just accepts it, no extra LLM call
    needed. Otherwise pressing Enter triggers a FRESH LLM call to suggest
    one from the goal text. Always returns a real, non-empty slug -- an
    LLM failure or unusable response falls back to the existing mechanical
    slug (first few words of the goal) rather than blocking /evolve."""
    if suggested_name:
        default_slug = _slugify_name_hint(suggested_name)
        raw = input(f"Name this tool (snake_case) [{default_slug}]: ").strip()
        return _slugify_name_hint(raw) if raw else default_slug

    raw = input(
        "Name this tool (snake_case), or press Enter to let the LLM suggest one from your idea: "
    ).strip()
    if raw:
        return _slugify_name_hint(raw)

    _console.render_note(console, "Asking the LLM to suggest a tool name...")
    llm_suggestion = _suggest_evolve_tool_name(goal)
    if llm_suggestion:
        _console.render_success(console, f"Suggested name: {llm_suggestion}")
        return llm_suggestion

    fallback = _slugify_name_hint(goal)
    _console.render_note(console, f"Could not get a name suggestion from the LLM -- using '{fallback}' instead.")
    return fallback


def _check_evolve_name_collision(console, tool_name: str) -> bool:
    """Warns if tool_name already matches a REAL tool already reachable by
    the agent -- built-in (agent/tools.py) or a previously-kept one.
    Building and approving a new candidate under the same name would
    silently REPLACE it in TOOL_REGISTRY the moment it's kept (and, for an
    already-kept tool, overwrite its file + metadata.json entry too) --
    neither _persist_kept_tool nor the keep-approval prompt itself warns
    about this on their own; this is the one place in the whole flow that
    catches it, before any real work is done. Read-only: never modifies
    kept_tools/ or TOOL_REGISTRY itself, only warns and asks. Returns True
    if the caller should proceed (no collision, or the user explicitly
    confirmed), False if they backed out -- "no" is the default on any
    unclear answer, matching this project's established pattern for
    consequential actions."""
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

    if tool_name not in TOOL_REGISTRY:
        return True

    metadata = _read_metadata(KEPT_TOOLS_DIR)
    if tool_name in metadata:
        kept_at = metadata[tool_name].get("kept_at", "an earlier session")
        what = f"a kept tool (approved {kept_at})"
    else:
        what = "a BUILT-IN Kratos tool"

    _console.render_note(
        console,
        f"'{tool_name}' is already {what}. Building and approving a new one under the SAME name "
        "will silently REPLACE it once you approve the keep decision.",
    )
    answer: str | None = None
    while answer is None:
        raw = input("Continue with this name anyway? [y/N]: ").strip().lower()
        if raw in ("", "y", "yes", "n", "no"):
            answer = raw
        else:
            _console.render_note(console, f"{raw!r} isn't a valid answer -- try again (y or n).")
    return answer in ("y", "yes")


def _resolve_evolve_test_file(console, tool_name: str, goal: str) -> Path | None:
    """WriteRequest.test_file is required and never auto-generated (see
    module-level comment above) -- prompts for a real path, suggesting
    this project's own established convention
    (tests/self_write_harnesses/test_<name>.py) as a starting guess,
    never assuming it already exists. Returns None (never raises) if the
    given/suggested path doesn't exist, so the caller aborts cleanly
    rather than handing run_self_write_loop a path that will fail later
    with a less clear error.

    tool_name (2026-07-28: now an already-resolved name from
    _resolve_evolve_tool_name, not re-derived here) drives BOTH the
    suggested path AND the drafted/template harness's TOOL_NAME
    consistently -- deliberately NOT re-derived from whatever file path
    the user ends up typing (the old behavior): the file location and the
    tool's registered name are separate concerns, and conflating them
    meant a custom save path could silently change what TOOL_NAME the
    draft used."""
    suggested = Path("tests") / "self_write_harnesses" / f"test_{tool_name}.py"
    console.print(
        f"\nEvo-loop needs a real, human-authored pytest harness file -- it's what defines "
        f"'correct' for this tool, and is never auto-generated. Suggested path: {suggested}"
    )
    # Sanity check (2026-07-28): catches an obvious fat-fingered path (e.g.
    # a stray non-.py path pasted from elsewhere) before it's treated as a
    # real pytest harness -- reject-and-reprompt, same established pattern
    # as the other /evolve prompts, rather than silently reading/writing
    # whatever was typed.
    path: Path | None = None
    while path is None:
        raw = input(f"Test harness file path [{suggested}]: ").strip()
        candidate_path = Path(raw) if raw else suggested
        if candidate_path.suffix == ".py":
            path = candidate_path
        else:
            _console.render_note(
                console, f"{str(candidate_path)!r} doesn't look like a Python file (no .py extension) -- try again."
            )
    if not path.exists():
        _console.render_error(
            console, f"No test file found at {path} -- create it first, then run /evolve again."
        )

        # Default yes -- an Enter keypress takes the more helpful path; "n"
        # opts straight out to the plain static template for anyone who'd
        # rather write from scratch or skip the LLM call/wait.
        #
        # Strict validation (2026-07-28), matching the resume-tier prompt's
        # own established fix (see _resolve_resume_tier's real-incident
        # comment): a real user's mistyped keystroke here shouldn't silently
        # become an answer they didn't intend -- only documented answers are
        # accepted, anything else is rejected with a visible message and the
        # SAME prompt re-shown, never a silent guess at what they meant.
        want_draft: str | None = None
        while want_draft is None:
            raw_draft = input("Draft a starter harness with the LLM for you to review? [Y/n]: ").strip().lower()
            if raw_draft in ("", "y", "yes", "n", "no"):
                want_draft = raw_draft
            else:
                _console.render_note(
                    console, f"{raw_draft!r} isn't a valid answer -- try again (Enter/y for yes, n for no)."
                )
        drafted_code = None
        if want_draft in ("", "y", "yes"):
            _console.render_note(console, "Drafting a starter harness (calls the LLM, can take a moment)...")
            drafted_code = _draft_evolve_harness(console, tool_name, goal)

        if drafted_code:
            _console.render_evolve_harness_template(console, drafted_code, path, drafted=True)
            # Real UX complaint (2026-07-28): the old separate "save?"
            # prompt dead-ended -- saying yes still meant manually retyping
            # the WHOLE /evolve command to actually proceed, even though
            # the draft was just fully read on screen seconds earlier.
            # Collapsed into one choice with 3 real options instead of a
            # generic y/n. Default (empty/unrecognized input) is DISCARD,
            # the least consequential of the three -- matches this
            # project's "no force-accept on anything consequential"
            # pattern applied to whichever option here is most
            # consequential (save-and-build-now actually starts the real
            # write/sandbox/approval pipeline), not just the save step
            # alone. Choosing save-and-build does NOT skip review -- the
            # draft was already shown in full immediately above; retyping
            # the same command a moment later wouldn't have shown it again
            # or given a materially different opportunity to review it.
            # Strict validation (2026-07-28) -- same reasoning as the draft
            # prompt above: a typo here would otherwise silently discard a
            # reviewed draft (or worse, silently pick a different option
            # than intended) instead of being caught and re-asked.
            choice: str | None = None
            while choice is None:
                raw_choice = input(
                    "[s]ave and start building now, [e]dit it yourself first, or [d]iscard? [s/e/d, default d]: "
                ).strip().lower()
                if raw_choice in ("", "s", "save", "e", "edit", "d", "discard"):
                    choice = raw_choice
                else:
                    _console.render_note(console, f"{raw_choice!r} isn't a valid choice -- try again (s, e, or d).")
            if choice in ("s", "save"):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(drafted_code, encoding="utf-8")
                _console.render_success(console, f"Draft saved to {path} -- starting evo-loop now.")
                return path
            elif choice in ("e", "edit"):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(drafted_code, encoding="utf-8")
                _console.render_success(console, f"Draft saved to {path}.")
                _console.render_note(
                    console,
                    "REVIEW IT before continuing -- especially the assertions, which are the model's "
                    "best guess at this tool's interface, not a verified fact. Edit as needed, then run "
                    "/evolve again to actually build the tool.",
                )
            else:
                _console.render_note(console, f"Discarded -- write your own harness at {path}, then run /evolve again.")
        else:
            template = _build_evolve_harness_template(tool_name, goal)
            _console.render_evolve_harness_template(console, template, path)
        return None
    return path


def _render_evolve_outcome(console, outcome: Any) -> None:
    """Closing summary after run_self_write_loop() returns. The
    write/sandbox-test/approval STAGES already rendered live through the
    existing request_approval panel (a LoopOutcome only reaches
    'approved'/'denied' after that panel already ran, per
    agent/self_approve.py's own refusal gate) -- this is just the final
    status line."""
    if outcome.status == "approved":
        kd = outcome.keep_decision
        _console.render_success(
            console,
            f"Kept: {kd.tool_name} (requires_approval={kd.requires_approval}) -- "
            "available immediately in this session, no restart needed.",
        )
    elif outcome.status == "denied":
        _console.render_note(
            console, "Evo-loop finished -- a candidate passed testing but was not kept (denied)."
        )
    else:
        _console.render_error(
            console,
            f"Evo-loop did not produce an approvable candidate (status: {outcome.status}) -- "
            f"{len(outcome.attempt_history)} attempt(s) made, none ever reached a human approval "
            "prompt.",
        )


def _cmd_evolve_list(console) -> None:
    """/evolve list (2026-07-28) -- browse everything the agent can already
    reach (built-in tools from agent/tools.py + previously-kept ones, the
    same TOOL_REGISTRY load_kept_tools() already merges both into) BEFORE
    picking a name for a new tool. Closes a real gap: until now the only
    way to discover a naming collision was to hit
    _check_evolve_name_collision's warning AFTER typing a name that
    already existed. Read-only, mirrors that check's own kept-vs-built-in
    distinction (kept tools show their real kept_at from metadata.json)."""
    from kratos.agent.tools import TOOL_REGISTRY
    from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

    metadata = _read_metadata(KEPT_TOOLS_DIR)
    rows = []
    for name in sorted(TOOL_REGISTRY):
        tool = TOOL_REGISTRY[name]
        is_kept = name in metadata
        first_line = tool.description.strip().splitlines()[0] if tool.description.strip() else ""
        description = first_line[:80] + ("..." if len(first_line) > 80 else "")
        rows.append({
            "name": name,
            "kind": "kept" if is_kept else "built-in",
            "requires_approval": tool.requires_approval,
            "kept_at": metadata[name].get("kept_at") if is_kept else None,
            "description": description,
        })
    _console.render_evolve_tool_list(console, rows)


def _cmd_evolve(console, session_state: dict[str, Any], arg_text: str, **_: Any) -> None:
    """/evolve -- the only thing that can ever actually start evo-loop
    (agent/loop.py's tool_proposal signal only ever suggests; nothing is
    auto-invoked, no exceptions -- see agent/console.py::
    render_evolve_suggestion and this project's standing no-auto-
    escalation principle). Three forms:
    - `/evolve` (no argument): uses the most recent auto-suggest, if one
      is pending on session_state['pending_evolve_suggestion'] (set by
      _run_investigate_turn's _on_step when agent/loop.py emits a
      tool_proposal step). Shows a usage hint, does nothing else, if none
      is pending -- never silent.
    - `/evolve "<idea>"`: starts fresh with the given idea, ignoring any
      pending suggestion entirely.
    - `/evolve list` (2026-07-28): browse built-in + kept tools instead of
      starting evo-loop -- see _cmd_evolve_list.
    Either way (for the two starting forms): real WriteRequest, real
    run_self_write_loop() call (Sprint 2's actual pipeline, unmodified),
    real console.py/request_approval rendering -- no mocking, no
    shortcuts."""
    stripped = arg_text.strip()
    if stripped.lower() in ("list", "ls"):
        _cmd_evolve_list(console)
        return

    idea = stripped.strip('"').strip("'").strip()
    if idea:
        goal = idea
        pending_name = None
    else:
        pending = session_state.get("pending_evolve_suggestion")
        if not pending:
            _console.render_note(
                console,
                'No pending evo-loop suggestion. Use /evolve "<your idea>" to propose something '
                "yourself, or run an investigation that hits a real capability gap first.",
            )
            return
        goal = f"{pending.get('name', '')}: {pending.get('description', '')}".strip(": ")
        pending_name = pending.get("name") or None

    tool_name = _resolve_evolve_tool_name(console, goal, suggested_name=pending_name)
    if not _check_evolve_name_collision(console, tool_name):
        return
    test_file = _resolve_evolve_test_file(console, tool_name, goal)
    if test_file is None:
        return

    from kratos.agent.self_write import WriteRequest
    from kratos.agent.self_write_loop import run_self_write_loop

    _console.render_note(
        console, f"Starting evo-loop (can take several minutes per attempt) -- goal: {goal!r}"
    )
    request = WriteRequest(goal=goal, test_file=test_file)

    # Real bug found and fixed during verification (2026-07-18): a Rich
    # Live spinner wrapping the WHOLE run_self_write_loop() call visibly
    # corrupted the approval prompt -- run_self_write_loop() has no
    # progress callback (confirmed via a real Step 1 audit; adding one
    # would mean changing its signature, out of scope), so there's no way
    # to know from outside when the silent write/sandbox-test phase ends
    # and the INTERACTIVE approval phase (a blocking input() inside
    # request_keep_approval) begins. A Live display actively re-rendering
    # at 8fps while that blocking input() is also reading the same
    # terminal is a real, confirmed conflict, not a hypothetical one --
    # caught by a real end-to-end run showing the approval prompt's own
    # text getting overwritten by the spinner. No spinner at all is the
    # correct fix here, not a smarter one: plain, static status text
    # before the call, then the call blocks normally with nothing else
    # competing for the terminal.
    outcome = run_self_write_loop(request)

    session_state["pending_evolve_suggestion"] = None
    _render_evolve_outcome(console, outcome)


def _cmd_settings(console, **_: Any) -> None:
    _console.render_note(
        console,
        "/settings is not yet implemented -- per-tool approval policy and content-based "
        "escalation rules are a separate, larger design pass (see the standing backlog). "
        "Nothing to configure here yet.",
    )


def _prompt_timezone_fallback(console, data_dir: Path):
    """One-time manual timezone entry, reached ONLY when auto-detection
    genuinely fails (utils/timeutil.display_tz_status -> "fallback") -- a
    rare, misconfigured-environment case, never a recurring nag on normal
    launches. Persists the answer as a display override so it isn't asked
    again; an empty/invalid answer defaults to UTC (also persisted, so the
    prompt doesn't recur every launch). Returns the resolved tzinfo."""
    _console.render_note(
        console,
        "Could not auto-detect this machine's timezone. Enter an IANA zone name "
        "(e.g. 'Europe/Helsinki', 'Asia/Dhaka', or 'UTC') for how timestamps are "
        "shown -- stored data is always UTC, this only affects display. Press Enter for UTC.",
    )
    try:
        answer = input("Display timezone [UTC]: ").strip()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    tz = _timeutil.zone_from_name(answer) if answer else None
    if answer and tz is None:
        _console.render_note(console, f"'{answer}' is not a known timezone -- defaulting to UTC.")
    chosen_name = answer if tz is not None else "UTC"
    _timeutil.set_display_timezone_override(data_dir, chosen_name)
    return _timeutil.zone_from_name(chosen_name) or _timeutil.resolve_display_tz(data_dir)


def _cmd_timezone(console, arg_text: str, data_dir: Path, **_: Any) -> None:
    """/timezone -- display-zone control (setting #5, opt-in override).

      /timezone            show the active display zone + how it was resolved
      /timezone auto       clear any override, revert to system auto-detection
      /timezone <zone>     pin a fixed display zone (e.g. UTC, Asia/Dhaka)

    Display-only: this never changes how anything is STORED (always UTC),
    only how stored instants are rendered. A pinned zone survives across
    sessions (persisted in the local config); 'auto' removes it."""
    arg = arg_text.strip()
    if not arg:
        source, tz = _timeutil.display_tz_status(data_dir)
        name = getattr(tz, "key", None) or str(tz)
        detected = _timeutil.local_tz_name() or "unknown"
        source_label = {
            "override": "fixed override",
            "auto": "auto-detected from this system",
            "fallback": "UTC fallback (auto-detection failed)",
        }.get(source, source)
        _console.render_note(
            console,
            f"Display timezone: {name} ({source_label}). "
            f"Detected system zone: {detected}. "
            "Use '/timezone <zone>' to pin one, or '/timezone auto' to follow this system.",
        )
        return

    if arg.lower() == "auto":
        _timeutil.set_display_timezone_override(data_dir, None)
        _set_display_tz(_timeutil.resolve_display_tz(data_dir))
        _console.render_note(
            console,
            f"Display timezone now follows this system ({_timeutil.local_tz_name() or 'unknown'}).",
        )
        return

    tz = _timeutil.zone_from_name(arg)
    if tz is None:
        _console.render_note(
            console,
            f"'{arg}' is not a known timezone. Use an IANA name like 'Europe/Helsinki', "
            "'Asia/Dhaka', or 'UTC' -- or '/timezone auto' to follow this system.",
        )
        return
    _timeutil.set_display_timezone_override(data_dir, arg)
    _set_display_tz(tz)
    _console.render_note(console, f"Display timezone pinned to {arg}. Stored data is unchanged (always UTC).")


def _cmd_model(console, session_state: dict[str, Any], **_: Any) -> None:
    """/model -- live switching (2026-07-18), constrained to models already
    present in .env. Candidates come from a real .env parse
    (adapters/llm_profiles.py::list_candidate_profiles) -- never invented,
    never free-form entry. On a valid pick: validate the WHOLE 4-variable
    group is actually usable (empty/placeholder values caught, e.g. a
    profile missing a real API key) before touching anything -- if it
    isn't, report exactly what's wrong and change nothing. THEN a real
    live reachability probe against the candidate's own endpoint
    (llm_interface.check_endpoint_reachable, 2026-07-18) -- validate_profile
    alone can't catch a syntactically-fine-but-wrong/expired key or an
    endpoint that just isn't running yet, both of which would otherwise
    only surface on the next real LLM call, after the switch already
    happened. Only once both checks pass: live-switch (llm_config.set_active_llm_profile -- takes effect on the
    very next LLM call in this process; see that function's own comment
    for why a frozen import can't do this) AND persist to .env (swap the
    whole 4-line group; every other line byte-identical) together, so this
    session and future launches never disagree. session_state['backend']
    is updated too, so the bottom toolbar reflects it immediately, same
    live-update mechanism /target already uses. Strict validation on the
    selection prompt itself, same convention as tonight's chooser/
    resume-tier fixes -- reject anything that isn't a valid number/exact
    name and re-prompt, never silently fall through; empty input cancels
    cleanly with no change."""
    candidates, current = _llm_profiles.list_candidate_profiles(ENV_FILE_PATH)
    if not candidates:
        _console.render_note(console, "No LLM profiles found in .env.")
        return

    ctx_note = (
        f"{LLAMA_N_CTX} tokens (local llama_cpp path only)"
        if get_active_llm_backend() != "openai_compatible"
        else "server-managed (not visible from here)"
    )
    console.print(f"Active model: [bold]{session_state['backend']}[/]")
    console.print(f"Context window: {ctx_note}\n")

    for i, c in enumerate(candidates, start=1):
        marker = " [bold](active)[/]" if current is not None and c.model == current.model else ""
        console.print(f"  [{i}] {c.model}{marker}")

    target = None
    while target is None:
        raw = input("\nSwitch to which model? [Enter to cancel]: ").strip()
        if raw == "":
            _console.render_note(console, "Cancelled -- no change.")
            return
        if raw.isdigit() and 1 <= int(raw) <= len(candidates):
            target = candidates[int(raw) - 1]
            continue
        matched = next((c for c in candidates if c.model == raw), None)
        if matched is not None:
            target = matched
            continue
        _console.render_note(
            console,
            f"{raw!r} isn't a listed model -- try again "
            f"(a number 1-{len(candidates)}, an exact model name, or Enter to cancel).",
        )

    if current is not None and target.model == current.model:
        _console.render_note(console, f"{target.model} is already active -- no change.")
        return

    problems = _llm_profiles.validate_profile(target)
    if problems:
        _console.render_error(
            console,
            f"Can't switch to {target.model} -- its .env profile isn't fully configured: "
            + "; ".join(problems)
            + ". Fill in the real value(s) in .env, then try /model again.",
        )
        return

    # Real live reachability check (2026-07-18), added on top of
    # validate_profile's static checks: a syntactically legitimate but
    # wrong/expired/revoked key, or an endpoint that's just not running
    # yet (e.g. Ollama not started), passes validate_profile cleanly and
    # would previously only fail on the NEXT real LLM call, after the
    # switch had already happened. Probes the CANDIDATE profile's own
    # base_url/api_key (llm_interface.check_endpoint_reachable, generalized
    # from what used to be _is_openai_compatible_running's inline-only
    # logic) -- never the currently-active one -- so this catches a broken
    # switch before it's made, not after.
    live = _console.thinking_spinner(console, f"Checking {target.model} is reachable...")
    try:
        reachable, detail = check_endpoint_reachable(target.values["LLM_BASE_URL"], target.values["LLM_API_KEY"])
    finally:
        live.stop()
    if not reachable:
        _console.render_error(
            console,
            f"Can't switch to {target.model} -- its endpoint ({target.values['LLM_BASE_URL']}) isn't "
            f"reachable right now ({detail}). Check it's running (e.g. `kratos llm-serve` for a local "
            "Ollama server) and the key is valid, then try /model again.",
        )
        return

    set_active_llm_profile(target.values)
    _llm_profiles.switch_profile(ENV_FILE_PATH, target, current)
    session_state["backend"] = target.model
    _console.render_success(
        console,
        f"Switched to {target.model} -- active now, and set as the default in .env for future launches.",
    )


def _cmd_shortcut(console, subcommand: str, rest: str, data_dir: Path) -> None:
    """Thin wrapper: parse `rest` through the REAL build_parser() as
    `[subcommand, *rest.split()]` and call the REAL args.func(args) -- the
    exact same code path `kratos <subcommand> ...` uses from the shell, not
    a reimplementation.

    --data-dir MUST come before the subcommand token -- real bug found
    during verification: it's a top-level parser argument, and argparse
    routes everything after the subcommand name to that subparser's own
    argument set, which doesn't know about --data-dir at all. Confirmed via
    a real byte-identical-output test against `kratos scan --target ...`
    that appending it after the subcommand fails with
    "unrecognized arguments: --data-dir ...".
    """
    from kratos.cli.app import build_parser

    argv = ["--data-dir", str(data_dir), subcommand, *rest.split()]
    parser = build_parser()
    try:
        parsed = parser.parse_args(argv)
    except SystemExit:
        _console.render_error(console, f"Could not parse arguments for {subcommand}: {rest!r}")
        return
    parsed.func(parsed)


# ---------------------------------------------------------------------------
# Step 3 / 4.1 -- implicit investigate turn
# ---------------------------------------------------------------------------

def _run_investigate_turn(
    console, store: SessionStore, session_state: dict[str, Any], goal: str, data_dir: Path
) -> None:
    _console.render_note(console, f"Starting investigation (up to {REPL_MAX_ITERS} steps)...")

    full_goal = goal
    if session_state.get("resume_context"):
        full_goal = f"{session_state['resume_context']}\n\n[Current goal:] {goal}"

    turn_id = store.start_turn(session_state["session_id"], goal)
    started_at = time.monotonic()

    findings_count = 0
    live = _console.thinking_spinner(console)

    def _on_step(step: dict) -> None:
        nonlocal findings_count
        live.stop()
        tool_name = step.get("tool")
        observation = step.get("observation")
        if tool_name:
            tool_result, effective_status = _console.unwrap_tool_result(observation)
            if effective_status == "error":
                error_text = tool_result.get("observation") if isinstance(tool_result, dict) else None
                _console.render_error(console, f"{tool_name} failed -- {error_text or 'no error detail available'}")
            elif tool_name == "correlate_findings" and isinstance(tool_result, dict) and tool_result.get("findings"):
                findings = tool_result["findings"]
                console.print(f"[{_console.SAFE}]✓[/] [bold]{tool_name}[/bold] -- {_console.plain_label(tool_name)} ({len(findings)} found)")
                for finding in findings:
                    _console.render_finding(console, finding)
                    findings_count += 1
                _console.render_tool_metadata_notes(console, tool_result)
            else:
                _console.render_tool_call(console, tool_name, effective_status)
        elif step.get("tool_proposal"):
            # Evo-loop auto-suggest (2026-07-18): render-only, never
            # invokes anything -- stashed on session_state so a bare
            # /evolve (no argument) can pick it up. Overwritten by a
            # later proposal in the same or a later turn; NOT cleared by
            # an unrelated turn producing no proposal at all, so it stays
            # usable until the user acts on it or a newer one replaces it.
            proposal = step["tool_proposal"]
            session_state["pending_evolve_suggestion"] = proposal
            _console.render_evolve_suggestion(console, proposal.get("name", ""), proposal.get("description", ""))
        live.start()

    try:
        result = run_agent(goal, data_dir, max_iters=REPL_MAX_ITERS, on_step=_on_step)
    except KeyboardInterrupt:
        # Bug fix (2026-07-16, real user report): Ctrl+C mid-investigation
        # used to propagate all the way to the top as an unhandled
        # exception, dumping a raw traceback -- caught here, at the REPL
        # turn-execution level, so run_agent()/agent/loop.py's own code is
        # completely untouched (they were never the problem; nothing here
        # catches or suppresses exceptions inside the loop itself, only a
        # user-initiated interrupt of the whole call).
        duration = time.monotonic() - started_at
        console.print(f"[{_console.TEXT_SECONDARY}]Investigation cancelled ({duration:.0f}s elapsed).[/]")
        # Distinct 'cancelled' status, not left as the crash-recovery
        # NULL/'in_progress' shape -- free to add (status is already a
        # plain TEXT column, no schema/migration needed) and gives real
        # distinguishing power later: a resumed session's summary can show
        # "-> cancelled" (user chose to stop) differently from "->
        # in_progress" (a genuine crash, ambiguous outcome, worth
        # flagging as such on resume) or a real completion.
        store.complete_turn(turn_id, "cancelled", transcript_ref=None)
        outcome_line = f"- Goal: {goal!r} -> cancelled"
        session_state["resume_context"] = (
            (session_state.get("resume_context", "") + "\n" + outcome_line).strip()
        )
        return
    finally:
        live.stop()

    duration = time.monotonic() - started_at

    _timestamp_line(console, "kratos:")
    if result["status"] == "final_answer":
        _console.render_result_panel(console, "Investigation complete", result["final_answer"], _console.SAFE)
        status = "final_answer"
    elif result["status"] == "max_iters_reached" and result.get("final_answer"):
        _console.render_result_panel(
            console, "Investigation incomplete (step limit reached)", result["final_answer"], _console.ATTENTION
        )
        status = "max_iters_reached"
    else:
        _console.render_error(console, f"Investigation stopped: {result['status']}")
        status = str(result["status"])

    console.print(f"[{_console.TEXT_SECONDARY}]Done in {duration:.0f}s[/]", justify="right")

    transcript_path = _transcripts_dir(data_dir) / f"{session_state['session_id']}_turn{turn_id}.json"
    transcript_path.write_text(json.dumps(result.get("transcript", []), indent=2, default=str), encoding="utf-8")
    store.complete_turn(turn_id, status, transcript_ref=str(transcript_path))

    outcome_line = f"- Goal: {goal!r} -> {status}"
    session_state["resume_context"] = (
        (session_state.get("resume_context", "") + "\n" + outcome_line).strip()
    )


# ---------------------------------------------------------------------------
# Step 3 -- main input loop
# ---------------------------------------------------------------------------

def _dispatch_slash(console, text: str, session_state: dict[str, Any], store: SessionStore, data_dir: Path) -> bool:
    """Returns False if the session should end."""
    parts = text.split(maxsplit=1)
    cmd = parts[0]
    rest = parts[1] if len(parts) > 1 else ""

    if cmd in ("/exit", "/quit"):
        return False
    if cmd == "/help":
        _cmd_help(console)
    elif cmd == "/clear":
        _cmd_clear(console, session_state)
    elif cmd == "/reset":
        _cmd_reset(console, session_state, store)
    elif cmd == "/delete":
        return _cmd_delete(console, session_state, store)
    elif cmd == "/rename":
        _cmd_rename(console, session_state, store, rest)
    elif cmd == "/evolve":
        _cmd_evolve(console, session_state, rest)
    elif cmd == "/target":
        _cmd_target(console, session_state, store, rest)
    elif cmd == "/settings":
        _cmd_settings(console)
    elif cmd == "/model":
        _cmd_model(console, session_state)
    elif cmd == "/timezone":
        _cmd_timezone(console, rest, data_dir)
    elif cmd in _SHORTCUT_TO_SUBCOMMAND:
        _cmd_shortcut(console, _SHORTCUT_TO_SUBCOMMAND[cmd], rest, data_dir)
    else:
        # design doc §4 fallback rule: an unmatched /-prefix is NOT an
        # error -- it falls through to being treated as goal text (e.g. a
        # goal that happens to start with a real path like /etc/...).
        return _handle_goal(console, text, session_state, store, data_dir)
    return True


def _log_chat_turn(store: SessionStore, session_state: dict[str, Any], goal: str, reply: str, data_dir: Path) -> None:
    """Chat turns (routed away from investigate) still get a real
    goal_history row -- status='chat_reply', distinct from investigation
    outcomes -- so light/full resume context includes the exchange for
    session continuity, not just investigations. transcript_ref stores a
    minimal single-entry "transcript" shaped like a final_answer step, so
    _build_full_resume_context's existing step-rendering logic picks it up
    for free on a full-tier resume -- no special-casing needed there."""
    turn_id = store.start_turn(session_state["session_id"], goal)
    transcript_path = _transcripts_dir(data_dir) / f"{session_state['session_id']}_turn{turn_id}.json"
    transcript_path.write_text(json.dumps([{"final_answer": reply}], indent=2), encoding="utf-8")
    store.complete_turn(turn_id, "chat_reply", transcript_ref=str(transcript_path))
    outcome_line = f"- Goal: {goal!r} -> chat_reply"
    session_state["resume_context"] = (
        (session_state.get("resume_context", "") + "\n" + outcome_line).strip()
    )


def _handle_goal(console, goal: str, session_state: dict[str, Any], store: SessionStore, data_dir: Path) -> bool:
    try:
        should_investigate, second_value = _route_input(goal, session_state.get("resume_context", ""))
    except KeyboardInterrupt:
        console.print(f"[{_console.TEXT_SECONDARY}]Cancelled.[/]")
        return True

    if should_investigate is None:
        _console.render_error(
            console,
            f"Could not reach the language model backend to decide how to handle this message "
            f"-- {second_value or 'no detail available'}",
        )
        return True

    if not should_investigate:
        _timestamp_line(console, "kratos:")
        console.print(second_value or "(no reply)")
        _log_chat_turn(store, session_state, goal, second_value or "", data_dir)
        return True

    _run_investigate_turn(console, store, session_state, goal, data_dir)
    return True


def _process_input(
    console, text: str, session_state: dict[str, Any], store: SessionStore, data_dir: Path
) -> bool:
    """Shared by the main loop and pending-input handling below -- one
    routing path for "text the user submitted", regardless of which prompt
    it came from. Returns False if the session should end."""
    store.touch_session(session_state["session_id"])
    if text.startswith("/"):
        return _dispatch_slash(console, text, session_state, store, data_dir)
    return _handle_goal(console, text, session_state, store, data_dir)


def _run_first_run_wizard(console, data_dir: Path) -> bool:
    """First-run trust + default-target setup (Sprint 3, 2026-07-16).

    "trusted" in the directory-scoped local config file is the SOLE gate for
    the whole wizard (both steps) -- matches Claude Code's own pattern: once
    trust is granted, never re-ask, even if the target step was left blank
    that first time. There is deliberately no separate mechanism to re-run
    just the target step later; /target (session-scoped) or hand-editing
    kratos_local_config.json cover that.

    Trust is persisted IMMEDIATELY on "yes", write-through, before the
    target step even starts -- Claude Code itself has had real, reported
    bugs where a trust decision failed to persist across launches; don't
    assume a single end-of-wizard write is safe, test the two-launch case
    for real (see the verification test).

    Returns False if the user declined trust (caller must exit without
    proceeding to the chooser); True otherwise (wizard completed, was
    skipped because already trusted, or the target step itself was skipped).
    """
    config = _kconfig.load_local_config(data_dir)
    if config.get("trusted"):
        return True

    from rich.panel import Panel

    console.print(
        Panel(
            "Do you trust the files in this folder?\n\n"
            "Kratos may read, write, or execute files in this directory.",
            title=f"[{_console.ACCENT}]Kratos[/] -- first run",
            border_style=_console.ACCENT,
        )
    )
    answer = input("Yes/No: ").strip().lower()
    if answer not in ("y", "yes"):
        console.print(f"[{_console.TEXT_SECONDARY}]Not trusted -- exiting.[/]")
        return False

    _kconfig.save_local_config(data_dir, trusted=True)

    console.print(
        f"\nOptional: set a default target IP/hostname for investigations "
        f"(currently: {_kconfig.SSH_TARGET_HOST}). You can change this anytime with /target -- "
        "leave blank to skip for now if you're not ready to configure a real target."
    )
    target_input = input("Default target: ").strip()
    if target_input:
        _kconfig.save_local_config(data_dir, default_target=target_input)
        _kconfig.set_active_target(target_input)
        _console.render_success(console, f"Default target set: {target_input}")
        _show_target_setup(console, target_input)
    else:
        _console.render_note(console, "Skipped -- using the configured default target for now.")

    console.print()
    return True


def run_session(top_level_args) -> int:
    data_dir: Path = top_level_args.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    console = _console.get_console()

    if not _run_first_run_wizard(console, data_dir):
        return 0

    # Resolve the display timezone once for this session (UTC-storage /
    # local-display split, see utils/timeutil.py). Silent in the normal case:
    # an explicit override (setting #5) or the auto-detected system zone needs
    # no interaction at all. Only a genuine auto-detection failure ("fallback")
    # prompts -- once -- for a manual zone, defaulting to UTC if declined.
    tz_source, display_tz = _timeutil.display_tz_status(data_dir)
    if tz_source == "fallback":
        display_tz = _prompt_timezone_fallback(console, data_dir)
    _set_display_tz(display_tz)

    # Seed the active-target override from a wizard-persisted default (if
    # any) BEFORE the chooser runs, so _choose_session()'s own
    # get_active_target() fallback (new-session default text, silent-first-
    # session creation) already reflects it -- same mechanism /target uses,
    # not a second one.
    persisted_target = _kconfig.load_local_config(data_dir).get("default_target")
    if persisted_target:
        _kconfig.set_active_target(persisted_target)

    store = SessionStore(data_dir / "kratos.db")

    # `kratos --resume <id-or-name>` / `--continue`/`-c` (2026-07-18, real
    # user report): both honored ONLY on the very first pass through the
    # loop below -- one-time "start here" instructions from the shell
    # invocation, not a persistent mode. A subsequent /delete-triggered
    # restart of this same loop must land on the normal chooser, never
    # silently re-apply either one again. --resume takes priority if both
    # are somehow given at once (more specific instruction wins).
    resume_session_id = getattr(top_level_args, "resume_session_id", None)
    continue_most_recent = bool(getattr(top_level_args, "continue_most_recent", False))

    # 2026-07-17 (/delete): _run_one_session returns True when a /delete
    # just archived the running session and wants the exact startup chooser
    # re-shown immediately, per the /delete spec -- False for a normal end
    # (/exit, /quit, or EOF), at which point this thin driver loop is done.
    while _run_one_session(
        console, store, data_dir, resume_session_id=resume_session_id, continue_most_recent=continue_most_recent
    ):
        resume_session_id = None
        continue_most_recent = False

    console.print("\nSession ended -- state saved, resume it next time you run `kratos`.")
    return 0


def _resolve_continue_most_recent(
    console, store: SessionStore, data_dir: Path
) -> tuple[str, list[str], str, str | None] | None:
    """`kratos --continue`/`-c` (2026-07-18): jumps straight to the most
    recently active session's [l]/[f] resume-tier prompt, skipping the
    top-level chooser TABLE entirely -- same "no table, still ask [l]/[f]"
    behavior as --resume <id>, for consistency between the two shortcuts.
    Returns None if there are no sessions at all yet, so the caller falls
    back to _choose_session's own "no sessions -> silently create one"
    first-run path rather than duplicating that logic here."""
    sessions = store.list_recent_sessions(limit=1)
    if not sessions:
        return None
    session = sessions[0]
    resume_context, pending = _resolve_resume_tier(console, store, session, data_dir)
    return session["session_id"], session["targets"], resume_context, pending


def _run_one_session(
    console,
    store: SessionStore,
    data_dir: Path,
    resume_session_id: str | None = None,
    continue_most_recent: bool = False,
) -> bool:
    """One full pass through the chooser and a session's input loop --
    extracted from run_session (2026-07-17) so /delete can trigger exactly
    the behavior its spec requires ("immediately shows the same startup
    chooser used on bare kratos launch... reuse that existing render path")
    without exiting the process: returning True here just makes run_session's
    thin `while` loop call this function again, landing back on
    _choose_session fresh, with the just-archived session now correctly
    excluded from it (SessionStore.list_recent_sessions filters out
    status='archived'). Returns False for every other end-of-session path
    (/exit, /quit, EOF), matching this function's only caller.

    `resume_session_id` (2026-07-18, --resume, accepts an ID or a
    /rename'd name): when given, skips _choose_session entirely and
    resolves straight to that session's [l]/[f] resume-tier prompt via
    _resolve_session_by_id_or_name -- the same resolution path typing a
    session ID/name directly at the chooser prompt uses. Falls back to the
    normal chooser if neither an ID nor a name matches, rather than
    dead-ending the whole process on a typo. `continue_most_recent`
    (2026-07-18, --continue/-c) does the same for "just the most recent
    session, no table" -- see _resolve_continue_most_recent."""
    if resume_session_id is not None:
        resolved = _resolve_session_by_id_or_name(console, store, data_dir, resume_session_id)
        if resolved is not None:
            session_id, targets, resume_context, pending_input = resolved
        else:
            _console.render_note(console, "Falling back to the session picker.")
            session_id, targets, resume_context, pending_input = _choose_session(console, store, data_dir)
    elif continue_most_recent:
        resolved = _resolve_continue_most_recent(console, store, data_dir)
        if resolved is not None:
            session_id, targets, resume_context, pending_input = resolved
        else:
            session_id, targets, resume_context, pending_input = _choose_session(console, store, data_dir)
    else:
        session_id, targets, resume_context, pending_input = _choose_session(console, store, data_dir)

    # Whichever session got picked/created, its first stored target becomes
    # this process's active target for the rest of the session -- /target
    # can still change it later. Multi-target is explicitly out of scope
    # (design doc §8): only the first is ever used, said explicitly rather
    # than silently.
    if targets:
        _kconfig.set_active_target(targets[0])
        if len(targets) > 1:
            _console.render_note(
                console,
                f"Using {targets[0]} for investigations in this session -- multi-target "
                f"execution isn't implemented yet, so the other {len(targets) - 1} target(s) "
                "are stored but won't be used.",
            )

    session_state: dict[str, Any] = {
        "session_id": session_id,
        "targets": targets,
        "resume_context": resume_context,
        "backend": _model_backend_label(),
        # Set True only by _cmd_delete on a confirmed /delete -- read at
        # every exit point below to decide "re-show the chooser" (True) vs.
        # "end the whole REPL" (False, the normal /exit /quit EOF case).
        "restart_chooser": False,
    }

    from rich.markup import escape

    console.print(
        f"\n[{_console.ACCENT}]Kratos[/] session " + escape(f"[{session_id}]") +
        f" -- target(s): {', '.join(targets)} -- model: {session_state['backend']}"
    )
    console.print("Type a goal in plain language, or /help for commands.\n")

    day_marker = _DayMarker()
    # Real bug fix (2026-07-17): resuming a session (either tier) restored
    # the model's context (and, for full-tier, now the visible transcript
    # too -- see above) but arrow-up input history was always empty,
    # in-memory-only, scoped to this process -- resuming didn't feel like
    # real continuity for the one thing a human actually interacts with
    # (retyping/editing a previous input). Re-fetching goal_history here
    # (cheap -- a handful of rows, same table light/full resume already
    # read) rather than threading it through _choose_session()'s return
    # value: this needs to apply identically regardless of which tier (or
    # neither, for a brand-new session -- empty history is a correct no-op)
    # was chosen, so it's simplest as one independent step after a
    # session_id exists, not tier-specific logic. InMemoryHistory takes
    # OLDEST-first ordering (its own load_history_strings reverses
    # internally) -- get_goal_history is already seq ASC, so no re-sorting
    # needed; the real most-recent prior input is what up-arrow shows first.
    prior_inputs = [h["goal"] for h in store.get_goal_history(session_id)]
    prompt_session: PromptSession = PromptSession(
        history=InMemoryHistory(history_strings=prior_inputs),
        completer=WordCompleter(SLASH_COMMAND_NAMES, sentence=True),
        style=_PT_STYLE,
        bottom_toolbar=lambda: _toolbar_fragments(session_state),
    )

    # Real bug fix: a message typed at the chooser/resume-tier prompt (before
    # the user realized it was a menu) used to vanish silently -- process it
    # here as this session's real first input, exactly like anything typed
    # at the normal "you>" prompt, instead of discarding it.
    if pending_input:
        day_marker.maybe_render(console)
        _print_trailing_timestamp(console, f"[{_console.TEXT_SECONDARY} bold]{_USER_PROMPT_LABEL}[/]{pending_input}")
        if not _process_input(console, pending_input, session_state, store, data_dir):
            return session_state["restart_chooser"]

    while True:
        day_marker.maybe_render(console)
        # kratos_repl_polish mockup (2026-07-17): trailing/right-aligned
        # timestamp, not a leading prefix -- see _print_trailing_timestamp
        # for the Rich-rendered response lines. This one line can't use
        # that same grid trick: the input line's real content length isn't
        # known until the user finishes typing, so a manual right-align
        # computed up front would be wrong the moment they type anything.
        # prompt_toolkit's own `rprompt` is built for exactly this --
        # pinned to the right edge, recalculated by its layout engine on
        # every redraw regardless of how much has been typed -- so the
        # label itself goes back to being plain ("you> ", styled via
        # _USER_PROMPT_STYLED -- see that constant's own comment for why it
        # isn't "kratos> " anymore; no separate print before/after either,
        # same no-clutter-on-bare-Enter property the old prefix design
        # already had).
        now_str = _display_now("%H:%M")
        try:
            with patch_stdout():
                text = prompt_session.prompt(
                    _USER_PROMPT_STYLED,
                    rprompt=FormattedText([(f"fg:{_console.TEXT_SECONDARY}", now_str)]),
                )
        except EOFError:
            break
        except KeyboardInterrupt:
            # Real user feedback: Ctrl+C used to end the whole session
            # immediately, even at an idle prompt with nothing running.
            # That's wrong -- Ctrl+C stopping an IN-FLIGHT response
            # (already handled by _run_investigate_turn's and
            # _handle_goal's own KeyboardInterrupt catches around the
            # actual LLM/tool calls) is the useful behavior; ending the
            # session on purpose is /exit's job, not an accidental
            # double-tap of the same key. Matches standard REPL convention
            # (bash, Python's own REPL, Claude Code): Ctrl+C at an empty
            # prompt cancels the current line and reprompts, it doesn't exit.
            console.print()
            continue

        text = text.strip()
        if not text:
            # Real, reported issue: repeated blank Enter presses used to
            # print a fresh "HH:MM you:" line each time for nothing -- the
            # timestamp is rendered as part of the prompt line itself
            # (rprompt, above), so a bare Enter genuinely produces zero
            # extra output.
            continue

        keep_going = _process_input(console, text, session_state, store, data_dir)

        if not keep_going:
            break

    return session_state["restart_chooser"]

"""
Launch screen -- the session chooser (design turns 6a-6e).

Backed entirely by an existing mechanism: storage/session_store.py. This is the
Textual re-imagining of cli/repl.py's _choose_session / _render_chooser flow.

Deliberate adaptation from the mockup: the mockup uses number keys (1-5) to
pick a row; here selection is a real cursor (↑↓ + Enter on a DataTable), which
is more idiomatic for a full-screen app and removes the multi-digit-typing
awkwardness the classic REPL had to work around. The single-key commands the
mockup documents (n / a / m / q, Enter) are preserved as bindings, and the #
column is kept for familiarity. Resume-depth (light/full, turn 6b) is a modal.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Input, Static

from kratos.storage.session_store import SessionStore
from kratos.utils import timeutil
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import PromptModal, ResumeTierModal

CHOOSER_SESSION_LIMIT = 20


class LaunchScreen(Screen):
    """Recent-sessions chooser. Pushes a SessionScreen once a session is
    picked/created; refreshes itself whenever it regains focus (e.g. after a
    /delete pops the session screen back to here)."""

    BINDINGS = [
        Binding("enter", "resume_selected", "resume", show=True),
        Binding("slash", "focus_filter", "search", show=True),
        Binding("escape", "clear_filter", "clear search", show=False),
        Binding("n", "new_session", "new", show=True),
        Binding("a", "archived", "archived", show=True),
        Binding("s", "settings", "settings", show=True),
        # ctrl+s too, since some users reach for it -- but 's' is the reliable
        # one (ctrl+s is the terminal's XOFF; Textual disables flow control so
        # it usually still arrives, but don't depend on it).
        Binding("ctrl+s", "settings", "settings", show=False),
        Binding("b", "back", "back", show=False),
        Binding("m", "more", "more", show=False),
        Binding("q", "quit_app", "quit", show=True),
    ]

    CSS = f"""
    LaunchScreen {{ padding: 1 2; }}
    LaunchScreen #title {{ height: 1; }}
    LaunchScreen #filter {{ margin: 1 0 0 0; border: round {T.TEXT_GHOST}; height: 3; }}
    LaunchScreen #filter:focus {{ border: round {T.ACCENT}; }}
    LaunchScreen #hints {{ color: {T.TEXT_DIM}; height: auto; margin-top: 1; }}
    LaunchScreen DataTable {{ height: 1fr; }}
    LaunchScreen #empty {{ color: {T.TEXT_DIM}; }}
    """

    def __init__(self, store: SessionStore, data_dir: Path) -> None:
        super().__init__()
        self._store = store
        self._data_dir = data_dir
        self._rows: list[dict[str, Any]] = []      # sessions fetched from the store
        self._display: list[dict[str, Any]] = []   # table rows: {"kind":"header"|"session", ...}
        self._filter = ""                          # live search text
        self._archived_mode = False
        self._offset = 0          # recent-mode paging (turn 6a "[m] more")
        self._has_more = False    # is there a page after the current one?
        self._display_tz = None   # resolved in on_mount (display-only; storage is UTC)

    def compose(self) -> ComposeResult:
        with Vertical():
            title = Text()
            title.append("KRATOS", style=f"bold {T.KRATOS_RED}")
            title.append("  recent sessions", style=T.TEXT_GHOST)
            yield Static(title, id="title")
            yield Input(placeholder="Filter by name, target, or last goal…  ( / )", id="filter")
            yield DataTable(id="sessions", cursor_type="row", zebra_stripes=False)
            yield Static("", id="hints")

    def on_mount(self) -> None:
        self._display_tz = timeutil.resolve_display_tz(self._data_dir)
        table = self.query_one("#sessions", DataTable)
        table.add_columns("#", "id", "name", "target", "last goal", "last active")
        self._reload()

    def on_screen_resume(self) -> None:
        # Returning here after a /delete popped the session screen -- refresh so
        # the just-archived session is gone (list_recent_sessions filters it).
        self._archived_mode = False
        self._filter = ""
        try:
            self.query_one("#filter", Input).value = ""
        except Exception:  # noqa: BLE001 -- widget may not be mounted yet
            pass
        self._reload()

    # --- data + rendering ------------------------------------------------
    def _reload(self) -> None:
        """Fetch the current page/mode from the store, then (re)render the
        table. Focuses the table -- used on load and on a mode/page change."""
        if self._archived_mode:
            self._rows = self._store.list_archived_sessions(limit=CHOOSER_SESSION_LIMIT)
            self._has_more = False
        else:
            self._rows = self._store.list_recent_sessions(limit=CHOOSER_SESSION_LIMIT, offset=self._offset)
            # Peek one row past this page to know whether "[m] more" applies.
            self._has_more = bool(
                self._store.list_recent_sessions(limit=1, offset=self._offset + CHOOSER_SESSION_LIMIT)
            )
        self._rebuild_display()
        self.query_one("#sessions", DataTable).focus()

    def _matches(self, s: dict[str, Any], q: str) -> bool:
        if not q:
            return True
        hay = " ".join([
            s.get("name") or "",
            " ".join(s.get("targets") or []),
            s.get("latest_goal") or "",
            s.get("session_id") or "",
        ]).lower()
        return q in hay

    def _bucket_for(self, last_active_at: Any) -> str:
        """Relative date bucket in the display zone. 'This week' = last 7 days,
        'This month' = last 30 -- relative labels people actually read, not raw
        week numbers."""
        dt = timeutil.parse_stored_instant(last_active_at)
        if dt is None:
            return "Older"
        d = dt.astimezone(self._display_tz).date()
        today = timeutil.utc_now().astimezone(self._display_tz).date()
        if d >= today:
            return "Today"
        if d == today - timedelta(days=1):
            return "Yesterday"
        if d > today - timedelta(days=7):
            return "This week"
        if d > today - timedelta(days=30):
            return "This month"
        return "Older"

    def _rebuild_display(self) -> None:
        """Render self._rows into the table applying the live filter and (when
        browsing unfiltered recent sessions) relative date-bucket headers.
        Filtered or archived views are flat -- results are already few, and
        buckets would just be noise there."""
        table = self.query_one("#sessions", DataTable)
        table.clear()
        self._display = []
        q = self._filter.strip().lower()
        filtered = [s for s in self._rows if self._matches(s, q)]
        use_buckets = (not self._archived_mode) and not q
        n = 0
        current_bucket = None
        for s in filtered:
            if use_buckets:
                b = self._bucket_for(s["last_active_at"])
                if b != current_bucket:
                    current_bucket = b
                    self._display.append({"kind": "header", "label": b})
                    table.add_row(Text(""), Text(""), Text(f"▾ {b}", style=f"bold {T.ACCENT}"),
                                  Text(""), Text(""), Text(""))
            n += 1
            name = s.get("name") or "(unnamed)"
            targets = ", ".join(s["targets"]) if s["targets"] else "(none)"
            goal = s.get("latest_goal") or "(no turns yet)"
            if len(goal) > 46:
                goal = goal[:43] + "…"
            last_active = timeutil.format_for_display(s["last_active_at"], "%Y-%m-%d %H:%M", tz=self._display_tz)
            self._display.append({"kind": "session", "session": s})
            table.add_row(str(n), s["session_id"], name, targets, goal, last_active)
        first = self._first_session_row()
        if first is not None:
            table.move_cursor(row=first)
        self._render_hints(shown=len(filtered))

    def _first_session_row(self) -> int | None:
        for i, item in enumerate(self._display):
            if item["kind"] == "session":
                return i
        return None

    def _session_at(self, row: int | None) -> dict[str, Any] | None:
        """The session at a table row, or None if the row is a bucket header
        (or out of range) -- so Enter on a header is an inert no-op."""
        if row is None or not (0 <= row < len(self._display)):
            return None
        item = self._display[row]
        return item["session"] if item["kind"] == "session" else None

    def _render_hints(self, shown: int | None = None) -> None:
        hints = self.query_one("#hints", Static)
        if not self._rows and not self._archived_mode:
            hints.update(Text("No sessions yet — press n to start one, or q to quit.", style=T.TEXT_DIM))
            return
        count_txt = ""
        if self._filter.strip():
            count_txt = f"showing {shown} of {len(self._rows)}  ·  esc clear  ·  "
        if self._archived_mode:
            hints.update(Text(f"{count_txt}Enter restore & resume · / search · b back to recent · q quit",
                              style=T.TEXT_DIM))
            return
        page = self._offset // CHOOSER_SESSION_LIMIT + 1
        page_txt = f"  ·  page {page}" if self._offset else ""
        if self._has_more:
            more = "  ·  m more"
        elif self._offset:
            more = "  ·  m back to page 1"
        else:
            more = ""
        hints.update(Text(f"{count_txt}Enter resume · / search · n new · a archived · s settings{more}{page_txt} · q quit",
                          style=T.TEXT_DIM))

    # --- filter (search) -------------------------------------------------
    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_clear_filter(self) -> None:
        if self._filter:
            self._filter = ""
            self.query_one("#filter", Input).value = ""
            self._rebuild_display()
        self.query_one("#sessions", DataTable).focus()

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self._filter = event.value
        self._rebuild_display()  # deliberately does NOT steal focus from the input

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        # Enter in the filter jumps into the results so ↑↓ + Enter can pick one.
        self.query_one("#sessions", DataTable).focus()

    # --- actions ---------------------------------------------------------
    def action_quit_app(self) -> None:
        # q always quits the app (the archived view's own hint lists 'b back'
        # and 'q quit' as distinct — b returns to recent, q leaves Kratos).
        self.app.exit()

    def action_back(self) -> None:
        # b = step back to the recent list: out of the archived view, or from a
        # paged recent list back to page 1. A no-op on the plain first page.
        if self._archived_mode:
            self._archived_mode = False
            self._reload()
        elif self._offset:
            self._offset = 0
            self._reload()

    def action_archived(self) -> None:
        self._archived_mode = True
        self._offset = 0
        self._reload()

    def action_settings(self) -> None:
        # Global settings (models / tools / general) reachable from the home
        # screen with no active session -- SettingsScreen handles session=None,
        # taking the data_dir directly. Session-specific config stays in-session
        # (/target, /rename); those live-updates just no-op here.
        from kratos.tui_mk2.screens.settings import SettingsScreen

        self.app.push_screen(SettingsScreen(data_dir=self._data_dir))

    def action_more(self) -> None:
        # Turn 6a "[m] more sessions": page forward through recent sessions
        # using the store's offset support; wrap back to page 1 once there are
        # no more (so a session can never become unreachable, and there's a way
        # back without a separate key).
        if self._archived_mode:
            return
        next_off = self._offset + CHOOSER_SESSION_LIMIT
        self._offset = next_off if self._store.list_recent_sessions(limit=1, offset=next_off) else 0
        self._reload()

    def action_resume_selected(self) -> None:
        # Enter is consumed by the focused DataTable (it fires RowSelected, see
        # below) before a screen-level binding would ever see it -- this action
        # stays as a keyboard fallback for any focus state where the table
        # isn't focused, and both funnel to the same _resume_flow.
        session = self._session_at(self.query_one("#sessions", DataTable).cursor_row)
        if session is not None:
            self._resume_flow(session)

    @on(DataTable.RowSelected, "#sessions")
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        session = self._session_at(event.cursor_row)
        if session is not None:  # None => a bucket header row, inert
            self._resume_flow(session)

    @work
    async def _resume_flow(self, session: dict[str, Any]) -> None:
        was_archived = self._archived_mode or session.get("status") == "archived"
        # Ask for the tier BEFORE committing anything. If the user backs out of
        # tier selection, nothing should change: don't un-archive the session,
        # and stay in whichever view we came from (the archived list if that's
        # where Enter was pressed) rather than dropping to the recent list.
        tier = await self._pick_tier(session)
        if tier is None:
            self._reload()  # re-render the CURRENT view (mode unchanged)
            return
        if was_archived:
            self._store.restore_session(session["session_id"])
        resume_context = self._build_context(session["session_id"], tier)
        self._open_session(session["session_id"], session["targets"], resume_context, full_replay=(tier == "f"))

    @work
    async def _new_session_flow(self) -> None:
        from kratos import kratos_config as _kconfig

        from kratos.tui_mk2.target_input import (
            KRATOS_HOST_SENTINEL,
            KRATOS_HOST_VALUE,
            expand_host_aliases,
            validate_targets,
        )

        default_target = _kconfig.get_active_target()
        while True:
            answer = await self.app.push_screen_wait(PromptModal(
                "New session",
                f"Target(s), space-separated [default: {default_target}]",
                initial="",
                quick_value=KRATOS_HOST_SENTINEL,
                quick_label="[Kratos-Host] — this machine (127.0.0.1)",
            ))
            if answer is None:
                return  # cancelled
            if answer == KRATOS_HOST_SENTINEL:
                targets = [KRATOS_HOST_VALUE]
                break
            if not answer.strip():
                targets = [default_target]
                break
            targets, err = validate_targets(expand_host_aliases(answer.split()))
            if err:
                # Reject garbage (a pasted command / quoted goal) and re-ask,
                # rather than letting it become an unresolvable active target.
                self.app.notify(err, severity="error", timeout=6)
                continue
            break
        name = await self.app.push_screen_wait(
            PromptModal("New session", "Name (optional — Enter to leave unnamed)", initial="")
        )
        if name is None:
            return
        session_id = self._store.create_session(targets, self.app.model_label())  # type: ignore[attr-defined]
        if name.strip():
            try:
                self._store.rename_session(session_id, name.strip())
            except Exception:  # noqa: BLE001 -- a name collision shouldn't abort creation
                pass
        self._open_session(session_id, targets, "")

    def action_new_session(self) -> None:
        self._new_session_flow()

    # --- helpers ---------------------------------------------------------
    async def _pick_tier(self, session: dict[str, Any]) -> str | None:
        from kratos.llm_config import get_active_llm_model

        warn = get_active_llm_model() == "qwen2.5:7b"
        return await self.app.push_screen_wait(ResumeTierModal(session["session_id"], warn))

    def _build_context(self, session_id: str, tier: str) -> str:
        # Reuse the classic REPL's PURE context builders so mk2 and the classic
        # REPL never diverge on what "resume" means. (These functions only
        # build the string fed to the model; they don't render anything.)
        from kratos.cli.repl import _build_full_resume_context, _build_light_resume_context

        history = self._store.get_goal_history(session_id)
        if tier == "f":
            return _build_full_resume_context(history, self._data_dir)
        return _build_light_resume_context(history)

    def _open_session(
        self, session_id: str, targets: list[str], resume_context: str, full_replay: bool = False
    ) -> None:
        from kratos.tui_mk2.screens.session import SessionScreen

        self.app.push_screen(
            SessionScreen(self._store, self._data_dir, session_id, targets, resume_context, full_replay=full_replay)
        )

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

from pathlib import Path
from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Static

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
        Binding("n", "new_session", "new", show=True),
        Binding("a", "archived", "archived", show=True),
        Binding("m", "more", "more", show=False),
        Binding("q", "quit_app", "quit", show=True),
    ]

    CSS = f"""
    LaunchScreen {{ padding: 1 2; }}
    LaunchScreen #title {{ height: 1; }}
    LaunchScreen #hints {{ color: {T.TEXT_DIM}; height: auto; margin-top: 1; }}
    LaunchScreen DataTable {{ height: 1fr; }}
    LaunchScreen #empty {{ color: {T.TEXT_DIM}; }}
    """

    def __init__(self, store: SessionStore, data_dir: Path) -> None:
        super().__init__()
        self._store = store
        self._data_dir = data_dir
        self._rows: list[dict[str, Any]] = []
        self._archived_mode = False
        self._display_tz = None  # resolved in on_mount (display-only; storage is UTC)

    def compose(self) -> ComposeResult:
        with Vertical():
            title = Text()
            title.append("KRATOS", style=f"bold {T.KRATOS_RED}")
            title.append("  recent sessions", style=T.TEXT_GHOST)
            yield Static(title, id="title")
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
        self._reload()

    def _reload(self) -> None:
        table = self.query_one("#sessions", DataTable)
        table.clear()
        if self._archived_mode:
            self._rows = self._store.list_archived_sessions(limit=CHOOSER_SESSION_LIMIT)
        else:
            self._rows = self._store.list_recent_sessions(limit=CHOOSER_SESSION_LIMIT)
        for i, s in enumerate(self._rows, start=1):
            name = s.get("name") or "(unnamed)"
            targets = ", ".join(s["targets"]) if s["targets"] else "(none)"
            goal = s.get("latest_goal") or "(no turns yet)"
            if len(goal) > 46:
                goal = goal[:43] + "…"
            # last_active_at is stored UTC -- render in the display zone
            # (falls back to the raw string if unparseable).
            last_active = timeutil.format_for_display(s["last_active_at"], "%Y-%m-%d %H:%M", tz=self._display_tz)
            table.add_row(str(i), s["session_id"], name, targets, goal, last_active)
        table.focus()
        self._render_hints()

    def _render_hints(self) -> None:
        hints = self.query_one("#hints", Static)
        if not self._rows and not self._archived_mode:
            hints.update(Text("No sessions yet — press n to start one, or q to quit.", style=T.TEXT_DIM))
            return
        if self._archived_mode:
            hints.update(Text("Enter restore & resume · b back to recent · q quit", style=T.TEXT_DIM))
            return
        more = "  ·  m more" if len(self._rows) >= CHOOSER_SESSION_LIMIT else ""
        hints.update(Text(f"Enter resume · n new · a archived{more} · q quit", style=T.TEXT_DIM))

    # --- actions ---------------------------------------------------------
    def action_quit_app(self) -> None:
        if self._archived_mode:
            self._archived_mode = False
            self._reload()
            return
        self.app.exit()

    def action_archived(self) -> None:
        self._archived_mode = True
        self._reload()

    def action_more(self) -> None:
        # Overflow view (turn 6a "[m] more"): mechanism exists via offset, but
        # a second page adds little at today's scale -- documented in the doc
        # as a small follow-up. For now, more == archived is NOT correct, so we
        # simply note it rather than silently doing the wrong thing.
        self.notify("More-sessions paging is a documented follow-up (see docs/kratos_mk2_tui.md).", timeout=4)

    def action_resume_selected(self) -> None:
        # Enter is consumed by the focused DataTable (it fires RowSelected, see
        # below) before a screen-level binding would ever see it -- this action
        # stays as a keyboard fallback for any focus state where the table
        # isn't focused, and both funnel to the same _resume_flow.
        if not self._rows:
            return
        table = self.query_one("#sessions", DataTable)
        row = table.cursor_row
        if row is None or not (0 <= row < len(self._rows)):
            return
        self._resume_flow(self._rows[row])

    @on(DataTable.RowSelected, "#sessions")
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        row = event.cursor_row
        if row is not None and 0 <= row < len(self._rows):
            self._resume_flow(self._rows[row])

    @work
    async def _resume_flow(self, session: dict[str, Any]) -> None:
        if self._archived_mode:
            self._store.restore_session(session["session_id"])
        elif session.get("status") == "archived":
            self._store.restore_session(session["session_id"])
        tier = await self._pick_tier(session)
        if tier is None:
            self._archived_mode = False
            self._reload()
            return
        resume_context = self._build_context(session["session_id"], tier)
        self._open_session(session["session_id"], session["targets"], resume_context, full_replay=(tier == "f"))

    @work
    async def _new_session_flow(self) -> None:
        from kratos import kratos_config as _kconfig

        default_target = _kconfig.get_active_target()
        target = await self.app.push_screen_wait(
            PromptModal("New session", f"Target(s), space-separated [default: {default_target}]", initial="")
        )
        if target is None:
            return
        targets = target.split() if target.strip() else [default_target]
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

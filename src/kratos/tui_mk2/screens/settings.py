"""
Full-screen model management (reached via /settings). Piece 3a of the model
settings screen: list every configured LLM profile with where it runs and its
context window, mark the active one, and switch -- reusing the EXACT
validate -> reachable -> set_active_llm_profile -> switch_profile path /model
already uses, so switching here behaves identically to switching there. Adding a
model and editing a context window (with detection) land on top of this screen
as follow-up steps (3b/3c).
"""
from __future__ import annotations

from typing import Any

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Static

from kratos.tui_mk2 import theme as T


class ModelSettingsScreen(Screen):
    """Model management hub. `session` is the SessionScreen underneath, reused
    for its cost/privacy blurb and footer refresh so a switch here updates the
    same live state a /model switch would."""

    BINDINGS = [
        Binding("escape,q", "close", "back to session", show=True),
        Binding("a", "add_model", "add model", show=True),
    ]

    CSS = f"""
    ModelSettingsScreen {{ padding: 1 2; }}
    ModelSettingsScreen #ms-title {{ height: 1; text-style: bold; color: {T.ACCENT}; }}
    ModelSettingsScreen #ms-sub {{ height: auto; color: {T.TEXT_DIM}; padding: 0 0 1 0; }}
    ModelSettingsScreen DataTable {{ height: 1fr; }}
    ModelSettingsScreen #ms-status {{ height: auto; color: {T.TEXT_MUTED}; padding: 1 0 0 0; }}
    ModelSettingsScreen #ms-hints {{ height: 1; color: {T.TEXT_DIM}; }}
    """

    def __init__(self, session: Any) -> None:
        super().__init__()
        self._session = session
        self._candidates: list = []
        self._current = None

    def compose(self) -> ComposeResult:
        yield Static("Model settings", id="ms-title")
        yield Static(
            "Switch the active model, or add one and set its context window. Active model is marked ●.",
            id="ms-sub",
        )
        table = DataTable(id="ms-table", cursor_type="row", zebra_stripes=False)
        table.add_columns(" ", "Model", "Where", "Context window")
        yield table
        yield Static("", id="ms-status")
        yield Static("↑↓ select   ·   Enter switch   ·   a add model   ·   esc back", id="ms-hints")

    def on_mount(self) -> None:
        self._reload()
        self.query_one("#ms-table", DataTable).focus()

    # --- data ------------------------------------------------------------
    def _reload(self) -> None:
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH

        self._candidates, self._current = _p.list_candidate_profiles(ENV_FILE_PATH)
        table = self.query_one("#ms-table", DataTable)
        table.clear()
        for c in self._candidates:
            active = self._current is not None and c.model == self._current.model
            mark = Text("●", style=T.SAFE) if active else Text(" ")
            where = self._session._profile_blurb(c.values)
            win = c.values.get("LLM_CONTEXT_WINDOW")
            win_txt = f"{int(win):,}" if (win and str(win).strip().isdigit()) else "auto"
            table.add_row(
                mark,
                Text(c.model, style=T.TEXT_BRIGHT if active else T.TEXT_MUTED),
                Text(where, style=T.TEXT_DIM),
                Text(win_txt, style=T.TEXT_MUTED),
            )
        if not self._candidates:
            self._set_status("No LLM profiles found in .env. (Add-model form arrives in the next step.)")

    def _selected_profile(self):
        if not self._candidates:
            return None
        idx = self.query_one("#ms-table", DataTable).cursor_row
        if idx is None or idx < 0 or idx >= len(self._candidates):
            return None
        return self._candidates[idx]

    def _set_status(self, msg: str, style: str | None = None) -> None:
        self.query_one("#ms-status", Static).update(Text(msg, style=style or T.TEXT_MUTED))

    # --- actions ---------------------------------------------------------
    def action_close(self) -> None:
        self.app.pop_screen()

    def action_add_model(self) -> None:
        # 3b lands here: push an AddModelModal (presets + detection + validation).
        self._set_status("Add-model form is the next build step — coming shortly.")

    @on(DataTable.RowSelected)
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        # Enter or click on a row -> switch. Handled here (not a screen-level
        # 'enter' binding) because a focused DataTable consumes Enter itself.
        self.action_switch()

    def action_switch(self) -> None:
        target = self._selected_profile()
        if target is None:
            return
        if self._current is not None and target.model == self._current.model:
            self._set_status(f"{target.model} is already active.")
            return
        self._do_switch(target)

    @work(thread=True)
    def _do_switch(self, target) -> None:
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH, set_active_llm_profile
        from kratos.llm_interface import check_endpoint_reachable

        problems = _p.validate_profile(target)
        if problems:
            self.app.call_from_thread(self._set_status, f"Can't switch: {'; '.join(problems)}", T.CRITICAL)
            return
        self.app.call_from_thread(self._set_status, f"Checking {target.model} is reachable…")
        reachable, detail = check_endpoint_reachable(target.values["LLM_BASE_URL"], target.values["LLM_API_KEY"])
        if not reachable:
            self.app.call_from_thread(self._set_status, f"Not reachable — {detail}", T.CRITICAL)
            return
        set_active_llm_profile(target.values)
        _p.switch_profile(ENV_FILE_PATH, target, self._current)
        self._session.session_state["backend"] = target.model
        self.app.call_from_thread(self._session._refresh_footer)
        self.app.call_from_thread(self._reload)
        self.app.call_from_thread(self._set_status, f"Switched to {target.model} — active now, saved to .env.", T.SAFE)

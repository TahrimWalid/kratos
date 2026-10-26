"""
Full-screen general Settings (reached via /settings). A tabbed hub -- Models is
one section, alongside placeholders for Tool approvals and General -- so
/settings is the settings home, not a model-only screen.

Models section: list every configured LLM profile with where it runs and its
context window, and MANAGE them -- switch, add (with provider presets + live
context-window detection), and edit a model's context window. Switching reuses
the exact validate -> reachable -> set_active_llm_profile -> switch_profile path
/model uses. The context-window field enforces the hard-vs-soft rule: above a
model's real max is rejected; above the currently-loaded-but-below-max is a soft
heads-up (the beefy-rig case); an undetectable endpoint is the user's own number.
"""
from __future__ import annotations

from typing import Any

from kratos.untrusted_rich import SafeText as Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Input, Select, TabbedContent, TabPane
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static

from kratos.tui_mk2 import render as R
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.table_fit import fit_columns
from kratos.tui_mk2.workers import ResilientWorkerHost

# Provider presets: label -> (base_url, backend). "" base_url = fill it yourself.
# Only OpenAI-compatible endpoints (what Kratos speaks); non-OpenAI-native
# providers are reachable via their OpenAI-compatible URL or an OpenRouter proxy.
_PRESETS: dict[str, tuple[str, str]] = {
    "Ollama (local)": ("http://127.0.0.1:11434/v1", "openai_compatible"),
    "OpenAI": ("https://api.openai.com/v1", "openai_compatible"),
    "Google Gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "openai_compatible"),
    "DeepSeek": ("https://api.deepseek.com/v1", "openai_compatible"),
    "OpenRouter": ("https://openrouter.ai/api/v1", "openai_compatible"),
    "Custom / other": ("", "openai_compatible"),
}


def _validate_window(raw: str, detected_max: int | None, detected_loaded: int | None) -> tuple[int | None, str | None, str | None]:
    """(value, hard_error, soft_warning). Empty -> (None, None, None) = leave it
    'auto'. Non-numeric -> a hard error. Above a KNOWN max -> hard error (will be
    rejected by the backend). Above the currently-loaded-but-<=max -> a soft
    heads-up, still allowed (reload your server bigger). Undetectable -> the
    user's own number, no ceiling to check."""
    raw = raw.strip()
    if not raw:
        return None, None, None
    if not raw.isdigit() or int(raw) <= 0:
        return None, "Context window must be a positive whole number of tokens.", None
    value = int(raw)
    if detected_max is not None and value > detected_max:
        return None, f"Exceeds this model's real max of {detected_max:,} — requests would be rejected. Lower it.", None
    if detected_loaded is not None and detected_max is not None and detected_loaded < value <= detected_max:
        return value, None, (f"Above what the server currently has loaded ({detected_loaded:,}) — make sure it's "
                             f"actually running at this size, or requests may fail.")
    return value, None, None


def _window_label(values: dict[str, str]) -> str:
    """Context-window cell for the Models table: the number plus where it came
    from, or what Kratos will do when nothing is saved."""
    win = str(values.get("LLM_CONTEXT_WINDOW", "")).strip()
    if win.isdigit():
        src = str(values.get("LLM_CONTEXT_SOURCE", "")).strip()
        tag = {"provider": "detected", "catalog": "catalog"}.get(src, "set")
        return f"{int(win):,} ({tag})"
    from kratos.adapters.llm_context_autofill import needs_autofill
    return "auto (detect on switch)" if needs_autofill(values) else "local default"


class _ContextField:
    """Shared detect+hint behavior for the add/edit forms (composition, not
    inheritance, to keep each modal's compose() explicit)."""

    def __init__(self, owner: ModalScreen):
        self.owner = owner
        self.detected_max: int | None = None
        self.detected_loaded: int | None = None
        self.detected_value: int | None = None       # what detection prefilled
        self.detected_authority: str | None = None   # "provider" | "catalog"

    def source_for(self, value: int | None) -> str | None:
        """The provenance to save with `value`: the detection's source if the
        user kept the detected number, else None (= user-set)."""
        if value is not None and value == self.detected_value:
            return self.detected_authority
        return None

    def detect(self, base_url: str, api_key: str, model: str) -> None:
        # Textual's @work only works on DOMNodes (it asserts), and this helper is
        # a plain object -- so the thread worker is started on the owning modal.
        self.owner.run_worker(lambda: self._detect_blocking(base_url, api_key, model),
                              thread=True, exclusive=True, group="context-detect")

    def _detect_blocking(self, base_url: str, api_key: str, model: str) -> None:
        from kratos.adapters.llm_context_detect import detect_context_window
        self.owner.app.call_from_thread(self.owner._set_hint, "Detecting context window…", T.TEXT_DIM)
        d = detect_context_window(base_url, api_key, model)
        self.detected_max = d.max_context
        self.detected_loaded = d.loaded_context
        self.detected_value = d.value
        self.detected_authority = d.authority
        if d.detectable:
            self.owner.app.call_from_thread(self.owner._set_window_value, str(d.value))
            # A catalog figure is the model's published max, not this provider's
            # limit -- shown as a heads-up, not a confirmed number.
            style = T.SAFE if d.authority == "provider" else T.ATTENTION
            self.owner.app.call_from_thread(self.owner._set_hint, d.detail, style)
        else:
            self.owner.app.call_from_thread(
                self.owner._set_hint, d.detail + " (your responsibility to set it correctly)", T.ATTENTION)


class AddModelModal(ModalScreen):
    """Add a new model: preset -> base URL/key/model -> Detect -> save. Dismisses
    with a values dict (LLM_BASE_URL/LLM_API_KEY/LLM_MODEL/KRATOS_LLM_BACKEND +
    optional LLM_CONTEXT_WINDOW) or None."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        Binding("ctrl+d", "detect", "detect", show=True, priority=True),
        Binding("ctrl+s", "save", "save", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._ctx = _ContextField(self)
        self._backend = "openai_compatible"
        self._soft_ok = False

    def action_detect(self) -> None:
        self._detect()

    def action_save(self) -> None:
        self._save()

    @on(Input.Submitted)
    def _on_submit(self, event: Input.Submitted) -> None:
        self._save()

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-card"):
            yield Static(Text("Add a model", style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Select([(k, k) for k in _PRESETS], prompt="Provider preset…", id="add-preset", allow_blank=True)
            yield Input(placeholder="Base URL (e.g. http://127.0.0.1:11434/v1)", id="add-url")
            yield Input(placeholder="API key (use 'ollama' for local)", id="add-key", password=True)
            yield Input(placeholder="Model name / string (e.g. qwen2.5:7b)", id="add-model")
            yield Input(placeholder="Context window — Ctrl+D to detect, or type a number", id="add-window")
            yield Static("", id="add-hint")
            yield Static(Text("Tab move · Enter save · Ctrl+D detect · Esc back", style=T.TEXT_DIM), id="add-keys")

    def on_mount(self) -> None:
        self.query_one("#add-preset", Select).focus()

    def _set_hint(self, msg: str, style: str = T.TEXT_DIM) -> None:
        self.query_one("#add-hint", Static).update(Text(msg, style=style))

    def _set_window_value(self, value: str) -> None:
        self.query_one("#add-window", Input).value = value

    @on(Select.Changed, "#add-preset")
    def _preset(self, event: Select.Changed) -> None:
        if event.value is None or event.value == Select.BLANK:
            return
        url, backend = _PRESETS[event.value]
        self._backend = backend
        self.query_one("#add-url", Input).value = url
        self._soft_ok = False

    def _detect(self) -> None:
        url = self.query_one("#add-url", Input).value.strip()
        model = self.query_one("#add-model", Input).value.strip()
        if not url or not model:
            self._set_hint("Enter a base URL and model name first, then Ctrl+D to detect.", T.ATTENTION)
            return
        self._ctx.detect(url, self.query_one("#add-key", Input).value.strip(), model)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _save(self) -> None:
        url = self.query_one("#add-url", Input).value.strip()
        model = self.query_one("#add-model", Input).value.strip()
        if not url or not model:
            self._set_hint("Base URL and model name are required.", T.CRITICAL)
            return
        if not self.query_one("#add-key", Input).value.strip():
            self._set_hint("An API key is required — use 'ollama' for a local server that ignores it.", T.CRITICAL)
            return
        value, hard, soft = _validate_window(
            self.query_one("#add-window", Input).value, self._ctx.detected_max, self._ctx.detected_loaded)
        if hard:
            self._set_hint(hard, T.CRITICAL)
            return
        if soft and not self._soft_ok:
            self._set_hint(soft + "  —  press Enter again to confirm.", T.ATTENTION)
            self._soft_ok = True
            return
        values = {
            "LLM_BASE_URL": url,
            "LLM_API_KEY": self.query_one("#add-key", Input).value.strip(),
            "LLM_MODEL": model,
            "KRATOS_LLM_BACKEND": self._backend,
        }
        if value is not None:
            values["LLM_CONTEXT_WINDOW"] = str(value)
            source = self._ctx.source_for(value)
            if source:
                values["LLM_CONTEXT_SOURCE"] = source
        self.dismiss(values)


class EditWindowModal(ModalScreen):
    """Edit one profile's context window. Dismisses with {"window": int,
    "source": "provider"|"catalog"|None} (set; source None = user-typed), the
    string 'clear' (back to auto), or None (cancel)."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        Binding("ctrl+d", "detect", "detect", show=True, priority=True),
        Binding("ctrl+s", "save", "save", show=True),
    ]

    def __init__(self, profile_values: dict[str, str]) -> None:
        super().__init__()
        self._values = profile_values
        self._ctx = _ContextField(self)
        self._soft_ok = False

    def action_detect(self) -> None:
        self._detect()

    def action_save(self) -> None:
        self._save()

    @on(Input.Submitted)
    def _on_submit(self, event: Input.Submitted) -> None:
        self._save()

    def compose(self) -> ComposeResult:
        current = self._values.get("LLM_CONTEXT_WINDOW", "")
        with Vertical(classes="modal-card"):
            yield Static(Text(f"Context window — {self._values.get('LLM_MODEL', '')}",
                              style=f"bold {T.ACCENT}"), classes="modal-title")
            yield Static(Text("Empty = auto (detected when you switch to this model; safe default if it "
                              "can't be detected).", style=T.TEXT_DIM))
            yield Input(value=current, placeholder="tokens — Ctrl+D to detect, or empty for auto", id="edit-window",
                        select_on_focus=False)
            yield Static("", id="edit-hint")
            yield Static(Text("Enter save · Ctrl+D detect · Esc back", style=T.TEXT_DIM), id="edit-keys")

    def on_mount(self) -> None:
        self.query_one("#edit-window", Input).focus()

    def _set_hint(self, msg: str, style: str = T.TEXT_DIM) -> None:
        self.query_one("#edit-hint", Static).update(Text(msg, style=style))

    def _set_window_value(self, value: str) -> None:
        self.query_one("#edit-window", Input).value = value

    def _detect(self) -> None:
        self._ctx.detect(self._values.get("LLM_BASE_URL", ""), self._values.get("LLM_API_KEY", ""),
                         self._values.get("LLM_MODEL", ""))

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _save(self) -> None:
        raw = self.query_one("#edit-window", Input).value.strip()
        if not raw:
            self.dismiss("clear")
            return
        value, hard, soft = _validate_window(raw, self._ctx.detected_max, self._ctx.detected_loaded)
        if hard:
            self._set_hint(hard, T.CRITICAL)
            return
        if soft and not self._soft_ok:
            self._set_hint(soft + "  —  press Enter again to confirm.", T.ATTENTION)
            self._soft_ok = True
            return
        self.dismiss({"window": value, "source": self._ctx.source_for(value)})


class SettingsScreen(ResilientWorkerHost, Screen):
    """General settings hub. `session` is the SessionScreen underneath, reused
    for its cost/privacy blurb and footer refresh."""

    _TABS = ["tab-models", "tab-approvals", "tab-general"]

    BINDINGS = [
        Binding("escape,q", "close", "back", show=True),
        Binding("enter,space", "primary", "select", show=True),
        Binding("s", "switch", "switch", show=False),
        Binding("a", "add", "add model", show=False),
        Binding("e", "edit", "edit ctx", show=False),
        Binding("d", "delete", "delete model", show=False),
        Binding("u", "tz_auto", "tz auto", show=False),
        Binding("n", "set_name", "your name", show=False),
        Binding("t", "set_theme", "theme", show=False),
        Binding("v", "view_source", "view code", show=False),
        Binding("c", "edit_description", "edit desc", show=False),
        # Tab nav is on ctrl+arrows, NOT bare [ / ] -- a leaked '[' from a
        # fragmented mouse-reporting escape sequence (SGR motion events over a
        # laggy SSH link) would otherwise land on prev_tab and cycle tabs on its
        # own ("ghost" tab switching). Modifier-keyed bindings can't collide with
        # a stray printable bracket.
        Binding("ctrl+right", "next_tab", "next tab", show=True),
        Binding("ctrl+left", "prev_tab", "prev tab", show=False),
    ]

    CSS = f"""
    SettingsScreen {{ padding: 1 2; }}
    SettingsScreen #set-title {{ height: 1; text-style: bold; color: {T.ACCENT}; padding: 0 0 1 0; }}
    SettingsScreen DataTable {{ height: 1fr; }}
    SettingsScreen #ms-hint {{ height: auto; color: {T.TEXT_DIM}; padding: 1 0 0 0; }}
    SettingsScreen #ms-status {{ height: auto; color: {T.TEXT_MUTED}; }}
    SettingsScreen .set-placeholder {{ color: {T.TEXT_DIM}; padding: 1 0; }}
    """

    def __init__(self, session: Any = None, data_dir: Any = None, initial_tab: str = "tab-models") -> None:
        super().__init__()
        self._initial_tab = initial_tab
        self._bud_rows: list[tuple[str, str]] = []  # (kind, key) per Budget-tab row
        # `session` is the SessionScreen underneath when opened via /settings
        # (used for live footer/backend/name/tz updates). Opened from the home
        # screen (Ctrl+S / 's') there is no session -- `data_dir` is passed
        # directly and the session-live updates simply no-op. The Models / Tools
        # / General tabs are all global and work either way.
        self._session = session
        self._data_dir_direct = data_dir
        self._candidates: list = []
        self._current = None
        self._ap_names: list[tuple[str, bool]] = []  # (tool_name, is_kept) per ap-table row
        # General tab row order (↑↓ navigable)
        self._gen_rows = ["name", "theme", "timezone", "findings.accept_max_days", "findings.default_view",
                          "logs.seal_verify_interval_minutes", "logs.seal_copy_budget_mb",
                          "collect.enabled", "collect.start_budget_seconds", "collect.sync_sources",
                          "collect.sync_initial_hours", "collect.sync_max_lines", "collect.ttl",
                          "detect.lookback_hours", "detect.finding_window_hours", "detect.pass_budget_seconds",
                          "detect.max_events_per_pass", "detect.coverage_days",
                          "detect.alert_batch_seconds", "detect.watch.max_per_rule_minute",
                          "detect.watch.offline_minutes",
                          "hunt.max_hits", "hunt.scan_seconds", "hunt.scan_days", "hunt.snapshot_files",
                          "hunt.index_seconds", "hunt.auto_max_indicators",
                          "vulndb.max_age_days", "vulndb.epss_high",
                          "trace.enabled", "trace.max_result_bytes", "trace.store_prompts", "trace.otel_export",
                          "privacy.mask_mode", "privacy.local_model_hosts",
                          "serve.port", "serve.allow_non_loopback", "serve.allowed_hosts", "serve.max_parallel",
                          "serve.requests_per_hour", "serve.link_hosts", "subagent.tls.require"]
        self._session_rows = ["target", "seal", "name", "reset", "delete"]  # This session tab rows
        # The "This session" tab only exists when opened from a live session
        # (/settings) — from the home screen there's nothing session-scoped to act on.
        self._TABS = ["tab-models", "tab-approvals", "tab-general", "tab-budget"]
        if session is not None:
            self._TABS = self._TABS + ["tab-session"]

    def compose(self) -> ComposeResult:
        yield Static("Settings", id="set-title")
        with TabbedContent(initial=self._initial_tab if self._initial_tab in self._TABS else "tab-models"):
            with TabPane("Models", id="tab-models"):
                yield DataTable(id="ms-table", cursor_type="row", zebra_stripes=False)
                yield Static(
                    Text("↑↓ select · enter/s switch · a add · e edit context window · d delete\n"
                         "ctrl+→ next tab · esc back", style=T.TEXT_DIM),
                    id="ms-hint")
                yield Static("", id="ms-status")
            with TabPane("Tools", id="tab-approvals"):
                yield Static(
                    Text("Every tool Kratos can use. For tools you built with /evolve you can choose "
                         "whether they ask you before running, read their code, and edit their "
                         "description. Built-in tools can't be changed here.", style=T.TEXT_DIM),
                    classes="set-placeholder")
                yield DataTable(id="ap-table", cursor_type="row", zebra_stripes=False)
                yield Static(
                    Text("↑↓ select · enter/space ask first on/off (your tools) · v view code\n"
                         "c edit description (your tools) · ctrl+→ next tab · esc back", style=T.TEXT_DIM),
                    id="ap-hint")
                yield Static("", id="ap-status")
            with TabPane("General", id="tab-general"):
                yield DataTable(id="gen-table", cursor_type="row", zebra_stripes=False)
                yield Static(
                    Text("↑↓ select · enter change · n name · t theme · u timezone auto\n"
                         "ctrl+→ next tab · esc back", style=T.TEXT_DIM),
                    id="gen-hint")
                yield Static("", id="gen-status")
            with TabPane("Budget", id="tab-budget"):
                yield DataTable(id="bud-table", cursor_type="row", zebra_stripes=False)
                yield Static("", id="bud-detail")
                yield Static(
                    Text("↑↓ select · enter change / resume / edit price · ctrl+→ next tab · esc back\n"
                         "Costs are estimates from list prices; your provider's bill is the real one.",
                         style=T.TEXT_DIM),
                    id="bud-hint")
                yield Static("", id="bud-status")
            if self._session is not None:
                with TabPane("This session", id="tab-session"):
                    yield DataTable(id="sess-table", cursor_type="row", zebra_stripes=False)
                    yield Static(
                        Text("↑↓ select · enter act (closes settings, acts in the session)\n"
                             "ctrl+→ next tab · esc back", style=T.TEXT_DIM),
                        id="sess-hint")

    def on_mount(self) -> None:
        table = self.query_one("#ms-table", DataTable)
        table.add_columns(" ", "Model", "Where", "Context window")
        self._reload()
        ap = self.query_one("#ap-table", DataTable)
        ap.add_columns("Tool", "Kind", "Asks first", "What it does")
        self._reload_approvals()
        gen = self.query_one("#gen-table", DataTable)
        gen.add_columns("Setting", "Value")
        self._reload_general()
        bud = self.query_one("#bud-table", DataTable)
        bud.add_columns("Limit", "Value", "Today")
        self._reload_budget()
        if self._session is not None:
            sess = self.query_one("#sess-table", DataTable)
            sess.add_columns("Setting", "Value")
            self._reload_session()
        table.focus()  # so ↑↓ navigate immediately, no click needed
        if self._initial_tab == "tab-budget":
            self.call_after_refresh(bud.focus)

    def refresh_theme(self) -> None:
        """Called by KratosTUI.apply_theme_pack after a live pack switch: re-render
        this screen's dynamic content so its Text (built with T.ACCENT etc. at
        add-time) picks up the new palette. Frozen CSS title colors update on the
        next launch; the Textual widget chrome updated already via the theme flip."""
        self._reload()
        self._reload_approvals()
        self._reload_general()
        self._reload_budget()
        if self._session is not None:
            self._reload_session()

    def _table_width(self, table: DataTable) -> int:
        return table.size.width or max(self.app.size.width - 6, 40)

    def on_resize(self, event) -> None:
        # The tables fit their width; refit when it changes.
        self.call_after_refresh(self._reload)
        self.call_after_refresh(self._reload_approvals)

    def _active_tab(self) -> str:
        return self.query_one(TabbedContent).active

    @on(TabbedContent.TabActivated)
    def _focus_active_table(self, event: TabbedContent.TabActivated) -> None:
        # Keep keyboard focus on the table of whichever tab is active, so ↑↓ work
        # without a click after switching tabs.
        tab = self._active_tab()
        if tab == "tab-models":
            self.query_one("#ms-table", DataTable).focus()
        elif tab == "tab-approvals":
            self.query_one("#ap-table", DataTable).focus()
        elif tab == "tab-general":
            self.query_one("#gen-table", DataTable).focus()
        elif tab == "tab-budget":
            self.query_one("#bud-table", DataTable).focus()
        elif tab == "tab-session":
            self.query_one("#sess-table", DataTable).focus()

    # --- data ------------------------------------------------------------
    def _reload(self) -> None:
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH

        self._candidates, self._current = _p.list_candidate_profiles(ENV_FILE_PATH)
        table = self.query_one("#ms-table", DataTable)
        keep = table.cursor_row if table.row_count else None
        table.clear()
        if not self._candidates:
            self._set_status("No models configured yet — press 'a' to add one.", T.ATTENTION)
        rows, active_row = [], None
        for i, c in enumerate(self._candidates):
            active = self._current is not None and c.model == self._current.model
            if active:
                active_row = i
            rows.append([
                Text("●", style=T.SAFE) if active else Text(" "),
                Text(c.model, style=T.TEXT_BRIGHT if active else T.TEXT_MUTED),
                Text(R.profile_blurb(c.values, short=True), style=T.TEXT_DIM),
                Text(_window_label(c.values), style=T.TEXT_MUTED),
            ])
        # Fit the width the table has: a long model name or label used to push the
        # context-window column off-screen behind a sideways scroll.
        for row in fit_columns(rows, self._table_width(table), shrink=[(2, 14), (1, 18)],
                               headers=(" ", "Model", "Where", "Context window")):
            table.add_row(*row)
        row = keep if keep is not None and 0 <= keep < len(rows) else active_row
        if row is not None:
            table.move_cursor(row=row)  # start on the model in use

    def _selected_profile(self):
        if not self._candidates:
            return None
        idx = self.query_one("#ms-table", DataTable).cursor_row
        if idx is None or idx < 0 or idx >= len(self._candidates):
            return None
        return self._candidates[idx]

    def _set_status(self, msg: str, style: str | None = None) -> None:
        self.query_one("#ms-status", Static).update(Text(msg, style=style or T.TEXT_MUTED))

    # --- actions (keyboard-first; no buttons on this screen) -------------
    def action_close(self) -> None:
        # dismiss (not pop_screen) so a flow that opened Settings with
        # push_screen_wait (the first-schedule budget modal's "Edit") resumes.
        self.dismiss(None)

    def action_next_tab(self) -> None:
        tc = self.query_one(TabbedContent)
        tc.active = self._TABS[(self._TABS.index(tc.active) + 1) % len(self._TABS)]

    def action_prev_tab(self) -> None:
        tc = self.query_one(TabbedContent)
        tc.active = self._TABS[(self._TABS.index(tc.active) - 1) % len(self._TABS)]

    def action_switch(self) -> None:
        if self._active_tab() != "tab-models":
            return
        target = self._selected_profile()
        if target is None:
            return
        if self._current is not None and target.model == self._current.model:
            self._set_status(f"{target.model} is already active.")
            return
        self._do_switch(target)

    def action_add(self) -> None:
        if self._active_tab() != "tab-models":
            return
        self._add_flow()

    def action_edit(self) -> None:
        if self._active_tab() != "tab-models":
            return
        self._edit_flow()

    def action_delete(self) -> None:
        if self._active_tab() != "tab-models":
            return
        self._delete_flow()

    @on(DataTable.RowSelected, "#ms-table")
    def _row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_switch()

    def action_primary(self) -> None:
        tab = self._active_tab()
        if tab == "tab-models":
            self.action_switch()
        elif tab == "tab-approvals":
            self._toggle_approval()
        elif tab == "tab-general":
            self._general_primary()
        elif tab == "tab-budget":
            self._budget_primary()
        elif tab == "tab-session":
            self._session_primary()

    # --- Tool approvals tab (kept tools; built-ins read-only) ------------
    def _reload_approvals(self) -> None:
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

        from kratos.tui_mk2 import render as R

        meta = _read_metadata(KEPT_TOOLS_DIR)
        ap = self.query_one("#ap-table", DataTable)
        keep = ap.cursor_row if ap.row_count else None
        ap.clear()
        self._ap_names = []
        rows = []
        for name in sorted(TOOL_REGISTRY):
            tool = TOOL_REGISTRY[name]
            is_kept = name in meta
            rows.append([
                Text(name, style=T.TEXT_MUTED),
                Text("yours" if is_kept else "built-in", style=T.ACCENT if is_kept else T.TEXT_FAINTER),
                Text("yes" if tool.requires_approval else "no",
                     style=T.ATTENTION if tool.requires_approval else T.TEXT_DIM),
                Text(R.tool_description(tool, meta.get(name)), style=T.TEXT_DIM),
            ])
            self._ap_names.append((name, is_kept))
        for row in fit_columns(rows, self._table_width(ap), shrink=[(3, 20), (0, 18)],
                               headers=("Tool", "Kind", "Asks first", "What it does")):
            ap.add_row(*row)
        if keep is not None and 0 <= keep < len(rows):
            ap.move_cursor(row=keep)

    def _set_ap_status(self, msg: str, style: str | None = None) -> None:
        self.query_one("#ap-status", Static).update(Text(msg, style=style or T.TEXT_MUTED))

    def _toggle_approval(self) -> None:
        if self._active_tab() != "tab-approvals":
            return
        ap = self.query_one("#ap-table", DataTable)
        idx = ap.cursor_row
        if idx is None or not (0 <= idx < len(self._ap_names)):
            return
        name, is_kept = self._ap_names[idx]
        if not is_kept:
            self._set_ap_status(
                f"{name} is built into Kratos — whether it asks first is fixed, not changeable here.", T.ATTENTION)
            return
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import set_kept_tool_approval

        new_val = not TOOL_REGISTRY[name].requires_approval
        try:
            set_kept_tool_approval(name, new_val)
        except Exception as e:  # noqa: BLE001 -- surface, don't crash the screen
            self._set_ap_status(f"Couldn't update {name}: {e}", T.CRITICAL)
            return
        self._reload_approvals()
        ap.move_cursor(row=idx)
        self._set_ap_status(
            f"{name}: {'asks you before each run' if new_val else 'runs without asking'} — saved.", T.SAFE)

    @on(DataTable.RowSelected, "#ap-table")
    def _ap_row_selected(self, event: DataTable.RowSelected) -> None:
        self._toggle_approval()

    def _selected_ap(self) -> tuple[str, bool] | None:
        ap = self.query_one("#ap-table", DataTable)
        idx = ap.cursor_row
        if idx is None or not (0 <= idx < len(self._ap_names)):
            return None
        return self._ap_names[idx]

    def _tool_source(self, name: str, is_kept: bool) -> tuple[str, str, str | None]:
        """(code, title, error). Kept tools: read their real .py from
        kept_tools/; built-ins: inspect.getsource of the handler. Failure to
        resolve source returns an error string rather than raising."""
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

        if is_kept:
            meta = _read_metadata(KEPT_TOOLS_DIR)
            src = KEPT_TOOLS_DIR / (meta.get(name) or {}).get("source_file", f"{name}.py")
            try:
                return src.read_text(encoding="utf-8"), f"{name} — kept tool ({src.name})", None
            except OSError as e:  # noqa: BLE001
                return "", "", f"Couldn't read {src.name}: {e}"
        import inspect

        tool = TOOL_REGISTRY.get(name)
        try:
            return inspect.getsource(tool.handler), f"{name} — built-in tool", None
        except (OSError, TypeError) as e:
            return "", "", f"Couldn't read built-in source for {name}: {e}"

    def action_view_source(self) -> None:
        if self._active_tab() != "tab-approvals":
            return
        sel = self._selected_ap()
        if sel is None:
            return
        name, is_kept = sel
        code, title, err = self._tool_source(name, is_kept)
        if err:
            self._set_ap_status(err, T.ATTENTION)
            return
        from kratos.tui_mk2.modals import CodeModal

        self.app.push_screen(CodeModal(title, code))

    def action_edit_description(self) -> None:
        if self._active_tab() != "tab-approvals":
            return
        self._edit_description_flow()

    @work
    async def _edit_description_flow(self) -> None:
        sel = self._selected_ap()
        if sel is None:
            return
        name, is_kept = sel
        if not is_kept:
            self._set_ap_status(
                f"{name} is a built-in tool — its description comes from its code, not editable here.",
                T.ATTENTION)
            return
        from kratos.tui_mk2.modals import PromptModal
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata, set_kept_tool_description

        current = (_read_metadata(KEPT_TOOLS_DIR).get(name) or {}).get("description", "")
        answer = await self.app.push_screen_wait(
            PromptModal(f"Description — {name}", "Short 'what it does' (empty = clear back to the code's own)",
                        initial=current))
        if answer is None:
            return
        try:
            set_kept_tool_description(name, answer.strip())
        except Exception as e:  # noqa: BLE001
            self._set_ap_status(f"Couldn't save description: {e}", T.CRITICAL)
            return
        idx = self.query_one("#ap-table", DataTable).cursor_row
        self._reload_approvals()
        if idx is not None:
            self.query_one("#ap-table", DataTable).move_cursor(row=idx)
        self._set_ap_status(
            f"Description saved for {name}." if answer.strip() else f"Description cleared for {name}.", T.SAFE)

    # --- General tab (name / theme / timezone -- one navigable table) ----
    def _data_dir(self):
        return getattr(self._session, "_data_dir", None) or self._data_dir_direct

    def _tz_value(self) -> str:
        from kratos.utils import timeutil

        source, tz = timeutil.display_tz_status(self._data_dir())
        name = getattr(tz, "key", None) or timeutil.now_for_display("%Z", tz=tz)
        src_txt = {"override": "fixed override", "auto": "auto-detected", "fallback": "UTC fallback"}.get(source, source)
        return f"{name}  ({src_txt})"

    def _reload_general(self) -> None:
        """Rebuild the General tab's 3-row table (name / theme / timezone) with
        current values, preserving the cursor. One ↑↓-navigable table, like the
        Models and Tools tabs -- Enter acts on the highlighted row."""
        gen = self.query_one("#gen-table", DataTable)
        idx = gen.cursor_row
        gen.clear()
        name = self._current_user_name()
        gen.add_row(Text("Your name", style=T.TEXT_MUTED),
                    Text(name or "not set (messages show 'you>')", style=T.TEXT))
        gen.add_row(Text("Theme", style=T.TEXT_MUTED),
                    Text(T.pack_label(T.active_pack_name()), style=T.TEXT))
        gen.add_row(Text("Display timezone", style=T.TEXT_MUTED),
                    Text(self._tz_value(), style=T.TEXT))
        max_days, view = self._findings_settings()
        gen.add_row(Text("Longest risk acceptance", style=T.TEXT_MUTED),
                    Text(f"{max_days} days  (a risk you accept comes back after this)", style=T.TEXT))
        gen.add_row(Text("/findings shows first", style=T.TEXT_MUTED),
                    Text("open and verified findings" if view == "open_verified" else "everything", style=T.TEXT))
        interval, budget = self._logs_settings()
        gen.add_row(Text("Sealed-journal check, at most every", style=T.TEXT_MUTED),
                    Text(f"{interval} minutes  (after investigations of a sealed machine)", style=T.TEXT))
        gen.add_row(Text("Sealed-journal copy per check", style=T.TEXT_MUTED),
                    Text(f"{budget} MB  (newest files first; the rest next time)", style=T.TEXT))
        for key, label, tail in self._collection_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        for key, label, tail in self._detect_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        for key, label, tail in self._hunt_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        age, epss = self._vulndb_settings()
        gen.add_row(Text("Vulnerability data counts as old after", style=T.TEXT_MUTED),
                    Text(f"{age} days  (then results say: run `kratos vulndb-update`)", style=T.TEXT))
        gen.add_row(Text("Likely-exploited threshold (EPSS)", style=T.TEXT_MUTED),
                    Text(f"{epss:.0%}  (a serious fixable CVE at least this likely to be exploited is high)", style=T.TEXT))
        for key, label, tail in self._trace_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        for key, label, tail in self._privacy_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        for key, label, tail in self._serve_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        for key, label, tail in self._agent_link_rows():
            gen.add_row(Text(label, style=T.TEXT_MUTED), Text(tail, style=T.TEXT))
        if idx is not None and 0 <= idx < len(self._gen_rows):
            gen.move_cursor(row=idx)

    # --- Encrypted agent link (kratos.subagent.tls, C.4) ---
    def _plaintext_agents(self, dd: Any) -> list[str]:
        from kratos.storage.subagent_store import SubAgentStore

        return [t.get("name") or t.get("hostname") or t["target_id"]
                for t in SubAgentStore(dd / "kratos.db").list_targets(include_revoked=False)
                if t.get("link_mode") != "tls-pinned"]

    def _agent_link_rows(self) -> list[tuple[str, str, str]]:
        from kratos.subagent import tls as _tls

        dd = self._data_dir()
        if dd is None:
            return [(_tls.REQUIRE, "Agent link: require encryption", "unavailable here")]
        if _tls.require_encryption(dd):
            tail = "on  (agents without encryption are refused)"
        else:
            plain = self._plaintext_agents(dd)
            tail = ("off  (" + (f"{len(plain)} paired agent(s) not encrypted yet -- update them with g in /subagent)"
                                if plain else "every paired agent is encrypted -- you can turn this on)"))
        return [(_tls.REQUIRE, "Agent link: require encryption", tail)]

    @work
    async def _set_agent_link_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.subagent import tls as _tls
        from kratos.tui_mk2.modals import ConfirmModal, ListPickerModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        value = await self.app.push_screen_wait(ListPickerModal("Agent link: require encryption", [
            ("off", "off — agents without encryption still connect (while you update them)"),
            ("on", "on — refuse any agent that connects without encryption")]))
        if value is None:
            return
        if value == "on":
            plain = self._plaintext_agents(dd)
            if plain:
                names = ", ".join(plain[:5]) + (f" and {len(plain) - 5} more" if len(plain) > 5 else "")
                ok = await self.app.push_screen_wait(ConfirmModal(
                    "Refuse agents that aren't encrypted yet?",
                    f"These paired agents haven't connected with encryption yet: {names}. They will be refused "
                    "(\"update the agent\") until you update each one (/subagent, select it, press g).",
                    yes_label="turn it on", no_label="keep it off"))
                if not ok:
                    return
        try:
            settings_store.set(_tls.REQUIRE, value, data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved -- the listener applies it to the next agent that connects.", T.SAFE)

    # --- Run records (kratos.trace) ---
    def _trace_rows(self) -> list[tuple[str, str, str]]:
        from kratos import settings_store
        from kratos.trace import settings as TS

        dd = self._data_dir()
        if dd is None:
            return [(k, k, "unavailable here") for k in self._gen_rows if k.startswith("trace.")]
        get = lambda k: settings_store.get(k, data_dir=dd)  # noqa: E731
        return [
            (TS.ENABLED, "Run records", "on  (each run's model calls, tools and answer; /trace)" if get(TS.ENABLED)
             else "off  (measurement only — no record of what runs did)"),
            (TS.MAX_RESULT_BYTES, "Most of one tool result kept", f"{get(TS.MAX_RESULT_BYTES) // 1024:,} KB  "
             "(larger: the start + a fingerprint)"),
            (TS.STORE_PROMPTS, "Keep the text sent to the model", "on  (large; for debugging)" if get(TS.STORE_PROMPTS)
             else "off  (sizes only)"),
            (TS.OTEL_EXPORT, "Copy to your OpenTelemetry collector",
             "on  (timings and token counts only, to OTEL_EXPORTER_OTLP_ENDPOINT)" if get(TS.OTEL_EXPORT)
             else "off  (nothing leaves this computer)"),
        ]

    # --- What the model sees (kratos.privacy) ---
    def _privacy_rows(self) -> list[tuple[str, str, str]]:
        from kratos import settings_store
        from kratos.privacy import mode as PM

        dd = self._data_dir()
        if dd is None:
            return [(k, k, "unavailable here") for k in self._gen_rows if k.startswith("privacy.")]
        chosen = settings_store.get(PM.MODE_KEY, data_dir=dd)
        hosts = settings_store.get(PM.LOCAL_HOSTS_KEY, data_dir=dd)
        return [
            (PM.MODE_KEY, "What the model sees", f"{chosen}  — {PM.describe_mode(data_dir=dd)}"),
            (PM.LOCAL_HOSTS_KEY, "Your own model machines", ", ".join(hosts) if hosts
             else "none  (only this machine counts as local)"),
        ]

    # --- Chat-client server (kratos serve) ---
    _SERVE_LABELS = {
        "serve.port": "Chat server port",
        "serve.allow_non_loopback": "Chat server may listen beyond this machine",
        "serve.allowed_hosts": "Chat server: extra Host names",
        "serve.max_parallel": "Chat server: investigations at once",
        "serve.requests_per_hour": "Chat server: messages per token per hour",
        "serve.link_hosts": "Chat answers: clickable link sites",
    }

    def _serve_rows(self) -> list[tuple[str, str, str]]:
        from kratos import settings_store
        from kratos.serve import settings as SS  # noqa: F401 -- registers serve.*

        dd = self._data_dir()
        keys = [k for k in self._gen_rows if k.startswith("serve.")]
        if dd is None:
            return [(k, self._SERVE_LABELS[k], "unavailable here") for k in keys]
        out = []
        for k in keys:
            v = settings_store.get(k, data_dir=dd)
            if isinstance(v, bool):
                tail = ("yes  (with --host; use a TLS reverse proxy)" if v
                        else "no  (127.0.0.1 only)") if k == SS.ALLOW_NON_LOOPBACK else ("yes" if v else "no")
            elif isinstance(v, list):
                tail = ", ".join(v) if v else ("none  (every link shown as text)" if k == SS.LINK_HOSTS else "none")
            else:
                tail = str(v)
            out.append((k, self._SERVE_LABELS[k], tail))
        return out

    @work
    async def _set_serve_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.tui_mk2.modals import ListPickerModal, PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        spec = next((sp for sp in settings_store.specs() if sp.key == key), None)
        if spec is None:
            return
        current = settings_store.get(key, data_dir=dd)
        if isinstance(current, bool):
            value = await self.app.push_screen_wait(ListPickerModal(self._SERVE_LABELS.get(key, key), [
                ("no", "no"), ("yes", "yes")]))
        else:
            shown = ", ".join(current) if isinstance(current, list) else str(current)
            value = await self.app.push_screen_wait(PromptModal(self._SERVE_LABELS.get(key, key), spec.doc,
                                                                initial=shown))
        if value is None:
            return
        try:
            settings_store.set(key, value, data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved -- the chat server reads it on the next request (the port on its next start).",
                             T.SAFE)

    @work
    async def _set_privacy_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.privacy import mode as PM
        from kratos.tui_mk2.modals import ListPickerModal, PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        if key == PM.MODE_KEY:
            value = await self.app.push_screen_wait(ListPickerModal(
                "What the model sees", [
                    ("auto", "auto — masked for a hosted model, not for one on your own machine"),
                    ("standard", "standard — names, machines, addresses and emails replaced with placeholders"),
                    ("strict", "strict — also short names, image logins and attackers' guesses"),
                    ("off", "off — sent as they are")]))
        else:
            current = ", ".join(settings_store.get(key, data_dir=dd))
            value = await self.app.push_screen_wait(PromptModal(
                "Your own model machines", "Host names or addresses, separated by commas (empty: none).",
                initial=current))
        if value is None:
            return
        try:
            settings_store.set(key, value, data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — " + PM.describe_mode(data_dir=dd) + ".", T.SAFE)

    @work
    async def _set_trace_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.trace import settings as TS
        from kratos.tui_mk2.modals import ListPickerModal, PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        spec = next((sp for sp in settings_store.specs() if sp.key == key), None)
        if spec is None:
            return
        if key == TS.MAX_RESULT_BYTES:
            answer = await self.app.push_screen_wait(PromptModal(spec.doc, "Bytes (1024 - 67108864)",
                                                                 initial=str(settings_store.get(key, data_dir=dd))))
            if answer is None:
                return
            value: Any = answer.strip()
        else:
            value = await self.app.push_screen_wait(ListPickerModal(spec.doc, [("on", "on"), ("off", "off")]))
            if value is None:
                return
        try:
            settings_store.set(key, value, data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — applies from the next run.", T.SAFE)

    # --- Package vulnerabilities (kratos.pkgvuln): how old the data may get, what counts as likely exploited ---
    def _vulndb_settings(self) -> tuple[Any, Any]:
        from kratos import settings_store
        from kratos.pkgvuln import settings as VS

        dd = self._data_dir()
        if dd is None:
            return 7, 0.1
        return settings_store.get(VS.MAX_AGE_DAYS, data_dir=dd), settings_store.get(VS.EPSS_HIGH, data_dir=dd)

    @work
    async def _set_vulndb_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.pkgvuln import settings as VS
        from kratos.tui_mk2.modals import PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        age, epss = self._vulndb_settings()
        title, hint, current = (("Vulnerability data counts as old after (days)", "1-365.", str(age))
                                if key == VS.MAX_AGE_DAYS else
                                ("Likely-exploited threshold", "A chance between 0 and 1, or a percentage "
                                 "(10% = 0.1, the commonly used EPSS threshold).", f"{epss:g}"))
        answer = await self.app.push_screen_wait(PromptModal(title, hint, initial=current))
        if answer is None:
            return
        try:
            settings_store.set(key, answer.strip(), data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — used from the next package check.", T.SAFE)

    # --- Collection (kratos.collect): what Kratos checks by itself before an investigation ---
    def _collection_rows(self) -> list[tuple[str, str, str]]:
        from kratos import settings_store
        from kratos.collect import checks as _checks  # noqa: F401 -- registers the checks and their settings
        from kratos.collect import registry
        from kratos.collect import settings as CS
        from kratos.collect.sync import settings as SS

        dd = self._data_dir()
        if dd is None:
            return [(k, k, "unavailable here") for k in self._gen_rows if k.startswith("collect.")]
        get = lambda k: settings_store.get(k, data_dir=dd)  # noqa: E731
        ttls = ", ".join(f"{c.short or c.label} {get(c.ttl_setting)}" for c in registry.checks("quick"))
        return [
            (CS.ENABLED, "Check the basics first", "on" if get(CS.ENABLED) else "off  (the model decides what to look at)"),
            (CS.START_BUDGET, "Most time spent checking first", f"{get(CS.START_BUDGET)} seconds  (the rest is reported as not checked)"),
            (SS.SOURCES, "Logs kept up to date", ", ".join(get(SS.SOURCES)) or "none"),
            (SS.INITIAL_HOURS, "First sync reaches back", f"{get(SS.INITIAL_HOURS)} hours"),
            (SS.MAX_LINES, "Most lines per log per round", f"{get(SS.MAX_LINES):,}"),
            ("collect.ttl", "Results stay fresh (minutes)", ttls),
        ]

    # --- Detection rules (kratos.detect, C.1) ---
    def _detect_rows(self) -> list[tuple[str, str, str]]:
        from kratos import settings_store
        from kratos.detect import settings as DS

        dd = self._data_dir()
        if dd is None:
            return [(k, k, "unavailable here") for k in self._gen_rows if k.startswith("detect.")]
        get = lambda k: settings_store.get(k, data_dir=dd)  # noqa: E731
        return [
            (DS.LOOKBACK_HOURS, "Detection rules: a new rule pack looks back", f"{get(DS.LOOKBACK_HOURS)} hours"),
            (DS.FINDING_WINDOW_HOURS, "Detection rules: a match stays open for",
             f"{get(DS.FINDING_WINDOW_HOURS)} hours without a new one"),
            (DS.PASS_BUDGET, "Detection rules: most time per machine", f"{get(DS.PASS_BUDGET)} seconds a pass"),
            (DS.MAX_EVENTS, "Detection rules: most log events per pass", f"{get(DS.MAX_EVENTS):,}"),
            (DS.COVERAGE_DAYS, "Detection rules: a log counts as collected if seen in",
             f"the last {get(DS.COVERAGE_DAYS)} days"),
            # C.2: continuous detection on agents
            (DS.ALERT_BATCH_SECONDS, "Continuous detection: live matches within this become one alert",
             f"{get(DS.ALERT_BATCH_SECONDS)} seconds"),
            (DS.WATCH_PER_RULE_MINUTE, "Continuous detection: matches of one rule sent a minute",
             f"{get(DS.WATCH_PER_RULE_MINUTE)}, then one summary"),
            (DS.WATCH_OFFLINE_MINUTES, "Continuous detection: say it isn't running after the link is down",
             f"{get(DS.WATCH_OFFLINE_MINUTES)} minutes"),
        ]

    # --- Hunting (kratos.hunt, C.3) ---
    def _hunt_rows(self) -> list[tuple[str, str, str]]:
        from kratos import settings_store
        from kratos.hunt import settings as HS

        dd = self._data_dir()
        if dd is None:
            return [(k, k, "unavailable here") for k in self._gen_rows if k.startswith("hunt.")]
        get = lambda k: settings_store.get(k, data_dir=dd)  # noqa: E731
        return [
            (HS.MAX_HITS, "Hunting: most matches listed", f"{get(HS.MAX_HITS)} (past it: counts and a hint to narrow)"),
            (HS.SCAN_SECONDS, "Hunting: most time searching log text", f"{get(HS.SCAN_SECONDS)} seconds a hunt"),
            (HS.SCAN_DAYS, "Hunting: log text searched back", f"{get(HS.SCAN_DAYS)} days (typed fields: everything)"),
            (HS.SNAPSHOT_FILES, "Hunting: saved reads searched per machine", f"{get(HS.SNAPSHOT_FILES)}, newest first"),
            (HS.INDEX_SECONDS, "Hunting: indexing older events before a hunt", f"{get(HS.INDEX_SECONDS)} seconds"),
            (HS.AUTO_MAX_INDICATORS, "Hunting: new malicious addresses hunted per intel update",
             f"{get(HS.AUTO_MAX_INDICATORS)}"),
        ]

    @work
    async def _set_detect_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.detect import settings as _DS  # noqa: F401 -- registers the detect.* settings
        from kratos.hunt import settings as _HS  # noqa: F401 -- and the hunt.* settings (same editor)
        from kratos.tui_mk2.modals import PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        spec = next((sp for sp in settings_store.specs() if sp.key == key), None)
        if spec is None:
            return
        answer = await self.app.push_screen_wait(PromptModal(spec.doc, "Enter the new value",
                                                             initial=str(settings_store.get(key, data_dir=dd))))
        if answer is None:
            return
        try:
            settings_store.set(key, answer.strip(), data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — applies on the next detection pass"
                             + (" and is sent to watching agents within seconds." if key.startswith("detect.watch.")
                                else "."), T.SAFE)

    @work
    async def _set_collect_setting_flow(self, key: str) -> None:
        from kratos import settings_store
        from kratos.collect import checks as _checks  # noqa: F401
        from kratos.collect import registry
        from kratos.collect.sync import settings as SS  # noqa: F401
        from kratos.tui_mk2.modals import ListPickerModal, PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        if key == "collect.ttl":
            key = await self.app.push_screen_wait(ListPickerModal(
                "Which result?", [(c.ttl_setting, f"{c.label} — now {settings_store.get(c.ttl_setting, data_dir=dd)} min")
                                  for c in registry.checks()]))
            if key is None:
                return
        spec = next((sp for sp in settings_store.specs() if sp.key == key), None)
        if spec is None:
            return
        current = settings_store.get(key, data_dir=dd)
        if key == "collect.enabled":
            value: Any = await self.app.push_screen_wait(ListPickerModal(
                "Check the basics first", [("on", "on — ports, sign-ins, altered logs, ... before the model starts"),
                                           ("off", "off — the model decides what to look at")]))
            if value is None:
                return
        else:
            shown = ", ".join(current) if isinstance(current, list) else str(current)
            answer = await self.app.push_screen_wait(PromptModal(spec.doc, "Enter the new value", initial=shown))
            if answer is None:
                return
            value = answer.strip()
        try:
            settings_store.set(key, value, data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — applies everywhere on the next read.", T.SAFE)

    def _general_primary(self) -> None:
        """Enter on the General tab acts on the highlighted setting."""
        idx = self.query_one("#gen-table", DataTable).cursor_row
        key = self._gen_rows[idx] if idx is not None and 0 <= idx < len(self._gen_rows) else None
        if key == "name":
            self._set_name_flow()
        elif key == "theme":
            self._set_theme_flow()
        elif key == "timezone":
            self._set_timezone_flow()
        elif key and key.startswith("findings."):
            self._set_findings_setting_flow(key)
        elif key and key.startswith("logs."):
            self._set_logs_setting_flow(key)
        elif key and key.startswith("collect."):
            self._set_collect_setting_flow(key)
        elif key and key.startswith(("detect.", "hunt.")):
            self._set_detect_setting_flow(key)
        elif key and key.startswith("vulndb."):
            self._set_vulndb_setting_flow(key)
        elif key and key.startswith("trace."):
            self._set_trace_setting_flow(key)
        elif key and key.startswith("privacy."):
            self._set_privacy_setting_flow(key)
        elif key and key.startswith("serve."):
            self._set_serve_setting_flow(key)
        elif key == "subagent.tls.require":
            self._set_agent_link_setting_flow(key)

    def _logs_settings(self) -> tuple[Any, Any]:
        from kratos import settings_store
        from kratos.logsources import seal as SEAL

        dd = self._data_dir()
        if dd is None:
            return 60, 256
        return (settings_store.get(SEAL.SEAL_INTERVAL_KEY, data_dir=dd),
                settings_store.get(SEAL.SEAL_BUDGET_KEY, data_dir=dd))

    @work
    async def _set_logs_setting_flow(self, key: str) -> None:
        """A journal-sealing setting (kratos.logsources.seal), saved in app_settings."""
        from kratos import settings_store
        from kratos.logsources import seal as SEAL
        from kratos.tui_mk2.modals import PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        interval, budget = self._logs_settings()
        title, hint, current = ((("Sealed-journal check interval (minutes)", "5-10080: the least time between two "
                                  "background checks of the same machine.", interval))
                                if key == SEAL.SEAL_INTERVAL_KEY else
                                ("Sealed-journal copy per check (MB)", "16-8192: how much journal one check copies "
                                 "from the machine; older files wait for the next check.", budget))
        answer = await self.app.push_screen_wait(PromptModal(title, hint, initial=str(current)))
        if answer is None:
            return
        try:
            settings_store.set(key, answer.strip(), data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — applies everywhere on the next read.", T.SAFE)

    def _findings_settings(self) -> tuple[Any, Any]:
        from kratos import settings_store
        from kratos.lifecycle import settings as LS

        dd = self._data_dir()
        if dd is None:
            return 180, "open_verified"
        return (settings_store.get(LS.ACCEPT_MAX_DAYS, data_dir=dd),
                settings_store.get(LS.DEFAULT_VIEW, data_dir=dd))

    @work
    async def _set_findings_setting_flow(self, key: str) -> None:
        """A finding-lifecycle setting (kratos.lifecycle.settings), saved in
        app_settings as this person ("tui:settings")."""
        from kratos import settings_store
        from kratos.lifecycle import settings as LS
        from kratos.tui_mk2.modals import ListPickerModal, PromptModal

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save this.", T.CRITICAL)
            return
        max_days, view = self._findings_settings()
        if key == LS.ACCEPT_MAX_DAYS:
            answer = await self.app.push_screen_wait(PromptModal(
                "Longest risk acceptance (days)",
                "1-365. Accepting a risk always needs an end date, at most this far ahead.", initial=str(max_days)))
            if answer is None:
                return
            value: Any = answer.strip()
        else:
            value = await self.app.push_screen_wait(ListPickerModal(
                "/findings shows first", [("open_verified", "open and verified findings (decided ones counted)"),
                                          ("all", "everything")]))
            if value is None:
                return
        try:
            settings_store.set(key, value, data_dir=dd, actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_gen_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_general()
        self._set_gen_status("Saved — applies everywhere on the next read.", T.SAFE)

    @on(DataTable.RowSelected, "#gen-table")
    def _gen_row_selected(self, event: DataTable.RowSelected) -> None:
        self._general_primary()

    # --- Budget tab (kratos.budget: spending limits, paused sources, prices) --
    _BUDGET_LABELS = {
        "budget.daily_cost_usd": "Daily budget, everything",
        "budget.unattended_daily_cost_usd": "Daily budget, unattended runs",
        "budget.daily_tokens": "Daily tokens, local/unpriced models",
        "budget.run_model_calls": "Model calls per run",
        "budget.run_tokens": "Tokens per run",
        "budget.trigger_fires_per_day": "Fires per trigger per day",
        "budget.trigger_investigations_allowed": "Triggers may start investigations",
        "budget.soft_limit_percent": "Warn when a limit is this full",
        "budget.breaker_failures": "Pause unattended runs after failures",
        "budget.breaker_window_minutes": "... counted within (minutes)",
        "budget.breaker_pause_minutes": "Pause length (minutes)",
    }

    def _budget_value(self, key: str, value: Any) -> str:
        from kratos.budget import limits as BL

        if key in (BL.DAILY_COST, BL.UNATTENDED_DAILY_COST):
            return f"${value:,.2f}" if value == 0 or value >= 0.01 else f"${value:,.4f}"
        if key == BL.TRIGGER_INVESTIGATIONS:
            return "on" if value else "off"
        if key == BL.SOFT_PERCENT:
            return f"{value}%"
        return f"{value:,}"

    def _reload_budget(self) -> None:
        """Every budget.* limit with today's spend against it, then paused
        sources (Enter resumes) and the price table (Enter edits)."""
        from kratos import settings_store
        from kratos.budget import limits as BL
        from kratos.budget import pricing, report

        table = self.query_one("#bud-table", DataTable)
        keep = table.cursor_row if table.row_count else 0
        table.clear()
        self._bud_rows = []
        dd = self._data_dir()
        if dd is None:
            table.add_row(Text("No data folder — budget settings unavailable here.", style=T.TEXT_DIM), "", "")
            self._bud_rows.append(("none", ""))
            return
        today = report.today(dd)
        spent = {sc.scope: sc for sc in today.scopes}
        today_col = {
            BL.DAILY_COST: spent[BL.SCOPE_DAILY_COST],
            BL.UNATTENDED_DAILY_COST: spent[BL.SCOPE_UNATTENDED_COST],
            BL.DAILY_TOKENS: spent[BL.SCOPE_DAILY_TOKENS],
        }
        for key in BL.KEYS:
            value = settings_store.get(key, data_dir=dd)
            used = today_col.get(key)
            if used is not None:
                style = T.CRITICAL if used.share >= 1.0 else (T.ATTENTION if used.share >= report.NEAR_SHARE else T.TEXT_MUTED)
                today_txt = Text(f"used {used.text}", style=style)
            else:
                today_txt = Text("")
            table.add_row(Text(self._BUDGET_LABELS.get(key, key), style=T.TEXT_MUTED),
                          Text(self._budget_value(key, value), style=T.TEXT), today_txt)
            self._bud_rows.append(("limit", key))
        table.add_row(Text("Paused sources", style=f"bold {T.TEXT_BRIGHT}"), "", "")
        self._bud_rows.append(("header", ""))
        if today.pauses:
            from kratos.utils import timeutil

            for p in today.pauses:
                until = timeutil.format_for_display(timeutil.epoch_to_utc_iso(p["until"]), "%H:%M", data_dir=dd)
                table.add_row(Text(f"  {p['key']}", style=T.ATTENTION), Text(f"paused until {until}", style=T.TEXT),
                              Text("enter = resume now", style=T.TEXT_DIM))
                self._bud_rows.append(("pause", p["key"]))
        else:
            table.add_row(Text("  none", style=T.TEXT_DIM), "", "")
            self._bud_rows.append(("header", ""))
        table.add_row(Text("Prices (USD per 1M tokens, in / out)", style=f"bold {T.TEXT_BRIGHT}"), "", "")
        self._bud_rows.append(("header", ""))
        for model, (rin, rout) in sorted(pricing.rates(dd).items()):
            table.add_row(Text(f"  {model}", style=T.TEXT_MUTED), Text(f"${rin:g} / ${rout:g}", style=T.TEXT),
                          Text("enter = edit", style=T.TEXT_DIM))
            self._bud_rows.append(("rate", model))
        table.add_row(Text("  + add a model's price", style=T.ACCENT), "", "")
        self._bud_rows.append(("rate_add", ""))
        if 0 <= keep < len(self._bud_rows):
            table.move_cursor(row=keep)
        self._show_budget_detail()

    def _selected_budget_row(self) -> tuple[str, str]:
        idx = self.query_one("#bud-table", DataTable).cursor_row
        if idx is None or not 0 <= idx < len(self._bud_rows):
            return ("none", "")
        return self._bud_rows[idx]

    def _show_budget_detail(self) -> None:
        from kratos import settings_store

        kind, key = self._selected_budget_row()
        if kind == "limit":
            doc = next((sp.doc for sp in settings_store.specs() if sp.key == key), "")
            text = f"{doc}  ({key})"
        elif kind == "pause":
            text = "Paused after repeated failed or looping runs. Enter resumes it now."
        elif kind in ("rate", "rate_add"):
            text = ("Used to estimate costs (not your bill). A model with no price still has its token limits; "
                    "a provider-reported cost is used when the response includes one.")
        else:
            text = ""
        self.query_one("#bud-detail", Static).update(Text(text, style=T.TEXT_DIM))

    @on(DataTable.RowHighlighted, "#bud-table")
    def _bud_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._show_budget_detail()

    @on(DataTable.RowSelected, "#bud-table")
    def _bud_row_selected(self, event: DataTable.RowSelected) -> None:
        self._budget_primary()

    def _set_bud_status(self, msg: str, style: str | None = None) -> None:
        self.query_one("#bud-status", Static).update(Text(msg, style=style or T.TEXT_MUTED))

    def _budget_primary(self) -> None:
        kind, key = self._selected_budget_row()
        if kind == "limit":
            self._set_budget_limit_flow(key)
        elif kind == "pause":
            self._resume_pause_flow(key)
        elif kind == "rate":
            self._edit_rate_flow(key)
        elif kind == "rate_add":
            self._edit_rate_flow(None)

    @work
    async def _set_budget_limit_flow(self, key: str) -> None:
        """Change one budget.* limit -- validated by the setting itself, recorded
        as this person (tui:settings); applies from the next model call."""
        from kratos import settings_store
        from kratos.budget import limits as BL
        from kratos.tui_mk2.modals import ListPickerModal, PromptModal

        dd = self._data_dir()
        if dd is None:
            return
        current = settings_store.get(key, data_dir=dd)
        label = self._BUDGET_LABELS.get(key, key)
        if key == BL.TRIGGER_INVESTIGATIONS:
            answer = await self.app.push_screen_wait(ListPickerModal(label, [
                ("off", "off — triggers only notify (no model spending)"),
                ("on", "on — a trigger may start a read-only investigation (spends model money, unattended)")]))
        else:
            doc = next((sp.doc for sp in settings_store.specs() if sp.key == key), "")
            hint = doc + (" 0 means none allowed; there is no 'unlimited' — set a large number on purpose."
                          if key != BL.SOFT_PERCENT else "")
            answer = await self.app.push_screen_wait(PromptModal(label, hint, initial=str(current)))
        if answer is None:
            return
        try:
            settings_store.set(key, answer.strip() if isinstance(answer, str) else answer, data_dir=dd,
                               actor="tui:settings")
        except settings_store.SettingError as e:
            self._set_bud_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_budget()
        self._set_bud_status("Saved — applies to the next model call, in every Kratos process.", T.SAFE)

    @work
    async def _resume_pause_flow(self, key: str) -> None:
        from kratos.budget import breaker
        from kratos.tui_mk2.modals import ConfirmModal

        dd = self._data_dir()
        if dd is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Resume now?", f"Let {key} runs use the model again before the pause ends? If whatever kept failing "
            "isn't fixed, it may pause again.", yes_label="resume", no_label="keep paused"))
        if not ok:
            return
        if breaker.resume(dd, key, actor="tui:settings"):
            self._set_bud_status(f"Resumed {key}.", T.SAFE)
        else:
            self._set_bud_status(f"{key} wasn't paused any more.", T.TEXT_MUTED)
        self._reload_budget()

    @work
    async def _edit_rate_flow(self, model: str | None) -> None:
        """Add or correct a model's price (USD per 1M tokens), or remove it."""
        from kratos import settings_store
        from kratos.budget import pricing
        from kratos.tui_mk2.modals import PromptModal

        dd = self._data_dir()
        if dd is None:
            return
        if model is None:
            from kratos.llm_config import get_active_llm_model

            model = await self.app.push_screen_wait(PromptModal(
                "Model name", "Exactly as your provider names it (as in /model).", initial=get_active_llm_model()))
            if not model or not model.strip():
                return
            model = model.strip()
        current = pricing.rates(dd).get(model)
        answer = await self.app.push_screen_wait(PromptModal(
            f"Price for {model}", "Input, output — US dollars per 1M tokens, e.g. 0.10, 0.40. "
            "Type 'remove' to delete this price.",
            initial=f"{current[0]:g}, {current[1]:g}" if current else ""))
        if answer is None:
            return
        try:
            if answer.strip().lower() == "remove":
                pricing.remove_rate(dd, model, actor="tui:settings")
                self._set_bud_status(f"Removed the price for {model}; its token limits still apply.", T.SAFE)
            else:
                parts = [p.strip().lstrip("$") for p in answer.replace("/", ",").split(",")]
                if len(parts) != 2:
                    raise settings_store.SettingError("give two prices: input, output")
                pricing.set_rate(dd, model, parts[0], parts[1], actor="tui:settings")
                self._set_bud_status(f"Saved the price for {model}.", T.SAFE)
        except settings_store.SettingError as e:
            self._set_bud_status(f"Not changed: {e}", T.CRITICAL)
            return
        self._reload_budget()

    # --- This session tab (session-scoped; only present with a session) --
    def _session_name(self) -> str:
        st = getattr(self._session, "session_state", {}) or {}
        sid = st.get("session_id")
        store = getattr(self._session, "_store", None)
        if store is None or not sid:
            return ""
        try:
            return (store.get_session(sid) or {}).get("name") or ""
        except Exception:  # noqa: BLE001 -- a missing/odd row shouldn't break the tab
            return ""

    def _reload_session(self) -> None:
        """Rebuild the 'This session' table (target / name / reset / delete)
        with current values. Defensive: tolerates a minimal session stub."""
        if self._session is None:
            return
        tbl = self.query_one("#sess-table", DataTable)
        idx = tbl.cursor_row
        tbl.clear()
        st = getattr(self._session, "session_state", {}) or {}
        targets = ", ".join(st.get("targets") or []) or "(none set)"
        name = self._session_name() or "(unnamed)"
        tbl.add_row(Text("Target", style=T.TEXT_MUTED), Text(targets, style=T.TEXT))
        tbl.add_row(Text("Log sealing", style=T.TEXT_MUTED), Text(self._seal_value(st), style=T.TEXT))
        tbl.add_row(Text("Session name", style=T.TEXT_MUTED), Text(name, style=T.TEXT))
        tbl.add_row(Text("Reset session", style=T.TEXT_MUTED),
                    Text("wipe screen + archive history, start fresh", style=T.TEXT_DIM))
        tbl.add_row(Text("Delete session", style=T.TEXT_MUTED),
                    Text("archive (soft-delete), back to the picker", style=T.TEXT_DIM))
        if idx is not None and 0 <= idx < len(self._session_rows):
            tbl.move_cursor(row=idx)

    def _seal_value(self, st: dict[str, Any]) -> str:
        from kratos.logsources import seal as SEAL

        dd, targets = self._data_dir(), st.get("targets") or []
        if dd is None or not targets:
            return "-"
        if not SEAL.has_key(dd, targets[0]):
            return "not set up  (Enter: set up -- recommended)"
        last = SEAL.latest_summary(dd, targets[0]) or {}
        return f"key on file, last check: {last.get('status', 'not yet')}  (Enter: replace / verify now / remove)"

    def _session_primary(self) -> None:
        idx = self.query_one("#sess-table", DataTable).cursor_row
        key = self._session_rows[idx] if idx is not None and 0 <= idx < len(self._session_rows) else None
        if key:
            self._run_session_action(key)

    def _run_session_action(self, key: str) -> None:
        """Session actions live on the SessionScreen and push their own modals /
        navigate (delete pops back to the picker). Running them while Settings
        sits ON TOP of the session would pop the wrong screen, so close Settings
        FIRST, then run the action back in the session — where it belongs."""
        session = self._session
        if session is None:
            return
        self.app.pop_screen()  # close Settings -> the session is active again
        if key == "target":
            session._target_flow("")
        elif key == "seal":
            session._seal_menu_flow()
        elif key == "name":
            session._rename_flow("")
        elif key == "reset":
            session._reset_flow()
        elif key == "delete":
            session._delete_flow()

    @on(DataTable.RowSelected, "#sess-table")
    def _sess_row_selected(self, event: DataTable.RowSelected) -> None:
        self._session_primary()

    def _set_gen_status(self, msg: str, style: str | None = None) -> None:
        self.query_one("#gen-status", Static).update(Text(msg, style=style or T.TEXT_MUTED))

    def _apply_tz_to_session(self) -> None:
        fn = getattr(self._session, "_apply_timezone_change", None)
        if callable(fn):
            fn()  # re-resolve the live session's display zone + refresh its header

    @work
    async def _set_timezone_flow(self) -> None:
        if self._active_tab() != "tab-general":
            return
        from kratos.tui_mk2.modals import PromptModal
        from kratos.utils import timeutil

        answer = await self.app.push_screen_wait(
            PromptModal("Set display timezone", "e.g. Asia/Dhaka, Europe/Helsinki, UTC (empty = cancel)"))
        if not answer or not answer.strip():
            return
        zone = answer.strip()
        if timeutil.zone_from_name(zone) is None:
            self._set_gen_status(f"{zone!r} isn't a known timezone.", T.CRITICAL)
            return
        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to persist the timezone.", T.CRITICAL)
            return
        timeutil.set_display_timezone_override(dd, zone)
        self._apply_tz_to_session()
        self._reload_general()
        self._set_gen_status(f"Display timezone set to {zone} — saved.", T.SAFE)

    # --- General tab (your name) -----------------------------------------
    def _current_user_name(self) -> str:
        from kratos import kratos_config as _kconfig

        dd = self._data_dir()
        if dd is None:
            return ""
        return (_kconfig.load_local_config(dd).get("user_name") or "").strip()

    @work
    async def _set_name_flow(self) -> None:
        if self._active_tab() != "tab-general":
            return
        from kratos.tui_mk2.modals import PromptModal
        from kratos import kratos_config as _kconfig

        dd = self._data_dir()
        if dd is None:
            self._set_gen_status("No data directory available to save a name.", T.CRITICAL)
            return
        answer = await self.app.push_screen_wait(
            PromptModal("Your name", "Shown as your prompt label (empty = clear, back to 'you')",
                        initial=self._current_user_name()))
        if answer is None:
            return
        name = answer.strip()
        _kconfig.save_local_config(dd, user_name=name)
        # Live-update the session's prompt label if it's a real SessionScreen.
        setter = getattr(self._session, "_set_user_name", None)
        if callable(setter):
            setter(name)
        self._reload_general()
        if name:
            self._set_gen_status(f"Name set to {name} — your messages now show '{name}>'.", T.SAFE)
        else:
            self._set_gen_status("Name cleared — your messages show 'you>' again.", T.SAFE)

    def action_set_name(self) -> None:
        self._set_name_flow()

    # --- General tab (theme pack) ----------------------------------------
    @work
    async def _set_theme_flow(self) -> None:
        if self._active_tab() != "tab-general":
            return
        from kratos.tui_mk2.modals import ListPickerModal

        active = T.active_pack_name()
        entries = [
            (name, f"{T.pack_label(name)}{'  (active)' if name == active else ''}")
            for name in T.PACKS
        ]
        picked = await self.app.push_screen_wait(
            ListPickerModal("Theme pack", entries,
                            subtitle="Recolors Kratos's chrome. Danger-red stays constant in every theme."))
        if picked is None:
            return
        if picked == active:
            self._set_gen_status(f"{T.pack_label(picked)} is already active.")
            return
        applied = self.app.apply_theme_pack(picked)  # live swap + persist; also calls refresh_theme
        if not applied:
            self._set_gen_status(f"Unknown theme {picked!r}.", T.CRITICAL)
            return
        self._set_gen_status(
            f"Theme set to {T.pack_label(picked)} — applied now; a full repaint of older lines "
            "happens next launch.", T.SAFE)

    def action_set_theme(self) -> None:
        self._set_theme_flow()

    def action_tz_auto(self) -> None:
        if self._active_tab() != "tab-general":
            return
        from kratos.utils import timeutil

        dd = self._data_dir()
        if dd is None:
            return
        timeutil.set_display_timezone_override(dd, None)
        self._apply_tz_to_session()
        self._reload_general()
        self._set_gen_status(f"Reverted to auto-detect ({timeutil.local_tz_name() or 'system local'}).", T.SAFE)

    @work
    async def _add_flow(self) -> None:
        values = await self.app.push_screen_wait(AddModelModal())
        if not values:
            return
        # Edge case: a model with this name already exists. add_profile would
        # append a second block that list_candidate_profiles then shadows by
        # name — confusing and unswitchable. Point the user at edit/delete
        # instead of silently creating a duplicate.
        if any(c.model == values["LLM_MODEL"] for c in self._candidates):
            self._set_status(
                f"A model named {values['LLM_MODEL']} already exists — edit its context window "
                "or delete it first, rather than adding a duplicate.", T.ATTENTION)
            return
        self._apply_add(values)

    @work(thread=True)
    def _apply_add(self, values: dict[str, str]) -> None:
        """Validate the new profile, then add it — activating it ONLY if its
        endpoint is actually reachable, so adding a model that's down (typo,
        server off) can't strand the live session on a dead backend. An
        unreachable-but-saved model stays inactive; the user switches to it once
        it's up. Runs in a thread because the reachability probe is a network
        call."""
        from kratos.adapters import llm_profiles as _p
        from kratos.adapters.llm_profiles import EnvProfile
        from kratos.llm_config import ENV_FILE_PATH, set_active_llm_profile
        from kratos.llm_interface import check_endpoint_reachable

        problems = _p.validate_profile(EnvProfile(values=values, line_indices={}, active=True))
        if problems:
            self.app.call_from_thread(self._set_status, f"Can't add: {'; '.join(problems)}", T.CRITICAL)
            return
        self.app.call_from_thread(self._set_status, f"Checking {values['LLM_MODEL']} is reachable…")
        reachable, detail = check_endpoint_reachable(values["LLM_BASE_URL"], values["LLM_API_KEY"])
        _p.add_profile(ENV_FILE_PATH, values, make_active=reachable)
        ctx_note = self._autofill_context(values) if reachable else None
        if reachable:
            set_active_llm_profile(values)
            if self._session is not None:  # no live session when opened from home
                self._session.session_state["backend"] = values["LLM_MODEL"]
                self.app.call_from_thread(self._session._refresh_footer)
            self.app.call_from_thread(self._reload)
            self.app.call_from_thread(
                self._set_status,
                f"Added {values['LLM_MODEL']} and switched to it — saved to .env."
                + (f" {ctx_note}" if ctx_note else ""), T.SAFE)
        else:
            self.app.call_from_thread(self._reload)
            self.app.call_from_thread(
                self._set_status,
                f"Saved {values['LLM_MODEL']} to .env, but did NOT switch to it — endpoint not reachable "
                f"({detail}). Switch to it here once it's running.", T.ATTENTION)

    @work
    async def _edit_flow(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            self._set_status("Select a model first, then Edit context window.")
            return
        result = await self.app.push_screen_wait(EditWindowModal(dict(profile.values)))
        if result is None:
            return
        window = None if result == "clear" else int(result["window"])
        source = None if result == "clear" else result.get("source")
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH, set_active_llm_profile
        _p.set_profile_context_window(ENV_FILE_PATH, profile.model, window, source=source)
        # If we edited the ACTIVE profile, re-sync the live override so the meter
        # and compaction pick the new window up immediately.
        if self._current is not None and self._current.model == profile.model:
            vals = dict(profile.values)
            vals.pop("LLM_CONTEXT_SOURCE", None)
            if window is None:
                vals.pop("LLM_CONTEXT_WINDOW", None)
            else:
                vals["LLM_CONTEXT_WINDOW"] = str(window)
                if source:
                    vals["LLM_CONTEXT_SOURCE"] = source
            set_active_llm_profile(vals)
            if self._session is not None:
                self._session._refresh_footer()
        self._reload()
        shown = "auto" if window is None else f"{window:,}"
        self._set_status(f"Set {profile.model} context window to {shown}.", T.SAFE)

    @work
    async def _delete_flow(self) -> None:
        from kratos.tui_mk2.modals import ConfirmModal

        profile = self._selected_profile()
        if profile is None:
            self._set_status("Select a model first, then delete.")
            return
        # Never delete the profile the running process is currently using -- that
        # would leave Kratos pointed at a model no longer in .env. Switch away first.
        if self._current is not None and self._current.model == profile.model:
            self._set_status(
                f"{profile.model} is the active model — switch to another model first, then delete it.",
                T.ATTENTION)
            return
        if len(self._candidates) <= 1:
            self._set_status("Can't delete the only configured model — add another first.", T.ATTENTION)
            return
        ok = await self.app.push_screen_wait(
            ConfirmModal(
                "Delete this model?",
                f"Removes {profile.model} from .env entirely. This only forgets the connection "
                "details here — it does not touch the model on its server. Add it again anytime.",
            )
        )
        if not ok:
            self._set_status("Delete cancelled — nothing changed.")
            return
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH
        _p.delete_profile(ENV_FILE_PATH, profile.model)
        self._reload()
        self._set_status(f"Deleted {profile.model} from .env.", T.SAFE)

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
        values = dict(target.values)
        set_active_llm_profile(values)
        _p.switch_profile(ENV_FILE_PATH, target, self._current)
        ctx_note = self._autofill_context(values)
        if ctx_note:
            set_active_llm_profile(values)   # re-sync with the newly saved window
        if self._session is not None:  # no live session when opened from home
            self._session.session_state["backend"] = target.model
            self.app.call_from_thread(self._session._refresh_footer)
        self.app.call_from_thread(self._reload)
        self.app.call_from_thread(
            self._set_status,
            f"Switched to {target.model} — active now, saved to .env." + (f" {ctx_note}" if ctx_note else "")
            + " Sent to it: " + _describe_mode(values) + ".",
            T.SAFE)

    @staticmethod
    def _autofill_context(values: dict[str, str]) -> str | None:
        """Detect-once-and-save for a just-added/switched profile (no-op if it
        already has a window or is local). Updates `values` in place. Runs on a
        worker thread (network). Returns a status suffix, or None."""
        from kratos.adapters.llm_context_autofill import autofill_context_window, describe
        from kratos.llm_config import ENV_FILE_PATH

        return describe(autofill_context_window(ENV_FILE_PATH, values), values.get("LLM_MODEL", ""))


# Backwards-compatible alias: /settings imported ModelSettingsScreen before the
# general hub existed.
ModelSettingsScreen = SettingsScreen


def _describe_mode(values: dict[str, str]) -> str:
    """What a just-chosen model profile is sent (kratos.privacy): masked or not."""
    from kratos.privacy import describe_mode

    return describe_mode(base_url=values.get("LLM_BASE_URL"))

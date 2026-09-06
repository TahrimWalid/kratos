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

from rich.text import Text
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Input, Select, Static, TabbedContent, TabPane

from kratos.tui_mk2 import theme as T

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


class _ContextField:
    """Shared detect+hint behavior for the add/edit forms (composition, not
    inheritance, to keep each modal's compose() explicit)."""

    def __init__(self, owner: ModalScreen):
        self.owner = owner
        self.detected_max: int | None = None
        self.detected_loaded: int | None = None

    @work(thread=True)
    def detect(self, base_url: str, api_key: str, model: str) -> None:
        from kratos.adapters.llm_context_detect import detect_context_window
        self.owner.app.call_from_thread(self.owner._set_hint, "Detecting context window…", T.TEXT_DIM)
        d = detect_context_window(base_url, api_key, model)
        self.detected_max = d.max_context
        self.detected_loaded = d.loaded_context
        if d.detectable:
            prefill = d.loaded_context or d.max_context
            self.owner.app.call_from_thread(self.owner._set_window_value, str(prefill))
            self.owner.app.call_from_thread(self.owner._set_hint, d.detail, T.SAFE)
        else:
            self.owner.app.call_from_thread(
                self.owner._set_hint, d.detail + " (your responsibility to set it correctly)", T.ATTENTION)


class AddModelModal(ModalScreen):
    """Add a new model: preset -> base URL/key/model -> Detect -> save. Dismisses
    with a values dict (LLM_BASE_URL/LLM_API_KEY/LLM_MODEL/KRATOS_LLM_BACKEND +
    optional LLM_CONTEXT_WINDOW) or None."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        Binding("ctrl+d", "detect", "detect", show=True),
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
        self.dismiss(values)


class EditWindowModal(ModalScreen):
    """Edit one profile's context window. Dismisses with an int (set), the
    string 'clear' (back to auto), or None (cancel)."""

    BINDINGS = [
        Binding("escape", "cancel", "cancel", show=True),
        Binding("ctrl+d", "detect", "detect", show=True),
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
            yield Static(Text("Empty = auto (Kratos picks a safe default for this model).", style=T.TEXT_DIM))
            yield Input(value=current, placeholder="tokens — Ctrl+D to detect, or empty for auto", id="edit-window")
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
        self.dismiss(value)


class SettingsScreen(Screen):
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
        Binding("right_square_bracket", "next_tab", "next tab", show=True),
        Binding("left_square_bracket", "prev_tab", "prev tab", show=False),
    ]

    CSS = f"""
    SettingsScreen {{ padding: 1 2; }}
    SettingsScreen #set-title {{ height: 1; text-style: bold; color: {T.ACCENT}; padding: 0 0 1 0; }}
    SettingsScreen DataTable {{ height: 1fr; }}
    SettingsScreen #ms-hint {{ height: auto; color: {T.TEXT_DIM}; padding: 1 0 0 0; }}
    SettingsScreen #ms-status {{ height: auto; color: {T.TEXT_MUTED}; }}
    SettingsScreen .set-placeholder {{ color: {T.TEXT_DIM}; padding: 1 0; }}
    """

    def __init__(self, session: Any) -> None:
        super().__init__()
        self._session = session
        self._candidates: list = []
        self._current = None
        self._ap_names: list[tuple[str, bool]] = []  # (tool_name, is_kept) per ap-table row

    def compose(self) -> ComposeResult:
        yield Static("Settings", id="set-title")
        with TabbedContent(initial="tab-models"):
            with TabPane("Models", id="tab-models"):
                yield DataTable(id="ms-table", cursor_type="row", zebra_stripes=False)
                yield Static(
                    Text("↑↓ select · enter/s switch · a add · e edit context window · d delete · "
                         "] next tab · esc back", style=T.TEXT_DIM),
                    id="ms-hint")
                yield Static("", id="ms-status")
            with TabPane("Tools", id="tab-approvals"):
                yield Static(
                    Text("Every tool the agent can use. Toggle whether a kept (self-written) tool "
                         "needs a human OK; view a kept tool's code; edit its short description. "
                         "Built-in tools' approval is fixed in code (read-only).", style=T.TEXT_DIM),
                    classes="set-placeholder")
                yield DataTable(id="ap-table", cursor_type="row", zebra_stripes=False)
                yield Static(
                    Text("↑↓ select · enter/space toggle approval (kept) · v view code · "
                         "c edit description (kept) · ] next tab · esc back", style=T.TEXT_DIM),
                    id="ap-hint")
                yield Static("", id="ap-status")
            with TabPane("General", id="tab-general"):
                yield Static("", id="gen-name")
                yield Static("", id="gen-theme")
                yield Static("", id="gen-tz")
                yield Static(
                    Text("n set your name · t theme · enter set a fixed display timezone · "
                         "u revert to auto-detect · esc back", style=T.TEXT_DIM),
                    id="gen-hint")
                yield Static("", id="gen-status")

    def on_mount(self) -> None:
        table = self.query_one("#ms-table", DataTable)
        table.add_columns(" ", "Model", "Where", "Context window")
        self._reload()
        ap = self.query_one("#ap-table", DataTable)
        ap.add_columns("Tool", "Kind", "Approval", "Description")
        self._reload_approvals()
        self._refresh_tz_status()
        self._refresh_name_status()
        self._refresh_theme_status()
        table.focus()  # so ↑↓ navigate immediately, no click needed

    def refresh_theme(self) -> None:
        """Called by KratosTUI.apply_theme_pack after a live pack switch: re-render
        this screen's dynamic content so its Text (built with T.ACCENT etc. at
        add-time) picks up the new palette. Frozen CSS title colors update on the
        next launch; the Textual widget chrome updated already via the theme flip."""
        self._reload()
        self._reload_approvals()
        self._refresh_tz_status()
        self._refresh_name_status()
        self._refresh_theme_status()

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

    # --- data ------------------------------------------------------------
    def _reload(self) -> None:
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH

        self._candidates, self._current = _p.list_candidate_profiles(ENV_FILE_PATH)
        table = self.query_one("#ms-table", DataTable)
        table.clear()
        if not self._candidates:
            self._set_status("No models configured yet — press 'a' to add one.", T.ATTENTION)
        for c in self._candidates:
            active = self._current is not None and c.model == self._current.model
            win = c.values.get("LLM_CONTEXT_WINDOW")
            win_txt = f"{int(win):,}" if (win and str(win).strip().isdigit()) else "auto"
            table.add_row(
                Text("●", style=T.SAFE) if active else Text(" "),
                Text(c.model, style=T.TEXT_BRIGHT if active else T.TEXT_MUTED),
                Text(self._session._profile_blurb(c.values), style=T.TEXT_DIM),
                Text(win_txt, style=T.TEXT_MUTED),
            )

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
        self.app.pop_screen()

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
            self._set_timezone_flow()

    # --- Tool approvals tab (kept tools; built-ins read-only) ------------
    def _reload_approvals(self) -> None:
        from kratos.agent.tools import TOOL_REGISTRY
        from kratos.agent.self_write_loop import KEPT_TOOLS_DIR, _read_metadata

        from kratos.tui_mk2 import render as R

        meta = _read_metadata(KEPT_TOOLS_DIR)
        ap = self.query_one("#ap-table", DataTable)
        ap.clear()
        self._ap_names = []
        for name in sorted(TOOL_REGISTRY):
            tool = TOOL_REGISTRY[name]
            is_kept = name in meta
            ap.add_row(
                Text(name, style=T.TEXT_MUTED),
                Text("kept" if is_kept else "built-in", style=T.ACCENT if is_kept else T.TEXT_FAINTER),
                Text("required" if tool.requires_approval else "auto",
                     style=T.ATTENTION if tool.requires_approval else T.TEXT_DIM),
                Text(R.tool_description(tool, meta.get(name)), style=T.TEXT_DIM),
            )
            self._ap_names.append((name, is_kept))

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
                f"{name} is a built-in tool — its approval is fixed in code, not editable here.", T.ATTENTION)
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
            f"{name}: approval {'required' if new_val else 'auto (runs without asking)'} — saved.", T.SAFE)

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

    # --- General tab (display timezone) ----------------------------------
    def _data_dir(self):
        return getattr(self._session, "_data_dir", None)

    def _refresh_tz_status(self) -> None:
        from kratos.utils import timeutil

        source, tz = timeutil.display_tz_status(self._data_dir())
        name = getattr(tz, "key", None) or timeutil.now_for_display("%Z", tz=tz)
        src_txt = {"override": "fixed override", "auto": "auto-detected", "fallback": "UTC fallback"}.get(source, source)
        self.query_one("#gen-tz", Static).update(Text(f"Display timezone: {name}  ({src_txt})", style=T.TEXT))

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
        self._refresh_tz_status()
        self._set_gen_status(f"Display timezone set to {zone} — saved.", T.SAFE)

    # --- General tab (your name) -----------------------------------------
    def _current_user_name(self) -> str:
        from kratos import kratos_config as _kconfig

        dd = self._data_dir()
        if dd is None:
            return ""
        return (_kconfig.load_local_config(dd).get("user_name") or "").strip()

    def _refresh_name_status(self) -> None:
        name = self._current_user_name()
        shown = name or "not set (messages show 'you>')"
        self.query_one("#gen-name", Static).update(Text(f"Your name: {shown}", style=T.TEXT))

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
        self._refresh_name_status()
        if name:
            self._set_gen_status(f"Name set to {name} — your messages now show '{name}>'.", T.SAFE)
        else:
            self._set_gen_status("Name cleared — your messages show 'you>' again.", T.SAFE)

    def action_set_name(self) -> None:
        self._set_name_flow()

    # --- General tab (theme pack) ----------------------------------------
    def _refresh_theme_status(self) -> None:
        active = T.active_pack_name()
        self.query_one("#gen-theme", Static).update(
            Text(f"Theme: {T.pack_label(active)}", style=T.TEXT))

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
        self._refresh_tz_status()
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
        if reachable:
            set_active_llm_profile(values)
            self._session.session_state["backend"] = values["LLM_MODEL"]
            self.app.call_from_thread(self._session._refresh_footer)
            self.app.call_from_thread(self._reload)
            self.app.call_from_thread(
                self._set_status, f"Added {values['LLM_MODEL']} and switched to it — saved to .env.", T.SAFE)
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
        window = None if result == "clear" else int(result)
        from kratos.adapters import llm_profiles as _p
        from kratos.llm_config import ENV_FILE_PATH, set_active_llm_profile
        _p.set_profile_context_window(ENV_FILE_PATH, profile.model, window)
        # If we edited the ACTIVE profile, re-sync the live override so the meter
        # and compaction pick the new window up immediately.
        if self._current is not None and self._current.model == profile.model:
            vals = dict(profile.values)
            if window is None:
                vals.pop("LLM_CONTEXT_WINDOW", None)
            else:
                vals["LLM_CONTEXT_WINDOW"] = str(window)
            set_active_llm_profile(vals)
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
        set_active_llm_profile(target.values)
        _p.switch_profile(ENV_FILE_PATH, target, self._current)
        self._session.session_state["backend"] = target.model
        self.app.call_from_thread(self._session._refresh_footer)
        self.app.call_from_thread(self._reload)
        self.app.call_from_thread(self._set_status, f"Switched to {target.model} — active now, saved to .env.", T.SAFE)


# Backwards-compatible alias: /settings imported ModelSettingsScreen before the
# general hub existed.
ModelSettingsScreen = SettingsScreen

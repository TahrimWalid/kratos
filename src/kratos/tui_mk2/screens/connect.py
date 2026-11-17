"""`/connect` (aliases `/openwebui`, `/chat-app`): connect a chat app to Kratos (docs/phaseE/E.5b).

One row per app -- Open WebUI, an AG-UI app, any OpenAI-compatible app -- with its state
(not connected, ok, expiring, expired, server down, port changed). Enter connects (or
replaces) the selected app: the machines, one confirm listing exactly what will be made,
then the one command or the values to paste, each in a click-to-copy box. `n` renews the
token, `u` disconnects, `s` installs the chat server as a user service.

The token appears only inside a CommandModal (to copy); this screen's log names the
token's id, never the token.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, title_row
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text

_STATE_STYLE = {"ok": T.SAFE, "expiring": T.ATTENTION, "server down": T.ATTENTION, "expired": T.CRITICAL,
                "revoked": T.CRITICAL, "port changed": T.CRITICAL, "not connected": T.TEXT_MUTED}


class ConnectScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter connect (or replace) · n new token (renew) · u disconnect\n"
                 "s run the chat server as a user service · r refresh · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter", "connect", "connect", show=True),
        Binding("n", "renew", "renew", show=True),
        Binding("u", "undo", "disconnect", show=True),
        Binding("s", "service", "service", show=True),
        Binding("r", "refresh", "refresh", show=True),
    ]
    CSS = layout_css("ConnectScreen", "cn")

    def __init__(self, data_dir: Path, *, app: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._start_app = app
        self._busy = False
        self._lines: list[Text] = []
        self._rows: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="cn-banner")
            yield DataTable(id="cn-table", cursor_type="row")
            yield Static(id="cn-detail")
            with VerticalScroll(id="cn-log"):
                yield Static(id="cn-log-text")
            yield Static(key_bar([("enter", "connect"), ("n", "renew"), ("u", "disconnect"), ("s", "service"),
                                  ("?", "all keys"), ("esc", "back")]), id="cn-hints")

    def on_mount(self) -> None:
        self.action_refresh()
        if self._start_app:
            from kratos.serve import connect as CN

            if self._start_app in CN.APPS:
                self.query_one("#cn-table", DataTable).move_cursor(row=CN.APPS.index(self._start_app))

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.action_refresh)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        self.app.push_screen(InfoModal("Chat apps — all keys", all_keys_text(self._ALL_KEYS)))

    def _actor(self) -> Actor:
        return Actor.current("tui")

    # ------------------------------------------------------------------ table
    def action_refresh(self) -> None:
        from kratos.serve import connect as CN
        from kratos.serve import status as ST

        live = {s.app: s for s in CN.status(self._data_dir)}
        self._rows = []
        for app in CN.APPS:
            s = live.get(app)
            self._rows.append({"app": app, "status": s, "state": s.state if s else "not connected"})
        self.query_one("#cn-banner", Static).update(title_row(
            "Chat apps", "", f"chat server {ST.summary(self._data_dir)}",
            note=f"{sum(1 for r in self._rows if r['status'])} connected"))
        table = self.query_one("#cn-table", DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        columns = ("app", "state", "machines", "token")
        table.add_columns(*columns)
        cells = []
        for r in self._rows:
            s = r["status"]
            cells.append([CN.APP_WORDS[r["app"]], Text(r["state"], style=_STATE_STYLE.get(r["state"], T.TEXT)),
                          ", ".join(s.machines) if s else "", s.token_name if s else ""])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(2, 16), (3, 12)], headers=columns):
            table.add_row(*row)
        table.move_cursor(row=min(cursor or 0, len(self._rows) - 1))
        self._show_detail()

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _selected(self) -> dict[str, Any] | None:
        try:
            table = self.query_one("#cn-table", DataTable)
        except Exception:  # noqa: BLE001
            return None
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    def _show_detail(self) -> None:
        from kratos.serve import connect as CN

        try:
            detail = self.query_one("#cn-detail", Static)
        except Exception:  # noqa: BLE001
            return
        r = self._selected()
        if r is None:
            detail.update(Text(""))
            return
        out = Text()
        s = r["status"]
        if s:
            out.append(s.words(), style=_STATE_STYLE.get(r["state"], T.TEXT))
        else:
            out.append(f"{CN.APP_WORDS[r['app']]} isn't connected. Press enter.", style=T.TEXT_MUTED)
        detail.update(out)

    def _log(self, text: str, style: str = T.TEXT) -> None:
        self._lines.append(Text(text, style=style))
        self._lines = self._lines[-200:]
        out = Text()
        for i, line in enumerate(self._lines):
            if i:
                out.append("\n")
            out.append_text(line)
        self.query_one("#cn-log-text", Static).update(out)

    # ------------------------------------------------------------------ connect
    def action_connect(self) -> None:
        r = self._selected()
        if r is None or self._busy:
            return
        self._connect_flow(r["app"])

    @work(exclusive=True)
    async def _connect_flow(self, app: str) -> None:
        from kratos import kratos_config
        from kratos.serve import connect as CN

        active = (kratos_config.get_active_target() or "").rsplit("@", 1)[-1].strip().strip("[]")
        try:
            from kratos.assets.store import known_machines

            known = [a.target for a in known_machines(self._data_dir)][:12]
        except Exception:  # noqa: BLE001
            known = []
        hint = "Comma-separated machines the app may ask about." + (
            f" Kratos knows: {', '.join(known)}" if known else "")
        typed = await self.app.push_screen_wait(PromptModal(f"Connect {CN.APP_WORDS[app]} — which machines?", hint,
                                                            initial=active))
        if typed is None:
            return
        machines = [m for m in typed.replace(" ", ",").split(",") if m.strip()]
        tools = False
        if app == "openwebui":
            tools = bool(await self.app.push_screen_wait(ConfirmModal(
                "Also let Open WebUI use Kratos's tools (MCP)?",
                "y: its tool servers may call Kratos too (the MCP door) · anything else: chat only (recommended)")))
        try:
            plan = await self._in_thread(lambda: CN.plan(self._data_dir, app, machines=machines, tools=tools))
            if plan.mode == "existing":
                choice = await self.app.push_screen_wait(ListPickerModal(
                    f"An Open WebUI already runs at {plan.facts.existing_openwebui}", [
                        ("existing", "connect that one (you paste the URL and key into its admin page)"),
                        ("new", f"start a separate Open WebUI for Kratos ({CN.OPENWEBUI_CONTAINER}, its own data)")]))
                if choice is None:
                    return
                if choice == "new":
                    plan = await self._in_thread(lambda: CN.plan(self._data_dir, app, machines=machines, tools=tools,
                                                                 new=True))
        except CN.ConnectError as e:
            self._log(f"Not connected: {e}", T.CRITICAL)
            return
        body = "\n".join(plan.summary() + [""] + plan.notes + ["", "Press y to make it."])
        if not await self.app.push_screen_wait(ConfirmModal(f"Connect {CN.APP_WORDS[app]}?", body)):
            self._log("Nothing changed.", T.TEXT_MUTED)
            return
        try:
            result = await self._in_thread(lambda: CN.apply(self._data_dir, plan, actor=self._actor(),
                                                            replace=bool(plan.replaces),
                                                            enable_agui=plan.enable_agui, created_by="tui"))
        except CN.ConnectError as e:
            self._log(f"Not connected: {e}", T.CRITICAL)
            return
        await self._show_result(result)
        if not plan.facts.serve_running:
            await self._offer_service(plan.facts)
        self.action_refresh()

    async def _in_thread(self, fn: Any) -> Any:
        import asyncio
        import contextvars

        return await asyncio.to_thread(contextvars.copy_context().run, fn)

    async def _show_result(self, result: Any) -> None:
        from kratos.serve import connect as CN

        p = result.plan
        self._log(f"✓ Connected {CN.APP_WORDS[p.app]}: token {result.token_id}, machines {', '.join(p.machines)}."
                  + (f" The old token {result.replaced_token} no longer works." if result.replaced_token else ""),
                  T.SAFE)
        for n in result.notes:
            self._log("  " + n, T.TEXT_MUTED)
        if result.command:
            await self.app.push_screen_wait(CommandModal(
                result.command, title="Run this one command",
                note=f"On THIS computer. The token is in {result.secret_path} (only you can read it). Then open "
                     f"{result.address}."))
        for label, value in result.paste:
            await self.app.push_screen_wait(CommandModal(value, title=f"Paste into the app: {label}",
                                                         note="Copy it with the button -- it is shown only here."))
        if result.check:
            await self.app.push_screen_wait(CommandModal(result.check, title="Check it works",
                                                         note="It reads the token from the file, not this line."))

    # ------------------------------------------------------------------ renew / undo / service
    def action_renew(self) -> None:
        r = self._selected()
        if r is None or self._busy or not r["status"]:
            return
        self._renew_flow(r["app"])

    @work(exclusive=True)
    async def _renew_flow(self, app: str) -> None:
        from kratos.serve import connect as CN

        if not await self.app.push_screen_wait(ConfirmModal(
                f"A new token for {CN.APP_WORDS[app]}?",
                "The current token stops working at once; the app needs the new one (Kratos shows where to paste "
                "it). Press y to go ahead.")):
            return
        try:
            result = await self._in_thread(lambda: CN.renew(self._data_dir, app, actor=self._actor(),
                                                            created_by="tui"))
        except CN.ConnectError as e:
            self._log(f"Not renewed: {e}", T.CRITICAL)
            return
        await self._show_result(result)
        self.action_refresh()

    def action_undo(self) -> None:
        r = self._selected()
        if r is None or self._busy or not r["status"]:
            return
        self._undo_flow(r["app"])

    @work(exclusive=True)
    async def _undo_flow(self, app: str) -> None:
        from kratos.serve import connect as CN

        if not await self.app.push_screen_wait(ConfirmModal(
                f"Disconnect {CN.APP_WORDS[app]}?",
                "Its token is revoked (the app stops getting answers at once) and its file removed. Press y.")):
            return
        try:
            u = await self._in_thread(lambda: CN.undo(self._data_dir, app, actor=self._actor()))
        except CN.ConnectError as e:
            self._log(f"Not disconnected: {e}", T.CRITICAL)
            return
        self._log(f"Disconnected {CN.APP_WORDS[app]}: token {u.token_id} revoked.", T.SAFE)
        if u.cleanup:
            await self.app.push_screen_wait(CommandModal("\n".join(u.cleanup), title="Remove the container too?",
                                                         note="Only if you want to. Kratos doesn't run these."))
        self.action_refresh()

    def action_service(self) -> None:
        if self._busy:
            return
        self._service_flow()

    @work(exclusive=True)
    async def _service_flow(self) -> None:
        from kratos.serve import connect as CN

        facts = await self._in_thread(lambda: CN.gather(self._data_dir))
        await self._offer_service(facts, asked=True)

    async def _offer_service(self, facts: Any, *, asked: bool = False) -> None:
        from kratos.serve import connect as CN

        if facts.serve_running and not asked:
            return
        if facts.serve_service:
            self._log(f"The chat server already runs as the {facts.serve_service} service {CN.SERVE_SERVICE}.",
                      T.TEXT_MUTED)
            return
        if not facts.systemd_user:
            self._log("There's no systemd user manager here: run `kratos serve` in a terminal and keep it open -- "
                      "the app works only while it runs.", T.ATTENTION)
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Run the chat server as a user service?",
            f"Installs {CN.SERVE_SERVICE} for your user (no sudo): it starts now, keeps running after you close Kratos"
            + (" and starts at boot." if facts.linger else ".")
            + ("" if facts.linger else " Lingering is off, so it stops when you log out (Kratos shows the one command "
                                       "that fixes that).") + "\n\nPress y to install."))
        if not ok:
            await self.app.push_screen_wait(CommandModal("\n".join(CN.serve_service_commands(self._data_dir)),
                                                         title="kratos-serve — run these yourself",
                                                         note="On THIS computer, when you're ready."))
            return
        self._log("Installing the kratos-serve user service…", T.ACCENT)
        ok_, words = await self._in_thread(lambda: CN.install_serve_service(self._data_dir, actor=self._actor()))
        self._log(("✓ " if ok_ else "✗ ") + words, T.SAFE if ok_ else T.CRITICAL)
        if ok_ and facts.linger is False:
            await self.app.push_screen_wait(CommandModal("sudo loginctl enable-linger $USER",
                                                         title="Keep the chat server running after logout",
                                                         note="Run once on THIS computer (needs sudo)."))
        self.action_refresh()

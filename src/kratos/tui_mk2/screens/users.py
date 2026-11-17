"""`/users` and `/audit`: sharing Kratos with other people (D.7).

`/users` lists every Kratos user -- role, the machines and @groups they may see, their
tokens and when each expires, the shared Open WebUI's mapped ids -- and lets the owner
add a user, change a role or scope, disable or enable one, make, rotate or revoke a token
and map an Open WebUI user. `/audit` shows the one audit trail (who did what, through
which door, allowed or refused). Both are the owner's, at this computer only; every
change is confirmed and recorded. Navigation follows tui_mk2/modals.py.
"""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos import authz
from kratos.authz import audit as AU
from kratos.authz import users as U
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import CommandModal, ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import resolve_display_tz

ROLE_CHOICES = [
    ("viewer", "viewer — reads findings, reports, hunts and answers for their machines"),
    ("investigator", "investigator — also starts investigations, fleet questions, re-checks, decides findings"),
    ("admin", "admin — like an investigator over the network (admin actions are only ever done here)"),
]


def _when(epoch: float | None, fmt: str = "%Y-%m-%d", tz: Any = None) -> str:
    """An epoch in the display zone (the same zone every other screen uses)."""
    if epoch is None:
        return "never"
    return datetime.fromtimestamp(float(epoch), tz=tz or resolve_display_tz()).strftime(fmt)


def _tokens(data_dir: Path) -> list[dict[str, Any]]:
    from kratos.serve import store as S

    return [t for t in S.list_tokens(data_dir) if not t.get("revoked_at")]


USERS_ABOUT = ("Other people reach Kratos only through `kratos serve` (a chat client or MCP) and see only their "
               "machines. Adding users, roles, machines and tokens happens only here, never over the network.")


class UsersScreen(Screen):
    _ALL_KEYS = ("↑↓ select · a add a user · r role · m machines · d disable / enable\n"
                 "t new token · o rotate a token · x revoke a token · w map an Open WebUI user · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("a", "add", "add user", show=True),
        Binding("r", "role", "role", show=True),
        Binding("m", "scope", "machines", show=True),
        Binding("d", "toggle", "disable/enable", show=True),
        Binding("t", "token", "new token", show=True),
        Binding("o", "rotate", "rotate token", show=True),
        Binding("x", "revoke", "revoke token", show=True),
        Binding("w", "map", "map Open WebUI user", show=True),
    ]

    # A2: title row, the table, a detail pane with the selected user's tokens and
    # Open WebUI ids in full, a short log and a key bar.
    CSS = layout_css("UsersScreen", "us")

    COLUMNS = ("user", "role", "state", "machines", "tokens")

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._rows: list[U.User] = []
        self._tokens: list[dict[str, Any]] = []
        self._maps: list[Any] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="us-banner")
            yield DataTable(id="us-table", cursor_type="row")
            yield Static(id="us-detail")
            yield VerticalScroll(id="us-log")
            yield Static(key_bar([("a", "add"), ("?", "all keys"), ("esc", "back")]), id="us-hints")

    def on_mount(self) -> None:
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{USERS_ABOUT}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("Users — all keys", body))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _mine(self, u: U.User) -> list[dict[str, Any]]:
        return [t for t in self._tokens if (t.get("user_id") or "owner") == u.user_id]

    def _show_detail(self) -> None:
        """The selected user in full: role, machines, every token with its expiry, Open WebUI ids."""
        try:
            detail = self.query_one("#us-detail", Static)
            hints = self.query_one("#us-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        u = self.selected()
        out = Text()
        if u is None:
            out.append(USERS_ABOUT, style=T.TEXT_MUTED)
            detail.update(out)
            hints.update(key_bar([("a", "add a user"), ("?", "all keys"), ("esc", "back")]))
            return
        out.append(u.name + (" (owner)" if u.is_owner else ""), style=f"bold {T.TEXT_BRIGHT}")
        out.append(f"   {u.role}", style=T.TEXT)
        out.append("   disabled" if u.disabled else "   active", style=T.CRITICAL if u.disabled else T.SAFE)
        out.append(f"\nmachines: {u.scope_text}", style=T.TEXT_MUTED)
        mine = self._mine(u)
        soon = time.time() + 14 * 86400
        for tok in mine:
            expiring = tok.get("expires_at") and float(tok["expires_at"]) < soon
            out.append(f"\ntoken {tok['name']}: expires {_when(tok.get('expires_at'), tz=self._tz)}",
                       style=T.ATTENTION if expiring else T.TEXT_DIM)
        if not mine:
            out.append("\nno tokens", style=T.TEXT_DIM)
        ids = [m.email or m.external_id for m in self._maps if m.user_id == u.user_id]
        if ids:
            out.append("\nOpen WebUI: " + ", ".join(ids), style=T.TEXT_DIM)
        detail.update(out)
        keys = [("r", "role"), ("m", "machines"), ("t", "token")] if not u.is_owner else [("t", "token")]
        hints.update(key_bar(keys + [("?", "all keys"), ("esc", "back")]))

    def note(self, renderable: Any) -> None:
        area = self.query_one("#us-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    def refresh_rows(self) -> None:
        table = self.query_one("#us-table", DataTable)
        keep = self._rows[table.cursor_row].user_id if self._rows and table.cursor_row is not None \
            and table.cursor_row < len(self._rows) else None
        self._rows = U.list_users(self._data_dir)
        self._tokens = _tokens(self._data_dir)
        self._maps = U.list_mappings(self._data_dir)
        soon = time.time() + 14 * 86400
        table.clear(columns=True)
        table.add_columns(*self.COLUMNS)
        cells = []
        for u in self._rows:
            mine = self._mine(u)
            expiring = any(t.get("expires_at") and float(t["expires_at"]) < soon for t in mine)
            state = Text("disabled", style=T.CRITICAL) if u.disabled else Text("active", style=T.SAFE)
            tok_text = (plural(len(mine), "token") + (" · one expires soon" if expiring else "")) if mine else "-"
            cells.append([u.name + (" (owner)" if u.is_owner else ""), u.role, state, u.scope_text,
                          Text(tok_text, style=T.ATTENTION if expiring else T.TEXT)])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(3, 12), (4, 10), (0, 12)],
                                            headers=self.COLUMNS)):
            table.add_row(*row, key=self._rows[i].user_id)
        at = next((i for i, u in enumerate(self._rows) if u.user_id == keep), None)
        if at is not None:
            table.move_cursor(row=at)        # stay on the user just changed
        disabled = sum(1 for u in self._rows if u.disabled)
        self.query_one("#us-banner", Static).update(title_row(
            "Users", plural(len(self._rows), "user"), f"{disabled} disabled" if disabled else ""))
        self._show_detail()

    def selected(self) -> U.User | None:
        table = self.query_one("#us-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    def _done(self, text: str, ok: bool = True) -> None:
        self.note(Text(text, style=T.SAFE if ok else T.CRITICAL))
        self.refresh_rows()

    def _actor(self) -> Any:
        return authz.owner_actor("tui")

    @work(exclusive=True)
    async def action_add(self) -> None:
        name = await self.app.push_screen_wait(PromptModal("New user's name", "letters, digits, . _ -"))
        if not name:
            return
        role = await self.app.push_screen_wait(ListPickerModal(f"Role for {name}", ROLE_CHOICES))
        if role is None:
            return
        scope = await self.app.push_screen_wait(PromptModal(
            f"Machines {name} may see", "comma-separated machines and @groups, e.g. web-01, @lab"))
        if scope is None:
            return
        entries = [s.strip() for s in scope.replace(" ", ",").split(",") if s.strip()]
        if not await self.app.push_screen_wait(ConfirmModal(f"Add {name}?", f"role: {role}\nmachines: "
                                                            f"{', '.join(entries) or 'nothing yet'}")):
            return
        try:
            u = U.add_user(self._data_dir, name, role, self._actor(), scopes=entries)
        except (U.UserError, authz.Denied) as e:
            self._done(f"Not added: {e}", ok=False)
            return
        self._done(f"Added {u.name} as {u.role}. Give them a token with t.")
        at = next((i for i, x in enumerate(self._rows) if x.user_id == u.user_id), None)
        if at is not None:
            self.query_one("#us-table", DataTable).move_cursor(row=at)

    @work(exclusive=True)
    async def action_role(self) -> None:
        u = self.selected()
        if u is None:
            return
        role = await self.app.push_screen_wait(ListPickerModal(f"Role for {u.name}", ROLE_CHOICES,
                                                               subtitle=f"now: {u.role}"))
        if role is None or role == u.role:
            return
        try:
            U.set_role(self._data_dir, u.user_id, role, self._actor())
        except (U.UserError, authz.Denied) as e:
            self._done(f"Not changed: {e}", ok=False)
            return
        self._done(f"{u.name} is now {role}.")

    @work(exclusive=True)
    async def action_scope(self) -> None:
        u = self.selected()
        if u is None:
            return
        scope = await self.app.push_screen_wait(PromptModal(
            f"Machines {u.name} may see", "comma-separated machines and @groups", initial=", ".join(u.scopes)))
        if scope is None:
            return
        entries = [s.strip() for s in scope.replace(" ", ",").split(",") if s.strip()]
        try:
            U.set_scopes(self._data_dir, u.user_id, entries, self._actor())
        except (U.UserError, authz.Denied) as e:
            self._done(f"Not changed: {e}", ok=False)
            return
        self._done(f"{u.name} may now see: {', '.join(entries) or 'nothing'}. A running investigation on a "
                   "machine taken out stops at its next read.")

    @work(exclusive=True)
    async def action_toggle(self) -> None:
        u = self.selected()
        if u is None:
            return
        verb = "Enable" if u.disabled else "Disable"
        if not await self.app.push_screen_wait(ConfirmModal(f"{verb} {u.name}?", "Disabled users are refused "
                                                            "everywhere from their next request.")):
            return
        try:
            U.set_disabled(self._data_dir, u.user_id, not u.disabled, self._actor())
        except (U.UserError, authz.Denied) as e:
            self._done(f"Not changed: {e}", ok=False)
            return
        self._done(f"{u.name} {'enabled' if u.disabled else 'disabled'}.")

    @work(exclusive=True)
    async def action_token(self) -> None:
        from kratos.serve import auth as A

        u = self.selected()
        if u is None:
            return
        name = await self.app.push_screen_wait(PromptModal(f"Token name for {u.name}", "e.g. alice-laptop",
                                                           initial=f"{u.name}-chat"))
        if not name:
            return
        mcp = await self.app.push_screen_wait(ConfirmModal("Also allow the MCP door?", "y: MCP and chat · "
                                                           "anything else: chat only"))
        try:
            token, row = A.create_token(self._data_dir, name=name, user=u.user_id, mcp=bool(mcp), created_by="tui")
        except A.TokenError as e:
            self._done(f"No token: {e}", ok=False)
            return
        self.app.push_screen(CommandModal(token, title=f"Token for {u.name} — copy it now",
                                          note=f"Kratos keeps only a hash. Expires {_when(row.get('expires_at'))}."))
        self._done(f"Made token {row['name']} ({row['token_id']}) for {u.name}.")

    async def _pick_token(self, title: str) -> dict[str, Any] | None:
        u = self.selected()
        if u is None:
            return None
        mine = [t for t in _tokens(self._data_dir) if (t.get("user_id") or "owner") == u.user_id]
        if not mine:
            self.note(Text(f"{u.name} has no live token.", style=T.TEXT_DIM))
            return None
        tid = await self.app.push_screen_wait(ListPickerModal(title, [
            (t["token_id"], f"{t['name']} ({t['kind']}) — expires {_when(t.get('expires_at'))}") for t in mine]))
        return next((t for t in mine if t["token_id"] == tid), None)

    @work(exclusive=True)
    async def action_rotate(self) -> None:
        from kratos.serve import auth as A

        t = await self._pick_token("Rotate which token?")
        if t is None:
            return
        try:
            token, row, _old = A.rotate(self._data_dir, t["token_id"], created_by="tui")
        except A.TokenError as e:
            self._done(f"Not rotated: {e}", ok=False)
            return
        self.app.push_screen(CommandModal(token, title=f"Replacement for {t['name']} — copy it now",
                                          note="The old token stopped working now."))
        self._done(f"Rotated {t['name']} -> {row['name']}.")

    @work(exclusive=True)
    async def action_revoke(self) -> None:
        from kratos.serve import auth as A

        t = await self._pick_token("Revoke which token?")
        if t is None or not await self.app.push_screen_wait(ConfirmModal(f"Revoke {t['name']}?", "It stops at once.")):
            return
        try:
            A.revoke(self._data_dir, t["token_id"])
        except A.TokenError as e:
            self._done(f"Not revoked: {e}", ok=False)
            return
        self._done(f"Revoked {t['name']}.")

    @work(exclusive=True)
    async def action_map(self) -> None:
        u = self.selected()
        if u is None:
            return
        ext = await self.app.push_screen_wait(PromptModal(
            f"Open WebUI user id for {u.name}", "Open WebUI: Admin Panel -> Users -> the user's id"))
        if not ext:
            return
        email = await self.app.push_screen_wait(PromptModal("Their email in Open WebUI (shown to you only)", ""))
        try:
            U.map_gateway(self._data_dir, "openwebui", ext, u.user_id, self._actor(), email=email or "")
        except (U.UserError, authz.Denied) as e:
            self._done(f"Not mapped: {e}", ok=False)
            return
        self._done(f"Open WebUI user {ext} is now {u.name}.")


AUDIT_ABOUT = ("Every allowed and refused action: who, through which door and credential. It can't be edited; "
               "`kratos audit prune` removes old rows (recorded).")


class AuditScreen(Screen):
    _ALL_KEYS = "↑↓ select · enter the whole row · f refused only · u one user · esc back"
    BINDINGS = [Binding("escape,q", "back", "back", show=True),
                Binding("question_mark", "all_keys", "all keys", show=False),
                Binding("f", "refused", "refused only", show=True),
                Binding("u", "by_user", "by user", show=True),
                Binding("enter", "detail", "detail", show=True, priority=True)]

    # A2: title row, the table, a detail pane with the door, credential and the full
    # "what / why" (cut at 80 columns before), and a key bar.
    CSS = layout_css("AuditScreen", "au", table_max="60%")

    COLUMNS = ("when", "result", "who", "action", "machine")

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._refused = False
        self._user: str | None = None
        self._rows: list[dict[str, Any]] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="au-banner")
            yield DataTable(id="au-table", cursor_type="row")
            yield Static(id="au-detail")
            yield VerticalScroll(id="au-log")
            yield Static(key_bar([("enter", "whole row"), ("f", "refused only"), ("u", "one user"),
                                  ("?", "all keys"), ("esc", "back")]), id="au-hints")

    def on_mount(self) -> None:
        try:
            authz.require(authz.owner_actor("tui"), authz.P.AUDIT_READ, data_dir=self._data_dir, obj="/audit",
                          audit_allowed=False)
        except authz.Denied as e:
            self.query_one("#au-banner", Static).update(title_row("Audit trail", note=f"refused: {e}"))
            return
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{AUDIT_ABOUT}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("Audit trail — all keys", body))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        try:
            detail = self.query_one("#au-detail", Static)
            table = self.query_one("#au-table", DataTable)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        if not self._rows or table.cursor_row is None:
            detail.update(Text(AUDIT_ABOUT, style=T.TEXT_MUTED))
            return
        r = self._rows[min(table.cursor_row, len(self._rows) - 1)]
        out = Text()
        refused = r["result"] == "refused"
        # A refusal is the system working, not a failure: the attention colour, not danger red.
        out.append(r["result"], style=f"bold {T.ATTENTION if refused else T.SAFE}")
        out.append(f"   {r['action']}", style=f"bold {T.TEXT_BRIGHT}")
        out.append(f"   {_when(r['at'], '%Y-%m-%d %H:%M:%S', tz=self._tz)}", style=T.TEXT_DIM)
        out.append(f"\n{r['user_name'] or r['user_id'] or '(nobody)'} through {r['interface']}"
                   + (f" ({r['credential']})" if r.get("credential") else ""), style=T.TEXT_MUTED)
        if r.get("machine"):
            out.append(f" · machine {r['machine']}", style=T.TEXT_MUTED)
        what = r["reason"] if refused and r["reason"] else (r["object"] or "")
        if what:
            out.append(f"\n{'why' if refused else 'what'}: {what}", style=T.TEXT)
        detail.update(out)

    def action_refused(self) -> None:
        self._refused = not self._refused
        self.refresh_rows()

    @work(exclusive=True)
    async def action_by_user(self) -> None:
        who = await self.app.push_screen_wait(PromptModal("Only this user (empty = everyone)", "name or id",
                                                          initial=self._user or ""))
        if who is None:
            return
        self._user = who.strip() or None
        self.refresh_rows()

    def refresh_rows(self) -> None:
        table = self.query_one("#au-table", DataTable)
        self._rows = AU.query(self._data_dir, user=self._user, result="refused" if self._refused else None, limit=500)
        table.clear(columns=True)
        table.add_columns(*self.COLUMNS)
        cells = []
        for r in self._rows:
            res = Text(r["result"], style=T.ATTENTION if r["result"] == "refused" else T.SAFE)
            cells.append([_when(r["at"], "%m-%d %H:%M:%S", tz=self._tz), res,
                          r["user_name"] or r["user_id"] or "(nobody)", r["action"], r["machine"] or "-"])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(2, 10), (3, 14), (4, 10)], headers=self.COLUMNS):
            table.add_row(*row)
        filt = " · ".join(b for b in (("refused only" if self._refused else ""),
                                      (f"user {self._user}" if self._user else "")) if b)
        self.query_one("#au-banner", Static).update(title_row("Audit trail", f"newest {len(self._rows)}", filt))
        self._show_detail()

    def action_detail(self) -> None:
        table = self.query_one("#au-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return
        r = self._rows[min(table.cursor_row, len(self._rows) - 1)]
        body = Text()
        for k in ("at", "result", "user_name", "user_id", "interface", "credential", "action", "machine", "object",
                  "reason", "run_id"):
            v = r.get(k)
            if k == "at":
                v = _when(v, "%Y-%m-%d %H:%M:%S", tz=self._tz)
            body.append(f"{k}: ", style=T.TEXT_DIM)
            body.append(f"{v if v not in (None, '') else '-'}\n")
        self.app.push_screen(InfoModal("Audit row", body))

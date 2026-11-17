"""`/channels` and `/outbox` (D.4): where Kratos sends what it finds, and what it sent.

/channels lists every channel (ntfy is built in) with what it receives, its state and how
delivery is going; a guided add per kind (webhook, syslog over TLS, email) states plainly
what will be sent and to whom before saving; Test sends a test message and shows the
result live. /outbox lists messages with their attempts, failures and dead letters, and
"retry now" for a receiver you fixed. Every change is confirmed and recorded with who
made it. Secrets are never shown, except a newly generated webhook signing secret, once.
Navigation follows tui_mk2/modals.py: Escape back, `y` confirms.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.lifecycle.decide import Actor
from kratos.outbox import config as C
from kratos.outbox import health as H
from kratos.outbox import store as S
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import epoch_to_utc_iso, format_for_display, resolve_display_tz

KIND_CHOICES = [
    ("webhook", "Webhook — an HTTPS POST, signed (Standard Webhooks); also a SIEM's HTTP collector"),
    ("syslog", "Syslog over TLS — RFC 5424 to rsyslog, syslog-ng, a SIEM's syslog input"),
    ("email", "Email — one message per run or batch, over STARTTLS or TLS"),
]
SCOPE_CHOICES = {
    "webhook": [("alerts", "alerts only (what triggers and schedules send)"),
                ("alerts,findings", "alerts and every change of matching findings"),
                ("findings", "findings changes only (a SIEM)"),
                ("findings,events", "findings changes and stored log events (a SIEM)")],
    "syslog": [("alerts", "alerts only"), ("alerts,findings", "alerts and findings changes"),
               ("findings,events", "findings changes and stored log events (a SIEM)")],
    "email": [("alerts", "alerts only"), ("alerts,findings", "alerts and a digest of findings changes per run")],
}
FORMAT_CHOICES = {
    "webhook": [("kratos", "Kratos JSON (Standard Webhooks payload)"), ("ocsf", "OCSF 1.9.0"), ("ecs", "ECS JSON")],
    "syslog": [("text", "readable text"), ("ocsf", "OCSF 1.9.0 JSON"), ("ecs", "ECS JSON")],
}
SEVERITY_CHOICES = [("", "everything"), ("low", "low and above"), ("medium", "medium and above"),
                    ("high", "high and critical only"), ("critical", "critical only")]
COLUMNS = ("channel", "kind", "state", "waiting", "last success")   # receives, format: the detail pane
CHANNELS_ABOUT = ("Where Kratos sends what it finds. Every message goes through the outbox: it is kept, retried "
                  "while a receiver is down, and listed in /outbox. Secrets are removed before anything leaves.")


def _when(epoch: float | None, tz: Any) -> str:
    if not epoch:
        return "-"
    return format_for_display(epoch_to_utc_iso(epoch), "%Y-%m-%d %H:%M", tz=tz)


class ChannelsScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter details · a add a channel · t send a test message\n"
                 "space on / off · x remove · o the outbox (what was sent) · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("a", "add", "add", show=True),
        Binding("t", "test", "test", show=True),
        Binding("space", "toggle", "on/off", show=True),
        Binding("enter,i", "details", "details", show=True, priority=True),
        Binding("x", "remove", "remove", show=True),
        Binding("o", "outbox", "outbox", show=True),
    ]

    # A2: title row, the table, a detail pane for the selected channel, a log, a key bar.
    CSS = layout_css("ChannelsScreen", "ch")

    def __init__(self, data_dir: Path) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._rows: list[C.Channel] = []
        self._health: dict[str, Any] = {}
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="ch-banner")
            yield DataTable(id="ch-table", cursor_type="row")
            yield Static(id="ch-detail")
            yield VerticalScroll(id="ch-log")
            yield Static(key_bar([("a", "add"), ("?", "all keys"), ("esc", "back")]), id="ch-hints")

    def on_mount(self) -> None:
        self.refresh_rows()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_outbox(self) -> None:
        self.app.push_screen(OutboxScreen(self._data_dir))

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append(f"\n\n{CHANNELS_ABOUT}\n\n{self._deliverer_words()}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("Channels — all keys", body))

    def _deliverer_words(self) -> str:
        h = H.read(self._data_dir)
        return (f"Delivering now: {h.deliverer}." if h.deliverer_live else
                "Nothing long-running delivers right now: this window delivers while it's open; install the "
                "always-on listener (L in /subagent) to deliver all the time.")

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        """The selected channel: what it receives, its format, the queue and the last success (A2)."""
        try:
            detail = self.query_one("#ch-detail", Static)
            hints = self.query_one("#ch-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        ch = self.selected()
        out = Text()
        if ch is None:
            out.append(CHANNELS_ABOUT, style=T.TEXT_MUTED)
            detail.update(out)
            hints.update(key_bar([("a", "add a channel"), ("o", "outbox"), ("?", "all keys"), ("esc", "back")]))
            return
        h = self._health.get(ch.name)
        ok, why = C.usable(ch)
        out.append(ch.name, style=f"bold {T.TEXT_BRIGHT}")
        out.append(f"   {ch.kind}", style=T.TEXT)
        if h is not None and h.failing:
            out.append("   failing", style=f"bold {T.CRITICAL}")
        elif not ok:
            out.append(f"   {why or 'off'}", style=T.TEXT_MUTED)
        out.append(f"\nreceives {', '.join(ch.scopes)} · format {ch.format}", style=T.TEXT_MUTED)
        waiting = h.backlog if h else 0
        dead = h.dead if h else 0
        out.append(f"\n{waiting} waiting · ", style=T.TEXT_DIM)
        out.append(f"{plural(dead, 'dead letter')}", style=T.ATTENTION if dead else T.TEXT_DIM)
        out.append(f" · last success {H.ago(ch.last_success_at)}", style=T.TEXT_DIM)
        detail.update(out)
        hints.update(key_bar([("enter", "details"), ("t", "test"), ("space", "on/off"), ("o", "outbox"),
                              ("?", "all keys"), ("esc", "back")]))

    def note(self, renderable: Any) -> None:
        area = self.query_one("#ch-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    def refresh_rows(self) -> None:
        table = self.query_one("#ch-table", DataTable)
        cursor = table.cursor_row
        self._rows = C.list_channels(self._data_dir)
        self._health = {c.name: c for c in H.read(self._data_dir).channels}
        health = self._health
        table.clear(columns=True)
        table.add_columns(*COLUMNS)
        cells = []
        for ch in self._rows:
            h = health.get(ch.name)
            ok, _why = C.usable(ch)
            if h is not None and h.failing:
                state = Text("FAILING", style=T.CRITICAL)
            elif ok:
                state = Text("on", style=T.SAFE)
            else:
                state = Text("off" if not ch.enabled else "not set up", style=T.TEXT_MUTED)
            dead = h.dead if h else 0
            waiting = Text(str(h.backlog if h else 0) + (f" · {dead} dead" if dead else ""),
                           style=T.ATTENTION if dead else T.TEXT)
            cells.append([ch.name, ch.kind, state, waiting, H.ago(ch.last_success_at)])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(0, 12)], headers=COLUMNS)):
            table.add_row(*row, key=self._rows[i].name)
        if self._rows:
            table.move_cursor(row=min(cursor or 0, len(self._rows) - 1))
        h = H.read(self._data_dir)
        self.query_one("#ch-banner", Static).update(title_row(
            "Channels", plural(len(self._rows), "channel"),
            f"delivering: {h.deliverer}" if h.deliverer_live else "",
            note="" if h.deliverer_live else "delivers only while this window is open (?)"))
        self._show_detail()

    def selected(self) -> C.Channel | None:
        table = self.query_one("#ch-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    # -- details ------------------------------------------------------------------------
    def action_details(self) -> None:
        ch = self.selected()
        if ch is None:
            return
        body = Text()
        body.append(ch.disclosure() + "\n\n")
        body.append(f"Receives: {', '.join(ch.scopes)} · format {ch.format} · filters: {ch.filters.describe()} · "
                    f"at most {ch.max_per_minute} a minute\n", style=T.TEXT_MUTED)
        cfg = {k: v for k, v in ch.config.items() if v not in (None, "", False)}
        if cfg:
            body.append("Settings: " + ", ".join(f"{k}={v}" for k, v in sorted(cfg.items())) + "\n",
                        style=T.TEXT_MUTED)
        names = C.secret_names(self._data_dir, ch.name)
        body.append(("Secrets: " + ", ".join(names) + " (never shown)" if names else "Secrets: none") + "\n",
                    style=T.TEXT_MUTED)
        if ch.failing_since:
            body.append(f"Failing since {_when(ch.failing_since, self._tz)}: {ch.last_error}\n", style=T.CRITICAL)
        body.append(f"Last success: {_when(ch.last_success_at, self._tz)}\n\nHistory:\n", style=T.TEXT_MUTED)
        for e in C.history(self._data_dir, ch.name, limit=12):
            body.append(f"  {_when(e['at'], self._tz)}  {e['action']}  by {e['actor']} ({e['interface']})\n")
        self.app.push_screen(InfoModal(f"Channel {ch.name}", body))

    # -- on / off, remove ---------------------------------------------------------------------
    @work(exclusive=True)
    async def action_toggle(self) -> None:
        ch = self.selected()
        if ch is None:
            return
        turn_on = not ch.enabled
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Turn {ch.name} {'on' if turn_on else 'off'}?",
            "Waiting messages go out again." if turn_on else "Its messages wait in the outbox until you turn it on."))
        if not ok:
            return
        try:
            C.set_enabled(self._data_dir, ch.name, turn_on, actor=Actor.current("tui"))
        except C.ChannelError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"{ch.name} turned {'on' if turn_on else 'off'}.", style=T.SAFE))
        self.refresh_rows()

    @work(exclusive=True)
    async def action_remove(self) -> None:
        ch = self.selected()
        if ch is None:
            return
        if ch.builtin:
            self.note(Text("ntfy is built in: turn it off with space (or remove KRATOS_NTFY_TOPIC from .env).",
                           style=T.ATTENTION))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Remove channel {ch.name}?", "Its settings and secrets are removed; its messages stay in the outbox as "
                                          "history (waiting ones are closed)."))
        if not ok:
            return
        n = C.remove_channel(self._data_dir, ch.name, actor=Actor.current("tui"))
        self.note(Text(f"Removed {ch.name}." + (f" {n} waiting message(s) closed." if n else ""), style=T.SAFE))
        self.refresh_rows()

    # -- test ----------------------------------------------------------------------------------
    @work(exclusive=True, thread=True)
    def action_test(self) -> None:
        ch = self.selected()
        if ch is None:
            return
        from kratos.cli.outbox_cmd import _enqueue_forward_test
        from kratos.outbox import worker as W
        from kratos.outbox.alerts import enqueue_alert

        if "alerts" in ch.scopes:
            res = enqueue_alert(f"Kratos test message for channel {ch.name}: if you can read this, delivery works.",
                                "info", deliver=[ch.name], data_dir=self._data_dir, kind="test", source="interactive",
                                message_id=f"test:{ch.name}:{int(time.time() * 1000)}")
        else:
            res = _enqueue_forward_test(self._data_dir, ch)
        if res.get("status") != "queued":
            self.app.call_from_thread(self.note, Text(f"Not sent: {res.get('observation') or res.get('status')}",
                                                      style=T.ATTENTION))
            return
        oid = res["outbox_ids"][0]
        self.app.call_from_thread(self.note, Text(f"Test message #{oid} queued for {ch.name}; delivering …",
                                                  style=T.TEXT_DIM))
        W.wake()
        deadline = time.monotonic() + 25
        row = None
        while time.monotonic() < deadline:
            with S.opened(self._data_dir) as conn:
                row = S.get(conn, oid)
            if row["status"] in ("delivered", "dead", "failed"):
                break
            if W.running_worker(self._data_dir) is None:
                W.flush(self._data_dir, label="the TUI", deadline_seconds=15)
            time.sleep(0.5)
        if row is None:
            return
        if row["status"] == "delivered":
            msg = Text(f"Delivered to {ch.destination}.", style=T.SAFE)
        elif row["status"] in ("dead", "failed"):
            msg = Text(f"{row['status']}: {row['last_error']}"
                       + (" — Kratos retries it on its schedule (see /outbox)." if row["status"] == "failed" else ""),
                       style=T.CRITICAL)
        else:
            msg = Text("Still waiting: another Kratos process delivers (see /outbox).", style=T.ATTENTION)
        self.app.call_from_thread(self.note, msg)
        self.app.call_from_thread(self.refresh_rows)

    # -- guided add ------------------------------------------------------------------------------
    @work(exclusive=True)
    async def action_add(self) -> None:
        kind = await self.app.push_screen_wait(ListPickerModal("What kind of channel?", KIND_CHOICES))
        if kind is None:
            return
        name = await self.app.push_screen_wait(PromptModal(
            "Name for it (lower-case letters, digits, - or _)", "soc-webhook, siem, ops-mail …"))
        if not name:
            return
        cfg: dict[str, Any] = {}
        secrets: dict[str, str] = {}
        if kind == "webhook":
            url = await self.app.push_screen_wait(PromptModal("Receiver URL (https://…)", "https://siem.example/kratos"))
            if not url:
                return
            cfg["url"] = url.strip()
            if url.strip().startswith("http://"):
                ok = await self.app.push_screen_wait(ConfirmModal(
                    "Send over plain HTTP?", "Findings would be readable on the network. Only for a receiver on this "
                                             "machine or your own network."))
                if not ok:
                    return
                cfg["allow_http"] = True
            secrets["signing_secret"] = C.new_webhook_secret()
        elif kind == "syslog":
            host = await self.app.push_screen_wait(PromptModal("Syslog server (host name or address)", "logs.example"))
            if not host:
                return
            port = await self.app.push_screen_wait(PromptModal("Port (TLS)", "6514", initial="6514"))
            if port is None:
                return
            cfg.update(host=host.strip(), port=port.strip() or "6514")
        else:
            host = await self.app.push_screen_wait(PromptModal("Mail server (host name)", "smtp.example"))
            if not host:
                return
            sec = await self.app.push_screen_wait(ListPickerModal("How does it encrypt?", [
                ("starttls", "STARTTLS (usually port 587)"), ("tls", "TLS from the start (usually port 465)")]))
            if sec is None:
                return
            sender = await self.app.push_screen_wait(PromptModal("From address", "kratos@example.com"))
            to = await self.app.push_screen_wait(PromptModal("To (comma separated)", "you@example.com"))
            user = await self.app.push_screen_wait(PromptModal("Login name (empty: none)", ""))
            if sender is None or to is None or user is None:
                return
            cfg.update(host=host.strip(), security=sec, **{"from": sender.strip()}, to=to, username=user.strip() or None)
            if user.strip():
                pw = await self.app.push_screen_wait(PromptModal(f"Password for {user.strip()} (kept in "
                                                                 "channel-secrets/, never shown)", ""))
                if not pw:
                    return
                secrets["password"] = pw
        ca = await self.app.push_screen_wait(PromptModal(
            "CA file for the receiver's certificate (empty: the system's CAs)", "/etc/ssl/my-ca.pem"))
        if ca is None:
            return
        if ca.strip():
            cfg["ca_file"] = ca.strip()
        scopes = await self.app.push_screen_wait(ListPickerModal("What should it receive?", SCOPE_CHOICES[kind]))
        if scopes is None:
            return
        fmt = "text"
        if kind in FORMAT_CHOICES and scopes != "alerts":
            fmt = await self.app.push_screen_wait(ListPickerModal("In which format?", FORMAT_CHOICES[kind]))
            if fmt is None:
                return
            if "alerts" in scopes and fmt in ("ocsf", "ecs"):
                scopes = ",".join(s for s in scopes.split(",") if s != "alerts")
        elif kind == "webhook":
            fmt = "kratos"
        sev = await self.app.push_screen_wait(ListPickerModal("Which severities?", SEVERITY_CHOICES))
        if sev is None:
            return
        mask = await self.app.push_screen_wait(ConfirmModal(
            "Replace account names, addresses and host names with placeholders before sending?",
            "y: the receiver sees placeholders (they are never turned back); n: it sees the real values.",
            yes_label="mask", no_label="send real values"))
        try:
            draft = C.Channel(name=C.check_name(name), kind=kind, config=C._clean_config(kind, cfg),
                              scopes=tuple(scopes.split(",")), format=fmt, mask_values=bool(mask))
        except C.ChannelError as e:
            self.note(Text(f"Not added: {e}", style=T.CRITICAL))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(f"Add channel {draft.name}?", draft.disclosure()))
        if not ok:
            self.note(Text("Not added.", style=T.TEXT_DIM))
            return
        try:
            ch = C.add_channel(self._data_dir, name=name, kind=kind, config=cfg, scopes=scopes.split(","), format=fmt,
                               filters={"min_severity": sev or None}, mask_values=bool(mask), secrets=secrets,
                               actor=Actor.current("tui"))
        except C.ChannelError as e:
            self.note(Text(f"Not added: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"Added {ch.name}. Press t to send a test message.", style=T.SAFE))
        if "signing_secret" in secrets:
            body = Text()
            body.append("Set your receiver up with this signing secret. It is shown only now:\n\n")
            body.append(secrets["signing_secret"] + "\n\n", style=f"bold {T.ACCENT}")
            body.append("The receiver checks the webhook-signature header with it (GUIDE: Sending findings "
                        "elsewhere has a ten-line verifier).", style=T.TEXT_MUTED)
            self.app.push_screen(InfoModal("Webhook signing secret", body))
        self.refresh_rows()


class OutboxScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter attempts · r retry now (a failing or dead message)\n"
                 "d dead letters · f failing · a all · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter,i", "details", "attempts", show=True, priority=True),
        Binding("r", "retry", "retry now", show=True),
        Binding("d", "filter('dead')", "dead letters", show=True),
        Binding("f", "filter('failed')", "failing", show=True),
        Binding("a", "filter('')", "all", show=True),
    ]

    # A2: title row, the table (hidden when there is nothing to list -- the sentence says so),
    # a detail pane with the summary and the last error in full, and a key bar.
    CSS = layout_css("OutboxScreen", "ob", table_max="60%")
    COLS = ("#", "channel", "status", "tries", "created", "summary")
    _STYLE = {"delivered": T.SAFE, "failed": T.ATTENTION, "dead": T.CRITICAL, "pending": T.TEXT_MUTED}

    def __init__(self, data_dir: Path, status: str = "") -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._status = status
        self._rows: list[Any] = []
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="ob-banner")
            yield DataTable(id="ob-table", cursor_type="row")
            yield Static(id="ob-detail")
            yield VerticalScroll(id="ob-log")       # keeps the key bar at the bottom
            yield Static(key_bar([("d", "dead letters"), ("f", "failing"), ("a", "all"), ("?", "all keys"),
                                  ("esc", "back")]), id="ob-hints")

    def on_mount(self) -> None:
        self.refresh_rows()
        self.set_interval(3.0, self.refresh_rows)

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.refresh_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        body.append("\n\nDelivered and dead messages are kept until you prune them (`kratos outbox prune`).",
                    style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("Outbox — all keys", body))

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        try:
            detail = self.query_one("#ob-detail", Static)
            hints = self.query_one("#ob-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        r = self.selected()
        filters = [("d", "dead letters"), ("f", "failing"), ("a", "all"), ("?", "all keys"), ("esc", "back")]
        if r is None:
            what = {"dead": "No dead letters.", "failed": "Nothing is failing right now."}.get(
                self._status, "Nothing has been sent yet. Messages appear here once a channel receives one (/channels).")
            detail.update(Text(what, style=T.TEXT_MUTED))
            hints.update(key_bar(filters))
            return
        out = Text()
        out.append(f"#{r['id']}  ", style=T.DATA)
        out.append(r["status"], style=f"bold {self._STYLE.get(r['status'], T.TEXT)}")
        out.append(f"   to {r['channel']} · {r['kind']} · {plural(r['attempts'], 'try', 'tries')}", style=T.TEXT_MUTED)
        out.append(f"\n{r['summary']}", style=T.TEXT)
        if r["last_error"] and r["status"] != "delivered":
            out.append(f"\nlast error: {r['last_error']}", style=T.ATTENTION)
        if r["status"] == "failed":
            out.append(f"\nnext try {_when(r['next_attempt_at'], self._tz)}", style=T.TEXT_DIM)
        detail.update(out)
        keys = [("enter", "attempts")] + ([("r", "retry now")] if r["status"] in ("dead", "failed") else [])
        hints.update(key_bar(keys + filters))

    def action_filter(self, status: str) -> None:
        self._status = status
        self.refresh_rows()

    def refresh_rows(self) -> None:
        table = self.query_one("#ob-table", DataTable)
        cursor = table.cursor_row
        with S.opened(self._data_dir) as conn:
            self._rows = S.listing(conn, status=self._status or None, limit=200)
            counts = S.counts(conn)
        table.clear(columns=True)
        table.add_columns(*self.COLS)
        cells = []
        for r in self._rows:
            cells.append([str(r["id"]), r["channel"], Text(r["status"], style=self._STYLE.get(r["status"], T.TEXT)),
                          str(r["attempts"]), _when(r["created_at"], self._tz), r["summary"]])
        available = table.size.width or max(self.app.size.width - 6, 40)
        for i, row in enumerate(fit_columns(cells, available, shrink=[(5, 16), (1, 10)], headers=self.COLS)):
            table.add_row(*row, key=str(self._rows[i]["id"]))
        table.display = bool(self._rows)          # no empty grid under the "nothing yet" sentence
        if self._rows:
            table.move_cursor(row=min(cursor or 0, len(self._rows) - 1))
        tot = {s: sum(c.get(s, 0) for c in counts.values()) for s in ("pending", "failed", "delivered", "dead")}
        summary = (f"{tot['pending']} waiting · {tot['failed']} retrying · {tot['delivered']} delivered · "
                   f"{plural(tot['dead'], 'dead letter')}")
        view = {"dead": "dead letters", "failed": "failing"}.get(self._status, "")
        self.query_one("#ob-banner", Static).update(title_row("Outbox", view, summary))
        self._show_detail()

    def selected(self) -> Any:
        table = self.query_one("#ob-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    def action_details(self) -> None:
        r = self.selected()
        if r is None:
            return
        with S.opened(self._data_dir) as conn:
            atts = S.attempts_of(conn, r["id"])
        body = Text()
        body.append(f"{r['summary']}\n\n")
        body.append(f"To {r['channel']} · {r['kind']} · {r['status']} · message id {r['message_id']}\n",
                    style=T.TEXT_MUTED)
        if r["status"] == "failed":
            body.append(f"Next try {_when(r['next_attempt_at'], self._tz)}\n", style=T.ATTENTION)
        body.append("\nAttempts:\n", style=T.TEXT_MUTED)
        for a in atts:
            state = "interrupted" if a["finished_at"] is None else ("ok" if a["ok"] else "failed")
            body.append(f"  {_when(a['started_at'], self._tz)}  {state}  {a['detail'] or ''}\n")
        if not atts:
            body.append("  none yet\n", style=T.TEXT_DIM)
        self.app.push_screen(InfoModal(f"Message #{r['id']}", body))

    @work(exclusive=True)
    async def action_retry(self) -> None:
        r = self.selected()
        if r is None or r["status"] not in ("dead", "failed"):
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Send #{r['id']} to {r['channel']} again now?", f"Last error: {r['last_error'] or '-'}"))
        if not ok:
            return
        with S.opened(self._data_dir) as conn:
            S.retry_now(conn, ids=[r["id"]])
        from kratos.outbox import worker as W

        W.wake()
        self.refresh_rows()

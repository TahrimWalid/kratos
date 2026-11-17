"""`/baseline` (alias `/normal`): what Kratos has learned is normal on a machine (E.3).

Today's deviations first, then each kind of normal with its learning status ("still
learning" is never "nothing unusual") and its most usual things with their weights. Enter
shows details; `a` accepts the selected deviation or entry as normal (it is never raised
again, and its finding is marked a false positive "expected behaviour"); `f` forgets an
entry (it counts as new again); `z` freezes or unfreezes learning (after an incident:
deviations are still raised, nothing is learned); `R` resets learning (the old profile is
kept); `r` runs the baseline now over what Kratos has stored. Every decision is confirmed
and recorded with who made it. Navigation follows tui_mk2/modals.py: Escape back, `y`
confirms.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.baseline import decide as BD
from kratos.baseline import present as BP
from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.keybar import all_keys_text, key_bar, layout_css, plural, title_row
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text
from kratos.utils.timeutil import format_for_display, resolve_display_tz

STATUS_STYLE = {"active": T.SAFE, "learning": T.ATTENTION, "frozen": T.ATTENTION, "not_learnable": T.TEXT_DIM}
SEV_STYLE = {"medium": T.ATTENTION, "low": T.TEXT, "info": T.TEXT_DIM}


class BaselineScreen(Screen):
    _ALL_KEYS = ("↑↓ select · enter details · a accept as normal · f forget a usual thing\n"
                 "z freeze / unfreeze learning · R reset learning · r run now · esc back")
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("question_mark", "all_keys", "all keys", show=False),
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("a", "accept", "accept as normal", show=True),
        Binding("f", "forget", "forget", show=True),
        Binding("z", "freeze", "freeze / unfreeze", show=True),
        Binding("R", "reset", "reset", show=True),
        Binding("r", "run", "run now", show=True),
    ]

    # A2: title row, the table, a detail pane for the selected row, a short log, a key bar.
    CSS = layout_css("BaselineScreen", "bl")

    def __init__(self, data_dir: Path, *, machine: str | None = None) -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._machine = machine
        self._view: dict[str, Any] | None = None
        self._rows: list[dict[str, Any]] = []
        self._error = ""
        self._tz = resolve_display_tz(self._data_dir)

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="bl-banner")
            yield DataTable(id="bl-table", cursor_type="row")
            yield Static(id="bl-detail")
            yield VerticalScroll(id="bl-log")
            yield Static(key_bar([("r", "run now"), ("?", "all keys"), ("esc", "back")]), id="bl-hints")

    def on_mount(self) -> None:
        self.reload()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.render_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_all_keys(self) -> None:
        body = all_keys_text(self._ALL_KEYS)
        v = self._view or {}
        if v.get("note"):
            body.append(f"\n\n{v['note']}", style=T.TEXT_MUTED)
        self.app.push_screen(InfoModal("What's normal — all keys", body))

    def _when(self, value: Any) -> str:
        return format_for_display(value, "%Y-%m-%d %H:%M", tz=self._tz) if value else "-"

    def note(self, renderable: Any) -> None:
        area = self.query_one("#bl-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    # -- data --------------------------------------------------------------
    def reload(self) -> None:
        self._error = ""
        try:
            tk, scope = BP.resolve_reader(self._data_dir, Actor.current("tui"), self._machine)
            self._machine = tk
            self._view = BP.view(self._data_dir, tk, scope=scope)
        except Exception as e:  # noqa: BLE001 -- shown, never a crash
            self._view, self._error = None, str(e)
        self.render_rows()

    def render_rows(self) -> None:
        table = self.query_one("#bl-table", DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        self._rows = []
        v = self._view
        if v is None:
            self.query_one("#bl-banner", Static).update(
                title_row("What's normal here", note=self._error or "nothing to show", note_style=T.CRITICAL))
            self._show_detail()
            return
        summary = " · ".join(b for b in ((f"machine zone {v['zone']}" if v.get("zone") else ""),
                                         (f"last run {self._when(v['checked_at'])}" if v.get("checked_at") else ""))
                             if b)
        banner = title_row("What's normal here", v["machine"], summary,
                           note="FROZEN (z unfreezes)" if v.get("frozen") else "")
        cells: list[list[Any]] = []
        for dv in v.get("deviations") or []:
            self._rows.append({"type": "dev", **dv})
            cells.append([Text(f"{dv['rule']} {dv.get('severity')}", style=SEV_STYLE.get(str(dv.get("severity")),
                                                                                       T.TEXT)),
                          f"{dv['subject']}: {dv['key']}", dv.get("machine_time") or ""])
        for d in v.get("dims") or []:
            word = BP.STATUS_WORDS.get(d["status"], d["status"])
            extra = (f"{d['learned_days']} days, {d['covered_days']} covered" if d["status"] == "active" else
                     d.get("learning") or d.get("reason") or "")
            self._rows.append({"type": "dim", **d})
            cells.append([Text(d["rule"], style=T.DATA), Text(f"{d['label']} — {word}",
                                                                style=STATUS_STYLE.get(d["status"], T.TEXT)), extra])
            for t in d.get("top") or []:
                self._rows.append({"type": "entry", "dim": d["name"], **t})
                mark = " · accepted" if t["accepted"] else ""
                cells.append(["", f"  {t['subject']}: {t['key']}", f"weight {t['weight']} · x{t['count']}{mark}"])
        self.query_one("#bl-banner", Static).update(banner)
        columns = ("", "what", "detail")
        table.add_columns(*columns)
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(1, 24), (2, 14)], headers=columns):
            table.add_row(*row)
        if self._rows:
            table.move_cursor(row=min(cursor or 0, len(self._rows) - 1))
        self._show_detail()

    def on_data_table_row_highlighted(self, _event: DataTable.RowHighlighted) -> None:
        self._show_detail()

    def _show_detail(self) -> None:
        """The selected row in words, and the keys that apply to it (A2)."""
        try:
            detail = self.query_one("#bl-detail", Static)
            hints = self.query_one("#bl-hints", Static)
        except Exception:  # noqa: BLE001 -- not mounted yet
            return
        r = self.selected()
        out = Text()
        if r is None:
            out.append((self._view or {}).get("note") or "Nothing learned yet. r runs it over what Kratos has stored.",
                       style=T.TEXT_MUTED)
            detail.update(out)
            hints.update(key_bar([("r", "run now"), ("?", "all keys"), ("esc", "back")]))
            return
        if r["type"] == "dev":
            out.append(f"{r['rule']}  ", style=T.DATA)
            out.append(f"{r.get('severity')}", style=f"bold {SEV_STYLE.get(str(r.get('severity')), T.TEXT)}")
            out.append(f"   {r['subject']}: {r['key']}", style=f"bold {T.TEXT_BRIGHT}")
            out.append(f"\n{r.get('machine_time') or ''}" + (f" · address {r['address']}" if r.get("address") else ""),
                       style=T.TEXT_DIM)
            if r.get("usual"):
                out.append("\nUsual: " + "; ".join(r["usual"]), style=T.TEXT_MUTED)
            if r.get("held"):
                out.append("\nNear an open serious finding: not learned as normal yet.", style=T.ATTENTION)
            keys = [("enter", "details"), ("a", "accept as normal")]
        elif r["type"] == "dim":
            out.append(f"{r['rule']}  ", style=T.DATA)
            out.append(f"{r['label']}", style=f"bold {T.TEXT_BRIGHT}")
            out.append(f"\n{BP.STATUS_WORDS.get(r['status'], r['status'])}", style=STATUS_STYLE.get(r["status"], T.TEXT))
            if r.get("learning") or r.get("reason"):
                out.append(f" — {r.get('learning') or r.get('reason')}", style=T.TEXT_MUTED)
            out.append(f"\nlearned over {plural(r['learned_days'], 'day')} ({r['covered_days']} covered) · "
                       f"{plural(r.get('entries', 0), 'usual thing')}", style=T.TEXT_DIM)
            keys = [("enter", "details"), ("z", "freeze"), ("r", "run now")]
        else:
            out.append(f"{r['subject']}: {r['key']}", style=f"bold {T.TEXT_BRIGHT}")
            out.append(f"\nweight {r['weight']} · seen {plural(r['count'], 'time')} · last {self._when(r['last_seen'])}",
                       style=T.TEXT_DIM)
            if r.get("accepted"):
                out.append("\naccepted as normal by a person", style=T.SAFE)
            keys = [("enter", "details"), ("a", "accept"), ("f", "forget")]
        detail.update(out)
        hints.update(key_bar(keys + [("?", "all keys"), ("esc", "back")]))

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#bl-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    # -- actions -----------------------------------------------------------
    def action_details(self) -> None:
        r = self.selected()
        if r is None:
            return
        body = Text()
        if r["type"] == "dev":
            body.append(f"{r['rule']} ({r.get('severity')}) — {r['subject']}: {r['key']}\n", style=T.TEXT)
            body.append(f"{r.get('machine_time') or ''}" + (f" · address {r['address']}" if r.get("address") else "")
                        + "\n", style=T.TEXT_DIM)
            if r.get("usual"):
                body.append("Usual: " + "; ".join(r["usual"]) + "\n")
            if r.get("learned"):
                body.append(f"{r['learned']}\n", style=T.TEXT_DIM)
            u = r.get("usual_on")
            if u:
                where = ", ".join(u.get("machines") or [])
                if u.get("outside_your_access"):
                    where = (where + ", " if where else "") + plural(u['outside_your_access'], 'machine') + " outside your access"
                body.append(f"First time here; usual for this account on: {where}\n", style=T.ATTENTION)
            if r.get("held"):
                body.append("Happened near an open serious finding: not learned as normal yet.\n", style=T.ATTENTION)
            body.append("\na accepts it as normal (never raised again).", style=T.TEXT_DIM)
        elif r["type"] == "dim":
            body.append(f"{r['label']}\n", style=T.TEXT)
            body.append(f"{BP.STATUS_WORDS.get(r['status'], r['status'])}", style=STATUS_STYLE.get(r["status"], T.TEXT))
            if r.get("learning"):
                body.append(f" — {r['learning']}")
            if r.get("reason"):
                body.append(f" — {r['reason']}")
            body.append(f"\nlearned over {r['learned_days']} days ({r['covered_days']} covered); "
                        f"{r.get('entries', 0)} usual things", style=T.TEXT_DIM)
            if r.get("evicted"):
                body.append(f"\n{plural(r['evicted'], 'rarely used thing')} set aside to stay within the limit",
                            style=T.TEXT_DIM)
            if r.get("held_back"):
                body.append(f"\n{plural(r['held_back'], 'observation')} held back near an open serious finding",
                            style=T.ATTENTION)
        else:
            body.append(f"{r['subject']}: {r['key']}\n", style=T.TEXT)
            body.append(f"weight {r['weight']} · seen {plural(r['count'], 'time')}\nfirst {self._when(r['first_seen'])}"
                        f"\nlast {self._when(r['last_seen'])}", style=T.TEXT_DIM)
            if r.get("accepted"):
                body.append("\naccepted as normal by a person", style=T.SAFE)
        self.app.push_screen(InfoModal("What's normal", body))

    @work(exclusive=True)
    async def action_accept(self) -> None:
        r = self.selected()
        if r is None or r["type"] not in ("dev", "entry"):
            self.note(Text("Select a deviation or a usual thing first.", style=T.TEXT_DIM))
            return
        reason = await self.app.push_screen_wait(PromptModal("Why is it normal? (optional)", "", initial=""))
        if reason is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Accept as normal?", f"{r['subject']}: {r['key']}\nIt won't be raised again on {self._machine}."))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            res = BD.accept(self._data_dir, self._machine, r["dim"], r["subject"], r["key"],
                            actor=Actor.current("tui"), reason=reason)
        except BD.BaselineError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"{r['subject']}: {r['key']} is normal now (finding: {res['finding']}).", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_forget(self) -> None:
        r = self.selected()
        if r is None or r["type"] != "entry":
            self.note(Text("Select a usual thing to forget.", style=T.TEXT_DIM))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Forget it?", f"{r['subject']}: {r['key']}\nIt counts as new again and may be raised."))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            BD.forget(self._data_dir, self._machine, r["dim"], r["subject"], r["key"], actor=Actor.current("tui"))
        except BD.BaselineError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text("Forgotten (recorded with your name).", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_freeze(self) -> None:
        frozen = bool((self._view or {}).get("frozen"))
        title = "Unfreeze: learning resumes?" if frozen else "Freeze learning?"
        body = ("Kratos learns from new history again." if frozen else
                "After an incident: deviations are still raised, nothing new is learned as normal.")
        ok = await self.app.push_screen_wait(ConfirmModal(title, body))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            (BD.unfreeze if frozen else BD.freeze)(self._data_dir, self._machine, actor=Actor.current("tui"))
        except BD.BaselineError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text("Unfrozen." if frozen else "Frozen.", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_reset(self) -> None:
        ok = await self.app.push_screen_wait(ConfirmModal(
            "Reset what's normal?", f"Learning starts again from now on {self._machine} (14 covered days before "
            "anything is raised). The old profile is kept as history."))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            BD.reset(self._data_dir, self._machine, actor=Actor.current("tui"))
        except BD.BaselineError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text("Reset: learning starts again (recorded with your name).", style=T.SAFE))
        self.reload()

    def action_run(self) -> None:
        self.note(Text("Learning from what Kratos has stored…", style=T.TEXT_DIM))
        self._run()

    @work(thread=True, exclusive=True)
    def _run(self) -> None:
        from kratos.baseline import record
        from kratos.kratos_config import pinned_target
        from kratos.run_context import run_scope

        try:
            with run_scope("interactive", target=self._machine), pinned_target(self._machine):
                doc = record.run(self._data_dir, self._machine)
            line = record.summary_line(doc)
        except Exception as e:  # noqa: BLE001
            line = f"not run ({type(e).__name__}: {e})"
        self.app.call_from_thread(self._after_run, line)

    def _after_run(self, line: str) -> None:
        self.note(Text(line, style=T.TEXT))
        self.reload()

"""`/compliance`: how a machine (or a group) stands against CIS, ISO 27001 and NIS2 (E.2).

Every control shows one of six statuses, from Kratos's own checks over facts it read --
a pass only with fresh, complete proof; organisational controls "need a person". Enter
shows a control's checks with what was found, when it was read, and the fix (a command
a person runs; Kratos never runs it). `o` sets an owner, `n` marks a control not
applicable (with a reason and an expiry), `l` the CIS level, `r` reads the machine again.
Decisions are confirmed and recorded with who made them. Navigation follows
tui_mk2/modals.py: Escape back, `y` confirms.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen

from kratos.compliance import frameworks as F
from kratos.compliance import owners as O
from kratos.compliance import report as RP
from kratos.compliance import status as ST
from kratos.lifecycle.decide import Actor
from kratos.tui_mk2 import theme as T
from kratos.tui_mk2.modals import ConfirmModal, InfoModal, ListPickerModal, PromptModal
from kratos.tui_mk2.safe_widgets import SafeDataTable as DataTable, SafeStatic as Static
from kratos.tui_mk2.table_fit import fit_columns
from kratos.untrusted_rich import SafeText as Text

STYLE = {"pass": T.SAFE, "fail": T.CRITICAL, "partial": T.ATTENTION, "not_checked": T.TEXT_DIM,
         "needs_person": T.TEXT_MUTED, "not_applicable": T.TEXT_DIM}
FW_WORDS = {"cis": "CIS", "iso27001": "ISO 27001", "nis2": "NIS2"}


class ComplianceScreen(Screen):
    BINDINGS = [
        Binding("escape,q", "back", "back", show=True),
        Binding("enter", "details", "details", show=True, priority=True),
        Binding("f", "framework", "framework", show=True),
        Binding("o", "owner", "owner", show=True),
        Binding("n", "na", "not applicable", show=True),
        Binding("l", "level", "CIS level", show=True),
        Binding("a", "toggle_all", "all rows", show=True),
        Binding("r", "refresh", "read again", show=True),
    ]

    CSS = """
    ComplianceScreen { padding: 1 2; }
    ComplianceScreen #co-banner { height: auto; padding: 0 0 1 0; }
    ComplianceScreen DataTable { height: 1fr; }
    ComplianceScreen #co-log { height: auto; max-height: 8; border-top: solid $panel; }
    ComplianceScreen #co-hints { height: auto; padding-top: 1; }
    """

    def __init__(self, data_dir: Path, *, machine: str | None = None, group: str | None = None,
                 framework: str = "cis") -> None:
        super().__init__()
        self._data_dir = Path(data_dir)
        self._machine = machine
        self._group = group
        self._fw = framework if framework in F.FRAMEWORKS else "cis"
        self._all = False
        self._doc: dict[str, Any] | None = None
        self._rows: list[dict[str, Any]] = []
        self._error = ""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(id="co-banner")
            yield DataTable(id="co-table", cursor_type="row")
            yield VerticalScroll(id="co-log")
            yield Static(Text("enter evidence · f framework · o owner · n N/A · l level · a all · r reread",
                              style=T.TEXT_DIM), id="co-hints")

    def on_mount(self) -> None:
        self.reload()

    def on_resize(self, _event) -> None:
        self.call_after_refresh(self.render_rows)

    def action_back(self) -> None:
        self.app.pop_screen()

    def note(self, renderable: Any) -> None:
        area = self.query_one("#co-log", VerticalScroll)
        area.mount(Static(renderable))
        area.scroll_end(animate=False)

    # -- data --------------------------------------------------------------
    def reload(self) -> None:
        self._error = ""
        try:
            machines, outside, label = RP.resolve_machines(self._data_dir, Actor.current("tui"),
                                                           machine=self._machine, group=self._group)
            self._doc = RP.build(self._data_dir, self._fw, machines, outside_scope=outside, label=label)
        except Exception as e:  # noqa: BLE001 -- shown, never a crash
            self._doc, self._error = None, str(e)
        self.render_rows()

    def _single(self) -> dict[str, Any] | None:
        if self._doc and len(self._doc["machines"]) == 1:
            return self._doc["machines"][0]
        return None

    def render_rows(self) -> None:
        table = self.query_one("#co-table", DataTable)
        cursor = table.cursor_row
        table.clear(columns=True)
        banner = Text()
        banner.append(f"Compliance — {FW_WORDS[self._fw]}", style=f"bold {T.ACCENT}")
        self._rows = []
        if self._doc is None:
            banner.append(f"\n{self._error or 'nothing to show'}", style=T.CRITICAL)
            self.query_one("#co-banner", Static).update(banner)
            return
        banner.append(f"   {self._doc['scope']}", style=T.TEXT_DIM)
        banner.append(f"\n{F.NOT_A_CERTIFICATION}", style=T.TEXT_MUTED)
        single = self._single()
        if single is not None:
            if single.get("status") != "read":
                banner.append(f"\nNot checked: {single.get('reason')}", style=T.ATTENTION)
            else:
                banner.append(f"\n{single.get('summary')}", style=T.TEXT)
                bits = [f"read {single.get('read_at')} via {single.get('via')}"]
                if single.get("product_note"):
                    bits.append(single["product_note"])
                banner.append("\n" + " · ".join(bits), style=T.TEXT_DIM)
            columns = ("control", "status", "what Kratos looks at", "owner")
            rows = [c for c in single.get("controls") or [] if self._all or c["status"] != "not_checked"
                    or c.get("checks")]
            hidden = len(single.get("controls") or []) - len(rows)
            if hidden:
                banner.append(f"\n{hidden} control(s) Kratos has no check for are hidden (a shows them)",
                              style=T.TEXT_DIM)
            self._rows = rows
            cells = [[c["control"], Text(ST.STATUS_WORDS[c["status"]], style=STYLE[c["status"]]), c.get("text", ""),
                      c.get("owner") or "-"] for c in rows]
        else:
            n = len(self._doc["machines"])
            banner.append(f"\n{n} machine(s)" + (f" · {self._doc['outside_scope']} outside your access (not shown)"
                                                  if self._doc.get("outside_scope") else ""), style=T.TEXT)
            columns = ("control", "status", "what Kratos looks at", "machines")
            self._rows = [r for r in self._doc.get("rollup") or [] if self._all or r["status"] != "not_checked"]
            cells = [[(f"{r['product']} " if r.get("product") else "") + r["control"],
                      Text(ST.STATUS_WORDS[r["status"]], style=STYLE[r["status"]]), r.get("text", ""),
                      ", ".join(f"{ST.STATUS_WORDS[k]} {v}" for k, v in r["counts"].items())] for r in self._rows]
        self.query_one("#co-banner", Static).update(banner)
        table.add_columns(*columns)
        available = table.size.width or max(self.app.size.width - 6, 40)
        for row in fit_columns(cells, available, shrink=[(2, 20), (3, 14)], headers=columns):
            table.add_row(*row)
        if cursor is not None and self._rows:
            table.move_cursor(row=min(cursor, len(self._rows) - 1))

    def selected(self) -> dict[str, Any] | None:
        table = self.query_one("#co-table", DataTable)
        if not self._rows or table.cursor_row is None:
            return None
        return self._rows[min(table.cursor_row, len(self._rows) - 1)]

    # -- actions -----------------------------------------------------------
    def action_toggle_all(self) -> None:
        self._all = not self._all
        self.render_rows()

    @work(exclusive=True)
    async def action_framework(self) -> None:
        pick = await self.app.push_screen_wait(ListPickerModal(
            "Which framework?", [(f, F.FRAMEWORK_NAMES[f]) for f in F.FRAMEWORKS],
            subtitle="the same Kratos checks, mapped to each framework's control ids"))
        if pick:
            self._fw = pick
            self.reload()

    def action_details(self) -> None:
        c = self.selected()
        if c is None:
            return
        body = Text()
        if self._single() is None:
            body.append(f"{c.get('text', '')}\n\n", style=T.TEXT)
            for k, v in c["counts"].items():
                body.append(f"{ST.STATUS_WORDS[k]}: {v} machine(s)\n")
            body.append("\nOpen one machine with /compliance <machine> for its evidence.", style=T.TEXT_DIM)
            self.app.push_screen(InfoModal(f"{FW_WORDS[self._fw]} {c['control']}", body))
            return
        body.append(f"{ST.STATUS_WORDS[c['status']]}", style=f"bold {STYLE[c['status']]}")
        if c.get("reason"):
            body.append(f" — {c['reason']}")
        body.append(f"\n{c.get('text', '')}\n", style=T.TEXT_MUTED)
        if c.get("person"):
            body.append(f"A person supplies: {c['person']}\n", style=T.TEXT_MUTED)
        if c.get("owner"):
            body.append(f"Owner: {c['owner']}\n")
        if c.get("uncovered_rules"):
            body.append("Not checked by Kratos (ComplianceAsCode rules — OpenSCAP can check them): "
                        + ", ".join(c["uncovered_rules"]) + "\n", style=T.TEXT_DIM)
        for r in c.get("check_results") or []:
            body.append(f"\n{r['id']}  ", style=T.ACCENT)
            body.append(r["status"], style=STYLE.get({"unknown": "not_checked", "na": "not_applicable"}.get(
                r["status"], r["status"]), T.TEXT))
            body.append(f"\n  {r['text']}\n  found: {r['found'] or r['reason']}")
            if r.get("read_at"):
                body.append(f"\n  read {r['read_at']} via {r.get('via')}", style=T.TEXT_DIM)
            if r.get("note"):
                body.append(f"\n  {r['note']}", style=T.ATTENTION)
            if r.get("linked_finding"):
                body.append(f"\n  already a finding: {r['linked_finding']} (see /findings)", style=T.ATTENTION)
            if r.get("other_read"):
                o = r["other_read"]
                body.append(f"\n  the {o.get('via')} read said {o.get('status')}: {o.get('found')}", style=T.TEXT_DIM)
            if r.get("fix"):
                body.append(f"\n  fix (you run it): {r['fix']}", style=T.SAFE)
        self.app.push_screen(InfoModal(f"{FW_WORDS[self._fw]} {c['control']}", body))

    async def _scope(self, c: dict[str, Any]) -> str | None:
        single = self._single()
        choices = []
        if single is not None:
            choices.append((f"machine:{single['machine']}", f"this machine ({single['machine']})"))
        if self._group:
            choices.append((f"group:{self._group.lstrip('@')}", f"the group @{self._group.lstrip('@')}"))
        choices.append(("all", "every machine"))
        return await self.app.push_screen_wait(ListPickerModal(f"For {FW_WORDS[self._fw]} {c['control']} on:",
                                                               choices))

    @work(exclusive=True)
    async def action_owner(self) -> None:
        c = self.selected()
        if c is None:
            return
        scope = await self._scope(c)
        if scope is None:
            return
        who = await self.app.push_screen_wait(PromptModal("Owner (a Kratos user's name, or any name)", "",
                                                          initial=""))
        if not who:
            return
        due = await self.app.push_screen_wait(PromptModal("Due date (YYYY-MM-DD, empty for none)", "", initial=""))
        if due is None:
            return
        ok = await self.app.push_screen_wait(ConfirmModal(f"Set the owner of {FW_WORDS[self._fw]} {c['control']}?",
                                                          f"{who}" + (f", due {due}" if due else "") + f"\n{scope}"))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            O.set_owner(self._data_dir, Actor.current("tui"), self._fw, c["control"], scope, who, due=due or None)
        except O.ComplianceError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"Owner set for {c['control']} (recorded with your name).", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_na(self) -> None:
        c = self.selected()
        if c is None:
            return
        scope = await self._scope(c)
        if scope is None:
            return
        reason = await self.app.push_screen_wait(PromptModal("Why doesn't it apply? (required)", "", initial=""))
        if not reason:
            return
        days = await self.app.push_screen_wait(PromptModal("For how many days? (1-365; Kratos asks again then)", "",
                                                           initial="365"))
        if not days:
            return
        try:
            n = int(days)
        except ValueError:
            self.note(Text("Not changed: days is a number.", style=T.CRITICAL))
            return
        ok = await self.app.push_screen_wait(ConfirmModal(
            f"Mark {FW_WORDS[self._fw]} {c['control']} not applicable?", f"{reason}\nfor {n} days · {scope}"))
        if not ok:
            self.note(Text("Not changed.", style=T.TEXT_DIM))
            return
        try:
            O.set_na(self._data_dir, Actor.current("tui"), self._fw, c["control"], scope, reason, n)
        except O.ComplianceError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.note(Text(f"{c['control']} is not applicable for {n} days (recorded with your name).", style=T.SAFE))
        self.reload()

    @work(exclusive=True)
    async def action_level(self) -> None:
        single = self._single()
        if single is None:
            self.note(Text("Open one machine to set its CIS level.", style=T.TEXT_DIM))
            return
        pick = await self.app.push_screen_wait(ListPickerModal(
            f"CIS profile for {single['machine']}", [("1", "Level 1 Server (the default)"),
                                                     ("2", "Level 2 Server (stricter; includes Level 1)")]))
        if pick is None:
            return
        try:
            O.set_level(self._data_dir, Actor.current("tui"), single["machine"], pick)
        except O.ComplianceError as e:
            self.note(Text(f"Not changed: {e}", style=T.CRITICAL))
            return
        self.reload()

    def action_refresh(self) -> None:
        self.note(Text("Reading the hardening facts again…", style=T.TEXT_DIM))
        self._refresh()

    @work(thread=True, exclusive=True)
    def _refresh(self) -> None:
        from kratos.compliance import record
        from kratos.kratos_config import pinned_target
        from kratos.run_context import run_scope

        machines = [s["machine"] for s in (self._doc or {}).get("machines") or []]
        lines = []
        for m in machines:
            try:
                with run_scope("interactive", target=m), pinned_target(m):
                    doc = record.run(self._data_dir, m)
                lines.append(f"{m}: {record.summary_line(doc)}")
            except Exception as e:  # noqa: BLE001
                lines.append(f"{m}: not read ({type(e).__name__}: {e})")
        self.app.call_from_thread(self._after_refresh, lines)

    def _after_refresh(self, lines: list[str]) -> None:
        for ln in lines:
            self.note(Text(ln, style=T.TEXT))
        self.reload()
